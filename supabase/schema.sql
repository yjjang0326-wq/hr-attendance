-- ============================================================
--  HR 근태·급여 관리 시스템 — Supabase 스키마
--  Supabase 대시보드 > SQL Editor 에 전체를 붙여넣고 실행하세요.
--  (여러 번 실행해도 안전합니다)
--
--  보안 모델: 테이블 직접 접근은 전면 차단(RLS deny-all).
--  anon 키로 호출할 수 있는 것은 아래 RPC 함수뿐이고,
--  모든 조회/저장은 로그인으로 발급받은 토큰을 요구합니다.
-- ============================================================

create extension if not exists pgcrypto with schema extensions;

-- ------------------------------------------------------------
-- 1. 테이블
-- ------------------------------------------------------------

-- 앱 데이터 전체(JSON 문서 1건). version 으로 동시 저장 충돌을 감지합니다.
create table if not exists public.hr_doc (
  id         text primary key default 'main',
  data       jsonb       not null default '{}'::jsonb,
  version    bigint      not null default 1,
  updated_at timestamptz not null default now()
);

-- 마스터관리자 자격증명(비밀번호는 bcrypt 해시로만 저장)
create table if not exists public.hr_cred (
  master_id    text primary key,
  user_id      text not null unique,
  pw_hash      text not null,
  phone_digits text not null default '',
  updated_at   timestamptz not null default now()
);

-- 로그인 세션 토큰
create table if not exists public.hr_session (
  token      uuid primary key default gen_random_uuid(),
  role       text not null check (role in ('master','sup','part')),
  subject_id text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '12 hours'
);
create index if not exists hr_session_exp_idx on public.hr_session (expires_at);

-- 비밀번호 재설정 1회용 티켓
create table if not exists public.hr_reset (
  ticket     uuid primary key default gen_random_uuid(),
  master_id  text not null,
  expires_at timestamptz not null default now() + interval '15 minutes'
);

-- 로그인 시도 제한(무차별 대입 방지)
create table if not exists public.hr_attempt (
  k            text primary key,
  fails        int not null default 0,
  locked_until timestamptz
);

-- ------------------------------------------------------------
-- 2. RLS: 전면 차단 (정책을 하나도 만들지 않음 = 직접 접근 불가)
--    SECURITY DEFINER 함수만 우회하여 접근합니다.
-- ------------------------------------------------------------
alter table public.hr_doc     enable row level security;
alter table public.hr_cred    enable row level security;
alter table public.hr_session enable row level security;
alter table public.hr_reset   enable row level security;
alter table public.hr_attempt enable row level security;

revoke all on public.hr_doc, public.hr_cred, public.hr_session,
              public.hr_reset, public.hr_attempt
  from anon, authenticated;

-- ------------------------------------------------------------
-- 3. 내부 헬퍼
-- ------------------------------------------------------------

-- 만료 데이터 정리
create or replace function public.hr__gc() returns void
language sql security definer set search_path = public, extensions as $fn$
  delete from public.hr_session where expires_at < now();
  delete from public.hr_reset   where expires_at < now();
$fn$;

-- 숫자만 추출
create or replace function public.hr__digits(v text) returns text
language sql immutable as $fn$
  select regexp_replace(coalesce(v, ''), '[^0-9]', '', 'g')
$fn$;

-- 시도 제한 확인 (5회 실패 시 10분 잠금)
create or replace function public.hr__guard(p_key text) returns void
language plpgsql security definer set search_path = public, extensions as $fn$
declare r public.hr_attempt%rowtype;
begin
  select * into r from public.hr_attempt where k = p_key;
  if found and r.locked_until is not null and r.locked_until > now() then
    raise exception '시도가 많아 잠시 잠겼습니다. % 초 후 다시 시도하세요.',
      ceil(extract(epoch from (r.locked_until - now())));
  end if;
end $fn$;

create or replace function public.hr__fail(p_key text) returns void
language plpgsql security definer set search_path = public, extensions as $fn$
begin
  insert into public.hr_attempt (k, fails) values (p_key, 1)
  on conflict (k) do update set
    fails = case when public.hr_attempt.locked_until is not null
                  and public.hr_attempt.locked_until < now()
                 then 1 else public.hr_attempt.fails + 1 end,
    locked_until = case when public.hr_attempt.fails + 1 >= 5
                        then now() + interval '10 minutes' else null end;
end $fn$;

create or replace function public.hr__ok(p_key text) returns void
language sql security definer set search_path = public, extensions as $fn$
  delete from public.hr_attempt where k = p_key;
$fn$;

-- 저장된 문서 읽기(없으면 생성)
create or replace function public.hr__doc() returns public.hr_doc
language plpgsql security definer set search_path = public, extensions as $fn$
declare d public.hr_doc%rowtype;
begin
  select * into d from public.hr_doc where id = 'main';
  if not found then
    insert into public.hr_doc (id, data, version) values ('main', '{}'::jsonb, 1)
      on conflict (id) do nothing;
    select * into d from public.hr_doc where id = 'main';
  end if;
  return d;
end $fn$;

-- 토큰 검증 → (role, subject_id). 유효하지 않으면 예외.
create or replace function public.hr__auth(p_token uuid)
returns table (role text, subject_id text)
language plpgsql security definer set search_path = public, extensions as $fn$
declare n int;
begin
  perform public.hr__gc();
  return query
    select s.role, s.subject_id from public.hr_session s
    where s.token = p_token and s.expires_at > now();
  get diagnostics n = row_count;
  if n = 0 then
    raise exception '세션이 만료되었습니다. 다시 로그인하세요.';
  end if;
end $fn$;

-- 역할별로 문서를 서버에서 실제로 잘라내서 반환
create or replace function public.hr__filter(p_doc jsonb, p_role text, p_subject text)
returns jsonb
language plpgsql immutable as $fn$
declare
  workers jsonb := coalesce(p_doc->'workers', '[]'::jsonb);
  sups    jsonb := coalesce(p_doc->'sups',    '[]'::jsonb);
  rec     jsonb := coalesce(p_doc->'rec',     '{}'::jsonb);
  keep    jsonb;
  out_rec jsonb := '{}'::jsonb;
  wid     text;
begin
  if p_role = 'master' then
    -- 비밀번호는 문서에 저장하지 않으므로 pw 키만 제거해서 반환
    return jsonb_set(p_doc, '{masters}', coalesce((
      select jsonb_agg(m - 'pw')
        from jsonb_array_elements(coalesce(p_doc->'masters', '[]'::jsonb)) m
    ), '[]'::jsonb));
  end if;

  if p_role = 'sup' then
    keep := coalesce((select jsonb_agg(w) from jsonb_array_elements(workers) w
                      where w->>'supId' = p_subject), '[]'::jsonb);
    sups := coalesce((select jsonb_agg(s) from jsonb_array_elements(sups) s
                      where s->>'id' = p_subject), '[]'::jsonb);
  else -- part
    keep := coalesce((select jsonb_agg(w) from jsonb_array_elements(workers) w
                      where w->>'id' = p_subject), '[]'::jsonb);
    sups := '[]'::jsonb;
  end if;

  for wid in select w->>'id' from jsonb_array_elements(keep) w loop
    if rec ? wid then
      out_rec := jsonb_set(out_rec, array[wid], rec->wid, true);
    end if;
  end loop;

  return jsonb_build_object(
    'masters',  '[]'::jsonb,
    'sups',     sups,
    'workers',  keep,
    'rec',      out_rec,
    'holidays', coalesce(p_doc->'holidays', '[]'::jsonb),
    'seq',      coalesce(p_doc->'seq', to_jsonb(1))
  );
end $fn$;

-- ------------------------------------------------------------
-- 4. 공개 RPC (anon 키로 호출 가능)
-- ------------------------------------------------------------

-- 로그인 화면용: 마스터가 이미 등록되어 있는지만 알려줍니다.
create or replace function public.hr_state() returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
begin
  perform public.hr__doc();
  return jsonb_build_object('hasMaster', (select count(*) > 0 from public.hr_cred));
end $fn$;

-- 최초 마스터관리자 가입 (1회만 허용)
create or replace function public.hr_signup(
  p_name text, p_birth text, p_phone text, p_user_id text, p_pw text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare d public.hr_doc%rowtype; mid text; tok uuid; doc jsonb;
begin
  if (select count(*) from public.hr_cred) > 0 then
    raise exception '이미 마스터관리자가 등록되어 있습니다.';
  end if;
  if length(coalesce(p_name, '')) = 0 then raise exception '모든 항목을 입력하세요.'; end if;
  if length(coalesce(p_user_id, '')) < 4 then raise exception '아이디는 4자 이상으로 입력하세요.'; end if;
  if length(coalesce(p_pw, ''))      < 4 then raise exception '비밀번호는 4자 이상으로 입력하세요.'; end if;
  if length(public.hr__digits(p_phone)) < 10 then raise exception '핸드폰번호를 정확히 입력하세요.'; end if;

  d := public.hr__doc();
  mid := 'm' || replace(gen_random_uuid()::text, '-', '');

  doc := jsonb_set(d.data, '{masters}',
    coalesce(d.data->'masters', '[]'::jsonb) || jsonb_build_array(jsonb_build_object(
      'id', mid, 'name', p_name, 'birth', p_birth, 'phone', p_phone,
      'userId', p_user_id, 'company', '본사 HR', 'owner', true)), true);

  update public.hr_doc set data = doc, version = version + 1, updated_at = now()
    where id = 'main';

  insert into public.hr_cred (master_id, user_id, pw_hash, phone_digits)
  values (mid, p_user_id, extensions.crypt(p_pw, extensions.gen_salt('bf', 10)),
          public.hr__digits(p_phone));

  select * into d from public.hr_doc where id = 'main';
  insert into public.hr_session (role, subject_id) values ('master', mid) returning token into tok;

  return jsonb_build_object('token', tok, 'role', 'master', 'subjectId', mid,
    'me', (select t.v from jsonb_array_elements(d.data->'masters') as t(v)
             where t.v->>'id' = mid),
    'doc', public.hr__filter(d.data, 'master', mid), 'version', d.version);
end $fn$;

-- 로그인. master: 아이디+비밀번호 / sup·part: 이름+생년월일
create or replace function public.hr_login(p_role text, p_a text, p_b text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare
  d public.hr_doc%rowtype; c public.hr_cred%rowtype;
  sid text; tok uuid; me jsonb; gkey text;
begin
  perform public.hr__gc();
  if p_role not in ('master', 'sup', 'part') then raise exception '잘못된 요청입니다.'; end if;
  gkey := p_role || ':' || lower(coalesce(p_a, ''));
  perform public.hr__guard(gkey);
  d := public.hr__doc();

  if p_role = 'master' then
    select * into c from public.hr_cred where user_id = p_a;
    if not found or c.pw_hash <> extensions.crypt(coalesce(p_b, ''), c.pw_hash) then
      perform public.hr__fail(gkey);
      raise exception '아이디 또는 비밀번호가 올바르지 않습니다.';
    end if;
    sid := c.master_id;
    select (t.v - 'pw') into me
      from jsonb_array_elements(coalesce(d.data->'masters', '[]'::jsonb)) as t(v)
      where t.v->>'id' = sid;
  else
    select t.v into me from jsonb_array_elements(
      coalesce(d.data->(case when p_role = 'sup' then 'sups' else 'workers' end), '[]'::jsonb)) as t(v)
      where t.v->>'name' = p_a
        and public.hr__digits(t.v->>'birth') = public.hr__digits(p_b)
      limit 1;
    if me is null then
      perform public.hr__fail(gkey);
      raise exception '등록되지 않은 계정입니다. 이름과 생년월일을 확인하세요.';
    end if;
    sid := me->>'id';
  end if;

  perform public.hr__ok(gkey);
  insert into public.hr_session (role, subject_id) values (p_role, sid) returning token into tok;
  return jsonb_build_object('token', tok, 'role', p_role, 'subjectId', sid, 'me', me,
    'doc', public.hr__filter(d.data, p_role, sid), 'version', d.version);
end $fn$;

-- 최신 데이터 가져오기
create or replace function public.hr_pull(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare a record; d public.hr_doc%rowtype;
begin
  select * into a from public.hr__auth(p_token);
  d := public.hr__doc();
  return jsonb_build_object('doc', public.hr__filter(d.data, a.role, a.subject_id),
    'version', d.version, 'role', a.role, 'subjectId', a.subject_id);
end $fn$;

-- 저장. 역할별 쓰기 범위를 서버에서 강제합니다.
--   master : 전체 저장
--   sup    : 담당 아르바이트생의 근무기록(rec)만
--   part   : 본인 근무기록만, 승인 완료된 날짜는 수정 불가
create or replace function public.hr_push(p_token uuid, p_doc jsonb, p_base_version bigint)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare
  a record; d public.hr_doc%rowtype; cur jsonb; nrec jsonb; wid text;
  allowed text[]; incoming jsonb; existing jsonb; day text; newv bigint;
begin
  select * into a from public.hr__auth(p_token);
  d := public.hr__doc();

  if p_base_version is not null and p_base_version <> d.version then
    return jsonb_build_object('conflict', true, 'version', d.version,
      'doc', public.hr__filter(d.data, a.role, a.subject_id));
  end if;

  cur := d.data;

  if a.role = 'master' then
    -- 마스터가 보낸 문서로 교체하되, 비밀번호는 문서에 저장하지 않습니다.
    cur := jsonb_set(p_doc, '{masters}', coalesce((
      select jsonb_agg(m - 'pw')
        from jsonb_array_elements(coalesce(p_doc->'masters', '[]'::jsonb)) m
    ), '[]'::jsonb), true);
    -- 문서에서 삭제된 마스터 계정의 자격증명도 함께 정리
    delete from public.hr_cred c where not exists (
      select 1 from jsonb_array_elements(coalesce(cur->'masters', '[]'::jsonb)) m
      where m->>'id' = c.master_id);
  else
    if a.role = 'sup' then
      select coalesce(array_agg(w->>'id'), '{}'::text[]) into allowed
        from jsonb_array_elements(coalesce(cur->'workers', '[]'::jsonb)) w
        where w->>'supId' = a.subject_id;
    else
      allowed := array[a.subject_id];
    end if;

    nrec := coalesce(cur->'rec', '{}'::jsonb);
    foreach wid in array allowed loop
      incoming := coalesce(p_doc->'rec'->wid, '{}'::jsonb);
      existing := coalesce(nrec->wid, '{}'::jsonb);
      for day in select jsonb_object_keys(incoming) loop
        -- 아르바이트생은 이미 승인된 기록을 덮어쓸 수 없습니다.
        if a.role = 'part' and coalesce(existing->day->>'status', '') = 'approved' then
          continue;
        end if;
        existing := jsonb_set(existing, array[day], incoming->day, true);
      end loop;
      nrec := jsonb_set(nrec, array[wid], existing, true);
    end loop;
    cur := jsonb_set(cur, '{rec}', nrec, true);
  end if;

  update public.hr_doc set data = cur, version = version + 1, updated_at = now()
    where id = 'main' returning version into newv;

  return jsonb_build_object('ok', true, 'version', newv);
end $fn$;

-- 마스터 계정 비밀번호 설정/변경 (로그인 상태에서 관리자 계정 메뉴용)
create or replace function public.hr_set_pw(p_token uuid, p_master_id text, p_pw text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare a record; uid_ text;
begin
  select * into a from public.hr__auth(p_token);
  if a.role <> 'master' then raise exception '권한이 없습니다.'; end if;
  if length(coalesce(p_pw, '')) < 4 then raise exception '비밀번호는 4자 이상으로 입력하세요.'; end if;

  select m->>'userId' into uid_
    from public.hr_doc d, jsonb_array_elements(coalesce(d.data->'masters', '[]'::jsonb)) m
    where d.id = 'main' and m->>'id' = p_master_id;
  if uid_ is null then raise exception '대상 계정을 찾을 수 없습니다.'; end if;

  insert into public.hr_cred (master_id, user_id, pw_hash)
  values (p_master_id, uid_, extensions.crypt(p_pw, extensions.gen_salt('bf', 10)))
  on conflict (master_id) do update
    set pw_hash = excluded.pw_hash, user_id = excluded.user_id, updated_at = now();
  return jsonb_build_object('ok', true);
end $fn$;

-- 마스터 계정의 아이디/핸드폰번호가 바뀌었을 때 자격증명 동기화
create or replace function public.hr_sync_cred(p_token uuid, p_master_id text,
                                               p_user_id text, p_phone text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare a record;
begin
  select * into a from public.hr__auth(p_token);
  if a.role <> 'master' then raise exception '권한이 없습니다.'; end if;
  update public.hr_cred
     set user_id = coalesce(nullif(p_user_id, ''), user_id),
         phone_digits = coalesce(nullif(public.hr__digits(p_phone), ''), phone_digits),
         updated_at = now()
   where master_id = p_master_id;
  return jsonb_build_object('ok', true);
end $fn$;

-- 비밀번호 찾기 1단계: 아이디 확인 → 마스킹된 핸드폰번호
create or replace function public.hr_reset1(p_user_id text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare c public.hr_cred%rowtype; nm text; ph text; gkey text;
begin
  gkey := 'reset1:' || lower(coalesce(p_user_id, ''));
  perform public.hr__guard(gkey);
  select * into c from public.hr_cred where user_id = p_user_id;
  if not found then
    perform public.hr__fail(gkey);
    raise exception '등록되지 않은 아이디입니다.';
  end if;
  if length(c.phone_digits) < 9 then
    raise exception '이 계정에는 핸드폰번호가 등록되어 있지 않습니다. 다른 HR 담당자에게 문의하세요.';
  end if;
  select m->>'name' into nm
    from public.hr_doc d, jsonb_array_elements(coalesce(d.data->'masters', '[]'::jsonb)) m
    where d.id = 'main' and m->>'id' = c.master_id;
  ph := substr(c.phone_digits, 1, 3) || '-'
     || repeat('*', length(c.phone_digits) - 7) || '-'
     || right(c.phone_digits, 4);
  return jsonb_build_object('acct', c.master_id, 'name', coalesce(nm, ''), 'phoneMasked', ph);
end $fn$;

-- 2단계: 핸드폰번호 전체 확인 → 1회용 티켓
create or replace function public.hr_reset2(p_acct text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare c public.hr_cred%rowtype; t uuid; gkey text;
begin
  perform public.hr__gc();
  gkey := 'reset2:' || coalesce(p_acct, '');
  perform public.hr__guard(gkey);
  select * into c from public.hr_cred where master_id = p_acct;
  if not found or c.phone_digits <> public.hr__digits(p_phone) then
    perform public.hr__fail(gkey);
    raise exception '핸드폰번호가 일치하지 않습니다.';
  end if;
  perform public.hr__ok(gkey);
  insert into public.hr_reset (master_id) values (p_acct) returning ticket into t;
  return jsonb_build_object('ticket', t);
end $fn$;

-- 3단계: 새 비밀번호 설정
create or replace function public.hr_reset3(p_ticket uuid, p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $fn$
declare r public.hr_reset%rowtype;
begin
  perform public.hr__gc();
  if length(coalesce(p_pw, '')) < 4 then raise exception '비밀번호는 4자 이상으로 입력하세요.'; end if;
  select * into r from public.hr_reset where ticket = p_ticket and expires_at > now();
  if not found then raise exception '인증이 만료되었습니다. 처음부터 다시 진행하세요.'; end if;
  update public.hr_cred
     set pw_hash = extensions.crypt(p_pw, extensions.gen_salt('bf', 10)), updated_at = now()
   where master_id = r.master_id;
  delete from public.hr_reset where ticket = p_ticket;
  return jsonb_build_object('ok', true);
end $fn$;

create or replace function public.hr_logout(p_token uuid) returns jsonb
language sql security definer set search_path = public, extensions as $fn$
  delete from public.hr_session where token = p_token;
  select jsonb_build_object('ok', true);
$fn$;

-- ------------------------------------------------------------
-- 5. 실행 권한: 내부 헬퍼는 숨기고, 공개 RPC만 anon 에 허용
-- ------------------------------------------------------------
revoke all on function
  public.hr__gc(),
  public.hr__digits(text),
  public.hr__guard(text),
  public.hr__fail(text),
  public.hr__ok(text),
  public.hr__doc(),
  public.hr__auth(uuid),
  public.hr__filter(jsonb, text, text)
  from public, anon, authenticated;

grant execute on function
  public.hr_state(),
  public.hr_signup(text, text, text, text, text),
  public.hr_login(text, text, text),
  public.hr_pull(uuid),
  public.hr_push(uuid, jsonb, bigint),
  public.hr_set_pw(uuid, text, text),
  public.hr_sync_cred(uuid, text, text, text),
  public.hr_reset1(text),
  public.hr_reset2(text, text),
  public.hr_reset3(uuid, text),
  public.hr_logout(uuid)
  to anon, authenticated;
