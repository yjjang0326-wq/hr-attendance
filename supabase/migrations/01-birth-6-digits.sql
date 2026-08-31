-- ============================================================
--  [적용 필요] 생년월일 앞 6자리 로그인
--  ------------------------------------------------------------
--  감독자·아르바이트 로그인 시 생년월일을 앞 6자리(YYMMDD)로
--  대조하도록 hr_login 함수를 교체합니다.
--  8자리(20020411)를 그대로 입력해도 인증됩니다.
--
--  Supabase 대시보드 > SQL Editor 에 전체를 붙여넣고 Run 하세요.
--  기존 데이터에는 아무 영향이 없습니다.
-- ============================================================

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
    -- 생년월일은 앞 6자리(YYMMDD)로 대조한다.
    -- 등록값이 2002-04-11 이든 20020411 이든 뒤 6자리는 020411 로 같으므로,
    -- 6자리만 입력해도 8자리를 그대로 입력해도 인증된다.
    if length(public.hr__digits(p_b)) < 6 then
      perform public.hr__fail(gkey);
      raise exception '생년월일 앞 6자리를 입력하세요. (예: 2002년 4월 11일 → 020411)';
    end if;
    select t.v into me from jsonb_array_elements(
      coalesce(d.data->(case when p_role = 'sup' then 'sups' else 'workers' end), '[]'::jsonb)) as t(v)
      where t.v->>'name' = p_a
        and right(public.hr__digits(t.v->>'birth'), 6) = right(public.hr__digits(p_b), 6)
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

grant execute on function public.hr_login(text, text, text) to anon, authenticated;
