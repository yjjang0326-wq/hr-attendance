-- ============================================================
--  생년월일 8자리 로그인 (기본 동작)
--  ------------------------------------------------------------
--  감독자·아르바이트 로그인 시 생년월일을 8자리(YYYYMMDD) 전체로
--  대조합니다. schema.sql 의 hr_login 과 동일한 내용이므로
--  여러 번 실행해도 안전합니다.
--
--  ▶ 실행이 필요한 경우
--    이전에 "앞 6자리" 버전(01-birth-6-digits.sql)을 실행하셨다면,
--    이 파일을 실행해 8자리 대조로 되돌리세요.
--    실행한 적이 없다면 이미 8자리 상태이므로 실행하지 않아도 됩니다.
--
--  Supabase 대시보드 > SQL Editor 에 붙여넣고 Run 하세요.
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
    -- 생년월일은 8자리(YYYYMMDD) 전체로 대조한다.
    -- 2002-04-11 / 20020411 어느 형식으로 저장·입력해도 숫자만 뽑아 비교한다.
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

grant execute on function public.hr_login(text, text, text) to anon, authenticated;
