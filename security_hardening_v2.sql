-- SiteArchitect v2 security hardening (applied 2026-11-15).
-- Removes unnecessary direct API access to trigger functions.
-- Keeps the role-checking helper available to authenticated users
-- because it is used by RLS policies. Does not touch project data.
revoke execute on function public.sitearchitect_handle_new_user() from public, anon, authenticated;
revoke execute on function public.sitearchitect_touch_review() from public, anon, authenticated;
revoke execute on function public.sitearchitect_is_teacher() from public, anon;
grant execute on function public.sitearchitect_is_teacher() to authenticated;
