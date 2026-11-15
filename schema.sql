-- SiteArchitect 11: schema, safe roles and RLS.
-- Execute in Supabase Dashboard > SQL Editor as project administrator.
-- Run once on a fresh Supabase project.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default 'Користувач' check (char_length(full_name) between 1 and 100),
  class_name text not null default '' check (char_length(class_name) <= 20),
  role text not null default 'student' check (role in ('student', 'teacher')),
  created_at timestamptz not null default now()
);

create table if not exists public.site_projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  project jsonb not null default '{}'::jsonb,
  status text not null default 'draft' check (status in ('draft','submitted')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists site_projects_owner_idx on public.site_projects(owner_id);
create index if not exists site_projects_status_idx on public.site_projects(status);
create index if not exists site_projects_updated_idx on public.site_projects(updated_at desc);

-- Role is NOT read from user_metadata. Users can modify their own metadata.
-- Trigger only creates STUDENT profiles. Only a DB administrator promotes a teacher.
create or replace function public.sitearchitect_handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles(id, full_name, class_name, role)
  values (
    new.id,
    left(coalesce(nullif(btrim(new.raw_user_meta_data ->> 'full_name'), ''), 'Користувач'), 100),
    left(coalesce(btrim(new.raw_user_meta_data ->> 'class_name'), ''), 20),
    'student'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists sitearchitect_on_auth_user_created on auth.users;
create trigger sitearchitect_on_auth_user_created
  after insert on auth.users for each row execute procedure public.sitearchitect_handle_new_user();

-- Backfill profiles if users registered before schema.sql was installed.
insert into public.profiles(id,full_name,class_name,role)
select id,
       left(coalesce(nullif(btrim(raw_user_meta_data->>'full_name'),''),'Користувач'),100),
       left(coalesce(btrim(raw_user_meta_data->>'class_name'),''),20),
       'student'
from auth.users
on conflict (id) do nothing;

create or replace function public.sitearchitect_is_teacher()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'teacher'
  );
$$;

revoke all on function public.sitearchitect_is_teacher() from public;
revoke all on function public.sitearchitect_handle_new_user() from public;
grant execute on function public.sitearchitect_is_teacher() to authenticated;

alter table public.profiles enable row level security;
alter table public.site_projects enable row level security;

-- IMPORTANT: previous implicit grants may be wide. Remove, then grant only necessary columns.
revoke all on table public.profiles from anon, authenticated;
revoke all on table public.site_projects from anon, authenticated;

grant select on table public.profiles to authenticated;
grant update(full_name, class_name) on table public.profiles to authenticated;

grant select on table public.site_projects to authenticated;
grant insert(owner_id, project, status) on table public.site_projects to authenticated;
grant update(project, status, updated_at) on table public.site_projects to authenticated;
grant delete on table public.site_projects to authenticated;

-- Profiles: each person reads their own profile, teacher reads all profiles.
drop policy if exists "sitearchitect_profiles_select" on public.profiles;
create policy "sitearchitect_profiles_select" on public.profiles
for select to authenticated
using (id = (select auth.uid()) or (select public.sitearchitect_is_teacher()));

drop policy if exists "sitearchitect_profiles_update_self" on public.profiles;
create policy "sitearchitect_profiles_update_self" on public.profiles
for update to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

-- Students can access only their own projects. Teachers have read-only access to all.
drop policy if exists "sitearchitect_projects_select" on public.site_projects;
create policy "sitearchitect_projects_select" on public.site_projects
for select to authenticated
using (owner_id = (select auth.uid()) or (select public.sitearchitect_is_teacher()));

drop policy if exists "sitearchitect_projects_insert_self" on public.site_projects;
create policy "sitearchitect_projects_insert_self" on public.site_projects
for insert to authenticated
with check (owner_id = (select auth.uid()));

drop policy if exists "sitearchitect_projects_update_self" on public.site_projects;
create policy "sitearchitect_projects_update_self" on public.site_projects
for update to authenticated
using (owner_id = (select auth.uid()))
with check (owner_id = (select auth.uid()));

drop policy if exists "sitearchitect_projects_delete_self" on public.site_projects;
create policy "sitearchitect_projects_delete_self" on public.site_projects
for delete to authenticated
using (owner_id = (select auth.uid()));

-- AFTER the teacher registers on the site, promote the profile through SQL Editor.
-- REPLACE the email with the teacher's actual registered address and run the command separately:
-- update public.profiles
-- set role = 'teacher'
-- where id = (select id from auth.users where email = 'your-teacher-email@example.com');

-- SECURITY CHECKS (manual):
-- * No data is accessible via the anon database role.
-- * Authenticated student SELECT sees own profiles/project rows only.
-- * Teacher SELECT sees all; teacher cannot update another student's project.
-- * Users cannot update role or owner_id using the Data API (column grants).
-- * Never put a secret/service_role key into config.js or a GitHub repository.
