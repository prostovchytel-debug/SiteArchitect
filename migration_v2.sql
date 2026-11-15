-- SiteArchitect 11 v2: grading and teacher comments.
-- SAFE MIGRATION for an existing installation: does not delete students, profiles or projects.
-- Run once in Supabase > SQL Editor as database administrator.
-- Enable Anonymous Sign-Ins separately under Authentication > Sign In / Providers.

begin;

create table if not exists public.site_project_reviews (
  project_id uuid primary key references public.site_projects(id) on delete cascade,
  grade smallint not null check (grade between 1 and 12),
  comment text not null default '' check (char_length(comment) <= 1500),
  reviewed_by uuid not null default auth.uid() references auth.users(id),
  reviewed_at timestamptz not null default now()
);

-- Refresh the reviewer and the review timestamp on each update.
create or replace function public.sitearchitect_touch_review()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.reviewed_at := now();
  new.reviewed_by := auth.uid();
  return new;
end;
$$;

drop trigger if exists sitearchitect_review_updated on public.site_project_reviews;
create trigger sitearchitect_review_updated
before update on public.site_project_reviews for each row
execute function public.sitearchitect_touch_review();

revoke all on function public.sitearchitect_touch_review() from public;

create index if not exists sa_reviews_reviewer_idx on public.site_project_reviews(reviewed_by);

alter table public.site_project_reviews enable row level security;
revoke all on table public.site_project_reviews from anon, authenticated;
grant select on public.site_project_reviews to authenticated;
grant insert(project_id, grade, comment) on public.site_project_reviews to authenticated;
grant update(grade, comment) on public.site_project_reviews to authenticated;

-- A student sees a review only of his/her own project.
-- A teacher sees all reviews.
drop policy if exists "sa_reviews_read" on public.site_project_reviews;
create policy "sa_reviews_read" on public.site_project_reviews
for select to authenticated
using (
  (select public.sitearchitect_is_teacher())
  or exists (
    select 1 from public.site_projects p
    where p.id = site_project_reviews.project_id
      and p.owner_id = (select auth.uid())
  )
);

-- Only a profile granted teacher rights by the DB administrator may grade.
-- Drafts cannot be graded until the student has submitted them.
drop policy if exists "sa_reviews_teacher_insert" on public.site_project_reviews;
create policy "sa_reviews_teacher_insert" on public.site_project_reviews
for insert to authenticated
with check (
  (select public.sitearchitect_is_teacher())
  and exists (
    select 1 from public.site_projects p
    where p.id = site_project_reviews.project_id and p.status = 'submitted'
  )
);

drop policy if exists "sa_reviews_teacher_update" on public.site_project_reviews;
create policy "sa_reviews_teacher_update" on public.site_project_reviews
for update to authenticated
using ((select public.sitearchitect_is_teacher()))
with check (
  (select public.sitearchitect_is_teacher())
  and exists (
    select 1 from public.site_projects p
    where p.id = site_project_reviews.project_id and p.status = 'submitted'
  )
);

-- Only the author may delete their unsubmitted draft; submitted work is retained.
-- Existing read/write policies for the actual project are not weakened.
drop policy if exists "sitearchitect_projects_delete_self" on public.site_projects;
create policy "sitearchitect_projects_delete_self" on public.site_projects
for delete to authenticated
using (owner_id = (select auth.uid()) and status = 'draft');

commit;

-- NOTE: Anonymous Supabase Auth users have the PostgreSQL "authenticated" role.
-- Do NOT grant read access to the database "anon" role and do NOT use service_role in config.js.
-- This migration can be re-run safely; prior reviews/projects remain intact.
