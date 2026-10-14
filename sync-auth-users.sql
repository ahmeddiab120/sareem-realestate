-- =============================================================
-- SAREEM — sync Supabase auth accounts with the site's users page
-- Run in the Supabase SQL editor. Re-runnable. No secret keys.
--
-- Direction: Supabase Auth  ->  public.user_roles (automatic).
-- The browser can never read auth.users (that needs the secret
-- service key), so the linking is done inside the database.
--
-- FIX included here: "Failed to create user: Database error
-- creating new user" happened because the trigger below tried to
-- write the role 'pending' into user_roles, and a user_roles table
-- created by an EARLIER copy of user-roles.sql still carries the
-- old check constraint that only allows
-- admin/owner/engineer/data_entry. Step 0 repairs that constraint,
-- and every trigger now swallows its own errors so that a problem
-- in the roles table can never again block account creation.
-- =============================================================

-- 0) repair the role column: it must accept 'pending'
alter table public.user_roles drop constraint if exists user_roles_role_check;
alter table public.user_roles
  add constraint user_roles_role_check
  check (role in ('admin','owner','engineer','data_entry','pending'));
alter table public.user_roles alter column role set default 'pending';

-- 1) backfill: every account that already exists gets a row so it shows up now
insert into public.user_roles (email, role)
select lower(u.email), 'pending'
from auth.users u
where u.email is not null
  and not exists (select 1 from public.user_roles r where r.email = lower(u.email))
on conflict (email) do nothing;

-- 2) a new account created in Supabase appears in the site automatically
create or replace function public.handle_new_auth_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.email is not null then
    insert into public.user_roles (email, role)
    values (lower(new.email), 'pending')
    on conflict (email) do nothing;
  end if;
  return new;
exception when others then
  -- the site also registers itself on first login, so losing this row is
  -- recoverable; blocking the account creation is not
  return new;
end $$;

drop trigger if exists on_auth_user_created_roles on auth.users;
create trigger on_auth_user_created_roles after insert on auth.users
  for each row execute function public.handle_new_auth_user();

-- 3) an email edited in Supabase follows the user to their role row
create or replace function public.handle_auth_user_email() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.email is distinct from old.email and new.email is not null then
    update public.user_roles set email = lower(new.email) where email = lower(old.email);
    if not found then
      insert into public.user_roles (email, role)
      values (lower(new.email), 'pending')
      on conflict (email) do nothing;
    end if;
  end if;
  return new;
exception when others then
  return new;
end $$;

drop trigger if exists on_auth_user_email_roles on auth.users;
create trigger on_auth_user_email_roles after update of email on auth.users
  for each row execute function public.handle_auth_user_email();

-- 4) an account deleted in Supabase is removed from the site as well
create or replace function public.handle_deleted_auth_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  delete from public.user_roles where email = lower(old.email);
  return old;
exception when others then
  return old;
end $$;

drop trigger if exists on_auth_user_deleted_roles on auth.users;
create trigger on_auth_user_deleted_roles after delete on auth.users
  for each row execute function public.handle_deleted_auth_user();

-- 5) what the database actually looks like now.
--    The constraint line must contain 'pending'.
select
  (select pg_get_constraintdef(c.oid)
     from pg_constraint c
    where c.conrelid = 'public.user_roles'::regclass and c.contype = 'c') as role_constraint,
  (select string_agg(tgname, ', ' order by tgname)
     from pg_trigger
    where tgrelid = 'auth.users'::regclass and not tgisinternal)           as auth_users_triggers,
  (select count(*) from auth.users)                                        as supabase_accounts,
  (select count(*) from public.user_roles)                                 as rows_in_user_roles;

select email, role, project_id, disabled from public.user_roles order by created_at;
