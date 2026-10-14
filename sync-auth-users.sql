-- =============================================================
-- SAREEM — sync Supabase auth accounts with the site's users page
-- Run in the Supabase SQL editor. Re-runnable. No secret keys.
--
-- Direction: Supabase Auth  ->  public.user_roles (automatic).
-- The browser can never read auth.users (that needs the secret
-- service key), so the linking is done inside the database.
-- =============================================================

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
end $$;

drop trigger if exists on_auth_user_deleted_roles on auth.users;
create trigger on_auth_user_deleted_roles after delete on auth.users
  for each row execute function public.handle_deleted_auth_user();

-- what you should see: every Supabase account, your own one still 'admin'
select email, role, project_id, disabled from public.user_roles order by created_at;
