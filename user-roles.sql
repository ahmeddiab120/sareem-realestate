-- =============================================================
-- SAREEM cost DB — roles & permissions (phase 1)
-- Run in the Supabase SQL editor as postgres. Re-runnable.
-- Roles: admin | owner | engineer | data_entry
-- Users are keyed by EMAIL because the browser cannot list auth.users.
-- =============================================================

create table if not exists public.user_roles (
  email      text primary key,
  role       text not null default 'owner' check (role in ('admin','owner','engineer','data_entry')),
  project_id text,
  disabled   boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.user_roles enable row level security;
grant select, insert, update, delete on public.user_roles to authenticated;

-- emails are matched case-insensitively, so keep the stored value lowercase
create or replace function public.user_roles_norm_email() returns trigger
language plpgsql as $$
begin
  new.email := lower(trim(new.email));
  return new;
end $$;

drop trigger if exists user_roles_norm_email_trg on public.user_roles;
create trigger user_roles_norm_email_trg before insert or update on public.user_roles
  for each row execute function public.user_roles_norm_email();

-- ---------- helper functions (security definer: no recursive RLS) ----------
create or replace function public.ur_email() returns text
language sql stable security definer set search_path = public as $$
  select lower(coalesce(auth.jwt()->>'email', ''));
$$;

create or replace function public.ur_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.user_roles where email = public.ur_email();
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.user_roles where email = public.ur_email()) = 'admin', false);
$$;

create or replace function public.role_in(variadic roles text[]) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.user_roles where email = public.ur_email()) = any(roles), false);
$$;

-- accounts with no row yet count as active (read-only) until an admin assigns them
create or replace function public.is_active_user() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select not disabled from public.user_roles where email = public.ur_email()), true);
$$;

create or replace function public.user_project_id() returns text
language sql stable security definer set search_path = public as $$
  select project_id from public.user_roles where email = public.ur_email();
$$;

-- ---------- drop the old wide-open policies ----------
drop policy if exists authenticated_full_access on public.materials;
drop policy if exists authenticated_full_access on public.suppliers;
drop policy if exists authenticated_full_access on public.prices;
drop policy if exists authenticated_full_access on public.projects;
drop policy if exists authenticated_full_access on public.project_quantities;
drop policy if exists authenticated_full_access on public.purchase_orders;
drop policy if exists sel_own_or_admin on public.user_roles;
drop policy if exists ins_bootstrap_or_admin on public.user_roles;
drop policy if exists upd_admin on public.user_roles;
drop policy if exists del_admin on public.user_roles;

-- re-runnable: clear any policy this script creates before re-creating it
do $$
declare t text; p text;
begin
  foreach t in array array['materials','suppliers','prices','projects','project_quantities','purchase_orders'] loop
    foreach p in array array['sel','ins','upd','del'] loop
      execute format('drop policy if exists %I on public.%I', p, t);
    end loop;
  end loop;
end $$;

-- ---------- materials / suppliers / prices ----------
-- read: every active account. write: admin + data_entry. delete: admin only.
do $$
declare t text;
begin
  foreach t in array array['materials','suppliers','prices'] loop
    execute format('create policy sel on public.%I for select to authenticated using (public.is_active_user())', t);
    execute format('create policy ins on public.%I for insert to authenticated with check (public.is_active_user() and public.role_in(''admin'',''data_entry''))', t);
    execute format('create policy upd on public.%I for update to authenticated using (public.is_active_user() and public.role_in(''admin'',''data_entry'')) with check (public.is_active_user() and public.role_in(''admin'',''data_entry''))', t);
    execute format('create policy del on public.%I for delete to authenticated using (public.is_admin())', t);
  end loop;
end $$;

-- ---------- projects ----------
-- an engineer only ever sees the project they are assigned to
create policy sel on public.projects for select to authenticated
  using (public.is_active_user() and (public.role_in('admin','owner','data_entry') or id::text = public.user_project_id()));
create policy ins on public.projects for insert to authenticated
  with check (public.is_active_user() and public.role_in('admin','data_entry'));
create policy upd on public.projects for update to authenticated
  using (public.is_active_user() and public.role_in('admin','data_entry'))
  with check (public.is_active_user() and public.role_in('admin','data_entry'));
create policy del on public.projects for delete to authenticated using (public.is_admin());

-- ---------- project_quantities ----------
create policy sel on public.project_quantities for select to authenticated
  using (public.is_active_user() and (public.role_in('admin','owner','data_entry') or project_id::text = public.user_project_id()));
create policy ins on public.project_quantities for insert to authenticated
  with check (public.is_active_user() and (public.role_in('admin','data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id())));
create policy upd on public.project_quantities for update to authenticated
  using (public.is_active_user() and (public.role_in('admin','data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id())))
  with check (public.is_active_user() and (public.role_in('admin','data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id())));
create policy del on public.project_quantities for delete to authenticated
  using (public.is_admin() or public.role_in('data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id()));

-- ---------- purchase_orders ----------
create policy sel on public.purchase_orders for select to authenticated
  using (public.is_active_user() and (public.role_in('admin','owner','data_entry') or project_id::text = public.user_project_id()));
create policy ins on public.purchase_orders for insert to authenticated
  with check (public.is_active_user() and (public.role_in('admin','data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id())));
create policy upd on public.purchase_orders for update to authenticated
  using (public.is_active_user() and (public.role_in('admin','data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id())))
  with check (public.is_active_user() and (public.role_in('admin','data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id())));
create policy del on public.purchase_orders for delete to authenticated
  using (public.is_admin() or public.role_in('data_entry') or (public.role_in('engineer') and project_id::text = public.user_project_id()));

-- ---------- user_roles ----------
create policy sel_own_or_admin on public.user_roles for select to authenticated
  using (email = public.ur_email() or public.is_admin());
-- bootstrap: while the table is empty, the first account to log in claims admin
create policy ins_bootstrap_or_admin on public.user_roles for insert to authenticated
  with check (public.is_admin() or (email = public.ur_email() and role = 'admin' and not exists (select 1 from public.user_roles)));
create policy upd_admin on public.user_roles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy del_admin on public.user_roles for delete to authenticated using (public.is_admin());

-- ---------- seed the first admin ----------
-- while the table is empty, the oldest existing auth account becomes admin
-- (the client also bootstraps this on first login; seeding here avoids a race)
insert into public.user_roles (email, role)
select lower(u.email), 'admin'
from auth.users u
where not exists (select 1 from public.user_roles)
  and u.email is not null
  and u.created_at = (select min(created_at) from auth.users where email is not null)
on conflict (email) do nothing;

select email, role, project_id, disabled from public.user_roles order by created_at;
