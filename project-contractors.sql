-- =============================================================
-- SAREEM cost DB — project contractors
-- Adds the "المقاولون" card on the كميات وتكلفة المشروع tab.
-- Run in the Supabase SQL editor as postgres. Re-runnable.
--
-- DEPENDENCY: user-roles.sql must already be applied — this script
-- reuses its helper functions (is_active_user, role_in, user_project_id).
-- =============================================================

create table if not exists public.project_contractors (
  id             text primary key,
  project_id     text not null references public.projects(id) on delete cascade,
  name           text not null,
  scope          text,
  contract_value numeric(14,2) not null default 0,
  paid_amount    numeric(14,2) default 0,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- nullable on purpose: the client upserts every row with an identical key set and
-- writes an explicit null for any column a row lacks, which a NOT NULL column rejects
alter table public.project_contractors
  add column if not exists paid_amount numeric(14,2) default 0;

alter table public.project_contractors enable row level security;
grant select, insert, update, delete on public.project_contractors to authenticated;

-- keep updated_at current on every edit
create or replace function public.project_contractors_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists project_contractors_touch_trg on public.project_contractors;
create trigger project_contractors_touch_trg before update on public.project_contractors
  for each row execute function public.project_contractors_touch();

-- ---------- RLS: same shape as project_quantities ----------
-- an engineer only ever reads the contractors of their own project;
-- admin + data_entry write; delete is admin + data_entry (needed for restore).
do $$
declare p text;
begin
  foreach p in array array['sel','ins','upd','del'] loop
    execute format('drop policy if exists %I on public.project_contractors', p);
  end loop;
end $$;

create policy sel on public.project_contractors for select to authenticated
  using (public.is_active_user() and (public.role_in('admin','owner','data_entry') or project_id::text = public.user_project_id()));
create policy ins on public.project_contractors for insert to authenticated
  with check (public.is_active_user() and public.role_in('admin','data_entry'));
create policy upd on public.project_contractors for update to authenticated
  using (public.is_active_user() and public.role_in('admin','data_entry'))
  with check (public.is_active_user() and public.role_in('admin','data_entry'));
create policy del on public.project_contractors for delete to authenticated
  using (public.role_in('admin','data_entry'));

select count(*) as contractor_rows from public.project_contractors;
