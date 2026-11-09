-- =============================================================
-- SAREEM cost DB — apartment units (الوحدات السكنية)
-- Adds the "الوحدات السكنية" tab: sales status of every unit in a project.
-- Run in the Supabase SQL editor as postgres. Re-runnable.
--
-- DEPENDENCY: user-roles.sql must already be applied — this script
-- reuses its helper functions (is_active_user, role_in).
--
-- ACCESS: read = admin + owner + data_entry; write = admin + data_entry.
-- The engineer role has NO access at all — units carry buyer names and
-- actual sale prices, which are more sensitive than cost data.
-- =============================================================

create table if not exists public.units (
  id          text primary key,
  project_id  text not null references public.projects(id) on delete cascade,
  code        text not null,
  area        numeric(10,2) not null default 0,
  rooms       integer       not null default 0,
  price       numeric(14,2) not null default 0,  -- السعر مع العمولة
  sale        numeric(14,2) not null default 0,  -- سعر البيع الفعلي
  paid        numeric(14,2) not null default 0,  -- المُستلم من المشتري
  buyer       text,
  status      text not null default 'av' check (status in ('av','pend','done')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- nullable on purpose: the client upserts every row with an identical key set and
-- writes an explicit null for any column a row lacks, which a NOT NULL column rejects.
-- buyer and paid are the columns an older or freshly built row may omit.
alter table public.units add column if not exists paid numeric(14,2) default 0;
alter table public.units add column if not exists buyer text;

alter table public.units enable row level security;
grant select, insert, update, delete on public.units to authenticated;

-- keep updated_at current on every edit
create or replace function public.units_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists units_touch_trg on public.units;
create trigger units_touch_trg before update on public.units
  for each row execute function public.units_touch();

-- ---------- RLS ----------
-- re-runnable: clear any policy this script creates before re-creating it
do $$
declare p text;
begin
  foreach p in array array['sel','ins','upd','del'] loop
    execute format('drop policy if exists %I on public.units', p);
  end loop;
end $$;

-- read: admin + owner + data_entry only (the engineer has no access to sales data)
create policy sel on public.units for select to authenticated
  using (public.is_active_user() and public.role_in('admin','owner','data_entry'));
-- write: admin + data_entry (the owner is read-only)
create policy ins on public.units for insert to authenticated
  with check (public.is_active_user() and public.role_in('admin','data_entry'));
create policy upd on public.units for update to authenticated
  using (public.is_active_user() and public.role_in('admin','data_entry'))
  with check (public.is_active_user() and public.role_in('admin','data_entry'));
create policy del on public.units for delete to authenticated
  using (public.role_in('admin','data_entry'));

select count(*) as unit_rows from public.units;
