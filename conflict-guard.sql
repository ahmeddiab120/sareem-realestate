-- =============================================================
-- SAREEM cost DB — conflict guard (updated_at on every table)
-- Gives every editable table a trustworthy "last edited" stamp so
-- the app can warn when two users edit the same record at once.
-- Run in the Supabase SQL editor as postgres. Re-runnable.
--
-- units and project_contractors already have updated_at + their own
-- touch triggers (units.sql / project-contractors.sql), so this
-- script covers the six core tables. If one of them already has the
-- column, the statements below are harmless no-ops.
-- =============================================================

-- one shared trigger function: stamp now() on every UPDATE
create or replace function public.touch_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

do $$
declare t text;
begin
  foreach t in array array['materials','suppliers','prices','projects','project_quantities','purchase_orders'] loop
    execute format('alter table public.%I add column if not exists updated_at timestamptz not null default now()', t);
    execute format('drop trigger if exists %I on public.%I', t || '_touch_trg', t);
    execute format('create trigger %I before update on public.%I for each row execute function public.touch_updated_at()', t || '_touch_trg', t);
  end loop;
end $$;

-- proof: every data table should now report an updated_at column
select table_name
from information_schema.columns
where table_schema = 'public'
  and column_name = 'updated_at'
  and table_name in ('materials','suppliers','prices','projects','project_quantities','purchase_orders','project_contractors','units')
order by table_name;
