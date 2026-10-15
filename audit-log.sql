-- =============================================================
-- SAREEM cost DB — change log (audit trail)
-- Adds the "سجل التغييرات" tab: who changed what, when, and from
-- which value to which value.
-- Run in the Supabase SQL editor as postgres. Re-runnable.
--
-- DEPENDENCY: user-roles.sql must already be applied — this script
-- reuses its helper functions (ur_email, role_in).
--
-- Watched tables (the sensitive ones only):
--   prices, project_quantities, purchase_orders, project_contractors
-- =============================================================

create table if not exists public.audit_log (
  id          bigint generated always as identity primary key,
  ts          timestamptz not null default now(),
  actor_email text not null default '',
  table_name  text not null,
  row_id      text,
  project_id  text,
  action      text not null check (action in ('insert','update','delete')),
  item_label  text,
  changes     jsonb not null default '{}'::jsonb
);

create index if not exists audit_log_ts_idx    on public.audit_log (ts desc);
create index if not exists audit_log_table_idx on public.audit_log (table_name);

alter table public.audit_log enable row level security;

-- append-only: the app can read the log but never write to it.
-- supabase grants every privilege on public tables by default, so the
-- write grants must be taken back explicitly.
revoke insert, update, delete on public.audit_log from anon, authenticated;
grant  select on public.audit_log to authenticated;

drop policy if exists sel_audit on public.audit_log;
create policy sel_audit on public.audit_log for select to authenticated
  using (public.role_in('admin','data_entry'));

-- ---------- capture trigger ----------
create or replace function public.audit_capture() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_new     jsonb := case when tg_op = 'DELETE' then null else to_jsonb(new) end;
  v_old     jsonb := case when tg_op = 'INSERT' then null else to_jsonb(old) end;
  v_changes jsonb := '{}'::jsonb;
  v_label   text  := '';
  v_mid     text;
  v_sid     text;
  k         text;
begin
  -- a save rewrites every row of the table, so an update with no real
  -- difference must not pollute the log
  for k in select jsonb_object_keys(coalesce(v_new, v_old)) loop
    if k in ('id','created_at','updated_at') then
      continue;
    end if;
    if k = 'items' then
      -- purchase order lines are a big array: keep the size, not the content
      if jsonb_typeof(coalesce(v_new, v_old) -> k) = 'array' then
        v_changes := v_changes || jsonb_build_object(k, jsonb_build_object(
          'from', case when v_old is null or jsonb_typeof(v_old -> k) <> 'array' then null else jsonb_array_length(v_old -> k) end,
          'to',   case when v_new is null or jsonb_typeof(v_new -> k) <> 'array' then null else jsonb_array_length(v_new -> k) end
        ));
      end if;
    elsif tg_op = 'UPDATE' then
      if v_new -> k is distinct from v_old -> k then
        v_changes := v_changes || jsonb_build_object(
          k, jsonb_build_object('from', v_old -> k, 'to', v_new -> k)
        );
      end if;
    elsif tg_op = 'INSERT' then
      v_changes := v_changes || jsonb_build_object(k, jsonb_build_object('from', null, 'to', v_new -> k));
    else
      v_changes := v_changes || jsonb_build_object(k, jsonb_build_object('from', v_old -> k, 'to', null));
    end if;
  end loop;

  if tg_op = 'UPDATE' and v_changes = '{}'::jsonb then
    return new;
  end if;

  v_mid := coalesce(v_new ->> 'material_id', v_old ->> 'material_id');
  v_sid := coalesce(v_new ->> 'supplier_id', v_old ->> 'supplier_id');

  if tg_table_name = 'prices' then
    v_label := 'سعر ' || coalesce((select name_ar from public.materials where id = v_mid), 'مادة محذوفة')
            || ' — ' || coalesce((select name from public.suppliers where id = v_sid), 'مورد محذوف');
  elsif tg_table_name = 'project_quantities' then
    v_label := 'بند كمية: ' || coalesce((select name_ar from public.materials where id = v_mid), 'مادة محذوفة');
  elsif tg_table_name = 'purchase_orders' then
    v_label := 'أمر شراء ' || coalesce(v_new ->> 'po_number', v_old ->> 'po_number', '');
  elsif tg_table_name = 'project_contractors' then
    v_label := 'مقاول: ' || coalesce(v_new ->> 'name', v_old ->> 'name', '');
  end if;

  insert into public.audit_log (actor_email, table_name, row_id, project_id, action, item_label, changes)
  values (
    public.ur_email(),
    tg_table_name,
    coalesce(v_new ->> 'id', v_old ->> 'id'),
    coalesce(v_new ->> 'project_id', v_old ->> 'project_id'),
    lower(tg_op),
    v_label,
    v_changes
  );

  return case when tg_op = 'DELETE' then old else new end;
end $$;

-- tables that do not exist yet (e.g. project_contractors before its own
-- script was run) are skipped with a notice instead of failing the run
do $$
declare t text;
begin
  foreach t in array array['prices','project_quantities','purchase_orders','project_contractors'] loop
    if to_regclass('public.' || t) is null then
      raise notice 'table public.% does not exist yet — skipped', t;
      continue;
    end if;
    execute format('drop trigger if exists audit_capture_trg on public.%I', t);
    execute format(
      'create trigger audit_capture_trg after insert or update or delete on public.%I
         for each row execute function public.audit_capture()', t);
  end loop;
end $$;

select c.relname as watched_table
from pg_trigger tg
join pg_class c on c.oid = tg.tgrelid
where tg.tgname = 'audit_capture_trg' and not tg.tgisinternal
order by 1;
