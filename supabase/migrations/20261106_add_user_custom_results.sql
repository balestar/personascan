alter table public.personascan_users
  add column if not exists custom_results jsonb not null default '[]'::jsonb;

comment on column public.personascan_users.custom_results is
  'Admin-authored flags (bot presence, RPC, mobile ping, etc.) that follow the user across all sessions.';
