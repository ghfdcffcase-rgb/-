-- Username identities for ordinary MITHAQ members.
-- Password hashes remain exclusively in Supabase Auth; this table stores no credentials.
create table if not exists public.member_usernames (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  username_normalized text generated always as (lower(username)) stored,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint member_usernames_username_length check (char_length(username) between 3 and 30),
  constraint member_usernames_username_format check (username ~ '^[[:alnum:]_][[:alnum:]_.-]*$'),
  constraint member_usernames_username_normalized_key unique (username_normalized)
);
alter table public.member_usernames enable row level security;
revoke all on public.member_usernames from anon, authenticated;
grant all on public.member_usernames to service_role;
