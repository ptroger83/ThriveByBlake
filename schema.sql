-- Thrive by Blake / The Peach Barn — storage schema
-- One profile per signed-in person, one log document per person (the app's full state as JSON).

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  name text,
  is_trainer boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.logs (
  user_id uuid primary key references auth.users(id) on delete cascade,
  json jsonb not null default '{}'::jsonb,
  updated_at bigint not null default 0,
  saved_at timestamptz not null default now()
);

-- make a profile row automatically when someone signs in for the first time
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- who is a trainer? (security definer so the policies below can ask without recursion)
create or replace function public.is_trainer()
returns boolean language sql security definer stable set search_path = public as $$
  select coalesce((select is_trainer from public.profiles where id = auth.uid()), false);
$$;

alter table public.profiles enable row level security;
alter table public.logs enable row level security;

drop policy if exists "profiles: own or trainer read" on public.profiles;
create policy "profiles: own or trainer read" on public.profiles
  for select using (id = auth.uid() or public.is_trainer());
drop policy if exists "profiles: own insert" on public.profiles;
create policy "profiles: own insert" on public.profiles
  for insert with check (id = auth.uid());
drop policy if exists "profiles: own or trainer update" on public.profiles;
create policy "profiles: own or trainer update" on public.profiles
  for update using (id = auth.uid() or public.is_trainer());

drop policy if exists "logs: own or trainer read" on public.logs;
create policy "logs: own or trainer read" on public.logs
  for select using (user_id = auth.uid() or public.is_trainer());
drop policy if exists "logs: own or trainer write" on public.logs;
create policy "logs: own or trainer write" on public.logs
  for insert with check (user_id = auth.uid() or public.is_trainer());
drop policy if exists "logs: own or trainer update" on public.logs;
create policy "logs: own or trainer update" on public.logs
  for update using (user_id = auth.uid() or public.is_trainer());

-- nobody deletes through the app
