-- Crows Nest Place — petition signatures
-- Run once in the Supabase SQL Editor.

create table if not exists public.signatures (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  name        text not null,
  suburb      text not null,
  contact     text not null,        -- email or phone, as given on the form
  comments    text,
  ip_hash     text,                 -- salted hash, never the raw IP
  user_agent  text
);

-- One signature per person: dedupe on the contact they gave,
-- ignoring case and surrounding whitespace.
create unique index if not exists signatures_contact_unique
  on public.signatures (lower(trim(contact)));

-- Keeps the per-IP rate-limit check fast as the table grows.
create index if not exists signatures_ip_recent
  on public.signatures (ip_hash, created_at desc);

-- Lock the table down.
-- RLS is ON with NO policies, so the public anon key can neither read
-- nor write. Only the service-role key -- held by the Vercel function
-- and never sent to the browser -- can touch this table.
alter table public.signatures enable row level security;
