-- ============================================================
-- SIH Secure DMS — Password Reset
-- Run once in Supabase SQL Editor.
-- ============================================================

create table if not exists public.password_reset_tokens (
    reset_id uuid primary key default gen_random_uuid(),
    user_id uuid not null references public.users(user_id) on delete cascade,
    token_hash text not null,
    expires_at timestamptz not null,
    status text not null default 'pending'
        check (status in ('pending','used','expired','revoked','locked')),
    attempts integer not null default 0
        check (attempts >= 0),
    created_at timestamptz not null default now()
);

create index if not exists idx_password_reset_tokens_user_status
    on public.password_reset_tokens(user_id, status, created_at desc);

create index if not exists idx_password_reset_tokens_expires
    on public.password_reset_tokens(expires_at);

-- ============================================================
-- DEMO HEAD ACCOUNT PASSWORD REPAIR
--
-- This repairs the known Secunderabad Police Head demo account.
-- Password used by the demo account after this migration:
--     Demo@1234
--
-- bcrypt is generated inside PostgreSQL. The plaintext password is
-- never stored; only the bcrypt hash is stored in users.password_hash.
-- ============================================================

update public.users u
set password_hash = crypt('Demo@1234', gen_salt('bf', 12)),
    account_status = case
        when u.account_status in ('activated','profile_pending','active')
            then u.account_status
        else 'activated'
    end,
    must_change_password = false
from public.employee_registry e
where e.employee_id = u.employee_id
  and e.employee_id = 'SEC-PS-HEAD-001';

-- ============================================================
-- OPTIONAL DEMO REPAIR FOR ALL DEPARTMENT HEADS
--
-- Uncomment ONLY if all demo Department Head accounts are supposed
-- to use the same demo password. Do not use this for production.
-- ============================================================

-- update public.users u
-- set password_hash = crypt('Demo@1234', gen_salt('bf', 12)),
--     account_status = case
--         when u.account_status in ('activated','profile_pending','active')
--             then u.account_status
--         else 'activated'
--     end,
--     must_change_password = false
-- from public.employee_registry e
-- where e.employee_id = u.employee_id
--   and (
--       lower(coalesce(e.rank,'')) like '%department head%'
--       or lower(coalesce(e.designation,'')) like '%department head%'
--   );

-- ============================================================
-- CLEANUP (optional): old expired/used reset records can be removed.
-- ============================================================

-- delete from public.password_reset_tokens
-- where created_at < now() - interval '30 days';
