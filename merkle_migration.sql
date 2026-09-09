-- NEMESIS integrity + external participant migration
-- Run once in Supabase SQL Editor.

ALTER TABLE public.document_versions
  ADD COLUMN IF NOT EXISTS version_number integer;

ALTER TABLE public.document_versions
  ADD COLUMN IF NOT EXISTS signing_key_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'document_versions_signing_key_id_fkey'
  ) THEN
    ALTER TABLE public.document_versions
      ADD CONSTRAINT document_versions_signing_key_id_fkey
      FOREIGN KEY (signing_key_id) REFERENCES public.user_keys(key_id);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.case_merkle_roots (
  merkle_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES public.cases(case_id) ON DELETE CASCADE,
  merkle_root text NOT NULL,
  version_set_fingerprint text NOT NULL,
  document_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid NULL REFERENCES public.users(user_id),
  anchor_reference text NULL,
  anchored_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_case_merkle_roots_case_created
  ON public.case_merkle_roots(case_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.external_case_participants (
  participant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES public.cases(case_id) ON DELETE CASCADE,
  invited_by uuid NOT NULL REFERENCES public.users(user_id),
  name text NOT NULL,
  email text NOT NULL,
  organization_name text NULL,
  organization_type text NOT NULL DEFAULT 'other',
  role text NOT NULL DEFAULT 'external_participant',
  purpose text NULL,
  allowed_document_types text[] NOT NULL DEFAULT '{}',
  permission_level text NOT NULL DEFAULT 'read',
  status text NOT NULL DEFAULT 'invited',
  invitation_token_hash text NULL,
  expires_at timestamptz NULL,
  accepted_at timestamptz NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT external_case_participants_permission_chk
    CHECK (permission_level IN ('read','upload','sign')),
  CONSTRAINT external_case_participants_status_chk
    CHECK (status IN ('invited','active','expired','revoked','completed'))
);

CREATE INDEX IF NOT EXISTS idx_external_case_participants_case
  ON public.external_case_participants(case_id);

-- Helpful unique guard: the same email can participate in many cases.
CREATE INDEX IF NOT EXISTS idx_external_case_participants_email_case
  ON public.external_case_participants(lower(email), case_id);

-- Backfill V1 for existing one-version documents.
WITH ranked AS (
  SELECT version_id,
         row_number() OVER (PARTITION BY document_id ORDER BY timestamp ASC, version_id ASC) AS rn
  FROM public.document_versions
)
UPDATE public.document_versions dv
SET version_number = ranked.rn
FROM ranked
WHERE dv.version_id = ranked.version_id
  AND dv.version_number IS NULL;

-- If you already have only one version per document, the first upload is V1.
