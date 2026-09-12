-- SIH Secure DMS: replace PaddleOCR storage with Case AI
-- Run this ONCE in Supabase SQL Editor.

-- 1. Case AI switches and ownership
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS head_user_id uuid;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_enabled_by uuid;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_enabled_at timestamptz;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_provider text;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_model text;

-- Populate/repair existing cases using an explicit Department Head.
UPDATE public.cases c
SET head_user_id = COALESCE(
    (SELECT u.user_id
     FROM public.users u
     JOIN public.employee_registry er ON er.employee_id=u.employee_id
     WHERE er.department_id=(SELECT er2.department_id FROM public.users u2 JOIN public.employee_registry er2 ON er2.employee_id=u2.employee_id WHERE u2.user_id=c.created_by LIMIT 1)
       AND (lower(coalesce(er.rank,'')) LIKE '%department head%' OR lower(coalesce(er.designation,'')) LIKE '%department head%')
     LIMIT 1),
    (SELECT da.user_id
     FROM public.department_admins da
     WHERE da.department_id=(SELECT er2.department_id FROM public.users u2 JOIN public.employee_registry er2 ON er2.employee_id=u2.employee_id WHERE u2.user_id=c.created_by LIMIT 1)
       AND da.can_delegate=true LIMIT 1),
    c.created_by
);

-- Explicit demo Head: Secunderabad Police
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO public.departments (name,type,jurisdiction,official_email_domain)
SELECT 'Secunderabad Police','police','Secunderabad, Hyderabad','demo.police'
WHERE NOT EXISTS (SELECT 1 FROM public.departments WHERE name='Secunderabad Police');

INSERT INTO public.employee_registry (employee_id,full_name,department_id,rank,designation,station_name,official_email,registry_status)
SELECT 'SEC-PS-HEAD-001','Secunderabad Police Head',d.department_id,'Department Head','Department Head','Secunderabad Police','karthikpeddoju1006@gmail.com','verified'
FROM public.departments d WHERE d.name='Secunderabad Police'
AND NOT EXISTS (SELECT 1 FROM public.employee_registry WHERE employee_id='SEC-PS-HEAD-001');

-- Ensure the new Head's official email is your email.
UPDATE public.employee_registry
SET official_email = 'karthikpeddoju1006@gmail.com'
WHERE employee_id = 'SEC-PS-HEAD-001';

INSERT INTO public.users (employee_id,password_hash,account_status,must_change_password)
SELECT 'SEC-PS-HEAD-001',crypt('Demo@1234',gen_salt('bf')),'active',false
WHERE NOT EXISTS (SELECT 1 FROM public.users WHERE employee_id='SEC-PS-HEAD-001');

INSERT INTO public.department_admins (user_id,department_id,can_invite_employees,can_delegate)
SELECT u.user_id,d.department_id,true,true
FROM public.users u JOIN public.departments d ON d.name='Secunderabad Police'
WHERE u.employee_id='SEC-PS-HEAD-001'
AND NOT EXISTS (SELECT 1 FROM public.department_admins da WHERE da.user_id=u.user_id AND da.department_id=d.department_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'cases_head_user_id_fkey'
    ) THEN
        ALTER TABLE public.cases
        ADD CONSTRAINT cases_head_user_id_fkey
        FOREIGN KEY (head_user_id) REFERENCES public.users(user_id);
    END IF;
END $$;

-- 2. AI extraction result per immutable document version
CREATE TABLE IF NOT EXISTS public.case_ai_documents (
    ai_document_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL REFERENCES public.cases(case_id) ON DELETE CASCADE,
    document_id uuid NOT NULL REFERENCES public.documents(document_id) ON DELETE CASCADE,
    version_id uuid NOT NULL REFERENCES public.document_versions(version_id) ON DELETE CASCADE,
    document_type text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','processing','completed','failed')),
    provider text,
    model text,
    fallback_used boolean NOT NULL DEFAULT false,
    extracted_text text,
    pages jsonb NOT NULL DEFAULT '[]'::jsonb,
    confidence numeric,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE(version_id)
);

CREATE INDEX IF NOT EXISTS idx_case_ai_documents_case
    ON public.case_ai_documents(case_id);
CREATE INDEX IF NOT EXISTS idx_case_ai_documents_status
    ON public.case_ai_documents(status);

-- Processing telemetry for user-visible AI progress. Safe to re-run.
ALTER TABLE public.case_ai_documents
    ADD COLUMN IF NOT EXISTS queued_at timestamptz;
ALTER TABLE public.case_ai_documents
    ADD COLUMN IF NOT EXISTS started_at timestamptz;
ALTER TABLE public.case_ai_documents
    ADD COLUMN IF NOT EXISTS stage text;
ALTER TABLE public.case_ai_documents
    ADD COLUMN IF NOT EXISTS progress_percent integer NOT NULL DEFAULT 0;
ALTER TABLE public.case_ai_documents
    ADD COLUMN IF NOT EXISTS estimated_seconds integer;

-- 3. Searchable case-specific chunks. These are derived data only.
CREATE TABLE IF NOT EXISTS public.case_ai_chunks (
    chunk_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL REFERENCES public.cases(case_id) ON DELETE CASCADE,
    document_id uuid NOT NULL REFERENCES public.documents(document_id) ON DELETE CASCADE,
    version_id uuid NOT NULL REFERENCES public.document_versions(version_id) ON DELETE CASCADE,
    page_number integer,
    chunk_index integer NOT NULL,
    text text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(version_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS idx_case_ai_chunks_case_version
    ON public.case_ai_chunks(case_id, version_id);

-- 4. Per-case AI conversation history
CREATE TABLE IF NOT EXISTS public.case_ai_messages (
    message_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL REFERENCES public.cases(case_id) ON DELETE CASCADE,
    user_id uuid REFERENCES public.users(user_id),
    role text NOT NULL CHECK (role IN ('user','assistant')),
    content text NOT NULL,
    sources jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_ai_messages_case_time
    ON public.case_ai_messages(case_id, created_at);

-- 5. PaddleOCR is no longer used. Its old derived OCR table is unnecessary.
DROP TABLE IF EXISTS public.document_ocr CASCADE;

-- IMPORTANT: this does NOT delete documents, document_versions, hashes,
-- signatures, members, storage files, or case records.

-- ============================================================
-- 7. External participant self-service accounts
-- External users are NOT internal users. Their account is the
-- case-scoped external_case_participants row itself.
-- ============================================================
ALTER TABLE public.external_case_participants
    ADD COLUMN IF NOT EXISTS password_hash text;
ALTER TABLE public.external_case_participants
    ADD COLUMN IF NOT EXISTS password_set_at timestamptz;
ALTER TABLE public.external_case_participants
    ADD COLUMN IF NOT EXISTS last_login_at timestamptz;

CREATE TABLE IF NOT EXISTS public.external_sessions (
    session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_id uuid NOT NULL REFERENCES public.external_case_participants(participant_id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_external_sessions_participant
    ON public.external_sessions(participant_id);
CREATE INDEX IF NOT EXISTS idx_external_sessions_expires
    ON public.external_sessions(expires_at);

-- Remove stale external sessions automatically.
CREATE OR REPLACE FUNCTION public.cleanup_external_sessions()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM public.external_sessions WHERE expires_at < now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_cleanup_external_sessions ON public.external_sessions;
CREATE TRIGGER trg_cleanup_external_sessions
AFTER INSERT ON public.external_sessions
FOR EACH ROW EXECUTE FUNCTION public.cleanup_external_sessions();

-- When a case is closed/completed/archived, delete the entire
-- case-scoped external account. external_sessions disappear by CASCADE.
CREATE OR REPLACE FUNCTION public.delete_external_accounts_on_case_close()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF lower(coalesce(NEW.status, '')) IN ('closed','completed','archived')
       AND lower(coalesce(OLD.status, '')) NOT IN ('closed','completed','archived') THEN
        DELETE FROM public.external_case_participants
        WHERE case_id = NEW.case_id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_delete_external_accounts_on_case_close ON public.cases;
CREATE TRIGGER trg_delete_external_accounts_on_case_close
AFTER UPDATE OF status ON public.cases
FOR EACH ROW EXECUTE FUNCTION public.delete_external_accounts_on_case_close();

-- Clean up any external accounts belonging to cases already closed.
DELETE FROM public.external_case_participants p
USING public.cases c
WHERE p.case_id = c.case_id
  AND lower(coalesce(c.status, '')) IN ('closed','completed','archived');

-- Existing FIR records generated as PDFs should be marked as pdf.
UPDATE public.documents
SET file_type = 'pdf'
WHERE document_type = 'fir'
  AND file_type <> 'pdf';
