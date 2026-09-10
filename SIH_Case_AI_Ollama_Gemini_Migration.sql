-- SIH Secure DMS: replace PaddleOCR storage with Case AI
-- Run this ONCE in Supabase SQL Editor.

-- 1. Case AI switches and ownership
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS head_user_id uuid;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_enabled_by uuid;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_enabled_at timestamptz;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_provider text;
ALTER TABLE public.cases ADD COLUMN IF NOT EXISTS ai_model text;

-- Repair existing cases and assign the actual Department Head.
-- In this SIH schema, department_admins.can_delegate marks the designated
-- Head/management account for a department. The FIR filer is only the
-- fallback when no designated Head exists.
UPDATE public.cases c
SET head_user_id = COALESCE(
    (
        SELECT da.user_id
        FROM public.users creator
        JOIN public.employee_registry er
          ON er.employee_id = creator.employee_id
        JOIN public.department_admins da
          ON da.department_id = er.department_id
         AND da.can_delegate = true
        WHERE creator.user_id = c.created_by
        LIMIT 1
    ),
    c.created_by
);

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
