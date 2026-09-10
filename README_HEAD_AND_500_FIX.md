# SIH Case AI — Head + 500 Fix

## Fixes
- Login 500 `Object of type bytes is not JSON serializable`: encrypted/public key bytes are decoded before Supabase JSON insert.
- FIR creation 500: fixed the incorrect `generate_fir_number(current_user["department_type"])` call.
- Department Head resolution: explicit `employee_registry` rank/designation `Department Head` is preferred, with legacy `department_admins.can_delegate` fallback.
- Existing case Head is repaired when Case AI status is requested.
- Case AI UI displays the resolved Case Head.
- Migration creates the explicit Secunderabad Police demo Head account `SEC-PS-HEAD-001` with password `Demo@1234`.

Run `SIH_Case_AI_Ollama_Gemini_Migration.sql` in Supabase before deploying.
