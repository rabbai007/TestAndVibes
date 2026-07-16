# Web App Hardening Checklist (manual companion to VibeCheck)

Automated scanners catch the mechanical stuff. This catches what they can't:
**business logic, access control, and multi-tenant isolation** — the flaws that
actually breach real apps. Work through it per feature/PR, not just once.

Legend: `[ ]` to review · focus on **the ones marked ★** — they're the classic
"vibe-coded app" killers.

## 1. Access control & multi-tenancy ★ (the #1 real-world breach class)
- [ ] ★ Every object fetched by ID checks the caller **owns/belongs to** it — not just "is logged in" (IDOR). Test: log in as tenant A, request tenant B's object ID → must be 403/404.
- [ ] ★ If you use row-level security (RLS), confirm the **app's DB role doesn't bypass it**. Many backends connect as a superuser/owner that ignores RLS — then an explicit `WHERE org_id = :caller_org` is your *only* guard.
- [ ] ★ Authorization is enforced **server-side**, never only by hiding UI. Re-issue the raw API call without the UI.
- [ ] Role/tenant is derived from the **verified session/token server-side**, never from a request body/header/param the client controls.
- [ ] Admin/privileged endpoints re-check role on **every** call, not once at login.
- [ ] No mass-assignment: request bodies are whitelisted to allowed fields before hitting the DB (can't set `role`, `org_id`, `is_admin`, `id`).

## 2. Authentication & sessions
- [ ] Passwords hashed with bcrypt/scrypt/argon2 (never MD5/SHA/plaintext).
- [ ] Brute-force protection (lockout/rate-limit) that **can't be reset by an unauthenticated call**.
- [ ] Session tokens: HttpOnly + Secure + SameSite cookies, or short-lived bearer tokens with refresh + server-side revocation.
- [ ] Logout / password-change **revokes existing sessions**.
- [ ] MFA available for privileged roles; token verification checks signature, issuer, audience, expiry, **and revocation**.
- [ ] Password reset + email-verification tokens are single-use, expiring, and unguessable.

## 3. Injection & input
- [ ] All SQL uses parameterized queries / an ORM — **no string interpolation** of user input (incl. column/table identifiers).
- [ ] No `eval`, `exec`, `child_process` with user input; no unsafe deserialization.
- [ ] Output encoding / framework auto-escaping on; no `dangerouslySetInnerHTML` / `v-html` / `innerHTML` with unsanitized input (use DOMPurify if you must).
- [ ] File uploads: validate type + size, store outside webroot, randomize names, never execute.
- [ ] SSRF: outbound requests from user-supplied URLs are host-allowlisted (block `169.254.169.254`, internal ranges).

## 4. Secrets & data
- [ ] ★ No secrets in the repo or git history (VibeCheck's secret pass covers this — keep it green).
- [ ] Secrets in a manager (Vault / cloud Secret Manager / env), not `.env` committed or baked into client bundles.
- [ ] Client bundles contain **only** public keys (Firebase web / Supabase anon are fine; service-role / `sk_live` / signing secrets are NOT).
- [ ] PII/PHI encrypted at rest (field- or DB-level); TLS 1.2+ in transit.
- [ ] Offline / local storage (localStorage, IndexedDB, mobile caches) doesn't retain sensitive data past logout, esp. on shared devices.
- [ ] Errors returned to clients are generic; stack traces / DB messages only in server logs.

## 5. Transport & headers (VibeCheck's dynamic pass checks these)
- [ ] HTTPS everywhere + HSTS; HTTP redirects to HTTPS.
- [ ] Content-Security-Policy set (on HTML responses, not just the API).
- [ ] X-Content-Type-Options: nosniff · X-Frame-Options/`frame-ancestors` · Referrer-Policy · Permissions-Policy.
- [ ] CORS allowlists specific origins — **no `Access-Control-Allow-Origin: *`** on credentialed/authenticated endpoints.
- [ ] Server/framework version banners suppressed.

## 6. Platform & ops
- [ ] Rate limiting on auth, expensive, and AI/LLM endpoints.
- [ ] Dependencies patched; CVE scan in CI (VibeCheck's dependency pass).
- [ ] Container images run as non-root, minimal base, no build tools in the runtime stage.
- [ ] Cloud storage buckets / databases are **private by default** (the classic "open S3 / public Firestore" breach).
- [ ] Audit logging on security events (login, role change, data export, admin action).
- [ ] Backups exist, are encrypted, and restore has been tested.

## 7. AI / LLM features (if any)
- [ ] User/free-text input is delimited/sentinel-wrapped and **can't escape into the system prompt** (prompt injection).
- [ ] LLM output that becomes an action (SQL, shell, API call, tool use) is validated/sandboxed — never executed blindly.
- [ ] No PII/PHI sent to third-party model APIs without a BAA / DPA and a clear data-flow.
- [ ] Per-user/per-org rate + cost limits on model calls.

---
*Companion to [VibeCheck](../README.md). Manual review by a human who understands
the app's intent — that's the part no scanner replaces.*
