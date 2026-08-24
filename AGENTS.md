# AGENTS.md — Security rules for AI coding assistants

Copy this file to your project root. Modern AI coding assistants read
`AGENTS.md` automatically and will follow these rules while writing code — stopping vulnerabilities at creation instead of
catching them later. This is layer 1 of 3: **prevent** (this file) →
**detect** (`vibecheck.sh` in CI) → **verify** (`hardening/CHECKLIST.md` + a
human). Keep all three.

> Trim or extend for your stack. Rules are imperative on purpose — an assistant
> should treat them as hard constraints, not suggestions.

## Non-negotiable rules

### Access control (the #1 thing to get right)
- Every endpoint that reads or writes a record **by id** MUST verify the
  authenticated caller owns or belongs to that record — not merely that they're
  logged in. No exceptions. This prevents IDOR / cross-tenant data leaks.
- Derive the user's identity, role, and tenant/org **only** from the verified
  session or token, resolved server-side. NEVER trust a role, `user_id`,
  `org_id`, or tenant id sent in the request body, query string, or a header.
- If the app is multi-tenant: every query against a tenant-scoped table MUST
  filter by the caller's tenant id. If the DB uses row-level security, do not
  assume it protects you — confirm the app's DB role does not bypass RLS; if it
  does, the explicit tenant filter is the only guard.
- Enforce authorization on the server for every request. Hiding a button or
  route in the UI is not access control.

### Injection & input
- Use parameterized queries or an ORM for ALL database access. Never build SQL
  (including column/table identifiers) by string concatenation with input.
- Never pass user input to `eval`, `exec`, a shell, `child_process`, or an
  unsafe deserializer.
- Never render user input with `dangerouslySetInnerHTML`, `v-html`,
  `innerHTML`, or `.html()`. If HTML output is truly required, sanitize with
  DOMPurify first.
- Validate and whitelist request bodies to the exact fields expected. Never
  spread a request body straight into a DB write (mass-assignment).
- For any outbound request built from a user-supplied URL, allowlist the host
  and block internal/metadata addresses (SSRF).

### Secrets & config
- Never hardcode secrets, API keys, tokens, or passwords. Read them from
  environment variables or a secrets manager.
- Never commit `.env` files or secrets to git. Add them to `.gitignore`.
- Only public keys may reach the client bundle (e.g. Firebase web / Supabase
  anon keys). Service-role keys, `sk_live` Stripe keys, and signing secrets are
  server-only — if you're tempted to put one in frontend code, stop.

### Authentication
- Hash passwords with bcrypt, scrypt, or argon2 — never MD5/SHA/plaintext.
- Verify JWTs fully: signature, issuer, audience, expiry, and revocation.
- Set auth cookies `HttpOnly`, `Secure`, `SameSite`. Invalidate sessions on
  logout and password change.
- Add rate limiting / lockout on auth endpoints — and make sure the counter
  can't be reset by an unauthenticated request.

### Data protection & transport
- Encrypt PII/PHI at rest; require TLS in transit.
- Return generic error messages to clients; keep stack traces and DB errors in
  server logs only.
- Do not persist sensitive data in `localStorage` / `IndexedDB` / client caches
  past logout, especially on shared devices.
- Set security headers: HSTS, a Content-Security-Policy, `X-Content-Type-
  Options: nosniff`, frame protection (`frame-ancestors`/X-Frame-Options), and
  a Permissions-Policy. CORS must name specific origins — never `*` on
  authenticated endpoints.

### AI / LLM features
- Sentinel-wrap or delimit user/free-text input so it cannot escape into the
  system prompt (prompt injection).
- Never execute LLM output as SQL, shell, or tool calls without validation.
- Don't send PII/PHI to third-party model APIs without the right data
  agreement, and rate/cost-limit model calls per user.

### MCP servers
- Validate and allowlist every tool argument before it reaches a shell, SQL
  query, file path, or outbound URL. Never expose a tool that takes a free-form
  `command`/`path`/`url` and passes it to a sink unchecked (RCE / SSRF).
- Authenticate the transport (bearer/OAuth/mTLS or a gateway). Do not accept
  unauthenticated MCP sessions — that hands callers your whole toolset.
- Keep instruction-like text and secrets out of tool/resource/prompt
  descriptions; a calling model reads them as guidance (tool poisoning).
- Treat tool results and resource content as untrusted input to the model — they
  can carry injected instructions. Scope tools least-privilege; gate destructive
  ones behind explicit confirmation.

## When you finish a feature
Before saying it's done, self-review against the rules above and note any you
could not satisfy. If the change touches auth, tenancy, data access, uploads,
or external calls, say so explicitly so a human can review it.

---
*Part of [VibeCheck](README.md). Detection: run `./vibecheck.sh`. Verification:
`hardening/CHECKLIST.md`.*
