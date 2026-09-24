# AI Governance Checklist (manual companion to VibeCheck)

The security checklist ([CHECKLIST.md](CHECKLIST.md) §7–8) covers whether your
AI features are *attackable*. This covers whether they are *governable* — the
data, provider, oversight, and compliance questions that a scanner cannot see
but an auditor, a customer's security review, or a regulator will ask. If you
ship an LLM feature to real users, own the answers here before, not after.

Marked ★ = do this before the feature reaches production with real user data.

## 1. Data flow & inventory ★
- [ ] ★ You have a written **data-flow diagram** for every AI feature: what leaves your boundary, to which provider, over which region/endpoint, and what comes back.
- [ ] ★ You know exactly what data reaches the model — user input, retrieved documents (RAG), tool results, system prompt — and none of it is data the user isn't authorized to see (RAG respects the same authz as the rest of the app; no cross-tenant retrieval).
- [ ] No PII/PHI/PCI/secrets in prompts unless there's a documented lawful basis and it's minimized (see [CHECKLIST.md](CHECKLIST.md) §7). Redact or tokenize before the call where possible.
- [ ] Data residency honored — if users are EU/regulated, the provider endpoint and region match (e.g. an EU inference region), and this is contractually confirmed.

## 2. Provider & contracts ★
- [ ] ★ A **DPA** is in place with every model/embedding/vector provider; a **BAA** where PHI is involved.
- [ ] ★ **Training opt-out** is confirmed in writing — your prompts and outputs are not used to train the provider's models (default varies by provider and by API-vs-consumer tier; verify for your account).
- [ ] Provider **data-retention** window is known and acceptable (how long they keep request/response logs), and you've set the shortest tier available (zero-retention where offered).
- [ ] Sub-processors are inventoried (the provider's own sub-processors count toward your compliance posture).
- [ ] A fallback/second provider or graceful-degradation path exists, so a single provider outage or policy change isn't an outage for you.

## 3. Model provenance & change control
- [ ] Model **version is pinned**, not a floating alias — a silent model swap changes behavior, cost, and safety profile. Upgrades are a reviewed change, not automatic.
- [ ] Any self-hosted / fine-tuned / downloaded model has known provenance (source, license, checksum) — this is the LLM03 supply-chain and LLM04 poisoning surface a regex can't check.
- [ ] Fine-tuning / RAG training data is inventoried, access-controlled, and vetted for poisoning; you can answer "what data shaped this model's behavior?"
- [ ] Prompt templates and system prompts are **version-controlled and reviewed** like code (a prompt change is a behavior change).

## 4. Evaluation & red-teaming ★
- [ ] ★ There's an **eval set** for the feature (correctness + safety) that runs before a prompt/model change ships — you can prove a change didn't regress.
- [ ] Adversarial / prompt-injection **red-teaming** was done against the actual deployed feature (not just the model in isolation), including injection via retrieved content and tool results.
- [ ] Known failure modes (hallucination/misinformation — LLM09, biased or unsafe output) are documented with their mitigation (grounding, citations, human review, refusal behavior).
- [ ] Output is grounded/cited where users may act on it; the UI signals AI-generated content and its uncertainty.

## 5. Human oversight & agency
- [ ] ★ High-impact actions an agent/tool can take (spend money, delete/modify data, send external messages, change access) require **human confirmation** or a hard policy limit — never fully autonomous (LLM06 excessive agency).
- [ ] Tools are least-privilege and scoped; there's a documented list of every action the AI can take on a user's behalf.
- [ ] Users can opt out of AI processing where the law or the contract requires it, and there's a non-AI path for consequential decisions.

## 6. Observability, audit & abuse
- [ ] Prompts, outputs, tool calls, model+version, and token/cost are **logged** (with secrets/PII redacted) so an incident is reconstructable — retained per your policy, not forever.
- [ ] Per-user/per-org **rate + spend limits** are enforced and alerted on (LLM10) — a runaway loop or abuse is capped and paged, not discovered on the invoice.
- [ ] Abuse/safety monitoring exists (jailbreak attempts, unsafe-content generation) with a response path.
- [ ] There's an **incident + rollback plan** specific to AI: how to disable the feature, roll back a prompt/model, and notify affected users.

## 7. Compliance & disclosure
- [ ] Privacy policy / terms **disclose** AI use, which providers, and what data is processed.
- [ ] Regulatory scope is assessed: **GDPR** (automated decision-making Art. 22, DPIA where high-risk), **EU AI Act** risk tier, sector rules (HIPAA, GLBA, FERPA) as applicable — with sign-off recorded.
- [ ] AI risks are in the org **risk register**, and this checklist has a named owner and a review cadence (model/provider landscape moves fast — revisit quarterly).
- [ ] Third-party / customer security questionnaires can be answered from the artifacts above without a fire drill.

---
*Companion to [VibeCheck](../README.md) and [CHECKLIST.md](CHECKLIST.md). These are
governance questions a scanner cannot answer — they need a human who owns the
feature and its risk. Map to OWASP-LLM: LLM02 (§1–2), LLM03/04 (§3), LLM06 (§5),
LLM08/09 (§4), LLM10 (§6).*
