---
name: vibecheck
description: Run the VibeCheck security scan on the code you just wrote or changed, fix what it finds, and report the result honestly. Use before saying a feature, fix or refactor is done; when asked to "check security", "run vibecheck" or "scan for vulnerabilities"; and before a commit or pull request that touches auth, data access, uploads, dependencies, secrets or infrastructure.
---

# VibeCheck: scan, fix, re-scan

VibeCheck (`vibecheck.sh`) runs secret, static, dependency, CISA KEV and IaC scans
and **fails closed**: a scan that could not run is an error, never a clean result.
Your job is to run it, fix real findings in the code, and report exactly what
happened. Never make the scan pass by hiding findings.

## 1. Find the script

Use the first that exists:

1. `./vibecheck.sh` in the repository root
2. `vibecheck.sh` on `PATH` (`command -v vibecheck.sh`)

If neither exists, stop and tell the user VibeCheck is not installed. Do not
download it yourself.

## 2. Run it

```bash
./vibecheck.sh --dir . --no-review --no-pdf
```

- On a branch, gate only on what the branch changed: add `--diff main` (or the
  real base branch). Fetch the base first if it is missing.
- Scans take minutes. Give the command a long timeout (10 minutes) rather than
  killing it.
- `--no-review` is deliberate: the adversarial review pass sends the code to a
  model provider and costs money per run. Run it (`--review`) only when the user
  asks for it.
- Do not add `--skip-*`, change `--fail-on`, or pass `--no-baseline` to get a
  different answer.

## 3. Read the exit code

| Exit | Meaning | What you do |
|---|---|---|
| 0 | Nothing at or above the threshold | Report clean, with the coverage caveat below |
| 1 | Findings at or above the threshold | Fix them (step 4) |
| 2 | Usage error | Your command is wrong; fix the flags |
| 3 | A pass could **not** complete | **Not clean.** Report which pass failed and why |

For exit 3, list the failed passes:

```bash
jq -r '.coverage.passes[] | select(.status=="error") | "\(.pass): \(.detail)"' vibecheck-report/findings.json
```

Usually a scanner is missing or the network is down. Tell the user; do not
retry with that pass skipped.

## 4. Fix the findings

```bash
jq -r '.active[] | "\(.severity)\t\(.tool)\t\(.file):\(.line)\t\(.rule)\t\(.title)"' vibecheck-report/findings.json
```

`active` is what gates. `accepted` (baseline) and `out_of_scope` (outside a
`--diff`) are context only.

Work in this order:

1. **Verified secrets** (`verified-secret.*`): tell the user **immediately** that
   the credential must be rotated. Removing it from the code does not un-leak it;
   it is still in git history.
2. **KEV-listed CVEs** (a `kev` object; title starts `[CISA KEV: actively
   exploited, ...]`): exploited in the wild, with a CISA due date. Upgrade the
   dependency to a fixed version.
3. **Critical, then high.** Fix the cause in the code, following `AGENTS.md`.
4. Medium and low: fix when the fix is small and safe; otherwise list them.

If a finding is a false positive, do not suppress it. Explain why to the user and
suggest they accept it in the baseline (`--write-baseline`, with a reason). Only
the user decides that.

**Never, without the user's explicit approval:** edit `.vibecheck-baseline.json`,
`.vibecheckignore` or `vibecheck.yml`; add `nosemgrep` or similar inline
suppressions; delete or weaken a test or rule; or commit a `vibecheck-report*/`
directory (reports describe real vulnerabilities).

## 5. Re-scan

Run the same command again after fixing. Repeat until it exits 0, or until every
remaining finding is one you have explained to the user.

## 6. Report

Tell the user, briefly:

- the exit code and what it means;
- what you fixed (file and finding);
- what is left, and why;
- any secret that needs rotating;
- which passes ran, were skipped or failed (`.coverage.passes`).

A clean scan is not proof the code is secure. Scanners cannot see broken access
control, cross-tenant leaks, race conditions or business-logic flaws
(`.coverage.not_detectable`). If the change touches authentication, tenancy,
data access, uploads or outbound calls, say so, so a human reviews it against
`hardening/CHECKLIST.md`.
