# Session journal — 2026-11-26: owner decisions executed (D-0035)

Owner gave the three decisions in chat — the exact residuals re-listed
by gate 0004 C7: "D-0014: confirmed / PAT: old token kept for now /
CVE: poll the advisory yourself and backfill".

## Session-start ritual (runbook 0/0b, warm path)

- Remote reconciliation: `git ls-remote origin refs/heads/main` =
  d8aac80 == `git rev-parse HEAD`. MATCH (run-10 closure + gate 0004).
- `git status --porcelain`: clean. No strays.
- Toolchain: absent (`cargo` not found — the recycle wiped ~/.cargo a
  SIXTH time). NOT reinstalled: this run touches zero Rust code
  (docs/harness only). Honest fallback per SANDBOX-RESTORE: the CI
  conclusion for HEAD is the baseline evidence.
- Baseline: d8aac80 == origin/main; CI run 45495227224 @ d8aac80 =
  SUCCESS (the run-10 closure push; its expected 121/120/120 ledger was
  recorded with run 10 — no re-count needed, no code changed since).
- Memory loaded per D-0027/D-0028 + direct reads: STATE.md header,
  DECISIONS tail (next free = D-0035), ROADMAP descope section,
  PROJECT_MEMORY.md (full), BACKUPS tail, gate-0004 record C7.

## Decisions executed (all three recorded as D-0035)

1. **D-0014 RATIFIED unchanged** — trojan over the S2 holo-tls client
   stays the named v1.0 second LIVE protocol; hy2/tuic alternates iff
   S3 completes on schedule; tripwire N=4 + terminal gate unchanged.
   The "PROPOSED DEFAULT, owner may override" window (open since
   2026-11-17, progress review 0002) is CLOSED. ROADMAP descope header
   annotated; graph OD-d0014 pending → decided.
2. **PAT: old token kept for now** — rotation declined this round;
   exposure window (token transited chat/upload) recorded as an
   owner-accepted residual; the recommendation to rotate stays in the
   playbook; env-var handling discipline unchanged.
3. **CVE polling delegated to the executor** — see the poll below;
   daily automated poll scheduled (cron, Asia/Rangoon 14:00 daily);
   the backfill procedure is recorded in D-0035 so any future session
   can execute it mechanically.

## CVE poll (2026-11-26T06:52Z, authenticated)

- Anonymous API: rate-limited (the known LESSONS condition) — polled
  authenticated via stdin-piped curl config (`curl -K -`; token never
  in argv/files/output).
- GLOBAL endpoint `api.github.com/advisories/GHSA-8h6m-w5qj-cq9g` →
  **404** even authenticated: the repo advisory is not yet in the
  global database (expected until GitHub promotes it / the CVE is
  assigned). Not an error state — recorded so future polls do not
  misread it.
- REPO endpoint `api.github.com/repos/maniesh-NR/HoloNet/
  security-advisories/GHSA-8h6m-w5qj-cq9g` → present, published,
  **cve_id = null — still pending assignment.** Nothing to backfill
  this session.

## Memory updates

DECISIONS +D-0035; ROADMAP descope header annotated (D-0014 RATIFIED);
graph.json: OD-d0014 → decided, +D-0035, +SES-2026-11-26, +2 edges
(authored, closes) — check OK 161 nodes/124 edges, RAG smoke OK 412
chunks; STATE.md run-11 header; PROJECT_MEMORY playbook item 3 closed +
CVE/PAT status refreshed; update_memory.py git-activity refresh run
pre-commit; this journal.

## Next

1. S2 (holo-tls) implementation per the amended charter (gate 0004
   conditions: R-05 interop harness during S2 CI work; CT-checklist
   review bar for secret-operand code; top-level-test-fn tidy at the
   first holo-crypto refactor).
2. Daily automated CVE poll; backfill per D-0035 when the id lands.
3. PAT rotation recommendation stands (owner declined this round).
