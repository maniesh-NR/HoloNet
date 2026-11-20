# Verdict archive — record 0003, round 1, reviewer A4 (verbatim)

Platform note: reproduced byte-exact from the reviewer agent's return
message. Launch metadata: parallel batch, 2026-11-20, task ID ADV-A4,
model requested "opus", platform served model family x-preview-l
(disclosed). A4's F3/C1 (live-remote divergence) drove this run's
mid-run fast-forward reconciliation; the record documents the outcome.

---

## A4 Process Audit — evidence summary

**What I verified mechanically before reading anything:** `sha256sum` of all four gate-0001 files; `ls-remote` against the live GitHub remote; reflog; index file modes; `#[test]` counts; append-only history of LESSONS/DECISIONS via `git log -p`; existence and hash of the moved orphan.

---

### 1. Chain + tie-in (mechanically verified, with one weak link)

- The tie-in HOLDS: `sha256sum harness/adversarial/verdicts/0001-S1-gate.md` = `5bbc465c…ab4f4`, identical to the quote in `harness/memory/BACKUPS.md:7` and to commit `8761716`'s message. All three archive hashes pinned at `0001-S1-gate.md:132-137` match the actual files (`4e0aa4e3…`, `a53a38b9…`, `500c8e2e…`). Record 0001 conforms to ADVERSARIAL.md: verdict tables, consensus computation, conditions carried into `ROADMAP.md:190-228` as claimed (`0001-S1-gate.md:96-104`), strict AGENT/VERDICT/DISSENT blocks present in both round archives, `chain: genesis` as the final line.
- BUT the harness-audit job is a smoke test, not a tie-in verifier: `.github/workflows/ci.yml:102` only greps for *any* 64-hex string in added BACKUPS.md lines — it never compares that hash to `sha256sum` of the record files. It audits only the tip commit (`fetch-depth: 2`, `HEAD~1..HEAD`, ci.yml:89,94), so a record committed separately from its BACKUPS line sails through, and a §1.4 conflict-merge that re-adds an *old* BACKUPS line also passes. **A reworded record committed together with a stale-hash BACKUPS line would pass CI today.**

### 2. The decisive finding: the remote has diverged and the run cannot see it

- `git ls-remote origin` (live, no local writes): `refs/heads/main` = `cc4564f8…`, `refs/tags/sandbox/latest` = `cc4564f8…`. Local main and local `sandbox/latest` = `8761716` (`git rev-parse`, reflog shows zero movement since 2026-11-13 07:02:44). `git cat-file -t cc4564f` fails — **the remote carries a commit this working copy has never seen**, pushed by a foreign actor (another sandbox or the owner) sometime in the past week.
- Therefore the disclosed fact "local main == origin/main @ 8761716" is **false against the live remote**. It could only have been "verified" via `git status`/`rev-parse origin/main`, which compares against a tracking ref stale since the 2026-11-13 clone (`reflog: clone 06:09:08`; never fetched). The 2026-11-13 journal's promised first act — "verify `sandbox/latest == origin/main` and record it in its journal" (`sessions/2026-11-13-harness-gate0001.md:95-96`) — was either skipped or performed by the unreliable method. No mandated step anywhere (`SANDBOX-RESTORE.md`, `STATE.md:56-58` re-verify checklist, `backup.sh`) ever queries the *live* remote.
- Consequence: this run's final backup **will be rejected non-fast-forward**; the §1.4 recovery (`fetch` + `rebase origin/main`, WORKFLOW.md:27-31) will then import unknown foreign commits onto the tree the panel is reviewing, and record 0002 would be authored on a premise already stale. The designed recovery path exists and is executable — so this is not unrecoverable — but the record must not be finalized until the divergence is reconciled and disclosed verbatim in it.

### 3. Restore runbook vs reality

`SANDBOX-RESTORE.md` was "exercised and verified" for the COLD path only (lines 3-7, 9-52). Everything that actually happened this run is absent from it: no warm path for a repo found on disk after recycle; no mention of the umask mode artifact (all 76 non-`backup.sh` tracked files flipped 100644→100755 — index shows 77 tracked files, 76×100644 + 1×100755); no `core.fileMode` guidance; no run-start remote reconciliation; no untracked-stray sweep; cargo-env sourcing only in the cold install step. The runbook drifted from reality in exactly the recycle case it was written for.

### 4. Untracked-WIP hazard — demonstrated, not hypothetical

`backup.sh:39` runs `git add -A` unconditionally. This run's 352-line non-compiling orphan proves a crashed session's leftover would have been silently committed as "backup". No script or doc guards it. Worse: the relocation destination `/home/z/my-project/` is **itself a git repo with automated UUID-message commits** (`git -C /home/z/my-project log`: `92c1924 bec15d02-…`; `status --porcelain` shows the orphan untracked inside it) — the hazard was relocated, not eliminated, and the orphan's only anchor is the panel prompt; no durable record pins its hash (`375d41cd…`).

### 5. Mode-flip recommendation

`core.fileMode false` is safe here: git tracks only the exec bit, never 0600-vs-0644, so the 0600 at-rest-secrets tests (fs-permission based) are unaffected; exactly one tracked file legitimately needs +x (`backup.sh`). Downside stated honestly: repo-local config does not survive a cold clone (must be a runbook step), and genuine future exec-bit changes are masked (mitigate with explicit `git update-index --chmod=+x`). LESSONS.md currently contains no umask/fileMode lesson (`rg 'umask|fileMode|mode'` → one unrelated hit).

### 6. Verdict-laundering residuals

Safeguards are real and I verified them (hash-pinned verbatim archives, strict format, disclosed independence limits). Still unauditable: (a) the record's verdict tables are aggregator paraphrase — verdict blocks live only by reference to archives; (b) the prompts archive is self-attested — nothing binds archived text to what was sent; (c) no reviewer-reply hash is anchored at reply time; (d) no mechanical check that every CONDITIONS item in the archives reaches the carried-forward list.

### 7. Run conduct (gray zones, honestly weighed)

Moving the orphan out of the shared review input before panel launch was legitimate hygiene but is also evidence removal: its history is unverifiable (untracked) and disclosure, while verbatim, is not anchorable. The temporary SIGMA wiring was fully reverted (`rg -i blake2 engine/` → zero hits; tree clean). §1.1/§1.5's "every prompt output ends with a durable push" is in practice one final backup per run — granularity never defined. §4 discipline is currently on track (STATE/journal due before final backup; LESSONS/DECISIONS append-only holds — zero deletion lines in full git history, `git log -p` checked). Two hygiene flags: `ROADMAP.md:160` carries a credential-shaped reference ("se0316" beside an api host) in a tracked file — owner must verify it is not live (WORKFLOW §3.3); `/home/z/my-project/.env` exists outside the repo (not read, not quoted). Immaterial: disclosed "353 lines" for the orphan measures 352 (`wc -l`).

**Calibration:** every hash tie-in I could check held; failure drill lines are preserved; the panel caught what the process missed. The state is recoverable and the honesty norms demonstrably held. But a false "verified" premise is about to be baked into an immutable record, and four recurring hazards (remote staleness, mode noise, untracked sweep, weak CI audit) have no mechanical guard. That is PROCEED_WITH_CONDITIONS territory, not BLOCK and not rubber-stamp.

AGENT: A4 Process Auditor
VERDICT: PROCEED_WITH_CONDITIONS

FINDINGS:
- [F1] Gate-0001 tie-in verified end-to-end: record sha256 `5bbc465c…` equals BACKUPS.md quote and commit message; all three archive hashes match; chain line, verdict format, and ROADMAP condition carry-over conform — evidence: harness/memory/BACKUPS.md:7, harness/adversarial/verdicts/0001-S1-gate.md:130-139, harness/memory/ROADMAP.md:190-228 (verified)
- [F2] harness-audit CI job checks hash *shape*, not hash *equality*, and audits only the tip commit: a reworded record + stale-hash BACKUPS line in one commit passes; separate commits and conflict-merged old lines also pass — evidence: .github/workflows/ci.yml:89-106 (verified)
- [F3] Live remote has diverged: ls-remote shows origin main and sandbox/latest at foreign commit `cc4564f8…` (object absent locally; reflog frozen at 2026-11-13 07:02:44), so the disclosed "local == origin/main @ 8761716" is false and this run's final backup will be rejected non-fast-forward, importing unknown commits before the record lands — evidence: git ls-remote output vs git rev-parse HEAD / sandbox/latest; sessions/2026-11-13-harness-gate0001.md:95-96 (verified)
- [F4] The promised first-act verification is unenforceable and was effectively voided: no mandated step defines *how* to verify remote equality; `git status`-based checks compare to a tracking ref stale since clone — evidence: harness/memory/SANDBOX-RESTORE.md (no reconciliation step), harness/memory/STATE.md:56-58 (verified)
- [F5] Restore runbook has no warm-restore branch: repo-found-on-disk path, umask mode artifact (76 files 100644→100755; index = 76×100644 + 1×100755), `core.fileMode`, untracked-stray sweep, and warm-shell cargo env are all absent — evidence: harness/memory/SANDBOX-RESTORE.md:3-52 (verified)
- [F6] backup.sh `git add -A` is unconditional: this run's non-compiling orphan proves a crashed-session leftover would be silently committed as "backup"; no guard exists in script or docs — evidence: harness/scripts/backup.sh:39 (verified)
- [F7] The orphan hazard was relocated into a second git repo with automated UUID commits, and its only anchor is the panel prompt — no durable record pins its sha256 `375d41cd…` — evidence: `git -C /home/z/my-project status --porcelain` (orphan listed), panel disclosure facts (verified)
- [F8] Record verdict tables are aggregator paraphrase; prompts archive and carried-forward conditions have no mechanical cross-check; reviewer replies are unanchored at reply time — residual laundering surface — evidence: harness/adversarial/verdicts/0001-S1-gate.md:15-20, harness/ADVERSARIAL.md:35-40 (verified)
- [F9] LESSONS/DECISIONS append-only holds (zero deletion lines in full history); 2026-11-20 STATE/journal correctly pending; no umask/fileMode lesson yet recorded anywhere — evidence: git log -p on both files; harness/memory/LESSONS.md (verified)
- [F10] Hygiene flags: credential-shaped reference in tracked ROADMAP.md:160; `.env` present at /home/z/my-project/.env outside the repo; disclosed orphan "353 lines" measures 352 — evidence: harness/memory/ROADMAP.md:160 (suspected, owner must confirm), filesystem listing (verified)

CONDITIONS:
- [C1] Before finalizing record 0002: run `git ls-remote origin refs/heads/main sandbox/latest`; fetch, inspect, and §1.4-reconcile the foreign tip `cc4564f8…` (determine what it touched); disclose the divergence verbatim inside record 0002; the record must land on the tree the panel actually reviewed.
- [C2] Add SANDBOX-RESTORE.md step 0 (mechanical): `ls-remote` equality check against local HEAD and `sandbox/latest`, STOP-and-reconcile on mismatch; mirror it into STATE.md's re-verify checklist and as a named journal line ("remote reconciliation: main=… latest=… match=Y/N"), making the 2026-11-13 first-act promise enforceable.
- [C3] Add the warm-restore branch to SANDBOX-RESTORE.md: untracked-stray audit via `git status --porcelain`; `git config core.fileMode false` after every restore/clone (one-line rationale: exec-bit-only tracking; 0600 fs-perm tests unaffected; genuine exec changes via `git update-index --chmod=+x`); cargo-env sourcing when `command -v cargo` fails; record measured restore time.
- [C4] Add the backup.sh pre-backup guard: FAIL on any untracked `??` path outside `harness/memory/` unless the operator's message contains that exact path; echo the porcelain listing; document honest failure modes (new-source false positive → name it in the message; bypass is loud, not silent; typo fails safe); record as a WORKFLOW §1 amendment + LESSONS entry.
- [C5] Strengthen the harness-audit job: fetch-depth 0; iterate the whole push range; require `sha256sum` of each new/changed verdicts file to appear verbatim in the SAME commit's added BACKUPS.md lines; require `chain:` on records ≥0002 to carry the previous record's hash.
- [C6] Laundering hardening in record 0002+: inline each reviewer's final AGENT/VERDICT/CONDITIONS/DISSENT block byte-exact; add a per-verdict sha256 column and per-reviewer launch metadata (task id, model); end with a one-line owner spot-check (`sha256sum` vs BACKUPS quote); mechanically cross-check every archived condition against the carried-forward list.
- [C7] Anchor the orphan in record 0002 by sha256 `375d41cd…` + location, state its history is unverifiable, move it fully outside every git tree or hand it to the owner for inspection/deletion; note the 352/353 count correction.
- [C8] Owner verification that the ROADMAP.md:160 provider reference is not a live credential; if live, rotate and scrub per WORKFLOW §3.3.

DISSENT/NOTES: I did not fetch (fetch writes tracking refs), so the *content* of foreign commit `cc4564f8…` is unverified — provenance is owner-side (GitHub push events are precisely the out-of-band anchor ADVERSARIAL.md:84-86 names; this incident proves why). If the foreign tip is a force-push rewrite rather than a descendant of 8761716, C1 escalation is mandatory, and I would then support BLOCK. The process passed every tamper check I could throw at it — the failure was an unmandated verification, not a dishonest one, which is why this is conditions, not block. Gate-0001 A4 conditions C1–C7 were applied and remain verifiable in-tree; nothing regressed.

Tokens -> prompt:55429 completion:3635 total:59064
Resume by calling Task with "resume": "agent-c2e211d2-46c2-400f-918d-663d8e8eda65".
