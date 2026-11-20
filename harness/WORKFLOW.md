# HoloNet Execution Workflow — BINDING

This document binds every future run on this repository, human or agent. It
cannot be silently amended: changes to it are entries in
`memory/DECISIONS.md` plus a commit, never a quiet rewrite.

## 1. Execution plans

1. Any run that touches or READS the repository first states an ordered
   plan (a task list with an end). Read-only runs (reviews, audits) still
   end with the backup step — a clean-tree push that refreshes
   `sandbox/latest` — so that every prompt output ends with a durable
   push, exactly as the owner requires.
2. The FINAL step of every plan is always, without exception:

       bash harness/scripts/backup.sh "<one-line summary of what this run did>"

3. A plan is COMPLETE only when `backup.sh` exits 0: `main` is pushed.
   The rolling tag `sandbox/latest` is advanced best-effort, and any
   tag-push failure is logged in `BACKUPS.md`; a failed `main` push
   appends a FAILED marker line to `BACKUPS.md` — committed locally
   immediately, reaching the remote only with the NEXT successful backup
   (a pushed log with no FAILED line therefore proves nothing about runs
   that died unpushed; the unpushed gap is the out-of-band signal) — and
   exits 1 (gate-0001 A4-C1/C2/C5). If the tree is clean, the script
   still pushes and refreshes the tag — a no-op backup is still a backup.
4. If the push fails (network, auth), the run is NOT complete. Report the
   failure honestly; do not claim success. If the push is rejected as
   non-fast-forward (another sandbox pushed concurrently): `git fetch
   origin && git rebase origin/main`, KEEP both `BACKUPS.md` lines on
   conflict, then retry once; a second failure escalates to the owner.
5. Backups are EVENT-DRIVEN: they fire at the end of every execution plan
   and every prompt output — never on a fixed time interval. There is
   intentionally no cron, timer, or scheduled backup in this project.
6. Interim commits during long stages are encouraged; the final backup is
   still mandatory.

## 2. Stage gates

1. The roadmap (`memory/ROADMAP.md`) is the only accepted stage sequence.
   Each stage has a charter with measurable acceptance criteria.
2. Starting stage N+1 requires a GATE: a comprehensive adversarial
   assessment of (a) the work completed so far and (b) the next stage's
   charter, conducted per `ADVERSARIAL.md`.
3. The gate passes only on role-separated blind consensus (see
   ADVERSARIAL.md, "Independence limits"): EVERY active reviewer returns
   a non-BLOCK verdict. A single BLOCK halts the transition.
4. A completed stage's results are adversarially assessed before they are
   trusted ("verify what you did", not only "plan what you will do").
5. Gate records live in `harness/adversarial/verdicts/NNNN-<gate>.md`
   and are immutable once pushed. Corrections are NEW records referencing
   the old. The run that pushes a record quotes its SHA-256 in its
   `BACKUPS.md` line, tying the log to the record.
6. Record numbers are SEQUENCE numbers of the verdicts directory, not
   gate identities; a gate is identified by its stage transition (e.g.
   "the S1→S2 gate"). A PROGRESS REVIEW (adversarial assessment without
   a stage transition) may occupy a record number; it has NO transition
   authority and must say so in its header (D-0011, gate-0002 review
   A3-C1/A4-C5). Record hashes are SHA-256 of the committed BLOB
   content — verify with `git show HEAD:<path> | sha256sum`, never by
   hashing the working-tree file, which CRLF checkouts can alter
   (D-0011, A4-C1; see also .gitattributes).

## 3. Honesty rules

1. Unfinished functionality returns explicit milestone errors; never fake
   success (project rule since day 0, unchanged).
2. Claims in `memory/STATE.md` are re-verified against the working tree
   after any restore before being trusted.
3. No secret ever enters a tracked file, log, or message. GitHub auth
   tokens are passed only via the `HOLO_GITHUB_TOKEN` environment variable.
4. Test counts quoted anywhere must be countable from the tree.

## 4. Memory discipline

1. Before the final backup of every run: update `memory/STATE.md` and write
   a session journal under `memory/sessions/` (done, changed, next, gate
   status).
2. `memory/LESSONS.md` and `memory/DECISIONS.md` are append-only.
3. Durable knowledge discovered mid-run (pitfalls, vector notes,
   infrastructure quirks) lands in `LESSONS.md` in the same run's backup.
4. First act of every run (record-0003 A3-C8): `git status --porcelain`;
   untracked/modified strays are triaged BEFORE new work and the
   disposition (discarded / kept-and-rederived / unrelated-artifact-
   outside-tree) is recorded in the session journal. Broken or
   crashed-session WIP is never committed and never trusted: reusable
   material (vectors, constants, scaffolding) must be re-derived from
   its primary RFC/NIST source and pass its own tests before reuse.
   backup.sh enforces the same rule at push time (refusal on strays
   outside harness/ unless the message carries --allow-untracked).
