# Record 0003 — Cross-validation progress review (no stage-transition authority)

- Date: 2026-11-20 (UTC)
- Run: independent cross-validation of the post-gate-0001 baseline +
  S1 pre-flight, launched in a DIFFERENT sandbox from the record-0002
  run. Per WORKFLOW §2.6 / D-0011: this is a PROGRESS REVIEW; the
  number 0003 is a directory SEQUENCE number, not a gate identity —
  the S1→S2 gate will be the next record (0004).
- Panel: A1 Reliability Skeptic, A2 Security Red, A3 Strategy
  Adversary, A4 Process Auditor (fixed roles per ADVERSARIAL.md);
  role-separated blind review; independence limits disclosed. An
  independent non-voting RESEARCHER lane was chartered; both launch
  attempts failed (empty responses) and the orchestrator executed the
  research pass directly (`harness/research/0001-s1-preflight-landscape.md`,
  D-0019).
- Model variation attempted (sonnet/opus split) — the platform served
  ONE model family (x-preview-l) for all four reviewers. Variation of
  prompt emphasis applied instead. Correlated-blind-spot risk remains
  probable and is disclosed, not designed away (D-0007).
- Baseline reviewed: `8761716` (the tree the parallel record-0002 run
  also reviewed). The baseline claims were re-verified locally: full
  workspace suite green (75/75, exit 0), record-0001 tie-in hash
  exact, chain `genesis` conformant.

## The divergence — disclosed verbatim (A4-F3, condition C1)

A4, running `git ls-remote origin` LIVE, found:

> `refs/heads/main` = `cc4564f8…` … Local main and local
> `sandbox/latest` = `8761716` … **the remote carries a commit this
> working copy has never seen**, pushed by a foreign actor (another
> sandbox or the owner) sometime in the past week. Therefore the
> disclosed fact "local main == origin/main @ 8761716" is **false
> against the live remote** … verified via `git status`/`rev-parse
> origin/main`, which compares against a tracking ref stale since the
> 2026-11-13 clone.

Reconciliation (per A4-C1 and WORKFLOW §1.4): `git fetch origin`;
`git merge --ff-only origin/main` — CLEAN FAST-FORWARD (local main was
a verified ancestor; no rebase, no conflicts, no history rewrite). The
foreign tip is a DESCENDANT, not a force-push — A4's escalation
trigger (BLOCK on rewrite) did not fire. Content: a parallel session
had pushed its own progress-review-0002 cycle (2026-11-17, verdicts
4× PROCEED_WITH_CONDITIONS — independently matching this panel's
pattern), CI diagnosis + memory-budget remediation (D-0015), the
pstack protocol (D-0016), harness-audit/backup-guard hardening
(D-0017), and **S1 item 0 itself** — the Windows entropy FFI, landed
fail-closed with windows-latest REQUIRED-green (ledger 76/75/75,
D-0018). All record-0003 work was then authored on the merged tree at
`cc4564f`. backup.sh now refuses to push when the live remote differs
from HEAD; SANDBOX-RESTORE gained step 0 (ls-remote reconciliation)
and 0b (warm-restore) — the two mechanical guards this incident
proved necessary.

## Round 1 verdicts (filed blind before aggregation)

| Reviewer | Verdict |
|---|---|
| A1 Reliability Skeptic | PROCEED_WITH_CONDITIONS |
| A2 Security Red | PROCEED_WITH_CONDITIONS |
| A3 Strategy Adversary | PROCEED_WITH_CONDITIONS |
| A4 Process Auditor | PROCEED_WITH_CONDITIONS |

## Consensus computation

CONSENSUS ⇔ ALL active reviewers non-BLOCK. A1 ✓, A2 ✓, A3 ✓, A4 ✓
— **CONSENSUS REACHED. The cross-validation passes: the baseline and
the S1 charter (as amended by record 0002) are endorsed by an
independent panel; the residual conditions below are binding.** No
remediation round was required (no BLOCK); the two mid-run conditions
that could not wait (A4-C1 reconciliation; owner-gated items) were
executed during the run and are evidenced by the final backup commit.

## Reviewer verdict blocks (byte-exact, per A4-C6)

Each reviewer's final AGENT/VERDICT/FINDINGS/CONDITIONS/DISSENT block
is archived byte-exact, one file per reviewer, with its committed blob
SHA-256 (D-0011 rule: `git show HEAD:<path> | sha256sum`):

| Archive | Blob SHA-256 |
|---|---|
| 0003-verdicts-A1.md | 2d619750d1ef4538d38608cdee61448f442cd0cb8c1f3b5667709f01790d2220 |
| 0003-verdicts-A2.md | 58b06baad549834980b24ff3436c48dd2e660e53bb3cbde461fc70ed785bc47a |
| 0003-verdicts-A3.md | 4563a283c3a274fab1df966e8a850a87e7da8975e1275c7ad185c317e042ea47 |
| 0003-verdicts-A4.md | a9cc35acaa51fefaa991f0d846c39d9e8a2604d1de6a6bfe43274f667b62ad06 |
| 0003-reviewer-prompts.md | 54a03a64d562cd6c9161af39b7b93a3b097d5659dbebe9708efeee14ec8db885 |

Prompt-archive honesty note: A1's prompt is archived byte-exact; the
A2/A3/A4 prompts and the two researcher charters are archived as
DISCLOSED STRUCTURAL COMPRESSIONS (every attack-surface element named
was sent; the full text lives in the orchestrator's Task-call record).
This is weaker than byte-exact archiving and is flagged here rather
than silently passed off as verbatim — the same self-attestation limit
A4-F8 names, honestly scoped.

## Cross-check: this panel's conditions vs the merged tree

The parallel record-0002 run had already closed, or validly re-framed,
most of this panel's findings. Disposition of every condition:

**Closed by the parallel run (verified on the merged tree):**
- A2-C1 (unsafe containment) — SUPERSEDED STRONGER:
  `#![forbid(unsafe_code)]` compile-time enforced on every crate except
  holo-util; sole `unsafe` = rand.rs FFI (D-0018). Verified by grep.
- A1-C4 (platform counts honesty) — STATE now quotes CI-verified
  76/75/75 (runs 44666798185/44668106188); ARCHITECTURE refreshed this
  run to match.
- A2-C10 / A2-F19 residue — THREAT-MODEL §G rewritten to shipped
  provenance (D-0018); "shipped today" wording gone.
- A2-C2 (FFI failure semantics) — closed BY DESIGN: direct linkage
  (advapi32 import lib) has no dynamic-load path; INJECT_FAIL seam
  covers call failure; LNK2019 import-lib lesson recorded (2dae1ce).
- A4-C5 (harness-audit strengthening) — SUPERSEDED STRONGER: whole-tree
  integrity audit with chain recomputation (D-0017).
- A4-C4's substance (backup guards) — merge/rebase/unmerged guards
  landed 2026-11-19; the UNTRACKED-sweep guard was still missing and
  is added THIS run (below).
- A1-C3's README spot — README already carries the honest
  "journals lost to recycle" wording (progress-review-0002 remediation).
- A2-F3 (README download warning) — README Releases section already
  rewritten to the API-verified release surface (D-0013).
- A3-C1 (S1 overload/split) — ADDRESSED BY DIFFERENT MECHANISM:
  internal ordering fix (item 0 first, now DONE) + descope tripwire
  N=4 (D-0014) instead of a formal S1a/b/c split; A3's residual risk
  is recorded, and the tripwire governs overrun.
- A3-C2 (item 0 head-of-line) — same ordering fix; item 0 is DONE.
- A3-C3 (conditions 7/8 invisible in charter body) — record 0002's
  amendments added them to the charter; verified present post-merge.
- A3-C6 (descope operationalization) — D-0014 names trojan-over-
  holo-tls, tripwire N=4, terminal gate; owner ratification still open.
- A3/A4-C8 (se0316 credential reference) — already OWNER-GATED by
  record 0002 (S5 chartering decision); duplicate escalation not
  re-opened; this run adds nothing to it.
- A2-C8 / A1 orphan-KAT (D-0009 sequencing) — D-0013 already
  re-escalated with reconciled facts (binaries no longer downloadable;
  deadline before S1 DONE; v0.3.1 cut BEFORE the XChaCha wire change).
  A2's playbook (advisory now, Windows-scoped, honest impact triad,
  v0.3.1 after item 0 — now satisfied — delete Windows zips only) is
  QUOTED INTO the owner decision queue without alteration.

**Applied THIS run (verified in the final backup commit):**
- A1-C1: TECHNIQUES.md phantom "ARCHITECTURE.md §12" citation → real
  targets (RESTORE + ROADMAP + holo-engine dispatch).
- A1-C2: TECHNIQUES.md RTT-wiring claim corrected to "validated but
  NOT wired".
- A1-C3 residue: TECHNIQUES.md + RESTORE.md OpenSSL-evidence wording →
  "self-attested; no recorded evidence survives".
- A1-C4 residue: ARCHITECTURE.md counts → CI-verified 76/75/75 +
  fail-closed wording → FFI-shipped wording.
- A1-C5/A4-C7: orphan disposition recorded (D-0020; LESSONS pitfalls;
  ROADMAP S1 item 1 SIGMA warning; KAT expectations reusable, code is
  not; full sha in the run report, truncated in tracked files so the
  D-0017 blob-resolution audit stays exact).
- A1-C6 residue + A4-C3: SANDBOX-RESTORE step 0b warm-restore branch +
  `core.fileMode false` + umask rationale; LESSONS umask entry.
- A1-F7: unused `holo-util` dep removed from holo-socks; redundant
  dev-dep removed from holo-engine; suite re-run green locally after
  the change.
- A1-F8/A3-C10: ProbeGuard bound pinned N=1024; jitter test made
  deterministic via injected seeded entropy; delay ceiling must be an
  explicit decision (charter text amended).
- A2-C3: X25519 charter precision (RFC 7748 §5 decode steps; ct_eq for
  the all-zero compare; verbatim RFC quote at drafting).
- A2-C4: AES-CFB mechanical enforcement clause (no pub raw CFB outside
  the wrapper; CI grep-audit).
- A2-C5: bignum/RSA acceptance strengthened (carry-boundary vectors;
  PKCS#1 v1.5 + PSS negative tests; verify-only scoping). Research
  annex names Wycheproof (C2SP) RsassaPkcs1/PssVerify + NIST CAVP as
  the citable vector sources.
- A2-C6: THREAT-MODEL §F branch-free requirement — carried into the S1
  charter's constant-time bar (record 0002 already added the CT bar;
  this run's A2-C6 residue folds into it; §F text itself untouched —
  no code shipped this run).
- A2-C7: close-vs-hang ELEVATED to an unauthenticated
  resource-exhaustion fix — first-chunk read deadline added to the S1
  backlog item and acceptance (charter amended this run).
- A2-C9: .gitignore += **/profiles.json, .env.local, keystore/.
- A3-C8: WORKFLOW §4.4 first-act untracked-stray triage with journaled
  disposition; backup.sh enforces it (below).
- A3-C9: OpenSSL-journal criterion made auditable (exact commands +
  ≥16 hex digest chars).
- A4-C1: divergence reconciled + disclosed (this record).
- A4-C2: SANDBOX-RESTORE step 0 mechanical ls-remote reconciliation +
  backup.sh live-remote refusal.
- A4-C4: backup.sh pre-backup guard — refusal on untracked paths
  outside harness/ unless the message carries --allow-untracked (loud
  bypass; failure modes documented in the script).
- A4-C6: this record complies — byte-exact verdict archives with
  per-verdict blob SHAs, launch metadata, disclosed prompt-compression
  limit, owner spot-check line below, and this cross-check table
  mechanically derived from the verdict archives.

**Owner-gated (carried, not actionable by agents):**
- D-0009/D-0013 decision (advisory vs v0.3.1) — deadline: before S1 is
  marked DONE; A2's playbook quoted into the queue.
- S5 credentials model (se0316) — record-0002 gate stands.
- Descope-rule ratification (D-0014 default) — owner may override.
- D-0007/the descope tripwire N: A3 proposed 3 sessions, record 0002
  set N=4 — the recorded N=4 stands unless the owner overrides.

## Research annex

`harness/research/0001-s1-preflight-landscape.md` (blob SHA-256
13d0a856bbcf0560eb0e2c57eef1a8d8003818347f9c031a7f7a122182ec2344):
std CSPRNG still unstable in rustc 1.100.0 (empirical E0658 in this
sandbox) → the D-0018 FFI is permanent for the 1.77.2 floor; XChaCha
STILL a draft (draft-irtf-cfrg-xchacha-03) → condition 8's citation is
correct as-is; TLS-in-TLS mitigation literature (USENIX Sec '24, NDSS
'25) → named for S2/S3 acceptance; ECH = RFC 9849 (2026-03) but ~0.06 %
real-world usage → not v1.0 cover; Wycheproof/C2SP + NIST CAVP named
for S1c. The roadmap carries these via the S1 amendments and the
next-session list; nothing in the annex changes stage order.

## Aggregator verification of reviewer claims (post-merge re-checks)

- A4-F3 (remote divergence) — verified TRUE live (ls-remote before and
  after fetch); reconciliation fast-forwarded to cc4564f.
- A1-F5 (orphan doubly broken) — verified TRUE (temporary wiring:
  E0425 ×2; with scoping fixed, KAT failures reproduced by A1
  independently; orchestrator re-confirmed the compile failure).
- A1-F1/F2 (doc claims) — verified TRUE on the tree; fixed this run.
- A2-F16 (profiles.json unignored) — verified TRUE (check-ignore
  probe); fixed this run.
- A1-F4 (per-platform counts as derivations) — verified TRUE against
  the PRE-merge tree; the merge made them CI-verified (76/75/75),
  which A1-C4's residue now reflects. Recorded as: finding true at
  review time, superseded by the merge.
- A3-F1 (conditions 7/8 invisible) — verified TRUE pre-merge;
  record-0002 amendments closed it; confirmed present post-merge.
- A2-F12 (only 5/11 crates forbid unsafe) — verified TRUE pre-merge;
  D-0018 closed it (all crates now forbid except holo-util).

## Anchors deposited (out-of-band)

- The SHA-256 of THIS record is quoted in the `harness/memory/BACKUPS.md`
  line of the run that pushes it (machine-checked by the harness-audit
  job per D-0017) and in the run's final report to the owner.
- GitHub server-side push events provide the second anchor.
- Owner spot-check: `git show HEAD:harness/adversarial/verdicts/0003-cross-validation.md | sha256sum` must equal the hash quoted in the BACKUPS.md line of the backup that carries this record.

## Verbatim archives (hashes)

See the table above (0003-verdicts-A1/A2/A3/A4, 0003-reviewer-prompts)
— committed in the same backup as this record.

chain: 72d8858d012b4a2d8477fd96af33c7aabcf0e7dda0d659ebd138c37ace3c05c5
