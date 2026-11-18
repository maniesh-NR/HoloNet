# Progress review 0002 — adversarial assessment of completed work + S1 charter readiness

Run: 2026-11-17 (UTC). Orchestrator: ZCode session on the owner's
Windows host (first Windows-host run; no Rust toolchain available —
verification was static analysis + public GitHub API only, a disclosed
limitation recorded in several verdicts).

**This is a PROGRESS REVIEW with NO stage-transition authority**
(WORKFLOW §2.6, D-0011): it assesses (a) the work completed since gate
0001 (commit range `53ff229..8761716`: harness installation, gate-0001
remediation, backup pipeline) and (b) the S1 charter's readiness. S1
itself was already authorized at gate 0001 and remains NOT started; this
review amends the S1 charter with binding conditions recorded below.

Panel: A1–A4 per `harness/ADVERSARIAL.md`, all one model family, one
orchestrator — procedural separation only (independence limits restated
in `0002-reviewer-prompts.md`). Non-panel analysts (Blue-Forensics,
Green-R1, Green-R2) produced reports used for remediation and roadmap
inputs; they do not vote. Their briefs are archived in the prompts file
appendix; full reports live outside the repo at
`project-management/reports/` (owner workspace) and are summarized in
the session journal.

## Launch incidents (recorded per A4/A3 dissents; honesty over polish)

- The panel was launched as one parallel batch of seven agents; the host
  concurrency limit cut six mid-run. A1/A4/Blue had partial progress and
  resumed with their original context; A2/A3/Green-R2 restarted with
  identical prompts. All resumes then ran concurrently. Blindness was
  preserved throughout: no reviewer saw another reviewer's output before
  filing.
- During resume, the ORCHESTRATOR MISLABELED four agents' roles in
  resume messages (positional ID mix-up); the error was detected and
  corrected mid-run before any verdict was filed; affected agents
  acknowledged the correction and confirmed they had executed their
  ORIGINAL prompt's mandate. Two agents note the incident in their
  verdicts (A3 dissent, A4 dissent) as an instance of the correlated
  orchestrator-failure mode ADVERSARIAL.md §Independence limits warns
  about. It is recorded here rather than smoothed over.
- Two agents hit transient quota/backend failures near completion and
  were re-resumed per the protocol's re-launch rule (a launch failure
  counts as non-response and requires re-launch before consensus).

## Verdicts (verbatim, as returned)

### A1 — Reliability Skeptic

All verification complete — the final batch landed before the
interruption (`sandbox/latest` = main = 8761716 verified via
`git ls-remote`; release.yml pins confirmed). Filing now from the
evidence in hand.

## A1 Review Summary — what I ran and checked myself

Static test count (grep `#[test]` per crate): config 10, crypto 17,
engine 8 (2 unit + 6 integration), net 9, proto 2, socks 5, ss 7,
theme 10, util 7 = **75 total**, countable from the tree; the 75/74/72
per-platform arithmetic checks out exactly against the three cfg gates
(rand.rs:110 unix, holo-config lib.rs:325 unix, integration.rs:365+448
linux → 75−1=74 macOS, 75−3=72 Windows). All dependencies are workspace
path deps — zero registry crates. `session.connect` is default-deny:
every non-shadowsocks driver hits the explicit milestone error
(holo-engine lib.rs:277-283), and the SS path runs a real reachability
probe before reporting "connected" (:292-303). Gate-record hash tie-in
verified at blob level: `git show
HEAD:harness/adversarial/verdicts/0001-S1-gate.md | sha256sum` =
`5bbc465c…`, matching BACKUPS.md:7 (the working-tree mismatch is a
CRLF-checkout artifact of `core.autocrlf=true`, not tampering).

The rot is in the **public evidence layer**, found via anonymous GitHub
API at the exact HEAD commit 8761716: CI run 43382900976 (push,
2026-11-13T07:02:48Z) shows **ubuntu-latest "Tests (holo-engine
integration)" FAILED** and **"Rust 1.77.2 compatibility" "Check" step
FAILED** — only windows-latest's failure is disclosed in STATE.md. The
"75 green on Linux" claim (STATE.md:14-18, BACKUPS.md:7) is locally
attested only; its only public counterpart at the same commit is red.
Additionally, only 3 releases exist publicly (v0.3.0 src-only,
v0.2.0-linux with SHA256SUMS, empty v0.2.0); the README's four-row
v0.2.0 release table and per-release SHA256SUMS promise are not backed
by downloadable artifacts, despite "success" release-workflow runs on
those tags. Positives verified: ARCHITECTURE "Current workspace" counts
match the tree; TECHNIQUES.md citations are real (RFC 6298/5681/9065,
SIGOPS 2008, CACM 2017, SIGCOMM'95, ACM Queue); S1 is genuinely not
started (no X25519/BLAKE2/FFI code); the 1.77.2-release builds at
v0.3.0 tags (Nov 8, pre-hardening) did succeed — the regression is in
the gate-0001 hardening commits. Logs are API-403 for anonymous access,
so failing-test identity within the integration suite is suspected (the
env-dependent throughput floor at integration.rs:351-357 and the 2 MB
RSS bound at :439-442 are the prime suspects), while the job/step
failures themselves are verified.

---

AGENT: A1 Reliability Skeptic
VERDICT: PROCEED_WITH_CONDITIONS
FINDINGS:
- [F1] The headline baseline claim "tests 75 green (Linux)" is
  contradicted by the project's own public CI at the exact reviewed
  commit: run 43382900976 (push @ 8761716, 2026-11-13T07:02:48Z), job
  "Test (ubuntu-latest)", step "Tests (holo-engine integration)" →
  failure ("Tests (bins)" skipped after it). STATE.md:14-18 and
  BACKUPS.md:7 assert green from a local run the same day; the CI
  failure 25 seconds after the push went unnoticed — no commit or
  STATE.md amendment in the 4 days since. Failing test unidentified
  (logs 403 anonymously); prime suspects are the environment-dependent
  perf tests: DEBUG-loopback throughput floor `mbps > 1.0` and the
  < 2 MB RSS bound with its 200 ms settle sleep. — evidence:
  api.github.com/repos/maniesh-NR/HoloNet/actions/runs/43382900976/jobs
  (job 131744590726, verified); harness/memory/STATE.md:14-18;
  harness/memory/BACKUPS.md:7;
  engine/crates/holo-engine/tests/integration.rs:351-357,429-442
  (failure verified; cause suspected)
- [F2] The "Rust 1.77.2 compatibility (Win7/Catalina baseline)" job
  FAILED at HEAD ("Check" step; toolchain install succeeded) —
  undisclosed anywhere. STATE.md discloses only the windows-latest red
  (STATE.md:19-23); README asserts all release binaries are built with
  Rust 1.77.2 (README.md:79-82) and release.yml pins every platform job
  to 1.77.2 (.github/workflows/release.yml:3,29-33,75-78,119-122,165+).
  The gate-0001 hardening commits (53ff229..8761716) regressed the very
  floor the release pipeline and platform matrix (README.md:149-155)
  depend on; the pre-hardening v0.3.0-* release builds (2026-11-08)
  passed on 1.77.2. Cause unknown (log inaccessible); the job-level
  failure is a verified public fact. — evidence:
  api.github.com/…/runs/43382900976/jobs (job 131744590636, verified);
  .github/workflows/ci.yml:108-122;
  .github/workflows/release.yml:3,29-33 (verified)
  [Aggregator note, not the reviewer's words: Blue-Forensics
  independently diagnosed the probable cause — 53ff229 rewrote
  Cargo.lock from v3 to v4, which cargo 1.77.2 cannot read; remediated
  this run.]
- [F3] README release-table claims vs published reality: only 3
  releases exist publicly — v0.3.0 (src tarball only), v0.2.0-linux
  (tarball + SHA256SUMS.txt), v0.2.0 (no assets). v0.2.0-windows,
  v0.2.0-macos, v0.2.0-android, and ALL v0.3.0-* releases are absent
  (releases/tags/v0.3.0-windows → 404) even though their release.yml
  runs concluded "success" on 2026-11-08 and the tags exist on the
  remote. README.md:84-95 promises per-OS prebuilt binaries with
  "SHA256SUMS.txt next to its archives" for every release. — evidence:
  api.github.com/repos/maniesh-NR/HoloNet/releases (3 entries,
  verified); api.github.com/…/releases/tags/v0.3.0-windows (404,
  verified); README.md:84-95; .github/workflows/release.yml:61-62,107-108
  (runs verified success; releases verified absent)
- [F4] README's OpenSSL cross-check claim is claim-rot: "recorded in
  the harness session journals" (README.md:31-35) — the only session
  journal that exists
  (harness/memory/sessions/2026-11-13-harness-gate0001.md, read in
  full) contains no OpenSSL cross-check record; the pre-recycle
  journals were lost. Gate-0001 A1-F10 process-evidence debt is
  therefore not merely open, it is now misstated. — evidence:
  README.md:31-35 vs harness/memory/sessions/ (one file, no OpenSSL
  mention) (verified)
- [F5] D-0009 (owner decision: security advisory vs v0.3.1 re-release
  for pre-hardening published binaries) is still pending 4 days after
  escalation — zero commits since 2026-11-13 (HEAD is the gate-0001
  backup). Compounding: D-0009's exposure text (DECISIONS.md:52-59)
  assumes the v0.2.0/v0.3.0 binaries are published, but per F3 most of
  those releases no longer exist — the disclosure's factual basis is
  stale in both directions and nobody reconciled it. — evidence:
  harness/memory/DECISIONS.md:52-59; git log (8761716 = 2026-11-13,
  latest) (verified)
- [F6] Verified positives (my own counts/checks, not trust): 75
  `#[test]` countable; per-platform 75/74/72 arithmetic exact vs the
  three cfg gates (engine/crates/holo-util/src/rand.rs:110;
  engine/crates/holo-config/src/lib.rs:325;
  engine/crates/holo-engine/tests/integration.rs:365,448); zero
  third-party crates (all Cargo.toml [dependencies]/[dev-dependencies]
  are path deps); `connect` default-deny with honest per-driver
  milestone errors (holo-engine/src/lib.rs:277-283) and a real
  pre-"connected" reachability probe (:292-303) — no fake-success path
  found; links importer maps exactly the 7 schemes into those driver
  names (holo-config/src/links.rs:31-42); unsupported-driver
  integration test asserts the milestone error (integration.rs:460+);
  ARCHITECTURE.md "Current workspace" (docs/ARCHITECTURE.md:21-41)
  matches my per-crate counts; TECHNIQUES.md citations real (RFC
  6298/5681/9065, SIGOPS 2008 CUBIC, CACM 2017 BBR, SIGCOMM'95 DRR, ACM
  Queue CoDel, RFC 8439 with the honest RFC 7539-supersession note);
  gate-0001 record SHA tie-in holds at blob level (BACKUPS.md:7 hash =
  `git show HEAD:…0001-S1-gate.md | sha256sum`; working-tree file
  differs only by CRLF checkout, core.autocrlf=true); `sandbox/latest`
  == `main` == 8761716 (git ls-remote); windows-latest red is the
  disclosed honest interim state and failed at exactly the predicted
  step (holo-ss) (verified)
- [F7] Baseline re-verification is currently impossible in-place and
  the fallback is red: STATE.md:56-58 instructs re-verifying with
  `cargo test --workspace` after restore, but this Windows review host
  has no Rust toolchain (stated constraint), leaving public CI as the
  only verification channel — and CI is red on ubuntu (F1). The socks
  CI step also still enforces via `|| true` + log-grep rather than exit
  code (ci.yml:41-50) — fragile seam, retained unchanged. — evidence:
  harness/memory/STATE.md:56-58; .github/workflows/ci.yml:41-50
  (verified)
- [F8] The current run's prompt archive
  `harness/adversarial/verdicts/0002-reviewer-prompts.md` is untracked
  (git status shows `??`) — mid-run normal, but per the gate-0001 A4-F5
  lesson it must land in this run's end-of-run backup or this progress
  review loses its auditable prompt record. — evidence: git status @
  working tree (verified)

CONDITIONS:
- [C1] Diagnose the ubuntu-latest integration failure at 8761716
  (re-run the workflow and/or read the job log with repo access; name
  the failing test), then either land a fix commit whose ubuntu CI is
  green, or amend STATE.md with the failure, its named cause, and an
  accepted-risk rationale (e.g., re-scoped floor/RSS assertion for
  shared runners). Checkable: green ubuntu job on a commit after
  8761716, or the STATE.md amendment quoting the failing test name.
- [C2] Restore or honestly re-scope the 1.77.2 floor: fix the
  regression so the "Rust 1.77.2 compatibility" job is green at the
  next commit, or record a DECISIONS.md entry amending the
  Win7/Catalina floor claim and update README/STATE accordingly — the
  tree must not assert a platform floor its own legacy job fails to
  check. Checkable: legacy-toolchain job conclusion on the next commit,
  or DECISIONS/README text.
- [C3] Make README's Releases section match published reality (which
  releases/assets actually exist, per the anonymous API), state why the
  "success" release runs produced no public releases for
  v0.2.0-windows/macos/android and v0.3.0-* (drafts? deleted?), and
  reconcile D-0009's exposure list with what is actually still
  downloadable; resolve or explicitly re-escalate the D-0009 owner
  decision. Checkable: README matches api.github.com/…/releases output;
  DECISIONS.md gains the decision or a dated re-escalation.
- [C4] Fix the OpenSSL claim: either record real cross-check process
  evidence in a session journal or reword README.md:31-35 to say the
  records were lost in the sandbox recycle — "recorded in the harness
  session journals" must not remain in the tree while the journals
  contain nothing. Checkable: README text or journal content.
- [C5] STATE.md must disclose the full CI state at HEAD (ubuntu red,
  1.77.2 red — not windows-only) so the next restore's verification
  guidance is complete, and land `0002-reviewer-prompts.md` plus this
  review's record in the end-of-run backup per WORKFLOW §2.5.
  Checkable: STATE.md text; tracked file in the pushed commit.

DISSENT/NOTES: The aggregator must NOT record "baseline 75 green" for
this review cycle — the only publicly verifiable execution of the suite
at the reviewed commit is red on Linux CI (F1), and my own verification
is static (grep-level counting plus API evidence), not execution: this
host has no Rust toolchain, a disclosed limitation that also means I
could not reproduce or rule out flakiness. Two premises in my own prompt
did not match the tree and the record should not inherit them: README
makes no "72.9 MB/s" claim anywhere in the repo (only the RSS +88–376 KB
figures, which match integration.rs:434-438), and topic count is 20 (not
absent). The engine's honesty architecture (default-deny dispatch,
milestone errors, fail-closed entropy) held up under tracing — my
verdict is not a code-trust failure but a baseline-evidence failure:
three undisclosed-or-stale public claims (CI red, absent releases,
OpenSSL journals) that the harness's own "claims must be
countable/verifiable" rule (WORKFLOW §3) treats as binding. Note for the
panel: F1 and F2 could each be a flaky runner and a toolchain fluke
respectively — but the step-level pattern (integration step failing on
ubuntu; "Check" failing after successful 1.77.2 install) argues against
both, and four days of non-observation is itself the finding.

### A2 — Security Red

Evidence gathering is complete. Here is my review.

# A2 Security Red — Progress Review (work since gate 0001 + S1 charter), record 0002-progress-review

## What I executed vs. read

Ran read-only commands: `git log/diff/tag` (`53ff229..8761716`),
targeted greps (secrets, `unsafe`, `set_permissions`, `is_loopback`,
`rand::` consumers), full reads of `docs/THREAT-MODEL.md`,
`holo-util/src/rand.rs`, `holo-ss/src/lib.rs` (complete server + client
paths), `holo-crypto/src/lib.rs` (Poly1305, GHASH, AEAD, ct_eq, AES,
GCM), `holo-net/src/lib.rs` (ProbeGuard), `holo-socks/src/lib.rs`
(bind), `holo-engine/src/lib.rs` (IPC token, proxy bind),
`holonetd`/`holonetctl` mains, both gate-0001 verdict files, ROADMAP. No
files modified, no builds, no mutating git commands.

## (a) Work completed since gate 0001

Only harness/docs plus two small engine changes: the stale "randomized
slow-close" comments fixed inside `serve_conn` (round-2 C2 satisfied)
and `holonetctl` now exits loudly on entropy failure. The backup
pipeline is now operational (`sandbox/latest` tag exists; BACKUPS.md
carries a success line with the record hash). No new engine code, no new
tests — so no new shipped risk was introduced by this run, and S1
remains unstarted exactly as chartered.

## (b) Crypto/data-plane findings (the new material this review adds)

**Replay protection is absent from the shipped SS server and from the
threat model itself.** `ServerConn::accept` reads the client's 32-byte
salt and derives the subkey with zero tracking of previously seen salts.
SIP004/Shadowsocks-AEAD requires server-side salt replay filtering;
without it, a censor can capture a genuine handshake (salt + first
chunk) and replay it — the server accepts, re-dials the recorded target
(replay/DoS), and the behavior is a known active-probing fingerprint
(real implementations reject replayed salts; holo-ss accepts).
THREAT-MODEL §C lists the close-vs-hang distinguisher, deterministic
slow-close, and unbounded ProbeGuard — but never mentions replay. The S1
server-path backlog therefore does not contain it either, and gate 0002
as chartered could pass with replay still unaddressed.

**The shipped "xchacha20-ietf-poly1305" cipher is not the standard
construction.** `Direction::seal/open` call
`hchacha20(&self.subkey, &zero_iv)` — a zero 16-byte input instead of
the nonce's first 16 bytes — and the assembled 24-byte `n24` is built
and dropped (the exact dead store binding condition 8 ordered removed).
holo-crypto contains a correct standard `aead_xchacha20poly1305_*` that
holo-ss does not call. Security assessment: HChaCha20(key, 0^16) is a
deterministic key transform with no nonce reuse, so this is not a
confidentiality break — but the cipher is advertised under a standard
name in shipped v0.3.0 and will not interoperate with any mainstream SS
peer. Condition 8 already charters the fix or de-scope; the residual
point is that a *mislabel* on a live wire protocol should be treated
with the same honesty bar as every other claim (advisory text if it
survives to another release).

**Windows secret-at-rest will regress the day the S1 FFI lands.** All
0600 enforcement is `#[cfg(unix)]`; there is no Windows ACL tightening
anywhere. The daemon's data dir falls back `$HOME` → `"."` — and `HOME`
is typically unset on Windows (USERPROFILE is the convention), so
`ipc-token` and `profiles.json` (all proxy credentials) would land in a
CWD-relative `.config/holonet` with default ACLs. Today this is masked
because fail-closed entropy kills the daemon before any write; S1 item 0
makes it live. The charter's item 0 acceptance covers entropy provenance
but says nothing about this.

**What I verified as sound** (so the aggregator doesn't over-correct):
Poly1305 clamp/fold matches RFC 8439 (2^130-only reduction, correct
final p-subtraction, limb bounds hold under my own recomputation);
GHASH is the standard reflected-bit algorithm with branches only on the
public accumulator; `ct_eq` guards both AEAD verifies and the IPC token
compare; GCM carries NIST tc3/tc4 vectors; empty-AAD TCP framing,
12-byte LE nonce increment, HKDF-SHA1 "ss-subkey", and
EVP_BytesToKey(MD5,32) all match SIP004; oversized-length rejection and
the opaque single error are genuinely wired; the rand split has exactly
one non-security consumer left (profile IDs) and it is correctly
classified; the tree remains credential-clean and `.gitignore` covers
the credential-shaped classes.

**Carried, still open, still chartered** (re-listed so the aggregator
cannot mark them done by silence): ProbeGuard unbounded growth;
deterministic slow-close and the close-vs-hang distinguisher;
off-loopback `proxy_listen` refusal (still binds any user-supplied
string, default SOCKS listener has no auth); mechanical rand-split
enforcement; Windows CI red by design until the FFI; artifact signing
at S7. One user-safety item I press hard: **D-0009 has no deadline** —
the published v0.2.0/v0.3.0 Windows binaries (predictable splitmix IPC
token → local auth → `profiles.list` credential theft) remain the
current public downloads four days after the disclosure was recorded,
and S1 will take weeks; every additional download is a user on a
vulnerable build.

AGENT: A2 Security Red
VERDICT: PROCEED_WITH_CONDITIONS
FINDINGS:
- [F1] Work since gate 0001 is honest and minimal: comment-only
  slow-close fixes in serve_conn, fail-closed entropy error in
  holonetctl, verdicts/backup installed; no new engine code or tests;
  backup pipeline now operational (sandbox/latest exists) — evidence:
  git diff 53ff229..HEAD (holo-ss/src/lib.rs:745-747,764-766;
  holonetctl/src/main.rs:34-43); harness/memory/BACKUPS.md:6; git tag -l
  (verified)
- [F2] No salt replay protection in the shipped SS server:
  ServerConn::accept accepts any 32-byte salt with no seen-salt cache,
  enabling captured-handshake replay (re-executes recorded target, DoS,
  active-probe fingerprint); the omission exists in the threat model
  itself, so the S1 backlog cannot catch it — evidence:
  engine/crates/holo-ss/src/lib.rs:599-634 (no salt tracking anywhere
  in file); docs/THREAT-MODEL.md:54-78 §C (verified)
- [F3] Shipped "xchacha20-ietf-poly1305" violates the standard it is
  named after: HChaCha20 invoked with zero 16-byte input instead of
  nonce[0..16], assembled n24 is dead; holo-crypto's correct standard
  construction is unused by holo-ss; non-interop with mainstream SS
  peers; binding condition 8 (ROADMAP) outstanding. Assessed as a
  deterministic key transform — mislabel/interop defect, not a
  confidentiality break — evidence: engine/crates/holo-ss/src/lib.rs:
  99-105,117-121 vs engine/crates/holo-crypto/src/lib.rs:610-638;
  harness/memory/ROADMAP.md:220-224 (verified; security-neutrality
  argued from code reading, suspected)
- [F4] Windows secret-at-rest gap latent in the tree: all 0600
  enforcement is #[cfg(unix)] (no Windows ACL hardening anywhere);
  holonetd data_dir falls back HOME → "./.config/holonet" and HOME is
  typically unset on Windows, so token+profiles.json would be written
  CWD-relative with default ACLs the day the S1 FFI makes Windows token
  generation succeed — evidence:
  engine/crates/holonetd/src/main.rs:6-14;
  engine/crates/holo-engine/src/lib.rs:88-99;
  engine/crates/holo-config/src/lib.rs:220-221 (verified)
- [F5] D-0009 disclosure still pending with no deadline: published
  v0.2.0/v0.3.0 Windows binaries (predictable splitmix IPC token →
  local auth → profiles.list credential-theft chain) remain the live
  downloads four days after disclosure — evidence:
  docs/THREAT-MODEL.md:132-138; harness/memory/STATE.md:33-35;
  harness/adversarial/verdicts/0001-verdicts-round1.md:77-80 (verified)
- [F6] ProbeGuard maps still grow unboundedly (insert/remove only,
  `last` never read for decay); deterministic slow-close and close-vs-
  hang distinguisher unchanged — all three known and chartered to land
  by end of S1 — evidence: engine/crates/holo-net/src/lib.rs:730-775;
  engine/crates/holo-ss/src/lib.rs:764-770;
  harness/memory/ROADMAP.md:75-80 (verified)
- [F7] Off-loopback proxy_listen refusal still absent: user-supplied
  settings string bound directly, no is_loopback check; default SOCKS
  listener has no auth — binding condition A2-C6 deferred to S6 as
  agreed — evidence: engine/crates/holo-engine/src/lib.rs:311-323;
  engine/crates/holo-socks/src/lib.rs:204-215;
  docs/THREAT-MODEL.md:27-30 (verified)
- [F8] Mechanical rand-split enforcement (A2-C3) not yet implemented;
  sole non-security consumer outside holo-util is holo-config profile-ID
  hex (correctly classified) — evidence:
  engine/crates/holo-util/src/rand.rs:69-99;
  engine/crates/holo-config/src/lib.rs:129 (verified)
- [F9] Crypto core verified sound by reading: Poly1305
  clamp/fold/final-subtraction correct under recomputation, GHASH
  standard reflected-bit form branching only on public accumulator,
  ct_eq at both AEAD verifies and token compare, GCM NIST tc3/tc4
  vectors, HKDF/ChaCha/EVP/SHA vectors present, empty-AAD framing +
  12-byte LE nonce match SIP004 — evidence:
  engine/crates/holo-crypto/src/lib.rs:448-556,845-900,587-606,1254;
  engine/crates/holo-ss/src/lib.rs:265-303 (verified)
- [F10] Threat-model thin spots: §C omits replay as a prober
  capability; §A frames the unauthenticated local SOCKS hop only as a
  config footgun, not the default consequence (any local process can
  ride the tunnel and blend its traffic with the user's); no deadline
  mechanism for D-0009 — evidence: docs/THREAT-MODEL.md:27-30,54-78,
  132-138 (verified as omissions)

CONDITIONS:
- [C1] Amend the S1 server-path backlog and THREAT-MODEL §C to include
  server-side salt replay protection: a bounded per-server seen-salt
  cache checked in ServerConn::accept, replay rejected through the same
  opaque auth-failure path (no new oracle), plus a named test (a
  replayed salt+first-chunk connection is rejected) — verifiable in
  ROADMAP.md text before S1 code starts and by the test at the S1→S2
  gate.
- [C2] S1 item 0 acceptance must add Windows secret-at-rest hygiene:
  data_dir falls back to USERPROFILE and refuses/errors when neither
  HOLONET_DATA nor HOME/USERPROFILE resolves (never CWD "."), and a
  recorded decision on Windows ACL tightening for
  ipc-token/profiles.json is reflected in THREAT-MODEL §A/§G —
  verifiable in ROADMAP text and code by the S1→S2 gate.
- [C3] D-0009 must be closed before S1 is marked DONE (at latest, the
  S1→S2 gate): publish an advisory and/or cut v0.3.1 from the hardened
  tree and supersede the vulnerable Windows assets, or record an
  explicit dated owner decision not to — verifiable in DECISIONS.md
  plus release assets.
- [C4] Re-confirm the carried conditions as S1→S2-gate checks:
  mechanical rand-split enforcement (A2-C3), ProbeGuard bounding +
  CSPRNG-jittered slow-close + close-vs-hang uniformization (round-2
  C4), off-loopback proxy_listen refusal (A2-C6), and the
  standard-XChaCha switch or honest de-scope with the dead n24 store
  removed (binding condition 8) — all already chartered; this condition
  only binds their appearance in the gate checklist.

DISSENT/NOTES: The aggregator must not smooth over three things. (1) F2
is a threat-model defect, not just a backlog omission: THREAT-MODEL §C
enumerates the prober's tricks and omits replay entirely, so as written
the model certifies a defense surface it never examined — fix the model
first, then the code. (2) F3's cipher mislabel lives in shipped v0.3.0
binaries; if it survives into the next published release, its fix must
be disclosed with the same honesty standard as the D-0009 disclosure,
not silently patched. (3) D-0009 has been pending since 2026-11-13 with
no owner-decision deadline; for the target user population (shared
machines, stalkerware exposure) the vulnerable Windows downloads are
the single highest real-world-risk item in the project today, and it is
a decision, not engineering — it should not ride behind weeks of S1
crypto work. Minor non-blocking note: ClientConn::write emits an extra
empty 34-byte chunk on every write() call (holo-ss/src/lib.rs:553-566,
unconditional write_chunk); it appears dead on the split_rw path but
should be checked or fixed during the S1 framing work. My round-1/
round-2 posture is unchanged in kind: the entropy foundation and
shipped error-opacity discipline are real; nothing found this run makes
starting S1 unsafe, but the S1 acceptance list is incomplete without
C1-C2, and C3 is a user-safety clock already running.

### A3 — Strategy Adversary

Verification is complete — evidence base is sufficient. Composing the
A3 review now.

---

# A3 — Strategy Adversary: progress review 0002 (work to date + S1 charter)

## 1. Sequencing / dependencies — the chain itself is sound

The S1 dependency order is correct and I found **no skipped
prerequisite**: HKDF/AES/SHA-2 exist in holo-crypto (docs/RESTORE.md:
13-17), bignum/RSA was correctly pulled forward from S2 into S1
(harness/memory/ROADMAP.md:71-73), ExpandLabel precedes TLS
(ROADMAP.md:69-70), X25519 precedes TLS/QUIC/WireGuard, and the Windows
FFI precedes the Windows-green CI criterion (ROADMAP.md:50-59, 88-92).
Binding conditions 7 and 8 (rand-split enforcement, XChaCha20
standardization) are already pulled into S1. Two sequencing defects
remain:

- **Off-loopback `proxy_listen` refusal is deferred to S6 while the
  exposure ships today.** Binding condition 6 says "(A2-C6; S6
  otherwise)" (ROADMAP.md:215-216), but the live v0.3.0 data plane
  already binds `proxy_listen` (ROADMAP.md:40-41). A non-loopback bind
  today is an unauthenticated open proxy in a censorship tool. This is
  ~20 LOC plus one test; deferring it four stages is sequencing
  failure, not scoping discipline. Pull it into S1.
- **The server-path hardening backlog carries slippage wording**: "must
  land by S2" (ROADMAP.md:75) conflicts with the acceptance list that
  demands the named tests at the S1→S2 gate (ROADMAP.md:111-115).
  Tighten to "lands in S1" — ProbeGuard's unbounded map is real
  (holo-net/src/lib.rs:732, `last: HashMap<IpAddr, Instant>`, no
  eviction).

## 2. Scope realism — S1 is two stages compressed into one

Measured baseline: the whole workspace is ~7,600 LOC / 75 tests
(per-crate `wc` sums; `#[test]` count = 75, verified — matches
STATE.md). For calibration, holo-crypto's *entire* v0.3.0 core was
1,312 LOC / 17 tests. S1 as chartered adds: Windows FFI, BLAKE2s **and**
b, X25519, AES-CFB, ExpandLabel, a full bignum with CIOS Montgomery
**plus** PKCS#1 v1.5 and PSS verify, three hardening items with named
tests, the XChaCha20 wire change, rand-split enforcement, and Windows
CI-green (ROADMAP.md:50-123). The bignum/RSA item alone rivals the
holo-crypto v0.3.0 session. Two internal cuts make it survivable:
**BLAKE2b has no consumer anywhere in S1–S7** (WireGuard needs BLAKE2s;
TLS/QUIC use SHA-2 — cut or justify, ROADMAP.md:60), and the RFC 7748
§5.2 **1,000,000-iteration vector** (ROADMAP.md:101-102) is a
debug-mode CI/runtime hazard that needs an explicit execution-mode
decision (release-mode or opt-in cfg) before implementation. Either
split S1 into S1a (item 0 FFI + Windows green + hardening + conditions
7/8) and S1b (crypto extensions), or keep one stage with enforced
ordering (item 0 merges first, Windows green before any
crypto-extension item) plus the tripwire from §3 below.

Spot-checks downstream: **S2** is realistic *only if* it declares "no
X.509 parser — SPKI pinning on raw DER" (currently unstated,
ROADMAP.md:125-132) and the binding-condition-1 driver deliverable is
merged into the charter body (see §3); "SNI masking" (ROADMAP.md:128)
is undefined and untestable as written. **S3** is plausible given
holo-net's existing link-sim, but "interop-observable framing only
(loopback)" (ROADMAP.md:141) is ambiguous. **S5** is the widest stage
(9 providers, ~51 tests, ROADMAP.md:160-165) and the most
tripwire-prone — split it. **S6** cannot be chartered under current
policy at all (see §5). **S7** has zero packaging artifacts in-tree
today (no flatpak/AppImage/NSIS files exist; only app_qt/CMakeLists.txt)
and its acceptance "packaging reproducible from a clean checkout" /
"each frontend displays real session state" (ROADMAP.md:181-182) has no
named test mechanism — frontends are ~2.2k LOC total, thin, so the
wiring is feasible but the criteria as written are not checkable.

## 3. Descope rules — the predecessor's binding conditions are still unmet

Gate-0001's A3 conditions required, "before gate 0002": the descope
rule must **NAME** the v1.0 TLS/QUIC protocol (ROADMAP.md:184-188 still
says only "SS + one TLS/QUIC-based protocol"), the tripwire must define
**N** (ROADMAP.md:205-209 leaves "N recorded sessions" undefined), and
terminal gate 0008 must be chartered (nothing exists). One full gate
cycle has passed with these still open — repeated unmet conditions
erode the binding mechanism. Draft language, ready to paste into
ROADMAP at this run's amendment:

- *Named protocol (default, owner may override):* "v1.0 ships
  Shadowsocks AEAD + **trojan** (TLS-based, framing over holo-tls)
  live; hy2/tuic (QUIC-based) become the named alternates only if S3
  completes on schedule."
- *Tripwire:* "If a stage is not acceptance-complete after **4** session
  journals in `harness/memory/sessions/` (calibration: exactly 1 journal
  exists today), the next gate MUST decide — split the stage, cut
  breadth under the descope rule, or extend with recorded owner
  sign-off (DECISIONS.md entry)."
- *Terminal gate:* "Gate 0008 (S7 completion + release assessment):
  per-platform green matrix, artifact signatures per condition 5,
  D-0009 disclosure status, THREAT-MODEL re-review, descope-rule
  conformance — all before any v1.0 publication."

Also: **the S2 charter body never absorbed binding condition 1's
deliverable** ("S2 delivers one TLS-based driver wired into
`session.connect`", ROADMAP.md:196-200) — it lives only in the
carried-conditions section. Merge it into the S2 charter with named
tests before the S1→S2 gate, or the next panel inherits an uncheckable
condition.

## 4. Gate-numbering collision (flagged per mandate)

ROADMAP hardcodes "Gate 0002 (S1 → S2)" at ROADMAP.md:123 (also :111,
:192). Today's record is `0002-progress-review.md` — a progress review,
not the S1→S2 gate. WORKFLOW §2.5 (harness/WORKFLOW.md:50-53) makes
records immutable once pushed, so the fix must land **before** this
record is pushed: a DECISIONS-logged ROADMAP amendment stating that
record numbers are sequence numbers, gate identity is the stage
transition, and the S1→S2 gate takes the next sequential number
(projected 0003). Rewrite the three hardcoded references to "the S1→S2
gate (next record after 0002-progress-review)". Also add one WORKFLOW
line (with DECISIONS entry) authorizing progress reviews in the verdict
namespace, since §2 currently defines records only for gates.

## 5. Operational risks

- **Windows-red CI dilutes the failure signal for all of S1**: the
  matrix runs windows-latest with `fail-fast: false`
  (.github/workflows/ci.yml:13-17) and STATE.md:19-23 honestly declares
  it red until item 0. Every push during S1 is red, so a *new* Windows
  regression is indistinguishable from the known one; the README CI
  badge (README.md:5) shows the workflow failing on main today.
  Mitigation: `continue-on-error: true` on the Windows job with display
  name "Test (windows-latest; expected-red until S1 item 0)", flipped
  off at item-0 completion; plus the ordering condition that
  Windows-green lands *before* any S1 crypto-extension item merges,
  bounding the red window. The per-platform test-count ledger
  (STATE.md:14-16; verified 75) is unaffected.
- **The MSRV floor is under-checked**: the legacy 1.77.2 job runs
  `cargo check --workspace` on ubuntu only (ci.yml:103-119) — no
  `x86_64-pc-windows-msvc` 1.77.2 check exists yet, and windows-latest
  tests on stable. The S1 acceptance requires fixing this
  (ROADMAP.md:89-92); it must not be forgotten at the S1→S2 gate. Note
  also: windows-latest is Server-grade, so the actual Win7 SP1 floor
  path (RtlGenRandom via advapi32) is **never CI-tested on the floor
  OS** — the charter's BCrypt claim (ROADMAP.md:97, "BCryptGenRandom
  alone is Win8+") is imprecise (the API is Vista+, but
  `BCRYPT_USE_SYSTEM_PREFERRED_RNG` can fail on Win7 with CNG disabled)
  and the real mitigation is an owner-machine Win7 smoke test before
  any release ships the FFI. Mark: suspected (reasoned, not measured).
- **S6 has a policy contradiction**: D-0008 confines `unsafe` to
  rand.rs *only* (DECISIONS.md:44-51), yet S6 needs Linux TUN ioctl,
  wintun (a third-party DLL, colliding with the "0 third-party crates"
  badge claim, README.md:9 / D-0002, DECISIONS.md:7-11), and utun; and
  killswitch is chartered as nftables-only while D-0001 makes Windows
  7+ a primary target — no Windows killswitch mechanism exists in the
  charter (ROADMAP.md:167-174). The S5→S6 gate must explicitly amend
  D-0002/D-0008 or S6 hits an unplanned policy fight mid-stage.
- **S5 ships other people's credentials**: "se0316 creds" against
  api2.sec-tunnel.com is named in tracked files (ROADMAP.md:163;
  docs/RESTORE.md:68) — in tension with D-0001 "no credentials"
  (DECISIONS.md:3-6) and WORKFLOW §3.3 (WORKFLOW.md:62). Embedded
  shared credentials in a public GPL binary are burnable, abusable, and
  ToS-exposed; and the "offline fixtures only" acceptance means
  live-API drift is never caught by tests. Owner decision on the
  credentials model required before S5 chartering; split S5 (VPN Gate +
  ≤2 providers first).
- **D-0009 is aging**: the advisory-vs-v0.3.1 decision has sat with the
  owner since 2026-11-13 (DECISIONS.md:52-59); published Windows
  binaries with predictable salts/tokens remain downloadable. Delay
  cost grows daily in exactly the threat model this project serves; and
  if v0.3.1 is chosen, it must be cut **before** the S1 XChaCha20 wire
  change (binding condition 8) lands, so the re-release doesn't break
  its own wire protocol. Note: the XChaCha20 fix itself changes a live
  v0.3.0 cipher (holo-ss/src/lib.rs:96-106, subkey via
  `hchacha20(key, zero_iv)` + 12-byte wire nonce, dead `n24` store
  confirmed) — the honest non-interop note must cover released-binary
  skew, not just external peers.
- **Process note for the audit trail**: this run's orchestration
  mislabeled my role in one resume message (corrected mid-run by the
  coordinator, before aggregation). Harmless here, but it is exactly
  the orchestrator failure mode ADVERSARIAL.md §Independence limits
  warns about; the record should note it.

## Verdict

S1 sequencing is right, nothing skipped, but S1 is overweight, three
predecessor descope conditions are still open, the gate-numbering fix
must precede this record's push, and two deferrals (open-proxy bind,
D-0009) are costing real exposure today. Proceed with the conditions
below.

AGENT: A3 Strategy Adversary
VERDICT: PROCEED_WITH_CONDITIONS
FINDINGS:
- [F1] Gate-numbering collision: ROADMAP hardcodes "Gate 0002 (S1 →
  S2)" while today's record 0002 is a progress review; records are
  immutable once pushed so the fix must land before push — evidence:
  harness/memory/ROADMAP.md:111,123,192; harness/WORKFLOW.md:50-53
  (verified)
- [F2] Descope rule still does not NAME the v1.0 TLS/QUIC protocol,
  tripwire N undefined, terminal gate 0008 unchartered — gate-0001 A3
  conditions one full cycle old and unmet — evidence:
  harness/memory/ROADMAP.md:184-188,205-209 (verified)
- [F3] S2 charter body never absorbed binding condition 1 (one
  TLS-based driver wired into session.connect) — condition lives only
  in carried-conditions section — evidence:
  harness/memory/ROADMAP.md:125-132 vs 196-200 (verified)
- [F4] S1 is two stages of work in one charter (FFI + BLAKE2s/b +
  X25519 + AES-CFB + ExpandLabel + bignum/RSA-CIOS + 3 hardening items
  + XChaCha20 wire change + rand-split + Windows-green) vs workspace
  baseline ~7.6k LOC/75 tests, holo-crypto v0.3.0 = 1312 LOC/17 tests
  — evidence: harness/memory/ROADMAP.md:50-123; engine/crates wc sums,
  #[test] count 75 (verified)
- [F5] RFC 7748 §5.2 1,000,000-iteration vector required "including
  iteration counts" with no execution-mode decision — debug-mode
  CI/runtime hazard — evidence: harness/memory/ROADMAP.md:101-102
  (suspected — runtime estimate unmeasured)
- [F6] Off-loopback proxy_listen refusal deferred to S6 although the
  live v0.3.0 data plane binds proxy_listen today (unauthenticated
  open-proxy exposure shipping now); fix is ~20 LOC + 1 test —
  evidence: harness/memory/ROADMAP.md:215-216,40-41 (verified)
- [F7] Hardening backlog "must land by S2" wording invites slippage
  against acceptance list demanding the named tests at the S1→S2 gate;
  ProbeGuard map confirmed unbounded — evidence:
  harness/memory/ROADMAP.md:75 vs 111-115;
  engine/crates/holo-net/src/lib.rs:730-747 (verified)
- [F8] Windows job red on every push until S1 item 0 (fail-fast:false
  full matrix; README CI badge failing on main) — new Windows
  regressions indistinguishable from the known red during all of S1 —
  evidence: .github/workflows/ci.yml:13-17;
  harness/memory/STATE.md:19-23; README.md:5 (verified)
- [F9] No 1.77.2 Windows-target check exists (legacy job checks Linux
  host only; windows-latest runs stable); Win7 SP1 floor path
  (RtlGenRandom) never CI-tested on the floor OS; charter's
  "BCryptGenRandom alone is Win8+" claim imprecise — evidence:
  .github/workflows/ci.yml:103-119,26-29;
  harness/memory/ROADMAP.md:89-92,97 (verified for CI text; suspected
  for floor-OS claim)
- [F10] S6 uncharterable under current policy: D-0008 confines unsafe
  to rand.rs only while S6 needs TUN/wintun/utun FFI; wintun.dll
  collides with "0 third-party crates" claim; killswitch is
  nftables-only with no Windows mechanism despite D-0001 Win7+ primary
  target — evidence: harness/memory/DECISIONS.md:44-51,7-11,3-6;
  harness/memory/ROADMAP.md:167-174; README.md:9 (verified)
- [F11] S5 ships third-party shared credentials ("se0316 creds") named
  in tracked files, contradicting D-0001 "no credentials" and WORKFLOW
  §3.3; "offline fixtures only" means live-API drift never caught by
  tests; 9 providers is the widest stage — evidence:
  harness/memory/ROADMAP.md:160-165; docs/RESTORE.md:67-71;
  harness/memory/DECISIONS.md:3-6; harness/WORKFLOW.md:62 (verified;
  drift risk suspected)
- [F12] S7 acceptance unmeasurable as written ("packaging reproducible
  from a clean checkout", "each frontend displays real session state" —
  no named test mechanism); zero packaging artifacts in-tree (no
  flatpak/AppImage/NSIS files); frontends ~2.2k LOC total — evidence:
  harness/memory/ROADMAP.md:178-182; tree find (verified)
- [F13] S2 term "SNI masking" undefined/untestable; "no X.509 parser —
  SPKI pinning on raw DER" unstated (hidden ASN.1 dependency risk); S3
  "interop-observable framing only (loopback)" ambiguous; BLAKE2b has
  no consumer in any chartered S1–S7 item; X25519/bignum constant-time
  bar absent from S1 acceptance (vectors-only passes a variable-time
  implementation) — evidence: harness/memory/ROADMAP.md:128,127-132,
  141,60,100-115 (verified text; consumer analysis by inspection)
- [F14] D-0009 pending 4 days; published Windows binaries with
  predictable salts/tokens remain downloadable; if v0.3.1 is chosen it
  must precede the S1 XChaCha20 wire change (which alters a live v0.3.0
  cipher — dead n24 store and zero-IV hchacha construction confirmed) —
  evidence: harness/memory/DECISIONS.md:52-59;
  engine/crates/holo-ss/src/lib.rs:96-106; docs/THREAT-MODEL.md:116+
  (verified)
- [F15] Tripwire calibration data point: exactly one session journal
  exists (harness/memory/sessions/), so "N recorded sessions" has an
  n=1 sample; descope-tripwire must be defined now, not at the S1→S2
  gate, because S1 is where overrun risk peaks — evidence:
  harness/memory/sessions/ (verified)

CONDITIONS:
- [C1] Before record 0002 is pushed: DECISIONS-logged ROADMAP amendment
  decoupling record sequence numbers from gate identity (S1→S2 gate =
  next record after 0002-progress-review), rewriting
  ROADMAP.md:111/123/192; plus one WORKFLOW line authorizing progress
  reviews in the verdict namespace (with DECISIONS entry).
- [C2] Before the S1→S2 gate closes: the descope rule NAMES the v1.0
  TLS/QUIC protocol (proposed default: SS + trojan over holo-tls;
  hy2/tuic as alternates if S3 completes), tripwire language added
  ("not acceptance-complete after 4 session journals ⇒ split / cut
  breadth / owner-signed extension, recorded in DECISIONS.md"),
  terminal-gate charter added (S7 completion + release assessment:
  per-platform green, signing condition 5, D-0009 status,
  THREAT-MODEL re-review), and binding condition 1's S2 driver
  deliverable merged into the S2 charter body with named tests.
- [C3] S1 internal ordering: Windows item 0 (FFI + windows-latest full
  suite green + 1.77.2 x86_64-pc-windows-msvc check added to the legacy
  job) merges before any S1 crypto-extension item; during the red
  window the Windows CI job carries continue-on-error with an honest
  display name ("expected-red until S1 item 0"), flipped off at item-0
  completion.
- [C4] Off-loopback proxy_listen refusal (binding condition 6) pulled
  into S1 with a named test (refuse 0.0.0.0/:: binds without explicit
  override), replacing the "S6 otherwise" deferral.
- [C5] The 1M-iteration X25519 vector gets a recorded execution-mode
  decision (release-mode test or opt-in cfg) in the S1 charter before
  implementation; "must land by S2" backlog wording tightened to
  "lands in S1".
- [C6] S1 charter records: BLAKE2b cut or justified (no consumer
  found), constant-time bar for X25519/bignum defined (code-review
  criterion or recorded decision — handed to A2 at the S1→S2 gate), "no
  X.509 parser; SPKI pinning on raw DER" written into S2, "SNI masking"
  defined-and-tested or cut; the OpenSSL cross-check journal check
  stated as a grep of the S1 session journal.
- [C7] Owner decisions scheduled at the START of the next working
  session: (a) D-0009 — advisory now, and if v0.3.1, cut it before the
  XChaCha20 wire change lands; (b) S5 credentials model (embedded
  shared creds with recorded risk acceptance vs user-supplied at
  runtime); S5 split into S5a (VPN Gate + ≤2 providers + integration
  chain test) and S5b (descope-eligible remainder).
- [C8] S6 pre-decision scheduled at or before the S5→S6 gate: amend
  D-0002/D-0008 to define TUN/killswitch FFI scope and the wintun.dll
  third-party-binary policy, and name a Windows killswitch mechanism or
  record v1.0 killswitch as Linux-only.

DISSENT/NOTES: The aggregator must not smooth over three things. (1) C1
is time-critical: records are immutable once pushed; if 0002 lands
without the numbering amendment, the collision is baked into the chain
permanently. (2) Two gate-0001 A3 conditions (named protocol,
tripwire/terminal gate) survived an entire gate cycle without being met
— if C2 slips again, the binding-conditions mechanism is decorative and
the panel should say so. (3) The open-proxy deferral (C4) and D-0009
(C7) are costing exposure TODAY on published binaries; "S6 otherwise"
and "owner pending" are not acceptable parking spots for live risks.
F5's runtime estimate and F9's floor-OS claims are reasoned, not
measured. Orchestration note for the audit trail: this run's coordinator
mislabeled my role in a resume message and corrected it before
aggregation — consistent with the correlated-failure mode disclosed in
ADVERSARIAL.md §Independence limits; record it in 0002.

### A4 — Process Auditor

All evidence is in. Compiling the audit.

**A4 PROCESS AUDIT — EVIDENCE SUMMARY**

Verified positives (rubber-stamp spot-checks all passed):
- Record 0001 blob hash = `5bbc465cff…ab4f4` matches the BACKUPS.md:7
  quote; all three verbatim-archive hashes quoted in
  `0001-S1-gate.md:132-137` match the committed blobs (computed via
  `git show HEAD:<path> | sha256sum`).
- 11 crates (STATE.md:11-13) = exact `ls engine/crates` listing; dead
  `n24` store at `engine/crates/holo-ss/src/lib.rs:97-98` (built, never
  used); test `os_entropy_fails_closed_on_unreadable_source` at
  `engine/crates/holo-util/src/rand.rs:120`; total `#[test]` attributes
  = 75, countable from the tree.
- DECISIONS.md append-only held in history (drill-commit diff
  `53ff229→2ae16b4` is a pure append of D-0009/D-0010 at file end);
  `.gitignore:58-65` carries credential patterns incl.
  `id_ed25519*`/`id_ecdsa*`; THREAT-MODEL §G exists
  (`docs/THREAT-MODEL.md:116`).

Verified negatives (the machinery gaps):

1. **Hash anchors break on this Windows host.** Working-tree
   `sha256sum 0001-S1-gate.md` = `13da8fdf…`, but the recorded hash is
   the LF blob `5bbc465c…` — the file checks out CRLF
   (`core.autocrlf=true`, no `.gitattributes` exists). Any honest
   verifier on this host who hashes the file as documented gets a
   mismatch; a future record written with CRLF endings would be
   committed LF-normalized while its pre-commit quoted hash would not
   match the pushed blob — and nothing would catch it (finding 2).
2. **harness-audit is existence-only and skipped the only gate push so
   far.** `ci.yml:102` greps for *any* 64-hex string in added
   BACKUPS.md lines — no equality check against the record's actual
   hash. The job diffs only `HEAD~1..HEAD` and CI runs once per push
   (head commit): gate 0001's record landed in `2ae16b4` (verified via
   `git show --stat`), so at the `8761716` push the diff
   `HEAD~1..HEAD` contained no verdict changes and the job exited 0
   vacuously. No job recomputes the record `chain:` line or the
   archived-verdict hashes — verdict text mutated after push is
   detectable only by a human recomputing hashes. Yet the record
   (`0001-S1-gate.md:122-124`) and STATE.md:40 present this as
   "machine-checked".
3. **backup.sh can corrupt the append-only log during the mandated
   rebase recovery.** WORKFLOW.md:28-31 requires `git rebase origin/main`
   with manual keep-both resolution; backup.sh:39-45 runs `git add -A`
   unconditionally with no unmerged-path or rebase-in-progress guard
   (`git branch --show-current` still returns main during a rebase, so
   backup.sh:26-30 passes). Running backup.sh mid-conflict commits
   BACKUPS.md with conflict markers as a "resolved" log line. The
   recovery command is also never printed at failure time
   (backup.sh:59).
4. **WARN lines are less durable than FAILED lines.** backup.sh:68
   appends the tag-push WARN without any commit (unlike the FAILED path
   at :57-58) — it sits as a dirty file until the next run, and its
   cause is discarded (`>/dev/null 2>&1`, :67).
5. **Restore runbooks are Linux-only; the mandated re-verify is
   unexecutable here.** SANDBOX-RESTORE.md:11-24 hardcodes
   `/home/z/my-project/…` and the x86_64-unknown-linux-gnu rustup;
   docs/RESTORE.md:34-35 and STATE.md:56-58 require `cargo test
   --workspace` green (75) after any restore. This host has no
   cargo/rustup and no MSVC linker — an honest restore-and-reverify
   here needs either a Windows toolchain bootstrap (absent from all
   runbooks) or an explicit downgraded evidence procedure (CI badge +
   GitHub Checks only). STATE's checklist is currently impossible as
   written on this host.
6. **Re-review scope rule is convention, not mechanism.** 
   ADVERSARIAL.md:62-67's full-panel re-run rule was applied correctly
   at gate 0001, but the scope determination was made by the
   aggregator/author itself (0001-S1-gate.md:47-51) — no mechanical
   check, no required field in the record. Prompt archives are likewise
   self-attested (ADVERSARIAL.md:36-40 discloses this;
   0002-reviewer-prompts.md honestly discloses the concurrency-limit
   sequential relaunch), and "verbatim" verdicts are qualified
   (0001-verdicts-round1.md:1-5 strips metadata). Model rotation remains
   advisory (ADVERSARIAL.md:33-34), not required — this panel is again
   same-model.
7. **Gate-numbering collision confirmed.** ROADMAP.md:111 and :123 call
   the S1→S2 transition "gate 0002", while record number 0002 is this
   progress review (untracked `verdicts/0002-reviewer-prompts.md:1-3`);
   the real S1 gate will land as record 0003, contradicting the ROADMAP
   label. WORKFLOW §2.2/§2.5 also define no "progress review" record
   type — benign drift, but unrecorded in the binding docs.
8. Minor: STATE.md:8-9 narrates 3 local commits this run; actual
   history is 4 (`53ff229`, `2ae16b4`, `5c40a7a`, `8761716`) with the
   immutable gate record landing inside the commit labeled "drill".
   BACKUPS.md's header (line 3) never documents FAILED/WARN marker
   semantics ("FAILED" occupies the prev-commit field).

AGENT: A4 Process Auditor
VERDICT: PROCEED_WITH_CONDITIONS
FINDINGS:
- [F1] Record hash anchors are not verifiable by working-tree hashing
  on this host: `sha256 harness/adversarial/verdicts/0001-S1-gate.md` =
  `13da8fdf…` ≠ recorded `5bbc465c…` (which matches the committed LF
  blob); cause is `core.autocrlf=true` CRLF checkout with no
  `.gitattributes`; no doc states hashes are blob-level — evidence:
  harness/memory/BACKUPS.md:7, computed hashes + `git config
  core.autocrlf`, absent .gitattributes (verified)
- [F2] harness-audit CI job verifies existence, not equality (any
  64-hex string passes), audits only HEAD~1..HEAD on a per-push trigger
  so intermediate-commit record landings are never audited — gate
  0001's record landed in 2ae16b4 and the 8761716 push skipped the
  audit vacuously — and no job verifies the record chain or archive
  hashes; verdict mutation after push is human-detectable only —
  evidence: .github/workflows/ci.yml:89-106, git show --stat
  2ae16b4/8761716, harness/adversarial/verdicts/0001-S1-gate.md:122-124
  claims "machine-checked" (verified)
- [F3] backup.sh has no guard against conflicted/rebase state; `git
  add -A` would commit BACKUPS.md conflict markers as a resolved log
  line, breaking append-only integrity; the WORKFLOW §1.4
  rebase-keep-both path is executable only as an undocumented manual
  edit and is never printed at failure time — evidence:
  harness/scripts/backup.sh:39-45,26-30,59;
  harness/WORKFLOW.md:28-31 (verified)
- [F4] Tag-push WARN marker is appended without commit (dirties the
  tree until the next run) and its failure reason is suppressed —
  evidence: harness/scripts/backup.sh:66-70 (verified)
- [F5] Restore runbooks are Linux-only and STATE's post-restore
  re-verify (cargo test green 75) is unexecutable on this Windows host
  (no toolchain, no MSVC); no Windows section exists — evidence:
  harness/memory/SANDBOX-RESTORE.md:11-24, docs/RESTORE.md:34-35,
  harness/memory/STATE.md:56-58 (verified)
- [F6] Full-panel-re-run scope rule is enforced only by the
  aggregator's own judgment (the conflicted party); no mechanical
  check or required record field; prompt archive and verdict
  transcription remain self-attested, model rotation advisory, and
  this panel is again single-model — evidence:
  harness/ADVERSARIAL.md:27-43,62-67,
  harness/adversarial/verdicts/0001-S1-gate.md:47-51 (verified)
- [F7] Gate-numbering collision: ROADMAP "gate 0002" = S1→S2
  transition while record 0002 is a progress review (future S1 gate
  record will be 0003); progress-review record type is undefined in
  WORKFLOW §2.2/§2.5 — evidence: harness/memory/ROADMAP.md:111,123,
  harness/adversarial/verdicts/0002-reviewer-prompts.md:1-3 (verified)
- [F8] Rubber-stamp spot-checks PASSED (counterweight to the above):
  record/archive hashes match at blob level; 11 crates, dead n24 store
  (holo-ss/src/lib.rs:97-98), test name
  os_entropy_fails_closed_on_unreadable_source
  (holo-util/src/rand.rs:120), 75 `#[test]` attributes countable,
  DECISIONS/LESSONS append-only in history — evidence: computed
  hashes, engine/crates listing, git log --follow (verified)

CONDITIONS:
- [C1] Add `.gitattributes` pinning `harness/** text eol=lf` (at
  minimum `harness/adversarial/verdicts/` and `harness/memory/`), and
  amend WORKFLOW §2.5 + ADVERSARIAL §Records with one sentence: record
  hashes are SHA-256 of committed blob content (`git show
  HEAD:<path> | sha256sum`), never working-tree bytes; verify a fresh
  checkout of record 0001 hashes to `5bbc465c…ab4f4`.
- [C2] Strengthen harness-audit (ci.yml): verify each added 64-hex
  string EQUALS the SHA-256 of the corresponding changed file under
  `harness/adversarial/verdicts/` in that commit; audit all commits in
  `origin/main..HEAD` (fetch-depth: 0), not just HEAD~1; add a step
  recomputing each record's `chain:` line against the previous record's
  blob hash and each quoted archive hash against the archived file.
- [C3] Harden backup.sh: abort when unmerged paths exist (`git diff
  --name-only --diff-filter=U --quiet` fails) or a rebase/merge is in
  progress, printing the WORKFLOW §1.4 recovery commands; commit the
  WARN line immediately (add+commit `|| true`, mirroring the FAILED
  path) and include the tag-push error in the WARN text.
- [C4] Add a Windows section (or an explicit Linux-only caveat with a
  Windows fallback) to SANDBOX-RESTORE.md and docs/RESTORE.md covering:
  repo path, toolchain bootstrap (rustup + MSVC Build Tools or GNU
  target), and for toolchain-less hosts an honest re-verify procedure
  (CI badge + GitHub Checks on HEAD as the evidence); reword STATE.md's
  re-verify checklist per-host instead of asserting `cargo test` green
  unconditionally.
- [C5] Resolve the numbering collision before record 0002 is pushed:
  one ROADMAP line stating "gate 0002" = the S1→S2 transition gate
  whose record number will be 0003+; record 0002-progress-review.md
  must state it is a progress review with no transition authority;
  record the progress-review record type via a DECISIONS entry
  (WORKFLOW is amended only via DECISIONS + commit, per its
  non-quiet-amendment rule).
- [C6] Make the remediation-scope determination mechanical: each gate
  record must include a field listing remediation-touched files vs the
  blocking finding's scope with the full-panel decision derived from
  that list; require each reviewer to quote the SHA-256 of its own
  prompt in its reply so the archived prompts are no longer purely
  self-attested.

DISSENT/NOTES: The resume message labeled me "A3 Strategy Adversary";
the coordinator corrected this mid-run — I executed the A4 mandate
throughout, and the verdict block above is filed as A4. The harness's
substance is honest — every hash I computed matched, append-only
discipline held, and every memory claim I spot-checked survived (F8) —
but two assurances in the record are overstated: the record's
"machine-checked by the harness-audit CI job" claim
(0001-S1-gate.md:122-124) provided zero assurance at the only push so
far (F2), and the hash-tie-in scheme cannot be executed as documented
on this host (F1). I did not verify remote-side state (GitHub push
events, remote CI): `origin/main` here is a local cache at 8761716 and
I stayed read-only; remote evidence was delegated to A1's anonymous
GETs and remains unverified by me. STATE.md's commit narrative
undercounts this-run history (3 vs 4 commits, gate record landed inside
the "drill" commit) — cosmetic but exactly the claim-rot class A1
hunts. If C1/C2 are not applied before the next gate record is pushed
from a Windows host, the chain-of-hashes guarantee degrades to prose.

## Consensus computation (mechanical, per ADVERSARIAL.md)

| Reviewer | Verdict | Non-BLOCK? |
|---|---|---|
| A1 Reliability Skeptic | PROCEED_WITH_CONDITIONS | yes |
| A2 Security Red | PROCEED_WITH_CONDITIONS | yes |
| A3 Strategy Adversary | PROCEED_WITH_CONDITIONS | yes |
| A4 Process Auditor | PROCEED_WITH_CONDITIONS | yes |

Rule: CONSENSUS ⇔ every active reviewer returns non-BLOCK. All four
active reviewers filed verdicts (launch failures were re-launched per
the protocol's re-launch rule and are recorded above). **Result:
CONSENSUS — PROCEED_WITH_CONDITIONS.**

Scope of this consensus: this is a PROGRESS REVIEW. It authorizes no
stage transition (S1 remains gated-open from gate 0001, not yet
started). Its output is (1) the binding conditions below, copied into
`memory/ROADMAP.md` (S1 charter amendments and carried checks), and
(2) the remediation record of this run.

## Aggregated binding conditions (copied into ROADMAP; provenance kept)

From A1 (reliability of the public evidence layer):
1. Diagnose the ubuntu-latest integration failure at 8761716; fix to
   green or amend STATE.md with the named failing test and an
   accepted-risk rationale.
2. Restore the 1.77.2 floor (lockfile v3 regression identified by
   Blue-Forensics and fixed this run — VERIFY the next CI run is
   green) or re-scope the floor claim via DECISIONS.
3. README Releases section matches published reality (DONE this run);
   reconcile D-0009's exposure list with the actual download surface
   (D-0013) and resolve or re-escalate D-0009 with a deadline.
4. OpenSSL cross-check claim reworded honestly (DONE this run);
   re-running cross-checks as RECORDED process evidence is an S1
   charter item (A3-C6).
5. STATE.md discloses the full CI state at HEAD (DONE this run).

From A2 (security):
6. S1 adds server-side salt-replay protection: bounded exact-match
   seen-salt cache (no Bloom filter — SIP022 forbids false positives),
   replay rejected through the existing opaque auth-failure path, named
   test. THREAT-MODEL §C amended this run; test lands with S1.
7. S1 item 0 adds Windows secret-at-rest hygiene (USERPROFILE fallback,
   never CWD, hard error without a resolvable data dir; recorded
   Windows ACL decision). THREAT-MODEL §G amended this run.
8. D-0009 closed before S1 DONE (advisory and/or v0.3.1 supersession,
   or a dated owner decision not to) — re-escalated as D-0013 with the
   reconciled exposure facts.
9. Carried checks re-confirmed at the S1→S2 gate: rand-split
   enforcement, ProbeGuard bounding, CSPRNG-jittered slow-close,
   close-vs-hang uniformity, off-loopback refusal, standard-XChaCha
   switch or honest de-scope (+ dead n24 removal; released-binary skew
   disclosed if v0.3.0 binaries are re-published).

From A3 (strategy):
10. Record-numbering decoupling + progress-review record type (DONE
    this run: WORKFLOW §2.6, D-0011, ROADMAP references rewritten).
11. Descope rule NAMES the v1.0 protocol — recorded default:
    Shadowsocks AEAD + trojan over holo-tls (owner may override; D-0014,
    informed by Green-R2's analysis); tripwire N=4 session journals;
    terminal gate charter (S7 completion + release assessment). DUE AT
    THE S1→S2 GATE AT THE LATEST (two of these conditions have already
    slipped one full cycle — the panel's warning about decorative
    binding conditions is recorded verbatim in A3's dissent).
12. S1 internal ordering: Windows item 0 first; continue-on-error with
    honest display name during the expected-red window; add a 1.77.2
    x86_64-pc-windows-msvc check to the legacy job.
13. Off-loopback proxy_listen refusal pulled into S1 (replaces the S6
    deferral).
14. S1 charter annotations: 1M-iteration X25519 vector execution-mode
    decision; BLAKE2b cut-or-justify; constant-time bar for
    X25519/bignum; "must land by S2" → "lands in S1".
15. S2 charter: driver deliverable merged into the charter body; "no
    X.509 parser — SPKI pinning on raw DER"; SNI masking defined or
    cut. S5 split S5a/S5b + owner credentials decision; S6 policy
    pre-decision (D-0002/D-0008 amendments) before chartering.
16. Owner decisions scheduled at the START of the next working session:
    D-0009/v0.3.1, S5 credentials model.

From A4 (process):
17. `.gitattributes` LF pinning + blob-hash verification wording (DONE
    this run); verify a fresh checkout of record 0001 hashes to
    `5bbc465c…ab4f4` (checkable post-push).
18. harness-audit strengthening (hash EQUALITY, origin/main..HEAD
    range, chain recomputation) — CI work item for the next code run.
19. backup.sh hardening (rebase/unmerged guard, WARN durability,
    print recovery commands) — next code run.
20. Windows restore section in SANDBOX-RESTORE.md + per-host re-verify
    wording (STATE.md updated this run; runbook section still due).
21. Mechanical remediation-scope field in future gate records +
    reviewers quote their own prompt's SHA-256 (adopted for future
    gates; not retrofittable to this one).

## Non-panel inputs (advisory, no vote; reports outside the repo)

- **Blue-Forensics** (progress forensics): timeline, verified-claims
  table (75 tests static-confirmed; per-OS arithmetic exact; zero deps
  confirmed; "72.9 MB/s" refuted as a repo claim; RSS claim confirmed
  as a real regression test), CI-run inventory (18 runs: 4 green, 12
  red, 2 cancelled), the Cargo.lock v4 regression diagnosis (remediated
  this run), release-surface inventory, open-risks list. Report:
  `project-management/reports/progress-forensics.md`.
- **Green-R1** (fixes/improvements research): 15 prioritized
  recommendations R-01…R-15 — salt-replay cache design (matches A2-C1),
  ProbeGuard bounding + randomized slow-close (matches A2/A3), SIP004
  UDP relay + SOCKS5 UDP ASSOCIATE design, subprocess-oracle interop
  harness (CI-side, D-0002-compatible), OpenSSL CLI differential +
  NIST ACVP fixtures, separate fuzz workspace, dudect-style timing
  tests, CoDel hard-limit, write_vectored adoption, DNS-leak
  hardening, release hygiene (toolchain pin, minisign, SLSA L1/L2,
  signed v0.3.1 closing D-0009). Report:
  `project-management/reports/research-improvements.md`.
- **Green-R2** (features/roadmap research): stage feasibility verdicts
  (S1/S2/S4 feasible-as-scoped; S3 needs-rescoping to a client-relay
  QUIC profile — no 0-RTT/migration/qlog; S5 needs-rescoping — reorder
  VPN Gate → Opera → warp_wg, cut warp_masque/Proton/Tor/Obscura/
  Lantern/Mozilla from v1.0; S6 feasible with TUN staging; S7 feasible
  with two owner-cost decisions), descope answer (trojan over the S2
  TLS client; VLESS-REALITY as chartered stretch; TUIC v5 as the
  QUIC-branch alternate), 15 candidates C-01…C-15. Report:
  `project-management/reports/research-features-roadmap.md`.

Research adoption is recorded in ROADMAP ("Research backlog adopted at
progress review 0002"); individual items carry their R-/C- IDs.

## Decision

Progress review 0002 PASSES on role-separated blind consensus (4/4
PROCEED_WITH_CONDITIONS, 0 BLOCK). The completed work since gate 0001
is honest and minimal; the S1 charter is AMENDED by this review's
binding conditions (10, 12, 13, 14 above) and remains open to start.
The most urgent outputs for the owner are the D-0009/v0.3.1 decision
and the release-surface reconciliation (D-0013), both of which are
decisions, not engineering.

chain: 5bbc465cff655a2d900c8f10fdd98602c67273311cc514429a30e67c3a0ab4f4
