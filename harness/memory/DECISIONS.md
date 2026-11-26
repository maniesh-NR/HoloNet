# Decision Log (append-only)

- **D-0001 (project start)**: GPL-3.0-or-later monorepo; targets
  Windows 7+ (x86/x64), macOS 10.15+ (x64/arm64), Android 8.0+
  (armv7/arm64), Linux Mint 20/21/22; portable-first builds; client
  software only — no servers, no credentials.
- **D-0002 (engine core)**: pure-std Rust, ZERO third-party crates.
  Portability to legacy platforms and auditability of a
  censorship-resistance tool outweigh development speed. Accepted cost:
  clean-room crypto/TLS/QUIC — mitigated by official RFC/NIST vectors as
  tests and OpenSSL cross-checks during development.
- **D-0003 (v0.2.0)**: Material You pipeline = one verified Rust color
  engine, ported to Dart/Kotlin/C++ and validated against Rust golden
  vectors, so all frontends render byte-identical M3 palettes.
- **D-0004 (post-recycle rebuild)**: after losing a 197-test engine to
  sandbox recycles, rebuild order = compact core → crypto foundation →
  first live data plane (Shadowsocks) → breadth (TLS, QUIC, importers,
  providers, system crates). Pitfalls preserved in `LESSONS.md` and
  `docs/RESTORE.md`.
- **D-0005 (2026-11-13, harness)**: installed binding execution workflow:
  (a) backups are EVENT-DRIVEN and always the LAST step of every execution
  plan and every prompt output — no cron/interval backups by design;
  (b) rolling restore tag `sandbox/latest` marks the last backup;
  (c) adversarial panel A1–A4 (Reliability Skeptic, Security Red, Strategy
  Adversary, Process Auditor) reviews every completed stage and every
  stage transition; transitions need unanimous non-BLOCK consensus;
  (d) verdict records are hash-chained in
  `harness/adversarial/verdicts/`; (e) durable project memory lives in
  `harness/memory/` and is pushed with every backup.
- **D-0006 (2026-11-13, gate 0001 A4-C9)**: commit identity is the
  owner's GitHub noreply identity — `maniesh-NR
  <83553290+maniesh-NR@users.noreply.github.com>` (already present on 7
  commits) — so harness-era work stays attributable to the owner. The
  anonymous `Z User <z@container>` is a fallback only when the owner
  identity is unavailable; fresh sandboxes must set the owner identity
  before the first commit (SANDBOX-RESTORE.md step 3).
- **D-0007 (2026-11-13, gate 0001 A4-C4)**: "independent consensus" is
  formally qualified as ROLE-SEPARATED BLIND REVIEW: reviewers are
  procedurally separated (parallel launch, no cross-visibility,
  verdicts before aggregation) but may share one model family and one
  orchestrator — correlated blind spots are probable and the limits are
  recorded in `harness/ADVERSARIAL.md`. Every gate record archives the
  reviewer prompts verbatim so the setup is auditable.
- **D-0008 (2026-11-13, gate 0001 A2-C1)**: entropy policy. ALL security
  material (AEAD salts, auth tokens, keys, nonces) comes from
  fail-closed OS entropy — no silent weak fallback anywhere; `splitmix64`
  is non-security only. Windows (pure std has no CSPRNG): interim state
  is an explicit FAIL-CLOSED error; the fix is a chartered, contained,
  audited FFI exception (RtlGenRandom / BCryptGenRandom) scoped to
  `holo-util/src/rand.rs` ONLY, staged as ROADMAP S1 item 0, re-reviewed
  at every gate. Documented in `docs/THREAT-MODEL.md` §G.
- **D-0009 (2026-11-13, gate 0001 A1-C1 — ESCALATED TO OWNER)**: the
  PUBLISHED v0.2.0/v0.3.0 release binaries predate the fail-closed
  entropy hardening — on Windows, their AEAD salts and IPC tokens come
  from the predictable splitmix64 fallback. Disclosed in THREAT-MODEL
  §G. The owner must decide at the next session: publish a security
  advisory, or cut a v0.3.1 re-release from the hardened tree (all four
  release jobs now emit SHA256SUMS.txt). Until decided: treat Windows
  binaries from v0.2.0/v0.3.0 as unsuitable for adversarial use.
- **D-0010 (2026-11-13, gate 0001 — consensus decision)**: gate 0001
  (S0 → S1) PASSED on unanimous non-BLOCK round-2 verdicts from all four
  active reviewers after remediation; record at
  `harness/adversarial/verdicts/0001-S1-gate.md`. S1 may start in the
  next run, under its amended charter and the binding conditions listed
  in ROADMAP.
- **D-0011 (2026-11-17, progress review 0002 A3-C1/A4-C1/C5)**: (a)
  Verdict-record numbers are directory SEQUENCE numbers, not gate
  identities; gates are identified by stage transition ("the S1→S2
  gate"). (b) PROGRESS REVIEWS (adversarial assessment with no stage
  transition) are an authorized record type; they state "no transition
  authority" in their header. (c) Record/archive hashes are SHA-256 of
  committed BLOB content — verify via `git show HEAD:<path> |
  sha256sum`, never by hashing working-tree files (CRLF checkouts
  differ); `.gitattributes` now pins `harness/**` (and scripts) to LF
  so fresh checkouts hash identically. ROADMAP's hardcoded "gate 0002"
  labels rewritten to stage-transition form. WORKFLOW §2.6 added.
- **D-0012 (2026-11-17, progress review 0002 — consensus decision)**:
  progress review 0002 PASSED: 4/4 PROCEED_WITH_CONDITIONS, 0 BLOCK,
  verdicts archived verbatim in
  `harness/adversarial/verdicts/0002-progress-review.md` (chain:
  5bbc465c…ab4f4 → this run's record). Its 21 aggregated binding
  conditions are copied into ROADMAP (S1 amendments, S2/S5/S6
  annotations, descope/tripwire/terminal-gate sections). Orchestrator
  incidents (concurrency-limit sequential resumes, one role-mislabel
  corrected mid-run) are recorded in the record header, not smoothed
  over. STATE.md re-verify wording is now per-host (A4-C4).
- **D-0013 (2026-11-17, re-escalation of D-0009 with reconciled facts —
  A1-C3/C5, A2-C3, A3-C7):** API-verified release surface: the
  pre-hardening WINDOWS binaries (predictable splitmix salts/IPC token)
  named in D-0009 are NO LONGER publicly downloadable (only
  v0.2.0-linux, empty v0.2.0, and source-only v0.3.0 are visible);
  downloads-before-removal are unknowable. The owner decision is now:
  (a) publish a short advisory anyway + cut a CHECKSUMMED, SIGNED
  v0.3.1 from the hardened tree and republish the per-OS binaries
  (which also fixes the invisible-releases defect), or (b) record a
  dated decision not to. DEADLINE: before S1 is marked DONE; if v0.3.1
  is chosen it must be cut BEFORE the S1 XChaCha20 wire change lands
  (binding condition 8) so the re-release does not break its own wire
  protocol. Also reconcile: v0.2.0/v0.3.0 per-OS release runs concluded
  "success" but produced no public releases (drafts/deleted?) —
  republish or delete explicitly.
- **D-0014 (2026-11-17, progress review 0002 A3-C2 — PROPOSED DEFAULT,
  owner may override at the next session):** the descope rule NAMES the
  v1.0 TLS/QUIC-based protocol: **trojan over the S2 holo-tls client**
  (smallest delta from the shipped SS plane; exercises all S1/S2
  deliverables; Green-R2 analysis), with hy2/tuic as named alternates
  iff S3 completes on schedule. Descope tripwire N=4 session journals;
  terminal gate = S7 completion + release assessment (per-platform
  green, signatures, D-0009/D-0013 status, THREAT-MODEL re-review,
  descope conformance). Closes gate-0001 A3-C5's requirements one cycle
  late — the panel's warning about slipped binding conditions is on
  record (A3 dissent).
- **D-0015 (2026-11-18, A1-C1 remediation — memory-regression budget)**:
  the Linux-only memory regression's ceiling is 2 MB → 8 MB over 64 MB
  relayed. Evidence: authenticated CI logs (runs 43382900976 @ 8761716
  and 44229892465 @ 26b48c9) show `memory_stays_bounded_under_sustained_relay`
  failing at +2520 KB on shared runners while the local Linux sandbox
  measured +88–376 KB — runner allocator/page-accounting variance, NOT a
  pooling regression (per-chunk allocation of 64 MB in 16 KB chunks
  would grow tens of MB; 8 MB = 12.5% of relayed volume still fails
  catastrophically wrong code). Chosen remediation path per A1-C1:
  fix to green rather than accepted-risk disclosure. The holo-ss side
  of the gate-0001 tightening (per-chunk bound) is untouched.
- **D-0016 (2026-11-19, owner instruction — pstack protocol adopted)**:
  a token-efficiency OPERATIONAL layer is added on top of the harness:
  (a) `PROJECT_MEMORY.md` (repo root) = compressed single-source
  operational view (tech-stack invariants, active playbook, verification
  contracts, key facts) — it POINTS INTO the harness memory but never
  replaces it; on conflict the harness files are authoritative and both
  get updated. (b) Zero-noise rule: no raw history dumps in context or
  memory files; `update_memory.py` (repo root) appends only STAT
  summaries of the last 3 commits (HOLO_MEMORY_FULL_DIFF=1 opts into
  patches) and replaces its section idempotently; run at session start
  or as pre-/post-commit hook. (c) Investigation before code + explicit
  verification contracts per task. This changes no binding workflow
  rule — backup.sh remains the final step of every run.
- **D-0017 (2026-11-19, A4-C2 implementation — audit-scope choice)**: the
  harness-audit CI job is reimplemented as a WHOLE-TREE integrity audit
  instead of the suggested per-commit `origin/main..HEAD` range audit:
  (1) every 64-hex string quoted in any verdict record or in BACKUPS.md
  must resolve to the blob sha256 of a TRACKED file (warn-only when the
  resolution lands outside `harness/adversarial/verdicts/`); (2) every
  gate record's final `chain:` line must equal the blob sha256 of the
  numerically previous record (0001 = "genesis"). Rationale: tree-level
  verification is strictly stronger against post-push mutation (it runs
  at EVERY push over ALL records, needs no deep fetch, and cannot be
  skipped by mid-history landings as the HEAD~1..HEAD diff was). Tradeoff
  honestly recorded: the per-commit form proved "record landed in the
  same push as its BACKUPS.md line"; the tree form proves integrity at
  every pushed state but not landing-coincidence — accepted (the
  BACKUPS.md tie-in quote IS covered by rule 1, which fails if a record
  hash is quoted but the record itself is absent/tampered). Verified
  locally: chain 0001=genesis, 0002=0001-blob, 85 blobs all resolve;
  backup.sh guards negative-tested (rebase sentinel → refusal with
  recovery commands printed, zero BACKUPS.md mutation).
- **D-0018 (2026-11-19, S1 item 0 — Windows entropy + secret-at-rest)**:
  (a) `os_fill` on Windows calls RtlGenRandom (advapi32 SystemFunction036)
  — chosen over BCryptGenRandom for the Windows 7 SP1 floor (XP-era API,
  no CNG-disabled caveat) — via the D-0008 contained FFI in
  `holo-util/src/rand.rs` ONLY (the workspace's sole unsafe), fail-closed
  with a test-only injection seam (INJECT_FAIL). (b) Data-dir resolution:
  HOLONET_DATA → HOME → USERPROFILE → hard error; the CWD "." fallback is
  REMOVED (A2-C2) — unit-tested. (c) Windows ACLs for ipc-token/
  profiles.json: rely on per-user profile-directory ACLs; no additional
  FFI (D-0008 containment) — residual (admin/SYSTEM readable) recorded
  in THREAT-MODEL §G, consistent with §A's root-out-of-scope limit.
- **D-0019 (2026-11-20, cross-validation progress review 0003 —
  consensus decision):** a second, fully independent adversarial panel
  (fresh agents, emphasis rotated, run in a DIFFERENT sandbox from the
  record-0002 one) reviewed the same baseline `8761716` and returned
  4/4 PROCEED_WITH_CONDITIONS, 0 BLOCK — matching record 0002's verdict
  pattern. Mid-run its A4 discovered via `git ls-remote` that
  origin/main had moved to `cc4564f` (a parallel session had pushed its
  own record-0002 cycle + S1 item 0); the run fast-forwarded and the
  record documents the divergence verbatim. Cross-check outcome: the
  majority of the 0002-record conditions were already closed by the
  parallel run (unsafe containment compile-enforced D-0018, memory
  budget D-0015, harness-audit full-tree D-0017, backup guards,
  platform counts CI-verified, descope/terminal-gate D-0014,
  D-0009/D-0013 re-escalation, credentials model owner-gated); the
  RESIDUAL conditions were applied this run (doc claim fixes A1-F1/F2/F3,
  per-platform-count ARCHITECTURE refresh, .gitignore profiles.json/
  .env.local/keystore, backup.sh untracked-guard + live-remote guard,
  SANDBOX-RESTORE step 0/0b, LESSONS additions) or carried into the S1
  charter (X25519 decode/ct_eq precision, CFB mechanical ban, read
  deadline for the close-vs-hang DoS elevation, ProbeGuard N=1024,
  deterministic jitter seam, delay-ceiling decision, OpenSSL-journal
  auditability). WORKFLOW §4.4 added: first-act untracked-stray triage
  with journaled disposition. Record numbering per D-0011: 0003 is a
  SEQUENCE number — the S1→S2 gate will be 0004. Research lane:
  subagent researcher failed twice (empty responses); the orchestrator
  ran the research pass directly — output in
  `harness/research/0001-s1-preflight-landscape.md`.
- **D-0020 (2026-11-20, orphan disposition — A1-C5/A4-C7):** the
  untracked `engine/crates/holo-crypto/src/blake2.rs` found on the
  restored tree (sha256 begins 375d41cd; full hash in the run report —
  truncated here so the D-0017 blob-resolution audit stays exact) is
  DOUBLY BROKEN: (1) SIGMA scoping E0425 — the file never compiled;
  (2) with scoping fixed, 3/5 of its own KATs fail for inputs where
  m[2] != m[8] — consistent with a mis-transcribed SIGMA row. Its 32
  embedded KAT EXPECTATIONS are authentic (independently verified
  against OpenSSL: hashlib + b2sum) and ARE reusable in S1; its CODE is
  not. Disposition: moved OUT of every git tree to
  `/home/z/my-project/blake2-orphan-2026-11-20.rs` (owner's machine;
  history unverifiable — it predates any tracking); S1 re-derives the
  mix schedule from RFC 7693 §3.3 and may copy the KAT expectations
  after re-verifying them against the official blake2-kat.json. LESSONS
  carries the pitfall; ROADMAP S1 item 1 carries the warning.
- **D-0021 (2026-11-20, owner instruction re-affirmation — memory
  hooks + gate):** update_memory.py (repo root) gains two modes:
  `--check` (verification gate: memory file present, activity section
  with ≥1 commit entry, newest entry an ancestor of HEAD, lag ≤
  NUM_COMMITS=3) and `--install-hooks` (.git/hooks/pre-commit
  refreshes the zero-noise activity section and stages
  PROJECT_MEMORY.md so every commit carries fresh memory; post-commit
  is a read-only structural check that warns, never blocks; hooks are
  local-only — re-install after a fresh clone/restore). Rationale: the
  re-affirmed pstack protocol demands session-start + hook operation;
  the write path stays single and idempotent so hook and manual runs
  cannot conflict. REJECTED: a JSON/graph twin for RAG — the
  structured markdown + harness/memory files already form the
  agent-accessible durable graph (D-0016 layering); a second derived
  artifact adds sync risk with no current consumer (revisit when a
  real RAG consumer exists). Same run, remediation (not a new
  decision): Cargo.lock v3 restored after the 0003-era v4 silent
  rewrite was found live on origin/main.
- **D-0022 (2026-11-20 run 4, harness bug fix — backup.sh retry
  deadlock):** the record-0003 A4-C2 live-remote guard refused on ANY
  HEAD≠remote mismatch, including local-AHEAD — which is exactly the
  state after an auth-failed push leaves FAILED-marker commits behind;
  every subsequent retry would refuse forever (a deadlock: the only way
  forward is a push, and the guard blocks all pushes). Found at run 4's
  session start (local 203f965 vs remote ef19a6f after run 3's honest
  push failure). Fix: refusal condition is now `! git merge-base
  --is-ancestor $REMOTE_HEAD $LOCAL_HEAD` — refuse ONLY when the remote
  has commits local lacks (true divergence / parallel-session push);
  local-ahead-or-equal is a safe fast-forward and allowed. Verified in a
  throwaway repo pair (guard_test scenarios A–E: equal ALLOW, local-ahead
  ALLOW, remote-ahead REFUSE, diverged REFUSE, unseen-remote REFUSE
  fail-closed) + bash -n syntax check. SANDBOX-RESTORE step 0 wording
  amended to match. Same run (context): S1 server-path hardening items
  A2-C1 (SaltCache) and A3-C4 (loopback-only bind) shipped — see
  ROADMAP/THREAT-MODEL annotations and the run-4 journal.
- **D-0023 (2026-11-20 run 5, S1 server-path hardening — three recorded
  decisions, all "a decision, not an accident" per record-0003 A3-C10
  / A1-F8):** (1) **ProbeGuard peer cap = 1024** (`PROBE_GUARD_PEER_CAP`):
  overflow decays the stalest peer (oldest recorded `last` failure) from
  both maps — N pinned by record-0003 A1-F8; honest residual: decayed
  peers re-admit fresh (backoff restarts) and >1024-IP rotation slides
  the window. (2) **Slow-close ceiling = 2 s** (`SLOW_CLOSE_MAX`), full
  jitter uniform over `[0, min(backoff, ceiling)]` drawn from the OS
  CSPRNG via a parameterized draw seam (production: `os_fill`; tests:
  seeded deterministic draws — A3-C10's injected-seam pattern, no flaky
  live-draw comparisons). Rationale: 5 doublings of 50 ms remain real
  progressive slowdown (the accidental 120 ms clamp neutered it after
  ~2 failures) while bounding failed-auth thread hold time; ProbeGuard's
  internal 10 s curve is unchanged for other call sites. Same item,
  found-by-inspection fix: the ProbeGuard Mutex was held ACROSS the
  sleep — every concurrent connection serialized behind one probe's
  delay; the lock now covers only the bookkeeping. (3)
  **Unauthenticated read deadline = 10 s** (`AUTH_READ_DEADLINE`), 2×
  the client's own 5 s dial timeout, covering salt + first chunk and
  cleared the moment auth completes; short values injectable for tests
  via `ServePolicy` (A3-C10 favors injected seams over global state —
  no env knobs added). Residual (recorded in THREAT-MODEL §C): the
  attacker-observable timeline still differs between immediate
  length-rejection and deadline-close on silence — inherent without
  breaking legitimate slow clients.
- **D-0024 (2026-11-20 run 6, S1a closing — rand-split enforcement,
  gate-0001 A2-C3 / ROADMAP S1 item 7):** the security/non-security
  randomness split is now MECHANICAL, not naming-and-docs. Three layers:
  (1) the weak PRNG (`fill`/`bytes`/`hex`/`alnum` + the splitmix64
  machinery) moved into `rand::nosec`, `#[doc(hidden)]`, with loud
  never-for-crypto docs; (2) BOTH re-export paths closed — the `rand`
  module root AND the crate root (`pub use rand::{bytes, fill}` deleted;
  the crate-root re-export was found by this run's call-site map and
  would have kept `holo_util::fill` compilable, silently defeating a
  module-only split); (3) the named audit test
  `rand_split_audit_no_weak_prng_outside_allowlist` scans every
  workspace `.rs` file (engine root via CARGO_MANIFEST_DIR ancestors;
  skips `target`/hidden dirs; floor asserts the scan found the real
  tree) for `nosec::`, `rand::fill`, `rand::bytes`, `rand::hex`,
  `rand::alnum`, `use rand::{` and fails with file:line outside the
  two-entry allowlist — the definition file plus the holo-config
  profile-ID consumer (the ONE consumer gate-0001 classified
  non-security); integration `tests/` dirs are exempt per the verdict's
  "outside holo-config IDs/tests". Residual, honest: unit-test modules
  inside src files are NOT exempt (a weak call there requires a visible
  allowlist edit + DECISIONS record), and `nosec` stays callable for
  anyone who edits the allowlist — exactly the reviewable, journaled
  path the condition demands. Both halves demonstrated live this run:
  a planted scratch violation made the audit FAIL with the offending
  line, and the old root call produced E0425.
- **D-0025 (2026-11-20, RESOLUTION of D-0009/D-0013 — owner decision,
  given in chat this session):** the owner chose **(a) advisory +
  v0.3.1**. The full picture, API-verified this session: the per-OS
  v0.2.0/v0.3.0 releases exist as SEVEN maintainer-visible DRAFTS
  (`v0.2.0-windows/-macos/-android`, `v0.3.0-windows/-macos/-linux/
  -android`) — the workflows' "success" uploads landed on drafts, which
  is the entire invisible-releases defect. The two Windows drafts hold
  pre-hardening binaries (predictable splitmix64 salts/IPC token);
  the five unix drafts are entropy-clean but superseded. Executor-
  recorded sub-decisions (within the (a) envelope; owner did not
  specify, each reviewable):
  (1) **Advisory published** as `docs/advisories/2026-11-20-sa-0001-
  v0.2.0-v0.3.0-windows-weak-entropy.md` (HoloNet-SA-0001) + the main
  v0.3.1 release notes; **GHSA CREATED AND PUBLISHED via API:
  GHSA-8h6m-w5qj-cq9g** (CVE requested, id pending assignment). Scope stated honestly: affected artifacts existed as
  drafts only (not publicly downloadable); any earlier public window
  is unknowable (D-0013); unix builds unaffected (/dev/urandom path).
  (2) **Phantom drafts DELETED** (all seven): republishing the Windows
  drafts would rebuild vulnerable code — never an option; deleting the
  unix drafts removes the one-click-publish footgun D-0013 named; the
  public `v0.2.0-linux` is KEPT (unaffected; superseded by
  v0.3.1-linux). Asset inventories quoted in the journal + BACKUPS.md
  before deletion.
  (3) **Signing**: Ed25519 detached signature over the master
  SHA256SUMS.txt — python-cryptography generation, verifiable with
  STOCK openssl (`openssl pkeyutl -verify -pubin -inkey <pub.pem>
  -rawin -in SHA256SUMS.txt -sigfile SHA256SUMS.txt.sig`), so users
  need no extra tooling. (ssh-keygen is unavailable in the executor
  sandbox — same minisign-style mechanism, different verification
  story; corrected before commit.) Keypair generated in the executor
  sandbox this session (private key NOT in the repo), public key
  committed with README verification instructions. Owner may re-key under an owner-held key
  at S7 — the S7 signing criterion becomes "re-sign under an
  owner-held key (or record no-go)".
  (4) **v0.3.1 cut** from the CI-verified tree `6314da0` (run
  44729423292 all-green 6/6) as 4 per-OS tags + a main release carrying
  the advisory, the master checksum manifest, and its signature.
  Deadline context: decided BEFORE the S1 XChaCha20 wire change (which
  is now UNBLOCKED) — v0.3.1 is a pure security re-release, no wire
  change bundled.
- **D-0026 (2026-11-20, S5 credentials model — owner decision, given
  in chat this session):** the owner chose **(ii) embedded, with
  recorded risk-acceptance**. This AMENDS D-0001 for S5 OPERATIONAL
  provider credentials only: shared/embedded provider credentials may
  be committed to the public GPL repo and shipped in binaries, with
  the owner explicitly accepting the named risks — extractability
  from public source and binaries, burnability through abuse, and
  provider-ToS exposure (account bans, credential attrition).
  Constraints that SURVIVE this decision: (a) WORKFLOW §3.3 session
  secrets (PATs, tokens) remain env-var-only, never committed — the
  amendment does NOT touch executor/session secrets; (b) S5 TEST
  fixtures remain synthetic — the "no credential material committed"
  acceptance narrows to test material (operational creds are exempted
  by this decision, test fixtures are not); (c) operational
  credentials live in one documented config module with a stated
  rotation/burn path in THREAT-MODEL §E; (d) the Green-R2 S5a ordering
  stands — VPN Gate first (official CSV, needs NO credentials),
  Opera's embedded creds land with the risk note attached.

- **D-0027 (2026-11-20/21, owner instruction — agentic memory as a data
  graph accessible to all agents)**: `harness/memory/graph/` holds
  `graph.json` — a typed node/edge view of the binding memory
  (decisions, stages, gate records, review conditions with statuses,
  components, tests, CI jobs, threats, gaps, lessons, sessions, owner
  decisions, tools, panel roles) with per-node source refs — plus
  `memory_graph.py` (`check`/`stats`/`query`/`dot`, std-only). The
  markdown memory remains AUTHORITATIVE; the graph is a derived,
  curated view. `check` enforces COVERAGE in the harness-audit CI job:
  a D-NNNN / stage / record / session present in the sources but
  missing from the graph fails CI, so the graph cannot silently rot.
  Hash-anchors unaffected (D-0011 blob rule still applies).
  NUMBERING NOTE (2026-11-21 reconciliation): this entry and D-0028
  were drafted as D-0019/D-0020 in a parallel session BEFORE the
  divergence was discovered; the pushed tree's D-0019..D-0026
  (cross-validation 0003 / orphan disposition / D-0021..D-0026) keep
  their numbers, so these were renumbered to D-0027/D-0028.
- **D-0028 (2026-11-21, owner instruction — RAG over the memory graph)**:
  `harness/memory/graph/memory_rag.py` gives every agent (and human)
  retrieval-augmented access to project memory: BM25 chunk retrieval over
  the binding markdown corpus (heading-chunked; identifiers like D-NNNN /
  A#-C# tokenize as single tokens so exact ids outrank prose) PLUS
  graph-context expansion (matched nodes contribute summary + 1-hop
  edges from graph.json). Interface: `ask "<query>" [-k N] [--json]`,
  `smoke` (retrieval regressions: RtlGenRandom→SystemFunction036,
  salt-replay, lockfile-v3, trojan-descope, backup-final-step + graph
  id-resolution). Std-only, zero dependencies; index built per
  invocation (corpus < 1 MB — always fresh, no cache to invalidate);
  lexical not semantic (limitation stated in the docstring). `check`
  (D-0019) and `smoke` both run in the harness-audit CI job so neither
  the graph nor the retrieval anchors can silently rot. The graph and
  markdown remain authoritative; this is a READ layer over them.
- **D-0029 (2026-11-21, run 8 — execution of binding condition 8,
  record-0003 A3-C3, sequenced by D-0025/D-0013; executor-recorded):**
  the xchacha20-ietf-poly1305 wire switched to the STANDARD
  construction — a method-sized SIP004 nonce (12 or 24 bytes) with the
  24-byte LE counter fed to holo-crypto's (now draft-vector-proven)
  `aead_xchacha20poly1305_*`; the mislabeled zero-IV re-key
  (HChaCha20(subkey, 0^16) + plain ChaCha20-Poly1305 over a 12-byte
  counter — record-0003 A2-F8) and the dead `n24` store are RETIRED,
  not kept as a compat mode: that construction never interoperated
  with ANY standard shadowsocks peer under the xchacha name, so there
  is nothing to stay compatible WITH — a dual-stack would only
  preserve the defect. Compat consequence, recorded honestly: chunk 0
  of a session coincidentally matches the retired construction (both
  nonces all-zero); divergence begins at the second AEAD operation —
  v0.3.1-and-earlier xchacha sessions cannot interop with post-run-8
  builds, exactly as they could not with any standard peer. Explicit
  non-goals: no cipher de-scope (the charter's alternative), no
  negotiation/versioning handshake (single-cipher-label wire;
  migration mechanics belong to a future protocol version if one is
  ever chartered). Vectors: draft-irtf-cfrg-xchacha-03 §2.2.1 /
  A.2.1 / A.1 fetched verbatim from the IETF archive this run — the
  crate's primitives were already draft-correct; the run's value was
  PROOF (no vector, no merge) plus the wire switch itself.
  NUMBERING NOTE (2026-11-21, run-8 rebase): this entry was drafted as
  D-0027 in the run-8 sandbox before the mid-run divergence on the
  parallel graph/RAG session was discovered; that session lawfully took
  D-0027/D-0028, so this is renumbered D-0029. Rebase also removed a
  stray pasted commit-message line ("dd6f4ba (…)") that had ridden to
  the top of the D-0028 entry on origin/main, and the duplicated
  misplaced NUMBERING NOTE above D-0027.
- **D-0030 (2026-11-25, run 10 — record-0003 A2-C4 execution, S1 item 3
  AES-CFB):** the mechanical shape of the CFB constraint. SP 800-38A
  CFB128 (AES-128/192/256) landed as `pub(crate) mod cfb128` inside
  holo-crypto (raw in-place encrypt/decrypt over the existing `Aes`,
  AES-encrypt-based in BOTH directions per the mode definition,
  arbitrary-length stream semantics); raw functions are NOT `pub`, and
  no authenticated wrapper consumer is chartered yet, so crate privacy
  IS the compile-failure half of the enforcement — no other crate can
  name them at all. Audit half: the `cfb_usage_audit` workspace
  grep-test (allowlist exactly `["crates/holo-crypto/src/lib.rs"]`,
  ≥15-file floor, file:line failure output); negative path demonstrated
  live this run — a planted holo-socks probe file containing "cfb" made
  the audit FAIL with `crates/holo-socks/src/cfb_probe_scratch.rs:1`,
  removal restored green. When a `pub` authenticated wrapper IS
  chartered (S4 legacy import paths / S7), consumer files extend the
  allowlist WITH a justification comment and a DECISIONS record — the
  visible, journaled path, same pattern as rand-split (D-0024). The
  legacy-provider constraint is unchanged: CFB is unauthenticated and
  forbidden outside such a wrapper.
- **D-0031 (2026-11-25, run 10 — progress review 0002 A3-C6/F13
  constant-time bar for the bignum item, S1 item 5):** recorded as an
  ACCEPTED-RISK decision. `holo-crypto::bignum` + `rsa` process PUBLIC
  data only — signatures, public keys, the exponent e, message hashes
  and salts are attacker-visible in the verification path — so
  variable-time behaviour (bit-branching `mont_pow`, the data-dependent
  final subtraction) is accepted FOR THIS STAGE, not an oversight. No
  secret-operand operation is in scope; RSA is shipped VERIFY-ONLY (no
  private-key ops). A future consumer that routes SECRET operands
  through this module (e.g. S2 client-side operations holding RSA
  private keys) MUST treat constant-time execution as its own
  requirement; this code does not provide it. This is the recorded
  criterion handed to A2 at the S1→S2 gate.
- **D-0032 (2026-11-25, run 10 — progress review 0002 A3-C5/F5
  execution-mode decision + A3-C6/F13 constant-time bar for X25519, S1
  item 2):** (a) EXECUTION MODE: RFC 7748 §5.2's iterated vectors
  (1,000 and 1,000,000 iterations) are `#[ignore]`-gated tests that run
  RELEASE-MODE ONLY (`cargo test -p holo-crypto --release
  x25519_iterated_rfc7748_1000 -- --ignored`) — never part of the
  default debug-mode CI suite. Executed 2026-11-25: the 1,000-iteration
  vector PASSED release-mode in 0.12 s (local); the 1M-iteration vector
  PASSED release-mode locally (wall time in the journal addendum). The
  DEFAULT suite carries the RFC's published single-iteration vectors
  (§5.2 pair incl. the top-bit-set u of vector 2, §6.1 DH pair) — the
  same arithmetic exercised in milliseconds. (b) CONSTANT-TIME BAR:
  recorded in the CHECKLIST form — `holo-crypto::x25519`'s module docs
  carry the checklist verbatim (branch-free ladder arithmetic with
  fixed fold rounds; XOR-mask cswap per RFC §4/§5; branch-free decode
  clamps; a fixed 255-iteration ladder; fe_invert branching only on
  the PUBLIC constant exponent p−2; the all-zero check via
  `crate::ct_eq`; no division on secret data). Both items are handed
  to A2 at the S1→S2 gate.
- **D-0033 (2026-11-25, gate 0004 — resolves the S2 charter's binding
  pre-start amendment, A3-C2/F6 + A1-C1):** "SNI masking" is CUT from
  S2. Justification: the S2 client pins the SPKI of the specific server
  it intends to reach; the SNI field is what selects the certificate a
  server returns, so a masked/borrowed SNI would make the pin certify
  an identity the client did NOT actually reach — breaking pinning
  semantics — while adding a distinct fingerprinting surface (a client
  that masks SNI behaves measurably differently from both an honest
  client and the browser population it mimics). ECH/encrypted-SNI is
  out of scope for a no-X.509-parser client. The S2 charter body no
  longer lists SNI masking (ROADMAP amended at gate 0004). If a future
  stage charters censorship circumvention that genuinely needs SNI
  flexibility, it must come back through a new decision with its own
  threat-model amendment.
- **D-0034 (2026-11-25, gate 0004 — executes A2-C1):** RSA public-
  exponent validation is ENFORCED in the verify path (not deferred):
  `public_key_checks` now rejects e < 3 or even e with the distinct
  error "rsa: public exponent must be an odd integer >= 3" (RFC 8017
  §3.1); named negative test `rsa_rejects_degenerate_exponent` pins the
  error for e = 1 / 2 / empty across BOTH verify fns and asserts e = 3
  passes the exponent gate. This closes the forged-signature hole an
  attacker-supplied e = 1 key would otherwise open before any S2
  consumer accepts keys from config.
- **D-0035 (2026-11-26, owner decisions — given in chat this session;
  executes the three owner residuals re-listed by gate 0004 C7):**
  (1) **D-0014 RATIFIED unchanged.** Trojan over the S2 holo-tls client
  stays the named v1.0 second LIVE protocol; hy2/tuic remain the named
  alternates iff S3 completes on schedule; the descope tripwire (N=4
  session journals) and the terminal-gate charter are unchanged. The
  2026-11-17 "PROPOSED DEFAULT, owner may override" status is CLOSED —
  the descope rule is now owner-ratified (ROADMAP annotated; graph
  OD-d0014 flipped to decided).
  (2) **PAT: old token KEPT for now** (owner declined rotation this
  round). The exposure window (the token transited chat/upload across
  sessions) is an owner-accepted residual; the standing rotation
  recommendation stays on record; the handling discipline is unchanged
  (env var only, reloaded from the owner upload per session, never in
  argv, files, or output).
  (3) **CVE polling DELEGATED to the executor** ("poll the advisory
  yourself and backfill"). First poll this session, 2026-11-26T06:52Z,
  authenticated: **cve_id = null — still pending assignment.** Polling
  mechanics recorded for reuse: the GLOBAL endpoint
  `api.github.com/advisories/GHSA-8h6m-w5qj-cq9g` returns 404 (the
  repo advisory is not yet in the global database — expected until
  promotion, not an error state); the REPO endpoint
  `api.github.com/repos/maniesh-NR/HoloNet/security-advisories/
  GHSA-8h6m-w5qj-cq9g` is the reliable target. A daily automated poll
  is scheduled; on assignment the backfill is mechanical and
  owner-input-free: docs/advisories/SA-0001, README security section,
  THREAT-MODEL, STATE.md, PROJECT_MEMORY.md, the graph node summary,
  plus a DECISIONS entry and a session journal, then a backup push.
  Nothing was backfilled this session (id still null).
