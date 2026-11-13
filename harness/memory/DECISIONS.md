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
