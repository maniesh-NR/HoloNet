# Session journal — 2026-11-20 (run 4): S1 server-path hardening (A2-C1 + A3-C4) + D-0022

## Goal
Continue the S1 amended charter: the two small high-value hardening
items first — salt-replay cache (A2-C1) and off-loopback proxy_listen
refusal (A3-C4) — plus landing the unpushed run-3 backup state.

## Session start
- update_memory.py refresh + --check PASS (hooks live, D-0021).
- Warm-restore 0/0b: remote reconciliation local=203f965 vs
  remote=ef19a6f → MATCH=N with local AHEAD by the two unpushed
  run-3 backup commits (FAILED marker). Untracked triage: none
  in-repo.
- **DEADLOCK FOUND (became D-0022):** backup.sh's A4-C2 guard refuses
  ANY HEAD≠remote mismatch — including local-ahead, i.e. exactly the
  state a failed push leaves behind. Every retry would refuse
  forever. Fixed before the end-of-run backup (below).
- Toolchain absent (recycle wiped ~/.cargo) → rustup reinstall
  (rustc 1.100.0, minimal profile) per SANDBOX-RESTORE step 2.

## Baseline verification (before any code change)
- `cargo test --workspace`: **76/76 green** on Linux — matches the
  D-0018 ledger exactly.
- Cargo.lock v3 invariant post-run: HELD (zero diff).

## Done (S1 items)
1. **A2-C1 salt-replay cache (holo-ss):** `SaltCache` — bounded FIFO
   (ring VecDeque + HashSet index, capacity 1024 =
   `SALT_CACHE_CAPACITY`); `admit()` returns false for a tracked
   duplicate. Admitted in `ServerConn::accept` right after the
   client-salt read, BEFORE any crypto work; refusal = the same
   opaque `auth_failed()` as a wrong password (no new oracle, no
   Bloom filter per SIP022). `serve_conn`/`accept` gained a
   `&Mutex<SaltCache>` param; call sites updated (3 in-crate + the
   engine integration helper).
   Named test `salt_cache_rejects_replayed_prefix`: hand-crafted
   valid prefix (salt ‖ encrypted target chunk) — the original
   connection tunnels end to end (payload echoed under the server's
   out-salt subkey), the byte-identical replay is refused with
   kind InvalidData + exactly "ss: auth failed", upstream dialed
   exactly once. Plus `salt_cache_admit_and_evict_semantics`
   (duplicate refusal, FIFO eviction bound, aged-out re-admission =
   the honest capacity limit, cap=0 = no protection).
2. **A3-C4 off-loopback refusal (holo-socks):**
   `require_loopback_listen` — resolves the listen address, requires
   EVERY resolved IP loopback (whole 127/8 and ::1 allowed; 0.0.0.0,
   ::, 8.8.8.8 refused), unresolvable names fail closed; called in
   `SocksServer::bind` BEFORE the OS bind; explicit operator
   override = env `HOLONET_PROXY_LISTEN_ANY=1` (read once at bind).
   Named tests: `non_loopback_bind_refused_ipv4_any` (0.0.0.0),
   `non_loopback_bind_refused_ipv6_any` (::),
   `non_loopback_bind_refused_literal_before_os` (192.0.2.1 — policy
   error text proves the check precedes the syscall),
   `env_override_allows_non_loopback_bind` (momentary 0.0.0.0:0
   bind, never served, dropped — serialized with the refusal tests
   on a test-lock because env is process-global),
   `loopback_policy_table` (pure, no bind/env).

## Verification
- `cargo test --workspace`: **83/83 green on Linux** (76 + 7: holo-ss
  7→9, holo-socks 5→10; per-crate sums re-checked from the runner
  output). Static `#[test]` count 85 (78+7).
- Cargo.lock v3 invariant post-run: HELD (zero diff — no Cargo.toml
  change means no lockfile regeneration; LESSONS refined
  accordingly).
- macOS/Windows ledger + README/ARCHITECTURE counts DEFERRED to the
  next CI-verified push (push auth absent this run; honesty rule:
  no unverified per-platform claims).
- D-0022 guard fix verified: bash -n clean; throwaway-repo scenarios
  A equal→ALLOW, B local-ahead→ALLOW (the deadlock fix), C
  remote-ahead→REFUSE, D diverged→REFUSE, E unseen-remote→REFUSE
  (fail-closed via merge-base's not-a-valid-commit exit). Script:
  /home/z/my-project/scripts/guard_test.sh (outside the repo).

## Docs updated
ROADMAP (item annotations DONE + baseline Linux 83; acceptance list
struck through with evidence), THREAT-MODEL (§A enforcement shipped;
§C salt-replay limit struck, moved to Defenses with the honest
1024-eviction residual), SANDBOX-RESTORE (4W static 85; step-0 guard
wording), STATE, DECISIONS D-0022, LESSONS (3 run-4 entries),
PROJECT_MEMORY, this journal.

## Backup
- Final step: backup.sh executed with the D-0022-fixed guard — the
  local-ahead state is now correctly ALLOWED to attempt the push;
  HOLO_GITHUB_TOKEN still absent → push fails honestly, FAILED marker
  committed locally per the durability rule. Outcome: BACKUPS.md
  tail.

## Next
1. Owner: D-0009/D-0013 (advisory vs v0.3.1 — BEFORE the XChaCha
   wire change), S5 credentials, D-0014; ALSO provide the token (env
   var) or push from the host so the run-3/4 backups land + CI
   verifies the 83-test tree.
2. S1 continues: ProbeGuard decay (N=1024), CSPRNG-jittered
   slow-close + delay-ceiling decision, close-vs-hang read deadline
   (A2-F6), XChaCha wire fix + rand-split enforcement, then
   BLAKE2s → X25519 → AES-CFB → ExpandLabel → bignum/RSA.
