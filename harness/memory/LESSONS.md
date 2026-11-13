# Lessons (append-only — read these FIRST on every restore)

## Infrastructure

- Sandbox recycles wiped the tree twice (a 197-test engine was lost once).
  GitHub is the only durable memory. Every execution plan ends with
  `harness/scripts/backup.sh`; restore = `git checkout sandbox/latest`.
- The persistent shell resets its cwd between messages: ALWAYS `cd` with
  absolute paths inside every Bash command; never rely on inherited cwd.
- The Write tool needs parent directories to exist: `mkdir -p` first.
- Fresh sandbox = reinstall toolchain (~2 min):
  `curl -o /tmp/rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init`,
  `chmod +x`, run with `-y --profile minimal --default-toolchain stable`,
  then `. "$HOME/.cargo/env"`. Engine builds on stable; CI pins 1.77.2
  for the Win7/Catalina floor.
- Fresh clone = no git identity: set `user.name`/`user.email` in the repo
  before committing (use the same author as previous commits).
- `git add -A` is safe only because `.gitignore` covers `engine/target/`,
  `**/target/`, logs, keystores, `**/ipc-token`. Keep it that way.

## Crypto pitfalls (each cost a debugging session once)

- Poly1305: accumulate and fold at 2^130 — NEVER 2^128; the RFC clamp is
  applied as ONE 128-bit number, not limb-wise.
- BLAKE2s/b: rotations are RIGHT (ROTR), not left.
- X25519: a24 = 121665; inversion exponent is p−2 (limb 0 = 0xffffffeb…);
  reject the all-zero shared secret.
- AES S-box: generate it, do not transcribe it (transcription typos are
  invisible to review and fatal to correctness).

## Protocol pitfalls

- QUIC: the packet-number decode window must be seeded from the FIRST
  packet — using u64::MAX silently drops packets ≥ 128. Initial salt:
  38762cf7f55934b34d179ae6a4c80cadccbb7f0a. Header-protection sample is
  taken AFTER the pn field.
- Shadowsocks server: send the salt BEFORE decrypting anything —
  wrong-password clients must fail fast, not deadlock.
- SOCKS5 RFC 1929: read ver+ulen in ONE 2-byte read; a second read for
  ulen consumes the username as a length and deadlocks the handshake.
- holo-socks accept loop: reset accepted sockets to blocking mode; count
  refused connections BEFORE the client-visible reply; the loop must
  survive dead queued connections (see git history: 10b709d, 4fbc127,
  be728ef).
- Clash YAML: an inline `[2001:db8::1]:443` value is a scalar, not a flow
  list.

## Process

- CI needs holo-socks tests with `--test-threads=1` and log-dump
  annotations on failure (see `.github/workflows/ci.yml`).
- Quote test counts only after counting them from the tree; re-run
  `cargo test --workspace` in the current sandbox before claiming green.
- Claim rot is real (gate 0001 A1): the README said "28 tests" and
  "71/71" in different sections, "randomized slow-close" for a
  deterministic delay, "+376 KB" for an unasserted observation. Honesty
  surfaces drift the moment features land — that is exactly why reviewer
  A1 re-counts everything at every gate.
- A backup log line appended BEFORE a successful push can claim a
  backup that never landed ("phantom backup", gate 0001 A4-F5) — hence
  backup.sh's FAILED marker lines: failures are durable facts.
- `*.dmg/` in .gitignore matches DIRECTORIES only — a bare `HoloNet.dmg`
  file was NOT ignored until the pattern was fixed. Verify ignore rules
  with `git check-ignore` probes, never by eyeballing patterns.
- `git add -A` sweeps whatever is not explicitly ignored — the ignore
  list must cover credential-shaped files (*.pem, *.key, *.env, id_rsa,
  *.p12) or a backup will commit secrets (gate 0001 A2-F8/A4-C3).
