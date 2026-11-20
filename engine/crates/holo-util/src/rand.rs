//! Randomness (std-only), with a STRICT separation of security and
//! non-security sources (see docs/THREAT-MODEL.md, "Entropy"):
//!
//! - `os_fill` / `os_bytes` / `os_hex`: OS entropy, FAIL-CLOSED. For ALL
//!   security material (AEAD salts, auth tokens, future keys and
//!   nonces). No silent fallback: if the OS source cannot be read, the
//!   call returns `Err` and the caller must surface it. Unix:
//!   `/dev/urandom`. Windows (S1 item 0, D-0008 — the chartered,
//!   contained FFI exception): RtlGenRandom via advapi32, available
//!   since Windows XP so the Windows 7 SP1 floor is covered; any
//!   syscall failure is an explicit error.
//! - The non-security PRNG lives in the `nosec` submodule (IDs, jitter,
//!   test data). NEVER for crypto material. The split is MECHANICAL
//!   since run 6 (gate-0001 A2-C3 / ROADMAP S1 item 7, D-0024): the
//!   weak names are not re-exported at the crate root or at this
//!   module's root (calling `rand::fill` for a nonce is a compile
//!   error), `nosec` is `#[doc(hidden)]`, and the `rand_split_audit`
//!   test fails CI if any file outside its allowlist references the
//!   weak PRNG at all.
use std::io::Read;

/// The ONLY `unsafe` in the workspace (D-0008, audited exception,
/// re-reviewed at every gate): Windows CSPRNG via RtlGenRandom
/// (advapi32's SystemFunction036). `grep -rn "unsafe" engine/crates/`
/// must return hits in this file ONLY.
#[cfg(windows)]
mod win_entropy {
    #[cfg(test)]
    use std::sync::atomic::AtomicBool;

    #[link(name = "advapi32")]
    extern "system" {
        // RtlGenRandom is a header-level macro; the import library
        // exports the underlying ordinal name SystemFunction036 (linking
        // as "RtlGenRandom" yields LNK2019 __imp_RtlGenRandom — CI-learned
        // 2026-11-20; a check-only cross-compile cannot catch this, only
        // the real MSVC link does).
        fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8;
    }

    /// TEST SEAM (fail-closed injection, analogous to unix's
    /// `os_fill_at` bad-path test): production never sets it.
    #[cfg(test)]
    pub(crate) static INJECT_FAIL: AtomicBool = AtomicBool::new(false);

    pub(crate) fn fill(buf: &mut [u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        #[cfg(test)]
        if INJECT_FAIL.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "RtlGenRandom injected failure — refusing weak randomness (fail-closed)",
            ));
        }
        // SystemFunction036 == RtlGenRandom; takes a ULONG length; buffer
        // needs are tiny (32-byte salts, tokens) but chunk defensively.
        let len = buf.len().min(u32::MAX as usize) as u32;
        let ok = unsafe { SystemFunction036(buf.as_mut_ptr(), len) };
        if ok == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "RtlGenRandom failed — refusing weak randomness (fail-closed)",
            ));
        }
        Ok(())
    }
}

/// Fail-closed OS entropy from an explicit source path (separable so the
/// failure path is unit-testable: an unreadable source is an `Err`).
pub fn os_fill_at(path: &str, buf: &mut [u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::open(path)?;
    f.read_exact(buf)
}

/// Fail-closed OS entropy for SECURITY material — no fallback, ever.
pub fn os_fill(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        win_entropy::fill(buf)
    }
    #[cfg(not(windows))]
    {
        os_fill_at("/dev/urandom", buf)
    }
}

/// Security-grade random bytes (fail-closed).
pub fn os_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    os_fill(&mut v)?;
    Ok(v)
}

/// Security-grade random hex, `2n` chars (fail-closed).
pub fn os_hex(n: usize) -> std::io::Result<String> {
    Ok(crate::hex::encode(&os_bytes(n)?))
}

/// NON-SECURITY PRNG — **never** for crypto material (IDs, jitter, test
/// data only). Sources: `/dev/urandom` when available, otherwise
/// splitmix64 seeded time^pid^counter — predictable by a local attacker
/// by design, which is exactly why it must never touch security material.
///
/// Mechanical enforcement (gate-0001 A2-C3 / ROADMAP S1 item 7, D-0024):
/// - these functions are NOT re-exported from `rand` or the crate root —
///   `rand::fill(...)` no longer compiles; only `rand::nosec::fill(...)`
///   does, and the module name is the review tripwire;
/// - `#[doc(hidden)]` keeps this module out of rustdoc and IDE
///   autocomplete, so the path must be typed deliberately;
/// - the `rand_split_audit` test (this file) fails CI if any workspace
///   file outside its allowlist references `nosec::` or a weak path.
///
/// If a new non-security consumer is genuinely needed: extend the audit
/// allowlist WITH a justification comment and record the decision in
/// `harness/memory/DECISIONS.md` — never reach for these from security
/// code, and never use them to "fix" a failing audit test.
#[doc(hidden)]
pub mod nosec {
    use std::io::Read;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0x9E3779B97F4A7C15);

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Non-security PRNG step (urandom when available, else splitmix64).
    fn next_u64() -> u64 {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut b = [0u8; 8];
            if f.read_exact(&mut b).is_ok() {
                return u64::from_le_bytes(b);
            }
        }
        let mut st = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ (std::process::id() as u64) << 32
            ^ COUNTER.fetch_add(1, Ordering::Relaxed);
        splitmix64(&mut st)
    }

    /// Non-security PRNG fill — IDs, jitter, test data. Never crypto material.
    pub fn fill(buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = next_u64().to_le_bytes();
            let take = (buf.len() - i).min(8);
            buf[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
    }

    /// Non-security random bytes.
    pub fn bytes(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        fill(&mut v);
        v
    }

    /// Non-security random hex, `2n` chars.
    pub fn hex(n: usize) -> String {
        crate::hex::encode(&bytes(n))
    }

    /// Non-security random lowercase-alnum, `n` chars.
    pub fn alnum(n: usize) -> String {
        const CS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        bytes(n)
            .iter()
            .map(|b| CS[(*b as usize) % CS.len()] as char)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn distinct() {
        assert_ne!(super::nosec::bytes(32), super::nosec::bytes(32));
        assert_eq!(super::nosec::hex(16).len(), 32);
        assert_eq!(super::nosec::alnum(32).len(), 32);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn os_entropy_succeeds_and_is_nonzero() {
        let mut b = [0u8; 32];
        super::os_fill(&mut b).expect("os entropy must be readable on unix");
        assert!(b.iter().any(|&x| x != 0), "entropy must not be all zero");
        assert_eq!(super::os_hex(16).unwrap().len(), 32);
    }

    #[cfg(windows)]
    #[test]
    fn os_entropy_succeeds_and_is_nonzero_windows() {
        // S1 item 0 (D-0008): the RtlGenRandom path must satisfy the same
        // contract as unix — real entropy, never all-zero.
        let mut b = [0u8; 32];
        super::os_fill(&mut b).expect("RtlGenRandom must succeed on windows");
        assert!(b.iter().any(|&x| x != 0), "entropy must not be all zero");
        assert_eq!(super::os_hex(16).unwrap().len(), 32);
        let mut empty: [u8; 0] = [];
        assert!(super::os_fill(&mut empty).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn os_entropy_fails_closed_on_ffi_failure_windows() {
        // S1 item 0 acceptance: a Windows FFI failure is a hard ERROR,
        // never a silent weak fallback (seam mirrors the unix
        // os_fill_at bad-path test).
        super::win_entropy::INJECT_FAIL.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut b = [0u8; 32];
        let r = super::os_fill(&mut b);
        super::win_entropy::INJECT_FAIL.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(r.is_err(), "injected FFI failure must surface as Err");
        assert!(b.iter().all(|&x| x == 0), "no bytes may be produced on failure");
    }

    #[test]
    fn os_entropy_fails_closed_on_unreadable_source() {
        // gate-0001 A2-C1: entropy failure must be an ERROR, never a
        // silent weak fallback
        let mut b = [0u8; 8];
        assert!(super::os_fill_at("/nonexistent-holonet-entropy", &mut b).is_err());
    }
}

/// Workspace grep-audit: the non-security PRNG may be referenced ONLY by
/// the allowlisted files below. This is the CI-enforced half of the
/// rand-split (gate-0001 A2-C3, "verifiable by compile failure or the
/// audit test" — here we ship BOTH: the compile-failure half is the
/// removal of the `rand` root names and the crate-root re-export, this
/// test is the audit half).
#[cfg(test)]
mod rand_split_audit {
    use std::path::{Path, PathBuf};

    /// Paths relative to the engine workspace root where the non-security
    /// PRNG may legitimately appear. Every entry carries its gate- or
    /// decision-classified justification; extend ONLY with the same.
    const ALLOWLIST: &[&str] = &[
        // The definition itself (module, docs, and this audit test).
        "crates/holo-util/src/rand.rs",
        // Profile-ID generation — the ONE consumer the gate-0001 verdict
        // classified as non-security ("the only remaining non-security
        // consumer is profile IDs"). Decision D-0024.
        "crates/holo-config/src/lib.rs",
    ];

    /// Patterns that must not appear outside the allowlist:
    /// - `nosec::` — any reference to the non-security module;
    /// - `rand::{name}` — the historical root-level weak paths (dead
    ///   since the split, kept so a future re-export with callers cannot
    ///   silently reintroduce them);
    /// - `use rand::{` — grouped re-imports of weak names.
    fn weak_patterns() -> Vec<String> {
        let mut pats = vec!["nosec::".to_string(), "use rand::{".to_string()];
        for name in ["fill", "bytes", "hex", "alnum"] {
            pats.push(format!("rand::{}", name));
        }
        pats
    }

    fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // hidden dirs (.git, .cargo)
            }
            if p.is_dir() {
                if name == "target" {
                    continue; // build artifacts
                }
                collect_rs(&p, out);
            } else if name.ends_with(".rs") {
                out.push(p);
            }
        }
    }

    #[test]
    fn rand_split_audit_no_weak_prng_outside_allowlist() {
        // manifest dir = engine/crates/holo-util → engine root is two
        // ancestors up; this keeps the audit correct in any checkout path.
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest
            .ancestors()
            .nth(2)
            .expect("engine workspace root above crates/<name>")
            .to_path_buf();

        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        // Guard against scanning the wrong (empty) root: the workspace
        // has 17 .rs files today and must only grow.
        assert!(
            files.len() >= 15,
            "workspace scan found only {} .rs files — wrong root?",
            files.len()
        );

        let pats = weak_patterns();
        let mut hits: Vec<String> = Vec::new();
        for f in &files {
            let rel = f
                .strip_prefix(&root)
                .expect("scanned path is under root")
                .to_string_lossy()
                .replace('\\', "/");
            // Integration-test directories are in the verdict's allowed
            // set ("outside holo-config IDs/tests"). Unit-test modules
            // inside src files are NOT exempt — extending ALLOWLIST is
            // the visible, reviewable path for those.
            if ALLOWLIST.contains(&rel.as_str()) || rel.contains("/tests/") {
                continue;
            }
            let src = match std::fs::read_to_string(f) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for (i, line) in src.lines().enumerate() {
                for pat in &pats {
                    if line.contains(pat.as_str()) {
                        hits.push(format!("{}:{}: matched \"{}\"", rel, i + 1, pat));
                    }
                }
            }
        }

        assert!(
            hits.is_empty(),
            "rand-split violation (gate-0001 A2-C3 / ROADMAP S1 item 7 / D-0024): the \
             non-security PRNG may only be referenced by the audit allowlist. Offenders:\n  \
             {}\nSecurity material MUST use holo_util::rand::os_fill/os_bytes/os_hex \
             (fail-closed). A genuinely new NON-security consumer extends ALLOWLIST with \
             a justification and a DECISIONS.md record.",
            hits.join("\n  ")
        );
    }
}
