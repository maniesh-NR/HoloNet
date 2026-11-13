//! Randomness (std-only), with a STRICT separation of security and
//! non-security sources (see docs/THREAT-MODEL.md, "Entropy"):
//!
//! - `os_fill` / `os_bytes` / `os_hex`: OS entropy (`/dev/urandom`),
//!   FAIL-CLOSED. For ALL security material (AEAD salts, auth tokens,
//!   future keys and nonces). No silent fallback: if the OS source cannot
//!   be read, the call returns `Err` and the caller must surface it.
//!   Windows has no `/dev/urandom` — those calls fail closed (an explicit
//!   error, never weak randomness) until the audited platform FFI lands
//!   (ROADMAP S1 item 0, decision D-0008).
//! - `fill` / `bytes` / `hex` / `alnum`: non-security PRNG (urandom when
//!   available, otherwise splitmix64 seeded time^pid^counter) for IDs,
//!   jitter, and test data. NEVER for crypto material.
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

/// Fail-closed OS entropy from an explicit source path (separable so the
/// failure path is unit-testable: an unreadable source is an `Err`).
pub fn os_fill_at(path: &str, buf: &mut [u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::open(path)?;
    f.read_exact(buf)
}

/// Fail-closed OS entropy for SECURITY material — no fallback, ever.
pub fn os_fill(buf: &mut [u8]) -> std::io::Result<()> {
    os_fill_at("/dev/urandom", buf)
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

#[cfg(test)]
mod tests {
    #[test]
    fn distinct() {
        assert_ne!(super::bytes(32), super::bytes(32));
        assert_eq!(super::hex(16).len(), 32);
        assert_eq!(super::alnum(32).len(), 32);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn os_entropy_succeeds_and_is_nonzero() {
        let mut b = [0u8; 32];
        super::os_fill(&mut b).expect("os entropy must be readable on unix");
        assert!(b.iter().any(|&x| x != 0), "entropy must not be all zero");
        assert_eq!(super::os_hex(16).unwrap().len(), 32);
    }

    #[test]
    fn os_entropy_fails_closed_on_unreadable_source() {
        // gate-0001 A2-C1: entropy failure must be an ERROR, never a
        // silent weak fallback
        let mut b = [0u8; 8];
        assert!(super::os_fill_at("/nonexistent-holonet-entropy", &mut b).is_err());
    }
}
