//! Randomness (std-only): urandom with a splitmix64 fallback.
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

fn next_u64() -> u64 {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
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

pub fn fill(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let v = next_u64().to_le_bytes();
        let take = (buf.len() - i).min(8);
        buf[i..i + take].copy_from_slice(&v[..take]);
        i += take;
    }
}

pub fn bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill(&mut v);
    v
}

pub fn hex(n: usize) -> String {
    crate::hex::encode(&bytes(n))
}

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
}
