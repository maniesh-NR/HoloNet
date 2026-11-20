//! holo-util — hex, base64, JSON, randomness (std-only).
pub mod base64;
pub mod hex;
pub mod json;
pub mod rand;

pub use base64::{decode, encode};
pub use hex::{decode as hex_decode, encode as hex_encode};
pub use json::Value;
// NOTE (D-0024, gate-0001 A2-C3 rand-split): the non-security PRNG names
// are deliberately NOT re-exported here — they live behind rand::nosec
// (doc-hidden) and the rand_split_audit test fails CI outside its allowlist.
