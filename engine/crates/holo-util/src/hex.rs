//! Lowercase hex.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex: odd length".into());
    }
    (0..cleaned.len() / 2)
        .map(|i| {
            let hi = (cleaned[2 * i] as char).to_digit(16).ok_or("hex: bad digit")?;
            let lo = (cleaned[2 * i + 1] as char).to_digit(16).ok_or("hex: bad digit")?;
            Ok(((hi << 4) | lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        assert_eq!(super::encode(&[0, 1, 0xab, 0xff]), "0001abff");
        assert_eq!(super::decode("00 01ABff").unwrap(), vec![0, 1, 0xab, 0xff]);
        assert!(super::decode("0").is_err());
    }
}
