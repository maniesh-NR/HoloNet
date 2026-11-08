//! links.rs — share-link parsers → Vec<Profile> (ss/vmess/vless/trojan/
//! hysteria2/tuic/wireguard:// + multi-line subscriptions).
use crate::{Profile, Profile as P};
use holo_proto::Params;
use holo_util::{base64, json::Value};

pub fn parse(text: &str) -> Result<Vec<Profile>, String> {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        match parse_line(line) {
            Ok(mut ps) => out.append(&mut ps),
            Err(e) => errs.push(e),
        }
    }
    if out.is_empty() {
        return Err(format!(
            "links: no profiles parsed ({})",
            errs.first().cloned().unwrap_or_default()
        ));
    }
    Ok(out)
}

pub fn parse_line(line: &str) -> Result<Vec<Profile>, String> {
    let (scheme, rest) = line.split_once("://").ok_or("links: not a URL")?;
    let p = match scheme {
        "ss" => parse_ss(rest).map(|p| vec![p]),
        "vmess" => parse_vmess(rest).map(|p| vec![p]),
        "vless" => parse_vless(rest).map(|p| vec![p]),
        "trojan" => parse_trojan(rest).map(|p| vec![p]),
        "hysteria2" | "hy2" => parse_hysteria2(rest).map(|p| vec![p]),
        "tuic" => parse_tuic(rest).map(|p| vec![p]),
        "wireguard" | "wg" => parse_wireguard(rest).map(|p| vec![p]),
        other => Err(format!("links: unsupported scheme {:?}", other)),
    }?;
    Ok(p)
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn split_url(rest: &str) -> (String, Vec<(String, String)>, String) {
    let (before_frag, frag) = match rest.find('#') {
        Some(p) => (&rest[..p], pct_decode(&rest[p + 1..])),
        None => (rest, String::new()),
    };
    let (authority, query_str) = match before_frag.find('?') {
        Some(p) => (&before_frag[..p], &before_frag[p + 1..]),
        None => (before_frag, ""),
    };
    let mut query = Vec::new();
    for pair in query_str.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.find('=') {
            Some(p) => (&pair[..p], &pair[p + 1..]),
            None => (pair, ""),
        };
        query.push((pct_decode(k), pct_decode(v)));
    }
    (authority.to_string(), query, frag)
}

fn qget(query: &[(String, String)], key: &str) -> Option<String> {
    query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn split_authority(auth: &str) -> (Option<String>, String, u16) {
    let (userinfo, hostport) = match auth.rfind('@') {
        Some(p) => (Some(auth[..p].to_string()), auth[p + 1..].to_string()),
        None => (None, auth.to_string()),
    };
    let (host, port) = parse_hostport(&hostport);
    (userinfo, host, port)
}

fn parse_hostport(s: &str) -> (String, u16) {
    if let Some(rb) = s.rfind(']') {
        // [v6]:port
        let host = s[1..rb].to_string();
        let port = s[rb + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        return (host, port);
    }
    match s.rfind(':') {
        Some(p) => (
            s[..p].trim_matches(['[', ']']).to_string(),
            s[p + 1..].parse().unwrap_or(0),
        ),
        None => (s.trim_matches(['[', ']']).to_string(), 0),
    }
}

fn profile(driver: &str, host: &str, port: u16, name: &str, params: Params) -> P {
    let mut p = P::new(driver, host, port).with_source("import:links");
    p.name = name.to_string();
    p.params = params;
    p
}

fn parse_ss(rest: &str) -> Result<P, String> {
    let (authority, query, name) = split_url(rest);
    let (userinfo, host, port) = split_authority(&authority);
    let (method, password) = if let Some(ui) = userinfo {
        // SIP002: base64url(method:password) — may be unpadded.
        let decoded = base64::decode(&ui).map_err(|e| format!("links/ss: {}", e))?;
        let text = String::from_utf8_lossy(&decoded).to_string();
        let (m, p) = text.split_once(':').ok_or("links/ss: no ':' in userinfo")?;
        (pct_decode(m), pct_decode(p))
    } else {
        // Legacy: whole authority is base64(method:password@host:port)
        let decoded = base64::decode(&authority).map_err(|e| format!("links/ss: {}", e))?;
        let text = String::from_utf8_lossy(&decoded).to_string();
        let at = text
            .rfind('@')
            .ok_or("links/ss: legacy payload lacks '@'")?;
        let (mp, hp) = (&text[..at], &text[at + 1..]);
        let (h, p) = parse_hostport(hp);
        let (m, pw) = mp
            .split_once(':')
            .ok_or("links/ss: no ':' in method:password")?;
        let mut params = Params::new();
        params.insert("method".into(), pct_decode(m));
        params.insert("password".into(), pct_decode(pw));
        return Ok(profile("shadowsocks", &h, p, &name, params));
    };
    let mut params = Params::new();
    params.insert("method".into(), method);
    params.insert("password".into(), password);
    if let Some(plugin) = qget(&query, "plugin") {
        let mut tokens = plugin.split(';');
        if let Some(n) = tokens.next() {
            if !n.is_empty() {
                params.insert("plugin".into(), n.to_string());
            }
        }
        for t in tokens {
            if let Some(eq) = t.find('=') {
                params.insert(format!("plugin_{}", &t[..eq]), t[eq + 1..].to_string());
            }
        }
    }
    if host.is_empty() || port == 0 {
        return Err("links/ss: missing host/port".into());
    }
    Ok(profile("shadowsocks", &host, port, &name, params))
}

fn parse_vmess(rest: &str) -> Result<P, String> {
    let decoded = base64::decode(rest.trim()).map_err(|e| format!("links/vmess: {}", e))?;
    let text = String::from_utf8_lossy(&decoded).to_string();
    let v = Value::parse(&text).map_err(|e| format!("links/vmess: bad JSON: {}", e))?;
    let host = v.str_or("add", "").to_string();
    let port: u16 = v
        .str_or("port", "0")
        .trim()
        .parse()
        .map_err(|_| "links/vmess: bad port")?;
    let mut params = Params::new();
    for (k, dst) in [
        ("id", "uuid"),
        ("aid", "aid"),
        ("scy", "scy"),
        ("net", "network"),
        ("type", "type"),
        ("host", "host"),
        ("path", "path"),
        ("tls", "tls"),
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fp"),
    ] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                params.insert(dst.into(), s.to_string());
            }
        }
    }
    if params.get("tls").is_none() {
        params.insert("tls".into(), "0".into());
    }
    let name = v.str_or("ps", "").to_string();
    Ok(profile("vmess", &host, port, &name, params))
}

fn parse_vless(rest: &str) -> Result<P, String> {
    let (authority, query, name) = split_url(rest);
    let (userinfo, host, port) = split_authority(&authority);
    let uuid = userinfo.ok_or("links/vless: missing uuid")?;
    let mut params = Params::new();
    params.insert("uuid".into(), uuid);
    for (k, dst) in [
        ("security", "security"),
        ("sni", "sni"),
        ("fp", "fp"),
        ("pbk", "pbk"),
        ("sid", "sid"),
        ("spx", "spx"),
        ("flow", "flow"),
        ("type", "network"),
        ("path", "path"),
        ("host", "host"),
        ("serviceName", "service_name"),
        ("encryption", "encryption"),
    ] {
        if let Some(v) = qget(&query, k) {
            if !v.is_empty() {
                params.insert(dst.into(), v);
            }
        }
    }
    if params.get("security").is_none() {
        params.insert("security".into(), "none".into());
    }
    Ok(profile("vless", &host, port, &name, params))
}

fn parse_trojan(rest: &str) -> Result<P, String> {
    let (authority, query, name) = split_url(rest);
    let (userinfo, host, port) = split_authority(&authority);
    let password = userinfo.ok_or("links/trojan: missing password")?;
    let mut params = Params::new();
    params.insert("password".into(), pct_decode(&password));
    if let Some(sni) = qget(&query, "sni") {
        params.insert("sni".into(), sni);
    }
    if let Some(t) = qget(&query, "type") {
        params.insert("network".into(), t);
    }
    Ok(profile("trojan", &host, port, &name, params))
}

fn parse_hysteria2(rest: &str) -> Result<P, String> {
    let (authority, query, name) = split_url(rest);
    let (userinfo, host, port) = split_authority(&authority);
    let mut params = Params::new();
    if let Some(auth) = userinfo {
        params.insert("auth".into(), pct_decode(&auth));
    }
    if let Some(obfs) = qget(&query, "obfs") {
        params.insert("obfs".into(), obfs);
    }
    if let Some(p) = qget(&query, "obfs-password") {
        params.insert("obfs_password".into(), p);
    }
    if let Some(sni) = qget(&query, "sni") {
        params.insert("sni".into(), sni);
    }
    if let Some(i) = qget(&query, "insecure") {
        params.insert("insecure".into(), i);
    }
    if let Some(pin) = qget(&query, "pinSHA256") {
        params.insert("pin_sha256".into(), pin);
    }
    Ok(profile("hysteria2", &host, port, &name, params))
}

fn parse_tuic(rest: &str) -> Result<P, String> {
    let (authority, query, name) = split_url(rest);
    let (userinfo, host, port) = split_authority(&authority);
    let creds = userinfo.ok_or("links/tuic: missing uuid:password")?;
    let (uuid, password) = creds
        .split_once(':')
        .ok_or("links/tuic: no ':' in credentials")?;
    let mut params = Params::new();
    params.insert("uuid".into(), uuid.to_string());
    params.insert("password".into(), pct_decode(password));
    for (k, dst) in [
        ("congestion_control", "congestion_control"),
        ("udp_relay_mode", "udp_relay_mode"),
        ("alpn", "alpn"),
        ("sni", "sni"),
        ("allow_insecure", "insecure"),
    ] {
        if let Some(v) = qget(&query, k) {
            params.insert(dst.into(), v);
        }
    }
    Ok(profile("tuic", &host, port, &name, params))
}

fn parse_wireguard(rest: &str) -> Result<P, String> {
    // wireguard://privkey@host:port?address=…&public-key=…#name
    let (authority, query, name) = split_url(rest);
    let (userinfo, host, port) = split_authority(&authority);
    let mut params = Params::new();
    if let Some(pk) = userinfo {
        params.insert("private_key".into(), pk);
    }
    if let Some(a) = qget(&query, "address") {
        params.insert("address".into(), a);
    }
    if let Some(pk) = qget(&query, "public-key") {
        params.insert("peer_public_key".into(), pk);
    }
    if let Some(psk) = qget(&query, "preshared-key") {
        params.insert("preshared_key".into(), psk);
    }
    if let Some(r) = qget(&query, "reserved") {
        params.insert("reserved".into(), r);
    }
    Ok(profile("wireguard", &host, port, &name, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use holo_proto::get_or_empty;

    #[test]
    fn ss_sip002() {
        // base64url("aes-256-gcm:secretpw") without padding
        let userinfo = base64::encode_url(b"aes-256-gcm:secretpw");
        let link = format!("ss://{}@example.com:8388#TestSS", userinfo);
        let ps = parse(&link).unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].driver, "shadowsocks");
        assert_eq!(ps[0].server, "example.com");
        assert_eq!(ps[0].port, 8388);
        assert_eq!(get_or_empty(&ps[0].params, "method"), "aes-256-gcm");
        assert_eq!(get_or_empty(&ps[0].params, "password"), "secretpw");
        assert_eq!(ps[0].name, "TestSS");
    }

    #[test]
    fn ss_legacy_full_b64() {
        // base64("aes-256-gcm:pw@1.2.3.4:8388")
        let payload = base64::encode(b"aes-256-gcm:pw@1.2.3.4:8388");
        let ps = parse(&format!("ss://{}", payload)).unwrap();
        assert_eq!(ps[0].server, "1.2.3.4");
        assert_eq!(ps[0].port, 8388);
    }

    #[test]
    fn vless_reality() {
        let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179&sni=www.yahoo.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#proxy";
        let ps = parse_line(link).unwrap();
        let p = &ps[0];
        assert_eq!(p.driver, "vless");
        assert_eq!(
            get_or_empty(&p.params, "uuid"),
            "b831381d-6324-4d53-ad4f-8cda48b30811"
        );
        assert_eq!(get_or_empty(&p.params, "security"), "reality");
        assert_eq!(
            get_or_empty(&p.params, "pbk"),
            "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
        );
        assert_eq!(get_or_empty(&p.params, "flow"), "xtls-rprx-vision");
    }

    #[test]
    fn trojan_and_hy2() {
        let ps = parse_line("trojan://s3cret@example.com:443?sni=cdn.example.com#tj").unwrap();
        assert_eq!(get_or_empty(&ps[0].params, "password"), "s3cret");
        assert_eq!(get_or_empty(&ps[0].params, "sni"), "cdn.example.com");
        let ps = parse_line("hy2://auth@h.example.com:8443?obfs=salamander&obfs-password=xyz#hy")
            .unwrap();
        assert_eq!(ps[0].driver, "hysteria2");
        assert_eq!(get_or_empty(&ps[0].params, "obfs"), "salamander");
    }

    #[test]
    fn multiline_subscription() {
        let userinfo = base64::encode_url(b"aes-256-gcm:x");
        let text = format!(
            "ss://{}@a.com:1#A\nss://{}@b.com:2#B\n# comment",
            userinfo, userinfo
        );
        let ps = parse(&text).unwrap();
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn ipv6_authority() {
        let userinfo = base64::encode_url(b"aes-256-gcm:x");
        let ps = parse_line(&format!("ss://{}@[2001:db8::1]:8388#v6", userinfo)).unwrap();
        assert_eq!(ps[0].server, "2001:db8::1");
        assert_eq!(ps[0].port, 8388);
    }
}
