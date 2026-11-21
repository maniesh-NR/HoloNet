//! holo-ss — Shadowsocks AEAD (SIP004) data plane, the first live protocol
//! in the HoloNet engine.
//!
//! Wire format (TCP, both directions independent):
//! `[32-byte salt]` then chunks: `[len(2 BE) | tag16][payload | tag16]`
//! - session subkey = HKDF-SHA1(master_key, salt, "ss-subkey", 32)
//! - master key = EVP_BytesToKey(MD5, password, 32)
//! - nonce = LE counter starting at zero, incremented after every
//!   AEAD operation (separate counters per direction): 12-byte for
//!   chacha20-ietf-poly1305 and aes-256-gcm, 24-byte for
//!   xchacha20-ietf-poly1305 — the standard SIP004 XChaCha wire
//!   (XChaCha20-Poly1305-IETF per draft-irtf-cfrg-xchacha, fixed 2026-
//!   11-21 run 8 after the mislabel found by record-0003 A2-F8)
//! - first chunk payload = SOCKS5 target address (+ optional user payload)
//!
//! Anti-probing: any AEAD tag failure closes the connection after a
//! delayed slow-close with per-peer exponential backoff
//! (holo_net::ProbeGuard). The error VALUE never leaks whether the failure
//! was salt, length, or payload. The close delay is CSPRNG-jittered since
//! run 5 (D-0023, ceiling 2 s — the deterministic-timing fingerprint is
//! closed).
//!
//! Supported ciphers: chacha20-ietf-poly1305, xchacha20-ietf-poly1305,
//! aes-256-gcm — all 32-byte keys, 16-byte tags.
#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use holo_crypto::{evp_bytes_to_key, hkdf_sha1, to_hex};

pub const SALT_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const MAX_PAYLOAD: usize = 0x3FFF;
pub const ADDR_MAX: usize = 1 + 1 + 255 + 16 + 2;

// ---------------------------------------------------------------------------
// ciphers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    ChaCha20IetfPoly1305,
    XChaCha20IetfPoly1305,
    Aes256Gcm,
}

impl Method {
    pub fn parse(s: &str) -> Option<Method> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chacha20-ietf-poly1305" => Some(Method::ChaCha20IetfPoly1305),
            "xchacha20-ietf-poly1305" => Some(Method::XChaCha20IetfPoly1305),
            "aes-256-gcm" => Some(Method::Aes256Gcm),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Method::ChaCha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Method::XChaCha20IetfPoly1305 => "xchacha20-ietf-poly1305",
            Method::Aes256Gcm => "aes-256-gcm",
        }
    }
}

/// One direction's crypto state: subkey + nonce counter.
struct Direction {
    method: Method,
    subkey: [u8; 32],
    nonce: Nonce,
}

/// SIP004 nonce: a little-endian counter starting at zero, incremented
/// after every AEAD operation. Its length is the cipher's AEAD nonce
/// length — 12 bytes (chacha20-ietf-poly1305, aes-256-gcm) or 24 bytes
/// (xchacha20-ietf-poly1305 = XChaCha20-Poly1305-IETF).
enum Nonce {
    N12([u8; 12]),
    N24([u8; 24]),
}

impl Nonce {
    fn zero_for(method: Method) -> Nonce {
        match method {
            Method::XChaCha20IetfPoly1305 => Nonce::N24([0u8; 24]),
            _ => Nonce::N12([0u8; 12]),
        }
    }

    /// little-endian increment over the full counter
    fn increment(&mut self) {
        let bytes: &mut [u8] = match self {
            Nonce::N12(n) => &mut n[..],
            Nonce::N24(n) => &mut n[..],
        };
        for b in bytes.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}

impl Direction {
    fn new(method: Method, master: &[u8; 32], salt: &[u8; 32]) -> Direction {
        let sub = hkdf_sha1(salt, master, b"ss-subkey", 32);
        let mut subkey = [0u8; 32];
        subkey.copy_from_slice(&sub);
        Direction {
            method,
            subkey,
            nonce: Nonce::zero_for(method), // SIP004: counter starts at zero
        }
    }

    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let out = match (&self.method, &self.nonce) {
            (Method::ChaCha20IetfPoly1305, Nonce::N12(n)) => {
                holo_crypto::aead_chacha20poly1305_encrypt(&self.subkey, n, aad, pt)
            }
            (Method::XChaCha20IetfPoly1305, Nonce::N24(n)) => {
                // Standard XChaCha20-Poly1305-IETF (draft-irtf-cfrg-xchacha,
                // holo-crypto draft-vector-proven): the 24-byte LE counter
                // IS the AEAD nonce; HChaCha20 subkey derivation happens
                // inside aead_xchacha20poly1305_*. Interops with mainstream
                // shadowsocks xchacha20-ietf-poly1305 peers.
                holo_crypto::aead_xchacha20poly1305_encrypt(&self.subkey, n, aad, pt)
            }
            (Method::Aes256Gcm, Nonce::N12(n)) => {
                holo_crypto::gcm::encrypt(&self.subkey, n, aad, pt)
            }
            _ => unreachable!("method/nonce length mismatch"),
        };
        self.nonce.increment();
        out
    }

    fn open(&mut self, aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
        let out = match (&self.method, &self.nonce) {
            (Method::ChaCha20IetfPoly1305, Nonce::N12(n)) => {
                holo_crypto::aead_chacha20poly1305_decrypt(&self.subkey, n, aad, ct_tag)
            }
            (Method::XChaCha20IetfPoly1305, Nonce::N24(n)) => {
                holo_crypto::aead_xchacha20poly1305_decrypt(&self.subkey, n, aad, ct_tag)
            }
            (Method::Aes256Gcm, Nonce::N12(n)) => {
                holo_crypto::gcm::decrypt(&self.subkey, n, aad, ct_tag)
            }
            _ => unreachable!("method/nonce length mismatch"),
        };
        self.nonce.increment();
        out
    }
}

/// Derive the 32-byte master key from a password (EVP_BytesToKey/MD5).
pub fn master_key(password: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&evp_bytes_to_key(password.as_bytes(), 32));
    k
}

/// Deterministic test vector for the KDF chain (documented, not secret):
/// lets other implementations validate our subkey derivation.
pub fn subkey_for_test(password: &str, salt: &[u8; 32]) -> String {
    let m = master_key(password);
    let d = Direction::new(Method::ChaCha20IetfPoly1305, &m, salt);
    to_hex(&d.subkey)
}

// ---------------------------------------------------------------------------
// address encoding (SOCKS5 format, shared with the wire protocol)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Domain(String, u16),
    Ipv4([u8; 4], u16),
    Ipv6([u8; 16], u16),
}

impl Target {
    pub fn parse(addr: &str) -> Result<Target, String> {
        // "host:port" — host may be v4, v6 ([..] form) or a domain
        let (host, port) = split_host_port(addr)?;
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Ok(Target::Ipv4(ip.octets(), port));
        }
        if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            return Ok(Target::Ipv6(ip.octets(), port));
        }
        if host.is_empty() || host.len() > 255 {
            return Err(format!("ss: bad host {host:?}"));
        }
        Ok(Target::Domain(host.to_string(), port))
    }

    pub fn to_string(&self) -> String {
        match self {
            Target::Domain(d, p) => format!("{d}:{p}"),
            Target::Ipv4(ip, p) => format!("{}:{}", std::net::Ipv4Addr::from(*ip), p),
            Target::Ipv6(ip, p) => format!("[{}]:{}", std::net::Ipv6Addr::from(*ip), p),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ADDR_MAX);
        match self {
            Target::Domain(d, _p) => {
                v.push(0x03);
                v.push(d.len() as u8);
                v.extend_from_slice(d.as_bytes());
            }
            Target::Ipv4(ip, _) => {
                v.push(0x01);
                v.extend_from_slice(ip);
            }
            Target::Ipv6(ip, _) => {
                v.push(0x04);
                v.extend_from_slice(ip);
            }
        }
        let p = match self {
            Target::Domain(_, p) | Target::Ipv4(_, p) | Target::Ipv6(_, p) => *p,
        };
        v.extend_from_slice(&p.to_be_bytes());
        v
    }

    fn decode(buf: &[u8]) -> Result<(Target, usize), String> {
        if buf.len() < 2 {
            return Err("ss: short address".into());
        }
        let (atyp, host_len, consumed) = match buf[0] {
            0x01 => (1, 4usize, 1 + 4),
            0x04 => (4, 16usize, 1 + 16),
            0x03 => (3, buf[1] as usize, 2 + buf[1] as usize),
            a => return Err(format!("ss: bad atyp {a}")),
        };
        if buf.len() < consumed + 2 {
            return Err("ss: truncated address".into());
        }
        let port = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]);
        let target = match atyp {
            1 => Target::Ipv4(buf[1..5].try_into().unwrap(), port),
            4 => Target::Ipv6(buf[1..17].try_into().unwrap(), port),
            _ => {
                let host = std::str::from_utf8(&buf[2..2 + host_len])
                    .map_err(|_| "ss: non-utf8 domain")?
                    .to_string();
                if host.is_empty() {
                    return Err("ss: empty domain".into());
                }
                Target::Domain(host, port)
            }
        };
        Ok((target, consumed + 2))
    }
}

fn split_host_port(s: &str) -> Result<(&str, u16), String> {
    if let Some(close) = s.rfind(']') {
        // [v6]:port
        if !s.starts_with('[') {
            return Err(format!("ss: bad bracketed host {s:?}"));
        }
        let host = &s[1..close];
        let rest = &s[close + 1..];
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("ss: no port after ] in {s:?}"))?;
        let port: u16 = port.parse().map_err(|_| format!("ss: bad port {port:?}"))?;
        Ok((host, port))
    } else {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("ss: no port in {s:?}"))?;
        let port: u16 = port.parse().map_err(|_| format!("ss: bad port {port:?}"))?;
        Ok((host, port))
    }
}

// ---------------------------------------------------------------------------
// framed stream — one direction over a shared TcpStream
// ---------------------------------------------------------------------------

/// Cryptographic stream I/O over one TCP direction. The client writes its
/// salt first; the server reads it. Reading is pull-based (exact framing).
struct Framing;

impl Framing {
    fn write_chunk(w: &mut impl Write, d: &mut Direction, payload: &[u8]) -> std::io::Result<()> {
        debug_assert!(payload.len() <= MAX_PAYLOAD);
        // length prefix (2 BE) is encrypted with its own tag (AAD = empty)
        let len_bytes = (payload.len() as u16).to_be_bytes();
        let len_ct = d.seal(&[], &len_bytes);
        w.write_all(&len_ct)?;
        let payload_ct = d.seal(&[], payload);
        w.write_all(&payload_ct)?;
        Ok(())
    }

    fn read_exact(rd: &mut impl Read, n: usize) -> std::io::Result<Vec<u8>> {
        let mut v = vec![0u8; n];
        rd.read_exact(&mut v)?;
        Ok(v)
    }

    fn read_chunk(rd: &mut impl Read, d: &mut Direction) -> std::io::Result<Option<Vec<u8>>> {
        // length: 2 bytes ct + 16 tag
        let len_ct = match Framing::read_exact(rd, 2 + TAG_LEN) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        let len_pt = d.open(&[], &len_ct).map_err(|_| auth_failed())?;
        let len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(auth_failed()); // oversized length = corrupt/probe
        }
        let payload_ct = Framing::read_exact(rd, len + TAG_LEN)?;
        let payload = d.open(&[], &payload_ct).map_err(|_| auth_failed())?;
        Ok(Some(payload))
    }
}

fn auth_failed() -> std::io::Error {
    // One opaque error for every crypto failure — no oracle for probers.
    std::io::Error::new(std::io::ErrorKind::InvalidData, "ss: auth failed")
}

// ---------------------------------------------------------------------------
// client connection (dialer side)
// ---------------------------------------------------------------------------

/// A client-side Shadowsocks tunnel connection. Write-side encrypts with
/// the client's own salt (sent first); read-side derives keys from the
/// server's salt.
pub struct ClientConn {
    sock: TcpStream,
    write: Direction,
    read: Option<Direction>,
    salt_sent: bool,
    inbuf: Vec<u8>, // decrypted payload waiting to be read
    target: Target,
    first_write_done: bool,
}

impl ClientConn {
    /// Dial `server` and establish the tunnel toward `target`.
    pub fn connect(
        server: &str,
        master: &[u8; 32],
        method: Method,
        target: Target,
        connect_timeout: Duration,
    ) -> std::io::Result<ClientConn> {
        let addr = resolve(server)?;
        let sock = TcpStream::connect_timeout(&addr, connect_timeout)?;
        sock.set_nodelay(true).ok();
        // security material: fail-closed OS entropy (A2/gate-0001)
        let salt = random_salt()?;
        let write = Direction::new(method, master, &salt);
        let mut c = ClientConn {
            sock,
            write,
            read: None,
            salt_sent: false,
            inbuf: Vec::new(),
            target,
            first_write_done: false,
        };
        c.send_salt(&salt)?;
        Ok(c)
    }

    fn send_salt(&mut self, salt: &[u8; 32]) -> std::io::Result<()> {
        self.sock.write_all(salt)?;
        self.salt_sent = true;
        Ok(())
    }

    /// Provide the master key for the read direction (server → client).
    /// Must be called after `connect` before the first read.
    pub fn set_read_master(&mut self, master: &[u8; 32], method: Method) {
        if self.read.is_none() {
            if let Ok(salt_bytes) = Framing::read_exact(&mut self.sock, SALT_LEN) {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&salt_bytes);
                self.read = Some(Direction::new(method, master, &salt));
            }
        }
    }

    pub fn target(&self) -> &Target {
        &self.target
    }
}

impl holo_proto::TunnelConn for ClientConn {
    /// Split into independent read/write halves. The write half owns the
    /// client-direction crypto (its salt was already sent); the read half
    /// owns the server-direction crypto. Each half keeps its own socket
    /// descriptor — the two nonce sequences stay independent, as SIP004
    /// requires.
    fn split_rw(
        self: Box<Self>,
    ) -> (
        Box<dyn std::io::Read + Send>,
        Box<dyn std::io::Write + Send>,
    ) {
        let sock_r = match self.sock.try_clone() {
            Ok(s) => s,
            Err(e) => {
                // degenerate but honest: fall back to a closed half
                let _ = e;
                let closed = std::net::TcpListener::bind("127.0.0.1:0")
                    .and_then(|l| l.local_addr())
                    .and_then(TcpStream::connect);
                match closed {
                    Ok(s) => {
                        let s2 = s.try_clone().expect("ss: split fallback clone");
                        return (
                            Box::new(ClientReadHalf {
                                sock: s2,
                                read: None,
                                inbuf: Vec::new(),
                            }),
                            Box::new(ClientWriteHalf {
                                sock: s,
                                write: None,
                                pending_addr: None,
                            }),
                        );
                    }
                    Err(_) => panic!("ss: cannot split conn"),
                }
            }
        };
        let rh = ClientReadHalf {
            sock: sock_r,
            read: self.read,
            inbuf: self.inbuf,
        };
        let wh = ClientWriteHalf {
            sock: self.sock,
            write: Some(self.write),
            pending_addr: if self.first_write_done {
                None
            } else {
                Some(self.target)
            },
        };
        (Box::new(rh), Box::new(wh))
    }
}

pub struct ClientReadHalf {
    sock: TcpStream,
    read: Option<Direction>,
    inbuf: Vec<u8>,
}

impl Read for ClientReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(d) = self.read.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "ss: read side not initialized",
            ));
        };
        if !self.inbuf.is_empty() {
            let n = buf.len().min(self.inbuf.len());
            buf[..n].copy_from_slice(&self.inbuf[..n]);
            self.inbuf.drain(..n);
            return Ok(n);
        }
        loop {
            match Framing::read_chunk(&mut self.sock, d) {
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        continue;
                    }
                    let n = buf.len().min(payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    self.inbuf.extend_from_slice(&payload[n..]);
                    return Ok(n);
                }
                Ok(None) => return Ok(0),
                Err(e) => return Err(e),
            }
        }
    }
}

pub struct ClientWriteHalf {
    sock: TcpStream,
    write: Option<Direction>,
    pending_addr: Option<Target>,
}

impl Write for ClientWriteHalf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(d) = self.write.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "ss: write side closed",
            ));
        };
        let mut sent = 0;
        let mut first_payload: Vec<u8> = Vec::new();
        if let Some(t) = self.pending_addr.take() {
            first_payload = t.encode();
        }
        if !buf.is_empty() && first_payload.len() < MAX_PAYLOAD {
            let room = MAX_PAYLOAD - first_payload.len();
            let take = buf.len().min(room);
            first_payload.extend_from_slice(&buf[..take]);
            sent += take;
        }
        if !first_payload.is_empty() {
            Framing::write_chunk(&mut self.sock, d, &first_payload)?;
        }
        while sent < buf.len() {
            let take = (buf.len() - sent).min(MAX_PAYLOAD);
            Framing::write_chunk(&mut self.sock, d, &buf[sent..sent + take])?;
            sent += take;
        }
        Ok(buf.len().max(1))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

impl Read for ClientConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "ss: read side not initialized (call set_read_master)",
            ));
        }
        // drain buffered payload first
        if !self.inbuf.is_empty() {
            let n = buf.len().min(self.inbuf.len());
            buf[..n].copy_from_slice(&self.inbuf[..n]);
            self.inbuf.drain(..n);
            return Ok(n);
        }
        loop {
            match Framing::read_chunk(&mut self.sock, self.read.as_mut().unwrap()) {
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        continue; // empty chunk: keep reading
                    }
                    let n = buf.len().min(payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    self.inbuf.extend_from_slice(&payload[n..]);
                    return Ok(n);
                }
                Ok(None) => return Ok(0), // clean EOF
                Err(e) => return Err(e),
            }
        }
    }
}

impl Write for ClientConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.salt_sent {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "ss: salt not sent",
            ));
        }
        let mut sent = 0;
        // first write carries the target address
        let mut first_payload: Vec<u8> = Vec::new();
        if !self.first_write_done {
            first_payload = self.target.encode();
            self.first_write_done = true;
        }
        if !first_payload.is_empty() && !buf.is_empty() {
            let room = MAX_PAYLOAD - first_payload.len();
            let take = buf.len().min(room);
            first_payload.extend_from_slice(&buf[..take]);
            sent += take;
        } else if !first_payload.is_empty() && buf.is_empty() {
            // address-only flush
        }
        Framing::write_chunk(&mut self.sock, &mut self.write, &first_payload)?;
        // remaining bytes as their own chunks
        while sent < buf.len() {
            let take = buf.len() - sent;
            let take = take.min(MAX_PAYLOAD);
            Framing::write_chunk(&mut self.sock, &mut self.write, &buf[sent..sent + take])?;
            sent += take;
        }
        Ok(buf.len().max(1))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

// ---------------------------------------------------------------------------
// server-side connection
// ---------------------------------------------------------------------------

/// Bounded FIFO cache of recently admitted client salts (S1 server-path
/// hardening, progress review 0002 A2-C1 — named acceptance: a replayed
/// salt+first-chunk connection is refused). A replayed captured prefix
/// gets the SAME opaque auth failure as a wrong password: same error,
/// same slow-close, no oracle for probers.
///
/// Honest limits: capacity-bounded FIFO — an attacker able to push
/// `capacity` fresh connections after capturing a prefix can age its
/// salt back out; an unbounded cache would instead be the DoS vector.
/// 1024 mirrors the ProbeGuard peer bound rationale (ROADMAP S1).
pub struct SaltCache {
    ring: VecDeque<[u8; SALT_LEN]>,
    index: HashSet<[u8; SALT_LEN]>,
    capacity: usize,
}

/// Default bound for server-side salt tracking (see SaltCache docs).
pub const SALT_CACHE_CAPACITY: usize = 1024;

impl SaltCache {
    pub fn new(capacity: usize) -> SaltCache {
        SaltCache {
            ring: VecDeque::new(),
            index: HashSet::new(),
            capacity,
        }
    }

    /// Record `salt`; returns false when it was already admitted and is
    /// still tracked — that connection is a replay and must be refused
    /// exactly like any other auth failure.
    pub fn admit(&mut self, salt: &[u8; SALT_LEN]) -> bool {
        if self.index.contains(salt) {
            return false;
        }
        self.index.insert(*salt);
        self.ring.push_back(*salt);
        if self.ring.len() > self.capacity {
            if let Some(old) = self.ring.pop_front() {
                self.index.remove(&old);
            }
        }
        true
    }

    fn len(&self) -> usize {
        self.ring.len()
    }
}

/// Server-side tunnel endpoint: reads the client's salt + target from the
/// first chunk, exposes the target, and turns raw reads into framed writes
/// back (server's own salt sent on construction).
pub struct ServerConn {
    sock: TcpStream,
    write: Direction,
    read: Direction,
    inbuf: Vec<u8>,
    pub target: Target,
}

impl ServerConn {
    /// Wrap an accepted server-side socket. Returns the target address.
    /// `salts` is the shared replay cache — a duplicate salt is refused
    /// with the opaque auth failure (A2-C1) before any crypto work.
    /// `auth_read_deadline` bounds the ENTIRE unauthenticated phase (salt
    /// read + first chunk): a client that completes a valid prefix and
    /// then goes silent cannot hold the per-connection thread forever
    /// (S1 A2-F6 elevation). The deadline is cleared before the
    /// authenticated relay starts, so idle tunnels are unaffected.
    pub fn accept(
        mut sock: TcpStream,
        master: &[u8; 32],
        method: Method,
        salts: &Mutex<SaltCache>,
        auth_read_deadline: Duration,
    ) -> std::io::Result<ServerConn> {
        sock.set_nodelay(true).ok();
        sock.set_read_timeout(Some(auth_read_deadline)).ok();
        // 1. client salt
        let salt_bytes = Framing::read_exact(&mut sock, SALT_LEN)?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);
        // 1b. salt-replay refusal (A2-C1): a captured prefix re-sent gets
        // the SAME opaque auth error as a wrong password — no oracle
        if !salts.lock().unwrap().admit(&salt) {
            return Err(auth_failed());
        }
        let mut read = Direction::new(method, master, &salt);
        // 2. send OUR salt BEFORE decrypting anything — a wrong-password
        //    client would otherwise block forever waiting for a salt that
        //    never comes (deadlock found by the tampered-salt test)
        let out_salt = random_salt()?;
        sock.write_all(&out_salt)?;
        // 3. first chunk: target address (decrypt failures surface here)
        let first = Framing::read_chunk(&mut sock, &mut read)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "ss: no first chunk")
        })?;
        let (target, used) = Target::decode(&first)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // auth completed: clear the unauthenticated-phase deadline so the
        // relay is never disturbed by it (idle tunnels are legitimate)
        sock.set_read_timeout(None).ok();
        let write = Direction::new(method, master, &out_salt);
        let mut s = ServerConn {
            sock,
            write,
            read,
            inbuf: Vec::new(),
            target,
        };
        // keep any payload after the address for the first read
        if used < first.len() {
            s.inbuf.extend_from_slice(&first[used..]);
        }
        Ok(s)
    }

    pub fn into_inner(self) -> TcpStream {
        self.sock
    }
}

impl Read for ServerConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.inbuf.is_empty() {
            let n = buf.len().min(self.inbuf.len());
            buf[..n].copy_from_slice(&self.inbuf[..n]);
            self.inbuf.drain(..n);
            return Ok(n);
        }
        loop {
            match Framing::read_chunk(&mut self.sock, &mut self.read) {
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        continue;
                    }
                    let n = buf.len().min(payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    self.inbuf.extend_from_slice(&payload[n..]);
                    return Ok(n);
                }
                Ok(None) => return Ok(0),
                Err(e) => return Err(e),
            }
        }
    }
}

impl Write for ServerConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0;
        while sent < buf.len() {
            let take = (buf.len() - sent).min(MAX_PAYLOAD);
            Framing::write_chunk(&mut self.sock, &mut self.write, &buf[sent..sent + take])?;
            sent += take;
        }
        Ok(buf.len().max(1))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

// ---------------------------------------------------------------------------
// dialer (holo-proto integration) + server loop
// ---------------------------------------------------------------------------

pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Explicit unauthenticated-phase read deadline (S1 A2-F6 elevation —
/// a DECISION, not an accident): a client that completes a valid prefix
/// (or nothing at all) and then goes silent must not hold the
/// per-connection thread indefinitely. 10 s = 2× the client's own 5 s
/// dial timeout (DIAL_TIMEOUT): generous for lossy links, yet bounds
/// the thread hold. Covers the salt read and the first chunk; cleared
/// the moment authentication completes.
pub const AUTH_READ_DEADLINE: Duration = Duration::from_secs(10);

/// Explicit slow-close ceiling (S1 A3-C10/F8 — a DECISION, not an
/// accident; the previous 120 ms clamp neutered the progressive-slowdown
/// property after ~2 failures). Rationale: a failed-auth thread sleeps
/// at most this long before closing — long enough to make large-scale
/// probing genuinely expensive (5 doublings of 50 ms before the
/// ceiling), short enough that a probe flood ties up a bounded amount
/// of thread time per connection. ProbeGuard's internal curve still
/// computes up to 10 s for other call sites; the SERVER-side applied
/// delay is capped here.
pub const SLOW_CLOSE_MAX: Duration = Duration::from_millis(2_000);

/// Server-side per-connection policy (the named decisions above; tests
/// inject shortened values through the same seam — A3-C10 favors
/// injected seams over global state).
#[derive(Clone, Copy, Debug)]
pub struct ServePolicy {
    pub auth_read_deadline: Duration,
    pub slow_close_max: Duration,
}

impl Default for ServePolicy {
    fn default() -> Self {
        ServePolicy {
            auth_read_deadline: AUTH_READ_DEADLINE,
            slow_close_max: SLOW_CLOSE_MAX,
        }
    }
}

/// Full-jitter slow-close delay: uniform over `[0, min(backoff, ceiling)]`
/// (Brooker-style full jitter — hides the deterministic backoff ladder
/// that fingerprinted the implementation, NDSS '20). The entropy draw is
/// PARAMETERIZED (the `os_fill_at` seam pattern): production passes an
/// `os_fill`-backed CSPRNG closure, tests pass a deterministic seeded
/// draw — two peers with identical failure counts provably get different
/// delays without any flaky live-draw comparison (A3-C10). On entropy
/// failure the caller falls back to the capped deterministic backoff
/// (fail-closed entropy must never panic the close path; the worst case
/// degrades to the pre-S1 deterministic behavior).
pub(crate) fn slow_close_delay(
    backoff: Duration,
    ceiling: Duration,
    draw: &mut dyn FnMut(&mut [u8]) -> std::io::Result<()>,
) -> std::io::Result<Duration> {
    let cap_ms = backoff.min(ceiling).as_millis() as u64;
    let mut b = [0u8; 8];
    draw(&mut b)?;
    let r = u64::from_be_bytes(b) % (cap_ms + 1);
    Ok(Duration::from_millis(r))
}

/// Produces tunnel connections toward arbitrary targets through one
/// Shadowsocks server.
pub struct SsDialer {
    pub server: String,
    master: [u8; 32],
    method: Method,
}

impl SsDialer {
    pub fn new(server: &str, password: &str, method: Method) -> SsDialer {
        SsDialer {
            server: server.to_string(),
            master: master_key(password),
            method,
        }
    }
}

impl holo_proto::Dialer for SsDialer {
    fn dial(
        &self,
        net: holo_proto::Network,
        addr: &str,
    ) -> std::io::Result<Box<dyn holo_proto::TunnelConn>> {
        if net == holo_proto::Network::Udp {
            // honest: UDP ASSOCIATE is a v0.4 milestone
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "ss: UDP relay is a milestone (docs/RESTORE.md v0.4)",
            ));
        }
        let target = Target::parse(addr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut c = ClientConn::connect(
            &self.server,
            &self.master,
            self.method,
            target,
            DIAL_TIMEOUT,
        )?;
        c.set_read_master(&self.master, self.method);
        Ok(Box::new(c))
    }
}

fn resolve(server: &str) -> std::io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    server
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "ss: unresolvable server"))
}

/// Server-side relay loop for one accepted client socket.
///
/// `upstream_dial` dials the real target; bytes are then pumped in both
/// directions with pooled buffers. Auth failures get a CSPRNG-jittered
/// slow-close (full jitter over `[0, min(backoff, slow_close_max)]`;
/// deterministic pre-S1 — the determinism was itself a fingerprint,
/// NDSS '20) and never reach the dialer. The ProbeGuard lock is HELD
/// only for the bookkeeping, never across the sleep — the sleep
/// serializes nothing. Replayed salts (A2-C1) are refused through the
/// same opaque path via the shared `salts` cache. The unauthenticated
/// read phase is bounded by `policy.auth_read_deadline` (A2-F6).
pub fn serve_conn<F>(
    sock: TcpStream,
    master: &[u8; 32],
    method: Method,
    guard: &Mutex<holo_net::ProbeGuard>,
    salts: &Mutex<SaltCache>,
    policy: ServePolicy,
    upstream_dial: F,
) -> std::io::Result<u64>
where
    F: FnOnce(&Target) -> std::io::Result<TcpStream>,
{
    let peer = sock
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
    let sc = match ServerConn::accept(
        sock,
        master,
        method,
        salts,
        policy.auth_read_deadline,
    ) {
        Ok(sc) => sc,
        Err(e) => {
            // auth/probe failure: record + slow close, no details out.
            // The guard lock covers ONLY the bookkeeping — it must never
            // be held across the sleep (holding it would serialize every
            // concurrent connection behind one probe's delay).
            let backoff = {
                let mut g = guard.lock().unwrap();
                g.on_failure(peer)
            };
            let delay = slow_close_delay(
                backoff,
                policy.slow_close_max,
                &mut |b| holo_util::rand::os_fill(b),
            )
            .unwrap_or(backoff.min(policy.slow_close_max)); // entropy fallback
            std::thread::sleep(delay);
            return Err(e);
        }
    };
    guard.lock().unwrap().on_success(peer);
    let target = sc.target.clone();
    let upstream = upstream_dial(&target)?;
    let pool = holo_net::BufferPool::new(16 * 1024, 16);
    let pool2 = pool.clone();
    // split the tunnel: read half decrypts client→server frames, write
    // half owns the server→client nonce sequence
    let (down_read_half, down_write_half) = split_server(sc)?;
    let up2 = upstream.try_clone()?;
    let a = std::thread::spawn(move || {
        let mut up = upstream;
        let mut dw = down_write_half;
        let mut total = 0u64;
        let mut buf = pool.get();
        loop {
            match up.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total += n as u64;
                    if dw.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Read);
        let _ = dw.flush();
        total
    });
    let b = std::thread::spawn(move || {
        let mut dr = down_read_half;
        let mut up = up2;
        let mut total = 0u64;
        let mut buf = pool2.get();
        loop {
            match dr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total += n as u64;
                    if up.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Write);
        total
    });
    let t1 = a.join().unwrap_or(0);
    let t2 = b.join().unwrap_or(0);
    Ok(t1 + t2)
}

/// Split a ServerConn into (read half, write half) over the same socket:
/// the read half keeps the framed decrypt state (client→server direction);
/// the write half owns THE server→client write Direction (one nonce
/// sequence per direction, as SIP004 requires).
fn split_server(sc: ServerConn) -> std::io::Result<(ServerReadHalf, ServerWriteHalf)> {
    // Clone the socket for the read half; keep the original for the write
    // half (which owns the write Direction).
    let sock_r = sc.sock.try_clone()?;
    let read = ServerReadHalf {
        sock: sock_r,
        read: sc.read,
        inbuf: sc.inbuf,
    };
    let write = ServerWriteHalf {
        sock: sc.sock,
        write: sc.write,
    };
    Ok((read, write))
}

pub struct ServerReadHalf {
    sock: TcpStream,
    read: Direction,
    inbuf: Vec<u8>,
}

impl Read for ServerReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.inbuf.is_empty() {
            let n = buf.len().min(self.inbuf.len());
            buf[..n].copy_from_slice(&self.inbuf[..n]);
            self.inbuf.drain(..n);
            return Ok(n);
        }
        loop {
            match Framing::read_chunk(&mut self.sock, &mut self.read) {
                Ok(Some(payload)) => {
                    if payload.is_empty() {
                        continue;
                    }
                    let n = buf.len().min(payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    self.inbuf.extend_from_slice(&payload[n..]);
                    return Ok(n);
                }
                Ok(None) => return Ok(0),
                Err(e) => return Err(e),
            }
        }
    }
}

pub struct ServerWriteHalf {
    sock: TcpStream,
    write: Direction,
}

impl ServerWriteHalf {
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

impl Write for ServerWriteHalf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0;
        while sent < buf.len() {
            let take = (buf.len() - sent).min(MAX_PAYLOAD);
            Framing::write_chunk(&mut self.sock, &mut self.write, &buf[sent..sent + take])?;
            sent += take;
        }
        Ok(buf.len().max(1))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Session salt — security material, so it comes from fail-closed OS
/// entropy (never the splitmix fallback).
pub(crate) fn random_salt() -> std::io::Result<[u8; 32]> {
    let mut s = [0u8; 32];
    holo_util::rand::os_fill(&mut s).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "ss: os entropy unavailable — refusing weak randomness (fail-closed)",
        )
    })?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use holo_proto::Dialer as _;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn all_methods() -> Vec<Method> {
        vec![
            Method::ChaCha20IetfPoly1305,
            Method::XChaCha20IetfPoly1305,
            Method::Aes256Gcm,
        ]
    }

    /// In-process SS server: accepts one connection, prints the target,
    /// then relays raw to the given upstream port.
    fn spawn_ss_server(
        method: Method,
        password: &'static str,
        upstream: u16,
    ) -> (u16, std::sync::Arc<Mutex<Vec<String>>>) {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        let targets = std::sync::Arc::new(Mutex::new(Vec::new()));
        let t2 = targets.clone();
        let guard = Mutex::new(holo_net::ProbeGuard::new());
        let guard = std::sync::Arc::new(guard);
        let salts =
            std::sync::Arc::new(Mutex::new(SaltCache::new(SALT_CACHE_CAPACITY)));
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let Ok(sock) = sock else { continue };
                let master = master_key(password);
                let t2 = t2.clone();
                let guard = guard.clone();
                let salts = salts.clone();
                std::thread::spawn(move || {
                    let _ = serve_conn(
                        sock,
                        &master,
                        method,
                        &guard,
                        &salts,
                        ServePolicy::default(),
                        |target| {
                            t2.lock().unwrap().push(target.to_string());
                            TcpStream::connect(("127.0.0.1", upstream))
                        },
                    );
                });
            }
        });
        (port, targets)
    }

    fn spawn_echo() -> u16 {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let Ok(mut sock) = sock else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf) {
                        if n == 0 || sock.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn address_encoding_roundtrip() {
        for m in all_methods() {
            let _ = m;
            for a in ["example.com:443", "1.2.3.4:8080", "[2001:db8::1]:9443"] {
                let t = Target::parse(a).unwrap();
                assert_eq!(t.to_string(), a, "roundtrip {a}");
                let enc = t.encode();
                let (t2, used) = Target::decode(&enc).unwrap();
                assert_eq!(used, enc.len());
                assert_eq!(t2, t);
            }
            assert!(Target::parse("no-port").is_err());
            assert!(Target::parse("host:99999").is_err());
            assert!(Target::parse("").is_err());
        }
    }

    #[test]
    fn kdf_deterministic_and_salt_bound() {
        let salt = [7u8; 32];
        let a = subkey_for_test("pw", &salt);
        let b = subkey_for_test("pw", &salt);
        assert_eq!(a, b);
        assert_ne!(a, subkey_for_test("pw2", &salt));
        assert_ne!(a, subkey_for_test("pw", &[8u8; 32]));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn full_tunnel_roundtrip_all_ciphers() {
        for method in all_methods() {
            let echo_port = spawn_echo();
            let (ss_port, targets) = spawn_ss_server(method, "hunter2", echo_port);
            let dialer = SsDialer::new(&format!("127.0.0.1:{ss_port}"), "hunter2", method);
            let mut conn = dialer
                .dial(holo_proto::Network::Tcp, &format!("127.0.0.1:{echo_port}"))
                .expect("dial");
            // write a pattern, read it back (echo)
            let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
            conn.write_all(&payload).unwrap();
            conn.flush().unwrap();
            let mut back = Vec::new();
            let mut buf = vec![0u8; 8192];
            while back.len() < payload.len() {
                let n = conn.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                back.extend_from_slice(&buf[..n]);
            }
            assert_eq!(back, payload, "cipher {:?}", method);
            let seen = targets.lock().unwrap();
            assert!(
                seen.iter().any(|t| t.ends_with(&echo_port.to_string())),
                "server saw target, cands: {:?}",
                *seen
            );
        }
    }

    #[test]
    fn tampered_salt_is_rejected_strictly() {
        // server must fail cleanly (auth error, no panic, no upstream dial)
        let echo_port = spawn_echo();
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let ss_port = ln.local_addr().unwrap().port();
        let dialed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d2 = dialed.clone();
        let guard = Mutex::new(holo_net::ProbeGuard::new());
        let guard = std::sync::Arc::new(guard);
        let salts =
            std::sync::Arc::new(Mutex::new(SaltCache::new(SALT_CACHE_CAPACITY)));
        std::thread::spawn(move || {
            if let Ok(sock) = ln.incoming().next().unwrap() {
                let master = master_key("correct-pw");
                let _ = serve_conn(
                    sock,
                    &master,
                    Method::Aes256Gcm,
                    &guard,
                    &salts,
                    ServePolicy::default(),
                    |_t| {
                    d2.store(true, std::sync::atomic::Ordering::SeqCst);
                    TcpStream::connect(("127.0.0.1", echo_port))
                });
            }
        });
        // client with the WRONG password derives a wrong subkey → garbage
        let wrong = SsDialer::new(
            &format!("127.0.0.1:{ss_port}"),
            "wrong-pw",
            Method::Aes256Gcm,
        );
        let mut conn = wrong
            .dial(holo_proto::Network::Tcp, &format!("127.0.0.1:{echo_port}"))
            .unwrap();
        // write "succeeds" on the client (it cannot know yet) — but on
        // some OSes the server's earlier close surfaces as ECONNRESET, so
        // tolerate write errors here; upstream must NOT be dialed either way
        let _ = conn.write_all(b"hello");
        let _ = conn.flush();
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            !dialed.load(std::sync::atomic::Ordering::SeqCst),
            "wrong-password client must never reach upstream"
        );
    }

    #[test]
    fn oversized_length_is_rejected_without_upstream() {
        // Forged but VALIDLY-encrypted length > MAX_PAYLOAD (the classic
        // prober trick) must be treated as an auth failure with NO upstream
        // dial — the same strict-fail guarantee as a wrong password.
        // (Added at gate 0001 per review A1-C4: the rejection path existed
        // at read_chunk but had no direct test.)
        let echo_port = spawn_echo();
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let ss_port = ln.local_addr().unwrap().port();
        let dialed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d2 = dialed.clone();
        let guard = Mutex::new(holo_net::ProbeGuard::new());
        let guard = std::sync::Arc::new(guard);
        let salts =
            std::sync::Arc::new(Mutex::new(SaltCache::new(SALT_CACHE_CAPACITY)));
        std::thread::spawn(move || {
            if let Ok(sock) = ln.incoming().next().unwrap() {
                let master = master_key("correct-pw");
                let _ = serve_conn(
                    sock,
                    &master,
                    Method::ChaCha20IetfPoly1305,
                    &guard,
                    &salts,
                    ServePolicy::default(),
                    |_t| {
                        d2.store(true, std::sync::atomic::Ordering::SeqCst);
                        TcpStream::connect(("127.0.0.1", echo_port))
                    },
                );
            }
        });
        // Act as a client with the CORRECT password but forge the first
        // length frame to claim MAX_PAYLOAD + 1.
        let master = master_key("correct-pw");
        let salt = random_salt().unwrap();
        let mut d = Direction::new(Method::ChaCha20IetfPoly1305, &master, &salt);
        let mut c = TcpStream::connect(("127.0.0.1", ss_port)).unwrap();
        c.write_all(&salt).unwrap();
        let forged = d.seal(&[], &((MAX_PAYLOAD + 1) as u16).to_be_bytes());
        c.write_all(&forged).unwrap();
        let _ = c.flush();
        // serve_conn applies backoff before closing; wait past that window
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !dialed.load(std::sync::atomic::Ordering::SeqCst),
            "oversized length must never reach upstream"
        );
    }

    #[test]
    fn udp_dial_is_honest_milestone() {
        let d = SsDialer::new("127.0.0.1:1", "pw", Method::ChaCha20IetfPoly1305);
        let err = d
            .dial(holo_proto::Network::Udp, "example.com:53")
            .err()
            .unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("milestone"));
    }

    #[test]
    fn method_parse_surface() {
        for (s, m) in [
            ("chacha20-ietf-poly1305", Method::ChaCha20IetfPoly1305),
            ("AES-256-GCM", Method::Aes256Gcm),
            ("xchacha20-ietf-poly1305", Method::XChaCha20IetfPoly1305),
        ] {
            assert_eq!(Method::parse(s), Some(m));
        }
        assert_eq!(Method::parse("rc4"), None);
        assert_eq!(Method::parse(""), None);
    }

    #[test]
    fn xchacha_wire_is_standard_aead_24byte_le_counter() {
        // Binding condition 8 (record-0003 A3-C3), the interop lock: the
        // xchacha20-ietf-poly1305 wire IS XChaCha20-Poly1305-IETF — chunk
        // k's ciphertext must equal the standard AEAD (draft-vector-proven
        // in holo-crypto) evaluated at the 24-byte LE nonce = k, byte for
        // byte. This is exactly what mainstream shadowsocks peers do.
        let master = master_key("pw-xchacha-interop");
        let salt = [7u8; 32];
        let mut subkey = [0u8; 32];
        subkey.copy_from_slice(&hkdf_sha1(&salt, &master, b"ss-subkey", 32));
        let mut d = Direction::new(Method::XChaCha20IetfPoly1305, &master, &salt);
        // SIP004 directions are one-way: seal and open live on separate
        // Directions with independent counters, exactly like the tunnel.
        let mut d_rd = Direction::new(Method::XChaCha20IetfPoly1305, &master, &salt);
        let aad: &[u8] = b"";
        let chunks: [&[u8]; 3] = [b"first", b"second chunk", &[9u8; 64]];
        for (k, pt) in chunks.iter().enumerate() {
            let mut n24 = [0u8; 24];
            n24[0] = k as u8; // LE counter = k
            let expect = holo_crypto::aead_xchacha20poly1305_encrypt(&subkey, &n24, aad, pt);
            let got = d.seal(aad, pt);
            assert_eq!(got, expect, "chunk {} must match the standard AEAD", k);
            let back = d_rd.open(aad, &got).unwrap();
            assert_eq!(back.as_slice(), *pt, "chunk {} roundtrip", k);
        }
        // and a tampered chunk fails closed (fresh direction ⇒ nonce 0 =
        // the chunk's own nonce, so the failure is the tag, not the counter)
        let mut d2 = Direction::new(Method::XChaCha20IetfPoly1305, &master, &salt);
        let mut bad = d2.seal(b"", b"t");
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut d3 = Direction::new(Method::XChaCha20IetfPoly1305, &master, &salt);
        assert!(d3.open(b"", &bad).is_err());
    }

    #[test]
    fn xchacha_wire_differs_from_the_retired_zeroiv_construction() {
        // The OLD (pre-run-8) mislabeled wire: HChaCha20(subkey, 0^16) as a
        // fixed re-key, then plain ChaCha20-Poly1305 with a 12-byte counter.
        // The two constructions COINCIDE at chunk 0 (both nonces all-zero —
        // first-session-chunk bytes are unchanged); they diverge from the
        // second AEAD operation, where the 12-byte counter puts the 1 in
        // nonce byte 0 while the 24-byte counter puts it in byte 16 of the
        // XChaCha nonce. Asserting divergence at chunk 1 locks the fix in
        // place — a regression back to the old path would re-produce these
        // bytes and fail this test.
        let master = master_key("pw-xchacha-interop");
        let salt = [7u8; 32];
        let mut subkey = [0u8; 32];
        subkey.copy_from_slice(&hkdf_sha1(&salt, &master, b"ss-subkey", 32));
        let mut d = Direction::new(Method::XChaCha20IetfPoly1305, &master, &salt);
        let _chunk0 = d.seal(b"", b"first");
        let new_wire = d.seal(b"", b"second"); // nonce = LE(1) over 24 bytes
        let retired = holo_crypto::aead_chacha20poly1305_encrypt(
            &holo_crypto::hchacha20(&subkey, &[0u8; 16]),
            &[1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // 12-byte counter = 1
            b"",
            b"second",
        );
        assert_ne!(
            new_wire,
            retired,
            "wire must be the standard XChaCha, not the retired zero-IV re-key"
        );
    }

    #[test]
    fn salt_cache_admit_and_evict_semantics() {
        let mut c = SaltCache::new(2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        let d = [3u8; 32];
        assert!(c.admit(&a), "first admit");
        assert!(!c.admit(&a), "tracked salt is refused");
        assert!(c.admit(&b));
        assert_eq!(c.len(), 2);
        assert!(c.admit(&d), "evicts the oldest, admits the new");
        assert_eq!(c.len(), 2, "ring stays capacity-bounded");
        // a was aged out by d's insertion — it re-admits (documented bound)
        assert!(c.admit(&a), "aged-out salt re-admits (bounded FIFO)");
        assert!(!c.admit(&a));
        // zero capacity degrades to NO protection (immediate eviction):
        // honest — a 0-capacity cache simply never refuses
        let mut z = SaltCache::new(0);
        assert!(z.admit(&a), "cap=0 admits the first sight");
        assert!(z.admit(&a), "cap=0 tracks nothing — no protection");
    }

    /// A2-C1 named acceptance test (ROADMAP S1 server-path hardening):
    /// a byte-identical replay of a captured prefix (salt + first chunk)
    /// is refused with the SAME opaque auth error as a wrong password,
    /// never reaches the upstream dialer, while the original connection
    /// tunnels successfully end to end.
    #[test]
    fn salt_cache_rejects_replayed_prefix() {
        let echo_port = spawn_echo();
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let ss_port = ln.local_addr().unwrap().port();
        let dialed = std::sync::Arc::new(std::sync::atomic::AtomicIsize::new(0));
        let d2 = dialed.clone();
        let guard = Mutex::new(holo_net::ProbeGuard::new());
        let guard = std::sync::Arc::new(guard);
        let salts =
            std::sync::Arc::new(Mutex::new(SaltCache::new(SALT_CACHE_CAPACITY)));
        let results: std::sync::Arc<Mutex<Vec<Result<u64, std::io::Error>>>> =
            std::sync::Arc::new(Mutex::new(Vec::new()));
        let r2 = results.clone();
        std::thread::spawn(move || {
            for sock in ln.incoming().flatten() {
                let master = master_key("pw");
                let res = serve_conn(
                    sock,
                    &master,
                    Method::ChaCha20IetfPoly1305,
                    &guard,
                    &salts,
                    ServePolicy::default(),
                    |_target| {
                        d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        TcpStream::connect(("127.0.0.1", echo_port))
                    },
                );
                let done = {
                    let mut g = r2.lock().unwrap();
                    g.push(res);
                    g.len() == 2
                };
                if done {
                    break;
                }
            }
        });
        // craft a valid prefix ONCE: salt || encrypted target chunk
        let master = master_key("pw");
        let salt = [0xA5u8; 32];
        let target = Target::parse(&format!("127.0.0.1:{echo_port}")).unwrap();
        let mut d = Direction::new(Method::ChaCha20IetfPoly1305, &master, &salt);
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&salt);
        Framing::write_chunk(&mut prefix, &mut d, &target.encode()).unwrap();

        // connection 1: the original — full tunnel, echo a payload back
        let mut c1 = TcpStream::connect(("127.0.0.1", ss_port)).unwrap();
        c1.write_all(&prefix).unwrap();
        Framing::write_chunk(&mut c1, &mut d, b"replay-test").unwrap();
        c1.flush().unwrap();
        // read the server's random out-salt, then the echoed chunk under
        // the subkey it derives (exactly what ClientConn does internally)
        let out_salt = Framing::read_exact(&mut c1, SALT_LEN).unwrap();
        let mut os = [0u8; 32];
        os.copy_from_slice(&out_salt);
        let mut rd = Direction::new(Method::ChaCha20IetfPoly1305, &master, &os);
        match Framing::read_chunk(&mut c1, &mut rd).unwrap() {
            Some(pt) => assert_eq!(pt, b"replay-test".to_vec(), "echo body"),
            None => panic!("no echoed chunk on the original connection"),
        }
        drop(c1); // clean EOF for both relay halves

        // wait for serve_conn #1 to finish before replaying (sequential is
        // the point: the replayed salt must be already admitted)
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while results.lock().unwrap().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "original connection never completed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        // connection 2: byte-identical prefix = the captured replay
        let mut c2 = TcpStream::connect(("127.0.0.1", ss_port)).unwrap();
        c2.write_all(&prefix).unwrap();
        c2.flush().unwrap();
        drop(c2);

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while results.lock().unwrap().len() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "replayed connection never handled"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let r = results.lock().unwrap();
        assert!(
            r[0].is_ok(),
            "original connection must succeed: {:?}",
            r[0]
        );
        let err = r[1].as_ref().err().expect("replay must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "ss: auth failed",
            "replay refusal is opaque (same value as wrong password)"
        );
        assert_eq!(
            dialed.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the replay must never reach upstream"
        );
    }

    // ------------------------------------------------------------------
    // S1 server-path hardening: slow-close jitter + read deadline
    // ------------------------------------------------------------------

    /// Deterministic seeded draw for the `slow_close_delay` seam (A3-C10
    /// injected-seam pattern — no flaky live-draw comparisons).
    fn seeded_draw(seed: u64) -> impl FnMut(&mut [u8]) -> std::io::Result<()> {
        let mut state = seed;
        move |b: &mut [u8]| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = (state >> ((i % 8) * 8)) as u8;
            }
            Ok(())
        }
    }

    /// S1 named acceptance test (A3-C10): the slow-close jitter is
    /// deterministic under a seeded entropy seam — two peers with
    /// identical failure counts get DIFFERENT delays, the same seed
    /// reproduces the same delay, the ceiling decision is enforced
    /// (backoff above the ceiling never exceeds it), zero backoff stays
    /// zero, and an entropy failure surfaces as Err (serve_conn then
    /// falls back to the capped deterministic backoff — never a panic).
    #[test]
    fn slow_close_jitter_seeded_deterministic() {
        let backoff = Duration::from_millis(400);
        let ceiling = Duration::from_millis(2000);
        // same seed → same delay (reproducibility of the seam)
        let a1 = slow_close_delay(backoff, ceiling, &mut seeded_draw(7)).unwrap();
        let a2 = slow_close_delay(backoff, ceiling, &mut seeded_draw(7)).unwrap();
        assert_eq!(a1, a2, "same seed must reproduce the same delay");
        // two peers, identical failure counts (same backoff), different
        // seeded entropy → different delays — WITHOUT comparing two live
        // CSPRNG draws (that comparison is the flake A3-C10 forbids)
        let a = slow_close_delay(backoff, ceiling, &mut seeded_draw(1)).unwrap();
        let b = slow_close_delay(backoff, ceiling, &mut seeded_draw(2)).unwrap();
        assert_ne!(a, b, "distinct seeds must yield distinct delays");
        // ceiling decision enforced: backoff above the ceiling caps it
        for i in 0..64u64 {
            let d = slow_close_delay(
                Duration::from_millis(10_000),
                ceiling,
                &mut seeded_draw(0xDEAD_BEEFu64.wrapping_add(i)),
            )
            .unwrap();
            assert!(d <= ceiling, "jittered delay {d:?} exceeds the ceiling");
        }
        // zero backoff cannot produce a negative/instant-sleep regression
        assert_eq!(
            slow_close_delay(Duration::ZERO, ceiling, &mut seeded_draw(3)).unwrap(),
            Duration::ZERO
        );
        // entropy failure surfaces as Err (caller falls back; no panic)
        assert!(slow_close_delay(backoff, ceiling, &mut |_| Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "entropy unavailable"
        )))
        .is_err());
    }

    /// S1 named acceptance test (A2-F6 elevation): a client that
    /// completes a VALID crypto prefix (salt + correctly-encrypted length
    /// header) and then goes silent — or sends nothing at all — must NOT
    /// hold the per-connection thread forever. With a shortened injected
    /// `auth_read_deadline` both connections terminate with an error and
    /// the upstream is never dialed; pre-fix, scenario (a) blocked the
    /// thread in `read_exact` with NO socket timeout (the recorded
    /// distinguisher / resource-exhaustion vector).
    #[test]
    fn silent_after_valid_length_times_out() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let ss_port = ln.local_addr().unwrap().port();
        let dialed = std::sync::Arc::new(std::sync::atomic::AtomicIsize::new(0));
        let d2 = dialed.clone();
        let guard = Mutex::new(holo_net::ProbeGuard::new());
        let guard = std::sync::Arc::new(guard);
        let salts =
            std::sync::Arc::new(Mutex::new(SaltCache::new(SALT_CACHE_CAPACITY)));
        let (tx, rx) = std::sync::mpsc::channel();
        let policy = ServePolicy {
            auth_read_deadline: Duration::from_millis(300),
            slow_close_max: Duration::from_millis(100),
        };
        std::thread::spawn(move || {
            for sock in ln.incoming().flatten().take(2) {
                let master = master_key("pw");
                let tx = tx.clone();
                let guard = guard.clone();
                let salts = salts.clone();
                let d2 = d2.clone();
                std::thread::spawn(move || {
                    let res = serve_conn(sock, &master, Method::ChaCha20IetfPoly1305,
                        &guard, &salts, policy, |_t| {
                            d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            TcpStream::connect(("127.0.0.1", 9))
                        });
                    let _ = tx.send(res);
                });
            }
        });
        // (a) valid crypto prefix, then silence: salt + correctly
        //     encrypted length header for a 32-byte payload, nothing more
        let master = master_key("pw");
        let salt = random_salt().unwrap();
        let mut d = Direction::new(Method::ChaCha20IetfPoly1305, &master, &salt);
        let mut c_a = TcpStream::connect(("127.0.0.1", ss_port)).unwrap();
        c_a.write_all(&salt).unwrap();
        let len_hdr = d.seal(&[], &32u16.to_be_bytes());
        c_a.write_all(&len_hdr).unwrap();
        let _ = c_a.flush();
        // (b) nothing at all after connecting (bare salt-less hang)
        let mut c_b = TcpStream::connect(("127.0.0.1", ss_port)).unwrap();
        let _ = c_b.flush();
        // both must terminate within deadline + slow-close (<< 5 s);
        // recv_timeout expiring = the hang regression this test guards
        for i in 0..2 {
            let res = rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("connection {i} hung past the read deadline"));
            let e = res.err().expect("silent client must fail, not relay");
            // deadline error kind is platform-dependent (WouldBlock on
            // Linux/macOS SO_RCVTIMEO, TimedOut on Windows); the
            // attacker-observable behavior (delayed close, no relay) is
            // what must be uniform — asserted via no-dial below
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "connection {i}: unexpected error {e:?}"
            );
        }
        // keep the sockets open until both deadlines fired, then clean up
        drop(c_a);
        drop(c_b);
        assert_eq!(
            dialed.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "silent clients must never reach upstream"
        );
    }
}
