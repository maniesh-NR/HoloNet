//! holo-ss — Shadowsocks AEAD (SIP004) data plane, the first live protocol
//! in the HoloNet engine.
//!
//! Wire format (TCP, both directions independent):
//! `[32-byte salt]` then chunks: `[len(2 BE) | tag16][payload | tag16]`
//! - session subkey = HKDF-SHA1(master_key, salt, "ss-subkey", 32)
//! - master key = EVP_BytesToKey(MD5, password, 32)
//! - nonce = 12-byte LE counter starting at zero, incremented after every
//!   AEAD operation (separate counters per direction)
//! - first chunk payload = SOCKS5 target address (+ optional user payload)
//!
//! Anti-probing: any AEAD tag failure closes the connection after a
//! randomized slow-close (holo_net::ProbeGuard), never leaking whether the
//! failure was salt, length, or payload.
//!
//! Supported ciphers: chacha20-ietf-poly1305, xchacha20-ietf-poly1305,
//! aes-256-gcm — all 32-byte keys, 16-byte tags.
#![forbid(unsafe_code)]

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
    nonce: [u8; 12],
}

impl Direction {
    fn new(method: Method, master: &[u8; 32], salt: &[u8; 32]) -> Direction {
        let sub = hkdf_sha1(salt, master, b"ss-subkey", 32);
        let mut subkey = [0u8; 32];
        subkey.copy_from_slice(&sub);
        Direction {
            method,
            subkey,
            nonce: [0u8; 12], // SIP004: nonce starts at zero, LE +1 per op
        }
    }

    fn increment(&mut self) {
        // little-endian increment over all 12 bytes
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let out = match self.method {
            Method::ChaCha20IetfPoly1305 => {
                holo_crypto::aead_chacha20poly1305_encrypt(&self.subkey, &self.nonce, aad, pt)
            }
            Method::XChaCha20IetfPoly1305 => {
                let mut n24 = [0u8; 24];
                n24[12..].copy_from_slice(&self.nonce);
                let zero_iv = [0u8; 16];
                let sub = holo_crypto::hchacha20(&self.subkey, &zero_iv);
                holo_crypto::aead_chacha20poly1305_encrypt(&sub, &self.nonce, aad, pt)
            }
            Method::Aes256Gcm => holo_crypto::gcm::encrypt(&self.subkey, &self.nonce, aad, pt),
        };
        self.increment();
        out
    }

    fn open(&mut self, aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
        let out = match self.method {
            Method::ChaCha20IetfPoly1305 => {
                holo_crypto::aead_chacha20poly1305_decrypt(&self.subkey, &self.nonce, aad, ct_tag)
            }
            Method::XChaCha20IetfPoly1305 => {
                let zero_iv = [0u8; 16];
                let sub = holo_crypto::hchacha20(&self.subkey, &zero_iv);
                holo_crypto::aead_chacha20poly1305_decrypt(&sub, &self.nonce, aad, ct_tag)
            }
            Method::Aes256Gcm => holo_crypto::gcm::decrypt(&self.subkey, &self.nonce, aad, ct_tag),
        };
        self.increment();
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
        let salt = random_salt();
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
    pub fn accept(
        mut sock: TcpStream,
        master: &[u8; 32],
        method: Method,
    ) -> std::io::Result<ServerConn> {
        sock.set_nodelay(true).ok();
        // 1. client salt
        let salt_bytes = Framing::read_exact(&mut sock, SALT_LEN)?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);
        let mut read = Direction::new(method, master, &salt);
        // 2. send OUR salt BEFORE decrypting anything — a wrong-password
        //    client would otherwise block forever waiting for a salt that
        //    never comes (deadlock found by the tampered-salt test)
        let out_salt = random_salt();
        sock.write_all(&out_salt)?;
        // 3. first chunk: target address (decrypt failures surface here)
        let first = Framing::read_chunk(&mut sock, &mut read)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "ss: no first chunk")
        })?;
        let (target, used) = Target::decode(&first)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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
/// directions with pooled buffers. Auth failures get a randomized
/// slow-close (anti-probing) and never reach the dialer.
pub fn serve_conn<F>(
    sock: TcpStream,
    master: &[u8; 32],
    method: Method,
    guard: &Mutex<holo_net::ProbeGuard>,
    upstream_dial: F,
) -> std::io::Result<u64>
where
    F: FnOnce(&Target) -> std::io::Result<TcpStream>,
{
    let peer = sock
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
    let sc = match ServerConn::accept(sock, master, method) {
        Ok(sc) => sc,
        Err(e) => {
            // auth/probe failure: slow close (randomized), no details out
            let mut g = guard.lock().unwrap();
            let delay = g.on_failure(peer);
            std::thread::sleep(delay.min(Duration::from_millis(120)));
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

pub(crate) fn random_salt() -> [u8; 32] {
    let mut s = [0u8; 32];
    holo_util::rand::fill(&mut s);
    s
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
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let Ok(sock) = sock else { continue };
                let master = master_key(password);
                let t2 = t2.clone();
                let guard = guard.clone();
                std::thread::spawn(move || {
                    let _ = serve_conn(sock, &master, method, &guard, |target| {
                        t2.lock().unwrap().push(target.to_string());
                        TcpStream::connect(("127.0.0.1", upstream))
                    });
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
        std::thread::spawn(move || {
            if let Ok(sock) = ln.incoming().next().unwrap() {
                let master = master_key("correct-pw");
                let _ = serve_conn(sock, &master, Method::Aes256Gcm, &guard, |_t| {
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
        // write succeeds (client doesn't know), but the server can't read
        // the target — upstream must NOT be dialed
        conn.write_all(b"hello").unwrap();
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            !dialed.load(std::sync::atomic::Ordering::SeqCst),
            "wrong-password client must never reach upstream"
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
}
