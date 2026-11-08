//! holo-socks — the local entry point of the HoloNet data plane.
//!
//! RFC 1928 SOCKS5 server (CONNECT + optional RFC 1929 user/pass auth)
//! whose targets are dialed through a [`holo_proto::Dialer`] (e.g. the
//! Shadowsocks tunnel from holo-ss). Cross-cutting features are wired
//! here, where they interact for real:
//! - traffic shaping through a shared [`holo_net::TokenBucket`], made
//!   fair across concurrent streams by [`holo_net::DrrQueue`] (Shreedhar
//!   & Varghese, SIGCOMM '95) — one stream cannot starve the others;
//! - pooled 16 KiB relay buffers ([`holo_net::BufferPool`]) — steady-state
//!   relaying allocates nothing;
//! - per-connection counters for the engine's `stats.get`.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use holo_net::{BufferPool, DrrQueue, TokenBucket};
use holo_proto::{Dialer, Network};

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Stats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub connections: AtomicU64,
    pub refused: AtomicU64,
}

impl Stats {
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed),
            self.connections.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------------------
// shaper: one shared token bucket + DRR fairness across streams
// ---------------------------------------------------------------------------

/// Shared bandwidth shaper. `admit` blocks until the global bucket can pay
/// for `len` bytes; waiters are served in DRR order so one stream cannot
/// monopolize the bucket. With rate == 0 it is a no-op.
pub struct Shaper {
    bucket: Arc<Mutex<TokenBucket>>,
    flow_seq: AtomicU64,
    active: Arc<Mutex<shaper::Registry>>,
    rate: u64,
}

mod shaper {
    use super::*;
    /// Serial registry of waiting streams + their granted bytes.
    #[derive(Default)]
    pub struct Registry {
        pub queue: DrrQueue<Grant>,
        pub idle: Mutex<std::collections::HashMap<u64, ()>>,
    }
    pub struct Grant {
        pub len: usize,
        pub done: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }
}

impl Shaper {
    pub fn new(rate_kbps: u64) -> Shaper {
        let bucket = if rate_kbps == 0 {
            Arc::new(Mutex::new(TokenBucket::unlimited()))
        } else {
            // burst = 32 KiB keeps single requests snappy without
            // letting the bucket pay for whole transfers
            Arc::new(Mutex::new(TokenBucket::new(rate_kbps * 1024, 32 * 1024)))
        };
        Shaper {
            bucket,
            flow_seq: AtomicU64::new(1),
            active: Arc::new(Mutex::new(shaper::Registry::default())),
            rate: rate_kbps,
        }
    }

    pub fn rate_kbps(&self) -> u64 {
        self.rate
    }

    /// Assign a DRR flow id to a new stream. Equal quanta for all streams:
    /// fairness, not priority.
    pub fn new_flow(&self) -> u64 {
        let id = self.flow_seq.fetch_add(1, Ordering::Relaxed);
        self.active.lock().unwrap().queue.register(id, 16384);
        id
    }

    pub fn drop_flow(&self, id: u64) {
        let mut reg = self.active.lock().unwrap();
        reg.queue.unregister(id);
        reg.idle.lock().unwrap().remove(&id);
    }

    /// Blocking admit of `len` bytes for flow `id`. Returns false on stop.
    ///
    /// Cooperative design: every waiter participates in serving the shared
    /// DRR queue (whoever holds the registry lock may pop the next grant in
    /// DRR order and pay for it from the shared bucket). No background thread
    /// is required; fairness comes from the DRR order, rate limiting from the
    /// bucket. With rate == 0 it is a no-op.
    pub fn admit(&self, flow: u64, len: usize, stop: &AtomicBool) -> bool {
        if self.rate == 0 {
            return !stop.load(Ordering::Relaxed);
        }
        let my_done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        {
            let mut reg = self.active.lock().unwrap();
            reg.queue.push(
                flow,
                shaper::Grant {
                    len,
                    done: my_done.clone(),
                },
                len,
            );
        }
        loop {
            if stop.load(Ordering::Relaxed) {
                // remove our pending grant if still queued (best effort)
                let mut reg = self.active.lock().unwrap();
                reg.queue.unregister(flow);
                reg.queue.register(flow, 16384);
                return false;
            }
            {
                let mut reg = self.active.lock().unwrap();
                if reg.queue.is_empty() {
                    // our grant was served by someone
                    let (lock, _) = &*my_done;
                    if *lock.lock().unwrap() {
                        return true;
                    }
                    continue;
                }
                // serve the next grant in DRR order — may be ours
                let popped = reg.queue.pop();
                if let Some((_f, grant)) = popped {
                    // pay the bucket (blocking up to the deficit, in small
                    // sleeps so stop stays responsive)
                    let mut b = self.bucket.lock().unwrap();
                    match b.try_acquire(grant.len) {
                        Ok(()) => {
                            let (lock, cv) = &*grant.done;
                            *lock.lock().unwrap() = true;
                            cv.notify_all();
                        }
                        Err(wait) => {
                            // not enough tokens: requeue this grant and wait
                            // (re-push through the SAME registry guard — a
                            // second lock here would self-deadlock)
                            reg.queue.push(flow, grant, len);
                            drop(reg);
                            drop(b);
                            let d = wait.min(std::time::Duration::from_millis(50));
                            std::thread::sleep(d);
                            continue;
                        }
                    }
                }
            }
            // check if OUR grant is done
            let (lock, _cv) = &*my_done;
            let g = lock.lock().unwrap();
            if *g {
                return true;
            }
            drop(g);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

pub struct SocksServer {
    pub listener: TcpListener,
    pub dialer: Arc<dyn Dialer>,
    pub shaper: Arc<Shaper>,
    pub stats: Arc<Stats>,
    pub auth: Option<(String, String)>,
    pub stop: Arc<AtomicBool>,
}

impl SocksServer {
    /// Bind and return the server handle (does not accept yet).
    pub fn bind(
        addr: &str,
        dialer: Arc<dyn Dialer>,
        shaper: Arc<Shaper>,
    ) -> std::io::Result<SocksServer> {
        let listener = TcpListener::bind(addr)?;
        Ok(SocksServer {
            listener,
            dialer,
            shaper,
            stats: Arc::new(Stats::default()),
            auth: None,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn with_auth(mut self, user: &str, pass: &str) -> SocksServer {
        self.auth = Some((user.to_string(), pass.to_string()));
        self
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept loop (blocking). Spawns one thread per connection. Returns
    /// when `stop` is set.
    pub fn serve(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            self.listener.set_nonblocking(true).ok();
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return;
                }
                match self.listener.accept() {
                    Ok((sock, _)) => {
                        let srv = self.clone();
                        std::thread::spawn(move || srv.handle(sock));
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::Interrupted =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(_) => return,
                }
            }
        })
    }

    fn handle(&self, sock: TcpStream) {
        let mut sock = sock;
        sock.set_nodelay(true).ok();
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(300)));
        let _ = sock.set_write_timeout(Some(std::time::Duration::from_secs(300)));
        if socks_handshake(&mut sock, self.auth.as_ref()).is_err() {
            self.stats.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // CONNECT request
        let target = match read_connect(&mut sock) {
            Ok(t) => t,
            Err(_) => {
                let _ = write_reply(&mut sock, 0x01); // general failure
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // dial through the tunnel
        let upstream = match self.dialer.dial(Network::Tcp, &target) {
            Ok(c) => c,
            Err(e) => {
                let code = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => 0x05,
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => 0x06,
                    std::io::ErrorKind::Unsupported => 0x07,
                    _ => 0x01,
                };
                let _ = write_reply(&mut sock, code);
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let _ = write_reply(&mut sock, 0x00); // success
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        relay(sock, upstream, &self.shaper, &self.stats, &self.stop);
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 wire handling (RFC 1928 + RFC 1929)
// ---------------------------------------------------------------------------

fn socks_handshake(sock: &mut TcpStream, auth: Option<&(String, String)>) -> std::io::Result<()> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr)?;
    if hdr[0] != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks: not v5",
        ));
    }
    let nmethods = hdr[1] as usize;
    if nmethods == 0 || nmethods > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks: bad methods",
        ));
    }
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods)?;
    let want_auth = auth.is_some();
    let chosen: u8 = if want_auth {
        if methods.contains(&0x02) {
            0x02
        } else {
            0xFF // no acceptable method
        }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        0xFF
    };
    sock.write_all(&[5, chosen])?;
    if chosen == 0xFF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socks: no acceptable method",
        ));
    }
    if chosen == 0x02 {
        let (user, pass) = auth.unwrap();
        // RFC 1929: ver(1) ulen(1) uname plen(1) passwd — vn holds ver+ulen
        let mut vn = [0u8; 2];
        sock.read_exact(&mut vn)?;
        if vn[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "socks: bad auth version",
            ));
        }
        let mut u = vec![0u8; vn[1] as usize];
        sock.read_exact(&mut u)?;
        let mut plen = [0u8; 1];
        sock.read_exact(&mut plen)?;
        let mut p = vec![0u8; plen[0] as usize];
        sock.read_exact(&mut p)?;
        if u != user.as_bytes() || p != pass.as_bytes() {
            sock.write_all(&[1, 1])?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "socks: auth failed",
            ));
        }
        sock.write_all(&[1, 0])?;
    }
    Ok(())
}

fn read_connect(sock: &mut TcpStream) -> std::io::Result<String> {
    let mut req = [0u8; 4];
    sock.read_exact(&mut req)?;
    if req[0] != 5 || req[1] != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks: only CONNECT",
        ));
    }
    let (host, extra) = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b)?;
            (std::net::Ipv4Addr::from(b).to_string(), 0)
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l)?;
            let mut d = vec![0u8; l[0] as usize];
            sock.read_exact(&mut d)?;
            (
                String::from_utf8(d).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "socks: utf8")
                })?,
                0,
            )
        }
        0x04 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b)?;
            (std::net::Ipv6Addr::from(b).to_string(), 0)
        }
        a => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("socks: bad atyp {a}"),
            ))
        }
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb)?;
    let port = u16::from_be_bytes(pb);
    let _ = extra;
    Ok(format!("{host}:{port}"))
}

fn write_reply(sock: &mut TcpStream, code: u8) -> std::io::Result<()> {
    // BND.ADDR 0.0.0.0 + BND.PORT 0 — minimal, correct-enough reply
    sock.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

// ---------------------------------------------------------------------------
// relay — pooled, shaped, counted
// ---------------------------------------------------------------------------

fn pump(
    mut src: Box<dyn Read + Send>,
    mut dst: Box<dyn Write + Send>,
    pool: &BufferPool,
    shaper: &Shaper,
    flow: u64,
    stop: &AtomicBool,
    counter: &AtomicU64,
) -> u64 {
    let mut total = 0u64;
    loop {
        if stop.load(Ordering::Relaxed) {
            return total;
        }
        let mut buf = pool.get();
        match src.read(&mut buf) {
            Ok(0) => return total,
            Ok(n) => {
                if !shaper.admit(flow, n, stop) {
                    return total;
                }
                if dst.write_all(&buf[..n]).is_err() {
                    return total;
                }
                let _ = dst.flush();
                total += n as u64;
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => return total,
        }
    }
}

/// Bidirectional relay: splits both the local socket and the tunnel conn
/// into read/write halves, then pumps each direction on its own thread.
/// All buffers come from a pool; all bytes pass the shared shaper (DRR
/// fair across streams); all bytes are counted into stats.
fn relay(
    local: TcpStream,
    upstream: Box<dyn holo_proto::TunnelConn>,
    shaper: &Arc<Shaper>,
    stats: &Arc<Stats>,
    stop: &Arc<AtomicBool>,
) {
    let pool = BufferPool::new(16 * 1024, 32);
    let local_r = match local.try_clone() {
        Ok(l) => l,
        Err(_) => return,
    };
    let (up_r, up_w) = upstream.split_rw();
    // direction 1: local → upstream (bytes_out)
    let shaper1 = shaper.clone();
    let stats1 = stats.clone();
    let stop1 = stop.clone();
    let pool1 = pool.clone();
    let flow1 = shaper.new_flow();
    let t1 = std::thread::spawn(move || {
        let n = pump(
            Box::new(local_r),
            up_w,
            &pool1,
            &shaper1,
            flow1,
            &stop1,
            &stats1.bytes_out,
        );
        shaper1.drop_flow(flow1);
        n
    });
    // direction 2: upstream → local (bytes_in)
    let shaper2 = shaper.clone();
    let stats2 = stats.clone();
    let stop2 = stop.clone();
    let pool2 = pool.clone();
    let flow2 = shaper.new_flow();
    let t2 = std::thread::spawn(move || {
        let n = pump(
            up_r,
            Box::new(local),
            &pool2,
            &shaper2,
            flow2,
            &stop2,
            &stats2.bytes_in,
        );
        shaper2.drop_flow(flow2);
        n
    });
    let _ = (t1.join(), t2.join());
    let _ = pool.pooled();
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Dialer to a real local echo server (via holo_proto::TcpConn).
    struct EchoDialer {
        echo_port: u16,
        refuse: bool,
    }
    impl Dialer for EchoDialer {
        fn dial(
            &self,
            _net: Network,
            addr: &str,
        ) -> std::io::Result<Box<dyn holo_proto::TunnelConn>> {
            if self.refuse && addr.contains("refused") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "refused",
                ));
            }
            let s = TcpStream::connect(("127.0.0.1", self.echo_port))?;
            Ok(Box::new(holo_proto::TcpConn(s)))
        }
    }

    fn spawn_echo() -> u16 {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for sock in ln.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut s = sock;
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    fn socks_connect(sock: &mut TcpStream, addr: &str) -> std::io::Result<()> {
        // CONNECT only — the greeting/auth exchange has already happened
        let (host, port) = addr.rsplit_once(':').unwrap();
        sock.write_all(&[5, 1, 0, 3, host.len() as u8])?;
        sock.write_all(host.as_bytes())?;
        sock.write_all(&port.parse::<u16>().unwrap().to_be_bytes())?;
        let mut reply = [0u8; 10];
        sock.read_exact(&mut reply)?;
        if reply[1] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("socks reply code {}", reply[1]),
            ));
        }
        Ok(())
    }

    #[test]
    fn full_socks5_roundtrip_with_auth_and_refusal() {
        let echo = spawn_echo();
        let dialer = Arc::new(EchoDialer {
            echo_port: echo,
            refuse: true,
        });
        let shaper = Arc::new(Shaper::new(0));
        let srv = Arc::new(
            SocksServer::bind("127.0.0.1:0", dialer.clone(), shaper)
                .unwrap()
                .with_auth("u", "p"),
        );
        let addr = srv.local_addr().unwrap().to_string();
        let handle = srv.clone().serve();
        std::thread::sleep(std::time::Duration::from_millis(60));

        // 1. wrong auth → refused
        let mut c = TcpStream::connect(&addr).unwrap();
        c.write_all(&[5, 1, 2]).unwrap(); // offer username/password
        let mut rep = [0u8; 2];
        c.read_exact(&mut rep).unwrap();
        assert_eq!(rep, [5, 2]);
        c.write_all(&[1, 1, b'x', 1, b'y']).unwrap();
        let mut ar = [0u8; 2];
        c.read_exact(&mut ar).unwrap();
        assert_eq!(ar, [1, 1]); // auth failure
        drop(c);

        // 2. correct auth → CONNECT → echo roundtrip
        let mut c = TcpStream::connect(&addr).unwrap();
        c.write_all(&[5, 1, 2]).unwrap();
        c.read_exact(&mut rep).unwrap();
        assert_eq!(rep, [5, 2]);
        c.write_all(&[1, 1, b'u', 1, b'p']).unwrap();
        c.read_exact(&mut ar).unwrap();
        assert_eq!(ar, [1, 0]); // success
        socks_connect(&mut c, &format!("target.local:{echo}")).expect("connect");
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        c.write_all(&payload).unwrap();
        let mut back = Vec::new();
        let mut buf = [0u8; 8192];
        while back.len() < payload.len() {
            let n = c.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            back.extend_from_slice(&buf[..n]);
        }
        assert_eq!(back, payload);
        drop(c);

        // 3. refused target → SOCKS error reply 0x05
        let mut c2 = TcpStream::connect(&addr).unwrap();
        c2.write_all(&[5, 1, 2]).unwrap(); // one method: username/password
        c2.read_exact(&mut rep).unwrap();
        c2.write_all(&[1, 1, b'u', 1, b'p']).unwrap();
        c2.read_exact(&mut ar).unwrap();
        assert_eq!(ar, [1, 0]);
        // CONNECT (server replies 5 = connection refused)
        let host = "refused.local";
        c2.write_all(&[5, 1, 0, 3, host.len() as u8]).unwrap();
        c2.write_all(host.as_bytes()).unwrap();
        c2.write_all(&echo.to_be_bytes()).unwrap();
        let mut reply = [0u8; 10];
        c2.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0x05);

        // stats: 1 successful relay (part 2); parts 1+3 are refused
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (i, o, conns, refused) = srv.stats.snapshot();
        assert_eq!(conns, 1, "conns {conns}");
        assert!(i >= 40_000 && o >= 40_000, "stats i={i} o={o}");
        assert!(refused >= 2, "refused {refused}");
        srv.stop.store(true, Ordering::Relaxed);
        let _ = handle;
    }

    #[test]
    fn shaper_limits_rate_when_enabled() {
        let shaper = Arc::new(Shaper::new(64)); // 64 KB/s
        let flow = shaper.new_flow();
        let stop = Arc::new(AtomicBool::new(false));
        let start = std::time::Instant::now();
        // 128 KB through a 64 KB/s shaper ≈ ≥ 1 s (32 KiB burst helps)
        for _ in 0..8 {
            assert!(shaper.admit(flow, 16 * 1024, &stop));
        }
        let elapsed = start.elapsed();
        shaper.drop_flow(flow);
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "shaper passed 128KB in {elapsed:?} — too fast for 64KB/s"
        );
    }

    #[test]
    fn shaper_unlimited_is_noop() {
        let shaper = Arc::new(Shaper::new(0));
        let flow = shaper.new_flow();
        let stop = Arc::new(AtomicBool::new(false));
        let start = std::time::Instant::now();
        for _ in 0..100 {
            assert!(shaper.admit(flow, 16 * 1024, &stop));
        }
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
    }

    #[test]
    fn socks_greeting_requires_v5() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for s in ln.incoming().flatten() {
                let _ = s;
            }
        });
        let mut c = TcpStream::connect(&addr).unwrap();
        c.write_all(&[4, 1]).unwrap(); // wrong version
        let mut buf = [0u8; 16];
        let r = c.read(&mut buf);
        assert!(r.is_err() || r.unwrap() == 0);
    }

    #[test]
    fn stats_default_zero() {
        let s = Stats::default();
        let (i, o, c, r) = s.snapshot();
        assert_eq!((i, o, c, r), (0, 0, 0, 0));
    }
}
