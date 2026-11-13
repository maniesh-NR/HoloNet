//! End-to-end integration tests: the whole HoloNet stack talking to itself
//! over real loopback TCP —
//!
//! ```text
//! IPC client (IpcClient) ──NDJSON──▶ Engine
//!   configs.import (ss:// link) → profiles.list
//!   session.connect             → data plane: local SOCKS5 (proxy_listen)
//! SOCKS5 client ──▶ local SOCKS ──▶ SsDialer (AEAD tunnel) ──▶ fake SS server
//!                                     │
//!                                     ▼
//!                                upstream echo
//!   stats.get / session.disconnect
//! ```
//!
//! Every subsystem that can work together must work together: settings
//! (proxy_listen, relay.max_rate_kbps) → engine → socks shaper (TokenBucket
//! + DRR) → pooled relay → Shadowsocks AEAD (holo-crypto) → anti-probing
//! server → upstream.
#![forbid(unsafe_code)]

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use holo_config::Store;
use holo_engine::{Engine, IpcClient};

// ---------------------------------------------------------------------------
// test infrastructure
// ---------------------------------------------------------------------------

fn spawn_echo() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for sock in ln.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = sock;
                let mut buf = [0u8; 16 * 1024];
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

/// A real Shadowsocks server (holo-ss serve_conn) relaying to `upstream`.
fn spawn_ss_server(method: holo_ss::Method, password: &'static str, _upstream: u16) -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    let guard = Arc::new(Mutex::new(holo_net::ProbeGuard::new()));
    std::thread::spawn(move || {
        for sock in ln.incoming().flatten() {
            let master = holo_ss::master_key(password);
            let guard = guard.clone();
            std::thread::spawn(move || {
                let _ = holo_ss::serve_conn(sock, &master, method, &guard, |target| {
                    let t = target.to_string();
                    let addr = t
                        .rsplit_once(':')
                        .map(|(h, p)| format!("{h}:{p}"))
                        .unwrap_or(t);
                    let port: u16 = addr.rsplit_once(':').unwrap().1.parse().unwrap();
                    TcpStream::connect(("127.0.0.1", port))
                });
            });
        }
    });
    port
}

/// Spin up the engine + IPC listener; returns (addr, token, engine, dir).
fn spawn_engine() -> (String, String, Arc<Engine>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("holonet-integ-{}", holo_config::new_id()));
    let store = Store::new(&dir);
    let engine = Engine::new(store);
    let token = holo_engine::ensure_token(&dir).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let events = engine.take_event_receiver().unwrap();
    holo_engine::serve_ipc(engine.clone(), ln, token.clone(), events);
    (addr, token, engine, dir)
}

/// SOCKS5 client with no-auth, CONNECT to `target`, returns the stream.
fn socks_connect(addr: &str, target: &str) -> TcpStream {
    let mut c = TcpStream::connect(addr).unwrap();
    c.write_all(&[5, 1, 0]).unwrap();
    let mut rep = [0u8; 2];
    c.read_exact(&mut rep).unwrap();
    assert_eq!(rep, [5, 0], "greeting");
    let (host, port) = target.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    // use IPv4 form (loopback resolves locally)
    let ip: std::net::Ipv4Addr = host.parse().unwrap();
    c.write_all(&[5, 1, 0, 1]).unwrap();
    c.write_all(&ip.octets()).unwrap();
    c.write_all(&port.to_be_bytes()).unwrap();
    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT reply code {}", reply[1]);
    c
}

fn read_n(c: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut back = Vec::with_capacity(n);
    let mut buf = vec![0u8; 16 * 1024];
    while back.len() < n {
        let got = c.read(&mut buf).expect("read");
        if got == 0 {
            break;
        }
        back.extend_from_slice(&buf[..got]);
    }
    back
}

fn make_ss_link(server_port: u16, method: &str, password: &str, name: &str) -> String {
    let userinfo = holo_util::base64::encode_url(format!("{method}:{password}").as_bytes());
    format!("ss://{userinfo}@127.0.0.1:{server_port}#{name}")
}

// ---------------------------------------------------------------------------
// integration tests
// ---------------------------------------------------------------------------

#[test]
fn full_chain_ipc_socks_ss_upstream() {
    let echo = spawn_echo();
    let ss = spawn_ss_server(holo_ss::Method::ChaCha20IetfPoly1305, "integ-pw", echo);
    let (addr, token, _engine, dir) = spawn_engine();

    let mut c = IpcClient::connect(&addr, &token).unwrap();

    // capabilities include the new surface
    let hello = c.request("ping", "{}").unwrap();
    assert!(hello.contains("pong"));

    // import the ss profile via share link
    let link = make_ss_link(ss, "chacha20-ietf-poly1305", "integ-pw", "IntegNode");
    let imp = c
        .request(
            "configs.import",
            &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
        )
        .unwrap();
    assert!(imp.contains("IntegNode"), "import: {imp}");
    let list = c.request("profiles.list", "{}").unwrap();
    assert!(list.contains("IntegNode"));
    // extract profile id
    let id_start = list.find("\"id\":\"").unwrap() + 6;
    let id = list[id_start..].split('"').next().unwrap().to_string();

    // use an ephemeral local proxy port so parallel tests can't collide
    c.request(
        "settings.set",
        "{\"values\":{\"proxy_listen\":\"127.0.0.1:0\"}}",
    )
    .unwrap();

    // connect → data plane up
    let st = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .unwrap();
    assert!(st.contains("\"state\":\"connected\""), "state: {st}");

    // full chain: SOCKS5 → tunnel → echo
    let stats0 = c.request("stats.get", "{}").unwrap();
    let socks = stats0
        .split("\"socks\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    assert!(socks.starts_with("127.0.0.1:"), "socks addr: {socks}");

    let mut conn = socks_connect(&socks, &format!("127.0.0.1:{echo}"));
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    conn.write_all(&payload).unwrap();
    conn.flush().unwrap();
    let back = read_n(&mut conn, payload.len());
    assert_eq!(back.len(), payload.len(), "echo length");
    assert_eq!(back, payload, "echo content");
    drop(conn);

    // stats must have counted the traffic
    std::thread::sleep(std::time::Duration::from_millis(150));
    let stats = c.request("stats.get", "{}").unwrap();
    assert!(stats.contains("\"connections\":1"), "stats: {stats}");
    let bi: u64 = stats
        .split("\"bytesIn\":")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let bo: u64 = stats
        .split("\"bytesOut\":")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(bi >= 300_000, "bytesIn {bi}");
    assert!(bo >= 300_000, "bytesOut {bo}");

    // disconnect stops the data plane
    let st = c.request("session.disconnect", "{}").unwrap();
    assert!(st.contains("\"state\":\"disconnected\""), "state: {st}");
    // stats after disconnect reset to zero
    let stats2 = c.request("stats.get", "{}").unwrap();
    assert!(
        stats2.contains("\"bytesIn\":0"),
        "stats after disconnect: {stats2}"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn shaping_rate_limit_end_to_end() {
    let echo = spawn_echo();
    let ss = spawn_ss_server(holo_ss::Method::Aes256Gcm, "shape-pw", echo);
    let (addr, token, _engine, dir) = spawn_engine();
    let mut c = IpcClient::connect(&addr, &token).unwrap();

    let link = make_ss_link(ss, "aes-256-gcm", "shape-pw", "ShapedNode");
    c.request(
        "configs.import",
        &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
    )
    .unwrap();
    let list = c.request("profiles.list", "{}").unwrap();
    let id = list[list.find("\"id\":\"").unwrap() + 6..]
        .split('"')
        .next()
        .unwrap()
        .to_string();

    // 128 KB/s limit + ephemeral port
    c.request(
        "settings.set",
        "{\"values\":{\"proxy_listen\":\"127.0.0.1:0\",\"relay.max_rate_kbps\":\"128\"}}",
    )
    .unwrap();
    let st = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .unwrap();
    assert!(st.contains("\"state\":\"connected\""), "state: {st}");
    let stats0 = c.request("stats.get", "{}").unwrap();
    let socks = stats0
        .split("\"socks\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();

    let mut conn = socks_connect(&socks, &format!("127.0.0.1:{echo}"));
    let payload = vec![7u8; 128 * 1024]; // 128 KB — ≥ 1 s at 128 KB/s
    let start = std::time::Instant::now();
    conn.write_all(&payload).unwrap();
    let back = read_n(&mut conn, payload.len());
    let elapsed = start.elapsed();
    assert_eq!(back.len(), payload.len());
    assert!(
        elapsed >= std::time::Duration::from_millis(700),
        "128KB took {elapsed:?} — shaping not applied"
    );
    drop(conn);
    let _ = c.request("session.disconnect", "{}").unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn performance_throughput_loopback() {
    let echo = spawn_echo();
    let ss = spawn_ss_server(holo_ss::Method::ChaCha20IetfPoly1305, "perf-pw", echo);
    let (addr, token, _engine, dir) = spawn_engine();
    let mut c = IpcClient::connect(&addr, &token).unwrap();

    let link = make_ss_link(ss, "chacha20-ietf-poly1305", "perf-pw", "PerfNode");
    c.request(
        "configs.import",
        &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
    )
    .unwrap();
    let list = c.request("profiles.list", "{}").unwrap();
    let id = list[list.find("\"id\":\"").unwrap() + 6..]
        .split('"')
        .next()
        .unwrap()
        .to_string();
    c.request(
        "settings.set",
        "{\"values\":{\"proxy_listen\":\"127.0.0.1:0\"}}",
    )
    .unwrap();
    let st = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .unwrap();
    assert!(st.contains("\"state\":\"connected\""));
    let stats0 = c.request("stats.get", "{}").unwrap();
    let socks = stats0
        .split("\"socks\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();

    let mut conn = socks_connect(&socks, &format!("127.0.0.1:{echo}"));
    let total = 8 * 1024 * 1024; // 8 MB
    let chunk = vec![0xA5u8; 64 * 1024];
    let start = std::time::Instant::now();
    // writer thread: push 8MB
    let wconn = conn.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let mut w = wconn;
        for _ in 0..(total / chunk.len()) {
            if w.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = w.flush();
    });
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    while received < total {
        let n = conn.read(&mut buf).expect("perf read");
        if n == 0 {
            break;
        }
        received += n;
    }
    let elapsed = start.elapsed();
    let _ = writer.join();
    let mbps = (received as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
    // loopback AEAD, DEBUG build — assert a conservative floor (release
    // builds with LTO run several times faster; see docs/TECHNIQUES.md)
    assert!(received == total, "only {received}/{total} bytes echoed");
    assert!(
        mbps > 1.0,
        "throughput too low: {mbps:.1} MB/s in {elapsed:?}"
    );
    eprintln!("perf: {received} bytes in {elapsed:?} = {mbps:.1} MB/s");
    drop(conn);
    let _ = c.request("session.disconnect", "{}").unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn memory_stays_bounded_under_sustained_relay() {
    let echo = spawn_echo();
    let ss = spawn_ss_server(holo_ss::Method::ChaCha20IetfPoly1305, "mem-pw", echo);
    let (addr, token, _engine, dir) = spawn_engine();
    let mut c = IpcClient::connect(&addr, &token).unwrap();

    let link = make_ss_link(ss, "chacha20-ietf-poly1305", "mem-pw", "MemNode");
    c.request(
        "configs.import",
        &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
    )
    .unwrap();
    let list = c.request("profiles.list", "{}").unwrap();
    let id = list[list.find("\"id\":\"").unwrap() + 6..]
        .split('"')
        .next()
        .unwrap()
        .to_string();
    c.request(
        "settings.set",
        "{\"values\":{\"proxy_listen\":\"127.0.0.1:0\"}}",
    )
    .unwrap();
    let st = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .unwrap();
    assert!(st.contains("\"state\":\"connected\""));
    let stats0 = c.request("stats.get", "{}").unwrap();
    let socks = stats0
        .split("\"socks\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();

    let rss_before = read_self_rss_kb();

    let mut conn = socks_connect(&socks, &format!("127.0.0.1:{echo}"));
    let total = 64 * 1024 * 1024; // 64 MB through the full chain
    let chunk = vec![0x5Au8; 16 * 1024];
    let wconn = conn.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let mut w = wconn;
        for _ in 0..(total / chunk.len()) {
            if w.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = w.flush();
    });
    let mut received = 0usize;
    let mut buf = vec![0u8; 16 * 1024];
    while received < total {
        let n = conn.read(&mut buf).expect("mem read");
        if n == 0 {
            break;
        }
        received += n;
    }
    let _ = writer.join();
    assert_eq!(received, total);
    // let the relay threads settle, then sample RSS again
    std::thread::sleep(std::time::Duration::from_millis(200));
    let rss_after = read_self_rss_kb();
    let growth = rss_after.saturating_sub(rss_before);
    eprintln!("mem: rss {rss_before} → {rss_after} KB (+{growth} KB) over 64MB relayed");
    // pooled relays allocate nothing per-chunk: growth must stay far below
    // the 64MB transferred. Observed in practice: +88..376 KB; the 2MB
    // ceiling sits 5-20x above observed noise while still catching any
    // per-chunk allocation regression (tightened at gate 0001 per A1-C3;
    // Linux-only test, documented in harness/memory/STATE.md).
    assert!(
        growth < 2 * 1024,
        "RSS grew {growth} KB — pooling/regression failure"
    );
    drop(conn);
    let _ = c.request("session.disconnect", "{}").unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(target_os = "linux")]
fn read_self_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest.trim().trim_end_matches("kB").trim();
            return kb.parse().unwrap_or(0);
        }
    }
    0
}

#[test]
fn unsupported_driver_is_honest_milestone() {
    let (addr, token, _engine, dir) = spawn_engine();
    let mut c = IpcClient::connect(&addr, &token).unwrap();
    // vmess profile (parsed by the links importer) — not live in v0.3
    let vm = holo_util::base64::encode_url(
        b"{\"v\":\"2\",\"ps\":\"VM\",\"add\":\"127.0.0.1\",\"port\":\"1\",\"id\":\"8a15d6a7-9c26-4aa1-96aa-b2df61ea9e2a\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\",\"scy\":\"auto\"}",
    );
    let link = format!("vmess://{vm}");
    let imp = c
        .request(
            "configs.import",
            &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
        )
        .unwrap();
    assert!(imp.contains("added"), "import: {imp}");
    let list = c.request("profiles.list", "{}").unwrap();
    let id = list[list.find("\"id\":\"").unwrap() + 6..]
        .split('"')
        .next()
        .unwrap()
        .to_string();
    c.request(
        "settings.set",
        "{\"values\":{\"proxy_listen\":\"127.0.0.1:0\"}}",
    )
    .unwrap();
    // IpcClient::request returns the raw JSON line — an RPC error carries
    // the "error" object with the honest milestone message
    let resp = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .expect("rpc transport ok");
    assert!(resp.contains("\"error\""), "rpc error expected: {resp}");
    assert!(resp.contains("milestone"), "error: {resp}");
    assert!(resp.contains("vmess"), "error names the driver: {resp}");
    // engine reports the error state (not stuck "connecting")
    let st2 = c.request("state.get", "{}").unwrap();
    assert!(
        st2.contains("\"state\":\"error\""),
        "state after milestone: {st2}"
    );
    assert!(st2.contains("milestone"), "state carries the reason: {st2}");
    // a fresh connect attempt is allowed (not busy-locked): the retry
    // produces the same honest milestone error, never "engine busy"
    let again = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .expect("rpc transport ok");
    assert!(again.contains("milestone"), "retry response: {again}");
    assert!(!again.contains("engine busy"), "must not be busy-locked");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn aes256gcm_profile_via_ipc_full_chain() {
    let echo = spawn_echo();
    let ss = spawn_ss_server(holo_ss::Method::Aes256Gcm, "gcm-pw", echo);
    let (addr, token, _engine, dir) = spawn_engine();
    let mut c = IpcClient::connect(&addr, &token).unwrap();
    let link = make_ss_link(ss, "aes-256-gcm", "gcm-pw", "GcmNode");
    c.request(
        "configs.import",
        &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
    )
    .unwrap();
    let list = c.request("profiles.list", "{}").unwrap();
    let id = list[list.find("\"id\":\"").unwrap() + 6..]
        .split('"')
        .next()
        .unwrap()
        .to_string();
    c.request(
        "settings.set",
        "{\"values\":{\"proxy_listen\":\"127.0.0.1:0\"}}",
    )
    .unwrap();
    let st = c
        .request("session.connect", &format!("{{\"profileId\":\"{}\"}}", id))
        .unwrap();
    assert!(st.contains("\"state\":\"connected\""), "{st}");
    let stats0 = c.request("stats.get", "{}").unwrap();
    let socks = stats0
        .split("\"socks\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    let mut conn = socks_connect(&socks, &format!("127.0.0.1:{echo}"));
    let payload = b"hello through aes-256-gcm tunnel";
    conn.write_all(payload).unwrap();
    let back = read_n(&mut conn, payload.len());
    assert_eq!(back.as_slice(), &payload[..]);
    drop(conn);
    let _ = c.request("session.disconnect", "{}").unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

// keep unused-import lints happy for the BufReader helper used above
#[allow(dead_code)]
fn _touch(_r: &BufReader<TcpStream>) {}
