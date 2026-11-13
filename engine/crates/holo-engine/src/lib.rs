//! holo-engine — the daemon core: IPC (NDJSON JSON-RPC 2.0 over
//! 127.0.0.1:7977, token auth) + the Material You theme bridge (`theme.get`
//! serves the full M3 role set derived from the user's seed color) + the
//! live data plane (session.connect starts a Shadowsocks tunnel with a
//! local SOCKS5 entry point; holo-net shaping applies user rate limits).
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};

use holo_config::{Profile, Settings, Store};
use holo_theme::{scheme_from_seed, Argb, Mode};

// ---------------------------------------------------------------------------
// IPC constants
// ---------------------------------------------------------------------------

pub const CODE_PARSE_ERROR: i64 = -32700;
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
pub const CODE_INVALID_PARAMS: i64 = -32602;
pub const CODE_INTERNAL_ERROR: i64 = -32603;
pub const CODE_AUTH_FAILED: i64 = -32001;
pub const CODE_ENGINE_BUSY: i64 = -32002;
pub const CODE_PROFILE_MISSING: i64 = -32003;
pub const DEFAULT_TCP_PORT: u16 = 7977;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, msg: &str) -> RpcError {
        RpcError {
            code,
            message: msg.to_string(),
        }
    }
    pub fn to_json(&self, id: u64) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{},\"message\":\"{}\"}}}}",
            id,
            self.code,
            json_escape(&self.message)
        )
    }
}

pub fn json_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

pub fn ensure_token(data_dir: &std::path::Path) -> Result<String, String> {
    let p = data_dir.join("ipc-token");
    if let Ok(t) = std::fs::read_to_string(&p) {
        let t = t.trim().to_string();
        if !t.is_empty() {
            tighten_private(&p);
            return Ok(t);
        }
    }
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    // SECURITY material: fail-closed OS entropy (gate-0001 A2) — never the
    // splitmix fallback, never a silent weak token.
    let t = holo_util::rand::os_hex(24)
        .map_err(|e| format!("ipc token: os entropy unavailable: {e}"))?;
    std::fs::write(&p, &t).map_err(|e| e.to_string())?;
    set_private(&p)?;
    Ok(t)
}

/// Secrets at rest readable by the owner only — best effort on every load
/// (defends files created before hardening existed), strict on creation.
fn tighten_private(p: &std::path::Path) {
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(target_family = "unix"))]
    let _ = p;
}

fn set_private(p: &std::path::Path) -> Result<(), String> {
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())
    }
    #[cfg(not(target_family = "unix"))]
    {
        let _ = p;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineState {
    pub state: String,
    pub profile_id: String,
    pub profile_name: String,
    pub error: String,
}

impl EngineState {
    fn disconnected() -> EngineState {
        EngineState {
            state: "disconnected".into(),
            profile_id: String::new(),
            profile_name: String::new(),
            error: String::new(),
        }
    }
}

pub struct Engine {
    pub store: Store,
    pub settings: Mutex<Settings>,
    state: Mutex<EngineState>,
    session: Mutex<Option<ActiveSession>>,
    events_tx: mpsc::Sender<String>,
    events_rx: Mutex<Option<mpsc::Receiver<String>>>,
}

/// A live data-plane session: the local SOCKS listener + its accept loop.
pub struct ActiveSession {
    pub profile_id: String,
    pub profile_name: String,
    pub socks_addr: String,
    pub server: Arc<holo_socks::SocksServer>,
    pub handle: std::thread::JoinHandle<()>,
}

impl Engine {
    pub fn new(store: Store) -> Arc<Engine> {
        let (tx, rx) = mpsc::channel();
        let settings = store.load_settings();
        Arc::new(Engine {
            store,
            settings: Mutex::new(settings),
            state: Mutex::new(EngineState::disconnected()),
            session: Mutex::new(None),
            events_tx: tx,
            events_rx: Mutex::new(Some(rx)),
        })
    }

    pub fn take_event_receiver(&self) -> Option<mpsc::Receiver<String>> {
        self.events_rx.lock().unwrap().take()
    }

    pub fn state(&self) -> EngineState {
        self.state.lock().unwrap().clone()
    }

    fn set_state(&self, st: EngineState) {
        let payload = state_json(&st);
        *self.state.lock().unwrap() = st;
        let _ = self.events_tx.send(format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"event\",\"params\":{{\"name\":\"state.changed\",\"payload\":{}}}}}",
            payload
        ));
    }

    fn emit(&self, name: &str, payload: &str) {
        let _ = self.events_tx.send(format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"event\",\"params\":{{\"name\":\"{}\",\"payload\":{}}}}}",
            name, payload
        ));
    }

    // -- Material You ------------------------------------------------------

    /// Resolve the *effective* mode: "system" follows the OS preference the
    /// frontend reports (query param `os_theme=dark|light`), else the
    /// setting itself. Desktop frontends call `theme.get` on every
    /// system-theme change.
    pub fn theme(&self, os_theme: Option<&str>) -> Result<holo_theme::Scheme, String> {
        let st = self.settings.lock().unwrap();
        let mode_str = st.get("theme_mode").unwrap_or("system").to_string();
        let mode = match mode_str.as_str() {
            "dark" => Mode::Dark,
            "light" => Mode::Light,
            _ => Mode::parse(os_theme.unwrap_or("light")), // system → OS-reported
        };
        let seed_hex = st.get("seed_color").unwrap_or("#6750A4").to_string();
        let seed = Argb::from_hex(&seed_hex).unwrap_or(holo_theme::DEFAULT_SEED);
        Ok(scheme_from_seed(seed, mode))
    }

    /// The M3 role set as a flat hex map (the cross-platform contract).
    pub fn theme_hex_map(&self, os_theme: Option<&str>) -> Vec<(String, String)> {
        let scheme = self.theme(os_theme).ok();
        let empty: Vec<(String, String)> = Vec::new();
        let roles = match &scheme {
            Some(s) => holo_theme::scheme_to_hex_map(s),
            None => return empty,
        };
        roles.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    // -- sessions ----------------------------------------------------------

    pub fn connect(self: &Arc<Self>, profile_id: &str) -> Result<EngineState, RpcError> {
        {
            let cur = self.state();
            if cur.state == "connecting" || cur.state == "connected" {
                return Err(RpcError::new(
                    CODE_ENGINE_BUSY,
                    "engine busy: disconnect first",
                ));
            }
        }
        let profiles = self.store.load_profiles();
        let profile = profiles
            .into_iter()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| RpcError::new(CODE_PROFILE_MISSING, "profile not found"))?;
        self.set_state(EngineState {
            state: "connecting".into(),
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            error: String::new(),
        });
        let result = self.start_data_plane(&profile);
        match result {
            Ok(session) => {
                let addr = session.socks_addr.clone();
                *self.session.lock().unwrap() = Some(*session);
                self.set_state(EngineState {
                    state: "connected".into(),
                    profile_id: profile.id.clone(),
                    profile_name: profile.name.clone(),
                    error: String::new(),
                });
                self.emit(
                    "session.started",
                    &format!(
                        "{{\"profile\":\"{}\",\"socks\":\"{}\",\"driver\":\"{}\"}}",
                        json_escape(&profile.name),
                        addr,
                        json_escape(&profile.driver)
                    ),
                );
            }
            Err(e) => {
                self.set_state(EngineState {
                    state: "error".into(),
                    profile_id: profile.id.clone(),
                    profile_name: profile.name.clone(),
                    error: json_escape(&e),
                });
                return Err(RpcError::new(CODE_INTERNAL_ERROR, &e));
            }
        }
        Ok(self.state())
    }

    /// Start the protocol data plane for a profile. Shadowsocks AEAD is
    /// live (v0.3.0); every other driver reports its milestone honestly.
    fn start_data_plane(self: &Arc<Self>, profile: &Profile) -> Result<Box<ActiveSession>, String> {
        if profile.driver != "shadowsocks" {
            return Err(format!(
                "holonet/{}: data plane is a milestone (v0.4+; docs/RESTORE.md) — live now: shadowsocks",
                profile.driver
            ));
        }
        let method_s = profile.params.get("method").cloned().unwrap_or_default();
        let password = profile.params.get("password").cloned().unwrap_or_default();
        let method = holo_ss::Method::parse(&method_s)
            .ok_or_else(|| format!("ss: unsupported method {:?} (live: chacha20-ietf-poly1305, xchacha20-ietf-poly1305, aes-256-gcm)", method_s))?;
        if password.is_empty() {
            return Err("ss: profile has no password".into());
        }
        let server = format!("{}:{}", profile.server, profile.port);
        // reachability probe at connect time — "connected" means the tunnel
        // endpoint answered, not just that a local listener came up
        {
            use std::net::ToSocketAddrs;
            let addr = server
                .to_socket_addrs()
                .map_err(|e| format!("ss: cannot resolve {server}: {e}"))?
                .next()
                .ok_or_else(|| format!("ss: unresolvable server {server}"))?;
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))
                .map_err(|e| format!("ss: server {server} unreachable: {e}"))?;
        }
        let dialer: Arc<dyn holo_proto::Dialer> =
            Arc::new(holo_ss::SsDialer::new(&server, &password, method));
        // local SOCKS listener from settings (proxy_listen), rate limit
        // (relay.max_rate_kbps, 0 = unlimited) — the paper-technique
        // shaping path: TokenBucket + DRR fairness across streams
        let listen = {
            let st = self.settings.lock().unwrap();
            st.get("proxy_listen")
                .unwrap_or("127.0.0.1:2080")
                .to_string()
        };
        let rate_kbps: u64 = {
            let st = self.settings.lock().unwrap();
            st.get("relay.max_rate_kbps")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        };
        let shaper = Arc::new(holo_socks::Shaper::new(rate_kbps));
        let srv = Arc::new(
            holo_socks::SocksServer::bind(&listen, dialer, shaper)
                .map_err(|e| format!("socks: cannot bind {listen}: {e}"))?,
        );
        let socks_addr = srv.local_addr().map_err(|e| e.to_string())?.to_string();
        let handle = srv.clone().serve();
        Ok(Box::new(ActiveSession {
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            socks_addr,
            server: srv,
            handle,
        }))
    }

    pub fn disconnect(&self) -> EngineState {
        // stop the data plane first, then report
        if let Some(sess) = self.session.lock().unwrap().take() {
            sess.server
                .stop
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = sess.handle.join();
        }
        let mut st = self.state();
        st.state = "disconnected".into();
        st.error = String::new();
        self.set_state(st.clone());
        self.emit("session.stopped", "{}");
        st
    }

    /// Engine counters: bytes through the local proxy (in/out), active
    /// connections, refused attempts, session address.
    pub fn stats(&self) -> String {
        let (bytes_in, bytes_out, conns, refused) = match &*self.session.lock().unwrap() {
            Some(s) => s.server.stats.snapshot(),
            None => (0, 0, 0, 0),
        };
        let socks = match &*self.session.lock().unwrap() {
            Some(s) => s.socks_addr.clone(),
            None => String::new(),
        };
        format!(
            "{{\"bytesIn\":{},\"bytesOut\":{},\"connections\":{},\"refused\":{},\"socks\":\"{}\"}}",
            bytes_in, bytes_out, conns, refused, socks
        )
    }

    pub fn import(&self, kind: &str, data: &str) -> Result<Vec<Profile>, RpcError> {
        let _ = kind; // links parser handles share URLs; other formats: RESTORE.md
        let profiles = holo_config::links::parse(data)
            .map_err(|e| RpcError::new(CODE_INVALID_PARAMS, &format!("import: {}", e)))?;
        for p in &profiles {
            self.store
                .add_profile(p.clone())
                .map_err(|e| RpcError::new(CODE_INTERNAL_ERROR, &e))?;
        }
        self.emit(
            "profiles.changed",
            &format!("{{\"count\":{}}}", profiles.len()),
        );
        Ok(profiles)
    }
}

fn state_json(st: &EngineState) -> String {
    format!(
        "{{\"state\":\"{}\",\"profileId\":\"{}\",\"profileName\":\"{}\",\"error\":\"{}\"}}",
        json_escape(&st.state),
        json_escape(&st.profile_id),
        json_escape(&st.profile_name),
        json_escape(&st.error)
    )
}

// ---------------------------------------------------------------------------
// IPC server
// ---------------------------------------------------------------------------

pub fn serve_ipc(
    engine: Arc<Engine>,
    listener: TcpListener,
    token: String,
    events: mpsc::Receiver<String>,
) -> std::thread::JoinHandle<()> {
    let clients: Arc<Mutex<Vec<(u64, TcpStream)>>> = Arc::new(Mutex::new(Vec::new()));
    let clients2 = clients.clone();
    std::thread::spawn(move || loop {
        let ev = match events.recv() {
            Ok(e) => e,
            Err(_) => break,
        };
        let mut out = String::with_capacity(ev.len() + 1);
        out.push_str(&ev);
        out.push('\n');
        clients2.lock().unwrap().retain(|(_, w)| {
            let mut w = w;
            w.write_all(out.as_bytes()).is_ok()
        });
    });
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(stream) = s else { continue };
            let engine = engine.clone();
            let token = token.clone();
            let clients = clients.clone();
            handle_ipc_conn(stream, engine, token, clients);
        }
    })
}

static CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Register the connection for event broadcasts and spawn its reader loop.
/// Returns immediately: one short-lived setup on the accept thread, one
/// reader thread per connection (removed from the broadcast list on EOF).
fn handle_ipc_conn(
    stream: TcpStream,
    engine: Arc<Engine>,
    token: String,
    clients: Arc<Mutex<Vec<(u64, TcpStream)>>>,
) {
    // RPC over loopback: send each framed line as soon as it is written.
    let _ = stream.set_nodelay(true);
    let w = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let cid = CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let helloed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut resp_w = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let clients2 = clients.clone();
    std::thread::spawn(move || {
        let mut r = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let resp = dispatch(trimmed, &engine, &token, &helloed);
                    let mut out = String::with_capacity(resp.len() + 1);
                    out.push_str(&resp);
                    out.push('\n');
                    if resp_w.write_all(out.as_bytes()).is_err() {
                        break;
                    }
                }
            }
        }
        // Connection over — deregister from the event broadcast list.
        clients2.lock().unwrap().retain(|(c, _)| *c != cid);
    });
    clients.lock().unwrap().push((cid, w));
}

fn dispatch(
    line: &str,
    engine: &Arc<Engine>,
    token: &str,
    helloed: &Arc<std::sync::atomic::AtomicBool>,
) -> String {
    use std::sync::atomic::Ordering;
    let v = match holo_util::json::parse(line) {
        Ok(v) => v,
        Err(e) => return RpcError::new(CODE_PARSE_ERROR, &format!("parse: {}", e)).to_json(0),
    };
    let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u64;
    let method = v
        .get("method")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let params = v.get("params").cloned().unwrap_or(holo_util::Value::Null);

    if method != "hello" && method != "ping" && !helloed.load(Ordering::Relaxed) {
        return RpcError::new(CODE_AUTH_FAILED, "authenticate with hello first").to_json(id);
    }
    let pstr = |k: &str| {
        params
            .get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    match method.as_str() {
        "hello" => {
            // auth material — constant-time compare (gate-0001 A2-F4);
            // length itself is public knowledge, only the bytes must not leak
            let supplied = pstr("token");
            if supplied.len() != token.len()
                || !holo_crypto::ct_eq(supplied.as_bytes(), token.as_bytes())
            {
                return RpcError::new(CODE_AUTH_FAILED, "bad token").to_json(id);
            }
            helloed.store(true, Ordering::Relaxed);
            let profiles = engine.store.load_profiles().len();
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"state\":\"{}\",\"profiles\":{},\"capabilities\":[\"theme\",\"import\",\"profiles\",\"events\"]}}}}",
                id, engine.state().state, profiles
            )
        }
        "ping" => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"pong\":true}}}}",
            id
        ),
        "state.get" => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
            id,
            state_json(&engine.state())
        ),
        "stats.get" => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
            id,
            engine.stats()
        ),
        "session.connect" => match engine.connect(&pstr("profileId")) {
            Ok(st) => format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                id,
                state_json(&st)
            ),
            Err(e) => e.to_json(id),
        },
        "session.disconnect" => {
            let st = engine.disconnect();
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                id,
                state_json(&st)
            )
        }
        "profiles.list" => {
            let profiles = engine.store.load_profiles();
            let arr = holo_util::Value::Arr(profiles.iter().map(|p| p.to_json()).collect());
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"profiles\":{}}}}}",
                id,
                holo_util::json::to_string(&arr)
            )
        }
        "profiles.remove" => match engine.store.remove_profile(&pstr("id")) {
            Ok(removed) => format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"removed\":{}}}}}",
                id, removed
            ),
            Err(e) => RpcError::new(CODE_INTERNAL_ERROR, &e).to_json(id),
        },
        "configs.import" => {
            match engine.import(&pstr("kind"), &pstr("data")) {
                Ok(profiles) => {
                    let arr = holo_util::Value::Arr(profiles.iter().map(|p| p.to_json()).collect());
                    format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"added\":{},\"profiles\":{}}}}}", id, profiles.len(), holo_util::json::to_string(&arr))
                }
                Err(e) => e.to_json(id),
            }
        }
        // -- Material You bridge -------------------------------------------
        "theme.get" => {
            // params: {osTheme?: "dark"|"light"} — the system theme the
            // frontend observed; used when theme_mode == "system".
            let os_theme = params
                .get("osTheme")
                .and_then(|x| x.as_str())
                .map(String::from);
            let roles = engine.theme_hex_map(os_theme.as_deref());
            let (mode, seed, dynamic) = {
                let st = engine.settings.lock().unwrap();
                (
                    st.get("theme_mode").unwrap_or("system").to_string(),
                    st.get("seed_color").unwrap_or("#6750A4").to_string(),
                    st.get("dynamic_color").unwrap_or("true").to_string(),
                )
            };
            let obj: std::collections::BTreeMap<String, holo_util::Value> = roles
                .into_iter()
                .map(|(k, v)| (k, holo_util::Value::s(v)))
                .chain([
                    ("_mode".to_string(), holo_util::Value::s(mode)),
                    ("_seed".to_string(), holo_util::Value::s(seed)),
                    ("_dynamic".to_string(), holo_util::Value::s(dynamic)),
                ])
                .collect();
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                id,
                holo_util::json::to_string(&holo_util::Value::Obj(obj))
            )
        }
        "settings.get" => {
            let st = engine.settings.lock().unwrap();
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                id,
                holo_util::json::to_string(&st.to_json())
            )
        }
        "settings.set" => {
            let mut st = engine.settings.lock().unwrap();
            if let Some(holo_util::Value::Obj(m)) = params.get("values") {
                for (k, val) in m {
                    if let Some(s) = val.as_str() {
                        st.set(k.clone(), s);
                    }
                }
            } else if let holo_util::Value::Obj(m) = &params {
                for (k, val) in m {
                    if let Some(s) = val.as_str() {
                        st.set(k.clone(), s);
                    }
                }
            }
            let snapshot = st.clone();
            drop(st);
            let r = engine.store.save_settings(&snapshot);
            match r {
                Ok(()) => format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
                    id,
                    holo_util::json::to_string(&snapshot.to_json())
                ),
                Err(e) => RpcError::new(CODE_INTERNAL_ERROR, &e).to_json(id),
            }
        }
        _ => RpcError::new(CODE_METHOD_NOT_FOUND, &format!("method {}", method)).to_json(id),
    }
}

// ---------------------------------------------------------------------------
// IPC client (holonetctl + tests)
// ---------------------------------------------------------------------------

pub struct IpcClient {
    pub stream: TcpStream,
    /// Persistent buffered reader — bytes read past a line MUST survive
    /// until the next `read_response` call. (A fresh `BufReader` per call
    /// discards them; when a reply and an event coalesce into one TCP
    /// segment — Windows coalesces readily — the client deadlocks.)
    reader: BufReader<TcpStream>,
    pub next_id: u64,
}

impl IpcClient {
    pub fn connect(addr: &str, token: &str) -> std::io::Result<IpcClient> {
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);
        let reader = BufReader::new(stream.try_clone()?);
        let mut c = IpcClient {
            stream,
            reader,
            next_id: 1,
        };
        let hello = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"hello\",\"params\":{{\"token\":\"{}\"}}}}\n", json_escape(token));
        c.stream.write_all(hello.as_bytes())?;
        let _ = c.read_response()?;
        c.next_id = 2;
        Ok(c)
    }

    pub fn request(&mut self, method: &str, params_json: &str) -> std::io::Result<String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"{}\"",
            id,
            json_escape(method)
        );
        if params_json != "{}" {
            line.push_str(&format!(",\"params\":{}", params_json));
        }
        line.push_str("}\n");
        self.stream.write_all(line.as_bytes())?;
        self.read_response()
    }

    fn read_response(&mut self) -> std::io::Result<String> {
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ipc: connection closed by daemon",
                ));
            }
            let t = line.trim().to_string();
            if t.is_empty() {
                continue;
            }
            if t.contains("\"method\":\"event\"") {
                continue;
            }
            return Ok(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_roundtrip_auth_state_theme() {
        let dir = std::env::temp_dir().join(format!("holonet-eng-{}", holo_config::new_id()));
        let store = Store::new(&dir);
        let engine = Engine::new(store);
        let token = ensure_token(&dir).unwrap();
        // 127.0.0.1:0 — ephemeral port on the one loopback address every OS
        // has bound (macOS lo0 only carries 127.0.0.1, unlike Linux's 127/8).
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        let events = engine.take_event_receiver().unwrap();
        serve_ipc(engine.clone(), ln, token.clone(), events);

        // Unauthenticated → rejected.
        let mut c0 = TcpStream::connect(&addr).unwrap();
        c0.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"state.get\"}\n")
            .unwrap();
        let mut r = BufReader::new(c0);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert!(line.contains("authenticate with hello first"), "{}", line);

        // Authenticated: import, list, theme.
        let mut c = IpcClient::connect(&addr, &token).unwrap();
        let st = c.request("state.get", "{}").unwrap();
        assert!(st.contains("disconnected"), "{}", st);
        let userinfo = holo_util::base64::encode_url(b"aes-256-gcm:pw");
        let link = format!("ss://{}@example.com:8388#TestNode", userinfo);
        let imp = c
            .request(
                "configs.import",
                &format!("{{\"kind\":\"auto\",\"data\":\"{}\"}}", link),
            )
            .unwrap();
        assert!(imp.contains("TestNode"), "{}", imp);
        let lst = c.request("profiles.list", "{}").unwrap();
        assert!(lst.contains("TestNode"));

        // theme.get: default seed, dark OS theme.
        let theme = c.request("theme.get", "{\"osTheme\":\"dark\"}").unwrap();
        assert!(theme.contains("\"_seed\":\"#6750A4\""), "{}", theme);
        assert!(theme.contains("\"primary\""), "{}", theme);

        // settings.set: change the seed → theme follows.
        c.request("settings.set", "{\"values\":{\"seed_color\":\"#B3261E\"}}")
            .unwrap();
        let theme2 = c.request("theme.get", "{\"osTheme\":\"dark\"}").unwrap();
        assert!(theme2.contains("\"_seed\":\"#B3261E\""), "{}", theme2);
        assert_ne!(theme, theme2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn theme_light_vs_dark_and_seed_change() {
        let dir = std::env::temp_dir().join(format!("holonet-eng2-{}", holo_config::new_id()));
        let store = Store::new(&dir);
        let engine = Engine::new(store);
        let light = engine.theme_hex_map(Some("light"));
        let dark = engine.theme_hex_map(Some("dark"));
        let lp = light.iter().find(|(k, _)| k == "primary").unwrap();
        let dp = dark.iter().find(|(k, _)| k == "primary").unwrap();
        assert_ne!(lp, dp);
        assert_ne!(light, dark);
        let _ = std::fs::remove_dir_all(dir);
    }
}
