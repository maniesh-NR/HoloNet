//! holo-proto — driver-level shared types: flat Params + the driver SPI.
use std::collections::BTreeMap;
use std::net::TcpStream;

/// Driver parameters / metadata map (sorted → deterministic serialization).
pub type Params = BTreeMap<String, String>;

pub fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn get_or_empty(params: &Params, key: &str) -> String {
    params.get(key).cloned().unwrap_or_default()
}

pub fn set_if_present(params: &mut Params, key: &str, val: Option<String>) {
    if let Some(v) = val {
        if !v.is_empty() {
            params.insert(key.to_string(), v);
        }
    }
}

/// Sorted `k=v` join — canonical form used for fingerprints.
pub fn canonical_string(params: &Params) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(";")
}

/// Transport network for a dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// A bidirectional stream connection produced by a `Dialer`.
pub trait Conn: std::io::Read + std::io::Write + Send {}

impl<T: std::io::Read + std::io::Write + Send> Conn for T {}

pub type BoxConn = Box<dyn Conn>;

/// A tunnel connection that can be split into independent read/write
/// halves — required for two-thread relaying (each thread pumps one
/// direction). Implementations own their crypto state per direction.
pub trait TunnelConn: Conn {
    fn split_rw(
        self: Box<Self>,
    ) -> (
        Box<dyn std::io::Read + Send>,
        Box<dyn std::io::Write + Send>,
    );
}

pub type BoxTunnel = Box<dyn TunnelConn>;

/// A plain-TCP tunnel conn (used for direct connections and tests).
pub struct TcpConn(pub TcpStream);

impl std::io::Read for TcpConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for TcpConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl TunnelConn for TcpConn {
    fn split_rw(
        self: Box<Self>,
    ) -> (
        Box<dyn std::io::Read + Send>,
        Box<dyn std::io::Write + Send>,
    ) {
        let r = self.0.try_clone().expect("tcp try_clone");
        (Box::new(r), Box::new(self.0))
    }
}

/// Produces connections whose traffic exits at the tunnel endpoint.
pub trait Dialer: Send + Sync {
    fn dial(&self, net: Network, addr: &str) -> std::io::Result<BoxTunnel>;
}

/// Driver lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Connecting,
    Connected,
    Closed,
    Error,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            State::Idle => "idle",
            State::Connecting => "connecting",
            State::Connected => "connected",
            State::Closed => "closed",
            State::Error => "error",
        })
    }
}

/// A configured protocol instance.
pub trait Driver: Send {
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn stop(&mut self);
    fn state(&self) -> State;
    fn dialer(&self) -> std::sync::Arc<dyn Dialer>;
}

type DriverFactory = fn(&Params) -> Result<Box<dyn Driver>, String>;

/// Global protocol driver registry.
pub struct Registry {
    factories: std::sync::Mutex<std::collections::HashMap<String, DriverFactory>>,
}

impl Registry {
    fn empty() -> Registry {
        Registry {
            factories: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    pub fn global() -> &'static Registry {
        static REG: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
        REG.get_or_init(Registry::empty)
    }
    pub fn register(&self, tag: &str, f: DriverFactory) {
        self.factories.lock().unwrap().insert(tag.to_string(), f);
    }
    pub fn new(&self, tag: &str, params: &Params) -> Result<Box<dyn Driver>, String> {
        let f = { self.factories.lock().unwrap().get(tag).copied() };
        match f {
            Some(f) => f(params),
            None => Err(format!("proto: unknown protocol {:?}", tag)),
        }
    }
    pub fn tags(&self) -> Vec<String> {
        let mut v: Vec<String> = self.factories.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoopDriver;
    impl Driver for NoopDriver {
        fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn stop(&mut self) {}
        fn state(&self) -> State {
            State::Idle
        }
        fn dialer(&self) -> std::sync::Arc<dyn Dialer> {
            unreachable!()
        }
    }
    fn factory(_p: &Params) -> Result<Box<dyn Driver>, String> {
        Ok(Box::new(NoopDriver))
    }

    #[test]
    fn registry_roundtrip() {
        let reg = Registry::global();
        reg.register("test-noop", factory);
        assert!(reg.new("test-noop", &Params::new()).is_ok());
        assert!(reg.new("missing", &Params::new()).is_err());
    }
    #[test]
    fn canonical_is_sorted() {
        let mut p = Params::new();
        p.insert("b".into(), "2".into());
        p.insert("a".into(), "1".into());
        assert_eq!(canonical_string(&p), "a=1;b=2");
    }
}
