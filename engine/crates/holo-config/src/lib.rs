//! holo-config — profiles, settings (incl. Material You theme seed) and the
//! store. Importers (Clash/V2Ray/sing-box/links/WireGuard INI) were part of
//! the full engine (see docs/RESTORE.md); this core keeps the link parser
//! so `configs.import` works for share URLs out of the box.
pub mod links;

use holo_proto::Params;
use holo_util::json::{self, Value};

/// One connectable entry (server + protocol + credentials).
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub source: String,
    pub driver: String,
    pub server: String,
    pub port: u16,
    pub params: Params,
    pub meta: Params,
}

impl Profile {
    pub fn new(driver: &str, server: &str, port: u16) -> Profile {
        Profile {
            id: new_id(),
            name: String::new(),
            source: String::new(),
            driver: driver.to_string(),
            server: server.to_string(),
            port,
            params: Params::new(),
            meta: Params::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Profile {
        let n: String = name.into();
        if !n.is_empty() {
            self.name = n;
        }
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Profile {
        self.source = source.into();
        self
    }

    /// Deterministic content fingerprint (dedupe across imports).
    pub fn fingerprint(&self) -> String {
        let mut kv: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        kv.sort();
        holo_util::hex_encode(
            format!(
                "{}|{}|{}|{}",
                self.driver,
                self.server,
                self.port,
                kv.join(";")
            )
            .as_bytes(),
        )
    }

    pub fn to_json(&self) -> Value {
        let params = Value::Obj(
            self.params
                .iter()
                .map(|(k, v)| (k.clone(), Value::s(v.clone())))
                .collect(),
        );
        let meta = Value::Obj(
            self.meta
                .iter()
                .map(|(k, v)| (k.clone(), Value::s(v.clone())))
                .collect(),
        );
        Value::obj(vec![
            ("id", Value::s(self.id.clone())),
            ("name", Value::s(self.name.clone())),
            ("source", Value::s(self.source.clone())),
            ("driver", Value::s(self.driver.clone())),
            ("server", Value::s(self.server.clone())),
            ("port", Value::n(self.port as f64)),
            ("params", params),
            ("meta", meta),
        ])
    }

    pub fn from_json(v: &Value) -> Result<Profile, String> {
        let mut p = Profile::new(
            v.str_or("driver", ""),
            v.str_or("server", ""),
            v.get("port")
                .and_then(|x| x.as_i64())
                .unwrap_or(0)
                .clamp(0, 65535) as u16,
        );
        p.id = v.str_or("id", "").to_string();
        p.name = v.str_or("name", "").to_string();
        p.source = v.str_or("source", "").to_string();
        if p.driver.is_empty() {
            return Err("config: profile has no driver".into());
        }
        if let Some(Value::Obj(m)) = v.get("params") {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    p.params.insert(k.clone(), s.to_string());
                }
            }
        }
        if let Some(Value::Obj(m)) = v.get("meta") {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    p.meta.insert(k.clone(), s.to_string());
                }
            }
        }
        Ok(p)
    }
}

pub fn new_id() -> String {
    holo_util::rand::hex(8)
}

// ---------------------------------------------------------------------------
// Settings (Material You aware)
// ---------------------------------------------------------------------------

/// Application settings. `theme_mode` = system|dark|light, `seed_color` =
/// the Material You seed (`#RRGGBB`), `dynamic_color` = use the platform
/// wallpaper palette (Android 12+) when available.
#[derive(Debug, Clone)]
pub struct Settings {
    pub values: Params,
}

impl Default for Settings {
    fn default() -> Self {
        let mut v = Params::new();
        v.insert("theme_mode".into(), "system".into());
        v.insert("seed_color".into(), "#6750A4".into());
        v.insert("dynamic_color".into(), "true".into());
        v.insert("mode".into(), "vpn".into());
        v.insert("proxy_listen".into(), "127.0.0.1:2080".into());
        v.insert("kill_switch".into(), "false".into());
        v.insert("bypass_lan".into(), "true".into());
        v.insert("auto_connect".into(), "false".into());
        v.insert("mtu".into(), "1420".into());
        Settings { values: v }
    }
}

impl Settings {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }
    pub fn set(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.values.insert(key.into(), val.into());
    }

    pub fn to_json(&self) -> Value {
        Value::Obj(
            self.values
                .iter()
                .map(|(k, v)| (k.clone(), Value::s(v.clone())))
                .collect(),
        )
    }
    pub fn from_json(v: &Value) -> Settings {
        let mut s = Settings::default();
        if let Some(Value::Obj(m)) = v.get("values").or(match v {
            Value::Obj(_) => Some(v),
            _ => None,
        }) {
            for (k, val) in m {
                if let Some(sval) = val.as_str() {
                    s.values.insert(k.clone(), sval.to_string());
                }
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct Store {
    pub dir: std::path::PathBuf,
}

impl Store {
    pub fn new(dir: &std::path::Path) -> Store {
        Store {
            dir: dir.to_path_buf(),
        }
    }

    fn read(&self, name: &str) -> Option<Value> {
        let text = std::fs::read_to_string(self.dir.join(name)).ok()?;
        json::parse(&text).ok()
    }

    fn write(&self, name: &str, v: &Value) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let p = self.dir.join(name);
        std::fs::write(&p, v.to_json()).map_err(|e| e.to_string())?;
        // profiles.json carries credentials (incl. WireGuard private keys):
        // owner-only at rest — gate-0001 A2-F6
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn load_profiles(&self) -> Vec<Profile> {
        let Some(v) = self.read("profiles.json") else {
            return Vec::new();
        };
        let Some(arr) = v.as_arr() else {
            return Vec::new();
        };
        arr.iter()
            .filter_map(|p| Profile::from_json(p).ok())
            .collect()
    }

    pub fn save_profiles(&self, profiles: &[Profile]) -> Result<(), String> {
        self.write(
            "profiles.json",
            &Value::Arr(profiles.iter().map(|p| p.to_json()).collect()),
        )
    }

    pub fn add_profile(&self, p: Profile) -> Result<(), String> {
        let mut all = self.load_profiles();
        if let Some(slot) = all.iter_mut().find(|x| x.id == p.id) {
            *slot = p;
        } else {
            all.push(p);
        }
        self.save_profiles(&all)
    }

    pub fn remove_profile(&self, id: &str) -> Result<bool, String> {
        let all = self.load_profiles();
        let filtered: Vec<Profile> = all.iter().filter(|p| p.id != id).cloned().collect();
        if filtered.len() == all.len() {
            return Ok(false);
        }
        self.save_profiles(&filtered)?;
        Ok(true)
    }

    pub fn load_settings(&self) -> Settings {
        match self.read("settings.json") {
            Some(v) => Settings::from_json(&v),
            None => Settings::default(),
        }
    }

    pub fn save_settings(&self, s: &Settings) -> Result<(), String> {
        let v = Value::obj(vec![("values", s.to_json())]);
        self.write("settings.json", &v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_roundtrip_and_store() {
        let dir = std::env::temp_dir().join(format!("holonet-cfg-{}", new_id()));
        let store = Store::new(&dir);
        let mut p = Profile::new("shadowsocks", "example.com", 8388)
            .with_name("Test")
            .with_source("import:links");
        p.params.insert("method".into(), "aes-256-gcm".into());
        p.params.insert("password".into(), "secret".into());
        store.add_profile(p.clone()).unwrap();
        let all = store.load_profiles();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Test");
        assert_eq!(
            all[0].params.get("method").map(String::as_str),
            Some("aes-256-gcm")
        );
        assert!(store.remove_profile(&all[0].id).unwrap());
        assert!(store.load_profiles().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn settings_material_you_defaults() {
        let s = Settings::default();
        assert_eq!(s.get("theme_mode"), Some("system"));
        assert_eq!(s.get("seed_color"), Some("#6750A4"));
        assert_eq!(s.get("dynamic_color"), Some("true"));
    }

    #[test]
    fn fingerprint_deterministic() {
        let mut p = Profile::new("trojan", "a.com", 443);
        p.params.insert("password".into(), "x".into());
        assert_eq!(p.fingerprint(), p.fingerprint());
        p.params.insert("k".into(), "v".into());
        assert_ne!(
            p.fingerprint(),
            Profile::new("trojan", "a.com", 443).fingerprint()
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn secrets_at_rest_are_owner_only() {
        // gate-0001 A2-F6: written stores must be 0600 on unix
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("holonet-cfg-perm-{}", new_id()));
        let store = Store::new(&dir);
        let mut p = Profile::new("shadowsocks", "example.com", 8388);
        p.params.insert("password".into(), "secret".into());
        store.add_profile(p).unwrap();
        let mode = std::fs::metadata(dir.join("profiles.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "profiles.json must be owner-only");
        let _ = std::fs::remove_dir_all(dir);
    }
}
