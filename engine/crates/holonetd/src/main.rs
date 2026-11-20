#![forbid(unsafe_code)] // D-0008 containment: compile-time-enforced; the ONLY exception is holo-util/src/rand.rs (Windows entropy FFI)

//! holonetd — the HoloNet daemon (core): IPC + Material You theme service.
use std::net::TcpListener;

/// Data-dir resolution (S1 item 0, A2-C2 / progress review 0002):
/// HOLONET_DATA → HOME → USERPROFILE → hard error. NEVER falls back to
/// the CWD: `ipc-token`/`profiles.json` must not land in a
/// working-directory-dependent location with unpredictable ACLs.
fn resolve_data_dir() -> Result<std::path::PathBuf, String> {
    if let Ok(d) = std::env::var("HOLONET_DATA") {
        if !d.trim().is_empty() {
            return Ok(std::path::PathBuf::from(d));
        }
    }
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            "no home directory: set HOME/USERPROFILE or HOLONET_DATA \
             (refusing to write secrets relative to the CWD)"
                .to_string()
        })?;
    Ok(std::path::PathBuf::from(format!("{}/.config/holonet", base)))
}

fn main() {
    println!("HoloNet daemon (holonetd) 0.3.0 — GPL-3.0");
    let data_dir = match resolve_data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    };
    println!("data dir: {}", data_dir.display());
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("fatal: cannot create data dir {}: {e}", data_dir.display());
        std::process::exit(1);
    }

    let store = holo_config::Store::new(&data_dir);
    let engine = holo_engine::Engine::new(store);
    let token = match holo_engine::ensure_token(&data_dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fatal: cannot create IPC token: {e}");
            std::process::exit(1);
        }
    };

    let addr = format!("127.0.0.1:{}", holo_engine::DEFAULT_TCP_PORT);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fatal: cannot bind {addr}: {e} (is another holonetd running?)");
            std::process::exit(1);
        }
    };
    let events = engine.take_event_receiver().unwrap();
    holo_engine::serve_ipc(engine.clone(), listener, token, events);
    let st = engine.settings.lock().unwrap();
    println!("control channel listening on {addr} (token file: <dataDir>/ipc-token)",);
    println!(
        "proxy: {} (live: shadowsocks AEAD; others report milestones)",
        st.get("proxy_listen").unwrap_or("127.0.0.1:2080"),
    );
    println!(
        "Material You: mode={} seed={} dynamic={}",
        st.get("theme_mode").unwrap_or("system"),
        st.get("seed_color").unwrap_or("#6750A4"),
        st.get("dynamic_color").unwrap_or("true"),
    );
    drop(st);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_data_dir;

    // env-mutating tests: this bin's test target is single-test, and test
    // binaries are separate processes — save/restore keeps it hermetic.
    #[test]
    fn data_dir_resolution_order_and_no_cwd_fallback() {
        // 1) HOLONET_DATA wins
        std::env::set_var("HOLONET_DATA", "/tmp/holonet-test-data-dir");
        assert_eq!(
            resolve_data_dir().unwrap(),
            std::path::PathBuf::from("/tmp/holonet-test-data-dir")
        );
        // 2) with nothing resolvable: hard Err, NEVER "."
        let saved_home = std::env::var("HOME").ok();
        let saved_prof = std::env::var("USERPROFILE").ok();
        std::env::remove_var("HOLONET_DATA");
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");
        match resolve_data_dir() {
            Ok(p) => panic!("must error without a home dir, got {}", p.display()),
            Err(e) => assert!(e.contains("refusing"), "error must explain the refusal: {e}"),
        }
        // 3) HOME fallback restores a path (not CWD)
        std::env::set_var("HOME", "/tmp/holonet-test-home");
        let p = resolve_data_dir().unwrap();
        assert!(p.starts_with("/tmp/holonet-test-home"), "got {}", p.display());
        // restore the environment for any later test in this binary
        std::env::remove_var("HOME");
        std::env::remove_var("HOLONET_DATA");
        if let Some(h) = saved_home {
            std::env::set_var("HOME", h);
        }
        if let Some(u) = saved_prof {
            std::env::set_var("USERPROFILE", u);
        }
    }
}
