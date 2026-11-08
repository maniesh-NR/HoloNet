//! holonetd — the HoloNet daemon (core): IPC + Material You theme service.
use std::net::TcpListener;

fn main() {
    println!("HoloNet daemon (holonetd) 0.2.0 — GPL-3.0");
    let data_dir = std::env::var("HOLONET_DATA").unwrap_or_else(|_| {
        format!("{}/.config/holonet", std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
    });
    let data_dir = std::path::PathBuf::from(data_dir);
    println!("data dir: {}", data_dir.display());
    std::fs::create_dir_all(&data_dir).ok();

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
    println!(
        "control channel listening on {addr} (token file: <dataDir>/ipc-token)",
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
