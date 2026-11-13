//! holonetctl — CLI control utility (state/list/import/theme/settings).
fn send(c: &mut holo_engine::IpcClient, method: &str, params: &str) {
    match c.request(method, params) {
        Ok(r) => println!("{}", r),
        Err(e) => eprintln!("error: {}", e),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: holonetctl <state|list|import <link>|theme [dark|light]|seed <hex>|connect <id>|disconnect> [--addr 127.0.0.1:7977]");
        std::process::exit(2);
    }
    let mut addr = format!("127.0.0.1:{}", holo_engine::DEFAULT_TCP_PORT);
    let mut pos: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--addr" {
            if let Some(v) = it.next() {
                addr = v.clone();
            }
        } else {
            pos.push(a.clone());
        }
    }

    let data_dir = std::env::var("HOLONET_DATA").unwrap_or_else(|_| {
        format!(
            "{}/.config/holonet",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
        )
    });
    // fail-closed entropy must stay VISIBLE on the CLI too (gate-0001
    // A1-C6): unwrap_or_default() would turn an entropy failure into a
    // misleading "bad token" auth error one step later
    let token = match holo_engine::ensure_token(std::path::Path::new(&data_dir)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("holonetctl: cannot read/create IPC token in {data_dir}: {e}");
            std::process::exit(1);
        }
    };
    let mut c = match holo_engine::IpcClient::connect(&addr, &token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "cannot reach daemon at {addr}: {} (is holonetd running?)",
                e
            );
            std::process::exit(1);
        }
    };
    match pos[0].as_str() {
        "state" => send(&mut c, "state.get", "{}"),
        "list" => send(&mut c, "profiles.list", "{}"),
        "theme" => {
            let os = pos.get(1).map(|s| s.as_str()).unwrap_or("light");
            let body = format!("{{\"osTheme\":\"{}\"}}", os);
            send(&mut c, "theme.get", &body);
        }
        "seed" => {
            let hex = pos.get(1).map(|s| s.as_str()).unwrap_or("#6750A4");
            let body = format!("{{\"values\":{{\"seed_color\":\"{}\"}}}}", hex);
            send(&mut c, "settings.set", &body);
        }
        "connect" => {
            let id = pos.get(1).map(|s| s.as_str()).unwrap_or("");
            let body = format!("{{\"profileId\":\"{}\"}}", id);
            send(&mut c, "session.connect", &body);
        }
        "disconnect" => send(&mut c, "session.disconnect", "{}"),
        "import" => {
            let data = pos.get(1).map(|s| s.as_str()).unwrap_or("");
            let body = format!(
                "{{\"kind\":\"auto\",\"data\":\"{}\"}}",
                data.replace('"', "\\\"")
            );
            send(&mut c, "configs.import", &body);
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    }
}
