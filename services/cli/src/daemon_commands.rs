use super::*;
use qrcode::QrCode;
use qrcode::render::unicode;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::net::IpAddr;
use std::net::UdpSocket;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonProcessState {
    pid: u32,
    endpoint: String,
    started_at_unix_ms: u64,
}

pub(super) fn run_daemon(command: DaemonCommand, state_path: &Path) -> Result<String> {
    let mut state = load_state(state_path)?;
    match command.command {
        DaemonSubcommand::Up(args) => daemon_up(state_path, &mut state, args),
        DaemonSubcommand::Down => daemon_down(state_path, &state),
        DaemonSubcommand::Restart(args) => daemon_restart(state_path, &mut state, args),
        DaemonSubcommand::Status => daemon_status(state_path, &state),
        DaemonSubcommand::Logs(args) => daemon_logs(state_path, args),
    }
}

fn daemon_up(state_path: &Path, state: &mut CliState, args: DaemonUpArgs) -> Result<String> {
    let pid_path = daemon_pid_path(state_path)?;
    let log_path = daemon_log_path(state_path)?;
    let listen_endpoint = resolve_daemon_listen_endpoint(state_path, state, args)?;
    let daemon_bind = daemon_bind_for_endpoint(&listen_endpoint)?;
    let codex_app_server_endpoint = derive_internal_app_server_endpoint(&listen_endpoint);

    if daemon_is_healthy(&listen_endpoint, state.config.auth_token.as_deref()) {
        return Ok(format!(
            "daemon is already healthy at {}\n\n{}",
            listen_endpoint,
            format_daemon_websocket_qr_output(&listen_endpoint)
        ));
    }

    if let Some(existing) = load_daemon_process_state(&pid_path)? {
        if process_exists(existing.pid) {
            return Ok(format!(
                "daemon is already running (pid {}) at {}\n\n{}",
                existing.pid,
                existing.endpoint,
                format_daemon_websocket_qr_output(&existing.endpoint)
            ));
        }
        clear_daemon_process_state(&pid_path)?;
    }

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create daemon state dir {}", parent.display()))?;
    }
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open daemon log {}", log_path.display()))?;
    let stderr_log = log_file
        .try_clone()
        .with_context(|| format!("clone daemon log handle {}", log_path.display()))?;

    let child = spawn_daemon_process(
        &daemon_bind,
        &codex_app_server_endpoint,
        &log_file,
        &stderr_log,
    )?;
    let pid = child.id();

    save_daemon_process_state(
        &pid_path,
        &DaemonProcessState {
            pid,
            endpoint: listen_endpoint.clone(),
            started_at_unix_ms: now_unix_ms(),
        },
    )?;

    for _ in 0..30 {
        if daemon_is_healthy(&listen_endpoint, state.config.auth_token.as_deref()) {
            return Ok(format!(
                "daemon started (pid {pid}) at {} (log: {})\n\n{}",
                listen_endpoint,
                log_path.display(),
                format_daemon_websocket_qr_output(&listen_endpoint)
            ));
        }
        if !process_exists(pid) {
            clear_daemon_process_state(&pid_path)?;
            bail!(
                "daemon exited before becoming healthy; inspect {}",
                log_path.display()
            );
        }
        thread::sleep(Duration::from_millis(200));
    }

    Ok(format!(
        "daemon started (pid {pid}) but health check timed out for {}; log: {}\n\n{}",
        listen_endpoint,
        log_path.display(),
        format_daemon_websocket_qr_output(&listen_endpoint)
    ))
}

fn daemon_down(state_path: &Path, state: &CliState) -> Result<String> {
    let pid_path = daemon_pid_path(state_path)?;
    let saved = load_daemon_process_state(&pid_path)?;

    if let Some(process) = saved {
        if process_exists(process.pid) {
            terminate_process(process.pid, "TERM")?;
            for _ in 0..20 {
                if !process_exists(process.pid) {
                    clear_daemon_process_state(&pid_path)?;
                    return Ok(format!("daemon stopped (pid {})", process.pid));
                }
                thread::sleep(Duration::from_millis(100));
            }
            terminate_process(process.pid, "KILL")?;
            clear_daemon_process_state(&pid_path)?;
            return Ok(format!("daemon force-stopped (pid {})", process.pid));
        }
        clear_daemon_process_state(&pid_path)?;
        return Ok("daemon was not running (stale pid state removed)".to_string());
    }

    if daemon_is_healthy(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
    ) {
        if let Some(pid) = find_unmanaged_daemon_pid(&state.config.daemon_endpoint)? {
            terminate_process(pid, "TERM")?;
            for _ in 0..20 {
                if !process_exists(pid) {
                    return Ok(format!("daemon stopped (unmanaged pid {pid})"));
                }
                thread::sleep(Duration::from_millis(100));
            }
            terminate_process(pid, "KILL")?;
            return Ok(format!("daemon force-stopped (unmanaged pid {pid})"));
        }
        return Ok(format!(
            "daemon is healthy at {} but pid auto-detection failed",
            state.config.daemon_endpoint
        ));
    }

    Ok("daemon is not running".to_string())
}

fn daemon_restart(state_path: &Path, state: &mut CliState, args: DaemonUpArgs) -> Result<String> {
    let stop_output = daemon_down(state_path, state)?;
    let start_output = daemon_up(state_path, state, args)?;
    Ok(format!("{stop_output}\n{start_output}"))
}

fn daemon_status(state_path: &Path, state: &CliState) -> Result<String> {
    let pid_path = daemon_pid_path(state_path)?;
    let saved = load_daemon_process_state(&pid_path)?;
    let healthy = daemon_is_healthy(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
    );

    if let Some(process) = saved {
        let running = process_exists(process.pid);
        return Ok(format!(
            "daemon: {}\nendpoint: {}\npid: {}\nhealth: {}\n\n{}",
            if running {
                "up"
            } else {
                "down (stale pid state)"
            },
            process.endpoint,
            process.pid,
            if healthy { "ok" } else { "unhealthy" },
            format_daemon_websocket_qr_output(&process.endpoint)
        ));
    }

    if healthy {
        let unmanaged_pid = find_unmanaged_daemon_pid(&state.config.daemon_endpoint)?;
        let pid_display = unmanaged_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        return Ok(format!(
            "daemon: up (unmanaged)\nendpoint: {}\npid: {}\nhealth: ok\n\n{}",
            state.config.daemon_endpoint,
            pid_display,
            format_daemon_websocket_qr_output(&state.config.daemon_endpoint)
        ));
    }

    Ok(format!(
        "daemon: {}\nendpoint: {}\npid: n/a\nhealth: {}\n\n{}",
        "down",
        state.config.daemon_endpoint,
        "unhealthy",
        format_daemon_websocket_qr_output(&state.config.daemon_endpoint)
    ))
}

fn websocket_url_for_daemon_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if let Some(rest) = trimmed.strip_prefix("http://") {
        return format!("ws://{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        return format!("wss://{rest}");
    }
    trimmed.to_string()
}

fn daemon_bind_for_endpoint(endpoint: &str) -> Result<String> {
    let (_, authority, _) = split_endpoint(endpoint)
        .ok_or_else(|| anyhow!("invalid daemon endpoint for bind resolution: {endpoint}"))?;
    Ok(authority)
}

fn spawn_daemon_process(
    daemon_bind: &str,
    codex_app_server_endpoint: &str,
    log_file: &fs::File,
    stderr_log: &fs::File,
) -> Result<std::process::Child> {
    let mut candidates = Vec::new();
    if let Ok(bin) = env::var("CRABBOT_DAEMON_BIN")
        && !bin.trim().is_empty()
    {
        candidates.push(bin);
    }
    if let Ok(current_exe) = env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        candidates.push(dir.join("crabbot_daemon").display().to_string());
    }
    candidates.push("crabbot_daemon".to_string());

    let mut last_error: Option<anyhow::Error> = None;
    for bin in candidates {
        let spawn_result = Command::new(&bin)
            .env("CRABBOT_DAEMON_BIND", daemon_bind)
            .env(
                "CRABBOT_CODEX_APP_SERVER_ENDPOINT",
                codex_app_server_endpoint,
            )
            .env("CRABBOT_DAEMON_SPAWN_CODEX_APP_SERVER", "true")
            .env("CRABBOT_CODEX_BIN", "codex")
            .stdin(Stdio::null())
            .stdout(
                log_file
                    .try_clone()
                    .with_context(|| format!("clone daemon log handle for {bin}"))?,
            )
            .stderr(
                stderr_log
                    .try_clone()
                    .with_context(|| format!("clone daemon stderr handle for {bin}"))?,
            )
            .spawn();

        match spawn_result {
            Ok(child) => return Ok(child),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                last_error = Some(anyhow!("daemon binary not found: {bin}"));
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("start daemon via {bin}"));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("unable to start crabbot_daemon")))
}

fn derive_internal_app_server_endpoint(listen_endpoint: &str) -> String {
    let relay_port = split_endpoint(listen_endpoint)
        .and_then(|(_, authority, _)| parse_port_from_authority(&authority))
        .filter(|port| *port < u16::MAX)
        .map(|port| port + 1)
        .unwrap_or(8789);
    format!("ws://127.0.0.1:{relay_port}")
}

fn parse_port_from_authority(authority: &str) -> Option<u16> {
    if authority.starts_with('[') {
        let idx = authority.rfind("]:")?;
        authority.get(idx + 2..)?.parse::<u16>().ok()
    } else {
        let (_, port) = authority.rsplit_once(':')?;
        port.parse::<u16>().ok()
    }
}

fn resolve_daemon_listen_endpoint(
    state_path: &Path,
    state: &mut CliState,
    args: DaemonUpArgs,
) -> Result<String> {
    let configured = state.config.daemon_endpoint.trim().to_string();
    let host = resolve_bind_host(&args)?;
    let mut endpoint = replace_endpoint_host(&configured, &host).ok_or_else(|| {
        anyhow!("cannot replace endpoint host in configured daemon endpoint: {configured}")
    })?;
    if let Some(port) = args.port {
        endpoint = replace_endpoint_port(&endpoint, port).ok_or_else(|| {
            anyhow!("cannot replace endpoint port in configured daemon endpoint: {endpoint}")
        })?;
    }

    if endpoint != state.config.daemon_endpoint {
        state.config.daemon_endpoint = endpoint.clone();
        save_state(state_path, state)?;
    }

    Ok(endpoint)
}

fn resolve_bind_host(args: &DaemonUpArgs) -> Result<String> {
    if args.tailscale {
        return detect_tailscale_ipv4()
            .ok_or_else(|| anyhow!("cannot detect tailscale IPv4; try --wifi, --local, or --all"));
    }
    if args.local {
        return Ok("127.0.0.1".to_string());
    }
    if args.bind_all {
        return Ok("0.0.0.0".to_string());
    }
    if args.wifi {
        return detect_wifi_ipv4()
            .ok_or_else(|| anyhow!("cannot detect Wi-Fi/LAN IPv4; try --local or --all"));
    }

    // Default mode is Wi-Fi/LAN. If detection fails, fall back to localhost.
    Ok(detect_wifi_ipv4().unwrap_or_else(|| "127.0.0.1".to_string()))
}

fn detect_tailscale_ipv4() -> Option<String> {
    let output = Command::new("tailscale").args(["ip", "-4"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| is_plain_ipv4(line))
        .map(ToString::to_string)
}

fn detect_wifi_ipv4() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip.to_string()),
        _ => None,
    }
}

fn is_plain_ipv4(value: &str) -> bool {
    let mut parts = value.split('.');
    for _ in 0..4 {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.is_empty() || part.parse::<u8>().is_err() {
            return false;
        }
    }
    parts.next().is_none()
}

#[cfg(test)]
fn endpoint_host_is_local(endpoint: &str) -> bool {
    let Some((_, authority, _)) = split_endpoint(endpoint) else {
        return false;
    };
    let host = authority
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn replace_endpoint_host(endpoint: &str, host: &str) -> Option<String> {
    let (scheme, authority, suffix) = split_endpoint(endpoint)?;
    let port = if authority.starts_with('[') {
        authority
            .rfind("]:")
            .and_then(|idx| authority.get(idx + 2..))
            .filter(|port| !port.is_empty())
            .map(ToString::to_string)?
    } else if let Some((_, port)) = authority.rsplit_once(':') {
        if port.is_empty() {
            return None;
        }
        port.to_string()
    } else {
        return None;
    };
    Some(format!("{scheme}://{host}:{port}{suffix}"))
}

fn replace_endpoint_port(endpoint: &str, port: u16) -> Option<String> {
    let (scheme, authority, suffix) = split_endpoint(endpoint)?;
    let host = if authority.starts_with('[') {
        let idx = authority.rfind("]:")?;
        authority.get(..=idx)?.to_string()
    } else {
        let (host, _) = authority.rsplit_once(':')?;
        host.to_string()
    };
    Some(format!("{scheme}://{host}:{port}{suffix}"))
}

fn split_endpoint(endpoint: &str) -> Option<(String, String, String)> {
    let trimmed = endpoint.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    let (authority, path_and_more) = if let Some((authority, suffix)) = rest.split_once('/') {
        (authority, format!("/{suffix}"))
    } else {
        (rest, String::new())
    };
    if authority.is_empty() {
        return None;
    }
    Some((scheme.to_string(), authority.to_string(), path_and_more))
}

fn render_qr_code(text: &str) -> String {
    match QrCode::new(text.as_bytes()) {
        Ok(code) => code.render::<unicode::Dense1x2>().quiet_zone(true).build(),
        Err(error) => format!("(qr unavailable: {error})"),
    }
}

fn format_daemon_websocket_qr_output(endpoint: &str) -> String {
    let websocket_url = websocket_url_for_daemon_endpoint(endpoint);
    let qr = render_qr_code(&websocket_url);
    format!("websocket_url: {websocket_url}\nqr:\n{qr}")
}

fn daemon_logs(state_path: &Path, args: DaemonLogsArgs) -> Result<String> {
    let log_path = daemon_log_path(state_path)?;
    if !log_path.exists() {
        return Ok(format!("daemon log not found at {}", log_path.display()));
    }

    let initial = read_log_tail(&log_path, args.tail)?;
    if !args.no_follow {
        if !initial.is_empty() {
            print!("{initial}");
            io::stdout().flush().context("flush daemon log output")?;
        }
        follow_log_file(&log_path)?;
        return Ok(String::new());
    }

    Ok(initial)
}

fn read_log_tail(path: &Path, tail_lines: usize) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if tail_lines == 0 {
        return Ok(String::new());
    }
    let mut lines: Vec<&str> = raw.lines().collect();
    if lines.len() > tail_lines {
        lines = lines.split_off(lines.len() - tail_lines);
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

fn follow_log_file(path: &Path) -> Result<()> {
    let mut position = fs::metadata(path)
        .with_context(|| format!("read metadata {}", path.display()))?
        .len();

    loop {
        thread::sleep(Duration::from_millis(250));
        let length = fs::metadata(path)
            .with_context(|| format!("read metadata {}", path.display()))?
            .len();

        if length < position {
            position = 0;
        }
        if length == position {
            continue;
        }

        let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        file.seek(SeekFrom::Start(position))
            .with_context(|| format!("seek {}", path.display()))?;
        let mut chunk = String::new();
        file.read_to_string(&mut chunk)
            .with_context(|| format!("read {}", path.display()))?;
        position = length;

        if !chunk.is_empty() {
            print!("{chunk}");
            io::stdout().flush().context("flush daemon log output")?;
        }
    }
}

fn daemon_pid_path(state_path: &Path) -> Result<PathBuf> {
    let dir = state_path.parent().ok_or_else(|| {
        anyhow!(
            "cannot resolve daemon state dir from path {}",
            state_path.display()
        )
    })?;
    Ok(dir.join("daemon-process.json"))
}

fn daemon_log_path(state_path: &Path) -> Result<PathBuf> {
    let dir = state_path.parent().ok_or_else(|| {
        anyhow!(
            "cannot resolve daemon state dir from path {}",
            state_path.display()
        )
    })?;
    Ok(dir.join("daemon.log"))
}

fn load_daemon_process_state(path: &Path) -> Result<Option<DaemonProcessState>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let state: DaemonProcessState = serde_json::from_str(&raw)
        .with_context(|| format!("parse daemon process state from {}", path.display()))?;
    Ok(Some(state))
}

fn save_daemon_process_state(path: &Path, state: &DaemonProcessState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create daemon state dir {}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(state).context("serialize daemon process state")?;
    fs::write(path, payload).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn clear_daemon_process_state(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn process_exists(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn terminate_process(pid: u32, signal: &str) -> Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .with_context(|| format!("send SIG{signal} to pid {pid}"))?;
    if status.success() {
        return Ok(());
    }
    bail!("failed to send SIG{signal} to pid {pid}")
}

fn find_unmanaged_daemon_pid(endpoint: &str) -> Result<Option<u32>> {
    let daemon_output = Command::new("pgrep")
        .args(["-af", "crabbot_daemon"])
        .output()
        .context("run pgrep for crabbot_daemon")?;
    if daemon_output.status.success() {
        let stdout = String::from_utf8_lossy(&daemon_output.stdout);
        for line in stdout.lines() {
            let mut parts = line.trim().splitn(2, char::is_whitespace);
            let pid_raw = parts.next().unwrap_or_default();
            let cmdline = parts.next().unwrap_or_default();
            if cmdline.contains("crabbot_daemon")
                && !cmdline.contains("pgrep")
                && let Ok(pid) = pid_raw.parse::<u32>()
            {
                return Ok(Some(pid));
            }
        }
    }

    let output = Command::new("pgrep")
        .args(["-af", "codex app-server"])
        .output()
        .context("run pgrep for codex app-server")?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let mut parts = line.trim().splitn(2, char::is_whitespace);
        let pid_raw = parts.next().unwrap_or_default();
        let cmdline = parts.next().unwrap_or_default();
        if cmdline.contains("codex app-server")
            && cmdline.contains("--listen")
            && cmdline.contains(endpoint)
            && let Ok(pid) = pid_raw.parse::<u32>()
        {
            return Ok(Some(pid));
        }
    }

    Ok(None)
}

#[cfg(test)]
pub(super) fn websocket_url_for_daemon_endpoint_for_test(endpoint: &str) -> String {
    websocket_url_for_daemon_endpoint(endpoint)
}

#[cfg(test)]
pub(super) fn format_daemon_websocket_qr_output_for_test(endpoint: &str) -> String {
    format_daemon_websocket_qr_output(endpoint)
}

#[cfg(test)]
pub(super) fn replace_endpoint_host_for_test(endpoint: &str, host: &str) -> Option<String> {
    replace_endpoint_host(endpoint, host)
}

#[cfg(test)]
pub(super) fn endpoint_host_is_local_for_test(endpoint: &str) -> bool {
    endpoint_host_is_local(endpoint)
}

#[cfg(test)]
pub(super) fn replace_endpoint_port_for_test(endpoint: &str, port: u16) -> Option<String> {
    replace_endpoint_port(endpoint, port)
}
