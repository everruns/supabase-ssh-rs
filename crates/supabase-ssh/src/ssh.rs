use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::bash::create_bash;
use crate::cache::{CachedResult, CommandCache};
use crate::line_editor::{LineEditor, LineEvent};
use crate::session::run_shell_session;

const LOGO: &str = "\
 ____                    _                    \r\n\
/ ___| _   _ _ __   __ _| |__   __ _ ___  ___ \r\n\
\\___ \\| | | | '_ \\ /  ` | '_ \\ / _` / __|/ _ \\\r\n\
 ___) | |_| | |_) | (_| | |_) | (_| \\__ \\  __/\r\n\
|____/ \\__,_| .__/ \\__,_|_.__/ \\__,_|___/\\___|\r\n\
            |_|";

fn banner() -> String {
    let green = "\x1b[38;2;62;207;142m";
    let dim = "\x1b[2m";
    let bg = "\x1b[48;2;50;50;50m";
    let reset = "\x1b[0m";

    format!(
        "{green}{LOGO}{reset}\r\n\r\n\
         Docs-over-SSH lets your agent browse Supabase documentation directly using bash.\r\n\r\n\
         Tell your agent to use {dim}ssh supabase.sh <command>{reset} to search the docs:\r\n\r\n\
         {bg}                                    {reset}\r\n\
         {bg}  {dim}# Setup using claude{reset}{bg}              {reset}\r\n\
         {bg}  $ ssh supabase.sh setup | claude  {reset}\r\n\
         {bg}                                    {reset}\r\n\r\n\
         {bg}                                         {reset}\r\n\
         {bg}  {dim}# Or append directly to AGENTS.md{reset}{bg}      {reset}\r\n\
         {bg}  $ ssh supabase.sh agents >> AGENTS.md  {reset}\r\n\
         {bg}                                         {reset}\r\n\r\n\
         Or explore them yourself with tree/grep/cat/etc:\r\n\r\n"
    )
}

fn prompt(cwd: &str) -> String {
    let green = "\x1b[38;2;62;207;142m";
    let reset = "\x1b[0m";
    let basename = cwd.rsplit('/').next().unwrap_or(cwd);
    format!("{green}{basename}{reset} $ ")
}

/// Helper to convert bytes to the type session.data() expects.
fn to_bytes(data: &[u8]) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(data)
}

/// Configuration for the SSH server.
#[allow(dead_code)]
pub struct SshServerConfig {
    pub port: u16,
    pub host_key: PrivateKey,
    pub docs_dir: PathBuf,
    pub idle_timeout_secs: u64,
    pub session_timeout_secs: u64,
    pub exec_timeout_secs: u64,
    /// Connections above this start getting probabilistically dropped.
    pub soft_limit: usize,
    /// All connections above this are rejected.
    pub hard_limit: usize,
    pub max_connections_per_ip: usize,
    pub cache_max_entries: usize,
    pub cache_max_output_bytes: usize,
    pub enable_cache: bool,
}

/// Shared state across all SSH connections.
struct SharedState {
    cache: Option<CommandCache>,
    docs_dir: PathBuf,
    idle_timeout_secs: u64,
    session_timeout_secs: u64,
    soft_limit: usize,
    hard_limit: usize,
    max_connections_per_ip: usize,
    /// Track active connections per IP.
    connections: HashMap<SocketAddr, usize>,
    total_connections: usize,
}

/// The SSH server that accepts connections.
pub struct SshServer {
    state: Arc<Mutex<SharedState>>,
}

impl SshServer {
    pub fn new(config: &SshServerConfig) -> Self {
        let cache = if config.enable_cache {
            Some(CommandCache::new(
                config.cache_max_entries,
                config.cache_max_output_bytes,
            ))
        } else {
            None
        };

        Self {
            state: Arc::new(Mutex::new(SharedState {
                cache,
                docs_dir: config.docs_dir.clone(),
                idle_timeout_secs: config.idle_timeout_secs,
                session_timeout_secs: config.session_timeout_secs,
                soft_limit: config.soft_limit,
                hard_limit: config.hard_limit,
                max_connections_per_ip: config.max_connections_per_ip,
                connections: HashMap::new(),
                total_connections: 0,
            })),
        }
    }
}

impl Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        info!(peer = ?peer_addr, "new SSH connection");
        SshHandler {
            peer_addr,
            state: self.state.clone(),
            has_pty: false,
            shell_line_tx: None,
            shell_task: None,
            line_editor: LineEditor::new(),
            session_start: Instant::now(),
            last_activity: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

/// Per-connection handler for SSH protocol events.
pub struct SshHandler {
    peer_addr: Option<SocketAddr>,
    state: Arc<Mutex<SharedState>>,
    has_pty: bool,
    shell_line_tx: Option<mpsc::Sender<String>>,
    shell_task: Option<tokio::task::JoinHandle<()>>,
    line_editor: LineEditor,
    session_start: Instant,
    /// Shared last-activity timestamp for idle timeout (shell mode).
    last_activity: Arc<Mutex<Instant>>,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        let peer = self.peer_addr;
        let state = self.state.clone();
        let duration = self.session_start.elapsed();
        info!(peer = ?peer, duration_secs = duration.as_secs(), "SSH connection closed");

        // Decrement connection count
        tokio::spawn(async move {
            let mut s = state.lock().await;
            s.total_connections = s.total_connections.saturating_sub(1);
            if let Some(addr) = peer {
                if let Some(count) = s.connections.get_mut(&addr) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        s.connections.remove(&addr);
                    }
                }
            }
        });
    }
}

impl SshHandler {
    /// Check connection limits and register the connection if accepted.
    /// All auth methods go through this single gate.
    async fn check_limits_and_accept(&mut self) -> Result<Auth> {
        let mut state = self.state.lock().await;

        // Probabilistic capacity check: linear ramp between soft and hard limit.
        // Below soft: always accept. Above hard: always reject.
        // Between: drop probability increases linearly.
        if state.total_connections >= state.soft_limit {
            let drop_probability = if state.total_connections >= state.hard_limit {
                1.0
            } else {
                (state.total_connections - state.soft_limit) as f64
                    / (state.hard_limit - state.soft_limit) as f64
            };

            if rand::random::<f64>() < drop_probability {
                warn!(
                    total = state.total_connections,
                    soft = state.soft_limit,
                    hard = state.hard_limit,
                    p = format!("{:.2}", drop_probability),
                    "rejecting connection: at capacity"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
        }

        // Check per-IP limit
        if let Some(addr) = self.peer_addr {
            let ip_count = state.connections.get(&addr).copied().unwrap_or(0);
            if ip_count >= state.max_connections_per_ip {
                warn!(
                    ip = %addr,
                    count = ip_count,
                    max = state.max_connections_per_ip,
                    "rejecting connection: per-IP limit"
                );
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
            *state.connections.entry(addr).or_insert(0) += 1;
        }

        state.total_connections += 1;
        Ok(Auth::Accept)
    }
}

impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.check_limits_and_accept().await
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        self.check_limits_and_accept().await
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.check_limits_and_accept().await
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.has_pty = true;
        session.channel_success(channel_id)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        info!(command = %command, "exec request");
        session.channel_success(channel)?;

        let cwd = "/supabase";

        // Try cache with mutable access
        let cached = {
            let mut state = self.state.lock().await;
            if let Some(cache) = state.cache.as_mut() {
                cache.get(cwd, &command)
            } else {
                None
            }
        };

        let result = if let Some(cached) = cached {
            cached
        } else {
            let docs_dir = {
                let state = self.state.lock().await;
                state.docs_dir.clone()
            };

            let mut bash = create_bash(&docs_dir).await?;
            let result = match bash.exec(&command).await {
                Ok(exec_result) => CachedResult {
                    stdout: exec_result.stdout.clone(),
                    stderr: exec_result.stderr.clone(),
                    exit_code: exec_result.exit_code,
                },
                Err(e) => {
                    // Resource limits, timeouts, etc. — return as stderr
                    CachedResult {
                        stdout: String::new(),
                        stderr: format!("Error: {e}\n"),
                        exit_code: 1,
                    }
                }
            };

            // Store in cache
            let mut state = self.state.lock().await;
            if let Some(cache) = state.cache.as_mut() {
                cache.set(cwd, &command, result.clone());
            }

            result
        };

        if !result.stdout.is_empty() {
            session.data(channel, to_bytes(result.stdout.as_bytes()))?;
        }
        if !result.stderr.is_empty() {
            session.extended_data(channel, 1, to_bytes(result.stderr.as_bytes()))?;
        }
        session.exit_status_request(channel, result.exit_code as u32)?;
        session.eof(channel)?;
        session.close(channel)?;

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("shell request");
        session.channel_success(channel)?;

        let (line_tx, line_rx) = mpsc::channel::<String>(32);
        self.shell_line_tx = Some(line_tx);

        let (docs_dir, idle_timeout_secs, session_timeout_secs) = {
            let state = self.state.lock().await;
            (
                state.docs_dir.clone(),
                state.idle_timeout_secs,
                state.session_timeout_secs,
            )
        };

        let mut handle = session.handle();
        let banner_text = banner();
        let last_activity = self.last_activity.clone();

        // Spawn an idle watcher that closes the channel if no data arrives
        let idle_handle = handle.clone();
        let idle_activity = last_activity.clone();
        let idle_watcher = tokio::spawn(async move {
            let idle_duration = std::time::Duration::from_secs(idle_timeout_secs);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let last = *idle_activity.lock().await;
                if last.elapsed() >= idle_duration {
                    let green = "\x1b[38;2;62;207;142m";
                    let reset = "\x1b[0m";
                    let msg = format!(
                        "\r\n\r\n{green}Session timed out. Reconnect by running: ssh supabase.sh{reset}\r\n\r\n"
                    );
                    let _ = idle_handle.data(channel, to_bytes(msg.as_bytes())).await;
                    info!("shell session idle timeout after {}s", idle_timeout_secs);
                    let _ = idle_handle.eof(channel).await;
                    let _ = idle_handle.close(channel).await;
                    return;
                }
            }
        });

        self.shell_task = Some(tokio::spawn(async move {
            let mut bash = match create_bash(&docs_dir).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "failed to create bash instance");
                    let msg = format!("Error: {}\r\n", e);
                    let _ = handle.data(channel, to_bytes(msg.as_bytes())).await;
                    let _ = handle.close(channel).await;
                    return;
                }
            };

            let session_future = run_shell_session(
                &mut bash,
                channel,
                &mut handle,
                line_rx,
                &banner_text,
                prompt,
            );

            // Enforce max session timeout
            let timeout_duration =
                std::time::Duration::from_secs(session_timeout_secs);
            match tokio::time::timeout(timeout_duration, session_future).await {
                Ok(Err(e)) => {
                    warn!(error = %e, "shell session error");
                }
                Err(_elapsed) => {
                    let green = "\x1b[38;2;62;207;142m";
                    let reset = "\x1b[0m";
                    let msg = format!(
                        "\r\n\r\n{green}Session timed out. Reconnect by running: ssh supabase.sh{reset}\r\n\r\n"
                    );
                    let _ = handle.data(channel, to_bytes(msg.as_bytes())).await;
                    info!("shell session timed out after {}s", session_timeout_secs);
                }
                Ok(Ok(())) => {}
            }

            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
            idle_watcher.abort();
        }));

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = &self.shell_line_tx {
            // Reset idle timer on any data from client
            *self.last_activity.lock().await = Instant::now();

            for &byte in data {
                match self.line_editor.feed(byte) {
                    LineEvent::Line(line) => {
                        // Echo the newline
                        session.data(channel, to_bytes(b"\r\n"))?;
                        // Send Ctrl+C prompt re-display or the line to the shell task
                        let _ = tx.send(line).await;
                    }
                    LineEvent::Eof => {
                        let _ = tx.send("exit".to_string()).await;
                    }
                    LineEvent::Echo(bytes) => {
                        if !bytes.is_empty() {
                            session.data(channel, to_bytes(&bytes))?;
                            // If this was Ctrl+C, also re-send the prompt
                            if byte == 0x03 {
                                let prompt_str = prompt("supabase");
                                session
                                    .data(channel, to_bytes(prompt_str.as_bytes()))?;
                            }
                        }
                    }
                    LineEvent::None => {}
                }
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.shell_line_tx.take() {
            drop(tx);
        }
        Ok(())
    }
}

/// Run the SSH server with graceful shutdown on SIGTERM/SIGINT.
pub async fn run_server(config: SshServerConfig) -> Result<()> {
    let version = std::env::var("VERSION").unwrap_or_else(|_| "dev".to_string());
    let server_id = format!("SSH-2.0-supabase-ssh_{version}");

    let russh_config = russh::server::Config {
        server_id: russh::SshId::Standard(Cow::Owned(server_id)),
        keys: vec![config.host_key.clone()],
        inactivity_timeout: Some(std::time::Duration::from_secs(config.idle_timeout_secs)),
        ..Default::default()
    };

    let port = config.port;
    let mut server = SshServer::new(&config);

    info!(port = port, "SSH server listening");

    // Run the server and listen for shutdown signals concurrently
    tokio::select! {
        result = server.run_on_address(Arc::new(russh_config), ("0.0.0.0", port)) => {
            result?;
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received, draining connections");
            // russh will drop all handlers, triggering Drop which decrements counts.
            // Give in-flight commands a moment to finish.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            info!("shutdown complete");
        }
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT (Ctrl+C).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { info!("SIGINT received"); }
            _ = sigterm.recv() => { info!("SIGTERM received"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for ctrl_c");
        info!("SIGINT received");
    }
}
