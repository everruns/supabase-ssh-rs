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
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub cache_max_entries: usize,
    pub cache_max_output_bytes: usize,
    pub enable_cache: bool,
}

/// Shared state across all SSH connections.
struct SharedState {
    cache: Option<CommandCache>,
    docs_dir: PathBuf,
    max_connections: usize,
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
                max_connections: config.max_connections,
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
            line_buffer: Vec::new(),
            session_start: Instant::now(),
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
    line_buffer: Vec<u8>,
    session_start: Instant,
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

impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        let mut state = self.state.lock().await;

        // Check capacity
        if state.total_connections >= state.max_connections {
            warn!(
                total = state.total_connections,
                max = state.max_connections,
                "rejecting connection: at capacity"
            );
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
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

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
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
            let exec_result = bash.exec(&command).await?;
            let result = CachedResult {
                stdout: exec_result.stdout.clone(),
                stderr: exec_result.stderr.clone(),
                exit_code: exec_result.exit_code,
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

        let docs_dir = {
            let state = self.state.lock().await;
            state.docs_dir.clone()
        };

        let mut handle = session.handle();
        let banner_text = banner();

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

            if let Err(e) =
                run_shell_session(&mut bash, channel, &mut handle, line_rx, &banner_text, prompt)
                    .await
            {
                warn!(error = %e, "shell session error");
            }

            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
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
            for &byte in data {
                match byte {
                    // Enter key
                    b'\r' | b'\n' => {
                        let line = String::from_utf8_lossy(&self.line_buffer).to_string();
                        self.line_buffer.clear();
                        session.data(channel, to_bytes(b"\r\n"))?;
                        let _ = tx.send(line).await;
                    }
                    // Backspace / DEL
                    0x7f | 0x08 => {
                        if !self.line_buffer.is_empty() {
                            self.line_buffer.pop();
                            session.data(channel, to_bytes(b"\x08 \x08"))?;
                        }
                    }
                    // Ctrl+C
                    0x03 => {
                        self.line_buffer.clear();
                        session.data(channel, to_bytes(b"^C\r\n"))?;
                        let green = "\x1b[38;2;62;207;142m";
                        let reset = "\x1b[0m";
                        let prompt_str = format!("{green}supabase{reset} $ ");
                        session.data(channel, to_bytes(prompt_str.as_bytes()))?;
                    }
                    // Ctrl+D (EOF)
                    0x04 => {
                        if self.line_buffer.is_empty() {
                            let _ = tx.send("exit".to_string()).await;
                        }
                    }
                    // Regular character
                    _ => {
                        self.line_buffer.push(byte);
                        session.data(channel, to_bytes(&[byte]))?;
                    }
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

/// Run the SSH server.
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
    server
        .run_on_address(Arc::new(russh_config), ("0.0.0.0", port))
        .await?;

    Ok(())
}
