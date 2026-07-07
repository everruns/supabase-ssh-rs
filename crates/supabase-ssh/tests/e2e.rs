//! End-to-end tests that spawn the ACTUAL production binary (`main.rs`) as a
//! subprocess, configured entirely through environment variables, and drive it
//! with a real russh client — exercising the full stack: env-var config,
//! ephemeral host-key generation, realfs docs mount, exec mode, and the
//! custom `ssh` command blocker.

use std::io::Write;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

/// Client handler that accepts any host key.
struct E2eClient;

impl russh::client::Handler for E2eClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A running server subprocess plus the port it listens on. Killed on drop.
struct ServerProcess {
    child: Child,
    port: u16,
    _docs: tempfile::TempDir,
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawn the server, retrying on the rare port race (another test grabbing the
/// freed ephemeral port between our probe and the child binding it).
async fn spawn_server() -> ServerProcess {
    for attempt in 0..3 {
        if let Some(server) = try_spawn_server().await {
            return server;
        }
        eprintln!("spawn_server attempt {attempt} failed to become ready; retrying");
    }
    panic!("server did not become ready after 3 attempts");
}

/// Build the binary and spawn it with a temp docs dir on an ephemeral port.
/// Returns None if the child never reports listening (e.g. lost a port race).
async fn try_spawn_server() -> Option<ServerProcess> {
    // Pick a free port by binding to 0 then releasing it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // Create a docs dir with real content the client will read/search.
    let docs = tempfile::tempdir().unwrap();
    let guide_dir = docs.path().join("guides/auth");
    std::fs::create_dir_all(&guide_dir).unwrap();
    let mut f = std::fs::File::create(guide_dir.join("passwords.md")).unwrap();
    writeln!(
        f,
        "# Password Auth\n\nSupabase supports password-based authentication with RLS policies."
    )
    .unwrap();
    drop(f);

    // Locate the compiled test binary's sibling `supabase-ssh` binary.
    let bin = env!("CARGO_BIN_EXE_supabase-ssh");

    let mut child = Command::new(bin)
        .env("PORT", port.to_string())
        .env("DOCS_DIR", docs.path())
        .env("RUST_LOG", "supabase_ssh=info")
        // Force ephemeral key generation (no key file present in temp cwd).
        .env("SSH_HOST_KEY_PATH", docs.path().join("nonexistent_key"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn server binary");

    // tracing_subscriber::fmt() logs to stdout — wait there for the ready line.
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let ready = timeout(Duration::from_secs(20), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("SSH server listening") {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    if !ready {
        let _ = child.start_kill();
        return None;
    }

    // Keep draining both pipes so their buffers never block the child.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    if let Some(stderr) = child.stderr.take() {
        let mut errlines = BufReader::new(stderr).lines();
        tokio::spawn(async move { while let Ok(Some(_)) = errlines.next_line().await {} });
    }

    Some(ServerProcess {
        child,
        port,
        _docs: docs,
    })
}

/// Connect, authenticate, and run a single exec command. Returns (stdout, exit_code).
/// Retries the connect/handshake a few times — under heavy parallel load the
/// crypto handshake can transiently hiccup even though the server is up.
async fn run_exec(port: u16, command: &str) -> (String, u32) {
    let mut session = None;
    for attempt in 0..5 {
        let config = Arc::new(russh::client::Config::default());
        match timeout(
            Duration::from_secs(10),
            russh::client::connect(config, ("127.0.0.1", port), E2eClient),
        )
        .await
        {
            Ok(Ok(s)) => {
                session = Some(s);
                break;
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(200 * (attempt + 1))).await;
            }
        }
    }
    let mut session = session.expect("failed to connect after 5 attempts");

    session
        .authenticate_none("agent")
        .await
        .expect("auth failed");

    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();

    let mut stdout = String::new();
    let mut exit_code = 0u32;
    let _ = timeout(Duration::from_secs(15), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => exit_code = exit_status,
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    })
    .await;

    (stdout, exit_code)
}

#[tokio::test]
async fn e2e_cat_doc() {
    let server = spawn_server().await;
    let (out, code) = run_exec(server.port, "cat /supabase/docs/guides/auth/passwords.md").await;
    assert_eq!(code, 0, "cat should succeed, output: {out:?}");
    assert!(out.contains("Password Auth"), "unexpected output: {out:?}");
    assert!(out.contains("RLS policies"), "unexpected output: {out:?}");
}

#[tokio::test]
async fn e2e_grep_search() {
    let server = spawn_server().await;
    let (out, code) = run_exec(server.port, "grep -rl RLS /supabase/docs/").await;
    assert_eq!(code, 0, "grep should succeed, output: {out:?}");
    assert!(
        out.contains("passwords.md"),
        "grep should find the doc, output: {out:?}"
    );
}

#[tokio::test]
async fn e2e_find_docs() {
    let server = spawn_server().await;
    let (out, code) = run_exec(server.port, "find /supabase/docs -name '*.md'").await;
    assert_eq!(code, 0, "find should succeed, output: {out:?}");
    assert!(out.contains("passwords.md"), "output: {out:?}");
}

#[tokio::test]
async fn e2e_ssh_command_is_blocked() {
    let server = spawn_server().await;
    let (out, code) = run_exec(server.port, "ssh supabase.sh agents").await;
    assert_ne!(code, 0, "ssh should be blocked with non-zero exit");
    assert!(
        out.to_lowercase().contains("not available"),
        "ssh blocker message expected, output: {out:?}"
    );
}

#[tokio::test]
async fn e2e_readonly_write_rejected() {
    let server = spawn_server().await;
    let (_out, code) = run_exec(server.port, "echo pwned > /supabase/docs/evil.md").await;
    assert_ne!(code, 0, "writing to read-only docs mount must fail");
}

#[tokio::test]
async fn e2e_agents_alias() {
    let server = spawn_server().await;
    let (out, code) = run_exec(server.port, "cat /supabase/AGENTS.md").await;
    assert_eq!(code, 0, "AGENTS.md should be readable, output: {out:?}");
    assert!(
        out.contains("Supabase Docs"),
        "AGENTS.md content expected, output: {out:?}"
    );
}
