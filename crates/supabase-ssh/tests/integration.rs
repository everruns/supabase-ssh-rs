use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::Server;
use tokio::net::TcpStream;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Test 1: Server starts and sends SSH protocol banner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_starts_and_sends_ssh_banner() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let host_key =
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();

    let config = Arc::new(russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-test".into()),
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    });

    let server_config = config.clone();
    let server_handle = tokio::spawn(async move {
        let mut server = TestServer;
        let _ = server.run_on_address(server_config, addr).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .expect("TCP connect timed out")
        .expect("TCP connect failed");

    let mut buf = vec![0u8; 256];
    stream.readable().await.unwrap();
    let n = stream.try_read(&mut buf).unwrap();
    let banner = String::from_utf8_lossy(&buf[..n]);

    assert!(
        banner.starts_with("SSH-2.0-test"),
        "Expected SSH banner, got: {banner}"
    );

    server_handle.abort();
}

// ---------------------------------------------------------------------------
// Test 2: Full SSH handshake + exec command via russh client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exec_echo_command_over_ssh() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let host_key =
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();

    let config = Arc::new(russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-test-exec".into()),
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });

    // Start server with a handler that runs bashkit
    let server_config = config.clone();
    let server_handle = tokio::spawn(async move {
        let mut server = BashServer;
        let _ = server.run_on_address(server_config, addr).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect with russh client
    let client_config = Arc::new(russh::client::Config::default());
    let mut session = timeout(
        Duration::from_secs(5),
        russh::client::connect(client_config, addr, TestClient),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect failed");

    // Authenticate (server accepts all)
    let auth_result = session
        .authenticate_none("user")
        .await
        .expect("auth failed");
    assert!(
        matches!(auth_result, russh::client::AuthResult::Success),
        "auth should succeed, got: {auth_result:?}"
    );

    // Open a channel and exec
    let mut channel = session.channel_open_session().await.expect("channel open");
    channel
        .exec(true, "echo hello world")
        .await
        .expect("exec");

    // Collect output
    let mut stdout = String::new();
    let mut exit_code: Option<u32> = None;

    let result = timeout(Duration::from_secs(10), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(exit_status);
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) => break,
                None => break,
                _ => {}
            }
        }
    })
    .await;

    assert!(result.is_ok(), "timed out waiting for command output");
    assert_eq!(stdout.trim(), "hello world", "stdout mismatch: {stdout:?}");
    assert_eq!(exit_code, Some(0), "exit code should be 0");

    session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .ok();
    server_handle.abort();
}

// ---------------------------------------------------------------------------
// Test 3: Exec a command that fails (nonexistent command)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exec_failing_command_returns_nonzero_exit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let host_key =
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();

    let config = Arc::new(russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-test-fail".into()),
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });

    let server_config = config.clone();
    let server_handle = tokio::spawn(async move {
        let mut server = BashServer;
        let _ = server.run_on_address(server_config, addr).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut session = timeout(
        Duration::from_secs(5),
        russh::client::connect(client_config, addr, TestClient),
    )
    .await
    .unwrap()
    .unwrap();

    session.authenticate_none("user").await.unwrap();

    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, "false").await.unwrap();

    let mut exit_code: Option<u32> = None;

    let _ = timeout(Duration::from_secs(10), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(exit_status);
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) => break,
                None => break,
                _ => {}
            }
        }
    })
    .await;

    assert_eq!(exit_code, Some(1), "exit code for `false` should be 1");

    session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .ok();
    server_handle.abort();
}

// ---------------------------------------------------------------------------
// Test 4: Real docs mounted via realfs, read via bashkit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exec_cat_doc_from_realfs_mount() {
    use std::io::Write;

    // Create a temp dir with a doc file
    let tmp = tempfile::tempdir().unwrap();
    let doc_path = tmp.path().join("test-guide.md");
    let mut f = std::fs::File::create(&doc_path).unwrap();
    writeln!(f, "# Test Guide\n\nThis is a test document.").unwrap();
    drop(f);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let host_key =
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();

    let config = Arc::new(russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-test-realfs".into()),
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });

    let docs_dir = tmp.path().to_path_buf();
    let server_config = config.clone();
    let server_handle = tokio::spawn(async move {
        let mut server = RealFsServer { docs_dir };
        let _ = server.run_on_address(server_config, addr).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut session = timeout(
        Duration::from_secs(5),
        russh::client::connect(client_config, addr, TestClient),
    )
    .await
    .unwrap()
    .unwrap();

    session.authenticate_none("user").await.unwrap();

    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .exec(true, "cat /supabase/docs/test-guide.md")
        .await
        .unwrap();

    let mut stdout = String::new();
    let mut exit_code: Option<u32> = None;

    let _ = timeout(Duration::from_secs(10), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(exit_status);
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) => break,
                None => break,
                _ => {}
            }
        }
    })
    .await;

    assert_eq!(exit_code, Some(0), "cat should succeed");
    assert!(
        stdout.contains("Test Guide"),
        "should contain doc content, got: {stdout:?}"
    );
    assert!(
        stdout.contains("This is a test document."),
        "should contain full doc body, got: {stdout:?}"
    );

    session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .ok();
    server_handle.abort();
}

// ---------------------------------------------------------------------------
// Helpers: minimal server/client impls
// ---------------------------------------------------------------------------

/// Minimal Server impl — just accepts auth.
struct TestServer;

impl Server for TestServer {
    type Handler = TestHandler;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        TestHandler
    }
}

struct TestHandler;

impl russh::server::Handler for TestHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }
}

/// Server that runs bashkit for exec requests.
struct BashServer;

impl Server for BashServer {
    type Handler = BashHandler;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        BashHandler
    }
}

struct BashHandler;

impl russh::server::Handler for BashHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        session.channel_success(channel)?;

        let mut bash = bashkit::Bash::builder().cwd("/").build();
        let result = bash.exec(&command).await?;

        if !result.stdout.is_empty() {
            session.data(channel, bytes::Bytes::from(result.stdout.into_bytes()))?;
        }
        if !result.stderr.is_empty() {
            session.extended_data(channel, 1, bytes::Bytes::from(result.stderr.into_bytes()))?;
        }
        session.exit_status_request(channel, result.exit_code as u32)?;
        session.eof(channel)?;
        session.close(channel)?;

        Ok(())
    }
}

/// Server that uses the real create_bash with realfs docs mount.
struct RealFsServer {
    docs_dir: std::path::PathBuf,
}

impl Server for RealFsServer {
    type Handler = RealFsHandler;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        RealFsHandler {
            docs_dir: self.docs_dir.clone(),
        }
    }
}

struct RealFsHandler {
    docs_dir: std::path::PathBuf,
}

impl russh::server::Handler for RealFsHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        session.channel_success(channel)?;

        let mut bash = supabase_ssh::bash::create_bash(&self.docs_dir).await?;
        let result = bash.exec(&command).await?;

        if !result.stdout.is_empty() {
            session.data(channel, bytes::Bytes::from(result.stdout.into_bytes()))?;
        }
        if !result.stderr.is_empty() {
            session.extended_data(channel, 1, bytes::Bytes::from(result.stderr.into_bytes()))?;
        }
        session.exit_status_request(channel, result.exit_code as u32)?;
        session.eof(channel)?;
        session.close(channel)?;

        Ok(())
    }
}

/// Minimal client handler — accepts any server key.
struct TestClient;

impl russh::client::Handler for TestClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true) // Accept any host key
    }
}
