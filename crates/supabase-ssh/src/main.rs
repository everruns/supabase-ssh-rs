use std::path::PathBuf;

use anyhow::Result;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use tracing::info;
use tracing_subscriber::EnvFilter;

use supabase_ssh::bash::default_docs_dir;
use supabase_ssh::ssh::{SshServerConfig, run_server};

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn load_host_key() -> Result<PrivateKey> {
    // Try SSH_HOST_KEY env var first (PEM-encoded)
    if let Ok(pem) = std::env::var("SSH_HOST_KEY") {
        let key = PrivateKey::from_openssh(&pem)?;
        let fp = key.fingerprint(HashAlg::Sha256);
        info!(fingerprint = %fp, "loaded host key from SSH_HOST_KEY env var");
        return Ok(key);
    }

    // Try reading from file
    let key_path =
        std::env::var("SSH_HOST_KEY_PATH").unwrap_or_else(|_| "./ssh_host_key".to_string());
    let path = PathBuf::from(&key_path);
    if path.exists() {
        let pem = std::fs::read_to_string(&path)?;
        let key = PrivateKey::from_openssh(&pem)?;
        let fp = key.fingerprint(HashAlg::Sha256);
        info!(path = %key_path, fingerprint = %fp, "loaded host key from file");
        return Ok(key);
    }

    // Generate a new key if none found
    info!("no host key found, generating ephemeral ed25519 key");
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)?;
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("supabase_ssh=info".parse()?))
        .init();

    let host_key = load_host_key()?;
    let docs_dir = default_docs_dir();

    let port: u16 = env_or("PORT", 22);
    let max_connections: usize = env_or("MAX_CONNECTIONS", 100);
    let max_connections_per_ip: usize = env_or("MAX_CONNECTIONS_PER_IP", 10);
    let idle_timeout_secs: u64 = env_or("IDLE_TIMEOUT", 60);
    let session_timeout_secs: u64 = env_or("SESSION_TIMEOUT", 600);
    let exec_timeout_secs: u64 = env_or("EXEC_TIMEOUT", 10);
    let enable_cache: bool = env_or("COMMAND_CACHE", true);
    let cache_max_entries: usize = env_or("COMMAND_CACHE_MAX_ENTRIES", 1000);
    let cache_max_output_bytes: usize = env_or("COMMAND_CACHE_MAX_OUTPUT_BYTES", 512 * 1024);

    info!(
        port = port,
        docs_dir = %docs_dir.display(),
        max_connections = max_connections,
        "starting supabase-ssh"
    );

    let config = SshServerConfig {
        port,
        host_key,
        docs_dir,
        idle_timeout_secs,
        session_timeout_secs,
        exec_timeout_secs,
        soft_limit: max_connections * 80 / 100, // 80% of max
        hard_limit: max_connections,
        max_connections_per_ip,
        cache_max_entries,
        cache_max_output_bytes,
        enable_cache,
    };

    run_server(config).await
}
