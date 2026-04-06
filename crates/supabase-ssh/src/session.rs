use anyhow::Result;
use bashkit::Bash;
use russh::ChannelId;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Helper to convert bytes to the type handle.data() expects.
fn to_bytes(data: &[u8]) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(data)
}

/// Runs an interactive shell session over an SSH channel.
///
/// Reads lines from `line_rx`, executes them via bashkit, and writes output
/// back through the session handle.
pub async fn run_shell_session(
    bash: &mut Bash,
    channel_id: ChannelId,
    handle: &mut russh::server::Handle,
    mut line_rx: mpsc::Receiver<String>,
    banner: &str,
    prompt_fn: impl Fn(&str) -> String,
) -> Result<()> {
    // Send banner
    if !banner.is_empty() {
        handle
            .data(channel_id, to_bytes(banner.as_bytes()))
            .await
            .map_err(|e| anyhow::anyhow!("failed to send banner: {e:?}"))?;
    }

    // Send initial prompt
    let cwd = bash.shell_state().cwd.to_string_lossy().to_string();
    let prompt = prompt_fn(&cwd);
    handle
        .data(channel_id, to_bytes(prompt.as_bytes()))
        .await
        .map_err(|e| anyhow::anyhow!("failed to send prompt: {e:?}"))?;

    while let Some(line) = line_rx.recv().await {
        let command = line.trim().to_string();

        if command == "exit" {
            let msg = "\r\n\x1b[38;2;62;207;142mThanks for stopping by!\x1b[0m\r\n\r\n";
            let _ = handle.data(channel_id, to_bytes(msg.as_bytes())).await;
            break;
        }

        if !command.is_empty() {
            let start = std::time::Instant::now();
            match bash.exec(&command).await {
                Ok(result) => {
                    if !result.stdout.is_empty() {
                        let stdout = result.stdout.replace('\n', "\r\n");
                        let _ = handle
                            .data(channel_id, to_bytes(stdout.as_bytes()))
                            .await;
                    }
                    if !result.stderr.is_empty() {
                        let stderr = result.stderr.replace('\n', "\r\n");
                        let _ = handle
                            .extended_data(channel_id, 1, to_bytes(stderr.as_bytes()))
                            .await;
                    }
                    let duration = start.elapsed();
                    info!(
                        command = %command,
                        exit_code = result.exit_code,
                        duration_ms = duration.as_millis() as u64,
                        "shell command executed"
                    );
                }
                Err(err) => {
                    let msg = format!("Error: {}\r\n", err);
                    let _ = handle.data(channel_id, to_bytes(msg.as_bytes())).await;
                    warn!(command = %command, error = %err, "shell command failed");
                }
            }
        }

        // Update prompt with potentially changed cwd
        let cwd = bash.shell_state().cwd.to_string_lossy().to_string();
        let prompt = prompt_fn(&cwd);
        let _ = handle
            .data(channel_id, to_bytes(prompt.as_bytes()))
            .await;
    }

    Ok(())
}
