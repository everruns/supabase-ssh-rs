# supabase-ssh (Rust)

SSH server that exposes Supabase documentation as a sandboxed virtual filesystem.
Agents and CLI users can browse docs using familiar bash commands over SSH.

Rust reimplementation using [russh](https://docs.rs/russh) for the SSH protocol
and [bashkit](https://github.com/everruns/bashkit) for the sandboxed bash interpreter.

## Quick start

```bash
# Generate a host key (or set SSH_HOST_KEY env var)
ssh-keygen -t ed25519 -f ssh_host_key -N ""

# Run (defaults to port 22, needs root or CAP_NET_BIND_SERVICE)
cargo run

# Or use a custom port
PORT=2222 cargo run
```

Then connect:

```bash
# Single command (exec mode)
ssh -p 2222 localhost 'grep -rl auth /supabase/docs/'

# Interactive shell
ssh -p 2222 localhost
```

## Configuration

All configuration is via environment variables, matching the TypeScript server:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `22` | SSH listen port |
| `DOCS_DIR` | `./docs` | Path to docs directory (mounted read-only) |
| `SSH_HOST_KEY` | — | PEM-encoded host key (takes priority) |
| `SSH_HOST_KEY_PATH` | `./ssh_host_key` | Path to host key file |
| `MAX_CONNECTIONS` | `100` | Hard connection limit (soft = 80%) |
| `MAX_CONNECTIONS_PER_IP` | `10` | Per-IP concurrency limit |
| `IDLE_TIMEOUT` | `60` | Seconds before idle shell disconnect |
| `SESSION_TIMEOUT` | `600` | Max session duration in seconds |
| `EXEC_TIMEOUT` | `10` | Per-command timeout (bashkit-enforced) |
| `COMMAND_CACHE` | `true` | Enable LRU command cache |
| `COMMAND_CACHE_MAX_ENTRIES` | `1000` | Cache capacity |
| `COMMAND_CACHE_MAX_OUTPUT_BYTES` | `524288` | Skip caching outputs larger than this |

## Architecture

```
src/
├── main.rs          # Entry point, env config, host key loading
├── lib.rs           # Public module exports
├── ssh.rs           # SSH server (russh), connection limits, auth, exec/shell
├── bash.rs          # bashkit sandbox setup, execution limits, realfs mount
├── session.rs       # Interactive shell REPL over SSH channels
├── line_editor.rs   # Line editor with arrow keys, history, readline shortcuts
└── cache.rs         # LRU command cache
```

### How it works

**Exec mode** (`ssh host command`): Creates a fresh bashkit sandbox per command,
executes it, returns stdout/stderr/exit code, closes the channel. Results are
cached in an LRU cache (safe because the VFS is read-only).

**Shell mode** (`ssh host`): Creates a persistent bashkit sandbox for the session.
The line editor processes raw terminal input (escape sequences, arrow keys, history)
and feeds completed lines to bashkit. Output is streamed back over the SSH channel.

### Security model

- **Sandboxed execution**: All commands run inside bashkit — no fork/exec, no host
  access. 156 Unix commands reimplemented in Rust.
- **Read-only host mount**: Docs directory mounted via `realfs` in `ReadOnly` mode.
  Path traversal blocked by canonicalize + prefix check.
- **Execution limits**: 1000 commands, 1000 loop iterations, 50 function depth,
  10s timeout, 1MB output cap, 1MB variable storage, 10K array entries.
- **Connection limits**: Probabilistic soft/hard ramp (80→100), per-IP concurrency
  (10), idle timeout (60s), session timeout (600s).
- **Custom `ssh` command**: Blocked inside sandbox with helpful error message.
- **Graceful shutdown**: SIGTERM/SIGINT stops accepting, drains in-flight commands.

## Building

```bash
cargo build --release
```

The binary is at `target/release/supabase-ssh`.

## Testing

```bash
# Run all tests (use larger stack for recursion security tests)
RUST_MIN_STACK=8388608 cargo test

# Run only security tests
RUST_MIN_STACK=8388608 cargo test --test security

# Run only integration tests (SSH protocol)
cargo test --test integration

# Run only unit tests (line editor, cache)
cargo test --lib
```

## Docker

```dockerfile
FROM rust:1.83-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/supabase-ssh /usr/local/bin/
COPY docs/ /app/docs/
WORKDIR /app
ENV DOCS_DIR=/app/docs
EXPOSE 22
CMD ["supabase-ssh"]
```
