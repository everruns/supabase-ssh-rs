//! Throwaway harness: runs the demo commands through the real bashkit sandbox
//! (same `create_bash` the server uses) and prints each command's real output
//! delimited by markers, so the README demo can be rendered from genuine output.
//!
//! Usage: DOCS_DIR=/path/to/docs cargo run --example capture_demo

use std::path::PathBuf;

use supabase_ssh::bash::create_bash;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let docs = PathBuf::from(std::env::var("DOCS_DIR").expect("set DOCS_DIR"));

    let commands = [
        "ls /supabase/docs",
        "find /supabase/docs/guides/auth -name '*.md'",
        "grep -ril 'row level security' /supabase/docs",
        "cat /supabase/docs/guides/auth/rls.md",
    ];

    for cmd in commands {
        // Fresh sandbox per command, exactly like the server's exec mode.
        let mut bash = create_bash(&docs).await?;
        let result = bash.exec(cmd).await?;
        println!("<<<CMD>>>{cmd}");
        print!("{}", result.stdout);
        if !result.stderr.is_empty() {
            print!("{}", result.stderr);
        }
        println!("<<<END>>>");
    }
    Ok(())
}
