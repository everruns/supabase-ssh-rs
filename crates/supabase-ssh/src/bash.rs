use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bashkit::{Bash, ExecutionLimits, InMemoryFs, MountableFs, OverlayFs};

const INSTRUCTIONS: &str = r#"```bash
# Search for a topic
ssh supabase.sh grep -rl 'auth' /supabase/docs/

# Read a specific guide
ssh supabase.sh cat /supabase/docs/guides/auth/passwords.md

# Find all guides in a section
ssh supabase.sh find /supabase/docs/guides/database -name '*.md'

# Search with context
ssh supabase.sh grep -r 'RLS' /supabase/docs/guides/auth --include='*.md' -l
```

All docs live under `/supabase/docs/` as markdown files. You can use any standard Unix tools (grep, find, cat, etc.) to search and read them."#;

fn agents_md() -> String {
    format!(
        "## Supabase Docs\n\n\
         Before working on a Supabase feature, check the docs via `ssh supabase.sh <command>`.\n\n\
         {INSTRUCTIONS}\n"
    )
}

fn skill_md() -> String {
    format!(
        "---\n\
         name: supabase-docs\n\
         description: Search and read Supabase documentation using a bash shell. Use when working on a Supabase feature or troubleshooting a problem.\n\
         ---\n\n\
         # Supabase Docs\n\n\
         Search and read Supabase documentation over SSH.\n\n\
         ## How to use\n\n\
         {INSTRUCTIONS}\n"
    )
}

const SETUP_MD: &str = r#"# Supabase Docs - Setup

You are helping a user set up access to Supabase documentation via SSH.

1. First tell them the purpose of this tool (docs over ssh/bash)
2. Ask the user which option they prefer (use AskUserQuestion or similar if available)

Options:

1. **Append to agent instructions file (recommended)** - Adds lightweight instructions to the project's agent config file. Most reliable since instructions are always loaded and the footprint is small.
2. **Install as a skill** - Creates a skill directory with a SKILL.md. Skills are loaded on-demand but not always reliable.
3. **Both** - Adds to agent instructions and installs the skill.

After the user chooses, follow the steps below. If you are unsure which agent or tool the user is using, ask them.

## Option 1: Agent instructions file

Run this command and append the output to the project's agent instructions file:

```bash
ssh supabase.sh agents >> <instructions-file>
```

Common instructions files by tool:

| Tool | File |
|------|------|
| Claude Code | `CLAUDE.md` |
| GitHub Copilot | `AGENTS.md` |
| Codex | `AGENTS.md` |
| Gemini CLI | `GEMINI.md` |
| Cursor | `AGENTS.md` |
| OpenCode | `AGENTS.md` |
| Other | `AGENTS.md` |

## Option 2: Skill

Run this command and write the output to the skill directory.

Pick the path that matches the user's tool. `.agents/skills/` is a cross-client convention supported by most tools:

| Tool | Skill path |
|------|-----------|
| Claude Code | `.claude/skills/supabase-docs/SKILL.md` |
| Codex | `.agents/skills/supabase-docs/SKILL.md` |
| Cursor | `.cursor/skills/supabase-docs/SKILL.md` or `.agents/skills/supabase-docs/SKILL.md` |
| OpenCode | `.opencode/skills/supabase-docs/SKILL.md` or `.agents/skills/supabase-docs/SKILL.md` |
| Gemini CLI | `.gemini/skills/supabase-docs/SKILL.md` or `.agents/skills/supabase-docs/SKILL.md` |
| GitHub Copilot | `.github/skills/supabase-docs/SKILL.md` |
| Other | `.agents/skills/supabase-docs/SKILL.md` |

```bash
mkdir -p <skill-dir>/supabase-docs
ssh supabase.sh skill > <skill-dir>/supabase-docs/SKILL.md
```

## Option 3: Both

Run both sets of commands above.

After setup, confirm to the user what was written and where.
"#;

fn execution_limits() -> ExecutionLimits {
    ExecutionLimits::new()
        .max_commands(1000)
        .max_loop_iterations(1000)
        .max_function_depth(50)
        .timeout(Duration::from_secs(30))
        .max_stdout_bytes(1024 * 1024)
        .max_stderr_bytes(1024 * 1024)
}

/// Creates a sandboxed Bash instance with docs mounted at /supabase/docs.
pub async fn create_bash(_docs_dir: &Path) -> Result<Bash> {
    // Create the base in-memory filesystem with initial files
    let base = InMemoryFs::new();
    base.add_file("/supabase/AGENTS.md", agents_md().as_bytes(), 0o644);
    base.add_file("/supabase/SKILL.md", skill_md().as_bytes(), 0o644);
    base.add_file("/supabase/SETUP.md", SETUP_MD.as_bytes(), 0o644);

    // Create an overlay of the real docs directory for read-only access
    let docs_lower = InMemoryFs::new();
    let docs_overlay = Arc::new(OverlayFs::new(Arc::new(docs_lower)));

    // Create a mountable filesystem with the base and mount docs
    let mountable = Arc::new(MountableFs::new(Arc::new(base)));
    mountable.mount("/supabase/docs", docs_overlay)?;

    let mut bash = Bash::builder()
        .fs(mountable)
        .cwd("/supabase")
        .env("HOME", "/supabase")
        .env("BASH_ALIAS_ll", "ls -alF")
        .env("BASH_ALIAS_la", "ls -a")
        .env("BASH_ALIAS_l", "ls -CF")
        .env("BASH_ALIAS_agents", "echo && cat /supabase/AGENTS.md")
        .env("BASH_ALIAS_skill", "echo && cat /supabase/SKILL.md")
        .env("BASH_ALIAS_setup", "cat /supabase/SETUP.md")
        .limits(execution_limits())
        .build();

    // Enable alias expansion
    bash.exec("shopt -s expand_aliases").await?;

    Ok(bash)
}

/// Default docs directory path.
pub fn default_docs_dir() -> PathBuf {
    let dir = std::env::var("DOCS_DIR").unwrap_or_else(|_| "./docs".to_string());
    PathBuf::from(dir).canonicalize().unwrap_or_else(|_| PathBuf::from("./docs"))
}
