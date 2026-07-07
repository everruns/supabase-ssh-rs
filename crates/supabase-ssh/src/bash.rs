use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use bashkit::{
    Bash, Builtin, BuiltinContext, ExecResult, ExecutionLimits, MemoryLimits, SessionLimits,
    async_trait,
};

/// Custom `ssh` command that blocks SSH from within the sandbox.
struct SshBlocker;

#[async_trait]
impl Builtin for SshBlocker {
    async fn execute(&self, ctx: BuiltinContext<'_>) -> bashkit::Result<ExecResult> {
        let cmd = ctx.args.join(" ");
        let hint = if cmd == "supabase.sh agents" {
            " >> AGENTS.md"
        } else {
            ""
        };
        Ok(ExecResult::err(
            format!(
                "ssh is not available from within this session.\n\
                 Exit first, then run:\n\n\
                   ssh {cmd}{hint}\n\n"
            ),
            1,
        ))
    }
}

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
    // Values mirror the original TypeScript just-bash EXECUTION_LIMITS where an
    // equivalent bashkit knob exists.
    ExecutionLimits::new()
        .max_commands(1000) // maxCommandCount
        .max_loop_iterations(1000) // maxLoopIterations
        .max_total_loop_iterations(10_000)
        .max_function_depth(50) // maxCallDepth
        .max_subst_depth(20) // maxSubstitutionDepth
        .max_subshell_depth(20)
        .max_file_descriptors(100) // maxFileDescriptors
        .timeout(Duration::from_secs(10)) // per-command execTimeout
        .max_input_bytes(1024 * 1024) // maxHeredocSize (1MB max script input)
        .max_stdout_bytes(1024 * 1024) // maxOutputSize
        .max_stderr_bytes(1024 * 1024) // maxOutputSize
}

fn session_limits() -> SessionLimits {
    SessionLimits::new()
        .max_total_commands(10_000)
        .max_exec_calls(500)
}

fn memory_limits() -> MemoryLimits {
    MemoryLimits::new()
        .max_array_entries(10_000)
        .max_variable_count(5_000)
        .max_total_variable_bytes(1024 * 1024) // 1MB total variable storage
}

/// Creates a sandboxed Bash instance with docs mounted at /supabase/docs.
///
/// Uses bashkit's `realfs` feature to mount the host docs directory as read-only
/// at `/supabase/docs`. The in-memory layer holds AGENTS.md, SKILL.md, SETUP.md
/// and receives any writes (which will fail since the sandbox rejects them).
pub async fn create_bash(docs_dir: &Path) -> Result<Bash> {
    let docs_dir_str = docs_dir.to_string_lossy();

    let mut bash = Bash::builder()
        // Mount the real docs directory read-only at /supabase/docs
        .mount_real_readonly_at(&*docs_dir_str, "/supabase/docs")
        .cwd("/supabase")
        .env("HOME", "/supabase")
        .env("BASH_ALIAS_ll", "ls -alF")
        .env("BASH_ALIAS_la", "ls -a")
        .env("BASH_ALIAS_l", "ls -CF")
        .env("BASH_ALIAS_agents", "echo && cat /supabase/AGENTS.md")
        .env("BASH_ALIAS_skill", "echo && cat /supabase/SKILL.md")
        .env("BASH_ALIAS_setup", "cat /supabase/SETUP.md")
        .builtin("ssh", Box::new(SshBlocker))
        .limits(execution_limits())
        .session_limits(session_limits())
        .memory_limits(memory_limits())
        .build();

    // Write virtual files into the in-memory layer
    bash.exec(&format!(
        "mkdir -p /supabase && cat > /supabase/AGENTS.md << 'AGENTS_EOF'\n{}\nAGENTS_EOF",
        agents_md()
    ))
    .await?;
    bash.exec(&format!(
        "cat > /supabase/SKILL.md << 'SKILL_EOF'\n{}\nSKILL_EOF",
        skill_md()
    ))
    .await?;
    bash.exec(&format!(
        "cat > /supabase/SETUP.md << 'SETUP_EOF'\n{}\nSETUP_EOF",
        SETUP_MD
    ))
    .await?;

    // Enable alias expansion
    bash.exec("shopt -s expand_aliases").await?;

    Ok(bash)
}

/// Default docs directory path.
pub fn default_docs_dir() -> PathBuf {
    let dir = std::env::var("DOCS_DIR").unwrap_or_else(|_| "./docs".to_string());
    PathBuf::from(dir)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("./docs"))
}
