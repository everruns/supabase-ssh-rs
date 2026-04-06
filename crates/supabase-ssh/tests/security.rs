//! Security tests — ported from apps/ssh/src/shell/attacks.test.ts
//!
//! Verifies that bashkit's execution limits catch abuse.
//!
//! Key difference from just-bash (TS): bashkit returns Err(ResourceLimit(...))
//! when limits are exceeded, rather than Ok(ExecResult { stderr: "..." }).
//! Both behaviors are correct — the limit IS enforced.

use std::io::Write;

use supabase_ssh::bash::create_bash;

async fn test_bash() -> bashkit::Bash {
    let tmp = tempfile::tempdir().unwrap();
    let mut f = std::fs::File::create(tmp.path().join("test.md")).unwrap();
    writeln!(f, "# Test").unwrap();
    drop(f);
    create_bash(tmp.path()).await.unwrap()
}

/// Returns true if the exec was stopped (either Err or non-zero exit with limit message).
async fn exec_is_stopped(bash: &mut bashkit::Bash, script: &str) -> bool {
    match bash.exec(script).await {
        Err(e) => {
            let msg = format!("{e:?}").to_lowercase();
            msg.contains("limit")
                || msg.contains("timeout")
                || msg.contains("depth")
                || msg.contains("resource")
                || msg.contains("commands")
                || msg.contains("iteration")
        }
        Ok(result) => {
            let s = result.stderr.to_lowercase();
            result.exit_code != 0
                && (s.contains("limit")
                    || s.contains("timeout")
                    || s.contains("depth")
                    || s.contains("iteration")
                    || s.contains("commands"))
        }
    }
}

/// Returns the result or describes the error.
async fn exec_result_or_err(
    bash: &mut bashkit::Bash,
    script: &str,
) -> Result<bashkit::ExecResult, String> {
    bash.exec(script).await.map_err(|e| format!("{e:?}"))
}

// ---------------------------------------------------------------------------
// Attack: infinite loops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn while_true_is_stopped() {
    let mut bash = test_bash().await;
    assert!(
        exec_is_stopped(&mut bash, "while true; do echo x; done").await,
        "infinite while loop must be stopped"
    );
}

#[tokio::test]
async fn until_false_is_stopped() {
    let mut bash = test_bash().await;
    assert!(
        exec_is_stopped(&mut bash, "until false; do echo x; done").await,
        "infinite until loop must be stopped"
    );
}

// ---------------------------------------------------------------------------
// Attack: output flooding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn output_bounded_to_1mb() {
    let mut bash = test_bash().await;
    let res = exec_result_or_err(
        &mut bash,
        "while true; do echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; done",
    ).await;
    match res {
        Ok(result) => {
            let total = result.stdout.len() + result.stderr.len();
            assert!(total <= 1024 * 1024 + 8192, "output should be bounded, got {total}");
        }
        Err(e) => {
            // ResourceLimit error is also acceptable — output was stopped
            assert!(
                e.to_lowercase().contains("limit") || e.to_lowercase().contains("output"),
                "unexpected error: {e}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Attack: string/memory amplification
// ---------------------------------------------------------------------------

/// Note: bashkit doesn't have a separate maxStringLength like just-bash.
/// The 25-iteration loop is under the 1000 limit, so it completes.
/// The 10s execution timeout is the backstop in production.
/// MemoryLimits.max_total_variable_bytes bounds total variable storage.
#[tokio::test]
async fn exponential_string_growth_bounded_by_timeout_or_memory() {
    let start = std::time::Instant::now();
    let mut bash = test_bash().await;
    let _ = exec_result_or_err(
        &mut bash,
        r#"x="AAAAAAAAAA"; for i in $(seq 1 25); do x="$x$x"; done; echo ${#x}"#,
    )
    .await;
    // Must complete within the 10s timeout
    assert!(start.elapsed().as_secs() < 15, "should complete within timeout");
}

#[tokio::test]
async fn large_array_bounded() {
    let mut bash = test_bash().await;
    assert!(
        exec_is_stopped(
            &mut bash,
            r#"arr=(); for i in $(seq 1 20000); do arr+=("$i"); done; echo ${#arr[@]}"#
        )
        .await,
        "large array construction must be bounded"
    );
}

// ---------------------------------------------------------------------------
// Attack: recursion depth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deep_recursion_stopped() {
    let mut bash = test_bash().await;
    assert!(
        exec_is_stopped(&mut bash, "f() { f; }; f").await,
        "deep recursion must be stopped by max_function_depth"
    );
}

// ---------------------------------------------------------------------------
// Attack: command count exhaustion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn many_commands_hit_limit() {
    let mut bash = test_bash().await;
    let cmds: Vec<String> = (0..1500).map(|i| format!("echo {i}")).collect();
    assert!(
        exec_is_stopped(&mut bash, &cmds.join("; ")).await,
        "1500 commands must hit max_commands limit"
    );
}

// ---------------------------------------------------------------------------
// Attack: sed amplification
// ---------------------------------------------------------------------------

/// Note: bashkit doesn't have a separate maxSedIterations like just-bash.
/// The sed loop terminates naturally when output hits max_stdout_bytes or
/// the 10s execution timeout fires.
#[tokio::test]
async fn sed_branch_loop_bounded_by_timeout_or_output() {
    let start = std::time::Instant::now();
    let mut bash = test_bash().await;
    let res = exec_result_or_err(
        &mut bash,
        r#"echo "aaa" | sed ":loop; s/a/aa/; t loop""#,
    )
    .await;
    let elapsed = start.elapsed();
    // Must be stopped by timeout (10s) or output limit (1MB)
    assert!(elapsed.as_secs() < 15, "sed loop should be bounded by timeout");
    match res {
        Ok(r) => {
            // Output should be bounded even if exit code is 0
            assert!(
                r.stdout.len() + r.stderr.len() <= 1024 * 1024 + 8192,
                "output should be bounded"
            );
        }
        Err(_) => {} // Resource limit error is fine
    }
}

// ---------------------------------------------------------------------------
// Attack: read-only HOST filesystem (realfs mount)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cannot_write_to_realfs_mount() {
    let mut bash = test_bash().await;
    let res = exec_result_or_err(&mut bash, r#"echo "pwned" > /supabase/docs/evil.md"#).await;
    match res {
        Ok(r) => assert_ne!(r.exit_code, 0, "write to realfs should fail"),
        Err(_) => {} // Error is acceptable
    }
}

#[tokio::test]
async fn cannot_mkdir_in_realfs_mount() {
    let mut bash = test_bash().await;
    let res = exec_result_or_err(&mut bash, "mkdir /supabase/docs/evil").await;
    match res {
        Ok(r) => assert_ne!(r.exit_code, 0, "mkdir in realfs should fail"),
        Err(_) => {}
    }
}

#[tokio::test]
async fn cannot_delete_from_realfs_mount() {
    let mut bash = test_bash().await;
    let res = exec_result_or_err(&mut bash, "rm /supabase/docs/test.md").await;
    match res {
        Ok(r) => assert_ne!(r.exit_code, 0, "rm in realfs should fail"),
        Err(_) => {}
    }
}

#[tokio::test]
async fn inmemory_writes_are_sandboxed() {
    let mut bash = test_bash().await;
    let result = bash
        .exec(r#"echo "test" > /tmp/test.txt && cat /tmp/test.txt"#)
        .await
        .unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("test"));
}

// ---------------------------------------------------------------------------
// Attack: timeout enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn execution_timeout_enforced() {
    let start = std::time::Instant::now();
    let mut bash = test_bash().await;
    let stopped = exec_is_stopped(
        &mut bash,
        "for i in $(seq 1 1000); do for j in $(seq 1 1000); do echo $i.$j; done; done",
    )
    .await;
    let elapsed = start.elapsed();

    assert!(stopped, "should be stopped by timeout or limits");
    assert!(elapsed.as_secs() < 15, "took {}s, expected <15s", elapsed.as_secs());
}

// ---------------------------------------------------------------------------
// Functional: concurrent execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_instances_dont_block_each_other() {
    let start = std::time::Instant::now();

    let handles: Vec<_> = (0..5)
        .map(|_| {
            tokio::spawn(async {
                let mut bash = test_bash().await;
                exec_result_or_err(
                    &mut bash,
                    "for i in $(seq 1 500); do x=$((i * 2)); done; echo done",
                )
                .await
            })
        })
        .collect();

    let results: Vec<_> = futures::future::join_all(handles).await;
    let elapsed = start.elapsed();

    for result in &results {
        let r = result.as_ref().unwrap();
        match r {
            Ok(exec_result) => assert!(
                exec_result.stdout.contains("done") || !exec_result.stderr.is_empty()
            ),
            Err(_) => {} // Resource limit is fine
        }
    }

    assert!(elapsed.as_secs() < 30, "took {}s, expected <30s", elapsed.as_secs());
}
