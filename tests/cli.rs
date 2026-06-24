//! End-to-end CLI tests: invoke the built `ce-iam` binary and assert exit codes, stdout shapes, and
//! the full mint -> wallet -> verify / role / root flows against an isolated temp `--data-dir`.
//!
//! These never touch the network for the offline paths (grant/verify-with-`--no-revocation-check`,
//! policy, role, wallet, root), so they are hermetic and fast. The binary is located via the
//! `CARGO_BIN_EXE_ce-iam` env var Cargo sets for integration tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ce-iam"))
}

fn data_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("ce-iam-cli-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run the binary with the given args under `dir`, returning the raw output.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .output()
        .expect("running ce-iam binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn whoami_prints_node_id() {
    let dir = data_dir("whoami");
    let out = run(&dir, &["whoami"]);
    assert!(out.status.success());
    let id = stdout(&out);
    assert_eq!(id.len(), 64, "node id is 64 hex chars: {id}");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    // --json shape.
    let out = run(&dir, &["whoami", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["node_id"], id);
}

#[test]
fn grant_then_verify_allow_and_deny() {
    let dir = data_dir("grant-verify");
    let me = stdout(&run(&dir, &["whoami"]));

    // Mint a grant to ourselves (so we are both issuer node and requester) for storage:read.
    let token = stdout(&run(
        &dir,
        &[
            "grant",
            "--to",
            &me,
            "--action",
            "storage:read",
            "--nonce",
            "1",
        ],
    ));
    assert!(!token.is_empty());

    // verify ALLOW -> exit 0.
    let out = run(
        &dir,
        &[
            "verify",
            "--token",
            &token,
            "--requester",
            &me,
            "--action",
            "storage:read",
            "--no-revocation-check",
        ],
    );
    assert!(out.status.success(), "expected ALLOW exit 0");
    assert!(stdout(&out).starts_with("ALLOW"));

    // verify DENY (action not granted) -> exit 1.
    let out = run(
        &dir,
        &[
            "verify",
            "--token",
            &token,
            "--requester",
            &me,
            "--action",
            "storage:write",
            "--no-revocation-check",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "expected DENY exit 1");
    assert!(stdout(&out).starts_with("DENY"));
}

#[test]
fn verify_json_shape() {
    let dir = data_dir("verify-json");
    let me = stdout(&run(&dir, &["whoami"]));
    let token = stdout(&run(
        &dir,
        &["grant", "--to", &me, "--action", "db:read", "--nonce", "5"],
    ));
    let out = run(
        &dir,
        &[
            "verify",
            "--token",
            &token,
            "--requester",
            &me,
            "--action",
            "db:read",
            "--no-revocation-check",
            "--json",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["authorized"], true);
}

#[test]
fn policy_validate_from_stdin_and_file() {
    use std::io::Write;
    let dir = data_dir("policy-validate");
    let policy = r#"{"version":"ce-iam-policy-v1","statements":[{"effect":"Allow","actions":["storage:*"],"resource":"any"}]}"#;

    // From file.
    let pf = dir.join("p.json");
    std::fs::write(&pf, policy).unwrap();
    let out = Command::new(bin())
        .arg("--data-dir")
        .arg(&dir)
        .args(["policy", "validate"])
        .arg(&pf)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).starts_with("OK"));

    // From stdin.
    let mut child = Command::new(bin())
        .arg("--data-dir")
        .arg(&dir)
        .args(["policy", "validate"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(policy.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).starts_with("OK"));
}

#[test]
fn role_catalog_flow_persists() {
    use std::io::Write;
    let dir = data_dir("role-flow");
    let alice = "ab".repeat(32);

    // Put a role from stdin.
    let policy = r#"{"version":"ce-iam-policy-v1","statements":[{"effect":"Allow","actions":["storage:read"],"resource":"any"}]}"#;
    let mut child = Command::new(bin())
        .arg("--data-dir")
        .arg(&dir)
        .args(["role", "put", "reader"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(policy.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "role put failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // List shows it.
    let out = run(&dir, &["role", "list", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["roles"][0], "reader");

    // Attach to alice, then effective-grants reflects it.
    assert!(
        run(&dir, &["role", "attach", &alice, "reader"])
            .status
            .success()
    );
    let out = run(&dir, &["role", "effective-grants", &alice, "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v[0]["abilities"][0], "storage:read");

    // A fresh process sees the persisted catalog (durability).
    let out = run(&dir, &["role", "get", "reader"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("storage:read"));

    // Detach removes the effective grant.
    assert!(
        run(&dir, &["role", "detach", &alice, "reader"])
            .status
            .success()
    );
    let out = run(&dir, &["role", "effective-grants", &alice]);
    assert!(stdout(&out).contains("no effective grants"));
}

#[test]
fn grant_from_role_then_verify() {
    use std::io::Write;
    let dir = data_dir("grant-role");
    let me = stdout(&run(&dir, &["whoami"]));

    let policy = r#"{"version":"ce-iam-policy-v1","statements":[{"effect":"Allow","actions":["run:invoke"],"resource":"any"}]}"#;
    let mut child = Command::new(bin())
        .arg("--data-dir")
        .arg(&dir)
        .args(["role", "put", "invoker"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(policy.as_bytes())
        .unwrap();
    assert!(child.wait_with_output().unwrap().status.success());

    let token = stdout(&run(
        &dir,
        &["grant", "--to", &me, "--role", "invoker", "--nonce", "9"],
    ));
    let out = run(
        &dir,
        &[
            "verify",
            "--token",
            &token,
            "--requester",
            &me,
            "--action",
            "run:invoke",
            "--no-revocation-check",
        ],
    );
    assert!(out.status.success());
}

#[test]
fn wallet_add_list_show_rm() {
    let dir = data_dir("wallet");
    let me = stdout(&run(&dir, &["whoami"]));
    let token = stdout(&run(
        &dir,
        &[
            "grant",
            "--to",
            &me,
            "--action",
            "storage:read",
            "--nonce",
            "1",
        ],
    ));

    assert!(run(&dir, &["wallet", "add", "g1", &token]).status.success());
    let out = run(&dir, &["wallet", "list", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v[0]["label"], "g1");

    // verify can reference the stored grant by label.
    let out = run(
        &dir,
        &[
            "verify",
            "--wallet-label",
            "g1",
            "--requester",
            &me,
            "--action",
            "storage:read",
            "--no-revocation-check",
        ],
    );
    assert!(out.status.success());

    // show prints the scope.
    let out = run(&dir, &["wallet", "show", "g1"]);
    assert!(stdout(&out).contains("storage:read"));

    assert!(run(&dir, &["wallet", "rm", "g1"]).status.success());
    let out = run(&dir, &["wallet", "list"]);
    assert!(stdout(&out).contains("empty"));
}

#[test]
fn root_add_list_retire() {
    let dir = data_dir("root");
    let key = "cd".repeat(32);
    assert!(
        run(&dir, &["root", "add", &key, "--label", "org"])
            .status
            .success()
    );
    let out = run(&dir, &["root", "list", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v[0]["label"], "org");
    // Retire and remove.
    assert!(run(&dir, &["root", "retire", &key]).status.success());
    assert!(run(&dir, &["root", "rm", &key]).status.success());
    let out = run(&dir, &["root", "list"]);
    assert!(stdout(&out).contains("no configured roots"));
}

#[test]
fn root_reissue_then_verify_under_new_root() {
    // Two isolated data dirs => two distinct node identities (old root issuer vs. new root).
    let old_dir = data_dir("reissue-old");
    let new_dir = data_dir("reissue-new");
    let alice = "12".repeat(32);
    let new_root = stdout(&run(&new_dir, &["whoami"]));

    // old root mints a grant for alice.
    let token = stdout(&run(
        &old_dir,
        &[
            "grant",
            "--to",
            &alice,
            "--action",
            "storage:read",
            "--nonce",
            "1",
        ],
    ));
    // new root re-issues it under its own key.
    let reissued = stdout(&run(&new_dir, &["root", "reissue", &token, "--nonce", "2"]));
    assert!(!reissued.is_empty());

    // Configure the old dir to accept the new root, then verify the reissued grant on the old node
    // targeting alice — accepted because it roots at the (now-accepted) new root.
    assert!(run(&old_dir, &["root", "add", &new_root]).status.success());
    let out = run(
        &old_dir,
        &[
            "verify",
            "--token",
            &reissued,
            "--requester",
            &alice,
            "--action",
            "storage:read",
            "--no-revocation-check",
            "--use-roots",
        ],
    );
    assert!(
        out.status.success(),
        "reissued grant should verify under the accepted new root: {}",
        stdout(&out)
    );
}

#[test]
fn verify_malformed_token_exits_nonzero_no_panic() {
    let dir = data_dir("malformed");
    let me = stdout(&run(&dir, &["whoami"]));
    let out = run(
        &dir,
        &[
            "verify",
            "--token",
            "zzznothex",
            "--requester",
            &me,
            "--action",
            "x",
            "--no-revocation-check",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).starts_with("DENY"));
}
