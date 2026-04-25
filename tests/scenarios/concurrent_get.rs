//! Two `bwx get` invocations against the same agent, launched in
//! parallel. The agent handles each incoming connection on its own
//! task, so both must complete and return the correct plaintext. This
//! catches regressions in the accept loop, state locking, or the
//! Touch ID session bookkeeping that would serialize or drop
//! simultaneous clients.

use std::process::Stdio;
use std::thread;

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn parallel_gets_both_succeed() {
    let server = skip_if_no_vaultwarden!();
    let email = "concurrent@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness.run_with_stdin(&["add", "conc.a"], b"pw-a\n\n\n");
    harness.run_with_stdin(&["add", "conc.b"], b"pw-b\n\n\n");

    // Spawn the two child processes nearly-simultaneously via threads
    // so they are more likely to collide on the agent's accept loop
    // than if we launched them sequentially from the same thread.
    // `thread::scope` lets the closures borrow `harness` without
    // moving it.
    let run_one = |name: &str| -> (std::process::ExitStatus, String) {
        let out = harness
            .cmd()
            .arg("get")
            .arg(name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn bwx get");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        (out.status, stdout)
    };

    let ((s1, out1), (s2, out2)) = thread::scope(|s| {
        let t1 = s.spawn(|| run_one("conc.a"));
        let t2 = s.spawn(|| run_one("conc.b"));
        (
            t1.join().expect("thread a panicked"),
            t2.join().expect("thread b panicked"),
        )
    });

    assert!(s1.success(), "concurrent get conc.a failed: {s1:?}");
    assert!(s2.success(), "concurrent get conc.b failed: {s2:?}");
    assert_eq!(out1.trim_end(), "pw-a");
    assert_eq!(out2.trim_end(), "pw-b");
}
