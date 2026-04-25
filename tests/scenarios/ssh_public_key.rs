use crate::common::{
    authenticate, register_user, upload_ssh_cipher, BwxHarness,
};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn ssh_public_key_roundtrips() {
    let server = skip_if_no_vaultwarden!();

    // Generate a throwaway ed25519 keypair.
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_path = tmp.path().join("id_ed25519");
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "bwx-e2e-pubkey",
            "-f",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("ssh-keygen");
    if !status.status.success() {
        eprintln!("skipping: ssh-keygen unavailable");
        return;
    }

    let priv_openssh = std::fs::read_to_string(&key_path).unwrap();
    let pub_line =
        std::fs::read_to_string(key_path.with_extension("pub")).unwrap();

    let email = "ssh_pub@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");
    let account =
        authenticate(&server, email, password).expect("authenticate");
    upload_ssh_cipher(
        &server,
        &account,
        "git.signer",
        &priv_openssh,
        pub_line.trim(),
        "SHA256:unknown",
    )
    .expect("upload");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["sync"]);

    // Primary command: print the stored OpenSSH public key.
    let got = harness.check(&["ssh-public-key", "git.signer"]);
    assert_eq!(
        got.trim(),
        pub_line.trim(),
        "ssh-public-key output doesn't match uploaded key"
    );

    // allowed_signers listing includes the email + matching pubkey.
    let signers = harness.check(&["ssh-allowed-signers"]);
    let line = signers
        .lines()
        .find(|l| l.contains(pub_line.split_whitespace().nth(1).unwrap()))
        .expect("allowed_signers missing our key");
    assert!(
        line.starts_with(&format!("{email} ")),
        "allowed_signers line doesn't lead with email: {line:?}"
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn ssh_public_key_rejects_non_ssh_entry() {
    let server = skip_if_no_vaultwarden!();

    let email = "ssh_pub_neg@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // A regular Login entry is not an SSH key.
    harness
        .run_with_stdin(&["add", "not.a.key"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add failed");

    let out = harness.run(&["ssh-public-key", "not.a.key"]);
    assert!(!out.status.success(), "should have failed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not an SSH key"),
        "unexpected error message: {stderr}"
    );
}
