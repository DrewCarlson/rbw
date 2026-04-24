//! rbw-agent as the SSH signer for `ssh-keygen -Y sign` — the sshsig
//! format git uses for commit/tag signing under `gpg.format = ssh`. The
//! wire-level sign request is identical to plain ssh-agent signing: the
//! caller wraps the payload in an sshsig preamble before handing it to the
//! agent. This scenario exercises the user-facing recipe in the repo's
//! `SPIKE_CODE_SIGNING.md`: fetch the pubkey + `allowed_signers` via rbw,
//! sign through the agent, verify with `ssh-keygen -Y verify`.

use std::process::Command;

use crate::common::{
    authenticate, register_user, upload_ssh_cipher, RbwHarness,
};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn rbw_agent_signs_sshsig_via_ssh_keygen() {
    let server = skip_if_no_vaultwarden!();

    // Generate a throwaway ed25519 keypair locally.
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_path = tmp.path().join("id_ed25519");
    let kg = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "rbw-e2e-sshsig",
            "-f",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("ssh-keygen");
    assert!(kg.status.success(), "ssh-keygen failed");

    let priv_openssh = std::fs::read_to_string(&key_path).unwrap();
    let pub_line =
        std::fs::read_to_string(key_path.with_extension("pub")).unwrap();

    let email = "sshsig@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");
    let account =
        authenticate(&server, email, password).expect("authenticate");
    upload_ssh_cipher(
        &server,
        &account,
        "git.signing.key",
        &priv_openssh,
        pub_line.trim(),
        "SHA256:unknown",
    )
    .expect("upload");

    let harness = RbwHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["sync"]);

    // Point ssh-keygen at rbw-agent.
    let sock = harness.runtime_dir.join("rbw/ssh-agent-socket");

    // Obtain the pubkey via `rbw ssh-public-key` — the user-facing recipe.
    let pub_from_rbw = harness.check(&["ssh-public-key", "git.signing.key"]);
    assert_eq!(
        pub_from_rbw.trim(),
        pub_line.trim(),
        "rbw ssh-public-key diverged from uploaded value"
    );
    let pub_file = tmp.path().join("signer.pub");
    std::fs::write(&pub_file, pub_from_rbw.trim()).unwrap();

    let message_path = tmp.path().join("payload.txt");
    std::fs::write(&message_path, b"signed by rbw-agent via sshsig\n")
        .unwrap();

    // `ssh-keygen -Y sign -f pubkey -n namespace file` consults SSH_AUTH_SOCK
    // for the matching private key and writes `file.sig` next to `file`.
    let out = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f", pub_file.to_str().unwrap(), "-n", "git"])
        .arg(&message_path)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .expect("ssh-keygen -Y sign");
    assert!(
        out.status.success(),
        "ssh-keygen -Y sign failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let sig_path = message_path.with_extension("txt.sig");
    assert!(sig_path.exists(), "signature file not written");
    let sig = std::fs::read_to_string(&sig_path).unwrap();
    assert!(
        sig.starts_with("-----BEGIN SSH SIGNATURE-----"),
        "not an sshsig-formatted signature:\n{sig}"
    );

    // Verify the signature round-trips by using `-Y verify` against an
    // allowed_signers file emitted by `rbw ssh-allowed-signers`.
    let allowed = tmp.path().join("allowed_signers");
    std::fs::write(&allowed, harness.check(&["ssh-allowed-signers"]))
        .unwrap();

    let vfy = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-f",
            allowed.to_str().unwrap(),
            "-I",
            email,
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(std::fs::File::open(&message_path).unwrap())
        .output()
        .expect("ssh-keygen -Y verify");
    assert!(
        vfy.status.success(),
        "ssh-keygen -Y verify failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&vfy.stdout),
        String::from_utf8_lossy(&vfy.stderr),
    );
}
