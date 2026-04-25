use std::process::Command;

use ssh_agent_lib::blocking::Client;
use ssh_agent_lib::proto::SignRequest;
use ssh_agent_lib::ssh_key::PublicKey;

use crate::common::{
    authenticate, register_user, upload_ssh_cipher, BwxHarness,
    VaultwardenServer,
};
use crate::skip_if_no_vaultwarden;

fn upload_and_sync(
    server: &VaultwardenServer,
    harness: &BwxHarness,
    email: &str,
    password: &str,
    cipher_name: &str,
) -> (tempfile::TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_path = tmp.path().join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "bwx-e2e-confirm",
            "-f",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("ssh-keygen");
    assert!(status.status.success(), "ssh-keygen failed");
    let priv_openssh = std::fs::read_to_string(&key_path).unwrap();
    let pub_line =
        std::fs::read_to_string(key_path.with_extension("pub")).unwrap();

    let account = authenticate(server, email, password).expect("auth");
    upload_ssh_cipher(
        server,
        &account,
        cipher_name,
        &priv_openssh,
        pub_line.trim(),
        "SHA256:unknown",
    )
    .expect("upload");
    harness.check(&["sync"]);
    (tmp, pub_line)
}

fn agent_stream(sock: &std::path::Path) -> std::os::unix::net::UnixStream {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(s) => break s,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("ssh socket unreachable: {e}"),
        }
    }
}

/// With `ssh_confirm_sign = true` and the fake pinentry auto-accepting the
/// CONFIRM dialog, signing should still succeed end-to-end.
#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn confirm_accept_allows_sign() {
    let server = skip_if_no_vaultwarden!();

    let email = "ssh_confirm_ok@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["config", "set", "ssh_confirm_sign", "true"]);

    // `config set` stops the agent; re-login so the fresh agent picks up
    // the new config value.
    harness.check(&["login"]);
    harness.check(&["unlock"]);

    let (_keydir, pub_line) =
        upload_and_sync(&server, &harness, email, password, "ok.key");

    let sock = harness.runtime_dir.join("bwx/ssh-agent-socket");
    let mut client = Client::new(agent_stream(&sock));
    let idents = client.request_identities().expect("ids");
    let expected = PublicKey::from_openssh(&pub_line).expect("parse pub");
    let ident = idents
        .iter()
        .find(|i| &i.pubkey == expected.key_data())
        .expect("uploaded key missing");

    let sig = client
        .sign(SignRequest {
            pubkey: ident.pubkey.clone(),
            data: b"with confirm".to_vec(),
            flags: 0,
        })
        .expect("sign should succeed when pinentry accepts");
    assert_eq!(sig.algorithm().as_str(), "ssh-ed25519");
    assert_eq!(sig.as_bytes().len(), 64);
}

/// When the user cancels the CONFIRM dialog, sign must fail and no
/// signature must be returned to the ssh client.
#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn confirm_decline_blocks_sign() {
    let server = skip_if_no_vaultwarden!();

    let email = "ssh_confirm_deny@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["config", "set", "ssh_confirm_sign", "true"]);
    harness.check(&["login"]);
    harness.check(&["unlock"]);

    let (_keydir, pub_line) =
        upload_and_sync(&server, &harness, email, password, "deny.key");

    // Swap the pinentry so CONFIRM returns ERR. Subsequent pinentry spawns
    // (including the one the agent kicks off for CONFIRM) pick up the new
    // script on disk.
    harness.reject_confirm_prompts();

    let sock = harness.runtime_dir.join("bwx/ssh-agent-socket");
    let mut client = Client::new(agent_stream(&sock));
    let idents = client.request_identities().expect("ids");
    let expected = PublicKey::from_openssh(&pub_line).expect("parse pub");
    let ident = idents
        .iter()
        .find(|i| &i.pubkey == expected.key_data())
        .expect("uploaded key missing");

    let res = client.sign(SignRequest {
        pubkey: ident.pubkey.clone(),
        data: b"declined".to_vec(),
        flags: 0,
    });
    assert!(
        res.is_err(),
        "sign unexpectedly succeeded when user cancelled: {:?}",
        res.ok().map(|s| s.algorithm().to_string())
    );
}
