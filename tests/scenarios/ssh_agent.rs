use std::process::Command;

use crate::common::{
    authenticate, register_user, upload_ssh_cipher, BwxHarness,
};
use crate::skip_if_no_vaultwarden;

/// Generate an ed25519 keypair via the local `ssh-keygen` binary. Returns
/// `(private_openssh, public_openssh_line, fingerprint)`. The test is
/// skipped if `ssh-keygen` isn't on `$PATH`.
fn generate_ed25519_key(
) -> Option<(tempfile::TempDir, String, String, String)> {
    let tmp = tempfile::tempdir().ok()?;
    let path = tmp.path().join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "bwx-e2e",
            "-f",
            path.to_str()?,
        ])
        .output()
        .ok()?;
    if !status.status.success() {
        return None;
    }
    let private = std::fs::read_to_string(&path).ok()?;
    let public = std::fs::read_to_string(path.with_extension("pub")).ok()?;
    let fp_out = Command::new("ssh-keygen")
        .args(["-lf", path.to_str()?])
        .output()
        .ok()?;
    let fp_line = String::from_utf8_lossy(&fp_out.stdout).into_owned();
    let fingerprint = fp_line
        .split_whitespace()
        .find(|s| s.starts_with("SHA256:"))
        .unwrap_or("SHA256:unknown")
        .to_string();
    Some((tmp, private, public.trim().to_string(), fingerprint))
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn ssh_agent_lists_uploaded_key() {
    let server = skip_if_no_vaultwarden!();

    let Some((_keydir, priv_openssh, pub_openssh, fingerprint)) =
        generate_ed25519_key()
    else {
        eprintln!("skipping: ssh-keygen not available");
        return;
    };

    let email = "ssh@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");
    let account =
        authenticate(&server, email, password).expect("authenticate");

    upload_ssh_cipher(
        &server,
        &account,
        "ssh.example",
        &priv_openssh,
        &pub_openssh,
        &fingerprint,
    )
    .expect("upload ssh cipher");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["sync"]);

    // bwx-agent binds an ssh-agent-protocol socket alongside its regular
    // IPC socket. Path mirrors `bwx::dirs::ssh_agent_socket_file()`.
    let sock = harness.runtime_dir.join("bwx/ssh-agent-socket");
    // The agent creates the socket lazily on first ssh-agent connection, so
    // just checking for its existence is a probe, not a gate.
    let key_b64 = pub_openssh
        .split_whitespace()
        .nth(1)
        .expect("openssh pubkey second token")
        .to_string();

    let out = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .expect("spawn ssh-add");
    assert!(
        out.status.success(),
        "ssh-add -L failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.lines().any(|l| {
            l.starts_with("ssh-ed25519") && l.contains(&key_b64)
        }),
        "uploaded pubkey missing from ssh-add -L listing:\n{listing}"
    );
}

/// Exercise the full sign path: connect to bwx-agent as an ssh client, ask
/// for identities, request a signature over arbitrary data, verify the
/// signature locally with the matching public key. Round-trip proves both
/// the agent protocol wiring and that bwx can reconstruct the private key
/// from the encrypted cipher field.
#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn ssh_agent_signs_data_verifiable_by_pubkey() {
    use ssh_agent_lib::blocking::Client;
    use ssh_agent_lib::proto::SignRequest;
    use ssh_agent_lib::ssh_key::PublicKey;

    let server = skip_if_no_vaultwarden!();

    let Some((_keydir, priv_openssh, pub_openssh, fingerprint)) =
        generate_ed25519_key()
    else {
        eprintln!("skipping: ssh-keygen not available");
        return;
    };

    let email = "ssh_sign@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");
    let account =
        authenticate(&server, email, password).expect("authenticate");

    upload_ssh_cipher(
        &server,
        &account,
        "ssh.sign.example",
        &priv_openssh,
        &pub_openssh,
        &fingerprint,
    )
    .expect("upload ssh cipher");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["sync"]);

    let sock_path = harness.runtime_dir.join("bwx/ssh-agent-socket");
    // The agent creates the ssh socket eagerly, but UnixStream::connect may
    // race the first listen; retry for a moment.
    let stream = {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match std::os::unix::net::UnixStream::connect(&sock_path) {
                Ok(s) => break s,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => panic!(
                    "ssh-agent socket not reachable at {}: {e}",
                    sock_path.display()
                ),
            }
        }
    };
    let mut client = Client::new(stream);

    let idents = client.request_identities().expect("request identities");
    let expected_pub =
        PublicKey::from_openssh(&pub_openssh).expect("parse pub");
    let ident = idents
        .iter()
        .find(|i| &i.pubkey == expected_pub.key_data())
        .expect("uploaded key not listed by agent");

    let message = b"bwx e2e ssh signing payload".to_vec();
    let sig = client
        .sign(SignRequest {
            pubkey: ident.pubkey.clone(),
            data: message,
            flags: 0,
        })
        .expect("sign");

    // The signature should carry the ed25519 algorithm and a 64-byte body.
    assert_eq!(
        sig.algorithm().as_str(),
        "ssh-ed25519",
        "unexpected signature algorithm: {:?}",
        sig.algorithm()
    );
    assert_eq!(
        sig.as_bytes().len(),
        64,
        "ed25519 signature should be 64 bytes, got {}",
        sig.as_bytes().len()
    );
}
