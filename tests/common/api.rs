use bwx::cipherstring::CipherString;
use bwx::identity::Identity;
use bwx::locked;
use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

use super::server::VaultwardenServer;

const KDF_ITERATIONS: u32 = 600_000;
const KDF_TYPE_PBKDF2: u8 = 0;

/// Register a new account against `/identity/accounts/register`, mirroring
/// the Bitwarden web vault's payload (PBKDF2 master key, wrapped 64-byte
/// vault key, fresh RSA keypair).
pub fn register_user(
    server: &VaultwardenServer,
    email: &str,
    password: &str,
) -> Result<(), String> {
    let mut pw_vec = locked::Vec::new();
    pw_vec.extend(password.as_bytes().iter().copied());
    let locked_pw = locked::Password::new(pw_vec);

    let identity = Identity::new(
        email,
        &locked_pw,
        bwx::api::KdfType::Pbkdf2,
        KDF_ITERATIONS,
        None,
        None,
    )
    .map_err(|e| format!("derive identity: {e}"))?;

    // Random 64-byte vault key (enc_key||mac_key), wrapped with the stretched
    // master key.
    use rand_8::RngCore as _;
    let mut vault_bytes = [0u8; 64];
    rand_8::rngs::OsRng.fill_bytes(&mut vault_bytes);

    let protected_symmetric_key =
        CipherString::encrypt_symmetric(&identity.keys, &vault_bytes)
            .map_err(|e| format!("encrypt vault key: {e}"))?
            .to_string();

    let mut vault_keys_buf = locked::Vec::new();
    vault_keys_buf.extend(vault_bytes.iter().copied());
    let vault_keys = locked::Keys::new(vault_keys_buf);

    // RSA-2048 keypair: public key as raw SPKI DER (base64); private key as
    // PKCS#8 DER wrapped with the vault key.
    let mut rng = rand_8::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("generate rsa: {e}"))?;
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);

    let pub_spki_der = rsa_pub
        .to_public_key_der()
        .map_err(|e| format!("encode rsa pub: {e}"))?;
    let pub_b64 = base64_encode(pub_spki_der.as_bytes());

    let priv_pkcs8 = rsa_priv
        .to_pkcs8_der()
        .map_err(|e| format!("encode rsa priv: {e}"))?;
    let wrapped_priv =
        CipherString::encrypt_symmetric(&vault_keys, priv_pkcs8.as_bytes())
            .map_err(|e| format!("wrap rsa priv: {e}"))?
            .to_string();

    let mph_b64 = base64_encode(identity.master_password_hash.hash());

    let body = serde_json::json!({
        "email": email,
        "name": email,
        "masterPasswordHash": mph_b64,
        "masterPasswordHint": null,
        "key": protected_symmetric_key,
        "keys": {
            "publicKey": pub_b64,
            "encryptedPrivateKey": wrapped_priv,
        },
        "kdf": KDF_TYPE_PBKDF2,
        "kdfIterations": KDF_ITERATIONS,
        "referenceData": null,
    });

    let url = format!("{}/identity/accounts/register", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .map_err(|e| format!("POST register: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!("register failed: {status} body={text}"));
    }
    Ok(())
}

fn base64_encode(b: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.encode(b)
}

fn base64_encode_url_safe_no_pad(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(b)
}

pub struct Account {
    pub access_token: String,
    pub vault_keys: locked::Keys,
}

/// Authenticate against vaultwarden's /identity/connect/token password flow,
/// in-process, so tests can POST ciphers directly to the server.
pub fn authenticate(
    server: &VaultwardenServer,
    email: &str,
    password: &str,
) -> Result<Account, String> {
    let mut pw_vec = locked::Vec::new();
    pw_vec.extend(password.as_bytes().iter().copied());
    let locked_pw = locked::Password::new(pw_vec);

    let identity = Identity::new(
        email,
        &locked_pw,
        bwx::api::KdfType::Pbkdf2,
        KDF_ITERATIONS,
        None,
        None,
    )
    .map_err(|e| format!("derive identity: {e}"))?;

    let form = [
        ("grant_type", "password"),
        ("scope", "api offline_access"),
        ("client_id", "cli"),
        ("deviceType", "8"),
        ("deviceIdentifier", "00000000-0000-0000-0000-000000000001"),
        ("deviceName", "bwx-e2e"),
        ("devicePushToken", ""),
        ("username", email),
        (
            "password",
            &base64_encode(identity.master_password_hash.hash()),
        ),
    ];

    let url = format!("{}/identity/connect/token", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header(
            "auth-email",
            base64_encode_url_safe_no_pad(email.as_bytes()),
        )
        .form(&form)
        .send()
        .map_err(|e| format!("POST token: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!("token failed: {status} body={text}"));
    }
    let body: serde_json::Value =
        resp.json().map_err(|e| format!("token json: {e}"))?;
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no access_token in response: {body}"))?
        .to_string();
    let protected_key = body
        .get("Key")
        .or_else(|| body.get("key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no key in response: {body}"))?;

    let wrapped = CipherString::new(protected_key)
        .map_err(|e| format!("parse key: {e}"))?;
    let vault_vec = wrapped
        .decrypt_locked_symmetric(&identity.keys)
        .map_err(|e| format!("unwrap vault key: {e}"))?;
    let vault_keys = locked::Keys::new(vault_vec);

    Ok(Account {
        access_token,
        vault_keys,
    })
}

/// Upload an `SshKey` cipher (Bitwarden type 5). `private_key_openssh` is
/// the full PEM-wrapped OpenSSH private key; `public_key_openssh` is the
/// single line `ssh-ed25519 AAAA... [comment]` form; `fingerprint` is
/// typically `SHA256:…`. All three are encrypted client-side.
pub fn upload_ssh_cipher(
    server: &VaultwardenServer,
    account: &Account,
    name: &str,
    private_key_openssh: &str,
    public_key_openssh: &str,
    fingerprint: &str,
) -> Result<(), String> {
    let encrypt = |s: &str| -> Result<String, String> {
        CipherString::encrypt_symmetric(&account.vault_keys, s.as_bytes())
            .map(|c| c.to_string())
            .map_err(|e| format!("encrypt field: {e}"))
    };

    let body = serde_json::json!({
        "type": 5,
        "name": encrypt(name)?,
        "notes": null,
        "favorite": false,
        "folderId": null,
        "organizationId": null,
        "sshKey": {
            "privateKey": encrypt(private_key_openssh)?,
            "publicKey": encrypt(public_key_openssh)?,
            "keyFingerprint": encrypt(fingerprint)?,
        },
    });

    let url = format!("{}/api/ciphers", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&account.access_token)
        .json(&body)
        .send()
        .map_err(|e| format!("POST ssh cipher: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!(
            "ssh cipher upload failed: {status} body={text}"
        ));
    }
    Ok(())
}

/// Upload a Login cipher. Fields are encrypted client-side with the
/// account's vault key before transmission.
pub fn upload_login_cipher(
    server: &VaultwardenServer,
    account: &Account,
    name: &str,
    totp: Option<&str>,
    username: Option<&str>,
    password_value: Option<&str>,
) -> Result<(), String> {
    let encrypt = |s: &str| -> Result<String, String> {
        CipherString::encrypt_symmetric(&account.vault_keys, s.as_bytes())
            .map(|c| c.to_string())
            .map_err(|e| format!("encrypt field: {e}"))
    };

    let enc_name = encrypt(name)?;
    let enc_totp = totp.map(encrypt).transpose()?;
    let enc_user = username.map(encrypt).transpose()?;
    let enc_password = password_value.map(encrypt).transpose()?;

    let body = serde_json::json!({
        "type": 1,
        "name": enc_name,
        "notes": null,
        "favorite": false,
        "folderId": null,
        "organizationId": null,
        "login": {
            "username": enc_user,
            "password": enc_password,
            "totp": enc_totp,
            "uris": null,
        },
    });

    let url = format!("{}/api/ciphers", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&account.access_token)
        .json(&body)
        .send()
        .map_err(|e| format!("POST cipher: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!("cipher upload failed: {status} body={text}"));
    }
    Ok(())
}
