use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn list_raw_emits_json() {
    let server = skip_if_no_vaultwarden!();

    let email = "raw@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness
        .run_with_stdin(&["add", "raw.example"], b"rawpw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add failed");

    let out = harness.check(&["list", "--raw"]);
    let parsed: serde_json::Value =
        serde_json::from_str(out.trim()).expect("list --raw is not JSON");
    let arr = parsed.as_array().expect("expected a JSON array");
    assert!(
        arr.iter()
            .any(|e| e.get("name").and_then(|v| v.as_str())
                == Some("raw.example")),
        "raw.example missing from JSON listing: {arr:?}"
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn get_raw_emits_json_with_password() {
    let server = skip_if_no_vaultwarden!();

    let email = "raw_get@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness
        .run_with_stdin(&["add", "raw.login"], b"secret\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add failed");

    let out = harness.check(&["get", "--raw", "raw.login"]);
    let parsed: serde_json::Value =
        serde_json::from_str(out.trim()).expect("get --raw is not JSON");
    let data = parsed.get("data").unwrap_or(&parsed);
    let pw = data
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("no password field in {parsed:?}"));
    assert_eq!(pw, "secret");
}
