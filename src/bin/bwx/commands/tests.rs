use super::cipher::DecryptedSearchCipher;
use super::exec::EnvSpec;
use super::find::{find_entry_raw, parse_needle};
use super::totp::decode_totp_secret;
use super::util::format_rfc3339;

#[test]
fn env_spec_parse_simple() {
    let s = EnvSpec::parse("AWS_KEY=aws/prod").unwrap();
    assert_eq!(s.var, "AWS_KEY");
    assert_eq!(s.entry, "aws/prod");
    assert_eq!(s.field, None);
}

#[test]
fn env_spec_parse_with_field() {
    let s = EnvSpec::parse("DB_URL=db/prod#uri").unwrap();
    assert_eq!(s.var, "DB_URL");
    assert_eq!(s.entry, "db/prod");
    assert_eq!(s.field.as_deref(), Some("uri"));
}

#[test]
fn env_spec_parse_field_uses_last_hash() {
    // Names containing '#' are unusual but legal in Bitwarden;
    // rsplit_once means only the final '#' delimits the field, so
    // an entry literally named "weird#name" can still take a
    // `#password` suffix.
    let s = EnvSpec::parse("X=weird#name#password").unwrap();
    assert_eq!(s.entry, "weird#name");
    assert_eq!(s.field.as_deref(), Some("password"));
}

#[test]
fn env_spec_parse_underscore_and_digits() {
    let s = EnvSpec::parse("_FOO_BAR2=item").unwrap();
    assert_eq!(s.var, "_FOO_BAR2");
}

#[test]
fn env_spec_parse_uuid_entry() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let s = EnvSpec::parse(&format!("TOK={uuid}#password")).unwrap();
    assert_eq!(s.entry, uuid);
    assert_eq!(s.field.as_deref(), Some("password"));
}

#[test]
fn env_spec_parse_uri_entry() {
    let s = EnvSpec::parse("PW=https://github.com").unwrap();
    assert_eq!(s.entry, "https://github.com");
    assert_eq!(s.field, None);
}

#[test]
fn env_spec_parse_rejects_missing_eq() {
    let err = EnvSpec::parse("FOO").unwrap_err().to_string();
    assert!(err.contains("expected VAR=ENTRY"), "got: {err}");
}

#[test]
fn env_spec_parse_rejects_empty_var() {
    let err = EnvSpec::parse("=foo").unwrap_err().to_string();
    assert!(err.contains("empty env var"), "got: {err}");
}

#[test]
fn env_spec_parse_rejects_empty_entry() {
    let err = EnvSpec::parse("FOO=").unwrap_err().to_string();
    assert!(err.contains("empty entry"), "got: {err}");
}

#[test]
fn env_spec_parse_rejects_leading_digit() {
    let err = EnvSpec::parse("1FOO=bar").unwrap_err().to_string();
    assert!(err.contains("not a valid env var name"), "got: {err}");
}

#[test]
fn env_spec_parse_rejects_invalid_chars() {
    let err = EnvSpec::parse("FOO-BAR=baz").unwrap_err().to_string();
    assert!(err.contains("not a valid env var name"), "got: {err}");
}

#[test]
fn env_spec_parse_empty_field_is_treated_as_no_field() {
    // Trailing '#' with no field name is a no-op; defaulting to
    // `password` later keeps the syntax forgiving.
    let s = EnvSpec::parse("X=foo#").unwrap();
    assert_eq!(s.entry, "foo#");
    assert_eq!(s.field, None);
}

#[test]
fn format_rfc3339_epoch() {
    let out = format_rfc3339(std::time::UNIX_EPOCH);
    assert_eq!(out, "1970-01-01T00:00:00.000000000Z");
}

#[test]
fn format_rfc3339_known_dates() {
    let cases = &[
        (946_684_800_u64, "2000-01-01T00:00:00.000000000Z"),
        (1_709_210_096_u64, "2024-02-29T12:34:56.000000000Z"),
        (2_147_483_647_u64, "2038-01-19T03:14:07.000000000Z"),
        (4_107_542_400_u64, "2100-03-01T00:00:00.000000000Z"),
    ];
    for (secs, expected) in cases {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(*secs);
        assert_eq!(&format_rfc3339(t), expected, "secs={secs}");
    }
}

#[test]
fn format_rfc3339_preserves_subsec_nanos() {
    let t = std::time::UNIX_EPOCH
        + std::time::Duration::new(1_700_000_000, 123_456_789);
    assert_eq!(format_rfc3339(t), "2023-11-14T22:13:20.123456789Z");
}

#[test]
fn test_find_entry() {
    let entries = &[
        make_entry("github", Some("foo"), None, &[]),
        make_entry("gitlab", Some("foo"), None, &[]),
        make_entry("gitlab", Some("bar"), None, &[]),
        make_entry("gitter", Some("baz"), None, &[]),
        make_entry("git", Some("foo"), None, &[]),
        make_entry("bitwarden", None, None, &[]),
        make_entry("github", Some("foo"), Some("websites"), &[]),
        make_entry("github", Some("foo"), Some("ssh"), &[]),
        make_entry("github", Some("root"), Some("ssh"), &[]),
        make_entry("codeberg", Some("foo"), None, &[]),
        make_entry("codeberg", None, None, &[]),
        make_entry("1password", Some("foo"), None, &[]),
        make_entry("1password", None, Some("foo"), &[]),
    ];

    assert!(
        one_match(entries, "github", Some("foo"), None, 0, false),
        "foo@github"
    );
    assert!(
        one_match(entries, "GITHUB", Some("foo"), None, 0, true),
        "foo@GITHUB"
    );
    assert!(one_match(entries, "github", None, None, 0, false), "github");
    assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
    assert!(
        one_match(entries, "gitlab", Some("foo"), None, 1, false),
        "foo@gitlab"
    );
    assert!(
        one_match(entries, "GITLAB", Some("foo"), None, 1, true),
        "foo@GITLAB"
    );
    assert!(
        one_match(entries, "git", Some("bar"), None, 2, false),
        "bar@git"
    );
    assert!(
        one_match(entries, "GIT", Some("bar"), None, 2, true),
        "bar@GIT"
    );
    assert!(
        one_match(entries, "gitter", Some("ba"), None, 3, false),
        "ba@gitter"
    );
    assert!(
        one_match(entries, "GITTER", Some("ba"), None, 3, true),
        "ba@GITTER"
    );
    assert!(
        one_match(entries, "git", Some("foo"), None, 4, false),
        "foo@git"
    );
    assert!(
        one_match(entries, "GIT", Some("foo"), None, 4, true),
        "foo@GIT"
    );
    assert!(one_match(entries, "git", None, None, 4, false), "git");
    assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
    assert!(
        one_match(entries, "bitwarden", None, None, 5, false),
        "bitwarden"
    );
    assert!(
        one_match(entries, "BITWARDEN", None, None, 5, true),
        "BITWARDEN"
    );
    assert!(
        one_match(entries, "github", Some("foo"), Some("websites"), 6, false),
        "websites/foo@github"
    );
    assert!(
        one_match(entries, "GITHUB", Some("foo"), Some("websites"), 6, true),
        "websites/foo@GITHUB"
    );
    assert!(
        one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
        "ssh/foo@github"
    );
    assert!(
        one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
        "ssh/foo@GITHUB"
    );
    assert!(
        one_match(entries, "github", Some("root"), None, 8, false),
        "ssh/root@github"
    );
    assert!(
        one_match(entries, "GITHUB", Some("root"), None, 8, true),
        "ssh/root@GITHUB"
    );

    assert!(
        no_matches(entries, "gitlab", Some("baz"), None, false),
        "baz@gitlab"
    );
    assert!(
        no_matches(entries, "GITLAB", Some("baz"), None, true),
        "baz@"
    );
    assert!(
        no_matches(entries, "bitbucket", Some("foo"), None, false),
        "foo@bitbucket"
    );
    assert!(
        no_matches(entries, "BITBUCKET", Some("foo"), None, true),
        "foo@BITBUCKET"
    );
    assert!(
        no_matches(entries, "github", Some("foo"), Some("bar"), false),
        "bar/foo@github"
    );
    assert!(
        no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
        "bar/foo@"
    );
    assert!(
        no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
        "bar/foo@gitlab"
    );
    assert!(
        no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
        "bar/foo@GITLAB"
    );

    assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
    assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
    assert!(
        many_matches(entries, "gi", Some("foo"), None, false),
        "foo@gi"
    );
    assert!(
        many_matches(entries, "GI", Some("foo"), None, true),
        "foo@GI"
    );
    assert!(
        many_matches(entries, "git", Some("ba"), None, false),
        "ba@git"
    );
    assert!(
        many_matches(entries, "GIT", Some("ba"), None, true),
        "ba@GIT"
    );
    assert!(
        many_matches(entries, "github", Some("foo"), Some("s"), false),
        "s/foo@github"
    );
    assert!(
        many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
        "s/foo@GITHUB"
    );

    assert!(
        one_match(entries, "codeberg", Some("foo"), None, 9, false),
        "foo@codeberg"
    );
    assert!(
        one_match(entries, "codeberg", None, None, 10, false),
        "codeberg"
    );
    assert!(
        no_matches(entries, "codeberg", Some("bar"), None, false),
        "bar@codeberg"
    );

    assert!(
        many_matches(entries, "1password", None, None, false),
        "1password"
    );
}

#[test]
fn test_find_by_uuid() {
    let entries = &[
        make_entry("github", Some("foo"), None, &[]),
        make_entry("gitlab", Some("foo"), None, &[]),
        make_entry("gitlab", Some("bar"), None, &[]),
        make_entry("12345678-1234-1234-1234-1234567890ab", None, None, &[]),
        make_entry("12345678-1234-1234-1234-1234567890AC", None, None, &[]),
        make_entry("123456781234123412341234567890AD", None, None, &[]),
    ];

    assert!(
        one_match(entries, &entries[0].0.id, None, None, 0, false),
        "foo@github"
    );
    assert!(
        one_match(entries, &entries[1].0.id, None, None, 1, false),
        "foo@gitlab"
    );
    assert!(
        one_match(entries, &entries[2].0.id, None, None, 2, false),
        "bar@gitlab"
    );

    assert!(
        one_match(
            entries,
            &entries[0].0.id.to_uppercase(),
            None,
            None,
            0,
            false
        ),
        "foo@github"
    );
    assert!(
        one_match(
            entries,
            &entries[0].0.id.to_lowercase(),
            None,
            None,
            0,
            false
        ),
        "foo@github"
    );

    assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
    assert!(one_match(
        entries,
        "12345678-1234-1234-1234-1234567890ab",
        None,
        None,
        3,
        false
    ));
    assert!(no_matches(
        entries,
        "12345678-1234-1234-1234-1234567890AB",
        None,
        None,
        false
    ));
    assert!(one_match(
        entries,
        "12345678-1234-1234-1234-1234567890AB",
        None,
        None,
        3,
        true
    ));
    assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
    assert!(one_match(
        entries,
        "12345678-1234-1234-1234-1234567890AC",
        None,
        None,
        4,
        false
    ));
    assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
    assert!(one_match(
        entries,
        "123456781234123412341234567890AD",
        None,
        None,
        5,
        false
    ));
}

#[test]
fn test_find_by_url_default() {
    let entries = &[
        make_entry("one", None, None, &[("https://one.com/", None)]),
        make_entry("two", None, None, &[("https://two.com/login", None)]),
        make_entry(
            "three",
            None,
            None,
            &[("https://login.three.com/", None)],
        ),
        make_entry("four", None, None, &[("four.com", None)]),
        make_entry("five", None, None, &[("https://five.com:8080/", None)]),
        make_entry("six", None, None, &[("six.com:8080", None)]),
        make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
    ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://login.one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com:443/", None, None, 0, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        one_match(entries, "https://two.com/", None, None, 1, false),
        "two"
    );
    assert!(
        one_match(
            entries,
            "https://two.com/other-page",
            None,
            None,
            1,
            false
        ),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );

    assert!(
        one_match(entries, "https://four.com/", None, None, 3, false),
        "four"
    );

    assert!(
        one_match(entries, "https://five.com:8080/", None, None, 4, false),
        "five"
    );
    assert!(
        no_matches(entries, "https://five.com/", None, None, false),
        "five"
    );

    assert!(
        one_match(entries, "https://six.com:8080/", None, None, 5, false),
        "six"
    );
    assert!(
        no_matches(entries, "https://six.com/", None, None, false),
        "six"
    );
    assert!(
        one_match(
            entries,
            "https://192.168.0.128:8080/",
            None,
            None,
            6,
            false
        ),
        "seven"
    );
    assert!(
        no_matches(entries, "https://192.168.0.128/", None, None, false),
        "seven"
    );
}

#[test]
fn test_find_by_url_domain() {
    let entries = &[
        make_entry(
            "one",
            None,
            None,
            &[("https://one.com/", Some(bwx::api::UriMatchType::Domain))],
        ),
        make_entry(
            "two",
            None,
            None,
            &[(
                "https://two.com/login",
                Some(bwx::api::UriMatchType::Domain),
            )],
        ),
        make_entry(
            "three",
            None,
            None,
            &[(
                "https://login.three.com/",
                Some(bwx::api::UriMatchType::Domain),
            )],
        ),
        make_entry(
            "four",
            None,
            None,
            &[("four.com", Some(bwx::api::UriMatchType::Domain))],
        ),
        make_entry(
            "five",
            None,
            None,
            &[(
                "https://five.com:8080/",
                Some(bwx::api::UriMatchType::Domain),
            )],
        ),
        make_entry(
            "six",
            None,
            None,
            &[("six.com:8080", Some(bwx::api::UriMatchType::Domain))],
        ),
        make_entry(
            "seven",
            None,
            None,
            &[("192.168.0.128:8080", Some(bwx::api::UriMatchType::Domain))],
        ),
    ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://login.one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com:443/", None, None, 0, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        one_match(entries, "https://two.com/", None, None, 1, false),
        "two"
    );
    assert!(
        one_match(
            entries,
            "https://two.com/other-page",
            None,
            None,
            1,
            false
        ),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );

    assert!(
        one_match(entries, "https://four.com/", None, None, 3, false),
        "four"
    );

    assert!(
        one_match(entries, "https://five.com:8080/", None, None, 4, false),
        "five"
    );
    assert!(
        no_matches(entries, "https://five.com/", None, None, false),
        "five"
    );

    assert!(
        one_match(entries, "https://six.com:8080/", None, None, 5, false),
        "six"
    );
    assert!(
        no_matches(entries, "https://six.com/", None, None, false),
        "six"
    );
    assert!(
        one_match(
            entries,
            "https://192.168.0.128:8080/",
            None,
            None,
            6,
            false
        ),
        "seven"
    );
    assert!(
        no_matches(entries, "https://192.168.0.128/", None, None, false),
        "seven"
    );
}

#[test]
fn test_find_by_url_host() {
    let entries = &[
        make_entry(
            "one",
            None,
            None,
            &[("https://one.com/", Some(bwx::api::UriMatchType::Host))],
        ),
        make_entry(
            "two",
            None,
            None,
            &[("https://two.com/login", Some(bwx::api::UriMatchType::Host))],
        ),
        make_entry(
            "three",
            None,
            None,
            &[(
                "https://login.three.com/",
                Some(bwx::api::UriMatchType::Host),
            )],
        ),
        make_entry(
            "four",
            None,
            None,
            &[("four.com", Some(bwx::api::UriMatchType::Host))],
        ),
        make_entry(
            "five",
            None,
            None,
            &[
                (
                    "https://five.com:8080/",
                    Some(bwx::api::UriMatchType::Host),
                ),
            ],
        ),
        make_entry(
            "six",
            None,
            None,
            &[("six.com:8080", Some(bwx::api::UriMatchType::Host))],
        ),
        make_entry(
            "seven",
            None,
            None,
            &[("192.168.0.128:8080", Some(bwx::api::UriMatchType::Host))],
        ),
    ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://login.one.com/", None, None, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com:443/", None, None, 0, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        one_match(entries, "https://two.com/", None, None, 1, false),
        "two"
    );
    assert!(
        one_match(
            entries,
            "https://two.com/other-page",
            None,
            None,
            1,
            false
        ),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );

    assert!(
        one_match(entries, "https://four.com/", None, None, 3, false),
        "four"
    );

    assert!(
        one_match(entries, "https://five.com:8080/", None, None, 4, false),
        "five"
    );
    assert!(
        no_matches(entries, "https://five.com/", None, None, false),
        "five"
    );

    assert!(
        one_match(entries, "https://six.com:8080/", None, None, 5, false),
        "six"
    );
    assert!(
        no_matches(entries, "https://six.com/", None, None, false),
        "six"
    );
    assert!(
        one_match(
            entries,
            "https://192.168.0.128:8080/",
            None,
            None,
            6,
            false
        ),
        "seven"
    );
    assert!(
        no_matches(entries, "https://192.168.0.128/", None, None, false),
        "seven"
    );
}

#[test]
fn test_find_by_url_starts_with() {
    let entries =
        &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    "https://one.com/",
                    Some(bwx::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(bwx::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(bwx::api::UriMatchType::StartsWith),
                )],
            ),
        ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://login.one.com/", None, None, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com:443/", None, None, 0, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        one_match(entries, "https://two.com/login", None, None, 1, false),
        "two"
    );
    assert!(
        one_match(entries, "https://two.com/login/sso", None, None, 1, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );
}

#[test]
fn test_find_by_url_exact() {
    let entries =
        &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(bwx::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(bwx::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(bwx::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(bwx::api::UriMatchType::Exact))],
            ),
        ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com", None, None, 0, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://one.com/foo", None, None, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://login.one.com/", None, None, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com:443/", None, None, 0, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        one_match(entries, "https://two.com/login", None, None, 1, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/login/sso", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );
    assert!(
        one_match(entries, "https://four.com/", None, None, 3, false),
        "four"
    );
    assert!(
        one_match(entries, "https://four.com", None, None, 3, false),
        "four"
    );
    assert!(
        no_matches(entries, "https://four.com/foo", None, None, false),
        "four"
    );
}

#[test]
fn test_find_by_url_regex() {
    let entries = &[
        make_entry(
            "one",
            None,
            None,
            &[(
                r"^https://one\.com/$",
                Some(bwx::api::UriMatchType::RegularExpression),
            )],
        ),
        make_entry(
            "two",
            None,
            None,
            &[(
                r"^https://two\.com/(login|start)",
                Some(bwx::api::UriMatchType::RegularExpression),
            )],
        ),
        make_entry(
            "three",
            None,
            None,
            &[(
                r"^https://(login\.)?three\.com/$",
                Some(bwx::api::UriMatchType::RegularExpression),
            )],
        ),
    ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://login.one.com/", None, None, false),
        "one"
    );
    assert!(
        one_match(entries, "https://one.com:443/", None, None, 0, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        one_match(entries, "https://two.com/login", None, None, 1, false),
        "two"
    );
    assert!(
        one_match(entries, "https://two.com/start", None, None, 1, false),
        "two"
    );
    assert!(
        one_match(entries, "https://two.com/login/sso", None, None, 1, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        one_match(entries, "https://three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://www.three.com/", None, None, false),
        "three"
    );
}

#[test]
fn test_find_by_url_never() {
    let entries =
        &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(bwx::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(bwx::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(bwx::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(bwx::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(bwx::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(bwx::api::UriMatchType::Never))],
            ),
        ];

    assert!(
        no_matches(entries, "https://one.com/", None, None, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://login.one.com/", None, None, false),
        "one"
    );
    assert!(
        no_matches(entries, "https://one.com:443/", None, None, false),
        "one"
    );
    assert!(no_matches(entries, "one.com", None, None, false), "one");
    assert!(no_matches(entries, "https", None, None, false), "one");
    assert!(no_matches(entries, "com", None, None, false), "one");
    assert!(
        no_matches(entries, "https://com/", None, None, false),
        "one"
    );

    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        no_matches(entries, "https://login.three.com/", None, None, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );

    assert!(
        no_matches(entries, "https://four.com/", None, None, false),
        "four"
    );

    assert!(
        no_matches(entries, "https://five.com:8080/", None, None, false),
        "five"
    );
    assert!(
        no_matches(entries, "https://five.com/", None, None, false),
        "five"
    );

    assert!(
        no_matches(entries, "https://six.com:8080/", None, None, false),
        "six"
    );
    assert!(
        no_matches(entries, "https://six.com/", None, None, false),
        "six"
    );
}

#[test]
fn test_find_with_multiple_urls() {
    let entries = &[
        make_entry(
            "one",
            None,
            None,
            &[
                ("https://one.com/", Some(bwx::api::UriMatchType::Domain)),
                ("https://two.com/", Some(bwx::api::UriMatchType::Domain)),
            ],
        ),
        make_entry(
            "two",
            None,
            None,
            &[(
                "https://two.com/login",
                Some(bwx::api::UriMatchType::Domain),
            )],
        ),
    ];

    assert!(
        no_matches(entries, "https://zero.com/", None, None, false),
        "zero"
    );
    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        many_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
}

#[test]
fn test_decode_totp_secret() {
    let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
    let want = b"hello world!".to_vec();
    assert!(decoded == want, "strips spaces");
}

/// Splits the joined fixture used by these tests into the parallel
/// slices `find_entry_raw` actually takes.
fn split_fixture(
    entries: &[(bwx::db::Entry, DecryptedSearchCipher)],
) -> (Vec<bwx::db::Entry>, Vec<DecryptedSearchCipher>) {
    entries.iter().cloned().unzip()
}

#[track_caller]
fn one_match(
    entries: &[(bwx::db::Entry, DecryptedSearchCipher)],
    needle: &str,
    username: Option<&str>,
    folder: Option<&str>,
    idx: usize,
    ignore_case: bool,
) -> bool {
    let (es, ds) = split_fixture(entries);
    entries_eq(
        &find_entry_raw(
            &es,
            &ds,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        )
        .unwrap(),
        &entries[idx],
    )
}

#[track_caller]
fn no_matches(
    entries: &[(bwx::db::Entry, DecryptedSearchCipher)],
    needle: &str,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bool {
    let (es, ds) = split_fixture(entries);
    let res = find_entry_raw(
        &es,
        &ds,
        &parse_needle(needle).unwrap(),
        username,
        folder,
        ignore_case,
    );
    if let Err(e) = res {
        format!("{e}").contains("no entry found")
    } else {
        false
    }
}

#[track_caller]
fn many_matches(
    entries: &[(bwx::db::Entry, DecryptedSearchCipher)],
    needle: &str,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bool {
    let (es, ds) = split_fixture(entries);
    let res = find_entry_raw(
        &es,
        &ds,
        &parse_needle(needle).unwrap(),
        username,
        folder,
        ignore_case,
    );
    if let Err(e) = res {
        format!("{e}").contains("multiple entries found")
    } else {
        false
    }
}

#[track_caller]
fn entries_eq(
    a: &(bwx::db::Entry, DecryptedSearchCipher),
    b: &(bwx::db::Entry, DecryptedSearchCipher),
) -> bool {
    a.0 == b.0 && a.1 == b.1
}

fn make_entry(
    name: &str,
    username: Option<&str>,
    folder: Option<&str>,
    uris: &[(&str, Option<bwx::api::UriMatchType>)],
) -> (bwx::db::Entry, DecryptedSearchCipher) {
    let id = bwx::uuid::new_v4();
    (
        bwx::db::Entry {
            id: id.to_string(),
            org_id: None,
            folder: folder.map(|_| "encrypted folder name".to_string()),
            folder_id: None,
            name: "this is the encrypted name".to_string(),
            data: bwx::db::EntryData::Login {
                username: username
                    .map(|_| "this is the encrypted username".to_string()),
                password: None,
                uris: uris
                    .iter()
                    .map(|(_, match_type)| bwx::db::Uri {
                        uri: "this is the encrypted uri".to_string(),
                        match_type: *match_type,
                    })
                    .collect(),
                totp: None,
            },
            fields: vec![],
            notes: None,
            history: vec![],
            key: None,
            master_password_reprompt: bwx::api::CipherRepromptType::None,
        },
        DecryptedSearchCipher {
            id: id.to_string(),
            entry_type: "Login".to_string(),
            folder: folder.map(std::string::ToString::to_string),
            name: name.to_string(),
            user: username.map(std::string::ToString::to_string),
            uris: uris
                .iter()
                .map(|(uri, match_type)| ((*uri).to_string(), *match_type))
                .collect(),
            fields: vec![],
            notes: None,
        },
    )
}
