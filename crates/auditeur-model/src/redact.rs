//! Secret redaction.
//!
//! Repository text is untrusted and often sensitive. Everything that leaves its
//! origin — evidence excerpts, finding titles, log lines, model prompts — passes
//! through this module first, so there is exactly one place to audit and one
//! place to strengthen.
//!
//! This is a mitigation, not a guarantee. It recognises common credential
//! shapes; a novel format will pass through. See SECURITY.md for the residual
//! risk and the roadmap item for a tunable, entropy-based detector.

use std::sync::OnceLock;

use regex::Regex;

/// Replacement for a redacted value, without a kind label.
pub const REDACTED: &str = "[REDACTED]";

fn secret_assignment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|passphrase|credential|private[_-]?key|access[_-]?key[_-]?id|client[_-]?secret|auth[_-]?token|aws_secret_access_key|secret[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9/+_\-\.=]{6,})"#,
        )
        .expect("secret-assignment pattern is valid")
    })
}

fn bearer_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/=]{8,})").expect("bearer pattern is valid")
    })
}

fn private_key_block() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
            .expect("private-key pattern is valid")
    })
}

fn aws_access_key_id() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("aws key pattern is valid")
    })
}

/// Credentials embedded in a connection string: `scheme://user:password@host`.
///
/// A password in a URL has no label in front of it — the keyword that the
/// assignment pattern looks for is absent — so without this pattern a database
/// or broker URL in a log line, an error message or a finding would keep its
/// password.
fn connection_string_credentials() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b([a-z][a-z0-9+.\-]{1,31})://([^:@/\s]{0,64}):([^@/\s]{1,128})@")
            .expect("connection-string pattern is valid")
    })
}

/// Whether `text` contains a private-key header whose footer has not arrived.
///
/// A caller that redacts incrementally — one line at a time, as a log writer
/// does — cannot expect a multi-line block to be recognised inside a single
/// line: the header alone, the body and the footer are three separate pieces of
/// text. Such a caller keeps buffering while this returns true, so the block is
/// redacted as one unit instead of leaking its body line by line.
///
/// The knowledge of what a private key looks like stays in this module; the
/// caller only asks the question.
pub fn has_unterminated_private_key_block(text: &str) -> bool {
    const HEADER: &str = "-----BEGIN ";
    const FOOTER: &str = "-----END ";
    const MARKER: &str = "PRIVATE KEY-----";

    let Some(header_at) = text.rfind(HEADER) else {
        return false;
    };
    let after_header = &text[header_at..];
    if !after_header.contains(MARKER) {
        // Some other kind of PEM block; nothing to hold back.
        return false;
    }
    match after_header.rfind(FOOTER) {
        // A private-key footer after the last header closes the block.
        Some(footer_at) => !after_header[footer_at..].contains(MARKER),
        None => true,
    }
}

/// Whether a captured value is a scheme word or a placeholder rather than a
/// secret.
///
/// `Bearer`, `Basic` and friends introduce the credential that follows them;
/// `null`, `none` and a boolean are configuration values that happen to sit after
/// a key name. Neither is a secret, and replacing one would hide the real value.
fn is_placeholder_value(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "bearer"
            | "basic"
            | "digest"
            | "negotiate"
            | "token"
            | "key"
            | "null"
            | "none"
            | "true"
            | "false"
            | "string"
            | "changeme"
    )
}

/// Remove a private-key block whose footer never arrives.
///
/// Truncation is ordinary: a log line is cut at a buffer boundary, a prompt is
/// clipped to a token budget, an evidence excerpt stops after a few lines. The
/// block pattern needs a footer to match, so without this the body of a
/// truncated key would survive.
fn redact_unterminated_private_key(text: &str) -> String {
    const HEADER: &str = "-----BEGIN ";
    const MARKER: &str = "PRIVATE KEY-----";

    match text.rfind(HEADER) {
        Some(header_at) if text[header_at..].contains(MARKER) => {
            format!("{}[REDACTED:private-key]", &text[..header_at])
        }
        _ => text.to_string(),
    }
}

fn high_entropy_token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Long base64/hex-ish runs: overwhelmingly machine-generated material
        // rather than prose or identifiers.
        Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").expect("entropy pattern is valid")
    })
}

/// Redact credential-shaped substrings from `input`.
///
/// Order matters: structured blocks are removed before line-oriented patterns,
/// and the entropy sweep runs last so that labelled secrets keep their label.
pub fn redact_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    // Order matters: structured blocks first, then URL credentials, then
    // labelled values, then token shapes, and the entropy sweep last so that a
    // labelled secret keeps its label.
    let without_keys = private_key_block().replace_all(input, "[REDACTED:private-key]");
    // A block with no footer cannot be matched by the pattern above, so what
    // remains of it is removed explicitly rather than left in place.
    let without_keys = if has_unterminated_private_key_block(&without_keys) {
        redact_unterminated_private_key(&without_keys)
    } else {
        without_keys.to_string()
    };
    let without_url_credentials = connection_string_credentials()
        .replace_all(&without_keys, |caps: &regex::Captures<'_>| {
            format!("{}://{}:[REDACTED:secret]@", &caps[1], &caps[2])
        })
        .to_string();
    // Bearer tokens before labelled values. In `token: Bearer abc…` the label
    // rule would otherwise treat the scheme word as the value — it is the first
    // word after the separator — and leave the token itself in place.
    let without_bearers = bearer_token()
        .replace_all(&without_url_credentials, "Bearer [REDACTED:token]")
        .to_string();
    let with_named_secrets = secret_assignment()
        .replace_all(&without_bearers, |caps: &regex::Captures<'_>| {
            let value = &caps[2];
            // A value that is itself a scheme word, a placeholder or a boolean is
            // not the secret. Redacting it would consume the label and hide the
            // fact that a real value follows.
            if is_placeholder_value(value) {
                return caps[0].to_string();
            }
            format!("{}: [REDACTED:secret]", &caps[1])
        })
        .to_string();
    let without_aws = aws_access_key_id()
        .replace_all(&with_named_secrets, "[REDACTED:aws-key-id]")
        .to_string();
    high_entropy_token()
        .replace_all(&without_aws, "[REDACTED:high-entropy]")
        .to_string()
}

/// Truncate `text` to at most `max_chars` characters, appending an ellipsis.
///
/// Operates on characters, not bytes, so multi-byte content cannot be split and
/// reported as invalid UTF-8.
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated: String = text.chars().take(max_chars).collect();
    truncated.push('\u{2026}');
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labelled_secrets_are_redacted() {
        for line in [
            "api_key = \"sk-live-abcdef123456\"",
            "API-KEY: 8f3a9c2d1b4e5f60718293a4b5c6d7e8",
            "PASSWORD=correct-horse-battery",
            "client_secret: \"abc123def456ghi789\"",
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ] {
            let redacted = redact_text(line);
            assert!(redacted.contains("[REDACTED:"), "not redacted: {redacted}");
        }
    }

    #[test]
    fn labelled_secret_values_do_not_survive() {
        let redacted = redact_text("password = \"hunter2hunter2\"");
        assert!(!redacted.contains("hunter2hunter2"), "got: {redacted}");
        assert!(
            redacted.contains("password"),
            "label should remain: {redacted}"
        );
    }

    #[test]
    fn bearer_tokens_and_aws_keys_are_redacted() {
        let redacted = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345");
        assert!(
            !redacted.contains("abcdefghijklmnopqrstuvwxyz012345"),
            "{redacted}"
        );

        let redacted = redact_text("key AKIAIOSFODNN7EXAMPLE in config");
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"), "{redacted}");
    }

    #[test]
    fn private_key_blocks_are_redacted_whole() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nmore base64\n-----END RSA PRIVATE KEY-----";
        let redacted = redact_text(input);
        assert!(!redacted.contains("MIIEowIBAAKCAQEA"), "{redacted}");
        assert!(redacted.contains("[REDACTED:private-key]"));
    }

    #[test]
    fn ordinary_code_is_not_mangled() {
        let input =
            "fn main() {\n    let total = count_files(root);\n    println!(\"{total}\");\n}";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(redact_text(""), "");
    }

    #[test]
    fn truncation_is_character_safe() {
        let text = "ä".repeat(20);
        let truncated = truncate_chars(&text, 5);
        assert_eq!(truncated.chars().count(), 6);
        assert_eq!(truncate_chars("abc", 5), "abc");
    }
}

/// Tests for the credential shapes that were missing or mishandled.
///
/// Values are assembled at run time rather than written as literals: a scanner
/// in the toolchain may rewrite a secret-shaped string on its way to disk, which
/// silently turns a test into a tautology. Building the value from fragments
/// keeps the fixture and the assertion honest.
#[cfg(test)]
mod credential_coverage {
    use super::*;

    fn assembled(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn a_connection_string_password_is_redacted() {
        let password = assembled(&["correct-horse", "-battery-staple"]);
        let line = format!("connecting to postgres://appuser:{password}@db.internal:5432/app");

        let redacted = redact_text(&line);
        assert!(!redacted.contains(&password), "{redacted}");
        // The rest of the line survives: the reader still learns which host was
        // being reached.
        assert!(redacted.contains("db.internal"), "{redacted}");
        assert!(redacted.contains("appuser"), "{redacted}");
        assert!(redacted.contains("[REDACTED:secret]"), "{redacted}");
    }

    #[test]
    fn a_url_without_credentials_is_left_alone() {
        for line in [
            "see https://example.com/docs/archive for details",
            "cloning from git://github.com/example/project.git",
            "endpoint http://127.0.0.1:1234/v1 answers",
        ] {
            assert_eq!(redact_text(line), line, "over-redacted: {line}");
        }
    }

    #[test]
    fn a_private_key_block_is_redacted_as_one_unit() {
        let body = "MIIEowIBAAKCAQEA".repeat(3);
        let block =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n");

        let redacted = redact_text(&block);
        assert!(!redacted.contains(&body), "{redacted}");
        assert!(!redacted.contains("RSA PRIVATE KEY"), "{redacted}");
        assert!(redacted.contains("[REDACTED:private-key]"), "{redacted}");
    }

    #[test]
    fn a_truncated_private_key_block_is_removed_to_the_end() {
        let body = "MIIEowIBAAKCAQEA".repeat(3);
        let truncated = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}");

        let redacted = redact_text(&truncated);
        assert!(!redacted.contains(&body), "{redacted}");
        assert!(redacted.contains("[REDACTED:private-key]"), "{redacted}");
    }

    #[test]
    fn an_unterminated_block_is_reported_as_unterminated() {
        let header = "-----BEGIN RSA PRIVATE KEY-----";
        assert!(has_unterminated_private_key_block(header));
        assert!(has_unterminated_private_key_block(&format!(
            "{header}\nMIIEowIBAAKCAQEA"
        )));
        assert!(!has_unterminated_private_key_block(&format!(
            "{header}\nbody\n-----END RSA PRIVATE KEY-----\n"
        )));
        assert!(!has_unterminated_private_key_block("no block here"));
        // A different kind of PEM block is not what this question is about.
        assert!(!has_unterminated_private_key_block(
            "-----BEGIN CERTIFICATE-----\nMIIB"
        ));
    }

    #[test]
    fn token_shapes_are_redacted_for_real() {
        let aws_key = assembled(&["AKIA", "IOSFODNN7EXAMPLE"]);
        let bearer = assembled(&["abcdefghijklmn", "opqrstuvwxyz012345"]);

        let redacted = redact_text(&format!("key {aws_key} and header Bearer {bearer}"));
        assert!(!redacted.contains(&aws_key), "{redacted}");
        assert!(!redacted.contains(&bearer), "{redacted}");
        assert!(redacted.contains("[REDACTED:aws-key-id]"), "{redacted}");
        assert!(redacted.contains("[REDACTED:token]"), "{redacted}");
    }

    #[test]
    fn a_labelled_secret_keeps_its_label_after_the_new_pass() {
        let value = assembled(&["hunter2", "hunter2"]);
        let redacted = redact_text(&format!("password = \"{value}\""));
        assert!(!redacted.contains(&value), "{redacted}");
        assert!(redacted.contains("password"), "{redacted}");
    }

    #[test]
    fn ordinary_prose_survives_untouched() {
        for line in [
            "the repository has 42 source files",
            "src/server.rs:42-57 looks suspicious",
            "no licence was declared in Cargo.toml",
            "audit finished in 80942 ms",
        ] {
            assert_eq!(redact_text(line), line, "over-redacted: {line}");
        }
    }
}

/// Regression tests for interactions between the credential rules.
#[cfg(test)]
mod rule_interaction {
    use super::*;

    fn assembled(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn a_labelled_bearer_token_loses_the_token_not_the_scheme_word() {
        for label in ["token", "api_key", "secret", "access_token"] {
            let value = assembled(&["abcdefghijklmn", "opqrstuvwxyz012345"]);
            let line = format!("{label}: Bearer {value}");
            let redacted = redact_text(&line);
            assert!(
                !redacted.contains(&value),
                "the token survived behind its label: {redacted}"
            );
            assert!(redacted.contains("[REDACTED"), "{redacted}");
        }
    }

    #[test]
    fn a_placeholder_after_a_key_name_is_left_alone() {
        // Nothing here is a secret, and redacting it would hide the fact that the
        // next line holds a real one.
        for line in [
            "auth_method = bearer",
            "token_type: Basic",
            "client_secret = null",
            "password = none",
        ] {
            assert_eq!(redact_text(line), line, "over-redacted: {line}");
        }
    }

    #[test]
    fn the_authorization_header_shape_is_redacted_whichever_rule_sees_it_first() {
        let value = assembled(&["abcdefghijklmn", "opqrstuvwxyz012345"]);
        for line in [
            format!("Authorization: Bearer {value}"),
            format!("authorization: bearer {value}"),
            format!("curl -H \"Authorization: Bearer {value}\" https://api.example.com"),
        ] {
            let redacted = redact_text(&line);
            assert!(!redacted.contains(&value), "{redacted}");
        }
    }
}
