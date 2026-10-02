//! Content hashing helpers.
//!
//! Used for evidence digests, configuration fingerprints and model checksums.
//! A single implementation keeps digests comparable across crates.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        // Writing to a String cannot fail; the result is ignored deliberately.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Short, stable identifier derived from `parts`.
///
/// The parts are joined with a unit separator so that `["a", "bc"]` and
/// `["ab", "c"]` cannot collide. The returned identifier is 16 hex characters
/// (64 bits) — long enough that collisions are irrelevant for a single run,
/// short enough to read in a report.
pub fn short_id(parts: &[&str]) -> String {
    let joined = parts.join("\u{1f}");
    let full = sha256_hex(joined.as_bytes());
    full.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn short_id_is_stable_and_separator_safe() {
        assert_eq!(short_id(&["a", "b"]), short_id(&["a", "b"]));
        assert_ne!(short_id(&["a", "bc"]), short_id(&["ab", "c"]));
        assert_eq!(short_id(&["x"]).len(), 16);
    }
}
