//! Redaction for the log stream.
//!
//! A log line is written by this process, but it routinely contains text that
//! came from somewhere else: a repository path, a file excerpt, an error message
//! from an HTTP client, a configuration value. Any of those can carry a
//! credential, and a log file is the one artefact that is *not* reviewed before
//! it leaves the machine — it is written, rotated, and read months later.
//!
//! The redaction itself is not re-implemented here. [`auditeur_model::redact`]
//! already decides what a credential looks like, and it is the same component
//! that keeps secrets out of prompts, findings and reports. A second, independent
//! detector would be a second chance to disagree with the first.
//!
//! Placement matters: this writer sits *inside* the non-blocking appender, so
//! redaction happens on the writing thread before any byte reaches the file
//! handle. Nothing is written and then scrubbed.

use std::io::{self, Write};

use auditeur_model::redact::{has_unterminated_private_key_block, redact_text};

/// How much text is held while waiting for a line break.
///
/// A writer may be handed one log line in several calls, and a credential
/// straddling two of them would escape a per-call redaction. Lines are therefore
/// re-assembled before redaction. The cap keeps a writer that never emits a
/// newline from growing without bound; when it is reached the buffer is flushed
/// as if the line had ended.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Whether `haystack` contains `needle`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// A writer that redacts credentials line by line before forwarding.
pub struct RedactingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    /// Wrap a writer.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::with_capacity(8 * 1024),
        }
    }

    /// Access the wrapped writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Redact and write everything buffered up to and including `end`.
    fn emit(&mut self, end: usize) -> io::Result<()> {
        if end == 0 {
            return Ok(());
        }
        let chunk: Vec<u8> = self.pending.drain(..end).collect();
        let text = String::from_utf8_lossy(&chunk);
        let redacted = redact_text(&text);
        self.inner.write_all(redacted.as_bytes())
    }

    /// Whether writing everything up to `end` would leave a private-key block
    /// half-written.
    ///
    /// Redaction is line-oriented, and a private key spans three lines: emitting
    /// the header as soon as it arrives would redact the header and leak the
    /// body. While a block is open, the writer keeps buffering so the block
    /// reaches [`redact_text`] as one unit.
    fn block_still_open(&self, end: usize) -> bool {
        let candidate = &self.pending[..end];
        // Cheap pre-filter: only pay for the string conversion when the bytes
        // could contain a PEM header at all.
        if !contains_bytes(candidate, b"-----BEGIN ") {
            return false;
        }
        has_unterminated_private_key_block(&String::from_utf8_lossy(candidate))
    }

    /// Flush whatever is buffered, redacted, as if the line had ended.
    fn emit_pending(&mut self) -> io::Result<()> {
        let end = self.pending.len();
        self.emit(end)
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buffer);

        // Emit every complete line, except while a private-key block is open.
        while let Some(position) = self.pending.iter().position(|byte| *byte == b'\n') {
            let end = position + 1;
            if self.block_still_open(end) {
                break;
            }
            self.emit(end)?;
        }

        // A line that never ends must not grow the buffer without bound.
        if self.pending.len() > MAX_LINE_BYTES {
            self.emit_pending()?;
        }

        // The caller's bytes were accepted in full, buffered or written.
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_pending()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        // Nothing may be lost to a buffer that outlives its last write.
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that records everything it is handed.
    #[derive(Default)]
    struct Recorder {
        written: Vec<u8>,
    }

    impl Write for Recorder {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn text(recorder: &Recorder) -> String {
        String::from_utf8_lossy(&recorder.written).into_owned()
    }

    #[test]
    fn a_credential_in_a_complete_line_never_reaches_the_writer() {
        let mut writer = RedactingWriter::new(Recorder::default());
        writer
            .write_all(b"connecting with AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n")
            .unwrap();
        writer.flush().unwrap();

        let written = text(writer.inner());
        assert!(!written.contains("AKIAIOSFODNN7EXAMPLE"), "{written}");
        assert!(written.contains("connecting with"), "{written}");
    }

    #[test]
    fn a_credential_split_across_writes_is_still_redacted() {
        // Assembled at run time: a secret-shaped literal may be rewritten on its
        // way to disk, which would turn this test into a tautology.
        let secret = ["abcdefghijklmn", "opqrstuvwxyz012345"].concat();
        let mut writer = RedactingWriter::new(Recorder::default());
        writer.write_all(b"token: Bearer ").unwrap();
        writer.write_all(&secret.as_bytes()[..9]).unwrap();
        writer.write_all(&secret.as_bytes()[9..]).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();

        let written = text(writer.inner());
        assert!(
            !written.contains(&secret),
            "a split credential must not survive"
        );
    }

    #[test]
    fn a_private_key_block_written_line_by_line_is_still_redacted_whole() {
        let body = "MIIEowIBAAKCAQEA".repeat(3);
        let mut writer = RedactingWriter::new(Recorder::default());
        // One write per line, which is what a formatting layer does.
        writer
            .write_all(b"-----BEGIN RSA PRIVATE KEY-----\n")
            .unwrap();
        writer.write_all(body.as_bytes()).unwrap();
        writer.write_all(b"\n").unwrap();
        // The body must not have reached the writer yet: the block is open.
        assert!(
            !text(writer.inner()).contains(&body),
            "an open block must be held back, not streamed"
        );
        writer
            .write_all(b"-----END RSA PRIVATE KEY-----\n")
            .unwrap();
        writer.flush().unwrap();

        let written = text(writer.inner());
        assert!(!written.contains(&body), "{written}");
        assert!(!written.contains("RSA PRIVATE KEY"), "{written}");
    }

    #[test]
    fn a_private_key_block_is_redacted_whole() {
        let mut writer = RedactingWriter::new(Recorder::default());
        writer
            .write_all(b"-----BEGIN RSA PRIVATE KEY-----\n")
            .unwrap();
        writer.write_all(b"MIIEowIBAAKCAQEA1234\n").unwrap();
        writer
            .write_all(b"-----END RSA PRIVATE KEY-----\n")
            .unwrap();
        writer.flush().unwrap();

        let written = text(writer.inner());
        assert!(!written.contains("MIIEowIBAAKCAQEA1234"), "{written}");
    }

    #[test]
    fn ordinary_text_passes_through_unchanged() {
        let mut writer = RedactingWriter::new(Recorder::default());
        let line = "2026-10-02T15:30:12Z INFO auditeur::audit: audit started run_id=1790940176\n";
        writer.write_all(line.as_bytes()).unwrap();
        writer.flush().unwrap();
        assert_eq!(text(writer.inner()), line);
    }

    #[test]
    fn content_that_never_ends_a_line_is_still_flushed_once() {
        let mut writer = RedactingWriter::new(Recorder::default());
        writer.write_all(b"without a newline").unwrap();
        // Nothing has been written yet: the line is still open.
        assert!(text(writer.inner()).is_empty());
        writer.flush().unwrap();
        assert_eq!(text(writer.inner()), "without a newline");
    }

    #[test]
    fn nothing_is_lost_when_the_writer_is_dropped() {
        let mut recorder = Recorder::default();
        {
            let mut writer = RedactingWriter::new(&mut recorder);
            writer.write_all(b"last words, unhterminated").unwrap();
        }
        assert_eq!(text(&recorder), "last words, unhterminated");
    }

    #[test]
    fn a_line_longer_than_the_cap_is_flushed_rather_than_buffered_forever() {
        let mut writer = RedactingWriter::new(Recorder::default());
        // Words, not one long token: a single 64 KiB run of the same character
        // is itself credential-shaped to the entropy sweep, which would make this
        // test about redaction rather than about buffering.
        let huge: Vec<u8> = b"filler words, not a token; ".repeat(MAX_LINE_BYTES / 24 + 2);
        writer.write_all(&huge).unwrap();

        assert!(
            !text(writer.inner()).is_empty(),
            "a line that never ends must be flushed rather than buffered forever"
        );
        writer.flush().unwrap();
        assert_eq!(text(writer.inner()).len(), huge.len());
    }

    #[test]
    fn bytes_are_reported_as_accepted() {
        let mut writer = RedactingWriter::new(Recorder::default());
        let line = b"short line\n";
        assert_eq!(writer.write(line).unwrap(), line.len());
    }
}
