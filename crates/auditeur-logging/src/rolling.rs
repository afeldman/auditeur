//! The rotating file itself.
//!
//! Rotation is size-based and delegated to `file-rotate` rather than written by
//! hand: an append-only log with a byte budget and a file count has enough
//! edge cases (partial writes, the boundary between two files, deleting the
//! oldest file) that a hand-rolled version is a liability.
//!
//! Naming, and what `max_files` means here:
//!
//! ```text
//! auditeur.log      the active file
//! auditeur.log.1    the previous file
//! auditeur.log.2    …
//! ```
//!
//! `max_files` counts the *rotated* files kept, so `max_files = 5` gives
//! `auditeur.log` plus `.1` to `.5` — six files, five of them history.

use std::io;
use std::path::{Path, PathBuf};

use file_rotate::suffix::AppendCount;
use file_rotate::{compression::Compression, ContentLimit, FileRotate};

/// Build the rotating writer for a log file.
///
/// The parent directory is created here, before `file-rotate` sees the path,
/// because that crate creates it with an `expect` and a missing, unwritable log
/// directory is an ordinary misconfiguration that deserves an error rather than
/// a panic.
///
/// `max_size_bytes` is a byte count, not a configured string: handing a raw
/// configuration value to a rotation library is how a size ends up parsed as a
/// duration and a log grows unbounded.
pub fn rotating_writer(
    path: &Path,
    max_size_bytes: u64,
    max_files: u32,
) -> io::Result<FileRotate<AppendCount>> {
    if max_size_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the rotation size must be greater than zero",
        ));
    }
    if max_files == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one rotated file must be kept",
        ));
    }

    if let Some(directory) = path.parent() {
        std::fs::create_dir_all(directory)?;
    }

    Ok(FileRotate::new(
        path,
        AppendCount::new(max_files as usize),
        ContentLimit::BytesSurpassed(max_size_bytes as usize),
        Compression::None,
        None,
    ))
}

/// The files a rotation of `path` with `max_files` may occupy, newest first.
///
/// Used by diagnostics to describe the log without guessing at names.
pub fn rotated_paths(path: &Path, max_files: u32) -> Vec<PathBuf> {
    let mut paths = vec![path.to_path_buf()];
    for index in 1..=max_files {
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        paths.push(PathBuf::from(name));
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn the_directory_is_created_before_the_writer_is_built() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/logs/auditeur.log");
        let writer = rotating_writer(&path, 4096, 2).unwrap();
        drop(writer);
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn a_zero_size_or_zero_file_count_is_refused_rather_than_panicking() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("logs/auditeur.log");
        assert!(rotating_writer(&path, 0, 2).is_err());
        assert!(rotating_writer(&path, 1024, 0).is_err());
        // The refusals happened before anything was created.
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn writing_past_the_limit_rotates_and_the_oldest_file_is_dropped() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("logs/auditeur.log");
        let mut writer = rotating_writer(&path, 1024, 2).unwrap();

        for index in 0..200 {
            writeln!(writer, "{index:04} {}", "x".repeat(64)).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        let first = std::fs::read_to_string(&path).unwrap();
        let one = std::fs::read_to_string(rotated_paths(&path, 2)[1].clone()).unwrap();

        // The file rotated at all, and the newest lines are in the active file.
        assert!(path.with_extension("log.1").exists() || one.contains("01"));
        assert!(first.contains("0199"), "{first}");
        assert!(!first.contains("0000"), "old lines must have rotated out");

        // max_files counts rotated files: the active one plus at most max_files.
        let directory = path.parent().unwrap();
        let files = std::fs::read_dir(directory).unwrap().count();
        assert!(
            files <= 3,
            "max_files = 2 must keep at most three files, found {files}"
        );
    }

    #[test]
    fn the_file_count_is_honoured_over_many_rotations() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("logs/auditeur.log");
        let mut writer = rotating_writer(&path, 512, 3).unwrap();

        for index in 0..400 {
            writeln!(writer, "{index:04} {}", "y".repeat(48)).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        let files = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert!(files <= 4, "max_files = 3 must keep at most four files");
        assert!(files > 1, "the log should have rotated");

        // The active file and every rotated file exist by name.
        for candidate in rotated_paths(&path, 3) {
            assert!(
                candidate.exists() || candidate.ends_with("auditeur.log.3"),
                "unexpected layout: {}",
                candidate.display()
            );
        }
    }

    #[test]
    fn the_documented_names_are_what_rotation_produces() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("logs/auditeur.log");
        let mut writer = rotating_writer(&path, 256, 2).unwrap();
        for index in 0..100 {
            writeln!(writer, "{index:04} {}", "z".repeat(40)).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        let names: Vec<String> = {
            let mut names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .collect();
            names.sort();
            names
        };
        assert!(names.contains(&"auditeur.log".to_string()), "{names:?}");
        assert!(
            names.iter().all(|name| name.starts_with("auditeur.log")),
            "{names:?}"
        );
    }
}
