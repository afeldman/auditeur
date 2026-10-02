//! File classification: text or binary, and which language a path belongs to.
//!
//! Classification is deliberately conservative and cheap: a known binary
//! extension is decided from the name alone, everything else is decided from
//! the first block of the file. Nothing here interprets file content.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use auditeur_model::Language;

/// How many bytes are inspected when sniffing for binary content.
pub const SNIFF_BYTES: usize = 8192;

/// Whether a file's content is textual or binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// Textual content, eligible for line-level analysis.
    Text,
    /// Binary content: recorded, digested, never analysed line by line.
    Binary,
}

impl FileKind {
    /// Stable identifier used in caches and reports.
    pub fn id(self) -> &'static str {
        match self {
            FileKind::Text => "text",
            FileKind::Binary => "binary",
        }
    }

    /// Whether line-level analysis is meaningful for this kind.
    pub fn is_text(self) -> bool {
        matches!(self, FileKind::Text)
    }
}

/// Extensions whose content is binary by definition.
///
/// Checking the name first avoids opening every image, archive and object file
/// in a repository just to discover that it is not source code.
pub const BINARY_EXTENSIONS: &[&str] = &[
    // images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "ico",
    "webp",
    "tiff",
    "tif",
    "heic",
    "avif",
    "psd",
    // documents
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "ods",
    // archives and packages
    "zip",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "zst",
    "tar",
    "7z",
    "rar",
    "jar",
    "war",
    "whl",
    "crate",
    "deb",
    "rpm",
    "dmg",
    "iso",
    "pkg",
    // compiled artefacts
    "o",
    "obj",
    "a",
    "so",
    "dylib",
    "dll",
    "exe",
    "bin",
    "class",
    "pyc",
    "pyo",
    "rlib",
    "rmeta",
    "wasm",
    "elf",
    "ko",
    "lib",
    "pdb",
    "dSYM",
    // media
    "mp3",
    "mp4",
    "m4a",
    "wav",
    "flac",
    "ogg",
    "opus",
    "avi",
    "mov",
    "mkv",
    "webm",
    "aac",
    // fonts
    "ttf",
    "otf",
    "woff",
    "woff2",
    "eot",
    // databases and misc binary
    "sqlite",
    "sqlite3",
    "db",
    "mdb",
    "dat",
    "pack",
    "idx",
    "npy",
    "npz",
    "pt",
    "pth",
    "onnx",
    "safetensors",
    "gguf",
    "pb",
    "parquet",
    "feather",
    "arrow",
    "h5",
    "hdf5",
    "nc",
    "img",
    "vrt",
    "cub",
    "lbl",
    "jp2",
    "pgm",
];

/// Whether an extension is known to denote binary content.
pub fn is_binary_extension(extension: &str) -> bool {
    let lowered = extension.to_ascii_lowercase();
    BINARY_EXTENSIONS.contains(&lowered.as_str())
}

/// Decide the kind from the bytes already read.
pub fn kind_from_bytes(bytes: &[u8]) -> FileKind {
    if bytes.contains(&0) {
        return FileKind::Binary;
    }
    // A high proportion of non-text control bytes also indicates binary data.
    let control = bytes
        .iter()
        .filter(|byte| {
            let byte = **byte;
            byte < 0x09 || (0x0e..0x20).contains(&byte)
        })
        .count();
    if !bytes.is_empty() && control * 100 / bytes.len() > 10 {
        FileKind::Binary
    } else {
        FileKind::Text
    }
}

/// Classify a file by extension, falling back to sniffing its first block.
pub fn classify_file(path: &Path) -> std::io::Result<FileKind> {
    if let Some(extension) = path.extension().and_then(|value| value.to_str()) {
        if is_binary_extension(extension) {
            return Ok(FileKind::Binary);
        }
    }
    let mut buffer = vec![0u8; SNIFF_BYTES];
    let read = {
        let mut file = File::open(path)?;
        let mut total = 0usize;
        loop {
            let chunk = file.read(&mut buffer[total..])?;
            if chunk == 0 {
                break;
            }
            total += chunk;
            if total == SNIFF_BYTES {
                break;
            }
        }
        total
    };
    Ok(kind_from_bytes(&buffer[..read]))
}

/// Well-known manifest files and the language they indicate.
const MANIFEST_FILES: &[(&str, Language)] = &[
    ("Cargo.toml", Language::Rust),
    ("Cargo.lock", Language::Rust),
    ("go.mod", Language::Go),
    ("go.sum", Language::Go),
    ("package.json", Language::NodeJs),
    ("package-lock.json", Language::NodeJs),
    ("pnpm-lock.yaml", Language::NodeJs),
    ("yarn.lock", Language::NodeJs),
    ("deno.json", Language::Deno),
    ("deno.jsonc", Language::Deno),
    ("deno.lock", Language::Deno),
    ("pyproject.toml", Language::Python),
    ("requirements.txt", Language::Python),
    ("setup.py", Language::Python),
    ("Pipfile", Language::Python),
    ("CMakeLists.txt", Language::Cpp),
    ("meson.build", Language::Cpp),
    ("Project.toml", Language::Julia),
    ("DESCRIPTION", Language::R),
    ("mix.exs", Language::Lisp),
];

/// The language a path belongs to, from its file name or extension.
pub fn language_for_path(path: &Path) -> Option<Language> {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())?;

    if let Some((_, language)) = MANIFEST_FILES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&file_name))
    {
        return Some(*language);
    }

    let extension = path.extension()?.to_str()?;
    let lowered = extension.to_ascii_lowercase();
    // Ambiguous extensions are resolved by exclusion: `.h` belongs to C, and
    // `.hh`/`.hpp` to C++, both already encoded in the extension lists.
    Language::ALL.into_iter().find(|language| {
        language
            .extensions()
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&lowered))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_extensions_are_recognised_case_insensitively() {
        assert!(is_binary_extension("PNG"));
        assert!(is_binary_extension("woff2"));
        assert!(!is_binary_extension("rs"));
        assert!(!is_binary_extension("toml"));
    }

    #[test]
    fn kind_from_bytes_detects_nul_and_control_heavy_content() {
        assert_eq!(kind_from_bytes(b"fn main() {}\n"), FileKind::Text);
        assert_eq!(kind_from_bytes(b"abc\0def"), FileKind::Binary);
        assert_eq!(kind_from_bytes(&[0x01, 0x02, 0x03, 0x04]), FileKind::Binary);
        assert_eq!(kind_from_bytes(b""), FileKind::Text);
        assert_eq!(kind_from_bytes("Grüße, Welt!\n".as_bytes()), FileKind::Text);
    }

    #[test]
    fn classification_uses_the_extension_fast_path() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("logo.png");
        std::fs::write(&image, b"not really a png but named like one").unwrap();
        assert_eq!(classify_file(&image).unwrap(), FileKind::Binary);
    }

    #[test]
    fn classification_sniffs_unknown_extensions() {
        let temp = tempfile::tempdir().unwrap();
        let text = temp.path().join("notes.weird");
        std::fs::write(&text, "plain text\n").unwrap();
        assert_eq!(classify_file(&text).unwrap(), FileKind::Text);

        let blob = temp.path().join("blob.weird");
        std::fs::write(&blob, [0u8, 1, 2, 3]).unwrap();
        assert_eq!(classify_file(&blob).unwrap(), FileKind::Binary);
    }

    #[test]
    fn binary_extension_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for extension in BINARY_EXTENSIONS {
            assert!(seen.insert(*extension), "duplicate extension {extension}");
        }
    }

    #[test]
    fn manifest_files_map_to_their_language() {
        assert_eq!(
            language_for_path(Path::new("/repo/Cargo.toml")),
            Some(Language::Rust)
        );
        assert_eq!(
            language_for_path(Path::new("/repo/go.mod")),
            Some(Language::Go)
        );
        assert_eq!(
            language_for_path(Path::new("/repo/package.json")),
            Some(Language::NodeJs)
        );
        assert_eq!(
            language_for_path(Path::new("/repo/pyproject.toml")),
            Some(Language::Python)
        );
        assert_eq!(
            language_for_path(Path::new("/repo/deno.jsonc")),
            Some(Language::Deno)
        );
        assert_eq!(
            language_for_path(Path::new("/repo/CMakeLists.txt")),
            Some(Language::Cpp)
        );
    }

    #[test]
    fn source_extensions_map_to_their_language() {
        assert_eq!(
            language_for_path(Path::new("src/main.rs")),
            Some(Language::Rust)
        );
        assert_eq!(
            language_for_path(Path::new("pkg/service.go")),
            Some(Language::Go)
        );
        assert_eq!(
            language_for_path(Path::new("app.py")),
            Some(Language::Python)
        );
        assert_eq!(
            language_for_path(Path::new("index.js")),
            Some(Language::NodeJs)
        );
        assert_eq!(
            language_for_path(Path::new("index.tsx")),
            Some(Language::Deno)
        );
        assert_eq!(
            language_for_path(Path::new("main.tf")),
            Some(Language::Terraform)
        );
        assert_eq!(
            language_for_path(Path::new("analysis.R")),
            Some(Language::R)
        );
        assert_eq!(language_for_path(Path::new("README")), None);
        assert_eq!(language_for_path(Path::new("Makefile")), None);
    }

    #[test]
    fn c_and_cpp_headers_do_not_collide() {
        assert_eq!(language_for_path(Path::new("a.h")), Some(Language::C));
        assert_eq!(language_for_path(Path::new("a.hh")), Some(Language::Cpp));
        assert_eq!(language_for_path(Path::new("a.cpp")), Some(Language::Cpp));
    }
}
