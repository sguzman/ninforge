//! Conservative, non-recursive discovery of *plaintext*, already accessible
//! Switch metadata sidecars in an explicitly selected directory.
//!
//! Discovery only chooses unique files; it never establishes that they belong
//! to the supplied package or authenticates their contents. No decryption.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

const MAX_DIRECTORY_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBundle {
    /// The sole standalone plaintext .cnmt found in this directory.
    pub cnmt: PathBuf,
    /// Sole .nacp file if present; still unauthenticated external evidence.
    pub nacp: Option<PathBuf>,
    /// Only a file named exactly main.nso (ASCII case insensitive) qualifies.
    /// Other NSOs are deliberately not guessed to be the main executable.
    pub main_nso: Option<PathBuf>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

fn unique(mut candidates: Vec<PathBuf>, multiple: &'static str) -> io::Result<Option<PathBuf>> {
    if candidates.len() > 1 {
        return Err(invalid(multiple));
    }
    Ok(candidates.pop())
}

/// Discover metadata in exactly one directory. Never descend into children,
/// follow symbolic links or choose between multiple CNMT/NACP files.
pub fn discover_metadata_dir(root: &Path) -> io::Result<MetadataBundle> {
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(invalid(
            "metadata root must be an ordinary directory, not a symlink",
        ));
    }
    let mut cnmt = Vec::new();
    let mut nacp = Vec::new();
    let mut main_nso = Vec::new();
    for (index, item) in fs::read_dir(root)?.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            return Err(invalid("metadata directory exceeds entry safety limit"));
        }
        let item = item?;
        let path = item.path();
        let name = item.file_name();
        let name = name.to_str();
        let suffix = path.extension().and_then(|extension| extension.to_str());
        let is_cnmt = suffix.is_some_and(|s| s.eq_ignore_ascii_case("cnmt"));
        let is_nacp = suffix.is_some_and(|s| s.eq_ignore_ascii_case("nacp"));
        let is_main_nso = name.is_some_and(|s| s.eq_ignore_ascii_case("main.nso"));
        if !(is_cnmt || is_nacp || is_main_nso) {
            continue;
        }
        // Reject candidate symlinks rather than silently following or ignoring
        // a different metadata file chosen by filename.
        if !item.file_type()?.is_file() {
            return Err(invalid(
                "metadata candidate is not a regular, non-symlink file",
            ));
        }
        if is_cnmt {
            cnmt.push(path);
        } else if is_nacp {
            nacp.push(path);
        } else {
            main_nso.push(path);
        }
    }
    let cnmt = unique(
        cnmt,
        "multiple CNMT files: choose one explicitly with package audit",
    )?
    .ok_or_else(|| invalid("no standalone plaintext .cnmt found in metadata directory"))?;
    Ok(MetadataBundle {
        cnmt,
        nacp: unique(
            nacp,
            "multiple NACP files: choose one explicitly with package audit",
        )?,
        main_nso: unique(main_nso, "ambiguous case-variant main.nso files")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let number = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "ninforge-metadata-{nonce}-{}-{number}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn add(&self, name: &str) {
            fs::write(self.0.join(name), b"synthetic metadata").unwrap();
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn discovers_unique_candidates_not_arbitrary_nso_modules() {
        let temp = Temp::new();
        temp.add("update.cnmt");
        temp.add("control.nacp");
        temp.add("main.nso");
        temp.add("sdk.nso");
        temp.add("contents.nca");
        let result = discover_metadata_dir(&temp.0).unwrap();
        assert_eq!(result.cnmt, temp.0.join("update.cnmt"));
        assert_eq!(result.nacp, Some(temp.0.join("control.nacp")));
        assert_eq!(result.main_nso, Some(temp.0.join("main.nso")));
    }

    #[test]
    fn missing_optional_candidates_do_not_invent_metadata() {
        let temp = Temp::new();
        temp.add("single.CNMT");
        let result = discover_metadata_dir(&temp.0).unwrap();
        assert!(result.nacp.is_none());
        assert!(result.main_nso.is_none());
        assert_eq!(result.cnmt, temp.0.join("single.CNMT"));
    }

    #[test]
    fn multiple_cnmt_and_nacp_candidates_are_explicit_errors() {
        let temp = Temp::new();
        temp.add("a.cnmt");
        temp.add("b.CNMT");
        assert!(discover_metadata_dir(&temp.0)
            .unwrap_err()
            .to_string()
            .contains("multiple CNMT"));
        fs::remove_file(temp.0.join("b.CNMT")).unwrap();
        temp.add("control.nacp");
        temp.add("second.nacp");
        assert!(discover_metadata_dir(&temp.0)
            .unwrap_err()
            .to_string()
            .contains("multiple NACP"));
    }

    #[test]
    fn no_cnmt_and_non_directory_are_rejected() {
        let temp = Temp::new();
        temp.add("control.nacp");
        assert!(discover_metadata_dir(&temp.0).is_err());
        assert!(discover_metadata_dir(&temp.0.join("control.nacp")).is_err());
    }

    #[test]
    fn does_not_descend_into_subdirectories() {
        let temp = Temp::new();
        fs::create_dir(temp.0.join("other")).unwrap();
        fs::write(temp.0.join("other/meta.cnmt"), b"synthetic").unwrap();
        assert!(discover_metadata_dir(&temp.0).is_err());
        temp.add("root.cnmt");
        assert_eq!(
            discover_metadata_dir(&temp.0).unwrap().cnmt,
            temp.0.join("root.cnmt")
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_candidates_and_symlink_directory() {
        use std::os::unix::fs::symlink;
        let temp = Temp::new();
        temp.add("real.cnmt");
        symlink(temp.0.join("real.cnmt"), temp.0.join("link.cnmt")).unwrap();
        assert!(discover_metadata_dir(&temp.0).is_err());
        fs::remove_file(temp.0.join("link.cnmt")).unwrap();
        symlink(&temp.0, temp.0.with_extension("link")).unwrap();
        assert!(discover_metadata_dir(&temp.0.with_extension("link")).is_err());
        fs::remove_file(temp.0.with_extension("link")).unwrap();
    }
}
