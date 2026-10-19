//! Candidate save-file inventory and no-overwrite backups.
//!
//! These are *extension hints*, not authenticated Nintendo save formats. Save
//! serialization is game- and emulator-specific. This module never edits saves.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_VISITED: usize = 100_000;
const MAX_DEPTH: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub size: u64,
    /// Extension-based identification only; not proof this is a valid save.
    pub hint: &'static str,
}

pub fn format_hint(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "sav" => Some("generic raw save candidate"),
        "srm" => Some("emulator SRAM candidate"),
        "dsv" => Some("DeSmuME DS save candidate"),
        "duc" => Some("Action Replay DS save candidate"),
        "gci" | "gcs" => Some("GameCube save candidate"),
        "eep" | "sra" | "fla" | "mpk" => Some("Nintendo 64 save candidate"),
        _ => None,
    }
}

/// Enumerate regular files with recognized save-like extensions. Refuse
/// symlinks and cap traversal. Do not infer console from a generic .sav/.srm.
pub fn inventory(root: &Path) -> io::Result<Vec<Candidate>> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "save root must be a real directory"));
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    let mut found = Vec::new();
    while let Some((path, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(io::Error::new(ErrorKind::InvalidData, "save directory nesting exceeds limit"));
        }
        let mut children = fs::read_dir(&path)?
            .map(|item| item.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        children.sort();
        for child in children.into_iter().rev() {
            visited += 1;
            if visited > MAX_VISITED {
                return Err(io::Error::new(ErrorKind::InvalidData, "save directory inventory exceeds file limit"));
            }
            let metadata = fs::symlink_metadata(&child)?;
            let kind = metadata.file_type();
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                stack.push((child, depth + 1));
            } else if kind.is_file() {
                if let Some(hint) = format_hint(&child) {
                    found.push(Candidate { path: child, size: metadata.len(), hint });
                }
            }
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(found)
}

/// Copy a user-selected regular file to a user-selected destination.
///
/// Files are streamed to a unique temporary file in the destination directory,
/// flushed to disk, then published with a hard link (fails if destination
/// exists, including an existing symlink). The temporary name is removed on
/// success and normal errors. A crash can leave an orphan temporary copy;
/// this is preferable to publishing a truncated backup.
///
/// Filesystems without hard-link support return an error without overwriting.
pub fn backup(source: &Path, destination: &Path) -> io::Result<u64> {
    let source_metadata = fs::symlink_metadata(source)?;
    if !source_metadata.file_type().is_file() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "source must be a regular, non-symlink file"));
    }
    let mut input = OpenOptions::new().read(true).open(source)?;
    if !input.metadata()?.file_type().is_file() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "source changed type during open"));
    }
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?.as_nanos();
    let mut staged = None;
    for attempt in 0..32 {
        let temporary = parent.join(format!(".ninforge-copy-{}-{nanos}-{attempt}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&temporary) {
            Ok(output) => { staged = Some((temporary, output)); break; }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    let (temporary, mut output) = staged.ok_or_else(|| io::Error::new(
        ErrorKind::AlreadyExists, "could not reserve a unique backup temporary file",
    ))?;

    let copied = (|| -> io::Result<u64> {
        let copied = io::copy(&mut input, &mut output)?;
        if copied != source_metadata.len() || input.metadata()?.len() != source_metadata.len() {
            return Err(io::Error::new(ErrorKind::InvalidData, "source changed size during backup"));
        }
        output.flush()?;
        output.sync_all()?;
        Ok(copied)
    })();
    drop(output);
    let result = copied.and_then(|count| {
        fs::hard_link(&temporary, destination)?;
        Ok(count)
    });
    let cleanup = fs::remove_file(&temporary);
    match result {
        Ok(count) => { cleanup?; Ok(count) }
        Err(err) => { let _ = cleanup; Err(err) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("ninforge-saves-{}-{nanos}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn inventory_is_a_hint_not_a_validator() {
        let temp = Fixture::new();
        fs::create_dir(temp.0.join("nested")).unwrap();
        fs::write(temp.0.join("nested/demo.DSV"), b"abc").unwrap();
        fs::write(temp.0.join("nested/rom.nds"), b"not a game").unwrap();
        let files = inventory(&temp.0).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].hint, "DeSmuME DS save candidate");
        assert_eq!(files[0].size, 3);
    }

    #[test]
    fn backup_is_exact_and_cannot_clobber_existing_file() {
        let temp = Fixture::new();
        let src = temp.0.join("source.sav");
        let dest = temp.0.join("saved.sav");
        fs::write(&src, b"synthetic save bytes").unwrap();
        assert_eq!(backup(&src, &dest).unwrap(), 20);
        assert_eq!(fs::read(&dest).unwrap(), b"synthetic save bytes");
        assert_eq!(backup(&src, &dest).unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&dest).unwrap(), b"synthetic save bytes");
        assert_eq!(inventory(&temp.0).unwrap().len(), 2);
    }

    #[test]
    fn refuses_directory_as_save_source() {
        let temp = Fixture::new();
        assert_eq!(backup(&temp.0, &temp.0.join("output.sav")).unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks_and_rejects_symlink_backup_source() {
        use std::os::unix::fs::symlink;
        let temp = Fixture::new();
        fs::write(temp.0.join("real.sav"), b"abc").unwrap();
        symlink(temp.0.join("real.sav"), temp.0.join("link.sav")).unwrap();
        assert_eq!(inventory(&temp.0).unwrap().len(), 1);
        assert_eq!(backup(&temp.0.join("link.sav"), &temp.0.join("out.sav")).unwrap_err().kind(), ErrorKind::InvalidInput);
    }
}
