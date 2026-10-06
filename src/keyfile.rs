//! Crash-safe creation of the assertion signing seed.
//!
//! The seed is written to a fresh temporary file in the same directory,
//! flushed, then hard-linked into place, which fails rather than replacing an
//! existing file, and the directory is flushed. A crash can therefore leave
//! only a stray temporary file (cleaned up on the next start), never a partial
//! seed at the final path. An existing final file of the wrong size is an error:
//! it is never silently regenerated, because backends trust the matching key.

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

fn temp_name(name: &str) -> String {
    let mut tag = [0u8; 8];
    // Uniqueness only; falls back to the process id if randomness fails.
    let tag = match getrandom_fill(&mut tag) {
        Ok(()) => tag.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        Err(_) => std::process::id().to_string(),
    };
    format!("{name}.tmp-{tag}")
}

fn getrandom_fill(buf: &mut [u8]) -> io::Result<()> {
    let seed = edge_assert::Signer::generate_seed().map_err(|_| io::Error::other("random"))?;
    for (b, s) in buf.iter_mut().zip(seed) {
        *b = s;
    }
    Ok(())
}

fn read_existing(path: &Path) -> io::Result<[u8; 32]> {
    fs::read(path)?
        .try_into()
        .map_err(|_| io::Error::other("assertion key file has the wrong size"))
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Load `dir/name`, creating it atomically with a fresh random seed if absent.
pub fn load_or_create_seed(dir: &Path, name: &str) -> io::Result<[u8; 32]> {
    // A concurrent starter's leftover-cleanup can remove our temporary before
    // it is linked; that surfaces as NotFound and is simply retried.
    let mut attempt = 0;
    loop {
        match try_load_or_create(dir, name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && attempt < 5 => attempt += 1,
            other => return other,
        }
    }
}

fn try_load_or_create(dir: &Path, name: &str) -> io::Result<[u8; 32]> {
    let path = dir.join(name);
    match read_existing(&path) {
        Ok(seed) => return Ok(seed),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Remove temporaries left behind by an earlier crash (best effort).
    if let Ok(entries) = fs::read_dir(dir) {
        let prefix = format!("{name}.tmp-");
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let seed = edge_assert::Signer::generate_seed()
        .map_err(|_| io::Error::other("random source unavailable"))?;
    let tmp = dir.join(temp_name(name));
    let written = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&seed)?;
        file.sync_all()
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let linked = fs::hard_link(&tmp, &path);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            sync_dir(dir)?;
            Ok(seed)
        }
        // Another starter won the race: use its key.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => read_existing(&path),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(temp_name("mcp-edge-keyfile-test"));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_once_and_reloads_the_same_seed() {
        let d = TempDir::new();
        let a = load_or_create_seed(&d.0, "k.bin").unwrap();
        let b = load_or_create_seed(&d.0, "k.bin").unwrap();
        assert_eq!(a, b);
        assert_eq!(fs::read(d.0.join("k.bin")).unwrap().len(), 32);
        assert_eq!(
            fs::read_dir(&d.0).unwrap().count(),
            1,
            "no temporaries left"
        );
    }

    #[test]
    fn wrong_size_final_file_is_an_error_not_replaced() {
        let d = TempDir::new();
        fs::write(d.0.join("k.bin"), [1u8; 10]).unwrap();
        assert!(load_or_create_seed(&d.0, "k.bin").is_err());
        assert_eq!(fs::read(d.0.join("k.bin")).unwrap(), vec![1u8; 10]);
    }

    #[test]
    fn crash_leftovers_do_not_brick_startup() {
        let d = TempDir::new();
        fs::write(d.0.join("k.bin.tmp-deadbeef"), []).unwrap();
        fs::write(d.0.join("k.bin.tmp-0123"), [7u8; 5]).unwrap();
        let seed = load_or_create_seed(&d.0, "k.bin").unwrap();
        assert_eq!(fs::read(d.0.join("k.bin")).unwrap(), seed.to_vec());
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_creators_agree_on_one_key() {
        let d = TempDir::new();
        let dir = d.0.clone();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || load_or_create_seed(&dir, "k.bin").unwrap())
            })
            .collect();
        let seeds: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(seeds.windows(2).all(|w| w[0] == w[1]));
    }
}
