// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use std::path::Path;

pub fn with_temp_secret_file<R, F>(prefix: &str, secret: &str, f: F) -> Result<R>
where
    F: FnOnce(&Path) -> Result<R>,
{
    use rand::RngCore as _;

    let mut path: std::path::PathBuf;
    let mut file = None;
    for _ in 0..16 {
        let mut rnd = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rnd);
        let name = format!("{}_{}.secret", prefix, hex::encode(rnd));
        path = std::env::temp_dir().join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(fh) => {
                file = Some((path, fh));
                break;
            }
            Err(_) => continue,
        }
    }
    let (path, mut fh) = file.ok_or_else(|| {
        anyhow!(
            "could not create temp secret file in {}",
            std::env::temp_dir().display()
        )
    })?;
    {
        use std::io::Write as _;
        fh.write_all(secret.as_bytes())?;
        fh.write_all(b"\n")?;
        let _ = fh.flush();
    }
    drop(fh);
    let res = f(&path);
    let _ = std::fs::remove_file(&path);
    res
}
