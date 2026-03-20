// SPDX-License-Identifier: AGPL-3.0-only
use std::fs::{create_dir_all, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use pc_codec::Encodable;

fn write_seed<P: AsRef<Path>>(path: P, bytes: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Seeds for codec_varint
    let varint_dir = base.join("fuzz/corpus/codec_varint");
    let mut buf = Vec::new();
    for (i, v) in [0u64, 1, 127, 128, 16_384, u64::MAX]
        .into_iter()
        .enumerate()
    {
        buf.clear();
        v.encode(&mut buf)?;
        write_seed(varint_dir.join(format!("varint-{}.bin", i)), &buf)?;
    }

    // Seeds for codec_vec (Vec<u8>)
    let vec_dir = base.join("fuzz/corpus/codec_vec");
    // Vec<u8>
    let mut buf = Vec::new();
    let v1: Vec<u8> = vec![1, 2, 3, 4, 5];
    v1.encode(&mut buf)?;
    write_seed(vec_dir.join("vec_u8.bin"), &buf)?;

    // Vec<[u8;32]>
    buf.clear();
    let v2: Vec<[u8; 32]> = vec![[0u8; 32], [1u8; 32], [2u8; 32]];
    v2.encode(&mut buf)?;
    write_seed(vec_dir.join("vec_arr32.bin"), &buf)?;

    // Vec<Vec<[u8;32]>>
    buf.clear();
    let v3: Vec<Vec<[u8; 32]>> = vec![vec![[9u8; 32]; 1], vec![[7u8; 32]; 2]];
    v3.encode(&mut buf)?;
    write_seed(vec_dir.join("vec_vec_arr32.bin"), &buf)?;

    Ok(())
}
