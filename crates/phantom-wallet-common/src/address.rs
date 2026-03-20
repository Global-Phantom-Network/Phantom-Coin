// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use bech32::FromBase32 as _;

pub fn lock_from_pc_address(addr: &str) -> Result<[u8; 32]> {
    let (hrp, data, variant) = bech32::decode(addr).map_err(|e| anyhow!("bech32 decode: {e}"))?;
    if hrp != "pc" {
        return Err(anyhow!("unexpected hrp: {hrp}"));
    }
    if variant != bech32::Variant::Bech32m {
        return Err(anyhow!("expected Bech32m variant"));
    }
    let (ver_u5, prog_u5) = data
        .split_first()
        .ok_or_else(|| anyhow!("bech32 data empty"))?;
    if ver_u5.to_u8() != 1 {
        return Err(anyhow!("unsupported witness version: {}", ver_u5.to_u8()));
    }
    let prog: Vec<u8> =
        Vec::<u8>::from_base32(prog_u5).map_err(|e| anyhow!("bech32 program decode: {e}"))?;
    if prog.len() != 32 {
        return Err(anyhow!(
            "program length must be 32 bytes, got {}",
            prog.len()
        ));
    }
    let mut lock = [0u8; 32];
    lock.copy_from_slice(&prog);
    Ok(lock)
}
