// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use pc_codec::{CodecError, Encodable};
use pc_crypto::blake3_32;
use pc_types::{LockCommitment, MintEvent};
use serde::Deserialize;

const ROLE_POLICY_DOMAIN_V1: &[u8] = b"pc:role:policy:v1\x01";

#[derive(Debug, Deserialize)]
struct RolePolicyFile {
    version: u8,
    #[serde(default)]
    mint_locks: Vec<String>,
    #[serde(default)]
    validator_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolePolicy {
    version: u8,
    mint_locks: Vec<[u8; 32]>,
    validator_ids: Vec<[u8; 32]>,
}

impl RolePolicy {
    pub fn from_json_bytes(data: &[u8]) -> Result<Self, String> {
        let file: RolePolicyFile =
            serde_json::from_slice(data).map_err(|e| format!("parse role_policy: {e}"))?;
        if file.version != 1 {
            return Err(format!("unsupported role_policy version: {}", file.version));
        }
        let mut mint_locks = parse_hex32_list(&file.mint_locks, "mint_locks")?;
        let mut validator_ids = parse_hex32_list(&file.validator_ids, "validator_ids")?;
        mint_locks.sort_unstable();
        mint_locks.dedup();
        validator_ids.sort_unstable();
        validator_ids.dedup();

        // Rollen-Exklusivität: Ein Identifier darf nicht sowohl Miner als auch Validator sein
        for id in &mint_locks {
            if validator_ids.binary_search(id).is_ok() {
                return Err(format!(
                    "role_policy: {} ist in mint_locks UND validator_ids - Rollen müssen exklusiv sein",
                    hex::encode(id)
                ));
            }
        }

        Ok(Self {
            version: file.version,
            mint_locks,
            validator_ids,
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(ROLE_POLICY_DOMAIN_V1.len() + self.encoded_len());
        buf.extend_from_slice(ROLE_POLICY_DOMAIN_V1);
        let _ = self.encode(&mut buf);
        blake3_32(&buf)
    }

    pub fn allows_mint_lock(&self, lock: &LockCommitment) -> bool {
        if self.mint_locks.is_empty() {
            return true;
        }
        self.mint_locks.binary_search(&lock.0).is_ok()
    }

    pub fn allows_validator_id(&self, validator_id: &[u8; 32]) -> bool {
        if self.validator_ids.is_empty() {
            return true;
        }
        self.validator_ids.binary_search(validator_id).is_ok()
    }

    pub fn allows_mint(&self, mint: &MintEvent) -> bool {
        mint.outputs.iter().all(|o| self.allows_mint_lock(&o.lock))
    }

    pub fn mint_locks_len(&self) -> usize {
        self.mint_locks.len()
    }

    pub fn validator_ids_len(&self) -> usize {
        self.validator_ids.len()
    }
}

impl Encodable for RolePolicy {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.mint_locks.encode(w)?;
        self.validator_ids.encode(w)?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.mint_locks.encoded_len()
            + self.validator_ids.encoded_len()
    }
}

fn parse_hex32_list(items: &[String], field: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::with_capacity(items.len());
    for s in items {
        let bytes = hex::decode(s).map_err(|e| format!("invalid hex in {field}: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "invalid length in {field}: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        out.push(arr);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_policy_commitment_is_order_independent() {
        let a = br#"{"version":1,"mint_locks":["0000000000000000000000000000000000000000000000000000000000000002"],"validator_ids":["0000000000000000000000000000000000000000000000000000000000000001","0000000000000000000000000000000000000000000000000000000000000003"]}"#;
        let b = br#"{"version":1,"validator_ids":["0000000000000000000000000000000000000000000000000000000000000003","0000000000000000000000000000000000000000000000000000000000000001"],"mint_locks":["0000000000000000000000000000000000000000000000000000000000000002"]}"#;
        let pa = RolePolicy::from_json_bytes(a).expect("parse a");
        let pb = RolePolicy::from_json_bytes(b).expect("parse b");
        assert_eq!(pa, pb);
        assert_eq!(pa.commitment(), pb.commitment());
    }

    #[test]
    fn role_policy_allows_all_when_lists_empty() {
        let data = br#"{"version":1}"#;
        let p = RolePolicy::from_json_bytes(data).expect("parse");
        let lock = LockCommitment([0x11; 32]);
        assert!(p.allows_mint_lock(&lock));
        assert!(p.allows_validator_id(&[0x22; 32]));
    }

    #[test]
    fn role_policy_rejects_overlap_between_miner_and_validator() {
        // Derselbe Identifier in beiden Listen → Fehler
        let data = br#"{"version":1,"mint_locks":["0000000000000000000000000000000000000000000000000000000000000001"],"validator_ids":["0000000000000000000000000000000000000000000000000000000000000001"]}"#;
        let result = RolePolicy::from_json_bytes(data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mint_locks UND validator_ids"));
    }

    #[test]
    fn role_policy_accepts_disjoint_lists() {
        // Verschiedene Identifier → OK
        let data = br#"{"version":1,"mint_locks":["0000000000000000000000000000000000000000000000000000000000000001"],"validator_ids":["0000000000000000000000000000000000000000000000000000000000000002"]}"#;
        let p = RolePolicy::from_json_bytes(data).expect("parse");
        assert_eq!(p.mint_locks_len(), 1);
        assert_eq!(p.validator_ids_len(), 1);
    }
}
