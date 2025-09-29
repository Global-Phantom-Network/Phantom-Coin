#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

use pc_crypto::{blake3_32, merkle_root_hashes, Hash32};
use pc_types::{Amount, OutPoint, MicroTx, MintEvent, LockCommitment};
use pc_types::{digest_microtx, digest_mint};
use std::collections::{HashMap, HashSet};
#[cfg(feature = "rocksdb")]
use rocksdb::{DB, Options, IteratorMode};

#[derive(Debug)]
pub enum StateError {
    MissingInput(OutPoint),
    DoubleSpend(OutPoint),
    AmountMismatch,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingInput(op) => write!(f, "missing input: {:?}", op),
            Self::DoubleSpend(op) => write!(f, "double spend: {:?}", op),
            Self::AmountMismatch => write!(f, "amounts in != out"),
        }
    }
}
impl std::error::Error for StateError {}

// Einfache Backend-Trait für UTXO-Storage
pub trait StateBackend {
    fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)>;
    fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment));
    fn del(&mut self, key: &OutPoint) -> bool;
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'a>;
}

pub struct InMemoryBackend {
    map: HashMap<OutPoint, (Amount, LockCommitment)>,
}
impl InMemoryBackend {
    pub fn new() -> Self { Self { map: HashMap::new() } }
    pub fn len(&self) -> usize { self.map.len() }
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}
impl Default for InMemoryBackend { fn default() -> Self { Self::new() } }
impl StateBackend for InMemoryBackend {
    fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)> { self.map.get(key).copied() }
    fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment)) { let _ = self.map.insert(key, val); }
    fn del(&mut self, key: &OutPoint) -> bool { self.map.remove(key).is_some() }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'a> {
        Box::new(self.map.iter().map(|(k, v)| (*k, *v)))
    }
}

  #[cfg(feature = "rocksdb")]
  pub struct RocksDbBackend {
      db: DB,
  }

  #[cfg(feature = "rocksdb")]
  impl RocksDbBackend {
      pub fn open(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
          let mut opts = Options::default();
          opts.create_if_missing(true);
          let db = DB::open(&opts, path)?;
          Ok(Self { db })
      }

      fn enc_key(op: &OutPoint) -> [u8; 36] {
          let mut k = [0u8; 36];
          k[0..32].copy_from_slice(&op.txid);
          k[32..36].copy_from_slice(&op.vout.to_be_bytes());
          k
      }
      fn dec_key(k: &[u8]) -> Option<OutPoint> {
          if k.len() != 36 { return None; }
          let mut txid = [0u8;32]; txid.copy_from_slice(&k[0..32]);
          let mut vout_b = [0u8;4]; vout_b.copy_from_slice(&k[32..36]);
          Some(OutPoint { txid, vout: u32::from_be_bytes(vout_b) })
      }
      fn enc_val(v: &(Amount, LockCommitment)) -> [u8; 40] {
          let mut out = [0u8; 40];
          out[0..8].copy_from_slice(&v.0.to_be_bytes());
          out[8..40].copy_from_slice(&v.1 .0);
          out
      }
      fn dec_val(b: &[u8]) -> Option<(Amount, LockCommitment)> {
          if b.len() != 40 { return None; }
          let mut amt_b = [0u8;8]; amt_b.copy_from_slice(&b[0..8]);
          let mut lock = [0u8;32]; lock.copy_from_slice(&b[8..40]);
          Some((u64::from_be_bytes(amt_b), LockCommitment(lock)))
      }
  }

  #[cfg(feature = "rocksdb")]
  impl StateBackend for RocksDbBackend {
      fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)> {
          let k = Self::enc_key(key);
          match self.db.get(k) { Ok(Some(v)) => Self::dec_val(&v), _ => None }
      }
      fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment)) {
          let k = Self::enc_key(&key);
          let v = Self::enc_val(&val);
          let _ = self.db.put(k, v);
      }
      fn del(&mut self, key: &OutPoint) -> bool {
          let k = Self::enc_key(key);
          self.db.delete(k).is_ok()
      }
      fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'a> {
          let it = self.db.iterator(IteratorMode::Start).filter_map(|kv| {
              match kv {
                  Ok((k, v)) => {
                      let key = Self::dec_key(&k)?;
                      let val = Self::dec_val(&v)?;
                      Some((key, val))
                  }
                  _ => None,
              }
          });
          Box::new(it)
      }
  }

// UTXO-State mit deterministischem Root
pub struct UtxoState<B: StateBackend> { backend: B }
impl<B: StateBackend> UtxoState<B> {
    pub fn new(backend: B) -> Self { Self { backend } }
    pub fn backend_mut(&mut self) -> &mut B { &mut self.backend }

    pub fn apply_mint(&mut self, m: &MintEvent) {
        let txid = digest_mint(m);
        for (i, out) in m.outputs.iter().enumerate() {
            let op = OutPoint { txid, vout: i as u32 };
            self.backend.put(op, (out.amount, out.lock));
        }
    }

    /// Prüft stateful (ohne Mutation), ob eine MicroTx anwendbar wäre.
    pub fn can_apply_micro_tx(&self, tx: &MicroTx) -> Result<(), StateError> {
        let mut seen: HashSet<OutPoint> = HashSet::new();
        let mut amt_in: u128 = 0;
        for tin in &tx.inputs {
            let op = tin.prev_out;
            if !seen.insert(op) { return Err(StateError::DoubleSpend(op)); }
            let (amt, _lock) = self.backend.get(&op).ok_or(StateError::MissingInput(op))?;
            amt_in = amt_in.saturating_add(amt as u128);
        }
        let mut amt_out: u128 = 0;
        for tout in &tx.outputs { amt_out = amt_out.saturating_add(tout.amount as u128); }
        if amt_in != amt_out { return Err(StateError::AmountMismatch); }
        Ok(())
    }

    pub fn apply_micro_tx(&mut self, tx: &MicroTx) -> Result<(), StateError> {
        // Doppelte Inputs verhindern
        let mut seen: HashSet<OutPoint> = HashSet::new();
        let mut amt_in: u128 = 0;
        for tin in &tx.inputs {
            let op = tin.prev_out;
            if !seen.insert(op) { return Err(StateError::DoubleSpend(op)); }
            let (amt, _lock) = self.backend.get(&op).ok_or(StateError::MissingInput(op))?;
            amt_in = amt_in.saturating_add(amt as u128);
        }
        let mut amt_out: u128 = 0;
        for tout in &tx.outputs { amt_out = amt_out.saturating_add(tout.amount as u128); }
        if amt_in != amt_out { return Err(StateError::AmountMismatch); }
        // Delete inputs, insert outputs (atomar genug im InMemory-Backend)
        for tin in &tx.inputs { let _ = self.backend.del(&tin.prev_out); }
        let txid = digest_microtx(tx);
        for (i, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint { txid, vout: i as u32 };
            self.backend.put(op, (out.amount, out.lock));
        }
        Ok(())
    }

    pub fn root(&self) -> Hash32 {
        // deterministische Reihenfolge: nach (txid,vout) sortieren
        let mut items: Vec<(OutPoint, (Amount, LockCommitment))> = self.backend.iter().collect();
        items.sort_by(|a, b| {
            let (ka, _va) = a; let (kb, _vb) = b;
            match ka.txid.cmp(&kb.txid) { core::cmp::Ordering::Equal => ka.vout.cmp(&kb.vout), o => o }
        });
        // Leaves mit Domain: H("pc:utxo:leaf:v1\x01" || txid(32) || vout(4) || amount(8) || lock(32))
        const UTXO_LEAF_DOMAIN: &[u8] = b"pc:utxo:leaf:v1\x01";
        let mut leaves: Vec<Hash32> = Vec::with_capacity(items.len());
        for (op, (amt, lock)) in items.into_iter() {
            let mut buf = Vec::with_capacity(UTXO_LEAF_DOMAIN.len() + 32 + 4 + 8 + 32);
            buf.extend_from_slice(UTXO_LEAF_DOMAIN);
            buf.extend_from_slice(&op.txid);
            buf.extend_from_slice(&op.vout.to_le_bytes());
            buf.extend_from_slice(&amt.to_le_bytes());
            buf.extend_from_slice(&lock.0);
            leaves.push(blake3_32(&buf));
        }
        merkle_root_hashes(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_types::{TxIn, TxOut};

    #[test]
    fn mint_then_tx_roundtrip_state() {
        let mut st = UtxoState::new(InMemoryBackend::new());
        // Mint erzeugt 2 Outputs
        let out0 = TxOut { amount: 50, lock: LockCommitment([1u8;32]) };
        let out1 = TxOut { amount: 30, lock: LockCommitment([2u8;32]) };
        let mint = MintEvent { version:1, prev_mint_id:[0u8;32], outputs: vec![out0, out1], pow_seed:[9u8;32], pow_nonce: 7 };
        st.apply_mint(&mint);
        let r1 = st.root();

        // Übertrage 50 -> 20 + 30
        let txid_m = digest_mint(&mint);
        let txin = TxIn { prev_out: OutPoint { txid: txid_m, vout: 0 }, witness: vec![] };
        let t_out0 = TxOut { amount: 20, lock: LockCommitment([3u8;32]) };
        let t_out1 = TxOut { amount: 30, lock: LockCommitment([4u8;32]) };
        let mtx = MicroTx { version:1, inputs: vec![txin], outputs: vec![t_out0, t_out1] };
        assert!(st.apply_micro_tx(&mtx).is_ok());
        let r2 = st.root();
        assert_ne!(r1, r2);

        // Double spend verhindern
        let txin_again = TxIn { prev_out: OutPoint { txid: txid_m, vout: 0 }, witness: vec![] };
        let mtx2 = MicroTx { version:1, inputs: vec![txin_again], outputs: vec![TxOut { amount: 50, lock: LockCommitment([5u8;32]) }] };
        assert!(matches!(st.apply_micro_tx(&mtx2), Err(StateError::MissingInput(_))));
    }

    #[test]
    fn amount_mismatch_rejected() {
        let mut st = UtxoState::new(InMemoryBackend::new());
        let out0 = TxOut { amount: 10, lock: LockCommitment([1u8;32]) };
        let mint = MintEvent { version:1, prev_mint_id:[0u8;32], outputs: vec![out0], pow_seed:[9u8;32], pow_nonce: 1 };
        st.apply_mint(&mint);
        let txid_m = digest_mint(&mint);
        let txin = pc_types::TxIn { prev_out: OutPoint { txid: txid_m, vout: 0 }, witness: vec![] };
        // outputs sum != inputs sum
        let bad = MicroTx { version:1, inputs: vec![txin], outputs: vec![TxOut { amount: 9, lock: LockCommitment([7u8;32]) }] };
        assert!(matches!(st.apply_micro_tx(&bad), Err(StateError::AmountMismatch)));
    }
}

#[cfg(all(test, feature = "rocksdb"))]
mod rocks_tests {
    use super::*;
    use pc_types::{TxIn, TxOut};

    fn unique_tmp_path(suffix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("pc_state_rocksdb_{}_{}", nanos, suffix));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn rocksdb_backend_basic_ops() {
        let path = unique_tmp_path("basic");
        let mut be = RocksDbBackend::open(&path).expect("open rocksdb");
        let op = OutPoint { txid: [7u8;32], vout: 1 };
        let val = (123u64, LockCommitment([9u8;32]));
        // put/get
        be.put(op, val);
        assert_eq!(be.get(&OutPoint { txid: [7u8;32], vout: 1 }), Some(val));
        // del
        assert!(be.del(&OutPoint { txid: [7u8;32], vout: 1 }));
        assert!(be.get(&OutPoint { txid: [7u8;32], vout: 1 }).is_none());
        // iter (should be empty)
        assert_eq!(be.iter().count(), 0);
    }

    #[test]
    fn rocksdb_state_root_changes() {
        let path = unique_tmp_path("root");
        let be = RocksDbBackend::open(&path).expect("open rocksdb");
        let mut st = UtxoState::new(be);

        // Mint 2 Outputs
        let m_out0 = TxOut { amount: 50, lock: LockCommitment([1u8;32]) };
        let m_out1 = TxOut { amount: 30, lock: LockCommitment([2u8;32]) };
        let mint = MintEvent { version:1, prev_mint_id:[0u8;32], outputs: vec![m_out0, m_out1], pow_seed:[3u8;32], pow_nonce: 11 };
        st.apply_mint(&mint);
        let r1 = st.root();
        assert_ne!(r1, [0u8;32]);

        // Spend 50 -> 20 + 30
        let txid_m = digest_mint(&mint);
        let txin = TxIn { prev_out: OutPoint { txid: txid_m, vout: 0 }, witness: vec![] };
        let t_out0 = TxOut { amount: 20, lock: LockCommitment([3u8;32]) };
        let t_out1 = TxOut { amount: 30, lock: LockCommitment([4u8;32]) };
        let mtx = MicroTx { version:1, inputs: vec![txin], outputs: vec![t_out0, t_out1] };
        assert!(st.apply_micro_tx(&mtx).is_ok());
        let r2 = st.root();
        assert_ne!(r1, r2);
    }
}
