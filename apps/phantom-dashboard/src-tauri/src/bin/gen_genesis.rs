use pc_codec::Encodable;
use pc_types::{digest_genesis_note, GenesisNote, GenesisParams, GenesisValidatorV1};

const MAINNET_EMISSION_BOOTSTRAP_BUCKET: u64 = 1_773_964_800;

fn decode_fixed_hex<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{label} ungültig: {e}"))?;
    if bytes.len() != N {
        return Err(format!(
            "{label} hat unerwartete Länge: {} != {}",
            bytes.len(),
            N
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn main() {
    run().unwrap_or_else(|e| panic!("{e}"));
}

fn run() -> Result<(), String> {
    // Fester, deterministischer Seed — definiert die Netzwerk-Identität.
    // DARF NIEMALS geändert werden, da sonst eine neue Blockchain entsteht.
    let seed: [u8; 32] = *b"PhantomCoin_Genesis_Mainnet_v1\x00\x00";
    let operator_id = decode_fixed_hex::<32>(
        "03f4e5197b88794fd4fb7db8c646ce413014cc580603d1353ebf5dffdaa2e22d",
        "operator_id",
    )?;
    let bls_pk = decode_fixed_hex::<48>(
        "8c019f9d0368b18d65ef9b7ae71b9b949140ee385409873ec823a2f1c4328e09173fd15caf7951364eaa97f53d3edb9f",
        "bls_pk",
    )?;
    let bls_pop = decode_fixed_hex::<96>(
        "b0cfc3daf9a5176bca89031f651f84e1f787aa23ef7936429ab4ed370b3cbecbc7483cf4f77b03aa5a2677598ddb9d5800a0529817df5986f23e9f766fcff24f5e81e4d96f22ac7c959e5d974136e23a6d4f46e9a8c89209c5c8fa32017abdb8",
        "bls_pop",
    )?;

    let note = GenesisNote {
        version: 3,
        network_name: b"phantom-mainnet".to_vec(),
        seed,
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 256,
            features: 0x8d,
        },
        genesis_validators: vec![GenesisValidatorV1 {
            operator_id,
            bls_pk,
            bls_pop,
        }],
        genesis_message: Vec::new(),
        emission_bootstrap_bucket: MAINNET_EMISSION_BOOTSTRAP_BUCKET,
    };

    let mut buf = Vec::with_capacity(note.encoded_len());
    note.encode(&mut buf)
        .map_err(|e| format!("genesis encode failed: {e}"))?;

    let nid = digest_genesis_note(&note);

    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "genesis_note.bin".to_string());

    std::fs::write(&out_path, &buf).map_err(|e| format!("write genesis_note.bin failed: {e}"))?;

    eprintln!("genesis_note.bin geschrieben: {}", out_path);
    eprintln!("  network_id : {}", hex::encode(nid));
    eprintln!("  network    : phantom-mainnet");
    eprintln!("  seed       : {}", hex::encode(seed));
    eprintln!(
        "  emission_bootstrap_bucket : {}",
        MAINNET_EMISSION_BOOTSTRAP_BUCKET
    );
    eprintln!("  bytes      : {}", buf.len());
    Ok(())
}
