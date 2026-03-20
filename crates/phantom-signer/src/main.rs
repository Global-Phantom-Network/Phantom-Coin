// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

use std::fs;
use std::io::{IsTerminal as _, Read as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use bech32::{self, FromBase32, ToBase32};
use bip32::secp256k1::PublicKey as B32SecpPk;
use bip32::PublicKey as Bip32PublicKeyTrait;
use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, ExtendedPublicKey};
use bip39::{Language, Mnemonic};
use bitbox_api::{self, runtime::DefaultRuntime, usb, Keypath, NoiseConfig, PersistedNoiseConfig};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use clap::{Parser, Subcommand, ValueEnum};
use futures::executor::block_on;
use pc_crypto::{blake3_32, bls, schnorr, BlsPublicKey, Hash32};
use pc_types::{MicroTx, NetworkId};
use phantom_i18n::{cli_texts, Lang};
use rpassword::read_password;
use secp256k1::PublicKey as SecpPub;
use serde::{Deserialize, Serialize};
use std::env;
use std::process::Command;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

mod helpers;
mod payjoin;
mod pkcs11_sign;
mod psbt;
mod slashdb;
mod walletdb;
use helpers::*;
mod keystore;
use keystore::*;
mod wallet_ops;
use wallet_ops::*;

#[cfg(test)]
mod tests;

#[derive(Debug, Parser)]
#[command(name = "phantom-signer", version, about = "Phantom Signer CLI", long_about = None)]
struct Cli {
    /// Path to a signer configuration file (TOML).
    /// Pfad zu einer Signer-Konfigurationsdatei (TOML)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Language for CLI messages (en, de, es, fr, it, pt, nl, ru, zh, ja, ko, tr, ar, pl)
    /// Sprache für CLI-Meldungen
    #[arg(long, default_value = "de", env = "PHANTOM_LANG")]
    lang: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generates a new key and stores it encrypted in the keystore.
    /// Generiert einen neuen Key und speichert ihn verschlüsselt im Keystore
    Keygen {
        #[arg(long, value_enum)]
        r#type: KeyType,
        #[arg(long, value_enum)]
        algo: Algo,
        /// Output file (keystore).
        /// Ausgabedatei (Keystore)
        #[arg(long)]
        out: PathBuf,
        /// Allow overwriting.
        /// Überschreiben erlauben
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Optional: read passphrase from an environment variable (name of the variable); disables the double prompt.
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable), deaktiviert doppelte Abfrage
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file; disables the double prompt.
        /// Optional: Passphrase aus Datei lesen, deaktiviert doppelte Abfrage
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Optional: derive keystore passphrase from a master passphrase for a role (validator/miner).
        /// Optional: Keystore-Passphrase aus Master-Passphrase für eine Rolle ableiten (validator/miner)
        #[arg(long, value_enum)]
        passphrase_role: Option<PassphraseRole>,
    },
    /// Creates an empty MicroTx (version=1, without inputs/outputs) as a binary file (pc-codec).
    /// Erstellt eine leere MicroTx (version=1, ohne Inputs/Outputs) als Binärdatei (pc-codec)
    TxNewEmpty {
        /// Output file.
        /// Ausgabedatei
        #[arg(long)]
        out: PathBuf,
    },
    /// Sends a finalized MicroTx (.bin) via HTTP RPC to the node (/tx/broadcast).
    /// Sendet eine finalisierte MicroTx (.bin) via HTTP RPC an den Node (/tx/broadcast)
    TxBroadcast {
        /// Node URL (e.g. http://127.0.0.1:8080).
        /// Node-URL (z. B. http://127.0.0.1:8080)
        #[arg(long, default_value = "https://127.0.0.1:8080")]
        node: String,
        /// Path to the finalized MicroTx (.bin).
        /// Pfad zur finalisierten MicroTx (.bin)
        #[arg(long)]
        tx: PathBuf,
        /// Optional bearer token for node RPC.
        /// Optionales Bearer-Token für Node-RPC
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        /// Optional: CA certificate (PEM) for TLS.
        /// Optional: CA‑Zertifikat (PEM) für TLS
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        /// Optional: client certificate + key (combined PEM) for mTLS.
        /// Optional: Client‑Zertifikat+Key (kombinierte PEM) für mTLS
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    /// Creates a Phantom PSBT (TOML) from a binary MicroTx (pc-codec) and derivation paths.
    /// Erzeugt eine Phantom-PSBT (TOML) aus einer binären MicroTx (pc-codec) und Ableitungspfaden
    PsbtCreate {
        /// Binary MicroTx file (pc-codec).
        /// Binäre MicroTx-Datei (pc-codec)
        #[arg(long)]
        tx_bin: PathBuf,
        /// Derivation paths, comma-separated; length must match the number of inputs.
        /// Ableitungspfade, komma-separiert, Länge muss Anzahl Inputs entsprechen
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,
        /// Output file (PSBT TOML).
        /// Ausgabedatei (PSBT TOML)
        #[arg(long)]
        out: PathBuf,
    },
    /// Computes the sighash of a Phantom PSBT.
    /// Berechnet den Sighash einer Phantom-PSBT
    PsbtSighash {
        /// Path to the PSBT TOML.
        /// Pfad zur PSBT TOML
        #[arg(long)]
        psbt: PathBuf,
        #[arg(long)]
        network_id: Option<String>,
    },
    /// Signs the Phantom PSBT with a local keystore (Schnorr).
    /// Signiert die Phantom-PSBT mit einem lokalen Keystore (Schnorr)
    SignTxWithKeystore {
        /// Path to the PSBT TOML.
        /// Pfad zur PSBT TOML
        #[arg(long)]
        psbt: PathBuf,
        /// Keystore (encrypted).
        /// Keystore (verschlüsselt)
        #[arg(long)]
        keystore: PathBuf,
        /// Optional: write signature (hex) to a file; otherwise stdout.
        /// Optional: Ausgabe der Signatur (hex) in Datei; sonst stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional: read passphrase from an environment variable (name of the variable).
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file.
        /// Optional: Passphrase aus Datei lesen
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        network_id: Option<String>,
    },
    /// Verifies the signature of a Phantom PSBT against a public key.
    /// Verifiziert die Signatur einer Phantom-PSBT gegen einen Public Key
    VerifyTxSig {
        /// Path to the PSBT TOML.
        /// Pfad zur PSBT TOML
        #[arg(long)]
        psbt: PathBuf,
        /// Algorithm.
        /// Algorithmus
        #[arg(long, value_enum)]
        algo: Algo,
        /// Public key hex (schnorr = xonly 32B).
        /// Public Key hex (schnorr=xonly 32B)
        #[arg(long)]
        pub_hex: String,
        /// Signature hex (schnorr = 64B).
        /// Signatur hex (schnorr=64B)
        #[arg(long)]
        sig_hex: String,
        #[arg(long)]
        network_id: Option<String>,
    },
    /// Finalizes a Phantom PSBT by appending a witness (xonly||sig) per input.
    /// Finalisiert eine Phantom-PSBT, indem pro Input Witness (xonly||sig) angehängt wird
    PsbtFinalize {
        /// Path to the PSBT TOML.
        /// Pfad zur PSBT TOML
        #[arg(long)]
        psbt: PathBuf,
        /// Comma-separated list of xonly public keys (hex), length = #inputs.
        /// Komma-separierte Liste von xonly-Public-Keys (hex), Länge = #Inputs
        #[arg(long, value_delimiter = ',')]
        pubkeys: Vec<String>,
        /// Comma-separated list of signatures (64B hex), length = #inputs.
        /// Komma-separierte Liste von Signaturen (64B hex), Länge = #Inputs
        #[arg(long, value_delimiter = ',')]
        sigs: Vec<String>,
        /// Output: finalized MicroTx (pc-codec binary).
        /// Ausgabe: finalisierte MicroTx (pc-codec binär)
        #[arg(long)]
        out: PathBuf,
    },
    /// Writes a (possibly finalized) MicroTx as a binary file (pc-codec).
    /// Schreibt eine (ggf. finalisierte) MicroTx als Binärdatei (pc-codec)
    TxWriteBin {
        /// Path to the PSBT TOML (optional, alternative to --tx-bin-src).
        /// Pfad zur PSBT TOML (optional, alternativ --tx-bin-src)
        #[arg(long)]
        psbt: Option<PathBuf>,
        /// If set, the source is already a binary MicroTx.
        /// Falls gesetzt: Quelle ist bereits eine binäre MicroTx
        #[arg(long)]
        tx_bin_src: Option<PathBuf>,
        /// Output file.
        /// Ausgabe-Datei
        #[arg(long)]
        out: PathBuf,
    },
    /// Signs a Phantom PSBT per input via an external BitBox02 signer and optionally finalizes it.
    /// Signiert eine Phantom-PSBT pro Input mittels externem BitBox02-Signer und finalisiert optional
    HwiSignTx {
        /// Path to the PSBT TOML.
        /// Pfad zur PSBT TOML
        #[arg(long)]
        psbt: PathBuf,
        /// Master fingerprint (optional).
        /// Master Fingerprint (optional)
        #[arg(long)]
        fingerprint: Option<String>,
        /// Path to the external signer (default: $PHANTOM_BITBOX2_SIGNER or "bitbox02-signer").
        /// Pfad zum externen Signer (Default: $PHANTOM_BITBOX2_SIGNER oder "bitbox02-signer")
        #[arg(long)]
        external_cmd: Option<PathBuf>,
        /// Output: finalized MicroTx (pc-codec binary). If not set, only signatures are output (JSON).
        /// Ausgabe: finalisierte MicroTx (pc-codec binär). Wenn nicht gesetzt, werden nur Signaturen ausgegeben (JSON)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        network_id: Option<String>,
    },
    /// Lists connected BitBox02 devices via HWI.
    /// Listet verbundene BitBox02-Geräte via HWI
    HwiEnumerate,
    /// Reads an xpub directly from the HWI device (BitBox02) for a path.
    /// Liest ein Xpub direkt vom HWI-Gerät (BitBox02) für einen Pfad
    HwiGetXpub {
        /// Master fingerprint (optional, if multiple devices).
        /// Master Fingerprint (optional: wenn mehrere Geräte)
        #[arg(long)]
        fingerprint: Option<String>,
        /// Derivation path, e.g. m/86'/<coin_type>'/0'.
        /// Derivation Path, z. B. m/86'/<coin_type>'/0'
        #[arg(long)]
        derivation: String,
    },
    /// Signs a message via the BitBox02 HWI device (UTF-8 text).
    /// Signiert eine Nachricht über das BitBox02-HWI-Gerät (UTF-8 Text)
    HwiSignMessage {
        /// Master fingerprint (optional, if multiple devices).
        /// Master Fingerprint (optional: wenn mehrere Geräte)
        #[arg(long)]
        fingerprint: Option<String>,
        /// Derivation path, e.g. m/86'/<coin_type>'/0'/change/index.
        /// Derivation Path, z. B. m/86'/<coin_type>'/0'/change/index
        #[arg(long)]
        derivation: String,
        /// Path to the message file (UTF-8).
        /// Pfad zur Nachrichtendatei (UTF-8)
        #[arg(long)]
        msg: PathBuf,
    },
    /// Imports an extended public key (xpub/ypub/zpub/tpub) as a watch-only keystore (for BitBox02 compatible paths).
    /// Importiert ein Extended Public Key (xpub/ypub/zpub/tpub) als Watch-Only Keystore (für BitBox02 kompatible Pfade)
    ImportXpub {
        /// Algorithm: currently only Schnorr (secp256k1 xonly) is supported.
        /// Algorithmus: aktuell nur Schnorr (secp256k1 xonly) sinnvoll
        #[arg(long, value_enum)]
        algo: Algo,
        /// Extended public key (Base58).
        /// Extended Public Key (Base58)
        #[arg(long)]
        xpub: String,
        /// Root derivation (e.g. m/86'/12345'/0').
        /// Root-Derivation (z. B. m/86'/12345'/0')
        #[arg(long)]
        derivation: String,
        /// Master fingerprint (hex, 4 bytes) – optional.
        /// Master Fingerprint (Hex, 4 Byte) – optional
        #[arg(long)]
        fingerprint: Option<String>,
        /// Output file (XpubStore).
        /// Ausgabedatei (XpubStore)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow overwriting.
        /// Überschreiben erlauben
        #[arg(long, default_value_t = false)]
        force: bool,
        /// HRP (Bech32m) for addresses, default: "pc".
        /// HRP (Bech32m) für Adressen, Default: "pc"
        #[arg(long, default_value = "pc")]
        hrp: String,
        /// Optional: read passphrase from an environment variable (name of the variable).
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file; disables TTY prompting.
        /// Optional: Passphrase aus Datei lesen; deaktiviert TTY-Abfrage
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Derives a receiving address from a watch-only XpubStore (Bech32m, version 1, program = xonly).
    /// Leite aus einem Watch-Only XpubStore eine Empfangsadresse ab (Bech32m, Version 1, Programm=xonly)
    AddrFromXpub {
        /// Path to the XpubStore (TOML).
        /// Pfad zum XpubStore (TOML)
        #[arg(long)]
        xpubstore: PathBuf,
        /// change (0=external, 1=internal)
        #[arg(long, default_value_t = 0u32)]
        change: u32,
        /// index
        #[arg(long, default_value_t = 0u32)]
        index: u32,
        #[arg(long)]
        wallet_db: Option<PathBuf>,
        #[arg(long)]
        label: Option<String>,
        /// Optional: read passphrase from an environment variable (name of the variable).
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file; disables TTY prompting.
        /// Optional: Passphrase aus Datei lesen; deaktiviert TTY-Abfrage
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    WalletListAddrs {
        #[arg(long)]
        wallet_db: PathBuf,
    },
    WalletShowAddr {
        #[arg(long)]
        wallet_db: PathBuf,
        #[arg(long)]
        addr: String,
    },
    /// Imports an existing secret (hex, 32 bytes) into a keystore.
    /// Importiert einen existierenden Secret (hex, 32 bytes) in einen Keystore
    Import {
        #[arg(long, value_enum)]
        r#type: KeyType,
        #[arg(long, value_enum)]
        algo: Algo,
        /// Secret in hex (32 bytes). DEBUG-only (release rejects this source due to argv leakage).
        /// Secret in Hex (32 bytes). Nur DEBUG (Release lehnt wegen argv-Leak ab).
        #[arg(long)]
        secret_hex: Option<String>,
        /// Secret from file (trimmed). Recommended in release builds.
        /// Secret aus Datei (getrimmt). Empfohlen für Release-Builds.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// Secret from environment variable name.
        /// Secret aus ENV-Variable (Name der Variable).
        #[arg(long)]
        secret_env: Option<String>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Optional: read passphrase from an environment variable (name of the variable); disables the double prompt.
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable), deaktiviert doppelte Abfrage
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file; disables the double prompt.
        /// Optional: Passphrase aus Datei lesen, deaktiviert doppelte Abfrage
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Optional: derive keystore passphrase from a master passphrase for a role (validator/miner).
        /// Optional: Keystore-Passphrase aus Master-Passphrase für eine Rolle ableiten (validator/miner)
        #[arg(long, value_enum)]
        passphrase_role: Option<PassphraseRole>,
    },
    /// Exports the public key (hex).
    /// Exportiert den Public Key (hex)
    ExportPub {
        #[arg(long)]
        keystore: PathBuf,
    },
    /// Exports the BLS proof-of-possession (hex).
    /// Exportiert den BLS Proof-of-Possession (hex)
    BlsPop {
        #[arg(long)]
        keystore: PathBuf,
        /// Optional: write PoP (hex) to a file; otherwise stdout.
        /// Optional: Ausgabe des PoP (hex) in Datei; sonst stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional: read passphrase from an environment variable (name of the variable).
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file.
        /// Optional: Passphrase aus Datei lesen
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Optional: derive keystore passphrase from a master passphrase for a role (validator/miner).
        /// Optional: Keystore-Passphrase aus Master-Passphrase für eine Rolle ableiten (validator/miner)
        #[arg(long, value_enum)]
        passphrase_role: Option<PassphraseRole>,
    },
    /// Signs a file.
    /// Signiert eine Datei
    Sign {
        #[arg(long)]
        keystore: PathBuf,
        /// Path to the message file; for Schnorr, blake3-32(msg) is signed.
        /// Pfad zur Nachrichtendatei; für Schnorr wird blake3-32(msg) signiert
        #[arg(long)]
        msg: PathBuf,
        /// Output of the signature in hex.
        /// Ausgabe der Signatur hex
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional: read passphrase from an environment variable (name of the variable).
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file.
        /// Optional: Passphrase aus Datei lesen
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Optional: derive keystore passphrase from a master passphrase for a role (validator/miner).
        /// Optional: Keystore-Passphrase aus Master-Passphrase für eine Rolle ableiten (validator/miner)
        #[arg(long, value_enum)]
        passphrase_role: Option<PassphraseRole>,
    },
    /// Verifies a signature.
    /// Verifiziert eine Signatur
    Verify {
        #[arg(long, value_enum)]
        algo: Algo,
        /// Public Key hex: schnorr=xonly(32B), bls=pk(48B)
        #[arg(long)]
        pub_hex: String,
        /// Path to the message file.
        /// Pfad zur Nachrichtendatei
        #[arg(long)]
        msg: PathBuf,
        /// Signature hex: schnorr = 64B, bls = 96B.
        /// Signatur hex: schnorr=64B, bls=96B
        #[arg(long)]
        sig_hex: String,
    },
    /// Initializes the slashing DB.
    /// Slashing-DB initialisieren
    SlashDbInit {
        /// Directory of the slashing DB.
        /// Verzeichnis der Slashing-DB
        #[arg(long)]
        db_dir: PathBuf,
    },
    /// Slashing DB: fetch vote.
    /// Slashing-DB: Vote abrufen
    SlashDbGet {
        /// Directory of the slashing DB.
        /// Verzeichnis der Slashing-DB
        #[arg(long)]
        db_dir: PathBuf,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        shard: u16,
        #[arg(long)]
        round: u64,
    },
    /// Slashing DB: set vote (idempotent).
    /// Slashing-DB: Vote setzen (idempotent)
    SlashDbPut {
        /// Directory of the slashing DB.
        /// Verzeichnis der Slashing-DB
        #[arg(long)]
        db_dir: PathBuf,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        shard: u16,
        #[arg(long)]
        round: u64,
        /// Header ID (32B hex).
        /// Header-ID (32B hex)
        #[arg(long)]
        header_hex: String,
    },
    /// Signs a seat vote (epoch, shard, round, header_id) with slashing enforcement (Schnorr).
    /// Signiert einen Seat-Vote (epoch, shard, round, header_id) mit Slashing-Enforcement (Schnorr)
    SeatVoteSign {
        /// Directory of the slashing DB.
        /// Verzeichnis der Slashing-DB
        #[arg(long)]
        db_dir: PathBuf,
        /// Epoch.
        /// Epoche
        #[arg(long)]
        epoch: u64,
        /// Shard ID.
        /// Shard-ID
        #[arg(long)]
        shard: u16,
        /// Round (logical consensus round).
        /// Runde (logische Konsensrunde)
        #[arg(long)]
        round: u64,
        /// Header ID (32B hex).
        /// Header-ID (32B hex)
        #[arg(long)]
        header_hex: String,
        /// Keystore (seat key, Schnorr).
        /// Keystore (Seat-Key, Schnorr)
        #[arg(long)]
        keystore: PathBuf,
        /// Optional: write the signature to a file; otherwise stdout.
        /// Optional: Ausgabe der Signatur in Datei; sonst stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional: read passphrase from an environment variable (name of the variable).
        /// Optional: Passphrase aus ENV-Variable lesen (Name der Variable)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file.
        /// Optional: Passphrase aus Datei lesen
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Optional: derive keystore passphrase from a master passphrase for a role (validator/miner).
        /// Optional: Keystore-Passphrase aus Master-Passphrase für eine Rolle ableiten (validator/miner)
        #[arg(long, value_enum)]
        passphrase_role: Option<PassphraseRole>,
    },
    /// Verifies a seat vote (Schnorr) against an xonly public key.
    /// Verifiziert einen Seat-Vote (Schnorr) gegen xonly-Public-Key
    SeatVoteVerify {
        /// Epoch.
        /// Epoche
        #[arg(long)]
        epoch: u64,
        /// Shard ID.
        /// Shard-ID
        #[arg(long)]
        shard: u16,
        /// Round (logical consensus round).
        /// Runde (logische Konsensrunde)
        #[arg(long)]
        round: u64,
        /// Header ID (32B hex).
        /// Header-ID (32B hex)
        #[arg(long)]
        header_hex: String,
        /// Public key xonly (32B hex).
        /// Public Key xonly (32B hex)
        #[arg(long)]
        pub_hex: String,
        /// Signature (64B hex).
        /// Signatur (64B hex)
        #[arg(long)]
        sig_hex: String,
    },
    /// Initiates a PayJoin request (sender side).
    /// Initiiert PayJoin-Request (Sender-Seite)
    PayjoinInitiate {
        /// Original PSBT (TOML).
        /// Original PSBT (TOML)
        #[arg(long)]
        psbt: PathBuf,
        /// Optional: PayJoin endpoint (https://...).
        /// Optional: PayJoin-Endpoint (https://...)
        #[arg(long)]
        endpoint: Option<String>,
        /// Output file (TOML).
        /// Output-Datei (TOML)
        #[arg(long)]
        out: PathBuf,
    },
    /// Responder adds inputs (receiver side).
    /// Responder fügt Inputs hinzu (Empfänger-Seite)
    PayjoinRespond {
        /// PayJoin request (TOML).
        /// PayJoin-Request (TOML)
        #[arg(long)]
        request: PathBuf,
        /// Additional inputs file (pc-codec encoded TxIn list).
        /// Additional-Inputs Datei (pc-codec-kodierte TxIn-Liste)
        #[arg(long)]
        add_inputs: PathBuf,
        /// Derivation paths for the additional responder inputs, comma-separated.
        /// Ableitungspfade für die zusätzlichen Responder-Inputs, komma-separiert.
        #[arg(long, value_delimiter = ',')]
        add_paths: Vec<String>,
        /// Output file (TOML).
        /// Output-Datei (TOML)
        #[arg(long)]
        out: PathBuf,
    },
    /// Validates a PayJoin response (sender side).
    /// Validiert PayJoin-Response (Sender-Seite)
    PayjoinFinalize {
        /// Original PSBT (TOML).
        /// Original PSBT (TOML)
        #[arg(long)]
        original: PathBuf,
        /// PayJoin response (TOML).
        /// PayJoin-Response (TOML)
        #[arg(long)]
        response: PathBuf,
        /// Output: finalized transaction (binary).
        /// Output: finalisierte TX (binär)
        #[arg(long)]
        out: PathBuf,
    },
    /// Parses a pc: URI with a PayJoin endpoint.
    /// Parst pc: URI mit PayJoin-Endpoint
    PayjoinParseUri {
        /// pc: URI
        #[arg(long)]
        uri: String,
    },
    /// Signs a message with PKCS#11 HSM.
    /// Signiert eine Nachricht mit PKCS#11 HSM
    SignPkcs11 {
        /// PKCS#11 module path (z.B. /usr/lib/libykcs11.so)
        #[arg(long)]
        module: PathBuf,
        /// PIN from environment variable (name of the variable)
        #[arg(long)]
        pin_env: String,
        /// Key ID (hex)
        #[arg(long)]
        key_id: String,
        /// Message file to sign
        #[arg(long)]
        msg: PathBuf,
        /// Output signature file
        #[arg(long)]
        out: PathBuf,
        /// Mechanism (ECDSA, ECDSA_SHA256)
        #[arg(long, default_value = "ECDSA")]
        mechanism: String,
    },
    /// Signs a seat vote with PKCS#11 HSM (with slashing enforcement).
    /// Signiert einen Seat-Vote mit PKCS#11 HSM (mit Slashing-Enforcement)
    SeatVoteSignPkcs11 {
        /// PKCS#11 module path
        #[arg(long)]
        module: PathBuf,
        /// PIN from environment variable
        #[arg(long)]
        pin_env: String,
        /// Key ID (hex)
        #[arg(long)]
        key_id: String,
        /// Verzeichnis der Slashing-DB
        #[arg(long)]
        db_dir: PathBuf,
        /// Epoche
        #[arg(long)]
        epoch: u64,
        /// Shard-ID
        #[arg(long)]
        shard: u16,
        /// Runde (logische Konsensrunde)
        #[arg(long)]
        round: u64,
        /// Header-ID (32B hex)
        #[arg(long)]
        header_hex: String,
        /// Optional: Ausgabe der Signatur in Datei; sonst stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    WalletBuildTx {
        #[arg(long, value_delimiter = ',')]
        inputs: Vec<String>,
        #[arg(long)]
        to_addr: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0u64)]
        fee: u64,
        #[arg(long)]
        change_addr: Option<String>,
        #[arg(long)]
        out_psbt: PathBuf,
        #[arg(long)]
        out_tx_bin: Option<PathBuf>,
    },
    WalletListUtxos {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "https://127.0.0.1:8080")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    WalletBalance {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "https://127.0.0.1:8080")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        include_staked: bool,
    },
    WalletHistory {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "https://127.0.0.1:8080")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    WalletSend {
        #[arg(long)]
        from_addr: String,
        #[arg(long)]
        to_addr: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0u64)]
        fee: u64,
        #[arg(long)]
        change_addr: Option<String>,
        /// Schnorr keystore file (encrypted). Alternative: use --seed-store + --wallet-db.
        /// Schnorr-Keystore-Datei (verschlüsselt). Alternative: --seed-store + --wallet-db.
        #[arg(long)]
        keystore: Option<PathBuf>,
        /// Encrypted BIP39 seed store (created by wallet-init/wallet-restore).
        /// Verschlüsselter BIP39 Seed-Store (erstellt von wallet-init/wallet-restore).
        #[arg(long)]
        seed_store: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
        #[arg(long)]
        wallet_db: Option<PathBuf>,
    },
    /// Bonds (locks) stake on-chain by creating a stake-bond MicroTx (version=2) and broadcasting it.
    /// Bondet (lockt) Stake on-chain, indem eine stake-bond MicroTx (Version=2) gebaut und gebroadcastet wird.
    StakeBond {
        /// Wallet address (stake lock); must be present in --wallet-db when using --seed-store.
        /// Wallet-Adresse (Stake-Lock); muss in --wallet-db existieren, wenn --seed-store genutzt wird.
        #[arg(long)]
        addr: String,
        /// UTXOs to bond (txid:vout), comma-separated.
        /// UTXOs zum Bonden (txid:vout), komma-separiert.
        #[arg(long, value_delimiter = ',')]
        utxos: Vec<String>,
        /// Schnorr keystore file (encrypted). Alternative: use --seed-store + --wallet-db.
        /// Schnorr-Keystore-Datei (verschlüsselt). Alternative: --seed-store + --wallet-db.
        #[arg(long)]
        keystore: Option<PathBuf>,
        /// Encrypted BIP39 seed store (created by wallet-init/wallet-restore).
        /// Verschlüsselter BIP39 Seed-Store (erstellt von wallet-init/wallet-restore).
        #[arg(long)]
        seed_store: Option<PathBuf>,
        /// Wallet DB directory (required when using --seed-store).
        /// Wallet-DB Verzeichnis (erforderlich bei --seed-store).
        #[arg(long)]
        wallet_db: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    /// Unbonds (unlocks) stake on-chain by creating a stake-unbond MicroTx (version=3) and broadcasting it.
    /// Unbondet (unlockt) Stake on-chain, indem eine stake-unbond MicroTx (Version=3) gebaut und gebroadcastet wird.
    StakeUnbond {
        /// Wallet address (stake lock); must be present in --wallet-db when using --seed-store.
        /// Wallet-Adresse (Stake-Lock); muss in --wallet-db existieren, wenn --seed-store genutzt wird.
        #[arg(long)]
        addr: String,
        /// Staked UTXOs to unbond (txid:vout), comma-separated.
        /// Gestakte UTXOs zum Unbonden (txid:vout), komma-separiert.
        #[arg(long, value_delimiter = ',')]
        utxos: Vec<String>,
        /// Schnorr keystore file (encrypted). Alternative: use --seed-store + --wallet-db.
        /// Schnorr-Keystore-Datei (verschlüsselt). Alternative: --seed-store + --wallet-db.
        #[arg(long)]
        keystore: Option<PathBuf>,
        /// Encrypted BIP39 seed store (created by wallet-init/wallet-restore).
        /// Verschlüsselter BIP39 Seed-Store (erstellt von wallet-init/wallet-restore).
        #[arg(long)]
        seed_store: Option<PathBuf>,
        /// Wallet DB directory (required when using --seed-store).
        /// Wallet-DB Verzeichnis (erforderlich bei --seed-store).
        #[arg(long)]
        wallet_db: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    /// Registers/updates validator metadata on-chain (validator registry) via MicroTx (version=4).
    /// Registriert/aktualisiert Validator-Metadaten on-chain (Validator-Registry) via MicroTx (Version=4).
    ValidatorRegister {
        /// Wallet address (stake lock); must be present in --wallet-db when using --seed-store.
        /// Wallet-Adresse (Stake-Lock); muss in --wallet-db existieren, wenn --seed-store genutzt wird.
        #[arg(long)]
        addr: String,
        /// Anchor staked UTXO (txid:vout).
        /// Anker-UTXO (gestakt) (txid:vout).
        #[arg(long)]
        anchor_utxo: String,
        /// BLS public key (48 bytes hex, 96 hex chars).
        /// BLS Public Key (48 Bytes Hex, 96 Hex-Zeichen).
        #[arg(long)]
        bls_pk: String,
        /// BLS proof-of-possession (96 bytes hex, 192 hex chars).
        /// BLS Proof-of-Possession (96 Bytes Hex, 192 Hex-Zeichen).
        #[arg(long)]
        bls_pop: String,
        /// Optional operator id (32 bytes hex). Default: validator_id derived from BLS pk.
        /// Optionale Operator-ID (32 Bytes Hex). Default: validator_id aus BLS pk abgeleitet.
        #[arg(long)]
        operator_id: Option<String>,
        /// Optional sequence (must be monotonic increasing). If omitted, fetched from node and incremented.
        /// Optional sequence (muss monoton steigen). Falls nicht gesetzt, vom Node geholt und inkrementiert.
        #[arg(long)]
        sequence: Option<u64>,
        /// Schnorr keystore file (encrypted). Alternative: use --seed-store + --wallet-db.
        /// Schnorr-Keystore-Datei (verschlüsselt). Alternative: --seed-store + --wallet-db.
        #[arg(long)]
        keystore: Option<PathBuf>,
        /// Encrypted BIP39 seed store (created by wallet-init/wallet-restore).
        /// Verschlüsselter BIP39 Seed-Store (erstellt von wallet-init/wallet-restore).
        #[arg(long)]
        seed_store: Option<PathBuf>,
        /// Wallet DB directory (required when using --seed-store).
        /// Wallet-DB Verzeichnis (erforderlich bei --seed-store).
        #[arg(long)]
        wallet_db: Option<PathBuf>,
        #[arg(long)]
        passphrase_env: Option<String>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        node: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    TxInfo {
        #[arg(long, default_value = "https://127.0.0.1:8080")]
        node: String,
        #[arg(long)]
        txid: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    BlockInfo {
        #[arg(long, default_value = "https://127.0.0.1:8080")]
        node: String,
        #[arg(long)]
        anchor: String,
        #[arg(long)]
        auth_token: Option<String>,
        /// Read bearer token from a file (trimmed). Overrides --auth-token if set.
        /// Bearer-Token aus Datei lesen (getrimmt). Hat Vorrang vor --auth-token.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        tls_client_pem: Option<PathBuf>,
    },
    /// Initializes a new wallet from a freshly generated BIP39 seed (24 words).
    /// Creates XpubStore and WalletDb at default locations, derives first address.
    /// Initialisiert ein neues Wallet aus frisch generiertem BIP39-Seed (24 Wörter).
    /// Erstellt XpubStore und WalletDb an Standardpfaden, leitet erste Adresse ab.
    WalletInit {
        /// HRP (Bech32m) for addresses, default: "pc".
        /// HRP (Bech32m) für Adressen, Default: "pc"
        #[arg(long, default_value = "pc")]
        hrp: String,
        /// Optional: custom wallet name (default: "default").
        /// Optional: benutzerdefinierter Wallet-Name (Default: "default")
        #[arg(long, default_value = "default")]
        wallet_name: String,
        /// Force overwrite existing wallet.
        /// Überschreiben existierender Wallet erzwingen
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Restores a wallet from an existing BIP39 seed (24 words).
    /// Creates XpubStore and WalletDb at default locations, derives first address.
    /// Stellt ein Wallet aus existierendem BIP39-Seed (24 Wörter) wieder her.
    /// Erstellt XpubStore und WalletDb an Standardpfaden, leitet erste Adresse ab.
    WalletRestore {
        /// HRP (Bech32m) for addresses, default: "pc".
        /// HRP (Bech32m) für Adressen, Default: "pc"
        #[arg(long, default_value = "pc")]
        hrp: String,
        /// Optional: custom wallet name (default: "default").
        /// Optional: benutzerdefinierter Wallet-Name (Default: "default")
        #[arg(long, default_value = "default")]
        wallet_name: String,
        /// Force overwrite existing wallet.
        /// Überschreiben existierender Wallet erzwingen
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Optional: read BIP39 seed words from an environment variable (non-interactive).
        /// Optional: BIP39-Seedwörter aus Umgebungsvariable lesen (nicht-interaktiv)
        #[arg(long)]
        mnemonic_env: Option<String>,
        /// Optional: read passphrase from an environment variable (non-interactive).
        /// Optional: Passphrase aus Umgebungsvariable lesen (nicht-interaktiv)
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Optional: read passphrase from a file (non-interactive).
        /// Optional: Passphrase aus Datei lesen (nicht-interaktiv)
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    let cfg = if let Some(ref p) = cli.config {
        Some(load_signer_config(p)?)
    } else {
        None
    };

    // Parse language from CLI argument
    let lang = match cli.lang.to_lowercase().as_str() {
        "en" | "english" => Lang::En,
        "de" | "deutsch" | "german" => Lang::De,
        "es" | "español" | "spanish" => Lang::Es,
        "fr" | "français" | "french" => Lang::Fr,
        "it" | "italiano" | "italian" => Lang::It,
        "pt" | "português" | "portuguese" => Lang::Pt,
        "nl" | "nederlands" | "dutch" => Lang::Nl,
        "ru" | "русский" | "russian" => Lang::Ru,
        "zh" | "chinese" | "中文" => Lang::Zh,
        "ja" | "japanese" | "日本語" => Lang::Ja,
        "ko" | "korean" | "한국어" => Lang::Ko,
        "tr" | "türkçe" | "turkish" => Lang::Tr,
        "ar" | "arabic" | "العربية" => Lang::Ar,
        "pl" | "polski" | "polish" => Lang::Pl,
        _ => Lang::De, // Default: Deutsch
    };
    let t = cli_texts(lang);

    match cli.command {
        Commands::Keygen {
            r#type,
            algo,
            out,
            force,
            passphrase_env,
            passphrase_file,
            passphrase_role,
        } => {
            ks_path_check(&out, force)?;
            let pass = get_passphrase_with_role(
                &passphrase_env,
                &passphrase_file,
                &passphrase_role,
                "Passphrase: ",
                true,
            )?;
            let mut pass_owned = pass;

            let kdf_params = default_kdf_params();
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let key = derive_key(&pass_owned, &salt, &kdf_params)?;
            pass_owned.zeroize();

            // Secret generieren
            let (pub_hex, secret_bytes): (String, Vec<u8>) = match algo {
                Algo::Schnorr => {
                    let mut sk = [0u8; 32];
                    OsRng.fill_bytes(&mut sk);
                    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sk)
                        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
                    let pub_hex = hex::encode(kp.public_xonly_bytes());
                    (pub_hex, sk.to_vec())
                }
                Algo::Bls => {
                    let mut ikm = [0u8; 32];
                    OsRng.fill_bytes(&mut ikm);
                    let kp = bls::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen"))?;
                    let pub_hex = hex::encode(kp.pk.to_bytes());
                    (pub_hex, ikm.to_vec())
                }
            };

            let (ct, nonce) = encrypt_secret(&key, &secret_bytes)?;

            let ks = Keystore {
                version: 1,
                key_type: (match r#type {
                    KeyType::Seat => "seat",
                    KeyType::Bond => "bond",
                    KeyType::Payout => "payout",
                })
                .to_string(),
                algo: (match algo {
                    Algo::Schnorr => "schnorr",
                    Algo::Bls => "bls",
                })
                .to_string(),
                kdf: KdfSection {
                    name: "argon2id".to_string(),
                    salt_b64: general_purpose::STANDARD.encode(salt),
                    params: kdf_params,
                },
                enc: EncSection {
                    cipher: "xchacha20poly1305".to_string(),
                    nonce_b64: general_purpose::STANDARD.encode(nonce),
                    ct_b64: general_purpose::STANDARD.encode(&ct),
                },
                pub_hex,
            };
            save_keystore(&ks, &out)?;
            info!(path = %out.display(), "keystore erstellt");
        }
        Commands::Import {
            r#type,
            algo,
            secret_hex,
            secret_file,
            secret_env,
            out,
            force,
            passphrase_env,
            passphrase_file,
            passphrase_role,
        } => {
            ks_path_check(&out, force)?;
            let pass = get_passphrase_with_role(
                &passphrase_env,
                &passphrase_file,
                &passphrase_role,
                "Passphrase: ",
                true,
            )?;
            let mut pass_owned = pass;
            let kdf_params = default_kdf_params();
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let key = derive_key(&pass_owned, &salt, &kdf_params)?;
            pass_owned.zeroize();

            let mut secret_hex_resolved =
                resolve_import_secret_hex(secret_hex, secret_file, secret_env)?;
            let mut secret_bytes = hex::decode(&secret_hex_resolved).context("secret decode")?;
            secret_hex_resolved.zeroize();
            if secret_bytes.len() != 32 {
                return Err(anyhow!("secret muss 32 bytes sein"));
            }
            let mut sec32 = [0u8; 32];
            sec32.copy_from_slice(&secret_bytes);
            secret_bytes.zeroize();

            let pub_hex = match algo {
                Algo::Schnorr => {
                    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
                    hex::encode(kp.public_xonly_bytes())
                }
                Algo::Bls => {
                    let kp =
                        bls::bls_keygen_from_ikm(&sec32).ok_or_else(|| anyhow!("bls keygen"))?;
                    hex::encode(kp.pk.to_bytes())
                }
            };

            let (ct, nonce) = encrypt_secret(&key, &sec32)?;
            sec32.zeroize();

            let ks = Keystore {
                version: 1,
                key_type: (match r#type {
                    KeyType::Seat => "seat",
                    KeyType::Bond => "bond",
                    KeyType::Payout => "payout",
                })
                .to_string(),
                algo: (match algo {
                    Algo::Schnorr => "schnorr",
                    Algo::Bls => "bls",
                })
                .to_string(),
                kdf: KdfSection {
                    name: "argon2id".to_string(),
                    salt_b64: general_purpose::STANDARD.encode(salt),
                    params: kdf_params,
                },
                enc: EncSection {
                    cipher: "xchacha20poly1305".to_string(),
                    nonce_b64: general_purpose::STANDARD.encode(nonce),
                    ct_b64: general_purpose::STANDARD.encode(&ct),
                },
                pub_hex,
            };
            save_keystore(&ks, &out)?;
            info!(path = %out.display(), "keystore importiert");
        }
        Commands::ExportPub { keystore } => {
            let ks = load_keystore(&keystore)?;
            println!("{}", ks.pub_hex);
        }
        Commands::BlsPop {
            keystore,
            out,
            passphrase_env,
            passphrase_file,
            passphrase_role,
        } => {
            let ks = load_keystore(&keystore)?;
            if ks.algo.as_str() != "bls" {
                return Err(anyhow!("keystore algo muss bls sein"));
            }
            let pass = get_passphrase_with_role(
                &passphrase_env,
                &passphrase_file,
                &passphrase_role,
                "Passphrase: ",
                false,
            )?;
            let mut pass_owned = pass;
            let salt = general_purpose::STANDARD.decode(&ks.kdf.salt_b64)?;
            let mut salt16 = [0u8; 16];
            salt16.copy_from_slice(&salt);
            let key = derive_key(&pass_owned, &salt16, &ks.kdf.params)?;
            pass_owned.zeroize();

            let nonce = general_purpose::STANDARD.decode(&ks.enc.nonce_b64)?;
            let ct = general_purpose::STANDARD.decode(&ks.enc.ct_b64)?;
            let mut nonce24 = [0u8; 24];
            nonce24.copy_from_slice(&nonce);
            let mut secret = decrypt_secret(&key, &nonce24, &ct)?;
            if secret.len() != 32 {
                return Err(anyhow!("invalid secret length"));
            }
            let mut ikm = [0u8; 32];
            ikm.copy_from_slice(&secret);
            secret.zeroize();

            let kp = bls::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen"))?;
            let pop = bls::bls_pop_prove(&kp.sk);
            ikm.zeroize();

            let pop_hex = hex::encode(pop);
            match out {
                Some(p) => fs::write(p, &pop_hex)?,
                None => println!("{}", pop_hex),
            }
        }
        Commands::Sign {
            keystore,
            msg,
            out,
            passphrase_env,
            passphrase_file,
            passphrase_role,
        } => {
            let ks = load_keystore(&keystore)?;
            let pass = get_passphrase_with_role(
                &passphrase_env,
                &passphrase_file,
                &passphrase_role,
                "Passphrase: ",
                false,
            )?;
            let mut pass_owned = pass;
            let salt = general_purpose::STANDARD.decode(&ks.kdf.salt_b64)?;
            let mut salt16 = [0u8; 16];
            salt16.copy_from_slice(&salt);
            let key = derive_key(&pass_owned, &salt16, &ks.kdf.params)?;
            pass_owned.zeroize();

            let nonce = general_purpose::STANDARD.decode(&ks.enc.nonce_b64)?;
            let ct = general_purpose::STANDARD.decode(&ks.enc.ct_b64)?;
            let mut nonce24 = [0u8; 24];
            nonce24.copy_from_slice(&nonce);
            let secret = decrypt_secret(&key, &nonce24, &ct)?;
            if secret.len() != 32 {
                return Err(anyhow!("invalid secret length"));
            }
            let mut sec32 = [0u8; 32];
            sec32.copy_from_slice(&secret);

            let msg_bytes = fs::read(&msg)?;

            let sig_hex = match ks.algo.as_str() {
                "schnorr" => {
                    let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                        .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
                    let digest: Hash32 = blake3_32(&msg_bytes);
                    let sig = schnorr::schnorr_sign(&digest, &kp);
                    hex::encode(sig)
                }
                "bls" => {
                    let kp =
                        bls::bls_keygen_from_ikm(&sec32).ok_or_else(|| anyhow!("bls keygen"))?;
                    let sig = bls::bls_sign(&msg_bytes, &kp.sk);
                    hex::encode(sig)
                }
                _ => return Err(anyhow!("unbekanntes algo")),
            };

            match out {
                Some(p) => fs::write(p, &sig_hex)?,
                None => println!("{}", sig_hex),
            }
        }
        Commands::TxNewEmpty { out } => {
            let tx = MicroTx {
                version: 1,
                inputs: vec![],
                outputs: vec![],
            };
            let enc = psbt::encode_tx(&tx)?;
            fs::write(&out, &enc)?;
            info!(path=%out.display(), "empty tx geschrieben");
        }
        Commands::TxBroadcast {
            node,
            tx,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;
            let bin = fs::read(&tx).with_context(|| format!("read {}", tx.display()))?;
            // Roundtrip validation.
            // Roundtrip-Validierung
            let _tx = psbt::decode_tx(&bin)?;
            let url = format!("{}/tx/broadcast", rc.node_url.trim_end_matches('/'));
            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::POST,
                &url,
                rc.auth_token.as_deref(),
                Some("application/octet-stream"),
                Some(bin),
            )?;
            if !status.is_success() {
                return Err(anyhow!("broadcast failed: {} {}", status, text));
            }
            println!("{}", text);
        }
        Commands::Verify {
            algo,
            pub_hex,
            msg,
            sig_hex,
        } => {
            let msg_bytes = fs::read(&msg)?;
            match algo {
                Algo::Schnorr => {
                    let mut pub_bytes = [0u8; 32];
                    let v = hex::decode(pub_hex)?;
                    if v.len() != 32 {
                        return Err(anyhow!("schnorr pubkey xonly muss 32 bytes sein"));
                    }
                    pub_bytes.copy_from_slice(&v);
                    let xpk = secp256k1::XOnlyPublicKey::from_slice(&pub_bytes)
                        .map_err(|_| anyhow!("ungültiger schnorr pubkey"))?;
                    let digest: Hash32 = blake3_32(&msg_bytes);
                    let sig_vec = hex::decode(sig_hex)?;
                    if sig_vec.len() != 64 {
                        return Err(anyhow!("schnorr signature muss 64 bytes sein"));
                    }
                    let mut sig64 = [0u8; 64];
                    sig64.copy_from_slice(&sig_vec);
                    let ok = schnorr::schnorr_verify(&digest, &sig64, &xpk);
                    if ok {
                        println!("OK");
                    } else {
                        println!("FAIL");
                    }
                }
                Algo::Bls => {
                    let v = hex::decode(pub_hex)?;
                    if v.len() != 48 {
                        return Err(anyhow!("bls public key muss 48 bytes sein"));
                    }
                    let mut pkb = [0u8; 48];
                    pkb.copy_from_slice(&v);
                    let pk: BlsPublicKey = pc_crypto::bls_pk_from_bytes(&pkb)
                        .ok_or_else(|| anyhow!("ungültiger bls pubkey"))?;
                    let sig_vec = hex::decode(sig_hex)?;
                    if sig_vec.len() != 96 {
                        return Err(anyhow!("bls signature muss 96 bytes sein"));
                    }
                    let mut sig96 = [0u8; 96];
                    sig96.copy_from_slice(&sig_vec);
                    let ok = bls::bls_verify(&msg_bytes, &sig96, &pk);
                    if ok {
                        println!("OK");
                    } else {
                        println!("FAIL");
                    }
                }
            }
        }
        Commands::HwiEnumerate => {
            let (paired, transport) = bitbox_connect_paired()?;
            let fingerprint = block_on(paired.root_fingerprint())
                .map_err(|e| anyhow!("bitbox root_fingerprint: {e:?}"))?;

            let transport_str = match transport {
                BitboxTransport::Usb => "usb",
                BitboxTransport::Bridge => "bridge",
            };
            let value = serde_json::json!([
                {
                    "type": "bitbox02",
                    "model": "BitBox02",
                    "fingerprint": fingerprint,
                    "transport": transport_str,
                }
            ]);

            println!("{}", serde_json::to_string(&value)?);
        }
        Commands::HwiGetXpub {
            fingerprint: _,
            derivation,
        } => {
            let (paired, _) = bitbox_connect_paired()?;

            let keypath = Keypath::try_from(derivation.as_str())
                .map_err(|e| anyhow!("ungültige derivation '{}': {e}", derivation))?;

            let xpub = block_on(paired.btc_xpub(
                bitbox_api::pb::BtcCoin::Btc,
                &keypath,
                bitbox_api::pb::btc_pub_request::XPubType::Xpub,
                false,
            ))
            .map_err(|e| anyhow!("bitbox btc_xpub: {e:?}"))?;

            let value = serde_json::json!({ "xpub": xpub });
            println!("{}", serde_json::to_string(&value)?);
        }
        Commands::HwiSignMessage {
            fingerprint,
            derivation,
            msg,
        } => {
            let m = fs::read_to_string(&msg).context("read msg file as UTF-8")?;
            if m.trim_start().starts_with('-') {
                return Err(anyhow!(
                    "hwi message darf nicht mit '-' beginnen (Argument-Injection-Schutz)"
                ));
            }
            if m.chars()
                .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
            {
                return Err(anyhow!(
                    "hwi message enthält unzulässige Steuerzeichen (Argument-Injection-Schutz)"
                ));
            }
            let hwi = resolve_hwi_binary()?;
            let mut cmd = Command::new(&hwi);
            cmd.args([
                "-f",
                "json",
                "signmessage",
                "--path",
                &derivation,
                "--message",
                &m,
            ]);
            if let Some(fp) = fingerprint.as_ref() {
                cmd.args(["--fingerprint", fp]);
            }
            let out = cmd.output().map_err(|e| anyhow!("hwi signmessage: {e}"))?;
            if !out.status.success() {
                return Err(anyhow!(
                    "hwi signmessage failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        Commands::ImportXpub {
            algo,
            xpub,
            derivation,
            fingerprint,
            out,
            force,
            hrp,
            passphrase_env,
            passphrase_file,
        } => {
            if !matches!(algo, Algo::Schnorr) {
                return Err(anyhow!(
                    "ImportXpub unterstützt aktuell nur Schnorr/secp256k1 xonly"
                ));
            }
            let dp = DerivationPath::from_str(&derivation)
                .map_err(|e| anyhow!("ungültige derivation: {e}"))?;
            let _xpub_parsed: ExtendedPublicKey<B32SecpPk> =
                ExtendedPublicKey::from_str(&xpub).map_err(|e| anyhow!("ungültiges xpub: {e}"))?;
            // Note: we store the imported xpub as well as the root derivation.
            // Hinweis: Wir speichern den importierten Xpub sowie die Root-Derivation.
            let xs = XpubStore {
                version: 1,
                kind: "xpub".to_string(),
                algo: "schnorr".to_string(),
                // Preserve original input value (including prefix).
                // originaler eingabewert beibehalten (inkl. Prefix)
                xpub,
                derivation: dp.to_string(),
                fingerprint,
                hrp,
            };
            let out_path = if let Some(p) = out {
                p
            } else {
                default_xpubstore_path(&xs.fingerprint, &xs.hrp)?
            };
            if passphrase_env.is_some() || passphrase_file.is_some() {
                let pass =
                    get_passphrase(&passphrase_env, &passphrase_file, "XpubStore Passphrase: ")?;
                save_xpub_store_with_passphrase(&xs, &out_path, &pass, force)?;
            } else {
                save_xpub_store(&xs, &out_path, force)?;
            }
            info!(path = %out_path.display(), "xpubstore erstellt");
        }
        Commands::AddrFromXpub {
            xpubstore,
            change,
            index,
            wallet_db,
            label,
            passphrase_env,
            passphrase_file,
        } => {
            let passphrase = if passphrase_env.is_some() || passphrase_file.is_some() {
                Some(get_passphrase(
                    &passphrase_env,
                    &passphrase_file,
                    "Passphrase: ",
                )?)
            } else {
                None
            };
            let xs = if let Some(pass) = passphrase.as_deref() {
                load_xpub_store_with_passphrase(&xpubstore, pass)?
            } else {
                load_xpub_store(&xpubstore)?
            };
            if xs.algo.as_str() != "schnorr" {
                return Err(anyhow!("xpubstore algo nicht unterstützt: {}", xs.algo));
            }
            let xpub: ExtendedPublicKey<B32SecpPk> =
                ExtendedPublicKey::from_str(&xs.xpub).map_err(|e| anyhow!("xpub parse: {e}"))?;
            let xonly = derive_child_xonly(&xpub, change, index)?;
            let addr = bech32m_address_from_xonly(&xs.hrp, &xonly)?;
            println!("{}", addr);
            if let Some(ref db_dir) = wallet_db {
                walletdb::WalletDb::init(db_dir)?;
                let pass = if let Some(pass) = passphrase.as_deref() {
                    pass.to_string()
                } else {
                    read_password_from_tty("Wallet-DB Passphrase: ")?
                };
                let wdb = walletdb::WalletDb::open_locked(db_dir, &pass)?;
                let meta = walletdb::WalletAddrMeta {
                    version: 1,
                    addr: addr.clone(),
                    hrp: xs.hrp.clone(),
                    change,
                    index,
                    xpub_derivation: xs.derivation.clone(),
                    fingerprint: xs.fingerprint.clone(),
                    xpubstore_path: xpubstore.to_string_lossy().to_string(),
                    label: label.clone(),
                };
                wdb.put_address(&meta)?;
            }
        }
        Commands::WalletListAddrs { wallet_db } => {
            let pass = read_password_from_tty("Wallet-DB Passphrase: ")?;
            let wdb = walletdb::WalletDb::open_locked(&wallet_db, &pass)?;
            let list = wdb.all_addresses()?;
            let json = serde_json::to_string_pretty(&list)?;
            println!("{}", json);
        }
        Commands::WalletShowAddr { wallet_db, addr } => {
            let pass = read_password_from_tty("Wallet-DB Passphrase: ")?;
            let wdb = walletdb::WalletDb::open_locked(&wallet_db, &pass)?;
            match wdb.get_address(&addr)? {
                Some(meta) => {
                    let json = serde_json::to_string_pretty(&meta)?;
                    println!("{}", json);
                }
                None => {
                    return Err(anyhow!("adresse nicht im wallet-db vorhanden"));
                }
            }
        }
        Commands::PsbtCreate { tx_bin, paths, out } => {
            let raw =
                fs::read(&tx_bin).with_context(|| format!("read tx_bin {}", tx_bin.display()))?;
            let tx = psbt::decode_tx(&raw)?;
            if paths.len() != tx.inputs.len() {
                return Err(anyhow!(
                    "paths len ({}) != inputs len ({})",
                    paths.len(),
                    tx.inputs.len()
                ));
            }
            let ders: Vec<psbt::Derivation> = paths
                .into_iter()
                .map(|p| psbt::Derivation { path: p })
                .collect();
            psbt::to_toml_file(&tx, &ders, &out)?;
            info!(path=%out.display(), "psbt erstellt");
        }
        Commands::PsbtSighash {
            psbt: psbt_path,
            network_id,
        } => {
            let (tx, _ders) = psbt::from_toml_file(&psbt_path)?;
            let nid = resolve_network_id_from_cfg_or_arg(cfg.as_ref(), network_id)?;
            let h = psbt::sighash_of_tx(&nid, &tx);
            println!("{}", hex::encode(h));
        }
        Commands::SignTxWithKeystore {
            psbt: psbt_path,
            keystore,
            out,
            passphrase_env,
            passphrase_file,
            network_id,
        } => {
            let (tx, _ders) = psbt::from_toml_file(&psbt_path)?;
            let ks = load_keystore(&keystore)?;
            if ks.algo.as_str() != "schnorr" {
                return Err(anyhow!("nur schnorr unterstützt"));
            }
            let pass = get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?;
            let mut pass_owned = pass;
            let salt = general_purpose::STANDARD.decode(&ks.kdf.salt_b64)?;
            let mut salt16 = [0u8; 16];
            salt16.copy_from_slice(&salt);
            let key = derive_key(&pass_owned, &salt16, &ks.kdf.params)?;
            pass_owned.zeroize();
            let nonce = general_purpose::STANDARD.decode(&ks.enc.nonce_b64)?;
            let ct = general_purpose::STANDARD.decode(&ks.enc.ct_b64)?;
            let mut nonce24 = [0u8; 24];
            nonce24.copy_from_slice(&nonce);
            let secret = decrypt_secret(&key, &nonce24, &ct)?;
            if secret.len() != 32 {
                return Err(anyhow!("invalid secret length"));
            }
            let mut sec32 = [0u8; 32];
            sec32.copy_from_slice(&secret);
            let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
            let nid = resolve_network_id_from_cfg_or_arg(cfg.as_ref(), network_id)?;
            let digest = psbt::sighash_of_tx(&nid, &tx);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            let sig_hex = hex::encode(sig);
            match out {
                Some(p) => fs::write(p, &sig_hex)?,
                None => println!("{}", sig_hex),
            }
        }
        Commands::VerifyTxSig {
            psbt: psbt_path,
            algo,
            pub_hex,
            sig_hex,
            network_id,
        } => {
            let (tx, _ders) = psbt::from_toml_file(&psbt_path)?;
            let nid = resolve_network_id_from_cfg_or_arg(cfg.as_ref(), network_id)?;
            let digest = psbt::sighash_of_tx(&nid, &tx);
            match algo {
                Algo::Schnorr => {
                    let v = hex::decode(pub_hex)?;
                    if v.len() != 32 {
                        return Err(anyhow!("schnorr pubkey xonly muss 32 bytes sein"));
                    }
                    let mut pub_bytes = [0u8; 32];
                    pub_bytes.copy_from_slice(&v);
                    let xpk = secp256k1::XOnlyPublicKey::from_slice(&pub_bytes)
                        .map_err(|_| anyhow!("ungültiger schnorr pubkey"))?;
                    let sig_vec = hex::decode(sig_hex)?;
                    if sig_vec.len() != 64 {
                        return Err(anyhow!("schnorr signature muss 64 bytes sein"));
                    }
                    let mut sig64 = [0u8; 64];
                    sig64.copy_from_slice(&sig_vec);
                    let ok = schnorr::schnorr_verify(&digest, &sig64, &xpk);
                    if ok {
                        println!("OK");
                    } else {
                        println!("FAIL");
                    }
                }
                Algo::Bls => return Err(anyhow!("BLS für MicroTx nicht vorgesehen")),
            }
        }
        Commands::PsbtFinalize {
            psbt: psbt_path,
            pubkeys,
            sigs,
            out,
        } => {
            let (tx, _ders) = psbt::from_toml_file(&psbt_path)?;
            if pubkeys.len() != tx.inputs.len() {
                return Err(anyhow!(
                    "pubkeys len ({}) != inputs len ({})",
                    pubkeys.len(),
                    tx.inputs.len()
                ));
            }
            if sigs.len() != tx.inputs.len() {
                return Err(anyhow!(
                    "sigs len ({}) != inputs len ({})",
                    sigs.len(),
                    tx.inputs.len()
                ));
            }
            let mut witnesses: Vec<Vec<u8>> = Vec::with_capacity(tx.inputs.len());
            for (i, (pk_hex, sig_hex)) in pubkeys.iter().zip(sigs.iter()).enumerate() {
                let pkv = hex::decode(pk_hex)?;
                if pkv.len() != 32 {
                    return Err(anyhow!("xonly pubkey muss 32 bytes sein (input #{})", i));
                }
                let mut pk32 = [0u8; 32];
                pk32.copy_from_slice(&pkv);
                let sv = hex::decode(sig_hex)?;
                if sv.len() != 64 {
                    return Err(anyhow!(
                        "schnorr signature muss 64 bytes sein (input #{})",
                        i
                    ));
                }
                let mut s64 = [0u8; 64];
                s64.copy_from_slice(&sv);
                witnesses.push(psbt::build_witness(&pk32, &s64));
            }
            let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
            let bin = psbt::encode_tx(&final_tx)?;
            fs::write(&out, &bin)?;
            info!(path=%out.display(), "tx finalisiert geschrieben");
        }
        Commands::TxWriteBin {
            psbt,
            tx_bin_src,
            out,
        } => {
            if let Some(src) = tx_bin_src {
                let raw = fs::read(&src).with_context(|| format!("read {}", src.display()))?;
                // Validate roundtrip.
                // validieren: roundtrip
                let tx = psbt::decode_tx(&raw)?;
                let enc = psbt::encode_tx(&tx)?;
                fs::write(&out, &enc)?;
                info!(path=%out.display(), "tx bin geschrieben");
            } else if let Some(p) = psbt {
                let (tx, _ders) = psbt::from_toml_file(&p)?;
                let enc = psbt::encode_tx(&tx)?;
                fs::write(&out, &enc)?;
                info!(path=%out.display(), "tx aus psbt geschrieben");
            } else {
                return Err(anyhow!("entweder --psbt oder --tx-bin-src angeben"));
            }
        }
        Commands::HwiSignTx {
            psbt: psbt_path,
            fingerprint,
            external_cmd,
            out,
            network_id,
        } => {
            let (tx, ders) = psbt::from_toml_file(&psbt_path)?;
            let nid = resolve_network_id_from_cfg_or_arg(cfg.as_ref(), network_id)?;
            let digest = psbt::sighash_of_tx(&nid, &tx);
            let cmd_path = resolve_bitbox2_signer_binary(external_cmd)?;
            let mut witnesses: Vec<Vec<u8>> = Vec::with_capacity(tx.inputs.len());
            for (i, d) in ders.iter().enumerate() {
                let mut cmd = Command::new(&cmd_path);
                // Expected CLI of the external signer:
                //   <cmd> --digest <hex> --path <derivation> [--fingerprint <fp>]
                // Output (stdout, JSON): {"pub_xonly_hex":"..","sig_hex":".."}
                cmd.args(["--digest", &hex::encode(digest)])
                    .args(["--path", &d.path]);
                if let Some(fp) = fingerprint.as_ref() {
                    cmd.args(["--fingerprint", fp]);
                }
                let outp = cmd
                    .output()
                    .with_context(|| format!("external signer exec (input #{})", i))?;
                if !outp.status.success() {
                    return Err(anyhow!(
                        "external signer failed (input #{}): {}",
                        i,
                        String::from_utf8_lossy(&outp.stderr)
                    ));
                }
                let v: serde_json::Value = serde_json::from_slice(&outp.stdout)
                    .with_context(|| format!("parse signer json (input #{})", i))?;
                let pk_hex = v
                    .get("pub_xonly_hex")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow!("missing pub_xonly_hex"))?;
                let sig_hex = v
                    .get("sig_hex")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow!("missing sig_hex"))?;
                let pkb = hex::decode(pk_hex).context("pub_xonly_hex decode")?;
                if pkb.len() != 32 {
                    return Err(anyhow!("xonly pubkey muss 32 bytes sein (input #{})", i));
                }
                let mut pk32 = [0u8; 32];
                pk32.copy_from_slice(&pkb);
                let sv = hex::decode(sig_hex).context("sig_hex decode")?;
                if sv.len() != 64 {
                    return Err(anyhow!(
                        "schnorr signature muss 64 bytes sein (input #{})",
                        i
                    ));
                }
                let mut s64 = [0u8; 64];
                s64.copy_from_slice(&sv);
                // Optional: lokale Verifikation pro Input
                let xpk = secp256k1::XOnlyPublicKey::from_slice(&pk32)
                    .map_err(|_| anyhow!("ungültiger schnorr pubkey (input #{})", i))?;
                let ok = schnorr::schnorr_verify(&digest, &s64, &xpk);
                if !ok {
                    return Err(anyhow!("signaturprüfung fehlgeschlagen (input #{})", i));
                }
                witnesses.push(psbt::build_witness(&pk32, &s64));
            }
            if let Some(outp) = out {
                let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
                let enc = psbt::encode_tx(&final_tx)?;
                fs::write(&outp, &enc)?;
                info!(path=%outp.display(), "tx von HWI signiert & geschrieben");
            } else {
                // Return JSON with lists.
                // JSON mit Listen zurückgeben
                let arr: Vec<serde_json::Value> = witnesses
                    .into_iter()
                    .map(|w| {
                        let (pk, sig) = w.split_at(32);
                        serde_json::json!({
                            "pub_xonly_hex": hex::encode(pk),
                            "sig_hex": hex::encode(sig),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr)?);
            }
        }
        Commands::SlashDbInit { db_dir } => {
            slashdb::SlashDb::init(&db_dir)?;
            println!("OK");
        }
        Commands::SlashDbGet {
            db_dir,
            epoch,
            shard,
            round,
        } => {
            let sdb = slashdb::SlashDb::open_locked(&db_dir)?;
            match sdb.get_vote(epoch, shard, round)? {
                Some(h) => println!("{}", hex::encode(h)),
                None => println!(),
            }
        }
        Commands::SlashDbPut {
            db_dir,
            epoch,
            shard,
            round,
            header_hex,
        } => {
            let v = hex::decode(&header_hex).context("header_hex decode")?;
            if v.len() != 32 {
                return Err(anyhow!("header_hex muss 32 bytes sein"));
            }
            let mut hb = [0u8; 32];
            hb.copy_from_slice(&v);
            let sdb = slashdb::SlashDb::open_locked(&db_dir)?;
            sdb.put_vote_if_absent(epoch, shard, round, hb)?;
            println!("OK");
        }
        Commands::SeatVoteSign {
            db_dir,
            epoch,
            shard,
            round,
            header_hex,
            keystore,
            out,
            passphrase_env,
            passphrase_file,
            passphrase_role,
        } => {
            // Parse header_id.
            // header_id parsen
            let hv = hex::decode(&header_hex).context("header_hex decode")?;
            if hv.len() != 32 {
                return Err(anyhow!("header_hex muss 32 bytes sein"));
            }
            let mut header_id = [0u8; 32];
            header_id.copy_from_slice(&hv);

            // Slashing enforcement: allow idempotent calls, otherwise an equivocation error is raised.
            // Slashing-Enforcement: idempotent erlauben, sonst Equivocation-Fehler
            let sdb = slashdb::SlashDb::open_locked(&db_dir)?;
            if let Some(existing) = sdb.get_vote(epoch, shard, round)? {
                if existing != header_id {
                    return Err(anyhow!(
                        "Equivocation: existierender Vote differiert (epoch={}, shard={}, round={})",
                        epoch, shard, round
                    ));
                }
            }
            sdb.put_vote_if_absent(epoch, shard, round, header_id)?;

            // Load keystore and decrypt secret.
            // Keystore laden + Secret entschlüsseln
            let ks = load_keystore(&keystore)?;
            if ks.key_type.as_str() != "seat" {
                return Err(anyhow!("Keystore ist kein Seat-Key"));
            }
            if ks.algo.as_str() != "schnorr" {
                return Err(anyhow!("SeatVoteSign unterstützt aktuell nur Schnorr"));
            }
            let pass = get_passphrase_with_role(
                &passphrase_env,
                &passphrase_file,
                &passphrase_role,
                "Passphrase: ",
                false,
            )?;
            let mut pass_owned = pass;
            let salt = general_purpose::STANDARD.decode(&ks.kdf.salt_b64)?;
            let mut salt16 = [0u8; 16];
            salt16.copy_from_slice(&salt);
            let key = derive_key(&pass_owned, &salt16, &ks.kdf.params)?;
            pass_owned.zeroize();
            let nonce = general_purpose::STANDARD.decode(&ks.enc.nonce_b64)?;
            let ct = general_purpose::STANDARD.decode(&ks.enc.ct_b64)?;
            let mut nonce24 = [0u8; 24];
            nonce24.copy_from_slice(&nonce);
            let secret = decrypt_secret(&key, &nonce24, &ct)?;
            if secret.len() != 32 {
                return Err(anyhow!("invalid secret length"));
            }
            let mut sec32 = [0u8; 32];
            sec32.copy_from_slice(&secret);
            let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;

            // Canonical message: domain || epoch_le(8) || shard_le(2) || round_le(8) || header_id(32).
            // Kanonische Nachricht: domain || epoch_le(8) || shard_le(2) || round_le(8) || header_id(32)
            const DOMAIN: &[u8] = b"pc:vote:seat:v1\x01";
            let mut msg = Vec::with_capacity(DOMAIN.len() + 8 + 2 + 8 + 32);
            msg.extend_from_slice(DOMAIN);
            msg.extend_from_slice(&epoch.to_le_bytes());
            msg.extend_from_slice(&shard.to_le_bytes());
            msg.extend_from_slice(&round.to_le_bytes());
            msg.extend_from_slice(&header_id);
            let digest: Hash32 = blake3_32(&msg);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            let sig_hex = hex::encode(sig);

            match out {
                Some(p) => fs::write(p, &sig_hex)?,
                None => println!("{}", sig_hex),
            }
        }
        Commands::SeatVoteVerify {
            epoch,
            shard,
            round,
            header_hex,
            pub_hex,
            sig_hex,
        } => {
            let hv = hex::decode(&header_hex).context("header_hex decode")?;
            if hv.len() != 32 {
                return Err(anyhow!("header_hex muss 32 bytes sein"));
            }
            let mut header_id = [0u8; 32];
            header_id.copy_from_slice(&hv);

            let pv = hex::decode(&pub_hex)?;
            if pv.len() != 32 {
                return Err(anyhow!("schnorr pubkey xonly muss 32 bytes sein"));
            }
            let mut pk32 = [0u8; 32];
            pk32.copy_from_slice(&pv);
            let xpk = secp256k1::XOnlyPublicKey::from_slice(&pk32)
                .map_err(|_| anyhow!("ungültiger schnorr pubkey"))?;

            let sv = hex::decode(&sig_hex)?;
            if sv.len() != 64 {
                return Err(anyhow!("schnorr signature muss 64 bytes sein"));
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&sv);

            const DOMAIN: &[u8] = b"pc:vote:seat:v1\x01";
            let mut msg = Vec::with_capacity(DOMAIN.len() + 8 + 2 + 8 + 32);
            msg.extend_from_slice(DOMAIN);
            msg.extend_from_slice(&epoch.to_le_bytes());
            msg.extend_from_slice(&shard.to_le_bytes());
            msg.extend_from_slice(&round.to_le_bytes());
            msg.extend_from_slice(&header_id);
            let digest: Hash32 = blake3_32(&msg);

            let ok = schnorr::schnorr_verify(&digest, &sig64, &xpk);
            if ok {
                println!("OK");
            } else {
                println!("FAIL");
            }
        }
        Commands::PayjoinInitiate {
            psbt,
            endpoint,
            out,
        } => {
            use base64::{engine::general_purpose, Engine as _};
            let (original_tx, derivations) = psbt::from_toml_file(&psbt)?;
            let psbt_toml: psbt::PhantomPsbtToml = {
                let enc = psbt::encode_tx(&original_tx)?;
                psbt::PhantomPsbtToml {
                    version: 1,
                    algo: "schnorr".to_string(),
                    tx_b64: general_purpose::STANDARD.encode(enc),
                    derivations,
                }
            };

            let request = payjoin::initiate_payjoin(psbt_toml, endpoint)?;
            payjoin::save_payjoin_request(&request, &out, false)?;
            info!(path = %out.display(), "PayJoin-Request erstellt");
        }
        Commands::PayjoinRespond {
            request,
            add_inputs,
            add_paths,
            out,
        } => {
            // Load request
            let req = payjoin::load_payjoin_request(&request)?;

            // Load additional inputs from binary file (pc-codec encoded TxIns)
            use pc_codec::Decodable;
            let inputs_bytes = fs::read(&add_inputs)?;
            let mut cursor: &[u8] = &inputs_bytes;
            let mut additional_inputs = Vec::new();
            while !cursor.is_empty() {
                match pc_types::TxIn::decode(&mut cursor) {
                    Ok(inp) => additional_inputs.push(inp),
                    Err(_) => break,
                }
            }

            if additional_inputs.is_empty() {
                return Err(anyhow!("No inputs found in add_inputs file"));
            }

            if add_paths.is_empty() {
                return Err(anyhow!(
                    "missing --add-paths (derivation paths) for responder inputs"
                ));
            }
            if add_paths.len() != additional_inputs.len() {
                return Err(anyhow!(
                    "--add-paths length ({}) must match number of additional inputs ({})",
                    add_paths.len(),
                    additional_inputs.len()
                ));
            }
            let additional_derivations: Vec<psbt::Derivation> = add_paths
                .into_iter()
                .map(|path| psbt::Derivation { path })
                .collect();

            let response =
                payjoin::respond_payjoin(&req, additional_inputs, additional_derivations, None)?;
            payjoin::save_payjoin_response(&response, &out, false)?;
            info!(
                path = %out.display(),
                inputs_added = response.inputs_added,
                "PayJoin-Response erstellt"
            );
        }
        Commands::PayjoinFinalize {
            original,
            response,
            out,
        } => {
            use base64::{engine::general_purpose, Engine as _};
            let (orig_tx, orig_derivations) = psbt::from_toml_file(&original)?;
            let orig_psbt: psbt::PhantomPsbtToml = {
                let enc = psbt::encode_tx(&orig_tx)?;
                psbt::PhantomPsbtToml {
                    version: 1,
                    algo: "schnorr".to_string(),
                    tx_b64: general_purpose::STANDARD.encode(enc),
                    derivations: orig_derivations,
                }
            };

            let resp = payjoin::load_payjoin_response(&response)?;
            payjoin::validate_payjoin_response(&orig_psbt, &resp)?;

            // Extract final TX from response PSBT
            use pc_codec::Decodable;
            let resp_bytes =
                general_purpose::STANDARD.decode(resp.modified_psbt.tx_b64.as_bytes())?;
            let final_tx = pc_types::MicroTx::decode(&mut &resp_bytes[..])?;
            let enc = psbt::encode_tx(&final_tx)?;
            fs::write(&out, &enc)?;
            info!(path = %out.display(), "Finalisierte TX gespeichert");
        }
        Commands::PayjoinParseUri { uri } => {
            let (addr, amount, pj_endpoint) = payjoin::parse_pc_uri(&uri)?;
            println!("Address: {}", addr);
            if let Some(amt) = amount {
                println!("Amount: {} sats", amt);
            }
            if let Some(ep) = pj_endpoint {
                println!("PayJoin-Endpoint: {}", ep);
            }
        }
        Commands::SignPkcs11 {
            module,
            pin_env,
            key_id,
            msg,
            out,
            mechanism,
        } => {
            info!("Signing with PKCS#11 HSM");
            let signature =
                pkcs11_sign::sign_file_with_hsm(&module, &pin_env, &key_id, &msg, &mechanism)?;
            let sig_hex = hex::encode(&signature);
            fs::write(&out, sig_hex.as_bytes())?;
            info!(
                module = %module.display(),
                key_id = %key_id,
                out = %out.display(),
                "Signature created with HSM"
            );
            println!("{}", sig_hex);
        }
        Commands::SeatVoteSignPkcs11 {
            module,
            pin_env,
            key_id,
            db_dir,
            epoch,
            shard,
            round,
            header_hex,
            out,
        } => {
            info!("Signing Seat-Vote with PKCS#11 HSM");
            let header_id = hex::decode(&header_hex).context("Invalid header hex")?;
            if header_id.len() != 32 {
                return Err(anyhow!("Header-ID must be 32 bytes"));
            }

            let signature = pkcs11_sign::seat_vote_sign_with_hsm(pkcs11_sign::SeatVoteHsmParams {
                module_path: &module,
                pin_env: &pin_env,
                key_id: &key_id,
                slash_db_path: &db_dir,
                epoch,
                shard,
                round,
                header_id: &header_id,
            })?;

            let sig_hex = hex::encode(&signature);
            if let Some(out_path) = out {
                fs::write(&out_path, sig_hex.as_bytes())?;
                info!(out = %out_path.display(), "Seat-Vote signature saved");
            }
            println!("{}", sig_hex);
        }
        Commands::WalletBuildTx {
            inputs,
            to_addr,
            amount,
            fee,
            change_addr,
            out_psbt,
            out_tx_bin,
        } => {
            if inputs.is_empty() {
                return Err(anyhow!("mindestens ein --inputs Eintrag wird benötigt"));
            }

            let mut txins: Vec<pc_types::TxIn> = Vec::with_capacity(inputs.len());
            let mut derivations: Vec<psbt::Derivation> = Vec::with_capacity(inputs.len());
            let mut total_in: u64 = 0;

            for (idx, spec) in inputs.iter().enumerate() {
                let mut parts = spec.split(':');
                let txid_hex = parts.next().ok_or_else(|| {
                    anyhow!(
                        "input #{}: erwartetes Format txid:vout:amount:derivation",
                        idx
                    )
                })?;
                let vout_str = parts
                    .next()
                    .ok_or_else(|| anyhow!("input #{}: fehlendes vout", idx))?;
                let amount_str = parts
                    .next()
                    .ok_or_else(|| anyhow!("input #{}: fehlender amount", idx))?;
                let derivation = parts
                    .next()
                    .ok_or_else(|| anyhow!("input #{}: fehlende derivation", idx))?;
                if parts.next().is_some() {
                    return Err(anyhow!(
                        "input #{}: zu viele Segmente, erwartet txid:vout:amount:derivation",
                        idx
                    ));
                }

                let mut txid = [0u8; 32];
                let raw_txid = hex::decode(txid_hex)
                    .map_err(|e| anyhow!("input #{}: txid hex decode: {e}", idx))?;
                if raw_txid.len() != 32 {
                    return Err(anyhow!(
                        "input #{}: txid muss 32 Byte (64 Hex-Zeichen) haben, got {}",
                        idx,
                        raw_txid.len()
                    ));
                }
                txid.copy_from_slice(&raw_txid);

                let vout: u32 = vout_str
                    .parse()
                    .map_err(|e| anyhow!("input #{}: vout parse: {e}", idx))?;
                let amt_in: u64 = amount_str
                    .parse()
                    .map_err(|e| anyhow!("input #{}: amount parse: {e}", idx))?;
                total_in = total_in
                    .checked_add(amt_in)
                    .ok_or_else(|| anyhow!("input-Beträge overflow"))?;

                txins.push(pc_types::TxIn {
                    prev_out: pc_types::OutPoint { txid, vout },
                    witness: Vec::new(),
                });
                derivations.push(psbt::Derivation {
                    path: derivation.to_string(),
                });
            }

            let required = amount
                .checked_add(fee)
                .ok_or_else(|| anyhow!("amount+fee overflow"))?;
            if total_in < required {
                return Err(anyhow!(
                    "Summe der Inputs ({}) kleiner als amount+fee ({}):",
                    total_in,
                    required
                ));
            }
            let change = total_in - required;

            let mut outputs: Vec<pc_types::TxOut> = Vec::new();
            let to_lock = lock_from_pc_address(&to_addr)?;
            outputs.push(pc_types::TxOut {
                amount,
                lock: to_lock,
            });

            if change > 0 {
                let change_addr_val = change_addr
                    .as_ref()
                    .ok_or_else(|| anyhow!("change > 0, aber --change-addr fehlt"))?;
                let change_lock = lock_from_pc_address(change_addr_val)?;
                outputs.push(pc_types::TxOut {
                    amount: change,
                    lock: change_lock,
                });
            }

            let tx = MicroTx {
                version: 1,
                inputs: txins,
                outputs,
            };

            pc_types::validate_microtx_sanity(&tx)
                .map_err(|e| anyhow!("tx sanity failed: {}", e))?;

            psbt::to_toml_file(&tx, &derivations, &out_psbt)?;
            info!(path = %out_psbt.display(), "wallet psbt erstellt");

            if let Some(out_bin) = out_tx_bin.as_ref() {
                let enc = psbt::encode_tx(&tx)?;
                fs::write(out_bin, &enc)?;
                info!(path = %out_bin.display(), "wallet tx bin geschrieben");
            }
        }
        Commands::WalletListUtxos {
            addr,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let lock = lock_from_pc_address(&addr)?;
            let lock_hex = hex::encode(lock.0);
            let url = format!(
                "{}/wallet/history/{}",
                rc.node_url.trim_end_matches('/'),
                lock_hex
            );

            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!("wallet-list-utxos failed: {} {}", status, text));
            }
            println!("{}", text);
        }
        Commands::WalletBalance {
            addr,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
            include_staked,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let lock = lock_from_pc_address(&addr)?;
            let lock_hex = hex::encode(lock.0);
            let url = format!(
                "{}/wallet/utxos_by_lock/{}",
                rc.node_url.trim_end_matches('/'),
                lock_hex
            );

            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!("wallet-balance failed: {} {}", status, text));
            }
            let parsed: WalletUtxoResp = serde_json::from_str(&text)
                .map_err(|e| anyhow!("wallet-balance parse json: {e}"))?;
            if !parsed.ok {
                return Err(anyhow!("wallet-balance: response ok=false"));
            }
            let mut balance: u64 = 0;
            let mut staked_balance: u64 = 0;
            for u in parsed.utxos.iter() {
                if u.staked {
                    staked_balance = staked_balance
                        .checked_add(u.amount)
                        .ok_or_else(|| anyhow!("staked balance overflow"))?;
                    if include_staked {
                        balance = balance
                            .checked_add(u.amount)
                            .ok_or_else(|| anyhow!("balance overflow"))?;
                    }
                } else {
                    balance = balance
                        .checked_add(u.amount)
                        .ok_or_else(|| anyhow!("balance overflow"))?;
                }
            }
            let out = serde_json::json!({
                "addr": addr,
                "lock": parsed.lock,
                "balance": balance,
                "staked_balance": staked_balance,
                "include_staked": include_staked,
            })
            .to_string();
            println!("{}", out);
        }
        Commands::WalletHistory {
            addr,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let lock = lock_from_pc_address(&addr)?;
            let lock_hex = hex::encode(lock.0);
            let url = format!(
                "{}/wallet/utxos_by_lock/{}",
                rc.node_url.trim_end_matches('/'),
                lock_hex
            );

            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!("wallet-history failed: {} {}", status, text));
            }
            let parsed: WalletUtxoResp = serde_json::from_str(&text)
                .map_err(|e| anyhow!("wallet-history parse json: {e}"))?;
            if !parsed.ok {
                return Err(anyhow!("wallet-history: response ok=false"));
            }
            let mut utxos = parsed.utxos.clone();
            utxos.sort_by_key(|u| u.minted_at);
            let mut balance: u64 = 0;
            let mut staked_balance: u64 = 0;
            for u in utxos.iter() {
                balance = balance
                    .checked_add(u.amount)
                    .ok_or_else(|| anyhow!("balance overflow"))?;
                if u.staked {
                    staked_balance = staked_balance
                        .checked_add(u.amount)
                        .ok_or_else(|| anyhow!("staked balance overflow"))?;
                }
            }
            let out = serde_json::json!({
                "addr": addr,
                "lock": parsed.lock,
                "balance": balance,
                "staked_balance": staked_balance,
                "n_utxos": utxos.len(),
                "utxos": utxos,
            })
            .to_string();
            println!("{}", out);
        }
        Commands::WalletSend {
            from_addr,
            to_addr,
            amount,
            fee,
            change_addr,
            keystore,
            seed_store,
            passphrase_env,
            passphrase_file,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
            wallet_db,
        } => {
            if amount == 0 {
                return Err(anyhow!("amount darf nicht 0 sein"));
            }

            if fee != 0 && fee < WALLET_MIN_FEE_ABS {
                return Err(anyhow!(
                    "Gebühr zu niedrig: fee={} < MIN_FEE_ABS={} (Subcoin). Diese Transaktion würde vom Node verworfen werden. Bitte eine höhere Gebühr angeben.",
                    fee,
                    WALLET_MIN_FEE_ABS
                ));
            }

            let rc = resolve_node_config(
                node,
                "http://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let from_lock = lock_from_pc_address(&from_addr)?;
            let from_lock_hex = hex::encode(from_lock.0);
            let utxo_url = format!(
                "{}/wallet/utxos_by_lock/{}",
                rc.node_url.trim_end_matches('/'),
                from_lock_hex
            );

            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let utxo_url_parsed = parse_http_url(&utxo_url)?;
            ensure_bearer_transport_safe(&utxo_url_parsed, rc.auth_token.as_deref())?;
            let mut req = client.get(utxo_url_parsed);
            if let Some(tok) = rc.auth_token.as_deref() {
                req = req.bearer_auth(tok);
            }
            let resp = match req.send() {
                Ok(r) => r,
                Err(e) => {
                    if e.is_connect() || e.is_timeout() {
                        return Err(anyhow!(
                            "wallet-send: Node {} nicht erreichbar oder Timeout ({}). Mögliche Ursachen (Beispiele): Node läuft nicht, falsche --node URL/Port, Netzwerk- oder Firewall-Problem.",
                            rc.node_url, e
                        ));
                    } else {
                        return Err(anyhow!(
                            "wallet-send: HTTP-Fehler beim UTXO-Request: {}. Mögliche Ursachen (Beispiele): falsches http/https-Schema, TLS-/Zertifikatsproblem, Proxy oder andere Zwischenkomponente blockiert die Anfrage.",
                            e
                        ));
                    }
                }
            };
            let status = resp.status();
            let text = read_response_text_limited(resp, MAX_HTTP_RESPONSE_BYTES)?;
            if !status.is_success() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(msg) = v.get("error").and_then(|e| e.as_str()) {
                        return Err(anyhow!(
                            "wallet-send: Node hat UTXO-Request abgelehnt ({}): {}. Mögliche Ursachen (Beispiele): ungültige Absenderadresse, falsches Request-Format, Node-Policy oder fehlende/beschädigte Authentifizierung.",
                            status, msg
                        ));
                    }
                }
                return Err(anyhow!(
                    "wallet-send utxo query failed: {} {}. Mögliche Ursachen (Beispiele): Node hat eine unerwartete Antwort geliefert oder eine vorgeschaltete Komponente (Proxy, Load-Balancer) antwortet nicht im erwarteten Format.",
                    status, text
                ));
            }
            let utxo_resp: WalletUtxoResp = serde_json::from_str(&text)
                .map_err(|e| anyhow!("wallet-send utxo parse json: {e}"))?;
            if !utxo_resp.ok {
                return Err(anyhow!(
                    "wallet-send: utxo response ok=false. Mögliche Ursachen (Beispiele): Node hat keine spendable UTXOs geliefert oder die Anfrage intern abgelehnt (Node-Logs und Konfiguration prüfen)."
                ));
            }

            let mut utxos: Vec<WalletUtxo> =
                utxo_resp.utxos.into_iter().filter(|u| !u.staked).collect();
            if utxos.is_empty() {
                return Err(anyhow!("keine spendable UTXOs für from_addr gefunden"));
            }

            utxos.sort_by_key(|u| u.minted_at);
            let required = amount
                .checked_add(fee)
                .ok_or_else(|| anyhow!("amount+fee overflow"))?;
            let mut selected: Vec<WalletUtxo> = Vec::new();
            let mut total_in: u64 = 0;
            for u in utxos.into_iter() {
                selected.push(u.clone());
                total_in = total_in
                    .checked_add(u.amount)
                    .ok_or_else(|| anyhow!("input-Beträge overflow"))?;
                if total_in >= required {
                    break;
                }
            }
            if total_in < required {
                return Err(anyhow!(
                    "nicht genug UTXOs: total_in={} < required={}",
                    total_in,
                    required
                ));
            }
            let change = total_in - required;

            let mut inputs: Vec<pc_types::TxIn> = Vec::with_capacity(selected.len());
            for (idx, u) in selected.iter().enumerate() {
                let raw_txid = hex::decode(&u.txid)
                    .map_err(|e| anyhow!("utxo #{}: txid hex decode: {e}", idx))?;
                if raw_txid.len() != 32 {
                    return Err(anyhow!(
                        "utxo #{}: txid muss 32 Byte (64 Hex-Zeichen) haben, got {}",
                        idx,
                        raw_txid.len()
                    ));
                }
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&raw_txid);
                inputs.push(pc_types::TxIn {
                    prev_out: pc_types::OutPoint { txid, vout: u.vout },
                    witness: Vec::new(),
                });
            }

            let mut outputs: Vec<pc_types::TxOut> = Vec::new();
            let to_lock = lock_from_pc_address(&to_addr)?;
            outputs.push(pc_types::TxOut {
                amount,
                lock: to_lock,
            });

            if change > 0 {
                let change_addr_val = if let Some(ref explicit) = change_addr {
                    explicit.clone()
                } else if let Some(ref db_dir) = wallet_db {
                    let pass = read_password_from_tty("Wallet-DB Passphrase: ")?;
                    let wdb = walletdb::WalletDb::open_locked(db_dir, &pass)?;
                    let meta_from = wdb
                        .get_address(&from_addr)?
                        .ok_or_else(|| {
                            anyhow!(
                                "change > 0, aber from_addr nicht im wallet-db; bitte --change-addr explizit setzen"
                            )
                        })?;
                    let xs_path = PathBuf::from(&meta_from.xpubstore_path);
                    let xs = load_xpub_store(&xs_path)?;
                    if xs.algo.as_str() != "schnorr" {
                        return Err(anyhow!(
                            "wallet-db xpubstore algo nicht unterstützt: {}",
                            xs.algo
                        ));
                    }
                    let xpub: ExtendedPublicKey<B32SecpPk> = ExtendedPublicKey::from_str(&xs.xpub)
                        .map_err(|e| anyhow!("xpub parse: {e}"))?;
                    let all = wdb.all_addresses()?;
                    let mut max_index: Option<u32> = None;
                    for m in all.into_iter() {
                        if m.xpubstore_path == meta_from.xpubstore_path && m.change == 1 {
                            max_index = Some(match max_index {
                                Some(cur) => cur.max(m.index),
                                None => m.index,
                            });
                        }
                    }
                    let next_index = match max_index {
                        Some(v) => v
                            .checked_add(1)
                            .ok_or_else(|| anyhow!("change index overflow"))?,
                        None => 0,
                    };
                    let xonly_change = derive_child_xonly(&xpub, 1, next_index)?;
                    let addr_change = bech32m_address_from_xonly(&xs.hrp, &xonly_change)?;
                    let meta_new = walletdb::WalletAddrMeta {
                        version: 1,
                        addr: addr_change.clone(),
                        hrp: xs.hrp.clone(),
                        change: 1,
                        index: next_index,
                        xpub_derivation: xs.derivation.clone(),
                        fingerprint: xs.fingerprint.clone(),
                        xpubstore_path: meta_from.xpubstore_path.clone(),
                        label: Some("change".to_string()),
                    };
                    wdb.put_address(&meta_new)?;
                    addr_change
                } else {
                    // Simple default: send change back to the sending address.
                    // Einfacher Default: Change an die Absenderadresse zurücksenden.
                    from_addr.clone()
                };
                let change_lock = lock_from_pc_address(&change_addr_val)?;
                outputs.push(pc_types::TxOut {
                    amount: change,
                    lock: change_lock,
                });
            }

            let tx = MicroTx {
                version: 1,
                inputs,
                outputs,
            };

            pc_types::validate_microtx_sanity(&tx)
                .map_err(|e| anyhow!("tx sanity failed: {}", e))?;

            let kp = if let Some(ref ks_path) = keystore {
                let ks = load_keystore(ks_path)?;
                if ks.algo.as_str() != "schnorr" {
                    return Err(anyhow!(
                        "wallet-send unterstützt aktuell nur Schnorr-Keystores"
                    ));
                }
                let pass = get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?;
                let mut pass_owned = pass;
                let salt = general_purpose::STANDARD.decode(&ks.kdf.salt_b64)?;
                let mut salt16 = [0u8; 16];
                salt16.copy_from_slice(&salt);
                let key = derive_key(&pass_owned, &salt16, &ks.kdf.params)?;
                pass_owned.zeroize();
                let nonce = general_purpose::STANDARD.decode(&ks.enc.nonce_b64)?;
                let ct = general_purpose::STANDARD.decode(&ks.enc.ct_b64)?;
                let mut nonce24 = [0u8; 24];
                nonce24.copy_from_slice(&nonce);
                let secret = decrypt_secret(&key, &nonce24, &ct)?;
                if secret.len() != 32 {
                    return Err(anyhow!("invalid secret length"));
                }
                let mut sec32 = [0u8; 32];
                sec32.copy_from_slice(&secret);
                let kp = schnorr::SchnorrKeypair::from_secret_key_bytes(&sec32)
                    .map_err(|_| anyhow!("ungültiger schnorr secret key"))?;
                sec32.zeroize();
                kp
            } else if let (Some(seed_path), Some(db_dir)) =
                (seed_store.as_ref(), wallet_db.as_ref())
            {
                let pass = get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?;
                schnorr_keypair_from_wallet_seedstore(db_dir, seed_path, &pass, &from_addr)?
            } else {
                return Err(anyhow!(
                    "wallet-send: signing source fehlt. Nutze --keystore oder --seed-store + --wallet-db"
                ));
            };

            // Safety: signing key must match from_addr lock.
            // Safety: Sign-Key muss zum from_addr Lock passen.
            let pub_xonly = kp.public_xonly_bytes();
            if pub_xonly != from_lock.0 {
                return Err(anyhow!(
                    "wallet-send: signing key passt nicht zu from_addr (pub_xonly != lock)"
                ));
            }

            let nid = fetch_network_id_from_node(
                &rc.node_url,
                rc.auth_token.as_deref(),
                rc.tls_ca.as_deref(),
                rc.tls_client_pem.as_deref(),
            )?;
            let digest = psbt::sighash_of_tx(&nid, &tx);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            if sig.len() != 64 {
                return Err(anyhow!("schnorr signature muss 64 bytes sein"));
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&sig);
            let witness = psbt::build_witness(&pub_xonly, &sig64);
            let witnesses: Vec<Vec<u8>> = std::iter::repeat_n(witness, tx.inputs.len()).collect();
            let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
            let enc = psbt::encode_tx(&final_tx)?;

            let url = format!("{}/tx/broadcast", rc.node_url.trim_end_matches('/'));
            let url_parsed = parse_http_url(&url)?;
            ensure_bearer_transport_safe(&url_parsed, rc.auth_token.as_deref())?;
            let mut req2 = client
                .post(url_parsed)
                .header("content-type", "application/octet-stream");
            if let Some(tok) = rc.auth_token.as_deref() {
                req2 = req2.bearer_auth(tok);
            }
            let resp2 = match req2.body(enc).send() {
                Ok(r) => r,
                Err(e) => {
                    if e.is_connect() || e.is_timeout() {
                        return Err(anyhow!(
                            "wallet-send: Node {} nicht erreichbar oder Timeout beim Broadcast ({}). Mögliche Ursachen (Beispiele): Node ist gerade nicht online, falsche --node URL/Port, Netzwerk- oder Firewall-Problem.",
                            rc.node_url, e
                        ));
                    } else {
                        return Err(anyhow!(
                            "wallet-send: HTTP-Fehler beim Broadcast-Request: {}. Mögliche Ursachen (Beispiele): falsches http/https-Schema, TLS-/Zertifikatsproblem, Proxy oder Load-Balancer blockiert den Broadcast.",
                            e
                        ));
                    }
                }
            };
            let status2 = resp2.status();
            let text2 = read_response_text_limited(resp2, MAX_HTTP_RESPONSE_BYTES)?;
            if !status2.is_success() {
                if let Some(kind) = classify_broadcast_state_error(&text2) {
                    match kind {
                        BroadcastStateErrorKind::MissingInput
                        | BroadcastStateErrorKind::DoubleSpend => {
                            let code = match kind {
                                BroadcastStateErrorKind::MissingInput => "missing_input",
                                BroadcastStateErrorKind::DoubleSpend => "double_spend",
                                BroadcastStateErrorKind::Other => "other",
                            };
                            return Err(anyhow!(
                                "wallet-send: Node hat Broadcast abgelehnt ({status2}, state_error={code}). Das deutet auf einen UTXO-Race/Double-Spend hin: ein ausgewählter Input wurde zwischen UTXO-Abfrage und Broadcast bereits ausgegeben. Bitte UTXOs neu laden und erneut senden."
                            ));
                        }
                        BroadcastStateErrorKind::Other => {
                            // fall through to the generic error handling below
                        }
                    }
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text2) {
                    if let Some(msg) = v.get("error").and_then(|e| e.as_str()) {
                        return Err(anyhow!(
                            "wallet-send: Node hat Broadcast abgelehnt ({}): {}. Mögliche Ursachen (Beispiele): zu wenig Guthaben oder Gebühr, doppelte/ungültige Transaktion, Node-/Mempool-Policy oder fehlende/beschädigte Authentifizierung.",
                            status2, msg
                        ));
                    }
                }
                return Err(anyhow!(
                    "wallet-send broadcast failed: {} {}. Mögliche Ursachen (Beispiele): Node oder eine vorgeschaltete Komponente hat den Broadcast nicht akzeptiert oder eine unerwartete Antwort geliefert.",
                    status2, text2
                ));
            }
            println!("{}", text2);
        }
        Commands::StakeBond {
            addr,
            utxos,
            keystore,
            seed_store,
            wallet_db,
            passphrase_env,
            passphrase_file,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            if utxos.is_empty() {
                return Err(anyhow!("stake-bond: keine --utxos angegeben"));
            }
            if utxos.len() > pc_types::MAX_TX_INPUTS {
                return Err(anyhow!(
                    "stake-bond: zu viele inputs: {} > MAX_TX_INPUTS={}",
                    utxos.len(),
                    pc_types::MAX_TX_INPUTS
                ));
            }

            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8443",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let lock = lock_from_pc_address(&addr)?;
            let lock_hex = hex::encode(lock.0);
            let url = format!(
                "{}/wallet/utxos_by_lock/{}",
                rc.node_url.trim_end_matches('/'),
                lock_hex
            );
            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!(
                    "stake-bond: utxo query failed: {} {}",
                    status,
                    text
                ));
            }
            let utxo_resp: WalletUtxoResp = serde_json::from_str(&text)
                .map_err(|e| anyhow!("stake-bond utxo parse json: {e}"))?;
            if !utxo_resp.ok {
                return Err(anyhow!("stake-bond: utxo response ok=false"));
            }

            // Determine signing key.
            let pass = get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?;
            let kp = if let Some(ref ks_path) = keystore {
                schnorr_keypair_from_keystore(ks_path, &pass)?
            } else if let (Some(seed_path), Some(db_dir)) =
                (seed_store.as_ref(), wallet_db.as_ref())
            {
                schnorr_keypair_from_wallet_seedstore(db_dir, seed_path, &pass, &addr)?
            } else {
                return Err(anyhow!(
                    "stake-bond: signing source fehlt. Nutze --keystore oder --seed-store + --wallet-db"
                ));
            };
            let mut pass_owned = pass;
            pass_owned.zeroize();

            // Safety: signing key must match addr lock.
            let pub_xonly = kp.public_xonly_bytes();
            if pub_xonly != lock.0 {
                return Err(anyhow!(
                    "stake-bond: signing key passt nicht zu addr (pub_xonly != lock)"
                ));
            }

            // Select and sum requested UTXOs (must be unstaked).
            let mut selected: Vec<WalletUtxo> = Vec::with_capacity(utxos.len());
            for s in utxos.iter() {
                let op = parse_outpoint_str(s)?;
                let want_txid = hex::encode(op.txid);
                let mut found: Option<WalletUtxo> = None;
                for u in utxo_resp.utxos.iter() {
                    if u.vout == op.vout && u.txid.eq_ignore_ascii_case(&want_txid) {
                        found = Some(u.clone());
                        break;
                    }
                }
                let u = found.ok_or_else(|| anyhow!("stake-bond: utxo nicht gefunden: {}", s))?;
                if u.staked {
                    return Err(anyhow!("stake-bond: utxo ist bereits gestakt: {}", s));
                }
                selected.push(u);
            }
            let mut total_in: u64 = 0;
            for u in selected.iter() {
                total_in = total_in
                    .checked_add(u.amount)
                    .ok_or_else(|| anyhow!("stake-bond: amount overflow"))?;
            }
            if total_in == 0 {
                return Err(anyhow!("stake-bond: total_in darf nicht 0 sein"));
            }

            // Build stake-bond tx (v2). We bond the full selected amount into a single staked output.
            let mut inputs: Vec<pc_types::TxIn> = Vec::with_capacity(selected.len());
            for (idx, u) in selected.iter().enumerate() {
                let raw_txid = hex::decode(&u.txid)
                    .map_err(|e| anyhow!("utxo #{}: txid hex decode: {e}", idx))?;
                if raw_txid.len() != 32 {
                    return Err(anyhow!(
                        "utxo #{}: txid muss 32 Byte (64 Hex-Zeichen) haben, got {}",
                        idx,
                        raw_txid.len()
                    ));
                }
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&raw_txid);
                inputs.push(pc_types::TxIn {
                    prev_out: pc_types::OutPoint { txid, vout: u.vout },
                    witness: Vec::new(),
                });
            }
            let outputs = vec![pc_types::TxOut {
                amount: total_in,
                lock,
            }];
            let tx = MicroTx {
                version: pc_types::TX_VERSION_STAKE_BOND_V1,
                inputs,
                outputs,
            };
            pc_types::validate_microtx_sanity(&tx)
                .map_err(|e| anyhow!("stake-bond: tx sanity failed: {}", e))?;

            let nid = fetch_network_id_from_node(
                &rc.node_url,
                rc.auth_token.as_deref(),
                rc.tls_ca.as_deref(),
                rc.tls_client_pem.as_deref(),
            )?;
            let digest = psbt::sighash_of_tx(&nid, &tx);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            if sig.len() != 64 {
                return Err(anyhow!("stake-bond: schnorr signature muss 64 bytes sein"));
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&sig);
            let witness = psbt::build_witness(&pub_xonly, &sig64);
            let witnesses: Vec<Vec<u8>> = std::iter::repeat_n(witness, tx.inputs.len()).collect();
            let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
            let enc = psbt::encode_tx(&final_tx)?;

            let url2 = format!("{}/tx/broadcast", rc.node_url.trim_end_matches('/'));
            let (status2, text2) = send_request_text(
                &client,
                reqwest::Method::POST,
                &url2,
                rc.auth_token.as_deref(),
                Some("application/octet-stream"),
                Some(enc),
            )?;
            if !status2.is_success() {
                return Err(anyhow!(
                    "stake-bond broadcast failed: {} {}",
                    status2,
                    text2
                ));
            }
            println!("{}", text2);
        }
        Commands::StakeUnbond {
            addr,
            utxos,
            keystore,
            seed_store,
            wallet_db,
            passphrase_env,
            passphrase_file,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            if utxos.is_empty() {
                return Err(anyhow!("stake-unbond: keine --utxos angegeben"));
            }
            if utxos.len() > pc_types::MAX_TX_INPUTS {
                return Err(anyhow!(
                    "stake-unbond: zu viele inputs: {} > MAX_TX_INPUTS={}",
                    utxos.len(),
                    pc_types::MAX_TX_INPUTS
                ));
            }

            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8443",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let lock = lock_from_pc_address(&addr)?;
            let lock_hex = hex::encode(lock.0);
            let url = format!(
                "{}/wallet/utxos_by_lock/{}",
                rc.node_url.trim_end_matches('/'),
                lock_hex
            );
            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!(
                    "stake-unbond: utxo query failed: {} {}",
                    status,
                    text
                ));
            }
            let utxo_resp: WalletUtxoResp = serde_json::from_str(&text)
                .map_err(|e| anyhow!("stake-unbond utxo parse json: {e}"))?;
            if !utxo_resp.ok {
                return Err(anyhow!("stake-unbond: utxo response ok=false"));
            }

            let pass = get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?;
            let kp = if let Some(ref ks_path) = keystore {
                schnorr_keypair_from_keystore(ks_path, &pass)?
            } else if let (Some(seed_path), Some(db_dir)) =
                (seed_store.as_ref(), wallet_db.as_ref())
            {
                schnorr_keypair_from_wallet_seedstore(db_dir, seed_path, &pass, &addr)?
            } else {
                return Err(anyhow!(
                    "stake-unbond: signing source fehlt. Nutze --keystore oder --seed-store + --wallet-db"
                ));
            };
            let mut pass_owned = pass;
            pass_owned.zeroize();

            let pub_xonly = kp.public_xonly_bytes();
            if pub_xonly != lock.0 {
                return Err(anyhow!(
                    "stake-unbond: signing key passt nicht zu addr (pub_xonly != lock)"
                ));
            }

            let mut selected: Vec<WalletUtxo> = Vec::with_capacity(utxos.len());
            for s in utxos.iter() {
                let op = parse_outpoint_str(s)?;
                let want_txid = hex::encode(op.txid);
                let mut found: Option<WalletUtxo> = None;
                for u in utxo_resp.utxos.iter() {
                    if u.vout == op.vout && u.txid.eq_ignore_ascii_case(&want_txid) {
                        found = Some(u.clone());
                        break;
                    }
                }
                let u = found.ok_or_else(|| anyhow!("stake-unbond: utxo nicht gefunden: {}", s))?;
                if !u.staked {
                    return Err(anyhow!("stake-unbond: utxo ist nicht gestakt: {}", s));
                }
                selected.push(u);
            }
            let mut total_in: u64 = 0;
            for u in selected.iter() {
                total_in = total_in
                    .checked_add(u.amount)
                    .ok_or_else(|| anyhow!("stake-unbond: amount overflow"))?;
            }
            if total_in == 0 {
                return Err(anyhow!("stake-unbond: total_in darf nicht 0 sein"));
            }

            let mut inputs: Vec<pc_types::TxIn> = Vec::with_capacity(selected.len());
            for (idx, u) in selected.iter().enumerate() {
                let raw_txid = hex::decode(&u.txid)
                    .map_err(|e| anyhow!("utxo #{}: txid hex decode: {e}", idx))?;
                if raw_txid.len() != 32 {
                    return Err(anyhow!(
                        "utxo #{}: txid muss 32 Byte (64 Hex-Zeichen) haben, got {}",
                        idx,
                        raw_txid.len()
                    ));
                }
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&raw_txid);
                inputs.push(pc_types::TxIn {
                    prev_out: pc_types::OutPoint { txid, vout: u.vout },
                    witness: Vec::new(),
                });
            }
            let outputs = vec![pc_types::TxOut {
                amount: total_in,
                lock,
            }];
            let tx = MicroTx {
                version: pc_types::TX_VERSION_STAKE_UNBOND_V1,
                inputs,
                outputs,
            };
            pc_types::validate_microtx_sanity(&tx)
                .map_err(|e| anyhow!("stake-unbond: tx sanity failed: {}", e))?;

            let nid = fetch_network_id_from_node(
                &rc.node_url,
                rc.auth_token.as_deref(),
                rc.tls_ca.as_deref(),
                rc.tls_client_pem.as_deref(),
            )?;
            let digest = psbt::sighash_of_tx(&nid, &tx);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            if sig.len() != 64 {
                return Err(anyhow!(
                    "stake-unbond: schnorr signature muss 64 bytes sein"
                ));
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&sig);
            let witness = psbt::build_witness(&pub_xonly, &sig64);
            let witnesses: Vec<Vec<u8>> = std::iter::repeat_n(witness, tx.inputs.len()).collect();
            let final_tx = psbt::attach_witnesses(tx, &witnesses)?;
            let enc = psbt::encode_tx(&final_tx)?;

            let url2 = format!("{}/tx/broadcast", rc.node_url.trim_end_matches('/'));
            let (status2, text2) = send_request_text(
                &client,
                reqwest::Method::POST,
                &url2,
                rc.auth_token.as_deref(),
                Some("application/octet-stream"),
                Some(enc),
            )?;
            if !status2.is_success() {
                return Err(anyhow!(
                    "stake-unbond broadcast failed: {} {}",
                    status2,
                    text2
                ));
            }
            println!("{}", text2);
        }
        Commands::ValidatorRegister {
            addr,
            anchor_utxo,
            bls_pk,
            bls_pop,
            operator_id,
            sequence,
            keystore,
            seed_store,
            wallet_db,
            passphrase_env,
            passphrase_file,
            node,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8443",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let lock = lock_from_pc_address(&addr)?;
            let lock_hex = hex::encode(lock.0);
            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;

            // Signing key (stake lock owner).
            let pass = get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?;
            let kp = if let Some(ref ks_path) = keystore {
                schnorr_keypair_from_keystore(ks_path, &pass)?
            } else if let (Some(seed_path), Some(db_dir)) =
                (seed_store.as_ref(), wallet_db.as_ref())
            {
                schnorr_keypair_from_wallet_seedstore(db_dir, seed_path, &pass, &addr)?
            } else {
                return Err(anyhow!(
                    "validator-register: signing source fehlt. Nutze --keystore oder --seed-store + --wallet-db"
                ));
            };
            let mut pass_owned = pass;
            pass_owned.zeroize();

            let pub_xonly = kp.public_xonly_bytes();
            if pub_xonly != lock.0 {
                return Err(anyhow!(
                    "validator-register: signing key passt nicht zu addr (pub_xonly != lock)"
                ));
            }

            // Ensure anchor UTXO exists for this lock and is staked.
            let url_utxos = format!(
                "{}/wallet/utxos_by_lock/{}",
                rc.node_url.trim_end_matches('/'),
                lock_hex
            );
            let (status_utxos, text_utxos) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url_utxos,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status_utxos.is_success() {
                return Err(anyhow!(
                    "validator-register: utxo query failed: {} {}",
                    status_utxos,
                    text_utxos
                ));
            }
            let utxo_resp: WalletUtxoResp = serde_json::from_str(&text_utxos)
                .map_err(|e| anyhow!("validator-register utxo parse json: {e}"))?;
            if !utxo_resp.ok {
                return Err(anyhow!("validator-register: utxo response ok=false"));
            }
            let anchor_op = parse_outpoint_str(&anchor_utxo)?;
            let want_txid = hex::encode(anchor_op.txid);
            let mut anchor_ok = false;
            for u in utxo_resp.utxos.iter() {
                if u.vout == anchor_op.vout && u.txid.eq_ignore_ascii_case(&want_txid) {
                    if !u.staked {
                        return Err(anyhow!(
                            "validator-register: anchor_utxo ist nicht gestakt: {}",
                            anchor_utxo
                        ));
                    }
                    anchor_ok = true;
                    break;
                }
            }
            if !anchor_ok {
                return Err(anyhow!(
                    "validator-register: anchor_utxo nicht gefunden für addr-lock: {}",
                    anchor_utxo
                ));
            }

            // Parse/verify BLS pk + PoP and derive validator_id.
            let bls_pk_raw = hex::decode(bls_pk.trim())
                .map_err(|e| anyhow!("validator-register: bls_pk hex decode: {e}"))?;
            if bls_pk_raw.len() != 48 {
                return Err(anyhow!(
                    "validator-register: bls_pk muss 48 bytes sein, got {}",
                    bls_pk_raw.len()
                ));
            }
            let mut bls_pk_bytes = [0u8; 48];
            bls_pk_bytes.copy_from_slice(&bls_pk_raw);
            let pk = pc_crypto::bls_pk_from_bytes(&bls_pk_bytes)
                .ok_or_else(|| anyhow!("validator-register: invalid bls_pk bytes"))?;

            let bls_pop_raw = hex::decode(bls_pop.trim())
                .map_err(|e| anyhow!("validator-register: bls_pop hex decode: {e}"))?;
            if bls_pop_raw.len() != 96 {
                return Err(anyhow!(
                    "validator-register: bls_pop muss 96 bytes sein, got {}",
                    bls_pop_raw.len()
                ));
            }
            let mut bls_pop_bytes = [0u8; 96];
            bls_pop_bytes.copy_from_slice(&bls_pop_raw);
            if !pc_crypto::bls_pop_verify(&pk, &bls_pop_bytes) {
                return Err(anyhow!(
                    "validator-register: bls_pop passt nicht zum bls_pk"
                ));
            }
            let validator_id = pc_crypto::attestor_recipient_id_from_bls(&pk);

            let operator_id_bytes: [u8; 32] = if let Some(oid_hex) = operator_id.as_ref() {
                parse_hex_32(oid_hex)?
            } else {
                validator_id
            };

            // Sequence: either explicit or fetched from node and incremented.
            let seq: u64 = if let Some(s) = sequence {
                s
            } else {
                let url_v = format!(
                    "{}/consensus/validator/{}",
                    rc.node_url.trim_end_matches('/'),
                    hex::encode(validator_id)
                );
                let (st, txt) = send_request_text(
                    &client,
                    reqwest::Method::GET,
                    &url_v,
                    rc.auth_token.as_deref(),
                    None,
                    None,
                )?;
                if st == reqwest::StatusCode::NOT_FOUND {
                    1
                } else if st.is_success() {
                    let v: serde_json::Value = serde_json::from_str(&txt)
                        .map_err(|e| anyhow!("validator-register: parse validator json: {e}"))?;
                    let cur = v.get("sequence").and_then(|x| x.as_u64()).ok_or_else(|| {
                        anyhow!("validator-register: node response missing sequence")
                    })?;
                    cur.checked_add(1)
                        .ok_or_else(|| anyhow!("validator-register: sequence overflow"))?
                } else {
                    return Err(anyhow!(
                        "validator-register: failed to fetch existing sequence: {} {}",
                        st,
                        txt
                    ));
                }
            };

            let nid = fetch_network_id_from_node(
                &rc.node_url,
                rc.auth_token.as_deref(),
                rc.tls_ca.as_deref(),
                rc.tls_client_pem.as_deref(),
            )?;

            // Signature message must match pc-state verifier exactly.
            const REG_DOMAIN: &[u8] = b"pc:validator:register:v1\x01";
            let mut msg =
                Vec::with_capacity(REG_DOMAIN.len() + 32 + 32 + 4 + 8 + 32 + 48 + 96 + 32);
            msg.extend_from_slice(REG_DOMAIN);
            msg.extend_from_slice(&nid);
            msg.extend_from_slice(&anchor_op.txid);
            msg.extend_from_slice(&anchor_op.vout.to_le_bytes());
            msg.extend_from_slice(&seq.to_le_bytes());
            msg.extend_from_slice(&operator_id_bytes);
            msg.extend_from_slice(&bls_pk_bytes);
            msg.extend_from_slice(&bls_pop_bytes);
            msg.extend_from_slice(&pub_xonly);
            let digest = blake3_32(&msg);
            let sig = schnorr::schnorr_sign(&digest, &kp);
            if sig.len() != 64 {
                return Err(anyhow!(
                    "validator-register: schnorr signature muss 64 bytes sein"
                ));
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&sig);

            // Witness layout: pk32 || sig64 || seq_u64_le || operator_id32 || bls_pk48 || bls_pop96
            let mut witness = Vec::with_capacity(pc_types::VALIDATOR_REGISTER_WITNESS_BYTES_V1);
            witness.extend_from_slice(&pub_xonly);
            witness.extend_from_slice(&sig64);
            witness.extend_from_slice(&seq.to_le_bytes());
            witness.extend_from_slice(&operator_id_bytes);
            witness.extend_from_slice(&bls_pk_bytes);
            witness.extend_from_slice(&bls_pop_bytes);

            let tx = MicroTx {
                version: pc_types::TX_VERSION_VALIDATOR_REGISTER_V1,
                inputs: vec![pc_types::TxIn {
                    prev_out: anchor_op,
                    witness,
                }],
                outputs: Vec::new(),
            };
            pc_types::validate_microtx_sanity(&tx)
                .map_err(|e| anyhow!("validator-register: tx sanity failed: {}", e))?;

            let enc = psbt::encode_tx(&tx)?;

            let url2 = format!("{}/tx/broadcast", rc.node_url.trim_end_matches('/'));
            let (status2, text2) = send_request_text(
                &client,
                reqwest::Method::POST,
                &url2,
                rc.auth_token.as_deref(),
                Some("application/octet-stream"),
                Some(enc),
            )?;
            if !status2.is_success() {
                return Err(anyhow!(
                    "validator-register broadcast failed: {} {}",
                    status2,
                    text2
                ));
            }
            println!("{}", text2);
        }
        Commands::TxInfo {
            node,
            txid,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let url = format!("{}/tx/info/{}", rc.node_url.trim_end_matches('/'), txid);

            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!("tx-info failed: {} {}", status, text));
            }
            println!("{}", text);
        }
        Commands::BlockInfo {
            node,
            anchor,
            auth_token,
            auth_token_file,
            tls_ca,
            tls_client_pem,
        } => {
            let rc = resolve_node_config(
                node,
                "https://127.0.0.1:8080",
                auth_token,
                auth_token_file,
                tls_ca,
                tls_client_pem,
                cfg.as_ref(),
            )?;

            let url = format!(
                "{}/block/info/{}",
                rc.node_url.trim_end_matches('/'),
                anchor
            );

            let client = build_rpc_client(rc.tls_ca.as_deref(), rc.tls_client_pem.as_deref())?;
            let (status, text) = send_request_text(
                &client,
                reqwest::Method::GET,
                &url,
                rc.auth_token.as_deref(),
                None,
                None,
            )?;
            if !status.is_success() {
                return Err(anyhow!("block-info failed: {} {}", status, text));
            }
            println!("{}", text);
        }
        Commands::WalletInit {
            hrp,
            wallet_name,
            force,
        } => {
            if !std::io::stderr().is_terminal() {
                return Err(anyhow!(
                    "wallet-init verweigert Seed-Anzeige ohne TTY auf stderr (Log-Leak-Schutz)"
                ));
            }
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.wallet_init_title);
            eprintln!("║  {}", t.wallet_init_generating);
            eprintln!("║");
            eprintln!("║  {}", t.wallet_init_important);
            eprintln!("║  {}", t.wallet_init_write_down);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!();

            let mut entropy = [0u8; 32];
            OsRng.fill_bytes(&mut entropy);
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
                .map_err(|e| anyhow!("mnemonic generate: {e}"))?;

            eprintln!("{}\n", t.seed_words);
            let words: Vec<&str> = mnemonic.word_iter().collect();
            for (i, word) in words.iter().enumerate() {
                let n = i + 1;
                if n <= 12 {
                    eprint!("{:>2}. {:<12} ", n, word);
                    if n == 6 || n == 12 {
                        eprintln!();
                    }
                } else {
                    eprint!("{:>2}. {:<12} ", n, word);
                    if n == 18 || n == 24 {
                        eprintln!();
                    }
                }
            }
            eprintln!();
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.wallet_init_press_enter);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            let mut _wait = String::new();
            std::io::stdin().read_line(&mut _wait).ok();

            eprintln!();
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.seed_verify_title);
            eprintln!("║  {}", t.seed_verify_hint);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!();

            // Fisher-Yates shuffle for random order
            let mut indices: Vec<usize> = (0..24).collect();
            for i in (1..24).rev() {
                let mut rand_bytes = [0u8; 4];
                OsRng.fill_bytes(&mut rand_bytes);
                let j = (u32::from_le_bytes(rand_bytes) as usize) % (i + 1);
                indices.swap(i, j);
            }

            // Verify each word (max 5 attempts per word)
            const MAX_ATTEMPTS: u32 = 5;
            for &idx in &indices {
                let expected = words
                    .get(idx)
                    .ok_or_else(|| anyhow!("seed word index out of bounds"))?;
                let mut attempts = 0u32;
                loop {
                    eprint!("{}{:>2}: ", t.seed_verify_prompt, idx + 1);
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                    let mut input = String::new();
                    std::io::stdin()
                        .read_line(&mut input)
                        .context("read seed word")?;
                    let input = input.trim().to_lowercase();
                    if input.is_empty() {
                        return Err(anyhow!("Seed-Verifikation abgebrochen."));
                    }
                    if input == *expected {
                        break;
                    }
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(anyhow!(
                            "Seed-Verifikation fehlgeschlagen: Wort #{} nach {} Versuchen falsch. Bitte erneut starten.",
                            idx + 1,
                            MAX_ATTEMPTS
                        ));
                    }
                    eprintln!(
                        "  ❌ Falsch. Versuch {}/{} – bitte nochmal prüfen.",
                        attempts, MAX_ATTEMPTS
                    );
                }
            }

            eprintln!();
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.seed_verify_success);
            eprintln!("║  {}", t.passphrase_policy);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!();

            let pass = read_pass_twice()?;

            let first_addr =
                init_wallet_from_mnemonic(&mnemonic, &hrp, &wallet_name, &pass, force)?;

            eprintln!();
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.wallet_init_success);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!("{}: {}", t.wallet_name, wallet_name);
            eprintln!("{}: {}", t.first_address, first_addr);
            eprintln!(
                "{}: {}",
                t.wallet_db,
                default_walletdb_path(&wallet_name)?.display()
            );
            eprintln!("{}: ~/.phantom/xpubs/", t.xpub_store);
            eprintln!(
                "{}: {}",
                t.seed_store,
                default_seedstore_path(&wallet_name)?.display()
            );
            eprintln!();
            println!("{}", first_addr);
        }
        Commands::WalletRestore {
            hrp,
            wallet_name,
            force,
            mnemonic_env,
            passphrase_env,
            passphrase_file,
        } => {
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.wallet_restore_title);
            eprintln!("║  {}", t.wallet_restore_enter_seed);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!();

            let mnemonic_input_owned = if let Some(env_name) = mnemonic_env.as_ref() {
                let v = env::var(env_name)
                    .with_context(|| format!("read mnemonic env {}", env_name))?;
                v
            } else {
                let mut mnemonic_input = String::new();
                std::io::stdin()
                    .read_line(&mut mnemonic_input)
                    .context("read mnemonic from stdin")?;
                mnemonic_input
            };
            let mnemonic_input = mnemonic_input_owned.trim();

            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_input)
                .map_err(|e| anyhow!("{}: {e}", t.wallet_restore_invalid))?;

            let word_count = mnemonic.word_count();
            if word_count != 24 {
                return Err(anyhow!(
                    "{}",
                    t.wallet_restore_wrong_count
                        .replace("{}", &word_count.to_string())
                ));
            }

            eprintln!();
            eprintln!(
                "{}",
                t.wallet_restore_recognized
                    .replace("{}", &word_count.to_string())
            );
            eprintln!();
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.passphrase_policy);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!();

            let pass = if passphrase_env.is_some() || passphrase_file.is_some() {
                get_passphrase(&passphrase_env, &passphrase_file, "Passphrase: ")?
            } else {
                read_pass_twice()?
            };

            let first_addr =
                init_wallet_from_mnemonic(&mnemonic, &hrp, &wallet_name, &pass, force)?;

            eprintln!();
            eprintln!("╔════════════════════════════════════════════════════════════════════╗");
            eprintln!("║  {}", t.wallet_restore_success);
            eprintln!("╚════════════════════════════════════════════════════════════════════╝");
            eprintln!("{}: {}", t.wallet_name, wallet_name);
            eprintln!("{}: {}", t.first_address, first_addr);
            eprintln!(
                "{}: {}",
                t.wallet_db,
                default_walletdb_path(&wallet_name)?.display()
            );
            eprintln!("{}: ~/.phantom/xpubs/", t.xpub_store);
            eprintln!(
                "{}: {}",
                t.seed_store,
                default_seedstore_path(&wallet_name)?.display()
            );
            eprintln!();
            println!("{}", first_addr);
        }
    }

    Ok(())
}
