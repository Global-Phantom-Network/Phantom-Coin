# HSM‑Flows (Design & Runbook)

Ziel: Signieren/Verifizieren sensibler Nachrichten (z. B. Seat‑Votes) über HSM/PKCS#11 – deterministische Build‑Artefakte bleiben unverändert.

## Anforderungen
- SoftHSM v2 (oder Hardware HSM/YubiKey mit PKCS#11)
- `pkcs11-tool`, `softhsm2-util`
- PKCS#11 Modulpfad (z. B. `/usr/lib/softhsm/libsofthsm2.so`)

## Token einrichten (SoftHSM Beispiel)
```bash
# 1) Token anlegen
softhsm2-util --init-token --label pc-hsm --slot 0 --pin 1234 --so-pin 0000

# 2) Schlüsselpaar generieren (EC) – Schnorr/BLS erfordern libs/curves außerhalb von PKCS#11;
#    für den Anfang ECDSA/NIST als Transport‑Demo (Signatur‑Pipe), später native Schnorr/BLS‑Binding.
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keygen --key-type EC:secp256k1 \
  --label pc-seat --id 01

# 3) Öffentlichen Schlüssel exportieren
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
  --read-object --type pubkey --id 01 -o pubkey.der
```

## Signieren über PKCS#11 (Transport‑Demo)
```bash
# Digest vorbereiten (blake3_32)
echo -n "hello" | openssl dgst -sha256 -binary > msg.bin   # Platzhalter‑Digest; in PhantomCoin: blake3_32

# PKCS#11 Signatur (ECDSA‑DER)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
  --sign --id 01 --mechanism ECDSA --input-file msg.bin --output-file sig.der
```

## Integration phantom-signer (geplanter CLI‑Pfad)
- Neues Subcommand (Design):
```
phantom-signer sign-pkcs11 \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --pin-env HSM_PIN \
  --key-id 01 \
  --msg msg.bin \
  --out sig.bin \
  [--mechanism ECDSA|EDDSA|VENDOR_BLS]
```
- Verhalten:
  - Lädt PKCS#11 Modul, öffnet Session, signiert `msg.bin` (Digest) mit `key-id`.
  - Pin aus `--pin-env` (kein Prompt, CI‑fähig).
  - Ergebnis: rohe Signatur oder DER (je nach Mechanismus) + JSON‑Metadaten (Key Label/ID).
- Hinweis: Für BLS/Schnorr via HSM braucht spezifische Module/APIs; bis dahin: 
  - Schlüsselmaterial im HSM verwalten (Export nur Public Key), Signatur extern (Custom Plugin) – oder
  - ECDSA als Transport‑Proof (nicht für Konsens), um HSM‑Pfade/Policies zu validieren.

## Policies
- Keine Secrets im Repo/Logs. Pins nur via ENV (`HSM_PIN`), niemals im CLI‑History.
- Systemd‑Service: `EnvironmentFile=/etc/phantom/hsm.env` (600), enthält `HSM_PIN=...`.
- Audit: Jeder Signatur‑Call loggt Key‑ID/Label, aber nie den Pin.

## Testmatrix
- SoftHSM2 (Linux)
- YubiKey 5 (PKCS#11, ECDSA/EdDSA)
- Vendor‑HSM (falls verfügbar)

## Nächste Schritte
- `phantom-signer`: Implementierung `sign-pkcs11` (separates Ticket)
- End‑to‑End Test: Seat‑Vote Digest → HSM Sign → Verify → Node Accept
