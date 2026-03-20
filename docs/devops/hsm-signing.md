# HSM/Signing-Integration für Release-Artefakte

## Übersicht
PhantomCoin-Releases werden kryptografisch signiert, um Authentizität und Integrität zu gewährleisten. Diese Dokumentation beschreibt die Integration von Hardware Security Modules (HSM) via PKCS#11 und Cosign Keyless Signing.

## Signing-Strategien

### 1. Cosign Keyless Signing (GitHub OIDC)
**Aktuell implementiert** in `.github/workflows/release.yml`

#### Vorteile
- Keine langlebigen privaten Keys im Repo/CI
- GitHub OIDC-Token als Identität
- Transparency Log (Rekor) für Audit-Trail
- Signatur-Verifikation via Public Rekor Log

#### Verwendung
```bash
# Signieren (automatisch in release.yml)
cosign sign --yes --key env://COSIGN_KEY ghcr.io/global-phantom-network/phantom-node:${TAG}

# Verifizieren
cosign verify \
  --certificate-identity-regexp="https://github.com/Global-Phantom-Network/Phantom-Coin" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/global-phantom-network/phantom-node:latest
```

#### Konfiguration in CI
```yaml
- name: Sign Docker image
  env:
    COSIGN_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
  run: |
    echo "$COSIGN_KEY" > cosign.key
    cosign sign --yes --key cosign.key ghcr.io/.../phantom-node:${TAG}
    rm cosign.key
```

---

### 2. HSM-Integration via PKCS#11

#### Architektur
```
Release-Artefakt → SHA256 Hash → PKCS#11 Signing → Signatur (detached .sig)
```

#### Unterstützte HSMs
- **YubiKey 5 / YubiHSM 2**: PKCS#11 via `ykcs11` / `yubihsm-pkcs11`
- **Nitrokey HSM**: OpenSC PKCS#11
- **Cloud HSMs**: AWS CloudHSM, Google Cloud HSM (via PKCS#11 Provider)

#### Setup-Schritte

**1. PKCS#11-Modul installieren (Beispiel YubiKey)**
```bash
# macOS
brew install ykman yubico-piv-tool

# Linux
apt-get install ykcs11 libykpiv2 yubico-piv-tool
```

**2. Key-Pair auf HSM generieren**
```bash
# RSA-4096 in Slot 9c (Digital Signature)
yubico-piv-tool -s 9c -a generate -A RSA4096 -o pubkey.pem

# Selbst-signiertes Zertifikat (oder CSR für CA)
yubico-piv-tool -s 9c -a verify-pin -a selfsign -S "/CN=PhantomCoin Release/" -i pubkey.pem -o cert.pem
yubico-piv-tool -s 9c -a import-certificate -i cert.pem
```

**3. Release-Artefakt signieren**
```bash
# SHA256 Hash des Tarballs
sha256sum phantomcoin-v1.0.0-linux-x86_64.tar.gz > SHA256SUMS

# PKCS#11 Signatur (detached)
pkcs11-tool --module /usr/lib/libykcs11.so \
  --sign --mechanism SHA256-RSA-PKCS \
  --slot 0 --pin <PIN> \
  --input-file SHA256SUMS \
  --output-file SHA256SUMS.hsm.sig
```

**4. Signatur verifizieren**
```bash
# Public Key aus HSM exportieren (einmalig)
pkcs11-tool --module /usr/lib/libykcs11.so --read-object --type pubkey --id 01 > release-pubkey.pem

# Signatur prüfen
openssl dgst -sha256 -verify release-pubkey.pem -signature SHA256SUMS.hsm.sig SHA256SUMS
```

---

### 3. GPG-Signing (Legacy-Alternative)

**Für Nutzer ohne PKCS#11-Infrastruktur**

```bash
# GPG-Key generieren (einmalig, offline auf Air-Gapped System)
gpg --full-generate-key  # RSA 4096, keine Expiration

# Release signieren
gpg --armor --detach-sign phantomcoin-v1.0.0-linux-x86_64.tar.gz

# Verifizieren
gpg --verify phantomcoin-v1.0.0-linux-x86_64.tar.gz.asc phantomcoin-v1.0.0-linux-x86_64.tar.gz
```

**Public Key Distribution**
```bash
# Public Key exportieren
gpg --armor --export release@phantom-coin.org > RELEASE_KEY.asc

# In Repo committen: docs/RELEASE_KEY.asc
# Zusätzlich auf Keyserver hochladen
gpg --send-keys <KEY_ID>
```

---

## CI-Integration (GitHub Actions)

### HSM-Signing in CI (Self-Hosted Runner mit angeschlossenem HSM)

```yaml
name: Release (HSM-signed)
on:
  push:
    tags: ['v*']
jobs:
  sign-release:
    runs-on: [self-hosted, hsm-enabled]
    steps:
      - uses: actions/checkout@v4
      - name: Build release artifact
        run: cargo build --release --locked
      - name: Package
        run: tar -czf phantomcoin-${GITHUB_REF_NAME}.tar.gz -C target/release phantom-node
      - name: Sign with HSM
        env:
          HSM_PIN: ${{ secrets.HSM_PIN }}
        run: |
          sha256sum phantomcoin-*.tar.gz > SHA256SUMS
          pkcs11-tool --module /usr/lib/libykcs11.so \
            --sign --mechanism SHA256-RSA-PKCS \
            --slot 0 --pin "$HSM_PIN" \
            --input-file SHA256SUMS \
            --output-file SHA256SUMS.hsm.sig
      - name: Upload release assets
        uses: softprops/action-gh-release@v1
        with:
          files: |
            phantomcoin-*.tar.gz
            SHA256SUMS
            SHA256SUMS.hsm.sig
```

---

## Best Practices

### Key-Management
- **HSM-Keys niemals exportieren**: Private Keys verbleiben im HSM.
- **PIN-Schutz**: HSM-PIN als GitHub Secret, niemals im Code.
- **Backup**: Disaster-Recovery-Keys in Offline-Tresor (Paper Wallet oder zweites HSM).
- **Rotation**: Release-Keys jährlich rotieren, alte Signaturen bleiben gültig.

### Audit-Trail
- **Transparency Log**: Cosign schreibt in Rekor (öffentlich nachvollziehbar).
- **SBOM**: Software Bill of Materials (Syft) für jedes Release generieren.
- **Provenance**: SLSA Level 3 Attestation via GitHub OIDC.

### Incident Response
- **Kompromittierter Key**: Sofort widerrufen, neue Signaturen mit rotiertem Key, Security Advisory veröffentlichen.
- **HSM-Verlust**: Backup-Key aus Tresor holen, neues HSM provisionieren, Key-Rotation durchführen.

---

## Verifikation durch Nutzer

### HSM/OpenSSL – Kurzleitfaden
```bash
# 1. Release herunterladen (Beispiel v1.0.0)
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.0.0/phantomcoin-v1.0.0-linux-x86_64.tar.gz
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.0.0/SHA256SUMS
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.0.0/SHA256SUMS.hsm.sig

# 2. Öffentlichen Schlüssel bereitstellen
# Option A: Bereitgestellte release-pubkey.pem verwenden
# Option B: Aus Zertifikat extrahieren:
#   openssl x509 -in release-cert.pem -pubkey -noout > release-pubkey.pem

# 3. HSM-Signatur prüfen (RSA-PKCS1v1.5 + SHA-256)
openssl dgst -sha256 -verify release-pubkey.pem -signature SHA256SUMS.hsm.sig SHA256SUMS

# 4. Dateien integritätsprüfen
sha256sum -c SHA256SUMS
```

Troubleshooting:
- "bad signature": Sicherstellen, dass mit SHA256 signiert wurde (Mechanismus: SHA256-RSA-PKCS) und bei OpenSSL `-sha256` genutzt wird.
- "unable to load key": Public Key im PEM-Format bereitstellen (`-----BEGIN PUBLIC KEY-----`).

### Empfohlener User-Flow (GPG – Alternative)
```bash
# 1. Release herunterladen
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.0.0/phantomcoin-v1.0.0-linux-x86_64.tar.gz
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.0.0/SHA256SUMS
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.0.0/SHA256SUMS.asc

# 2. Public Key importieren (einmalig)
curl -sSL https://raw.githubusercontent.com/Global-Phantom-Network/Phantom-Coin/main/docs/RELEASE_KEY.asc | gpg --import

# 3. Signatur prüfen
gpg --verify SHA256SUMS.asc SHA256SUMS

# 4. Hash prüfen
sha256sum -c SHA256SUMS
```

**Cosign-Verifikation (Docker-Images)**
```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/Global-Phantom-Network" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/global-phantom-network/phantom-node:v1.0.0
```

---

## Roadmap

- [ ] **SLSA Level 3 Provenance**: Build-Provenance-Attestation via GitHub Actions
- [ ] **Notary v2**: OCI-native Signing für Multi-Arch-Images
- [ ] **In-Toto**: Supply-Chain-Attestation für Build-Pipeline
- [ ] **Sigstore**: Keyless Signing auch für Binaries (nicht nur Container)

---

## Referenzen
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [PKCS#11 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [YubiKey PIV Guide](https://developers.yubico.com/PIV/Guides/)
- [SLSA Framework](https://slsa.dev/)
