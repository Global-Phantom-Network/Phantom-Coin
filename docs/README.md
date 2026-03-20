# Phantom-Coin Documentation Index

Dieses Verzeichnis enthaelt viele technische Unterlagen. Fuer den aktuellen Live-Pfad sind die
folgenden Dokumente kanonisch:

## Kern-Dokumente

- [SPEC_POW.md](./SPEC_POW.md)
  - Live-Spezifikation fuer Emissionsrunden, Difficulty, `round_id`, `hit_bucket`, `bits_used`
    und die Graph-Anbindung von Mints.
- [mining-api.md](./mining-api.md)
  - Operator- und Miner-Dokumentation fuer `/mint/template`, `/mint/status`, `/mint/submit`.
- [observability.md](./observability.md)
  - Betriebs-, Metrik-, Persistenz- und Troubleshooting-Dokumentation fuer `phantom-node`.
- [SPEC_CODEC.md](./SPEC_CODEC.md)
  - Kanonische Wire- und Commitment-Spezifikation fuer aktive Datentypen, insbesondere
    `MintEvent` V2 und `AnchorPayloadV3`.

## Weitere Live-Spezifikationen

- [SPEC_MATURITY.md](./SPEC_MATURITY.md)
- [SPEC_P2P.md](./SPEC_P2P.md)
- [SPEC_SLASHING.md](./SPEC_SLASHING.md)
- [SPEC_FEES.md](./SPEC_FEES.md)
- [GENESIS.md](./GENESIS.md)
- [STAKING.md](./STAKING.md)

## Praktische Guides

- [network_bootstrap.md](./network_bootstrap.md)
- [backup-recovery-guide.md](./backup-recovery-guide.md)
- [deployment-guide.md](./deployment-guide.md)
- [devops/README.md](./devops/README.md)

## Lesereihenfolge fuer neue Operatoren

1. [SPEC_POW.md](./SPEC_POW.md)
2. [mining-api.md](./mining-api.md)
3. [observability.md](./observability.md)
4. [SPEC_CODEC.md](./SPEC_CODEC.md)

## Lesereihenfolge fuer Entwickler

1. [SPEC_CODEC.md](./SPEC_CODEC.md)
2. [SPEC_POW.md](./SPEC_POW.md)
3. [SPEC_P2P.md](./SPEC_P2P.md)
4. [SPEC_MATURITY.md](./SPEC_MATURITY.md)
