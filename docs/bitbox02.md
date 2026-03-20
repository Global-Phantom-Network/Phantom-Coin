# BitBox02 – Kurz‑Doku (PhantomCoin)

## Voraussetzungen
- BitBox02 per USB **oder** BitBoxBridge (Standard: `http://127.0.0.1:8178`).
- Bridge möglichst lokal betreiben (keine fremden Hosts).

## GUI (phantom-gui-wallet)
- **Einstellungen → BitBox02**
  - Transport wählen: `Auto` / `USB` / `Bridge`
  - Bridge‑URL eintragen und **Bridge prüfen**
- **BitBox02 erkennen**: Gerät suchen (HWI).
- **BitBox02 XPub lesen**: XPub aus der BitBox02 auslesen.

## TUI (phantom-tui)
- **BitBox Settings**:
  - `transport (auto|usb|bridge)`
  - `bridge_url`
  - `bridge_check (true|false)`  
- Danach **HWI Enumerate** oder **HWI Get Xpub** nutzen.

## CLI (phantom-signer)
- Geräte auflisten: `phantom-signer hwi-enumerate`
- XPub lesen: `phantom-signer hwi-get-xpub --derivation "m/86'/12345'/0'"`
- Transport erzwingen:
  - `PHANTOM_BITBOX_TRANSPORT=bridge` (oder `usb`, `auto`)
  - `PHANTOM_BITBOX_BRIDGE_URL=http://127.0.0.1:8178`

### Tx‑Signing (extern)
`phantom-signer hwi-sign-tx ...` nutzt einen externen BitBox‑Signer:
- Pfad: `PHANTOM_BITBOX2_SIGNER`, sonst `bitbox02-signer`

## Hinweise
- **Auto‑Modus**: Erst USB, dann Bridge.
- Bridge‑Status wird in GUI/TUI geprüft und angezeigt.
