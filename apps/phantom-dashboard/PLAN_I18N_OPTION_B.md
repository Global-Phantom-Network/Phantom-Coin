# Plan: Dashboard i18n auf phantom_i18n Crate umstellen (Option B)

## Ist-Zustand
- App.tsx nutzt überall `t.keyName` (React Context + Hook) ✅
- TypeScript-Dateien: `types.ts` (Interface), `de.ts` (komplett), `en.ts` (fehlen ~30 Wallet-Wizard Keys)
- `index.ts`: React Context/Provider/Hook, lädt Locale synchron aus .ts-Dateien
- `phantom-i18n` Crate existiert (common.rs, cli.rs, tui.rs), 14 Sprachen, wird vom Dashboard NICHT genutzt

## Ziel
- Alle ~280 Dashboard-Texte in `phantom-i18n/src/dashboard.rs` (Rust)
- Alle 14 Sprachen dort komplett
- Tauri-Command liefert Texte als JSON ans Frontend
- React-Hook holt Texte über Bridge statt aus lokalen .ts-Dateien
- `de.ts`, `en.ts` werden gelöscht; `types.ts` bleibt (TypeScript-Typsicherheit)

## Schritte

### 1. Rust: `dashboard.rs` in phantom-i18n anlegen
- `DashboardTexts` Struct mit `#[derive(Serialize)]` + `#[serde(rename_all = "camelCase")]`
- ~280 Felder als `pub field: &'static str`
- `pub fn dashboard_texts(lang: Lang) -> &'static DashboardTexts`
- 14 `const`-Blöcke (DASHBOARD_DE, DASHBOARD_EN, DASHBOARD_ES, ...)
- Felder aus `de.ts` und `en.ts` übernehmen, 12 Sprachen übersetzen

### 2. Rust: phantom-i18n Cargo.toml anpassen
- `serde = { version = "1", features = ["derive"] }` hinzufügen

### 3. Rust: lib.rs erweitern
- `mod dashboard; pub use dashboard::*;`

### 4. Tauri: Cargo.toml + main.rs
- `phantom-i18n` als Dependency hinzufügen
- Tauri-Command: `get_dashboard_texts(lang: String) -> serde_json::Value`

### 5. Frontend: index.ts umverdrahten
- `invoke('get_dashboard_texts', { lang })` statt lokaler Import
- Fallback: Bei Fehler → englische Texte hardcoded (Notfall)
- `loadLocale()` / `saveLocale()` bleiben (LocalStorage)

### 6. Frontend: de.ts + en.ts löschen
- `types.ts` bleibt (Interface für TypeScript-Check)

### 7. Sprachauswahl-Dropdown in Einstellungen

### 8. Test: cargo check + tsc --noEmit
