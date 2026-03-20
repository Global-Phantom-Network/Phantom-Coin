#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# Generates docs/AUDIT_EVIDENCE_MATRIX.md from AUDIT_FINDINGS.txt.
# The goal is a *non-fuzzy* evidence map:
# - Code evidence anchors are searched only within the audit-referenced files.
# - Test evidence only lists real Rust tests (#[test]/#[tokio::test] + fn name).

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import subprocess


ROOT = Path(".")
AUDIT_PATH = ROOT / "AUDIT_FINDINGS.txt"
OUT_PATH = ROOT / "docs" / "AUDIT_EVIDENCE_MATRIX.md"


def expand_braces(s: str) -> list[str]:
    """Expand a simple single-level {a,b,c} brace pattern in a path string."""
    m = re.search(r"\{([^{}]+)\}", s)
    if not m:
        return [s]
    parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
    return [s[: m.start()] + p + s[m.end() :] for p in parts]


def parse_file_paths(files_raw: list[str]) -> list[str]:
    out: list[str] = []
    for fr in files_raw:
        for s in expand_braces(fr):
            s = s.split("(")[0].strip()
            for part in re.split(r"\s*,\s*", s):
                part = part.strip()
                if not part:
                    continue
                part = part.split(" Z.")[0].split(" Z:")[0].split(" Z")[0].strip()
                out.append(part)
    # de-dup preserve order
    seen: set[str] = set()
    dedup: list[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup


@dataclass(frozen=True)
class Finding:
    fid: int
    title: str
    prio: str | None
    module: str | None
    files_raw: list[str]
    zeilen: str | None
    fix_lines: list[str]
    test_lines: list[str]


SECTION_PRIO_RE = re.compile(r"^\s*P([012])\s+—")
FINDING_RE = re.compile(r"^\[x\]\s+F(\d+)\s+—\s+(.*)$")


def extract_section(block: list[str], name: str) -> list[str]:
    out: list[str] = []
    in_sec = False
    for ln in block:
        if re.match(rf"^\s*{re.escape(name)}:\s*$", ln):
            in_sec = True
            continue
        if in_sec:
            if ln.strip() == "":
                break
            if re.match(
                r"^\s*(Risiko:|Fix:|Test:|Modul:|Datei:|Zeilen:|Confidence:|Prio:)\b", ln
            ):
                break
            out.append(ln.rstrip())
    return out


def parse_findings(lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    current_prio: str | None = None
    idx = 0
    while idx < len(lines):
        msec = SECTION_PRIO_RE.match(lines[idx])
        if msec:
            current_prio = f"P{msec.group(1)}"

        mf = FINDING_RE.match(lines[idx])
        if not mf:
            idx += 1
            continue

        start_prio = current_prio
        fid = int(mf.group(1))
        title = mf.group(2).strip()
        start = idx
        idx += 1

        # Consume until next finding header; update current_prio for subsequent findings,
        # but use start_prio snapshot for this finding (otherwise prio can be pulled from
        # the *next* section header).
        while idx < len(lines) and not FINDING_RE.match(lines[idx]):
            msec = SECTION_PRIO_RE.match(lines[idx])
            if msec:
                current_prio = f"P{msec.group(1)}"
            idx += 1

        block = lines[start:idx]

        module = None
        files_raw: list[str] = []
        zeilen = None
        prio = None
        for ln in block:
            mm = re.search(r"\bModul:\s*(.*)$", ln)
            if mm and not module:
                module = mm.group(1).strip()
            md = re.search(r"\bDatei:\s*(.*)$", ln)
            if md:
                files_raw.append(md.group(1).strip())
            mz = re.search(r"\bZeilen:\s*(.*)$", ln)
            if mz and not zeilen:
                zeilen = mz.group(1).strip()
            mp = re.search(r"\bPrio:\s*(P[012])\b", ln)
            if mp and not prio:
                prio = mp.group(1)
        if prio is None:
            prio = start_prio

        findings.append(
            Finding(
                fid=fid,
                title=title,
                prio=prio,
                module=module,
                files_raw=files_raw,
                zeilen=zeilen,
                fix_lines=extract_section(block, "Fix"),
                test_lines=extract_section(block, "Test"),
            )
        )
    return findings


def is_camel(s: str) -> bool:
    return bool(re.match(r"^[A-Z][A-Za-z0-9]+$", s))


def is_const(s: str) -> bool:
    return s.isupper() and "_" in s and any(c.isalpha() for c in s)


STOP_LOWER = {
    "und",
    "oder",
    "mit",
    "von",
    "auf",
    "in",
    "bei",
    "als",
    "wenn",
    "dann",
    "nur",
    "kein",
    "keine",
    "nicht",
    "ist",
    "sind",
    "muss",
    "soll",
    "wird",
    "werden",
    "liefert",
    "liefern",
    "ablehnen",
    "abgelehnt",
    "abbrechen",
    "starten",
    "startet",
    "pruefen",
    "prueft",
    "versuch",
    "versuche",
    "simuliert",
    "simulierter",
    "parallel",
    "parallele",
    "manuell",
    "risiko",
    "fix",
    "test",
    "datei",
    "zeilen",
    "modul",
    "confidence",
    "prio",
    "funktion",
    "endpoint",
    "endpoints",
    "http",
    "tls",
    "metrics",
    "mempool",
    "pow",
    "p2p",
    "node",
    "gui",
    "tui",
    "validator",
    "seed",
    "default",
    "gleich",
    "gleiche",
    "zweiter",
    "erster",
    "response",
    "request",
    "error",
    "ausgeben",
    "ausgabe",
    "anzeigen",
    "nutzen",
    "nutze",
    "verwenden",
    "verwendet",
    "verwendung",
    "verwende",
    "innerhalb",
    "nach",
    "vor",
    "ab",
}

STOP_EXACT = {
    "HTTP",
    "TLS",
    "Endpoint",
    "Endpoints",
    "Metrics",
    "Mempool",
    "PoW",
    "P2P",
    "Node",
    "GUI",
    "TUI",
    "Validator",
}


OVERRIDE_CODE_ANCHORS: dict[int, list[str]] = {
    1: ["status_serve_handle_request_inner", "make_svc"],
    3: ["metrics_addr", "is_loopback"],
    17: ["mint_seeds", "create_new(true)"],
    19: ["Persist mint into mempool_dir/mints", "mints_dir"],
    20: ["mint_seeds", "seed reservation"],
    24: ["resolve_import_secret_hex", "secret_hex"],
    25: ["stderr().is_terminal"],
    38: ["seat_vote_sign_with_hsm", "protocol-required Schnorr"],
    58: ["inbound_incoming_and_incomingfrom_are_equivalent", "IncomingFrom"],
    59: ["rocksdb_store_ttl_cleanup"],
    60: ["dedupe_insert_capped"],
    68: ["StdRng", "seed_from_u64"],
    72: ["U2fHidCommunication", "encode(msg"],
    74: ["scan_stealth_payments requires spend_secret"],
}


def extract_candidate_tokens(f: Finding) -> list[str]:
    toks: list[str] = []
    if f.zeilen:
        m = re.search(r"\(([^)]*)\)", f.zeilen)
        if m:
            toks += re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", m.group(1))

    title = f.title
    toks += re.findall(r"--[A-Za-z0-9_-]+", title)
    toks += re.findall(r"/[A-Za-z0-9_\-/]+", title)
    toks += re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", title)

    blob = "\n".join(f.fix_lines + f.test_lines)
    toks += re.findall(r"--[A-Za-z0-9_-]+", blob)
    toks += re.findall(r"/[A-Za-z0-9_\-/]+", blob)
    toks += re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", blob)

    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def iter_anchor_variants(tok: str) -> list[str]:
    out = [tok]
    if tok.startswith("--"):
        raw = tok[2:]
        out += [raw, raw.replace("-", "_")]
    if "-" in tok:
        out.append(tok.replace("-", "_"))
    if "::" in tok:
        out.append(tok.split("::")[-1])
    seen: set[str] = set()
    uniq: list[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


_file_cache: dict[Path, list[str] | None] = {}


def get_lines(p: Path) -> list[str] | None:
    if p in _file_cache:
        return _file_cache[p]
    try:
        data = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        data = None
    _file_cache[p] = data
    return data


def find_in_file(p: Path, needle: str) -> int | None:
    data = get_lines(p)
    if not data:
        return None
    for i, ln in enumerate(data, start=1):
        if needle in ln:
            return i
    return None


def pick_code_evidence(f: Finding) -> str | None:
    paths = [
        p
        for p in parse_file_paths(f.files_raw)
        if (ROOT / p).exists() and (ROOT / p).is_file()
    ]
    if not paths:
        return None

    ranked: list[str] = []
    ranked += OVERRIDE_CODE_ANCHORS.get(f.fid, [])
    for t in extract_candidate_tokens(f):
        if t in STOP_EXACT:
            continue
        tl = t.lower().strip("-/ ")
        if tl in STOP_LOWER:
            continue
        keep = False
        if "_" in t:
            keep = True
        elif t.startswith("/") or t.startswith("--"):
            keep = True
        elif is_const(t) and len(t) >= 8:
            keep = True
        elif is_camel(t) and len(t) >= 4:
            keep = True
        if not keep:
            continue
        ranked.append(t)

    # de-dup preserve order
    seen: set[str] = set()
    ranked2: list[str] = []
    for t in ranked:
        if t not in seen:
            seen.add(t)
            ranked2.append(t)

    for p in paths:
        pp = ROOT / p
        for t in ranked2:
            for v in iter_anchor_variants(t):
                ln = find_in_file(pp, v)
                if ln is not None:
                    return f"{p}:{ln} (anchor: {v})"
    return paths[0]


def build_test_index() -> dict[str, list[tuple[Path, int]]]:
    rust_files = [
        p
        for p in ROOT.rglob("*.rs")
        if "target/" not in str(p)
        and (str(p).startswith("crates/") or str(p).startswith("apps/"))
    ]
    test_attr_re = re.compile(r"^\s*#\[(tokio::test|test|async_std::test)\]")
    fn_re = re.compile(
        r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )

    test_index: dict[str, list[tuple[Path, int]]] = {}
    for p in rust_files:
        data = get_lines(p)
        if not data:
            continue
        pending = 0
        for i, ln in enumerate(data, start=1):
            if test_attr_re.match(ln):
                pending = 6
                continue
            if pending > 0:
                pending -= 1
                m = fn_re.match(ln)
                if m:
                    name = m.group(1)
                    test_index.setdefault(name, []).append((p, i))
                    pending = 0
    return test_index


OVERRIDE_TEST_NAMES: dict[int, list[str]] = {
    1: ["f1_status_serve_http_and_tls_share_one_inner_handler"],
    2: ["a2_accepts_apply_mint_with_future_telemetry_time"],
    3: ["p2p_quic_listen_metrics_smoke"],
    4: ["journal_recovery_roundtrip", "journal_recovery_ignores_truncated_tail_record"],
    17: ["f17_parallel_mint_submissions_with_same_seed_only_one_is_accepted"],
    19: ["f19_f20_standalone_mint_rpc_persists_mint_and_rejects_seed_replay"],
    20: ["f19_f20_standalone_mint_rpc_persists_mint_and_rejects_seed_replay"],
    24: ["resolve_import_secret_hex_rejects_secret_hex_in_release_builds"],
    25: ["f25_wallet_init_refuses_seed_output_without_tty_on_stderr"],
    26: ["f26_hwi_signmessage_rejects_message_starting_with_dash"],
    27: [
        "resolve_bitbox2_signer_rejects_relative_env_path_in_release_builds",
        "resolve_bitbox2_signer_allows_relative_env_path_in_debug_builds",
    ],
    29: ["classify_broadcast_state_error_double_spend"],
    34: ["resolve_node_config_uses_config_node_url_when_cli_is_default"],
    38: ["seat_vote_sign_with_hsm_is_fail_closed_without_schnorr_mechanism"],
    39: ["test_validate_response_rejects_sender_output_replacement"],
    40: ["test_privacy_validator_allows_duplicate_amounts"],
    42: ["open_locked_rejects_wrong_passphrase_with_marker"],
    43: ["test_pc_uri_parsing"],
    44: ["test_initiate_rejects_non_https_non_loopback_endpoint"],
    46: ["to_toml_file_sets_private_permissions"],
    48: ["get_payload_rejects_oversized_file"],
    49: ["bool_decode_non_canonical_rejected"],
    58: ["inbound_incoming_and_incomingfrom_are_equivalent"],
    59: ["rocksdb_store_ttl_cleanup"],
    60: ["f60_dedupe_insert_capped_keeps_new_key_and_caps_len"],
    64: ["merge_limits_new_peers_per_call"],
    65: ["seed_store_path_for_wallet_db_ok"],
    67: ["blocked_peers_persist_roundtrip_and_expiry"],
    68: ["deterministic_with_fixed_seed"],
    66: ["f66_inmemory_store_caps_headers_len"],
    72: ["u2fhid_write_rejects_oversized_message_without_panic"],
    74: ["test_scan_without_spend_secret_is_rejected"],
    75: ["overlay_del_reports_true_only_when_key_exists"],
    76: ["readyz_check_mempool_dir_uses_blocking_bridge_and_reports_errors"],
    78: [
        "committee_seed_anchor_none_without_finalized_root_or_genesis",
        "committee_seed_anchor_prefers_last_final_payload_root",
    ],
    79: ["test_save_stealth_keys_is_encrypted_on_disk"],
    81: ["open_locked_rejects_malformed_legacy_entry_during_migration"],
    84: [
        "committee_seed_is_deterministic",
        "committee_hash_selection_is_deterministic",
        "committee_hash_filters_below_min_stake",
        "committee_hash_enforces_operator_dedup",
        "committee_hash_rejects_invalid_bls_pop",
        "committee_hash_empty_candidates_returns_empty",
    ],
    86: ["prune_old_utxos_removes_entries_without_minted_at"],
    87: ["validator_stake_lock_index_tracks_put_update_and_delete"],
    83: ["restore_snapshot_clears_existing_state_before_apply"],
    90: ["status_color_keywords"],
    94: ["seed_store_path_resolves_to_phantom_seeds_dir"],
    95: ["next_address_index_errors_on_overflow"],
    96: ["execute_send_errors_on_amount_plus_fee_overflow"],
    97: ["execute_send_errors_on_invalid_fee_instead_of_silent_zero"],
    118: ["pending_dedup_attaches_waiters"],
    119: ["unsolicited_payload_response_is_ignored"],
}


def pick_test_evidence(f: Finding, test_index: dict[str, list[tuple[Path, int]]]) -> str | None:
    blob = "\n".join(f.test_lines)
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", blob)
    cands: list[str] = []
    for t in toks:
        if t.lower() in STOP_LOWER:
            continue
        if "_" in t or t.startswith("e2e_") or re.match(r"^[aA]\d+_", t):
            cands.append(t)

    # Prepend overrides while preserving the given override order.
    cands = list(OVERRIDE_TEST_NAMES.get(f.fid, [])) + cands

    seen: set[str] = set()
    uniq: list[str] = []
    for t in cands:
        if t not in seen:
            seen.add(t)
            uniq.append(t)

    for t in uniq:
        if t in test_index:
            p, line = test_index[t][0]
            return f"{p.relative_to(ROOT)}:{line} (test: {t})"

    # Last-resort deterministic mapping: allow tests named f<id>_* to attach to finding <id>.
    # This keeps the evidence strict while reducing the need for per-finding override entries.
    pref = f"f{f.fid}_"
    for name in sorted(test_index.keys()):
        if name.startswith(pref):
            p, line = test_index[name][0]
            return f"{p.relative_to(ROOT)}:{line} (test: {name})"
    return None


def main() -> int:
    if not AUDIT_PATH.exists():
        raise SystemExit(f"missing {AUDIT_PATH}")

    findings = parse_findings(AUDIT_PATH.read_text(encoding="utf-8").splitlines())
    test_index = build_test_index()

    out: list[str] = []
    out.append("# Phantom-Coin Audit Evidence Matrix")
    out.append("")
    out.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out.append("")
    out.append("Verification baseline (run manually before trusting this document):")
    out.append("- `cargo fmt --all -- --check`")
    out.append("- `cargo test --workspace`")
    out.append("- `cargo test --workspace --all-targets --no-run`")
    out.append("")
    head = "unknown"
    branch = "unknown"
    try:
        head = (
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
            .decode("utf-8", errors="replace")
            .strip()
        )
        branch = (
            subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT)
            .decode("utf-8", errors="replace")
            .strip()
        )
    except Exception:
        pass

    out.append("Repo state:")
    out.append(f"- HEAD: `{head}`")
    out.append(f"- Branch: `{branch}`")
    out.append("")
    out.append("Legend:")
    out.append("- `Code Evidence` points to an anchor inside the audit-referenced file(s) when possible.")
    out.append(
        "- `Test Evidence` only lists real Rust tests (functions preceded by `#[test]`/`#[tokio::test]`)."
    )
    out.append("")

    for f in sorted(findings, key=lambda x: x.fid):
        out.append(f"## F{f.fid} ({f.prio}) — {f.title}")
        out.append("")
        if f.module:
            out.append(f"- Module: `{f.module}`")
        for fr in f.files_raw:
            out.append(f"- Audit File: `{fr}`")
        if f.zeilen:
            out.append(f"- Audit Lines: `{f.zeilen}`")

        code_ev = pick_code_evidence(f)
        out.append(
            f"- Code Evidence: `{code_ev}`"
            if code_ev
            else "- Code Evidence: (missing file reference; manual spot-check required)"
        )

        test_ev = pick_test_evidence(f, test_index)
        if test_ev:
            out.append(f"- Test Evidence: `{test_ev}`")
        else:
            if f.test_lines:
                spec = " ".join(s.strip() for s in f.test_lines if s.strip())
                if spec:
                    out.append(f"- Test Spec (audit): {spec}")
            out.append("- Test Evidence: (no matching Rust test found; manual spot-check required)")

        if f.fid == 38:
            out.append(
                "- Note: PKCS#11 seat vote signing is fail-closed (Schnorr required). This is consensus-safe, but HSM voting is disabled until a Schnorr-capable mechanism exists."
            )
        out.append("")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
