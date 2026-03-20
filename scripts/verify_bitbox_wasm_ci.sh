#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="wasm32-unknown-unknown"
TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable-x86_64-apple-darwin}"

if [[ "$(uname -s)" == "Linux" ]]; then
  TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required for the optional bitbox-api wasm verification path" >&2
  exit 1
fi

rustup target add --toolchain "$TOOLCHAIN" "$TARGET" >/dev/null

detect_llvm_bindir() {
  if [[ -n "${LLVM_BINDIR:-}" && -x "${LLVM_BINDIR}/clang" ]]; then
    printf '%s\n' "$LLVM_BINDIR"
    return 0
  fi
  if command -v llvm-config >/dev/null 2>&1; then
    local bindir
    bindir="$(llvm-config --bindir 2>/dev/null || true)"
    if [[ -n "$bindir" && -x "$bindir/clang" ]]; then
      printf '%s\n' "$bindir"
      return 0
    fi
  fi
  for bindir in /usr/local/opt/llvm/bin /opt/homebrew/opt/llvm/bin /usr/lib/llvm-18/bin /usr/lib/llvm-17/bin /usr/lib/llvm-16/bin; do
    if [[ -x "$bindir/clang" ]]; then
      printf '%s\n' "$bindir"
      return 0
    fi
  done
  return 1
}

if [[ -z "${CC_wasm32_unknown_unknown:-}" || -z "${AR_wasm32_unknown_unknown:-}" ]]; then
  if llvm_bindir="$(detect_llvm_bindir)"; then
    export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-$llvm_bindir/clang}"
    export AR_wasm32_unknown_unknown="${AR_wasm32_unknown_unknown:-$llvm_bindir/llvm-ar}"
  fi
fi

if [[ -z "${CC_wasm32_unknown_unknown:-}" ]] || [[ ! -x "${CC_wasm32_unknown_unknown}" ]]; then
  echo "missing wasm C compiler: set CC_wasm32_unknown_unknown or install LLVM clang" >&2
  exit 1
fi

if [[ -z "${AR_wasm32_unknown_unknown:-}" ]] || [[ ! -x "${AR_wasm32_unknown_unknown}" ]]; then
  echo "missing wasm archiver: set AR_wasm32_unknown_unknown or install LLVM llvm-ar" >&2
  exit 1
fi

if ! "$CC_wasm32_unknown_unknown" --print-targets 2>/dev/null | grep -q "wasm32"; then
  echo "configured clang does not advertise wasm32 target support: $CC_wasm32_unknown_unknown" >&2
  exit 1
fi

export PATH="$HOME/.cargo/bin:$PATH"

rustup run "$TOOLCHAIN" cargo check -p bitbox-api --target "$TARGET" --features wasm

