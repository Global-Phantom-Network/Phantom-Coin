#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Reproducible packaging for PhantomCoin release artifacts
# Usage:
#   scripts/release/repro_package.sh \
#     --bin target/release/phantom-node \
#     --docs ./docs \
#     --out phantomcoin-vX.Y.Z-linux-x86_64.tar.gz

BIN=""
DOCS_DIR=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      BIN="$2"; shift 2 ;;
    --docs)
      DOCS_DIR="$2"; shift 2 ;;
    --out)
      OUT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$BIN" || -z "$DOCS_DIR" || -z "$OUT" ]]; then
  echo "Missing required args. See script header for usage." >&2
  exit 2
fi

if [[ ! -f "$BIN" ]]; then
  echo "Binary not found: $BIN" >&2
  exit 2
fi
if [[ ! -d "$DOCS_DIR" ]]; then
  echo "Docs dir not found: $DOCS_DIR" >&2
  exit 2
fi

"$ROOT_DIR/scripts/security/scan_runtime_artifacts.sh" --root "$ROOT_DIR"

# Prepare staging dir
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT
mkdir -p "$STAGE_DIR/dist"

cp "$BIN" "$STAGE_DIR/dist/"
cp -r "$DOCS_DIR" "$STAGE_DIR/dist/docs"

# Strip platform-local junk files from the staged artifact tree.
find "$STAGE_DIR/dist" \( -name '.DS_Store' -o -name 'Thumbs.db' \) -delete

"$ROOT_DIR/scripts/security/scan_runtime_artifacts.sh" --root "$STAGE_DIR/dist"

# Prefer gnu tar if available on macOS
TAR_BIN="tar"
if command -v gtar >/dev/null 2>&1; then
  TAR_BIN="gtar"
fi

if [[ "$TAR_BIN" == "gtar" ]]; then
  # Reproducible archive via GNU tar: sorted entries, mtime=0, uid/gid=0, gzip no timestamp
  ( cd "$STAGE_DIR/dist" && \
    "$TAR_BIN" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - . \
    | gzip -n > "$OUT" )
else
  # macOS/BSD tar lacks the required reproducibility flags; use Python tarfile + gzip instead.
  python3 - "$STAGE_DIR/dist" "$OUT" <<'PY'
import gzip
import os
import stat
import sys
import tarfile
from pathlib import Path

src = Path(sys.argv[1])
out = Path(sys.argv[2])

def add_path(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    st = path.lstat()
    info = tarfile.TarInfo(arcname)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = stat.S_IMODE(st.st_mode)

    if path.is_symlink():
      info.type = tarfile.SYMTYPE
      info.linkname = os.readlink(path)
      tar.addfile(info)
      return

    if path.is_dir():
      info.type = tarfile.DIRTYPE
      tar.addfile(info)
      return

    info.size = st.st_size
    with path.open("rb") as fh:
      tar.addfile(info, fh)

with out.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            paths = [src] + sorted(src.rglob("*"))
            for path in paths:
                rel = path.relative_to(src)
                arcname = "." if rel == Path(".") else f"./{rel.as_posix()}"
                add_path(tar, path, arcname)
PY
fi

# Output SHA256
sha256sum "$OUT" || shasum -a 256 "$OUT" || true

echo "Created reproducible package: $OUT"
