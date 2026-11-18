"""Build the committed, reproducible Python scanner bundle for Vercel.

Run this after changing scanner Python source or api/ephemeral.py:
    python scripts/build_session_runtime.py
CI can verify it without writing files:
    python scripts/build_session_runtime.py --check

Only scanner source and the stateless session service enter this archive.
Credentials, Terraform state, fixtures and application storage are excluded.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "web" / "scan-runtime.zip"
MANIFEST = ROOT / "web" / "scan-runtime.manifest.json"


def normalized_source(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def source_entries(root: Path = ROOT) -> list[tuple[str, str, bytes]]:
    sources = sorted((root / "scanner").rglob("*.py"))
    if not sources:
        raise ValueError("No scanner Python source was found.")
    entries = [(path.relative_to(root).as_posix(), path.relative_to(root).as_posix(),
                normalized_source(path)) for path in sources]
    service = root / "api" / "ephemeral.py"
    entries.append(("api/ephemeral.py", "lytascan_session.py", normalized_source(service)))
    return sorted(entries, key=lambda entry: entry[1])


def build_bundle(root: Path = ROOT) -> tuple[bytes, bytes]:
    entries = source_entries(root)
    target = io.BytesIO()
    # Stored entries keep bytes reproducible across Python/zlib versions.
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for _, name, contents in entries:
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, contents)
    bundle = target.getvalue()
    manifest = {
        "format_version": 1,
        "source_normalization": "utf8-lf",
        "archive": {"name": "scan-runtime.zip", "sha256": hashlib.sha256(bundle).hexdigest()},
        "files": [{"source": source, "path": name, "sha256": hashlib.sha256(contents).hexdigest()}
                  for source, name, contents in entries],
    }
    return bundle, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify the committed bundle without writing it.")
    args = parser.parse_args()
    try:
        bundle, manifest = build_bundle()
    except (OSError, ValueError) as error:
        print(f"Cannot build the session scanner bundle: {error}", file=sys.stderr)
        return 1
    artifacts = ((ARCHIVE, bundle), (MANIFEST, manifest))
    stale = [path for path, contents in artifacts if not path.is_file() or
             (normalized_source(path) if path == MANIFEST else path.read_bytes()) != contents]
    if args.check:
        if stale:
            print("Session scanner bundle is missing or stale. Run python scripts/build_session_runtime.py.", file=sys.stderr)
            return 1
        print("Session scanner bundle is current.")
        return 0
    for path, contents in artifacts:
        if path in stale:
            path.write_bytes(contents)
    print(f"Session scanner bundle ready ({len(bundle):,} bytes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
