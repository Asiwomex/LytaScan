"""The deployable session scanner must match source and run without the checkout."""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

from scripts.build_session_runtime import ARCHIVE, MANIFEST, ROOT, build_bundle, normalized_source


def test_bundle_is_deterministic_and_limits_its_contents(tmp_path):
    (tmp_path / "scanner").mkdir()
    (tmp_path / "api").mkdir()
    (tmp_path / "scanner" / "__init__.py").write_bytes(b"# scanner\r\n")
    (tmp_path / "api" / "ephemeral.py").write_bytes(b"VALUE = 42\r\n")
    (tmp_path / "api" / "app.py").write_text("DO_NOT_BUNDLE = True\n")
    (tmp_path / ".env").write_text("EXAMPLE_SECRET=excluded\n")

    bundle, manifest = build_bundle(tmp_path)
    assert (bundle, manifest) == build_bundle(tmp_path)
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        assert archive.namelist() == ["lytascan_session.py", "scanner/__init__.py"]
        assert archive.read("lytascan_session.py") == b"VALUE = 42\n"
        assert all(entry.date_time == (1980, 1, 1, 0, 0, 0) for entry in archive.infolist())
    assert [file["source"] for file in json.loads(manifest)["files"]] == [
        "api/ephemeral.py", "scanner/__init__.py",
    ]


def test_committed_session_bundle_matches_the_scanner():
    bundle, manifest = build_bundle(ROOT)
    assert ARCHIVE.read_bytes() == bundle, "Run python scripts/build_session_runtime.py"
    assert normalized_source(MANIFEST) == manifest, "Run python scripts/build_session_runtime.py"


def test_bundle_imports_and_discovers_rules_outside_the_checkout(tmp_path):
    # Isolated mode and an unrelated working directory ensure the package is
    # loaded from the deployed archive rather than accidentally from this repo.
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import lytascan_session; "
        "from scanner.engine import discover_checks; "
        "checks = discover_checks(include_v2=True); "
        "assert len(checks) >= 60; "
        "assert len({check.meta.pillar for check in checks}) == 6; "
        "assert '.zip' in lytascan_session.__file__; "
        "print(len(checks))"
    )
    result = subprocess.run([sys.executable, "-I", "-c", script, str(ARCHIVE)],
                            cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip()) >= 60
