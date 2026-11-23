import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "beacon/scripts/check-version.py"


class VersionCheckTest(unittest.TestCase):
    def run_check(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_repository_baseline_is_consistent(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Beacon Python ", result.stdout)
        self.assertIn("Contrib ", result.stdout)
        self.assertIn("Core ", result.stdout)

    def test_rejects_wheel_with_different_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "beacon_profiling-9.9.9-py3-none-any.whl"
            with ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "beacon_profiling-9.9.9.dist-info/METADATA",
                    "Metadata-Version: 2.3\n"
                    "Name: beacon-profiling\n"
                    "Version: 9.9.9\n",
                )
            result = self.run_check("--wheel", str(wheel))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wheel version 9.9.9 differs", result.stderr)

    def test_release_tag_matches_release_state(self) -> None:
        version_file = ROOT / "beacon/version.properties"
        version = next(
            line.removeprefix("version=")
            for line in version_file.read_text(encoding="utf-8").splitlines()
            if line.startswith("version=")
        )
        result = self.run_check("--tag", f"v{version}")
        if ".dev" in version:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Only RC and final Beacon versions", result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)


class SecurityProvenanceTest(unittest.TestCase):
    checker: ModuleType

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("check_version", SCRIPT)
        assert spec is not None and spec.loader is not None
        self.checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checker)

    def test_rejects_missing_export_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            properties = Path(directory) / "security-spec.properties"
            properties.write_text(
                "\n".join(
                    line
                    for line in self.checker.SECURITY_PROPERTIES_FILE.read_text().splitlines()
                    if not line.startswith("exportProfile=")
                ),
                encoding="utf-8",
            )
            with patch.object(
                self.checker, "SECURITY_PROPERTIES_FILE", properties
            ):
                with self.assertRaisesRegex(
                    ValueError, "contract pin differs"
                ):
                    self.checker.check_security_provenance()

    def test_rejects_modified_schema_artifacts(self) -> None:
        paths = (
            "beacon-otel/src/beacon_security/siem-v1.schema.json",
            "beacon-otel/src/beacon_security/evidence.schema.json",
            "beacon-otel/tests/security/fixtures/spec/beacon-security-siem-v1.schema.json",
            "beacon-otel/tests/security/fixtures/spec/beacon-security-event-v2.schema.json",
        )
        for changed in paths:
            with (
                self.subTest(path=changed),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                for name in paths:
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, destination)
                (root / changed).write_text("{}", encoding="utf-8")
                with patch.object(self.checker, "ROOT", root):
                    with self.assertRaisesRegex(
                        ValueError, "Security .*differs"
                    ):
                        self.checker.check_security_provenance()


if __name__ == "__main__":
    unittest.main()
