import importlib.util
import json
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


def load_version_check() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_version", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load Beacon version check")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

    def test_rejects_all_extra_missing_an_individual_plugin(self) -> None:
        check = load_version_check()
        source = (ROOT / "beacon-otel/pyproject.toml").read_text(
            encoding="utf-8"
        )
        baseline = json.loads(
            (ROOT / "beacon/upstream.lock.json").read_text(encoding="utf-8")
        )["upstream"]["releaseTag"].removeprefix("v")
        source = source.replace(
            f'  "opentelemetry-instrumentation-redis == {baseline}",\n', ""
        )
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "pyproject.toml"
            project.write_text(source, encoding="utf-8")
            with patch.object(check, "BEACON_OTEL_PYPROJECT", project):
                with self.assertRaisesRegex(ValueError, "extras are stale"):
                    check.check_optional_dependencies(
                        check.product_version(), baseline
                    )

    def test_sync_updates_individual_and_all_extras_together(self) -> None:
        check = load_version_check()
        source = (ROOT / "beacon-otel/pyproject.toml").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "pyproject.toml"
            project.write_text(source, encoding="utf-8")
            with patch.object(check, "BEACON_OTEL_PYPROJECT", project):
                check.check_optional_dependencies("9.8.7", "0.99b0", sync=True)
                check.check_optional_dependencies("9.8.7", "0.99b0")
            updated = project.read_text(encoding="utf-8")
        self.assertEqual(
            updated.count("opentelemetry-instrumentation-redis == 0.99b0"), 2
        )
        self.assertEqual(updated.count("beacon-profiling == 9.8.7"), 1)
        self.assertNotIn("beacon-profiling", updated.split("all = [", 1)[1])

    def test_rejects_duplicate_extras_in_manifest(self) -> None:
        check = load_version_check()
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "extras.json"
            manifest.write_text('["redis", "redis"]', encoding="utf-8")
            with patch.object(check, "INSTRUMENTATION_EXTRAS_FILE", manifest):
                with self.assertRaisesRegex(ValueError, "unique and sorted"):
                    check.instrumentation_extras()


if __name__ == "__main__":
    unittest.main()
