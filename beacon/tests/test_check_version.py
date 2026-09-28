import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
