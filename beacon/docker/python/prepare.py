"""Verify immutable public release wheels before building the distribution image."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True).strip()


def download(url: str) -> bytes:
    return subprocess.check_output(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
            "--max-time",
            "60",
            url,
        ]
    )


def main() -> None:
    version, target = sys.argv[1:]
    assert re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version)
    output = Path(target).resolve()
    output.mkdir(parents=True, exist_ok=True)
    assert not list(output.iterdir()), "Staging directory must be empty"
    repo = "beacon-observability/beacon-python"
    release = json.loads(gh("api", f"repos/{repo}/releases/tags/v{version}"))
    assert not release["draft"] and not release["prerelease"]
    assert release["tag_name"] == f"v{version}"
    commit = gh("api", f"repos/{repo}/commits/v{version}", "--jq", ".sha")
    assets = output / "assets"
    assets.mkdir()
    records = []
    for name in ("beacon-otel", "beacon-profiling"):
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        metadata = json.loads(
            download(f"https://pypi.org/pypi/{name}/{version}/json")
        )
        assert metadata["info"]["name"] == name
        assert metadata["info"]["version"] == version
        wheel = next(
            item for item in metadata["urls"] if item["filename"] == filename
        )
        assert not wheel["yanked"]
        assert wheel["url"].startswith("https://files.pythonhosted.org/")
        public_bytes = download(wheel["url"])
        digest = hashlib.sha256(public_bytes).hexdigest()
        assert digest == wheel["digests"]["sha256"]
        asset = next(
            item for item in release["assets"] if item["name"] == filename
        )
        expected_url = f"https://github.com/{repo}/releases/download/v{version}/{filename}"
        assert asset["browser_download_url"] == expected_url
        (assets / filename).write_bytes(download(expected_url))
        assert (assets / filename).read_bytes() == public_bytes
        records.append(
            {
                "name": name,
                "version": version,
                "file": filename,
                "sha256": digest,
                "url": wheel["url"],
            }
        )
        print(f"Verified {filename}: {digest}", flush=True)
    (output / "requirements.in").write_text(
        f"beacon-otel[profiling,requests]=={version}\n"
    )
    subprocess.check_call(
        [
            "uv",
            "--no-config",
            "pip",
            "compile",
            str(output / "requirements.in"),
            "--python-version",
            "3.13",
            "--universal",
            "--generate-hashes",
            "--no-emit-index-url",
            "--no-header",
            "--no-annotate",
            "--quiet",
            "--index-url",
            "https://pypi.org/simple",
            "--output-file",
            str(output / "requirements.lock"),
        ]
    )
    (output / "Dockerfile").write_bytes((HERE / "Dockerfile").read_bytes())
    provenance = {
        "version": version,
        "source_commit": commit,
        "release": release["html_url"],
        "runtime": "CPython 3.13 / Debian bookworm glibc",
        "resolver": subprocess.check_output(
            ["uv", "--version"], text=True
        ).strip(),
        "dependency_lock_sha256": hashlib.sha256(
            (output / "requirements.lock").read_bytes()
        ).hexdigest(),
        "artifacts": records,
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
