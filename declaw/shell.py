"""declaw.shell — Subprocess, downloads and cached tool jars."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import os
import shutil
import subprocess as sp

import requests

from declaw.config import BUNDLETOOL_URL, PACKAGES_DIR, UTILS_DIR, log


def _run(cmd: list, *, check: bool = True, capture: bool = False) -> sp.CompletedProcess:
    log.debug("$ %s", " ".join(map(str, cmd)))
    return sp.run(list(map(str, cmd)), check=check, text=True, capture_output=capture)


# Big apps (Western Union, banking apps with 10+ dex files) blow out the JVM
# default heap and apktool / signer get OOM-killed. Override via env.
_JVM_HEAP = os.environ.get("DECLAW_JVM_HEAP", "4g")


def _java(*args: str) -> list:
    """Build a `java -Xmx... -jar ... <args>` command line."""
    return ["java", f"-Xmx{_JVM_HEAP}", *args]


# --------------------------------------------------------------------------- #
#  Network / caching                                                          #
# --------------------------------------------------------------------------- #

def _gh_latest(api_url: str) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(api_url, timeout=30, headers=headers)
    r.raise_for_status()
    return r.json()


def _stream_download(url: str, dest: Path) -> None:
    log.info("Downloading %s", dest.name)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with requests.get(url, timeout=300, stream=True) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                if chunk:
                    fh.write(chunk)
    tmp.rename(dest)


_JAR_CACHE_PATTERNS = {
    "iBotPeaches/Apktool": "apktool_*.jar",
    "patrickfav/uber-apk-signer": "uber-apk-signer-*.jar",
    "google/bundletool": "bundletool-*.jar",
}


def _existing_cached_jar(api_url: str) -> Optional[Path]:
    for repo, pattern in _JAR_CACHE_PATTERNS.items():
        if repo in api_url:
            matches = sorted(UTILS_DIR.glob(pattern))
            return matches[-1] if matches else None
    return None


def _cached_jar(api_url: str, *, refresh: bool) -> Path:
    # Fast path: cached file already present and user did not ask to refresh.
    # Avoids a GitHub API round-trip on every run (and lets declaw work offline).
    if not refresh:
        existing = _existing_cached_jar(api_url)
        if existing is not None:
            log.debug("Using cached %s", existing.name)
            return existing
    info = _gh_latest(api_url)
    asset = next((a for a in info.get("assets", []) if a["name"].endswith(".jar")), None)
    if asset is None:
        raise RuntimeError(f"No .jar asset found at {api_url}")
    dest = UTILS_DIR / asset["name"]
    if dest.exists() and not refresh:
        log.debug("Using cached %s", dest.name)
        return dest
    _stream_download(asset["browser_download_url"], dest)
    return dest


def fetch_bundletool(*, refresh: bool) -> Path:
    """Return a cached bundletool jar (for .aab -> .apks conversion)."""
    # Offline fast path: reuse a cached bundletool-*.jar without a GitHub round
    # trip (matters for air-gapped runs; see DECLAW_BYPASS_URLS docstring).
    if not refresh:
        cached = sorted(UTILS_DIR.glob("bundletool-*.jar"))
        if cached:
            log.debug("Using cached %s", cached[-1].name)
            return cached[-1]
    info = _gh_latest(BUNDLETOOL_URL)
    asset = next((a for a in info.get("assets", []) if a["name"].endswith(".jar")), None)
    if asset is None:
        raise RuntimeError("No bundletool jar found in latest release")
    dest = UTILS_DIR / asset["name"]
    if dest.exists() and not refresh:
        log.debug("Using cached %s", dest.name)
        return dest
    _stream_download(asset["browser_download_url"], dest)
    return dest


def _bundletool_cmd(jar: Path, *args: str) -> list:
    return _java("-jar", str(jar), *args)


def convert_aab(aab: Path, *, refresh: bool) -> Path:
    """Convert a Google .aab into a universal .apks set via bundletool.

    Returns the path to the generated .apks (a zip with a single
    universal.apk inside), ready to be fed through extract_bundle().
    bundletool signs with an auto-generated debug key; uber-apk-signer
    re-signs everything later so the key doesn't matter.
    """
    bundletool_jar = fetch_bundletool(refresh=refresh)
    out_dir = PACKAGES_DIR / f"{aab.stem}_aab"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    apks_out = out_dir / f"{aab.stem}.apks"
    log.info("Converting %s to universal APKs via bundletool", aab.name)
    _run(_bundletool_cmd(
        bundletool_jar,
        "build-apks",
        f"--bundle={aab}",
        f"--output={apks_out}",
        "--mode=universal",
    ))
    return apks_out
