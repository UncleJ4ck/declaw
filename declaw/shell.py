"""declaw.shell — Subprocess, downloads and cached tool jars."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import hashlib
import os
import re
import shutil
import subprocess as sp

import requests

from declaw.config import BUNDLETOOL_URL, PACKAGES_DIR, UTILS_DIR, log

# Hard ceiling on any child process so a wedged adb/apktool/npm cannot hang declaw
# forever. Generous (a big apktool build or install is minutes, not this); override
# for pathological cases. hwbp.py/capture.py set their own tighter per-call timeouts.
_SUBPROCESS_TIMEOUT = float(os.environ.get("DECLAW_SUBPROCESS_TIMEOUT", "1200"))


def _run(cmd: list, *, check: bool = True, capture: bool = False,
         timeout: Optional[float] = None) -> sp.CompletedProcess:
    log.debug("$ %s", " ".join(map(str, cmd)))
    return sp.run(list(map(str, cmd)), check=check, text=True, capture_output=capture,
                  timeout=timeout if timeout is not None else _SUBPROCESS_TIMEOUT)


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


def _stream_download(url: str, dest: Path, *, expected_digest: Optional[str] = None) -> None:
    """Stream `url` to `dest` atomically, optionally verifying its SHA-256.

    expected_digest, when given, is GitHub's release-asset digest in the form
    "sha256:<hex>" (the releases API returns it per asset). The hash is computed
    over the bytes as they stream and the file is only moved into place when it
    matches; a mismatch unlinks the partial and raises. This guards a download at
    fetch time against a corrupted or truncated transfer and CDN drift. It is not
    a defense against an upstream or transport compromise: whoever can rewrite the
    downloaded bytes can rewrite the digest the API hands us. Cached files taken
    by the caller's dest.exists() fast path are not re-checked. An unknown-algo
    prefix or None skips the check, which keeps non-GitHub / offline-bypass URLs
    (which carry no digest) working."""
    log.info("Downloading %s", dest.name)
    h = None
    if expected_digest and expected_digest.startswith("sha256:"):
        want = expected_digest.split(":", 1)[1].strip().lower()
        h = hashlib.sha256()
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with requests.get(url, timeout=300, stream=True) as resp:
            resp.raise_for_status()
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1 << 20):
                    if chunk:
                        fh.write(chunk)
                        if h is not None:
                            h.update(chunk)
        if h is not None and h.hexdigest() != want:
            raise RuntimeError(
                f"{dest.name}: sha256 mismatch (expected {want}, got {h.hexdigest()})")
        tmp.rename(dest)
    except BaseException:
        # a mid-stream drop or a failed integrity check must not leave a partial
        # .part orphan behind for the next run to trip over; the caller retries.
        tmp.unlink(missing_ok=True)
        raise


_JAR_CACHE_PATTERNS = {
    "iBotPeaches/Apktool": "apktool_*.jar",
    "patrickfav/uber-apk-signer": "uber-apk-signer-*.jar",
    "google/bundletool": "bundletool-*.jar",
}


def _jar_version_key(name: str) -> tuple[int, ...]:
    """Numeric version tuple from a jar filename, so 2.11.1 sorts above 2.9.3
    (a lexicographic sort picks 2.9.3, the stale one)."""
    return tuple(int(n) for n in re.findall(r"\d+", name))


def _newest_jar(matches: list[Path]) -> Optional[Path]:
    return max(matches, key=lambda p: _jar_version_key(p.name)) if matches else None


def _existing_cached_jar(api_url: str) -> Optional[Path]:
    for repo, pattern in _JAR_CACHE_PATTERNS.items():
        if repo in api_url:
            return _newest_jar(list(UTILS_DIR.glob(pattern)))
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
    _stream_download(asset["browser_download_url"], dest,
                     expected_digest=asset.get("digest"))
    return dest


def fetch_bundletool(*, refresh: bool) -> Path:
    """Return a cached bundletool jar (for .aab -> .apks conversion).

    bundletool is just another google/* release jar, so the generic _cached_jar
    path handles it: same newest-cache glob (see _JAR_CACHE_PATTERNS), same GitHub
    round-trip, same digest verification. Kept as a named wrapper for the callers
    that read as "get me bundletool"."""
    return _cached_jar(BUNDLETOOL_URL, refresh=refresh)


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
