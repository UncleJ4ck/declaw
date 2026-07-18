"""declaw.reflutter — reFlutter prebuilt-engine static Flutter patch."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import os
import shutil

import requests

from declaw.config import REFLUTTER_ABI_MAP, REFLUTTER_CSV_URL, REFLUTTER_MIN_VERSION, REFLUTTER_RELEASE_URL, UTILS_DIR, log
from declaw.shell import _stream_download
from declaw.manifest import ApkInspection


# --------------------------------------------------------------------------- #
#  Flutter static patch via reFlutter                                         #
# --------------------------------------------------------------------------- #

def _fetch_reflutter_engine_map(refresh: bool) -> dict[str, str]:
    """Return {snapshot_hash_hex: flutter_version}."""
    cache = UTILS_DIR / "reflutter-enginehash.csv"
    if not cache.exists() or refresh:
        _stream_download(REFLUTTER_CSV_URL, cache)
    mapping: dict[str, str] = {}
    for line in cache.read_text(encoding="utf-8").splitlines()[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3:
            version, _commit, snap = parts[:3]
            if version and snap:
                mapping[snap.lower()] = version
    return mapping


def _flutter_version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return (0, 0, 0)


def _find_flutter_snapshot_hash(libflutter: Path, known: dict[str, str]) -> Optional[str]:
    """Scan the libflutter.so bytes for any known snapshot hash."""
    data = libflutter.read_bytes()
    for h in known:
        if h.encode() in data:
            return h
    return None


def try_patch_flutter_static(
    unpacked: Path,
    inspection: ApkInspection,
    *,
    refresh: bool,
) -> bool:
    """Swap in reFlutter's pre-patched libflutter.so when the engine
    snapshot hash is known. Returns True if any ABI was patched."""
    if "flutter" not in inspection.frameworks:
        return False
    if os.environ.get("DECLAW_FLUTTER_STATIC", "1") == "0":
        log.info("Flutter static patch disabled by DECLAW_FLUTTER_STATIC=0.")
        return False
    try:
        known = _fetch_reflutter_engine_map(refresh=refresh)
    except requests.RequestException as exc:
        log.warning("reFlutter hash table fetch failed (%s). Falling back to Frida hooks.", exc)
        return False

    patched_any = False
    for abi in sorted(inspection.abis):
        if abi not in REFLUTTER_ABI_MAP:
            continue  # reFlutter publishes arm / arm64 only
        libflutter = unpacked / "lib" / abi / "libflutter.so"
        if not libflutter.exists():
            continue
        snap = _find_flutter_snapshot_hash(libflutter, known)
        if not snap:
            log.info("Flutter: unknown engine hash in lib/%s/, relying on Frida script.", abi)
            continue
        version = known[snap]
        if _flutter_version_tuple(version) < REFLUTTER_MIN_VERSION:
            log.info("Flutter %s (lib/%s/) has hardcoded proxy in reFlutter's patch, skipping.",
                     version, abi)
            continue
        arch = REFLUTTER_ABI_MAP[abi]
        cache = UTILS_DIR / f"reflutter-libflutter-{snap}-{arch}.so"
        if not cache.exists() or refresh:
            try:
                _stream_download(REFLUTTER_RELEASE_URL.format(hash=snap, arch=arch), cache)
            except requests.RequestException as exc:
                log.warning("reFlutter asset download failed for %s / %s (%s). Falling back.",
                            version, arch, exc)
                continue
        shutil.copy2(cache, libflutter)
        log.info("Flutter: replaced lib/%s/libflutter.so with reFlutter engine %s",
                 abi, version)
        patched_any = True
    return patched_any
