"""declaw.boringssl_patch — static cert-verify patch machinery for a bundled
BoringSSL .so. Byte-exact, unit-tested, AND validated end-to-end against a real
BoringSSL (2026-07-06): patching bssl::ssl_verify_peer_cert in a from-source
libssl.so made a verifying client accept a self-signed cert (unpatched rejected
it, verify_result=18); negative control clean. See research/boringssl-patch/.

The intent: overwrite ``ssl_verify_peer_cert``'s prologue so it returns
``ssl_verify_ok`` (0) unconditionally. IF the given offset is really that
function, BoringSSL then accepts any certificate chain, defeating native cert
pinning with NO runtime injection (the patched .so ships inside the repackaged
APK, so there is no frida/gadget for anti-frida to see). This would be the
non-rooted counterpart to --hwbp-capture.

What is proven: the 8-byte AArch64 stub is correct and the APK rewrite is
byte-exact (tests/test_boringssl_patch.py), AND that patching this exact function
defeats verification on a real BoringSSL (research/boringssl-patch/mitm_test.sh:
unpatched client rejects a self-signed cert, patched client completes the TLS 1.3
handshake with verify_result still nonzero). What is NOT proven: a full Android
repackage+re-sign+run against a real pinned app on a device (env-blocked here), and
locating the offset in a stripped release .so (this validation used from-source
symbols; a shipped app's BoringSSL is stripped, so the offset is still per-build
ground truth from utils/find_ssl_verify.js / BoringSecretHunter). Still NOT a PairIP
bypass: native integrity re-check catches the re-signed .so.

Scope, stated honestly:
  * This is the same trick reFlutter applies to libflutter's BoringSSL; declaw
    already covers Flutter that way and Java/OkHttp pinning via smali. This
    module generalizes it to a NON-Flutter bundled BoringSSL (e.g. a vendored
    libttboringssl.so, a bundled libcronet).
  * PairIP and similar packers re-verify the APK signature AND native lib
    integrity at runtime, so a patched+re-signed .so is detected and the app is
    killed. This path is therefore NOT a PairIP bypass. For PairIP, key
    extraction with --hwbp-capture (no file change) is the route.
  * ssl_verify_peer_cert is an internal, stripped function with no unique string
    anchor, so it cannot be located generically the way ssl_log_secret can. The
    offset is obtained per-build as ground truth from a frida run
    (utils/find_ssl_verify.js) and passed in. The patch itself is byte-exact and
    verified here.

arm64 only (the patch is AArch64 machine code).
"""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from declaw.config import log

# AArch64: `mov w0, #0` (MOVZ w0,#0 = 0x52800000) ; `ret` (0xd65f03c0), LE bytes.
# ssl_verify_ok == 0, returned in w0.
_PATCH = bytes([0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6])


def _apply_stub(buf: bytearray, offset: int, label: str) -> None:
    """Bounds- and ELF-check `buf`, then write the return-0 stub at `offset`.
    Refuses a non-ELF target: a wrong LIB@OFFSET would otherwise write 8 bytes
    into arbitrary data and silently corrupt the .so."""
    if offset < 0 or offset + len(_PATCH) > len(buf):
        raise ValueError(f"offset 0x{offset:x} out of range for {label} ({len(buf)} bytes)")
    if buf[:4] != b"\x7fELF":
        raise ValueError(f"{label} is not an ELF .so (wrong entry?); refusing to patch")
    buf[offset:offset + len(_PATCH)] = _PATCH


def patch_ssl_verify_peer_cert(so_path: Path, offset: int, *, out_path: Path | None = None) -> Path:
    """Write the return-ssl_verify_ok stub at `offset` in `so_path`.
    Returns the path written (out_path, or so_path in place)."""
    data = bytearray(Path(so_path).read_bytes())
    _apply_stub(data, offset, str(so_path))
    dst = Path(out_path) if out_path else Path(so_path)
    dst.write_bytes(bytes(data))
    return dst


def verify_patch(so_path: Path, offset: int) -> bool:
    """True iff the bytes at `offset` are exactly the return-0 stub."""
    with open(so_path, "rb") as fh:
        fh.seek(offset)
        return fh.read(len(_PATCH)) == _PATCH


def parse_spec(spec: str) -> tuple[str, int | None]:
    """'libssl.so@0x5aa30' -> ('libssl.so', 0x5aa30); 'libssl.so' or 'libssl.so@auto'
    -> ('libssl.so', None) meaning: auto-locate ssl_verify_peer_cert in that .so."""
    lib, _, off = spec.partition("@")
    if not lib:
        raise ValueError(f"--patch-boringssl expects LIB[@OFFSET], got {spec!r}")
    if not off or off.strip().lower() == "auto":
        return lib.strip(), None
    return lib.strip(), int(off, 0)


def _so_entries(zf: zipfile.ZipFile, lib_substr: str) -> list[str]:
    # arm64 only: the stub is AArch64 machine code and the offset is per-ABI, so
    # never touch armeabi-v7a/x86 copies (patching them with arm64 bytes corrupts).
    return [n for n in zf.namelist()
            if n.startswith("lib/arm64-v8a/") and n.endswith(".so")
            and lib_substr in Path(n).name]


def apk_contains_lib(apk: Path, lib_substr: str) -> bool:
    with zipfile.ZipFile(apk) as zf:
        return bool(_so_entries(zf, lib_substr))


def resolve_offset(so_bytes: bytes, lib_name: str) -> int:
    """Auto-locate the LIVE ssl_verify_peer_cert file offset in a BoringSSL .so.
    Distinguishes it from the ssl_reverify_peer_cert decoy (patching the decoy is a
    silent no-op). Raises if it cannot pick a live candidate."""
    from declaw.find_verify import find_in_bytes
    r = find_in_bytes(so_bytes)
    if r["live"] is None:
        raise ValueError(
            f"could not auto-locate ssl_verify_peer_cert in {lib_name} "
            f"({len(r['candidates'])} candidate(s)); pass LIB@OFFSET explicitly")
    if r["reverify"] is not None:
        log.info("patch-boringssl: %s live ssl_verify_peer_cert @0x%x "
                 "(decoy ssl_reverify_peer_cert @0x%x skipped)",
                 lib_name, r["live"], r["reverify"])
    else:
        log.info("patch-boringssl: %s ssl_verify_peer_cert @0x%x", lib_name, r["live"])
    return r["live"]


def patch_apk_boringssl(apk_in: Path, apk_out: Path, lib_substr: str, offset: int | None) -> int:
    """Rewrite apk_in -> apk_out with the return-ssl_verify_ok stub applied at
    `offset` in every matching lib/<abi>/<lib_substr>*.so. Returns how many .so
    were patched. Decompresses/recompresses the target entry; all other entries
    are copied byte-for-byte with their original compression."""
    apk_in, apk_out = Path(apk_in), Path(apk_out)
    with zipfile.ZipFile(apk_in) as zin:
        targets = set(_so_entries(zin, lib_substr))
        if not targets:
            shutil.copy2(apk_in, apk_out)
            return 0
        # a hardcoded offset is per-build ground truth for ONE lib; if the substring
        # matches several distinct libs it corrupts all but one. Auto (offset is None)
        # sidesteps this: each lib is scanned for its own ssl_verify_peer_cert.
        basenames = {Path(t).name for t in targets}
        if len(basenames) > 1 and offset is not None:
            log.warning("patch-boringssl: %r matches multiple libs %s; the same offset "
                        "0x%x is applied to all, which corrupts every lib but the one it "
                        "was found in. Use a more specific LIB name, or @auto.", lib_substr,
                        sorted(basenames), offset)
        patched = 0
        with zipfile.ZipFile(apk_out, "w") as zout:
            for info in zin.infolist():
                # read by ZipInfo, not by name: duplicate-named entries would otherwise
                # all collapse to the last member's bytes.
                data = zin.read(info)
                if info.filename in targets:
                    try:
                        off = offset if offset is not None else resolve_offset(data, info.filename)
                        buf = bytearray(data)
                        _apply_stub(buf, off, info.filename)
                        data = bytes(buf)
                        patched += 1
                    except ValueError as e:
                        # explicit offset is user ground truth: fail loud. @auto can match
                        # several libs; skip one with no locatable ssl_verify_peer_cert.
                        if offset is not None:
                            raise
                        log.warning("patch-boringssl: skipped %s (%s)", info.filename, e)
                # preserve per-entry compression (STORED stays STORED, etc.)
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zout.writestr(zi, data)
        return patched


def patch_boringssl_in_apks(apks: list[Path], spec: str, work_dir: Path) -> tuple[list[Path], int]:
    """Given the APK set of an app, patch the one that carries the target lib.
    Returns (updated_apk_list, total_so_patched). Unmatched APKs pass through."""
    lib_substr, offset = parse_spec(spec)
    work_dir.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    total = 0
    for apk in apks:
        if apk_contains_lib(apk, lib_substr):
            dst = work_dir / apk.name
            n = patch_apk_boringssl(apk, dst, lib_substr, offset)
            total += n
            out.append(dst)
        else:
            out.append(apk)
    return out, total
