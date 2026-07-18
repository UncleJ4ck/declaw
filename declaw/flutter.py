"""declaw.flutter — Static libflutter ssl_verify_peer_cert byte patch."""
from __future__ import annotations

from pathlib import Path
import re
import struct
import zipfile
import zlib

from declaw.config import log
from declaw.gadget import FLUTTER_TLS_SIGS


# APK lib/<abi>/ directory name -> instruction-set key in FLUTTER_TLS_SIGS.
_ABI_TO_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


def _flutter_return_stub(arch: str, retval: int) -> bytes:
    """Machine code that does `return retval;` for the given instruction set."""
    if arch == "arm64":
        return struct.pack("<II", 0x52800000 | ((retval & 0xFFFF) << 5), 0xD65F03C0)
    if arch == "arm":  # Thumb: movs r0, #retval ; bx lr
        return struct.pack("<HH", 0x2000 | (retval & 0xFF), 0x4770)
    if arch in ("x86_64", "x86"):  # mov eax, retval ; ret
        return b"\xb8" + struct.pack("<I", retval & 0xFFFFFFFF) + b"\xc3"
    raise ValueError(f"no return stub for arch {arch}")


def _sig_to_regex(sig: str) -> "re.Pattern[bytes]":
    """Compile an NVISO-style nibble-wildcard signature to a bytes regex."""
    out = b""
    for tok in sig.split():
        hi, lo = tok[0], tok[1]
        if hi == "?" and lo == "?":
            out += b"."
        elif hi != "?" and lo != "?":
            out += re.escape(bytes([int(tok, 16)]))
        else:
            vals = [b for b in range(256)
                    if (hi == "?" or f"{b:02X}"[0] == hi.upper())
                    and (lo == "?" or f"{b:02X}"[1] == lo.upper())]
            out += b"[" + b"".join(re.escape(bytes([v])) for v in vals) + b"]"
    return re.compile(out, re.DOTALL)


def _patch_flutter_tls_bytes(data: bytes, arch: str) -> tuple[bytes, list[int]]:
    """Return (patched_data, [offsets]) with every ssl_verify_peer_cert match in
    `data` overwritten by a success-returning stub for `arch`. No-op (empty list)
    when no signature matches, so it is safe on non-Flutter libs and idempotent
    (a patched prologue no longer matches)."""
    sigs = FLUTTER_TLS_SIGS.get(arch)
    if not sigs:
        return data, []
    buf = bytearray(data)
    hits: list[int] = []
    for sig, retval in sigs:
        stub = _flutter_return_stub(arch, retval)
        for m in _sig_to_regex(sig).finditer(data):
            off = m.start()
            if off in hits:
                continue
            buf[off:off + len(stub)] = stub
            hits.append(off)
    return bytes(buf), sorted(hits)


def _static_patch_flutter_so(apk: Path) -> int:
    """Patch any Stored lib/<abi>/libflutter.so inside `apk` in place so its
    TLS verification always succeeds, fixing the entry CRC and re-writing the
    APK bytes. Returns the number of call sites patched across all ABIs. Leaves
    every other zip entry (resources.arsc, alignment, the manifest) untouched,
    so the existing sign step's zipalign still holds. Deflated libflutter.so is
    reported and skipped (rare; would need a full re-zip)."""
    # Cheap gate: only Flutter apps carry libflutter.so. Reading just the zip central
    # directory lets the common non-Flutter case skip the full read_bytes below (this
    # runs on every base + split of every app). A Deflated libflutter.so still enters
    # the byte path, which detects and reports it.
    try:
        with zipfile.ZipFile(apk) as zf:
            if not any(n.rsplit("/", 1)[-1] == "libflutter.so" for n in zf.namelist()):
                return 0
    except (zipfile.BadZipFile, OSError):
        pass  # fall through; the byte path validates the EOCD and no-ops safely
    raw = bytearray(apk.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0:
        return 0
    # rfind can land on a "PK\x05\x06" inside the archive comment; the REAL EOCD is the
    # one whose comment-length field equals the bytes remaining after it. Scan back for
    # it rather than reading cd_off/cd_count from a bogus location and misapplying.
    while eocd >= 0 and eocd + 22 <= len(raw) and \
            eocd + 22 + struct.unpack_from("<H", raw, eocd + 20)[0] != len(raw):
        eocd = raw.rfind(b"PK\x05\x06", 0, eocd)
    if eocd < 0:
        log.warning("no valid EOCD in %s; static libflutter patch skipped", apk.name)
        return 0
    cd_off = struct.unpack_from("<I", raw, eocd + 16)[0]
    cd_count = struct.unpack_from("<H", raw, eocd + 10)[0]
    if cd_off == 0xFFFFFFFF or cd_count == 0xFFFF:
        # zip64: real values live in the zip64 EOCD we do not parse. Bail rather
        # than walk a bogus offset. APKs almost never hit this.
        log.warning("zip64 APK %s: static libflutter patch skipped (use the "
                    "runtime hook instead)", apk.name)
        return 0
    total = 0
    p = cd_off
    for _ in range(cd_count):
        if raw[p:p + 4] != b"PK\x01\x02":
            break
        gp_flag = struct.unpack_from("<H", raw, p + 8)[0]
        method = struct.unpack_from("<H", raw, p + 10)[0]
        comp_size = struct.unpack_from("<I", raw, p + 20)[0]
        name_len = struct.unpack_from("<H", raw, p + 28)[0]
        extra_len = struct.unpack_from("<H", raw, p + 30)[0]
        comment_len = struct.unpack_from("<H", raw, p + 32)[0]
        lh_off = struct.unpack_from("<I", raw, p + 42)[0]
        name = raw[p + 46:p + 46 + name_len].decode("utf-8", "replace")
        m = re.fullmatch(r"lib/([^/]+)/libflutter\.so", name)
        if m:
            arch = _ABI_TO_ARCH.get(m.group(1))
            if arch is None:
                pass
            elif method != 0:
                log.warning("libflutter.so in %s is compressed; static TLS "
                            "patch skipped for %s", apk.name, name)
            else:
                # Local header: 30 + name_len + extra_len -> entry data.
                lname_len = struct.unpack_from("<H", raw, lh_off + 26)[0]
                lextra_len = struct.unpack_from("<H", raw, lh_off + 28)[0]
                data_off = lh_off + 30 + lname_len + lextra_len
                blob = bytes(raw[data_off:data_off + comp_size])
                patched, hits = _patch_flutter_tls_bytes(blob, arch)
                if hits:
                    raw[data_off:data_off + comp_size] = patched
                    crc = zlib.crc32(patched) & 0xFFFFFFFF
                    struct.pack_into("<I", raw, p + 16, crc)        # central dir
                    if not (gp_flag & 0x08):
                        # Only update the local CRC when there is no trailing data
                        # descriptor (bit 3). With a descriptor the local CRC is 0
                        # and the authoritative copy is the central dir entry.
                        struct.pack_into("<I", raw, lh_off + 14, crc)
                    total += len(hits)
                    log.info("Static Flutter TLS patch: %s %s -> %d site(s) at %s",
                             apk.name, name, len(hits),
                             ", ".join(hex(h) for h in hits))
        p += 46 + name_len + extra_len + comment_len
    if total:
        apk.write_bytes(raw)
    return total
