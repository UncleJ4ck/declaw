"""declaw.gadget — Frida gadget download and 16 KB ELF re-alignment."""
from __future__ import annotations

from pathlib import Path
import lzma
import re
import shutil
import struct

from declaw.config import DEFAULT_FRIDA_VERSION, FRIDA_ABI_MAP, FRIDA_RELEASES_LATEST_URL, FRIDA_RELEASES_TAG_URL, UTILS_DIR, log
from declaw.shell import _gh_latest, _stream_download


def fetch_frida_gadget(abi: str, *, refresh: bool, version: str = DEFAULT_FRIDA_VERSION) -> Path:
    if abi not in FRIDA_ABI_MAP:
        raise ValueError(f"Unsupported ABI for Frida gadget: {abi}")
    suffix = FRIDA_ABI_MAP[abi]
    # Fast path: cached gadget for THIS version + ABI. Matching on version too
    # because mixing a 16.x gadget with a 17.x cached one would reintroduce
    # the script-mode-broken bug; we have to be specific.
    pinned_so = UTILS_DIR / f"libfrida-gadget-{version}-{suffix}.so"
    if pinned_so.exists() and not refresh:
        log.debug("Using cached %s", pinned_so.name)
        return pinned_so
    # Fallback: any older cached version is better than failing on a flaky
    # network, but warn loudly so the user knows they may be hitting the
    # 17.x script-broken bug. Real bug surfaced during the docker-android
    # x86_64 test run: the pinned arm64 gadget was downloaded but the x86_64
    # ABI silently fell back to a stale 17.x cache and the gadget script
    # silently no-op'd in the emulator. Downloading the pinned version per
    # ABI is the only correct behaviour; if the network is down, fail loudly.
    if version.lower() == "latest":
        info = _gh_latest(FRIDA_RELEASES_LATEST_URL)
    else:
        info = _gh_latest(FRIDA_RELEASES_TAG_URL.format(tag=version))
    tag = info.get("tag_name", version).lstrip("v")
    pattern = re.compile(rf"frida-gadget-.*{re.escape(suffix)}\.so\.xz$")
    asset = next((a for a in info.get("assets", []) if pattern.search(a["name"])), None)
    if asset is None:
        raise RuntimeError(f"No frida-gadget asset for {abi} in release {tag}")
    xz = UTILS_DIR / asset["name"]
    so = UTILS_DIR / f"libfrida-gadget-{tag}-{suffix}.so"
    if so.exists() and not refresh:
        log.debug("Using cached %s", so.name)
        return so
    if not xz.exists() or refresh:
        _stream_download(asset["browser_download_url"], xz)
    log.info("Decompressing %s", xz.name)
    with lzma.open(xz, "rb") as src, open(so, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return so


# Android 15+ on a 16 KB-page device (Pixel 8/9, current AOSP, many 2024+ phones)
# refuses to correctly map a .so whose LOAD segments are 4 KB-aligned. The Frida
# gadget ships 4 KB-aligned for every version (verified 16.7.19 and 17.x), so on
# such a device its segments land on the wrong pages and the first hook the
# script installs jumps through a corrupt trampoline -> SIGSEGV. Re-aligning the
# gadget's LOAD segments to 16 KB fixes it; 16 KB is a superset of 4 KB so the
# result still loads on every older 4 KB-page device. This is additive: it only
# touches the injected gadget, never the app's own libs (already 16 KB-aligned).
GADGET_PAGE_ALIGN = 0x4000  # 16 KB


def _align_native_lib_16k(src: Path, dst: Path) -> bool:
    """Copy src -> dst, re-aligning ELF64 LOAD segments to 16 KB when needed.

    Returns True if a re-align was applied, False if the lib was already
    >= 16 KB-aligned and copied verbatim. Inserts the minimum zero padding
    before each under-aligned LOAD segment so its file offset satisfies the
    loader's congruence rule (p_offset % page == p_vaddr % page), bumps
    p_align to 16 KB, shifts every program-header offset to track the inserted
    padding, and grows the file accordingly. Section headers (loader-irrelevant)
    are dropped so their now-stale offsets cannot trip a strict linker.

    Pure stdlib (struct) on purpose: lief 0.17 silently fails to relocate this
    gadget's bss-bearing trailing segment, producing a "p_offset past end of
    file" image that the Android linker rejects.
    """
    data = bytearray(src.read_bytes())
    # ELF64 little-endian only (every Android gadget ABI we ship). Anything
    # else: copy verbatim rather than risk a bad rewrite.
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2 or data[5] != 1:
        shutil.copy2(src, dst)
        return False
    en = "<"
    PAGE = GADGET_PAGE_ALIGN
    PT_LOAD = 1
    (e_phoff,) = struct.unpack_from(en + "Q", data, 0x20)
    (e_shoff,) = struct.unpack_from(en + "Q", data, 0x28)
    (e_phentsize,) = struct.unpack_from(en + "H", data, 0x36)
    (e_phnum,) = struct.unpack_from(en + "H", data, 0x38)
    (e_shentsize,) = struct.unpack_from(en + "H", data, 0x3A)
    (e_shnum,) = struct.unpack_from(en + "H", data, 0x3C)

    phdrs = []  # (hdr_offset, p_type, p_offset, p_vaddr, p_align)
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(en + "I", data, base)[0]
        p_offset, p_vaddr = struct.unpack_from(en + "QQ", data, base + 8)
        p_align = struct.unpack_from(en + "Q", data, base + 48)[0]
        phdrs.append((base, p_type, p_offset, p_vaddr, p_align))

    loads = [p for p in phdrs if p[1] == PT_LOAD]
    if not loads or all(p[4] >= PAGE for p in loads):
        shutil.copy2(src, dst)
        return False

    # Walk LOAD segments in file order, inserting just enough padding before
    # each so its new offset is page-congruent with its vaddr.
    inserts = []  # (at_old_offset, pad_bytes)
    cum = 0
    for _, _, p_offset, p_vaddr, _ in sorted(loads, key=lambda p: p[2]):
        need = (p_vaddr - (p_offset + cum)) % PAGE
        cum += need
        inserts.append((p_offset, need))

    def shift_for(off: int) -> int:
        return sum(pad for at, pad in inserts if at <= off)

    # Rebuild the file with the padding spliced in.
    out = bytearray()
    pos = 0
    for at, pad in sorted(inserts, key=lambda x: x[0]):
        out += data[pos:at]
        out += b"\x00" * pad
        pos = at
    out += data[pos:]

    # Fix up every program-header offset; bump LOAD alignment to the page size.
    for base, p_type, p_offset, _p_vaddr, _p_align in phdrs:
        struct.pack_into(en + "Q", out, base + 8, p_offset + shift_for(p_offset))
        if p_type == PT_LOAD:
            struct.pack_into(en + "Q", out, base + 48, PAGE)
    # Shift e_phoff if it moved.
    struct.pack_into(en + "Q", out, 0x20, e_phoff + shift_for(e_phoff))
    # Keep the section header table but track the padding: the Android linker
    # validates e_shstrndx, so the table must stay present and consistent
    # (zeroing it trips "invalid e_shstrndx"). Shift e_shoff and every section
    # offset by the padding inserted before them.
    if e_shoff and e_shnum:
        struct.pack_into(en + "Q", out, 0x28, e_shoff + shift_for(e_shoff))
        for i in range(e_shnum):
            old_sh = e_shoff + i * e_shentsize
            new_sh = old_sh + shift_for(old_sh)
            sh_offset = struct.unpack_from(en + "Q", data, old_sh + 24)[0]
            if sh_offset:
                struct.pack_into(en + "Q", out, new_sh + 24,
                                 sh_offset + shift_for(sh_offset))

    dst.write_bytes(out)
    return True


# --------------------------------------------------------------------------- #
#  Static Flutter TLS bypass (no gadget, no Frida)                            #
# --------------------------------------------------------------------------- #
#
# Flutter ships its own BoringSSL inside libflutter.so and verifies the server
# cert against a baked-in trust store, ignoring the system store, the NSC, and
# any user CA. The only reliable defeat is to neuter ssl_verify_peer_cert (and
# the session_verify_cert_chain helper) so it always reports success. The NVISO
# runtime hook does this with Frida, but the gadget's Interceptor SIGSEGVs on
# some new arm64 SoCs (Pixel 8 / Tensor G3, Android 16) and Frida 17's gadget
# won't run scripts at all. So we also do it STATICALLY at patch time: locate
# the function by NVISO's byte signatures and overwrite its prologue with a stub
# that returns the success value. No runtime, no Frida, device-independent.
#
# These signatures are ported verbatim from NVISO's disable-flutter-tls.js
# (the Android "libflutter.so" config). ssl_verify_peer_cert returns an
# enum ssl_verify_result_t where ssl_verify_ok == 0; that return convention has
# been stable across BoringSSL/Flutter versions for years, which is why the stub
# value lives with each signature (retval) rather than being guessed. Update
# this table from upstream when a new Flutter engine ships an unmatched layout:
#   https://github.com/NVISOsecurity/disable-flutter-tls-verification
FLUTTER_TLS_SIGS: dict[str, list[tuple[str, int]]] = {
    "arm64": [
        ("F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9", 0),
        ("F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 "
         "F4 03 00 AA 68 1A 40 F9", 0),
        ("FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 "
         "B5 00 00 B4 B6 4A 40 F9", 0),
        ("FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 "
         "DA 02 00 B4 48 03 40 F9", 1),
    ],
    "arm": [
        ("2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8", 0),
    ],
    "x86_64": [
        ("55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? "
         "?? 0? 00 00 4D 85 ?? 74 1? 4D 8B", 0),
        ("55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 "
         "4C 8B A0 28 02 00 00 4D 85 E4 74", 0),
        ("55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 "
         "30 48 8B 98 D0 01 00 00 48 85 DB", 0),
    ],
    "x86": [
        ("55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 "
         "8B 7D 08 8B 17 8B 42 18 8B 80 88 01", 0),
    ],
}
