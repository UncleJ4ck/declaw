"""Standalone hard-assertion tests for declaw.boringssl_patch.
Run: uv run python tests/test_boringssl_patch.py

Self-contained: builds a synthetic APK in a temp dir, no device or sample needed.
Verifies the arm64 return-ssl_verify_ok stub is byte-exact, that only the arm64
copy is touched, that the patch is size-preserving, and that spec parsing and
range checks behave.
"""
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.boringssl_patch import (  # noqa: E402
    _PATCH, patch_ssl_verify_peer_cert, verify_patch, parse_spec,
    patch_apk_boringssl, apk_contains_lib,
)

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def main():
    # 1) the stub is exactly `mov w0,#0` (0x52800000) + `ret` (0xd65f03c0), LE.
    check(_PATCH == bytes([0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]),
          "stub bytes are `mov w0,#0 ; ret` little-endian")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        # 2) file-level patch is byte-exact and size-preserving.
        so = td / "libx.so"
        original = b"\x7fELF" + (bytes(range(256)) * 8)[4:]   # 2048 bytes, valid ELF magic
        so.write_bytes(original)
        off = 0x100
        patch_ssl_verify_peer_cert(so, off)
        patched = so.read_bytes()
        check(len(patched) == len(original), "patch preserves file size")
        check(patched[off:off + 8] == _PATCH, "stub written at the offset")
        check(patched[:off] == original[:off] and patched[off + 8:] == original[off + 8:],
              "bytes outside the stub are untouched")
        check(verify_patch(so, off), "verify_patch confirms the stub")
        check(not verify_patch(so, off + 4), "verify_patch false on a non-stub offset")

        # 3) out-of-range offset raises.
        raised = False
        try:
            patch_ssl_verify_peer_cert(so, len(original) - 2)
        except ValueError:
            raised = True
        check(raised, "out-of-range offset raises ValueError")

        # 4) spec parsing.
        check(parse_spec("libttboringssl.so@0x3038c") == ("libttboringssl.so", 0x3038c),
              "parse_spec hex offset")
        check(parse_spec("libssl.so@12345") == ("libssl.so", 12345),
              "parse_spec decimal offset")
        check(parse_spec("libssl.so") == ("libssl.so", None),
              "parse_spec bare lib -> auto (None)")
        check(parse_spec("libssl.so@auto") == ("libssl.so", None),
              "parse_spec @auto -> auto (None)")
        bad = False
        try:
            parse_spec("")
        except ValueError:
            bad = True
        check(bad, "parse_spec rejects empty spec")

        # 4b) a wrong offset into a non-ELF entry is refused, not silently written.
        notelf = td / "notelf.so"
        notelf.write_bytes(b"\x00\x01\x02\x03" + b"\xAA" * 512)
        refused = False
        try:
            patch_ssl_verify_peer_cert(notelf, 0x40)
        except ValueError:
            refused = True
        check(refused, "non-ELF target is refused (ELF-magic sanity)")

        # 5) APK patch: only the arm64 copy is patched; v7a is left intact.
        apk_in = td / "split.apk"
        libbytes = b"\x7fELF" + bytes([0xAA]) * 4092   # 4096 bytes, valid ELF magic
        with zipfile.ZipFile(apk_in, "w") as z:
            z.writestr("lib/arm64-v8a/libttboringssl.so", libbytes)
            z.writestr("lib/armeabi-v7a/libttboringssl.so", libbytes)
            z.writestr("classes.dex", b"dexdexdex")
        check(apk_contains_lib(apk_in, "libttboringssl.so"), "apk_contains_lib finds the lib")

        apk_out = td / "split_patched.apk"
        off2 = 0x200
        n = patch_apk_boringssl(apk_in, apk_out, "libttboringssl.so", off2)
        check(n == 1, "patch_apk_boringssl patches exactly the arm64 copy (not v7a)")
        with zipfile.ZipFile(apk_out) as z:
            a64 = z.read("lib/arm64-v8a/libttboringssl.so")
            a32 = z.read("lib/armeabi-v7a/libttboringssl.so")
            dex = z.read("classes.dex")
            names = z.namelist()
        check(a64[off2:off2 + 8] == _PATCH, "arm64 lib carries the stub in the output apk")
        check(a32 == libbytes, "armeabi-v7a lib is byte-for-byte unchanged")
        check(dex == b"dexdexdex", "other entries (classes.dex) are preserved")
        check(len(names) == 3, "no entries added or dropped")

        # 6) duplicate-named entries keep their OWN bytes (read by ZipInfo, not name).
        dup = td / "dup.apk"
        with zipfile.ZipFile(dup, "w") as z:
            z.writestr("res/x", b"FIRST-copy")
            z.writestr("res/x", b"SECOND-copy")
            z.writestr("lib/arm64-v8a/libttboringssl.so", libbytes)
        dup_out = td / "dup_patched.apk"
        patch_apk_boringssl(dup, dup_out, "libttboringssl.so", 0x200)
        with zipfile.ZipFile(dup_out) as z:
            payloads = [z.read(i) for i in z.infolist() if i.filename == "res/x"]
        check(sorted(payloads) == [b"FIRST-copy", b"SECOND-copy"],
              "duplicate-named entries are not collapsed to the last member")

    print()
    if FAILS:
        print(f"{FAILS} FAILURES")
        sys.exit(1)
    print("all boringssl_patch tests passed")


if __name__ == "__main__":
    main()
