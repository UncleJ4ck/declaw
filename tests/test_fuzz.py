"""Fuzz + stress the pure parsers in declaw. They ingest attacker-controlled APK
bytes and user-supplied specs, so they must degrade gracefully, never raise an
unhandled exception, and stay correct on the boundaries.
Run: uv run python tests/test_fuzz.py
"""
import io
import os
import random
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.analyze import (           # noqa: E402
    analyze_apks, _scan_dex, AppProfile, _DEX_MAX_ENTRIES,
)
from declaw.boringssl_patch import parse_spec, patch_apk_boringssl, apk_contains_lib  # noqa: E402

FAILS = 0
random.seed(1337)
_TD = tempfile.TemporaryDirectory()
_TMP = Path(_TD.name)
_n = [0]


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def wrote(name: str, data: bytes) -> Path:
    _n[0] += 1
    p = _TMP / f"f{_n[0]}"
    p.write_bytes(data)
    return p


def fuzz_analyze():
    # 1. non-zip garbage of many shapes must not raise; profile stays empty.
    shapes = [b"", b"\x00" * 10, b"not a zip at all", os.urandom(4096),
              b"PK\x03\x04" + os.urandom(50),            # zip magic then garbage
              b"PK\x05\x06" + b"\x00" * 18,               # empty-EOCD-ish
              bytes(range(256)) * 4]
    ok = True
    for i, s in enumerate(shapes):
        try:
            p = analyze_apks([wrote(f"junk{i}.apk", s)])
            # garbage yields an empty profile, never a crash
            if p.frameworks or p.anti_tamper or p.cronet:
                ok = False
        except Exception as e:
            print("  raised on shape", i, repr(e)); ok = False
    check(ok, "analyze_apks tolerates non-zip garbage (no raise, empty profile)")

    # 2. truncated valid zip (cut mid-file) must not raise.
    _n[0] += 1
    full = _TMP / "full.apk"
    with zipfile.ZipFile(full, "w") as z:
        z.writestr("lib/arm64-v8a/libflutter.so", b"x" * 5000)
        z.writestr("classes.dex", b"okhttp3/ " * 500)
    raw = full.read_bytes()
    ok = True
    for cut in (10, len(raw) // 3, len(raw) // 2, len(raw) - 5):
        try:
            analyze_apks([wrote(f"trunc{cut}.apk", raw[:cut])])
        except Exception as e:
            print("  raised on truncation", cut, repr(e)); ok = False
    check(ok, "analyze_apks tolerates truncated zips")

    # 3. hostile entry names (path traversal, absolute, unicode, huge) must not escape or raise.
    _n[0] += 1
    hz = _TMP / "hostile.apk"
    with zipfile.ZipFile(hz, "w") as z:
        z.writestr("../../../../etc/passwd", b"root")
        z.writestr("/abs/lib/arm64-v8a/libpairipcore.so", b"x")
        z.writestr("lib/arm64-v8a/" + "A" * 3000 + ".so", b"x")
        z.writestr("lib/arm64-v8a/libflutter.so", b"x")          # legit alongside hostile
        z.writestr("lib/‮/evil.so", b"x")
    try:
        p = analyze_apks([hz])
        # the legit flutter lib is still detected; no exception
        check("flutter" in p.frameworks, "hostile-name apk still detects the legit lib, no raise")
    except Exception as e:
        check(False, f"hostile-name apk raised {e!r}")

    # 4. a "classes.dex" that is not a dex (random bytes) must not raise.
    try:
        analyze_apks([_mk({"classes.dex": os.urandom(10000)})])
        check(True, "non-dex classes.dex tolerated")
    except Exception as e:
        check(False, f"non-dex classes.dex raised {e!r}")

    # 5. random valid mini-apks, 200 rounds, never raise.
    libs = ["libflutter.so", "libpairipcore.so", "libmetasec_ov.so", "libcronet.1.so",
            "libttboringssl.so", "libc++_shared.so", "x" * 200 + ".so"]
    abis = ["arm64-v8a", "armeabi-v7a", "x86", "weird-abi", ""]
    ok = True
    for _ in range(200):
        ent = {}
        for _ in range(random.randint(0, 6)):
            ent[f"lib/{random.choice(abis)}/{random.choice(libs)}"] = os.urandom(random.randint(0, 64))
        if random.random() < 0.5:
            ent["classes.dex"] = os.urandom(random.randint(0, 200))
        try:
            analyze_apks([_mk(ent)])
        except Exception as e:
            print("  round raised", repr(e)); ok = False; break
    check(ok, "200 randomized mini-apks: no raise")


def _mk(entries: dict) -> Path:
    _n[0] += 1
    p = _TMP / f"m{_n[0]}.apk"
    with zipfile.ZipFile(p, "w") as z:
        for k, v in entries.items():
            z.writestr(k, v)
    return p


def fuzz_specs():
    # parse_spec: valid ones parse, hostile ones raise ValueError (not some other error).
    check(parse_spec("libssl.so@0x3038c") == ("libssl.so", 0x3038c), "spec hex ok")
    check(parse_spec("l@0") == ("l", 0), "spec zero ok")
    # a bare lib, an explicit @auto, and a trailing @ all mean auto-locate (offset None).
    check(parse_spec("noat") == ("noat", None), "bare lib -> auto")
    check(parse_spec("libssl.so@auto") == ("libssl.so", None), "@auto -> auto")
    check(parse_spec("lib@") == ("lib", None), "trailing @ -> auto")
    bad = ["", "@", "@0x10", "lib@notanumber", "lib@@0x1", "lib@0xZZ"]
    ok = True
    for b in bad:
        try:
            parse_spec(b)
            print("  spec did NOT reject", repr(b)); ok = False
        except ValueError:
            pass
        except Exception as e:
            print("  spec wrong error type for", repr(b), repr(e)); ok = False
    check(ok, "parse_spec rejects hostile specs with ValueError only")

    # patch_apk_boringssl on a non-zip / no-match must not corrupt or raise unexpectedly.
    junk = wrote("junk.apk", b"not a zip")
    try:
        apk_contains_lib(junk, "libx.so")   # opens as zip -> BadZipFile
        check(False, "apk_contains_lib on non-zip should raise BadZipFile")
    except zipfile.BadZipFile:
        check(True, "apk_contains_lib surfaces BadZipFile on non-zip (caller catches)")
    except Exception as e:
        check(False, f"apk_contains_lib wrong error on non-zip: {e!r}")

    # valid apk, lib present but offset out of range -> ValueError (guarded)
    a = _mk({"lib/arm64-v8a/libx.so": b"\x00" * 16})
    try:
        patch_apk_boringssl(a, _TMP / "o.apk", "libx.so", 0xFFFF)
        check(False, "out-of-range offset should raise ValueError")
    except ValueError:
        check(True, "patch_apk_boringssl guards out-of-range offset")

    # valid apk, no matching lib -> 0 patched, output is a clean copy (no raise)
    a = _mk({"lib/arm64-v8a/libother.so": b"\x00" * 16})
    n = patch_apk_boringssl(a, _TMP / "o2.apk", "libttboringssl.so", 0)
    check(n == 0, "no matching lib -> 0 patched, no raise")


def fuzz_offset_override():
    # DECLAW_HWBP_OFFSETS spec is user-supplied ground truth: must never raise.
    from declaw.hwbp import _offset_override
    check(_offset_override("/system/lib/libssl.so", "libssl.so@1f13c") == "0x1f13c", "override basic")
    check(_offset_override("/x/libssl.so", "other@1,libssl.so@0x2b") == "0x2b", "override picks match, keeps 0x")
    check(_offset_override("/x/libc.so", "libssl.so@1f13c") is None, "override no-match -> None")
    hostile = ["", "@", "lib@", "@x", "libssl.so@", "libssl.so@zzz", ",,,@@@,,,",
               "@@@@@", "a" * 100000, "\x00@\x01", "libssl.so@1f13c,,,,",
               "‮@1f13c", os.urandom(64).hex() + "@ff", "libssl.so@ ", " @ @ @ ",
               "libssl.so@" + "f" * 100000]
    ok = True
    for h in hostile:
        try:
            r = _offset_override("/system/lib/libssl.so", h)
            if not (r is None or isinstance(r, str)):
                print("  bad return type for", repr(h[:20]), type(r)); ok = False
        except Exception as e:
            print("  _offset_override raised on", repr(h[:20]), repr(e)); ok = False
    check(ok, "_offset_override tolerates hostile specs (None or str, never raises)")


def fuzz_zip_bomb():
    # A malicious APK's classes.dex is attacker-controlled and decompressed to scan
    # markers; the read must be bounded so a zip bomb cannot exhaust memory.
    import declaw.analyze as A
    orig = A._DEX_SCAN_LIMIT
    try:
        A._DEX_SCAN_LIMIT = 1000
        # marker BEYOND the limit must NOT be scanned (this fails on the old unbounded read)
        p = analyze_apks([_mk({"classes.dex": b"\x00" * 4000 + b"org/chromium/net"})])
        check(p.cronet is False, "dex scan bounded: marker past _DEX_SCAN_LIMIT not read")
        # marker WITHIN the limit is still found
        p = analyze_apks([_mk({"classes.dex": b"org/chromium/net" + b"\x00" * 200})])
        check(p.cronet is True, "dex scan reads up to the limit (marker within found)")
    finally:
        A._DEX_SCAN_LIMIT = orig
    # a real highly-compressible dex (100MB zeros -> ~100KB on disk) analyzes bounded.
    _n[0] += 1
    bomb = _TMP / "bomb.apk"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", b"\x00" * (100 * 1024 * 1024))
    t0 = time.time()
    analyze_apks([bomb])
    dt = time.time() - t0
    check(dt < 15, f"zip-bomb dex analyzed bounded in {dt:.1f}s (<15s), no OOM")


def stress():
    # big apk: thousands of lib entries + a large dex. Must finish fast and stay correct.
    _n[0] += 1
    big = _TMP / "big.apk"
    t0 = time.time()
    with zipfile.ZipFile(big, "w") as z:
        for i in range(5000):
            z.writestr(f"lib/arm64-v8a/libnoise{i}.so", b"x")
        z.writestr("lib/arm64-v8a/libpairipcore.so", b"x")     # needle in the haystack
        z.writestr("classes.dex", b"filler " * 100000 + b"org/chromium/net")
    p = analyze_apks([big])
    dt = time.time() - t0
    check(p.anti_tamper == {"PairIP"}, "stress: PairIP found among 5000 libs")
    check(p.cronet is True, "stress: cronet marker found in large dex")
    check(dt < 30, f"stress: analyze finished in {dt:.1f}s (<30s)")


def fuzz_dex_robustness():
    # zlib.error (corrupt DEFLATE stream) is not an OSError subclass; _scan_dex must
    # swallow it rather than crash the analysis.
    class ZlibErrZf:
        def namelist(self): return ["classes.dex"]
        def open(self, name): raise zlib.error("corrupt deflate block")
    try:
        _scan_dex(ZlibErrZf(), AppProfile())
        check(True, "dex: corrupt DEFLATE (zlib.error) is swallowed, not fatal")
    except Exception as e:
        check(False, f"dex: zlib.error escaped ({type(e).__name__})")

    # entry-count cap: a hostile APK with many classesN.dex must not scan unbounded.
    opened = []
    class ManyDexZf:
        def namelist(self): return [f"classes{i}.dex" for i in range(1, 500)]
        def open(self, name):
            opened.append(name)
            return io.BytesIO(b"okhttp3/")
    _scan_dex(ManyDexZf(), AppProfile())
    check(len(opened) <= _DEX_MAX_ENTRIES,
          f"dex: entry-count cap holds (scanned {len(opened)} <= {_DEX_MAX_ENTRIES})")


def main():
    fuzz_analyze()
    fuzz_specs()
    fuzz_offset_override()
    fuzz_zip_bomb()
    fuzz_dex_robustness()
    stress()
    print()
    if FAILS:
        print(f"{FAILS} FAILURES"); sys.exit(1)
    print("all fuzz/stress tests passed")


if __name__ == "__main__":
    main()
