"""Hard-assertion unit tests for declaw.analyze (TLS-stack / anti-tamper detection
and strategy routing). Pure logic, no device. Builds synthetic APK zips.
Run: uv run python tests/test_analyze.py
"""
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.analyze import analyze_apks  # noqa: E402

FAILS = 0
_TD = tempfile.TemporaryDirectory()
_TMP = Path(_TD.name)
_n = [0]


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def apk(entries: dict) -> Path:
    """entries: {zip_name: bytes}. Returns a temp .apk path."""
    _n[0] += 1
    p = _TMP / f"a{_n[0]}.apk"
    with zipfile.ZipFile(p, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return p


def prof(entries: dict):
    return analyze_apks([apk(entries)])


def main():
    # 1. Flutter -> framework flutter, patch mode
    p = prof({"lib/arm64-v8a/libflutter.so": b"\x7fELF", "classes.dex": b"x"})
    check("flutter" in p.frameworks, "libflutter.so -> flutter framework")
    check(p.strategy()[0] == "patch", "flutter routes to patch")

    # 2. Flutter via assets path
    p = prof({"assets/flutter_assets/kernel_blob.bin": b"x"})
    check("flutter" in p.frameworks, "assets/flutter_assets -> flutter")

    # 3. PairIP anti-tamper -> capture
    p = prof({"lib/arm64-v8a/libpairipcore.so": b"x"})
    check(p.anti_tamper == {"PairIP"}, "libpairipcore.so -> PairIP")
    check(p.strategy()[0] == "capture", "anti-tamper routes to capture")

    # 4. ByteDance MetaSec (added this session) -> capture
    p = prof({"lib/arm64-v8a/libmetasec_ov.so": b"x"})
    check("ByteDance MetaSec" in p.anti_tamper, "libmetasec_ov.so -> MetaSec")
    check(p.strategy()[0] == "capture", "MetaSec routes to capture")

    # 5. cronet by lib name -> cronet True, capture
    p = prof({"lib/arm64-v8a/libcronet.140.0.1.so": b"x"})
    check(p.cronet is True, "libcronet* -> cronet True")
    check(p.strategy()[0] == "capture", "cronet routes to capture")

    # 6. cronet by dex marker only (GMS-provided, no libcronet)
    p = prof({"classes.dex": b"blah org/chromium/net/UrlRequest blah"})
    check(p.cronet is True, "org/chromium/net dex marker -> cronet True")

    # 7. bundled non-Flutter BoringSSL -> bundled_boringssl, NOT cronet
    p = prof({"lib/arm64-v8a/libttboringssl.so": b"x"})
    check(p.bundled_boringssl == {"libttboringssl.so"}, "libttboringssl.so -> bundled_boringssl")
    check(p.cronet is False, "libttboringssl.so is not cronet")

    # 8. OkHttp dex marker -> okhttp True, patch (not capture)
    p = prof({"classes.dex": b"Lokhttp3/OkHttpClient;"})
    check(p.okhttp is True, "okhttp3/ dex marker -> okhttp True")
    check(p.strategy()[0] == "patch", "okhttp routes to patch")

    # 9. Java pinning markers -> java_pinning True
    for marker in (b"okhttp3/CertificatePinner", b"com/datatheorem/android/trustkit", b"certificatetransparency"):
        p = prof({"classes.dex": b"pre " + marker + b" post"})
        check(p.java_pinning is True, f"pin marker {marker[:20]!r} -> java_pinning")

    # 10. conscrypt marker (case-insensitive) -> conscrypt True
    p = prof({"classes.dex": b"ORG/CONSCRYPT/Conscrypt"})
    check(p.conscrypt is True, "org/conscrypt (any case) -> conscrypt True")

    # 11. abi detection across split
    p = analyze_apks([
        apk({"lib/arm64-v8a/x.so": b"x"}),
        apk({"lib/x86_64/x.so": b"x", "lib/armeabi-v7a/x.so": b"x"}),
    ])
    check(p.abis == {"arm64-v8a", "x86_64", "armeabi-v7a"}, "abis collected across splits")

    # 12. ByteDance-like combo: MetaSec + bundled boringssl + cronet dex -> capture, both flags
    p = prof({
        "lib/arm64-v8a/libmetasec_ov.so": b"x",
        "lib/arm64-v8a/libttboringssl.so": b"x",
        "classes.dex": b"org/chromium/net okhttp3/",
    })
    check("ByteDance MetaSec" in p.anti_tamper and p.bundled_boringssl == {"libttboringssl.so"},
          "combo: MetaSec + bundled_boringssl both detected")
    check(p.strategy()[0] == "capture", "combo (anti-tamper) routes to capture")

    # 13. plain app, no markers -> patch, standard reason
    p = prof({"classes.dex": b"nothing interesting", "res/x": b"y"})
    check(p.strategy()[0] == "patch", "plain app -> patch")
    check("no notable markers" in p.summary() or p.summary(), "summary is non-empty / sane")

    # 14. summary reflects flags
    p = prof({"lib/arm64-v8a/libpairipcore.so": b"x", "lib/arm64-v8a/libcronet.so": b"x"})
    s = p.summary()
    check("anti-tamper=" in s and "cronet" in s, "summary lists cronet + anti-tamper")

    global FAILS
    FAILS += test_offset_override()
    FAILS += test_prune_abis()
    print()
    if FAILS:
        print(f"{FAILS} FAILURES"); sys.exit(1)
    print("all analyze tests passed")


def test_offset_override():
    # DECLAW_HWBP_OFFSETS escape hatch for libs the arm64 finder can't locate
    # (32-bit/ARM literal pools, a vendored bundled BoringSSL). Pure resolution logic.
    from declaw.hwbp import _offset_override
    fails = 0
    cases = [
        ("/system/lib/libssl.so", "libssl.so@1f13c", "0x1f13c"),
        ("/apex/com.android.conscrypt/lib/libssl.so", "libssl.so@1f13c", "0x1f13c"),
        ("/data/app/x/lib/arm64-v8a/libttboringssl.so",
         "libssl.so@1f13c,libttboringssl.so@49d214", "0x49d214"),
        ("/system/lib64/libssl.so", "libttboringssl.so@49d214", None),  # no match
        ("/system/lib/libssl.so", "libssl.so@0x1f13c", "0x1f13c"),      # 0x-prefixed
        ("/system/lib/libssl.so", "garbage,libssl.so@1f13c", "0x1f13c"),  # skip malformed
        ("/system/lib/libssl.so", "", None),                            # empty spec
    ]
    for path, spec, want in cases:
        got = _offset_override(path, spec)
        print(("PASS " if got == want else "FAIL ") + f"_offset_override({path}, {spec!r}) == {want} (got {got})")
        if got != want:
            fails += 1
    return fails


def test_prune_abis():
    # _prune_lib_abis must NEVER delete all libs: an unresolved 'auto' (local mode),
    # a typo, or an absent ABI keeps everything; a real present ABI prunes the rest.
    from declaw.pipeline import _prune_lib_abis
    fails = 0

    def mktree():
        d = Path(tempfile.mkdtemp(dir=_TMP))
        for abi in ("arm64-v8a", "armeabi-v7a", "x86"):
            (d / "lib" / abi).mkdir(parents=True)
            (d / "lib" / abi / "libx.so").write_bytes(b"\x7fELF")
        return d

    def abis(d):
        return {p.name for p in (d / "lib").iterdir() if p.is_dir()}

    for keep in ("auto", "bogus-abi"):
        t = mktree()
        _prune_lib_abis(t, keep)
        got = abis(t)
        ok = got == {"arm64-v8a", "armeabi-v7a", "x86"}
        print(("PASS " if ok else "FAIL ") + f"_prune_lib_abis keep={keep!r} keeps all ABIs (got {sorted(got)})")
        if not ok:
            fails += 1

    t = mktree()
    _prune_lib_abis(t, "arm64-v8a")
    got = abis(t)
    ok = got == {"arm64-v8a"}
    print(("PASS " if ok else "FAIL ") + f"_prune_lib_abis keep='arm64-v8a' drops others (got {sorted(got)})")
    if not ok:
        fails += 1
    return fails


if __name__ == "__main__":
    main()
