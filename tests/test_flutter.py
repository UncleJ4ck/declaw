"""Hard-assertion tests for the static libflutter patch and its cheap precheck.
Run: uv run python tests/test_flutter.py

The precheck (added for speed) reads only the zip central directory and returns 0
when no libflutter.so is present, so the common non-Flutter app skips a full APK
read. These tests pin the contract that it MUST NOT change the patch outcome:
- a non-Flutter APK returns 0 (nothing to patch),
- an APK whose stored libflutter.so carries a real ssl_verify prologue still patches
  (count > 0) -> the precheck did not wrongly skip it,
- an APK with a libflutter.so but no matching prologue returns 0 (byte path ran).
"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.flutter import _static_patch_flutter_so  # noqa: E402
from declaw.gadget import FLUTTER_TLS_SIGS  # noqa: E402

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def _concrete_from_sig(sig: str) -> bytes:
    """Turn a masked prologue signature ('F? 0F ?? ...') into concrete bytes that
    are guaranteed to match: every '?' nibble becomes '0', fixed nibbles are kept."""
    return bytes(int(tok.replace("?", "0"), 16) for tok in sig.split())


def _make_apk(tmp: Path, entries: dict[str, bytes], *, stored=("lib/",)) -> Path:
    apk = tmp / "t.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        for name, data in entries.items():
            comp = zipfile.ZIP_STORED if name.startswith(stored) else zipfile.ZIP_DEFLATED
            zf.writestr(zipfile.ZipInfo(name), data, compress_type=comp)
    return apk


def main():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # 1. non-Flutter APK -> 0, and it must not raise
        apk = _make_apk(tmp, {
            "classes.dex": b"dex\x00" + b"\x00" * 200,
            "lib/arm64-v8a/libc++_shared.so": b"\x7fELF" + b"\x00" * 512,
            "resources.arsc": b"\x00" * 128,
        })
        check(_static_patch_flutter_so(apk) == 0, "non-Flutter APK returns 0")

        # 2. Flutter APK with a real arm64 prologue in a stored libflutter.so -> patched
        sig = FLUTTER_TLS_SIGS["arm64"][0][0]
        payload = b"\x00" * 64 + _concrete_from_sig(sig) + b"\x00" * 64
        apk = _make_apk(tmp, {
            "classes.dex": b"dex\x00" + b"\x00" * 64,
            "lib/arm64-v8a/libflutter.so": b"\x7fELF" + b"\x00" * 60 + payload,
        })
        n = _static_patch_flutter_so(apk)
        check(n > 0, f"stored libflutter.so with a matching prologue is patched (got {n})")

        # 3. libflutter.so present but no matching prologue -> byte path ran, found nothing
        apk = _make_apk(tmp, {
            "lib/arm64-v8a/libflutter.so": b"\x7fELF" + b"\x00" * 1024,
        })
        check(_static_patch_flutter_so(apk) == 0,
              "libflutter.so without a prologue returns 0 (precheck let it through)")

    print("\n%d failure(s)" % FAILS)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
