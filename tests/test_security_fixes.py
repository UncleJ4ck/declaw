"""Hard-assertion regression tests for the audit security fixes (device-free).
Run: uv run python tests/test_security_fixes.py

- hwbp._SAFE_LIB_PATH: the /proc/pid/maps lib-path guard must reject any path with a
  shell metacharacter (the root command-injection sink) and accept real Android .so
  paths, so a crafted target cannot inject into the root monitor command.
- shlex.quote: even if a path slipped the guard, quoting must neutralize it inside the
  inner sh -c (the metacharacter ends up as a literal, not a command separator).
- config._frida_major: "latest" must classify as a modern major (>= 17), not 0, or the
  CLI prints the opposite Android-16 guidance.
- shell._stream_download: a supplied sha256 digest must fail closed (mismatch raises and
  leaves no file / no .part), verify a correct one, and skip on None / an unknown algo
  so non-GitHub and offline-bypass URLs (which carry no digest) still download.
"""
import hashlib
import shlex
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.hwbp import _SAFE_LIB_PATH  # noqa: E402
from declaw.config import _frida_major, DEFAULT_FRIDA_VERSION  # noqa: E402
from declaw import shell  # noqa: E402


class _FakeResp:
    """Minimal streaming-response stand-in for requests.get (context manager)."""
    def __init__(self, chunks):
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=1):
        yield from self._chunks

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("  ok  " if cond else " FAIL ") + msg)
    if not cond:
        FAILS += 1


def main():
    print("hwbp injection guard: real .so paths accepted")
    legit = [
        "/system/lib64/libssl.so",
        "/apex/com.android.conscrypt/lib64/libssl.so",
        "/data/app/~~aB0c==/com.x-Zy9==/lib/arm64/libcronet.so",
        "/data/data/com.pkg/files/libboringssl.so",
    ]
    for p in legit:
        check(_SAFE_LIB_PATH.match(p) is not None, f"accepts {p}")

    print("hwbp injection guard: metacharacter paths rejected at the source")
    evil = [
        "/data/data/evil/files/libssl;id.so",
        "/data/local/tmp/libssl$(reboot).so",
        "/x/libssl`id`.so",
        "/x/libssl|nc.so",
        "/x/lib&&ssl.so",
        "/x/lib ssl.so",
        "/x/libssl>(evil).so",
    ]
    for p in evil:
        check(_SAFE_LIB_PATH.match(p) is None, f"rejects {p!r}")

    print("defense in depth: shlex.quote neutralizes a metacharacter path in the inner sh -c")
    poisoned = "/x/libssl;id.so"
    inner = " ".join(shlex.quote(a) for a in ["/bin/mon", "1234", poisoned, "5aa30"])
    # the ';' must be inside a single-quoted token, not a bare command separator
    check("'/x/libssl;id.so'" in inner, "poisoned path is single-quoted, ; is inert")
    check(";id.so'" not in inner.replace("'/x/libssl;id.so'", ""), "no unquoted ; remains")

    print("config._frida_major: 'latest' is modern, real versions parse")
    check(_frida_major("latest") >= 17, "latest -> >= 17")
    check(_frida_major("latest") == int(DEFAULT_FRIDA_VERSION.split(".")[0]),
          "latest tracks the default major")
    check(_frida_major("16.7.19") == 16, "16.7.19 -> 16")
    check(_frida_major("v17.15.2") == 17, "v17.15.2 -> 17")
    check(_frida_major("garbage") == 0, "unparseable -> 0")

    digest_tests()

    print("\n%d failure(s)" % FAILS)
    return 1 if FAILS else 0


def digest_tests():
    print("shell._stream_download: sha256 digest verification (mocked transport)")
    payload = b"declaw integrity test payload " * 4096  # ~120 KB, several chunks
    good = "sha256:" + hashlib.sha256(payload).hexdigest()
    orig_get = shell.requests.get
    shell.requests.get = lambda *a, **k: _FakeResp([payload[i:i + (1 << 16)]
                                                    for i in range(0, len(payload), 1 << 16)])
    try:
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            dst = d / "good.bin"
            shell._stream_download("http://x/good", dst, expected_digest=good)
            check(dst.read_bytes() == payload, "correct digest: file lands with exact bytes")
            check(not (d / "good.bin.part").exists(), "correct digest: .part cleaned up")

            dst2 = d / "bad.bin"
            raised = ""
            try:
                shell._stream_download("http://x/bad", dst2, expected_digest="sha256:" + "0" * 64)
            except RuntimeError as e:
                raised = str(e)
            check("sha256 mismatch" in raised, "wrong digest: raises sha256 mismatch")
            check(not dst2.exists() and not (d / "bad.bin.part").exists(),
                  "wrong digest fails closed: no file, no .part left behind")

            dst3 = d / "none.bin"
            shell._stream_download("http://x/none", dst3, expected_digest=None)
            check(dst3.read_bytes() == payload, "None digest: downloads unchecked (offline/bypass path)")

            dst4 = d / "algo.bin"
            shell._stream_download("http://x/algo", dst4, expected_digest="sha512:" + "f" * 128)
            check(dst4.read_bytes() == payload, "unknown-algo digest: skipped, not falsely rejected")
    finally:
        shell.requests.get = orig_get


if __name__ == "__main__":
    sys.exit(main())
