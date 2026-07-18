"""Hard-assertion regression tests for the audit security fixes (device-free).
Run: uv run python tests/test_security_fixes.py

- hwbp._SAFE_LIB_PATH: the /proc/pid/maps lib-path guard must reject any path with a
  shell metacharacter (the root command-injection sink) and accept real Android .so
  paths, so a crafted target cannot inject into the root monitor command.
- shlex.quote: even if a path slipped the guard, quoting must neutralize it inside the
  inner sh -c (the metacharacter ends up as a literal, not a command separator).
- config._frida_major: "latest" must classify as a modern major (>= 17), not 0, or the
  CLI prints the opposite Android-16 guidance.
"""
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.hwbp import _SAFE_LIB_PATH  # noqa: E402
from declaw.config import _frida_major, DEFAULT_FRIDA_VERSION  # noqa: E402

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

    print("\n%d failure(s)" % FAILS)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
