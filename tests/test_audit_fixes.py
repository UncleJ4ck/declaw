"""Hard-assertion tests for the pure logic behind two audit fixes (device-free).
Run: uv run python tests/test_audit_fixes.py

- shell._newest_jar: cached-tool selection must pick the highest version, not the
  lexicographically-last filename (2.11.1 beats 2.9.3, which a plain sort gets wrong).
- config.safe_pkg: must reject `..` / all-dot package names, or `PACKAGES_DIR / pkg`
  escapes the cache dir (the docstring promises no traversal).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.shell import _jar_version_key, _newest_jar  # noqa: E402
from declaw.config import safe_pkg  # noqa: E402

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def main():
    # version key is numeric, so 2.11.1 > 2.9.3 (lexicographic gets this backwards)
    check(_jar_version_key("apktool_2.11.1.jar") > _jar_version_key("apktool_2.9.3.jar"),
          "2.11.1 > 2.9.3 numerically")
    check(_jar_version_key("bundletool-1.17.2.jar") > _jar_version_key("bundletool-1.9.0.jar"),
          "bundletool 1.17.2 > 1.9.0")

    # _newest_jar picks the highest version regardless of glob order
    newest = _newest_jar([Path("apktool_2.9.3.jar"), Path("apktool_2.11.1.jar")])
    check(newest is not None and newest.name == "apktool_2.11.1.jar",
          "newest jar of {2.9.3, 2.11.1} is 2.11.1")
    check(_newest_jar([Path("apktool_2.11.1.jar"), Path("apktool_2.9.3.jar")]).name
          == "apktool_2.11.1.jar", "order-independent (reversed input)")
    check(_newest_jar([]) is None, "empty -> None")

    # safe_pkg rejects traversal and empties, accepts real package names
    for bad in ("", ".", "..", "...", "a..b", "../etc", "a/b", "a b", "a;b"):
        try:
            safe_pkg(bad)
            check(False, f"safe_pkg wrongly accepted {bad!r}")
        except ValueError:
            check(True, f"safe_pkg rejects {bad!r}")
    for ok in ("com.example.app", "com.x_y.z2", "a.b.c"):
        check(safe_pkg(ok) == ok, f"safe_pkg accepts {ok!r}")

    print("\n%d failure(s)" % FAILS)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
