"""CLI mode resolution + routing. The 5 old mode flags collapsed into --mode/--offset;
this locks that the new flags AND the deprecated aliases route to the right runner.
Run: uv run python tests/test_cli.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import declaw.cli as C          # noqa: E402
import declaw.hwbp as H         # noqa: E402
import declaw.capture as CAP    # noqa: E402
from declaw.cli import parse_args, _resolve_mode  # noqa: E402

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def rm(*a):
    return _resolve_mode(parse_args(["TGT", *a]))


# --- (mode, offset) resolution: new flags + deprecated aliases ---
for got, want, name in [
    (rm(), ("auto", ""), "default -> auto"),
    (rm("--mode", "patch"), ("patch", ""), "--mode patch"),
    (rm("--mode", "mempatch", "--offset", "libssl.so@0x1"), ("mempatch", "libssl.so@0x1"), "mempatch+offset"),
    (rm("--mode", "hwbp"), ("hwbp", ""), "--mode hwbp"),
    (rm("--mode", "capture"), ("capture", ""), "--mode capture"),
    (rm("--auto"), ("auto", ""), "legacy --auto"),
    (rm("--capture"), ("capture", ""), "legacy --capture"),
    (rm("--hwbp-capture"), ("hwbp", ""), "legacy --hwbp-capture"),
    (rm("--patch-boringssl", "libssl.so@0x2"), ("patch", "libssl.so@0x2"), "legacy --patch-boringssl"),
    (rm("--mempatch", "libssl.so@0x3"), ("mempatch", "libssl.so@0x3"), "legacy --mempatch"),
]:
    check(got == want, f"resolve {name}: {got}")

# --- main() routes to the right runner (monkeypatched; no device) ---
calls = []
H.run_hwbp_capture = lambda *a, **k: (calls.append(("hwbp", a, k)) or 0)
H.run_mempatch = lambda *a, **k: (calls.append(("mempatch", a, k)) or 0)
CAP.run_capture = lambda *a, **k: (calls.append(("capture", a, k)) or 0)
C.run_pipeline = lambda **k: (calls.append(("pipeline", k)) or 0)
C.auto_detect_proxy_host = lambda serial: None


def route(argv):
    calls.clear()
    rc = C.main(argv)
    return (calls[0] if calls else None), rc


r, _ = route(["pkg", "--mode", "hwbp"])
check(r and r[0] == "hwbp", "route hwbp")
r, rc = route(["pkg", "--mode", "mempatch"])
check(rc == 2 and r is None, "mempatch without --offset -> error 2, no run")
r, _ = route(["pkg", "--mode", "mempatch", "--offset", "libssl.so@0x1"])
check(r and r[0] == "mempatch" and r[1][2] == "libssl.so@0x1", "mempatch+offset routed")
r, _ = route(["pkg", "--mode", "capture"])
check(r and r[0] == "capture", "route capture")
r, _ = route(["pkg", "--mode", "auto"])
check(r and r[0] == "pipeline" and r[1]["auto"] is True, "auto -> pipeline(auto=True)")
r, _ = route(["pkg", "--mode", "patch", "--offset", "libssl.so@0x9"])
check(r and r[0] == "pipeline" and r[1]["auto"] is False and r[1]["patch_boringssl"] == "libssl.so@0x9",
      "patch+offset -> pipeline(patch_boringssl set)")

print()
if FAILS:
    print(f"{FAILS} FAILURES")
    sys.exit(1)
print("all cli tests passed")
