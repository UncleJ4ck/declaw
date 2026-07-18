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

# --- --minimal folded into --mode minimal (must force minimal=True, not a full repack) ---
r, _ = route(["pkg", "--mode", "minimal"])
check(r and r[0] == "pipeline" and r[1]["minimal"] is True and r[1]["auto"] is False,
      "--mode minimal -> pipeline(minimal=True, auto=False)")
r, _ = route(["pkg", "--minimal"])
check(r and r[0] == "pipeline" and r[1]["minimal"] is True and r[1]["auto"] is True,
      "legacy --minimal alias -> pipeline(minimal=True, auto=True)")

# --- keep-abi default is auto; 'all'/'none' keep every ABI; a name forces one ---
r, _ = route(["pkg"])
check(r and r[1]["keep_abi"] == "auto", "default keep_abi=auto")
r, _ = route(["pkg", "--keep-abi", "all"])
check(r and r[1]["keep_abi"] is None, "--keep-abi all -> keep every ABI (None)")
r, _ = route(["pkg", "--keep-abi", "none"])
check(r and r[1]["keep_abi"] is None, "--keep-abi none -> keep every ABI (None)")
r, _ = route(["pkg", "--keep-abi", "x86_64"])
check(r and r[1]["keep_abi"] == "x86_64", "--keep-abi x86_64 -> that ABI")

# --- _pick_abi: device abilist (priority) intersected with the app's shipped ABIs ---
from declaw.pipeline import _pick_abi  # noqa: E402
for got, want, name in [
    (_pick_abi(["arm64-v8a", "armeabi-v7a", "armeabi"], {"arm64-v8a", "armeabi-v7a"}), "arm64-v8a",
     "arm64 phone keeps primary arm64"),
    (_pick_abi(["x86_64", "arm64-v8a"], {"x86_64", "arm64-v8a"}), "x86_64",
     "x86_64 emulator keeps native x86_64 when shipped"),
    (_pick_abi(["x86_64", "arm64-v8a"], {"arm64-v8a", "armeabi-v7a"}), "arm64-v8a",
     "x86_64 emulator, arm64-only app -> keep arm64-v8a (the win)"),
    (_pick_abi(["arm64-v8a", "armeabi-v7a", "armeabi"], {"armeabi-v7a"}), "armeabi-v7a",
     "32-bit-only app on arm64 device -> keep armeabi-v7a, do not brick"),
    (_pick_abi(["x86_64"], {"arm64-v8a"}), None, "no match -> None (keep all)"),
    (_pick_abi(["arm64-v8a"], set()), None, "app has no native libs -> None (keep all)"),
]:
    check(got == want, f"_pick_abi {name}: got {got!r}")

print()
if FAILS:
    print(f"{FAILS} FAILURES")
    sys.exit(1)
print("all cli tests passed")
