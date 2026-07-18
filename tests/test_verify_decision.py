"""Hard-assertion tests for the mempatch offset guard decision (device-free).
Run: uv run python tests/test_verify_decision.py

The device path (mempatch/hwbp/verify) needs a phone, but its decision core is pure:
given the finder's {live, decoy} and the user's offset, resolve auto, refuse the decoy,
warn on a mismatch. This locks that logic in CI with the real conscrypt/cronet offsets.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.hwbp import verify_offset_decision  # noqa: E402

# real ground-truth offsets
C_LIVE, C_DECOY = 0x5AA30, 0x5AD30   # conscrypt
R_LIVE, R_DECOY = 0x3AE98, 0x3B198   # cronet

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def main():
    # auto (off=None) resolves to the live offset
    off, err, warn = verify_offset_decision(C_LIVE, C_DECOY, None)
    check(off == C_LIVE and err is None and warn is None, "auto -> live 0x5aa30")

    # auto with no live candidate is a clear error, not a silent pass
    off, err, warn = verify_offset_decision(None, None, None)
    check(off is None and err and "pass --offset" in err, "auto, no candidate -> error")

    # the decoy offset is refused, with a pointer to the live one (conscrypt)
    off, err, warn = verify_offset_decision(C_LIVE, C_DECOY, C_DECOY)
    check(off is None and err and "DECOY" in err and "0x5aa30" in err,
          "conscrypt decoy 0x5ad30 refused -> live 0x5aa30")

    # same for cronet ground truth
    off, err, warn = verify_offset_decision(R_LIVE, R_DECOY, R_DECOY)
    check(off is None and err and "DECOY" in err and "0x3ae98" in err,
          "cronet decoy 0x3b198 refused -> live 0x3ae98")

    # the live offset passes clean, no warning
    off, err, warn = verify_offset_decision(C_LIVE, C_DECOY, C_LIVE)
    check(off == C_LIVE and err is None and warn is None, "explicit live 0x5aa30 -> ok")

    # an offset that is neither live nor decoy passes but warns
    off, err, warn = verify_offset_decision(C_LIVE, C_DECOY, 0x1234)
    check(off == 0x1234 and err is None and warn and "not the detected live" in warn,
          "unknown offset -> proceed + warn")

    # if the finder found nothing, an explicit offset is passed through unguarded
    off, err, warn = verify_offset_decision(None, None, 0xBEEF)
    check(off == 0xBEEF and err is None and warn is None, "no finder result -> explicit offset passes")

    print("\n%d failure(s)" % FAILS)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
