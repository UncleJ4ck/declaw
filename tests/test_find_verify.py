"""Hard-assertion tests for declaw.find_verify (live vs decoy ssl_verify_peer_cert).
Run: uv run python tests/test_find_verify.py

Self-contained, no device or full .so needed. Two layers:
  1. instruction predicates against real aarch64 encodings.
  2. scan_words against a real 848-byte slice of conscrypt BoringSSL .text covering
     both ssl_verify_peer_cert (live, 0x5aa30) and ssl_reverify_peer_cert (decoy,
     0x5ad30). The whole session's bug was patching the decoy, so this locks the
     classifier on ground truth.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from declaw.find_verify import (  # noqa: E402
    scan_words, _movz_w_0x2e, _ldr_x_0x30, _blr, _cmp_w0_1,
    _mov_w_w1, _sub_sp, _stp_fp_lr, _sub_imm,
)

# real conscrypt libssl .text, file offset 0x5aa30..0x5ad80 (p_offset==p_vaddr, so
# file offset == vaddr here). Contains ssl_verify_peer_cert then ssl_reverify_peer_cert.
_GT = (
    "ffc301d1fd7b01a9fb1300f9fa6703a9f85f04a9f65705a9f44f06a9fd4300915ad03bd5f403"
    "00aa481740f9e80700f9130040f9681a40f91be940f99b0600b4604740f93fba009488d243f9"
    "f50300aa084540f9e00308aa3aba0094bf0200eb21070054f5031faa88d243f9004540f934ba"
    "0094bf0200ebe20a0054604740f9e10315aa33ba009488d243f9f70300aae10315aa084540f9"
    "e00308aa2dba0094f90300aae00317aa1eba0094f60300aae00317aa1fba0094f70300aae003"
    "19aa18ba0094f80300aae00319aa19ba0094ff0200ebe1000054e00316aae10318aae20317aa"
    "77b90094b5060091e0fbff341f2003d5038cdd5000028052e1031f2a22228052a41f80521500"
    "0014880640f9c9058052e9130039081940f9e80200b4e1130091e00313aa00013fd61f040071"
    "000800544003003588d243f91f5900f9470000141f2003d56389dd5000028052e1031f2a2222"
    "8052041e805201b80094e00313aa41008052e2058052392300942000805249000014683640f9"
    "80d243f9e2130091e10314aa080940f9082540f900013fd6280080520001200a000600341f04"
    "0071a10700541f2003d54386dd5000028052e1031f2aa20f805224258052e8b70094e2134039"
    "e00313aa41008052e7ffff17738340f9730000b4e00313aac8ba009488d243f9008140f91381"
    "00f9400000b4c7b90094737f40f9730000b4e00313aabfba009488d243f9007d40f9137d00f9"
    "400000b4beb90094685b40f989d243f9e0031f2a285900f91b000014880640f9083144396800"
    "003420008052030000147fb80094e0031f2a88d243f949068052095900f940faff3568924239"
    "a8010037880640f9083504910801407928011036693640f9283141f9c80000b4213541f9e003"
    "13aa00013fd61f000071cd010054e0031f2a481740f9e90740f91f0109ebc1020054f44f46a9"
    "fb1340f9f65745a9f85f44a9fa6743a9fd7b41a9ffc30191c0035fd61f2003d5437ddd50f403"
    "002a00028052e1031f2a22248052a42680529fb700949f020071080a8052290e80522201881a"
    "b4ffff1771bf0094ff0301d1fd7b01a9f51300f9f44f03a9fd43009155d03bd5f303012ac905"
    "8052a81640f9e80700f9142040a9e9130039081940f9c80000b4e1130091e00314aa00013fd6"
    "1f040071c10100541f2003d5"
)

FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def main():
    # 1) predicates on real encodings
    check(_movz_w_0x2e(0x528005C9), "movz w9,#0x2e recognized")
    check(not _movz_w_0x2e(0x528005E0), "movz w0,#0x2f rejected")
    check(_mov_w_w1(0x2A0103F3), "mov w19,w1 recognized (reverify tell)")
    check(not _mov_w_w1(0x2A0203F3), "mov w19,w2 rejected (not the w1 arg)")
    check(_sub_sp(0xD101C3FF) and _sub_imm(0xD101C3FF) == 0x70, "sub sp,#0x70 + frame")
    check(_sub_sp(0xD10103FF) and _sub_imm(0xD10103FF) == 0x40, "sub sp,#0x40 + frame")
    check(_ldr_x_0x30(0xF9401908), "ldr x8,[x8,#0x30] recognized (callback load)")
    check(not _ldr_x_0x30(0xF9401D08), "ldr x8,[x8,#0x38] rejected (wrong offset)")
    check(_blr(0xD63F0100), "blr x8 recognized")
    check(_cmp_w0_1(0x7100041F), "cmp w0,#1 recognized")
    check(_stp_fp_lr(0xA9017BFD), "stp x29,x30,[sp,#0x10] recognized")

    # 2) classifier on the real ground-truth slice (base file offset/vaddr = 0x5aa30)
    chunk = bytes.fromhex(_GT)
    words = struct.unpack_from("<%dI" % (len(chunk) // 4), chunk, 0)
    r = scan_words(words, 0x5AA30, 0x5AA30)
    check(r["live"] == 0x5AA30, "picks live ssl_verify_peer_cert @0x5aa30 (got %s)"
          % (hex(r["live"]) if r["live"] is not None else None))
    check(r["reverify"] == 0x5AD30, "flags decoy ssl_reverify_peer_cert @0x5ad30 (got %s)"
          % (hex(r["reverify"]) if r["reverify"] is not None else None))
    live = [c for c in r["candidates"] if c["kind"] == "live"]
    rev = [c for c in r["candidates"] if c["kind"] == "reverify"]
    check(len(live) == 1 and not live[0]["reads_w1"] and live[0]["frame"] == 0x70,
          "live: one candidate, no w1 read, frame 0x70")
    check(len(rev) == 1 and rev[0]["reads_w1"] and rev[0]["frame"] == 0x40,
          "decoy: one candidate, reads w1, frame 0x40")

    print("\n%d failure(s)" % FAILS)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
