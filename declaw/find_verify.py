#!/usr/bin/env python3
"""Locate the LIVE ssl_verify_peer_cert in a from-source BoringSSL .so.

BoringSSL ships two look-alikes that both call config->custom_verify_callback:
  - ssl_verify_peer_cert(hs)              <- the one the handshake calls (patch THIS)
  - ssl_reverify_peer_cert(hs, send_alert)<- resumption/hints path (DECOY: patch = no-op)

They compile almost identically. The reliable tell: the reverify variant takes a
second arg (send_alert) and reads it (`mov w?, w1`) near the top; the live one takes
a single arg and never reads w1. Both are stripped and objdump mislabels them as the
nearest export, so name-based lookup fails. This finds them by shape.
"""
import struct
import sys

# aarch64 instruction predicates (little-endian 32-bit words)
def _movz_w_0x2e(w): return (w & 0xFFFFFFE0) == 0x528005C0   # movz w?, #0x2e (default alert 46)
def _ldr_x_0x30(w):  return (w & 0xFFC00000) == 0xF9400000 and ((w >> 10) & 0xFFF) == 6  # ldr x?,[x?,#0x30]
def _blr(w):         return (w & 0xFFFFFC1F) == 0xD63F0000   # blr x?
def _cmp_w0_1(w):    return w == 0x7100041F                  # cmp w0, #1  (subs wzr,w0,#1)
def _mov_w_w1(w):    return (w & 0xFFFFFFE0) == 0x2A0103E0   # mov w?, w1  (orr w?,wzr,w1)
def _sub_sp(w):      return (w & 0xFF0003FF) == 0xD10003FF   # sub sp, sp, #imm (sh=0)
def _stp_fp_lr(w):   return (w & 0xFFC07FFF) == 0xA9007BFD   # stp x29,x30,[sp,#imm]
def _sub_imm(w):     return (w >> 10) & 0xFFF                # imm12 of a sub (frame size)


def _exec_segment(data):
    """Return (file_offset, vaddr, size) of the first PT_LOAD with PF_X. ELF64 LE only."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("not an ELF64 file")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        if p_type == 1 and (p_flags & 1):            # PT_LOAD, PF_X
            p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 8)
            p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
            return p_offset, p_vaddr, p_filesz
    raise ValueError("no executable LOAD segment")


def scan_words(words, seg_off, seg_va):
    """Classify verify functions in a list of aarch64 instruction words. Pure; unit-testable.

    Returns {'live', 'reverify', 'candidates'}. foff = seg_off + index*4 (the FILE offset
    to hand declaw), vaddr = seg_va + index*4.
    """
    n = len(words)
    # 1) callback sites: movz #0x2e, then ldr[#0x30] -> blr -> cmp w0,#1 within a short window
    sites = []
    for i in range(n):
        if not _movz_w_0x2e(words[i]):
            continue
        ldr = blr = None
        for j in range(i + 1, min(i + 18, n)):
            if ldr is None and _ldr_x_0x30(words[j]):
                ldr = j
            elif ldr is not None and blr is None and _blr(words[j]):
                blr = j
            elif blr is not None and _cmp_w0_1(words[j]):
                sites.append(i)
                break
            elif blr is not None:
                break
    # 2) map each site to its function entry (nearest preceding `sub sp` + `stp x29,x30`)
    seen = {}
    for site in sites:
        entry = None
        for k in range(site, max(site - 512, -1), -1):
            if _sub_sp(words[k]) and any(_stp_fp_lr(words[k + d]) for d in (1, 2, 3) if k + d < n):
                entry = k
                break
        if entry is None or entry in seen:
            continue
        reads_w1 = any(_mov_w_w1(words[m]) for m in range(entry, site + 1))
        seen[entry] = {
            "foff": seg_off + entry * 4,
            "vaddr": seg_va + entry * 4,
            "reads_w1": reads_w1,
            "frame": _sub_imm(words[entry]),
            "kind": "reverify" if reads_w1 else "live",
        }
    cands = sorted(seen.values(), key=lambda c: c["vaddr"])
    lives = [c for c in cands if c["kind"] == "live"]
    revs = [c for c in cands if c["kind"] == "reverify"]
    # tiebreak among multiple 'live': the real ssl_verify_peer_cert has the larger frame
    live = max(lives, key=lambda c: c["frame"])["foff"] if lives else None
    return {"live": live, "reverify": revs[0]["foff"] if revs else None, "candidates": cands}


def find_in_bytes(data):
    """Locate the live/reverify verify functions in raw ELF64 bytes.

    Each candidate: {foff, vaddr, reads_w1, frame, kind}. foff is the FILE offset to
    hand to declaw (--offset LIB@0x...) / boringssl_patch / mempatch.
    """
    seg_off, seg_va, seg_sz = _exec_segment(data)
    text = data[seg_off:seg_off + seg_sz]
    words = struct.unpack_from("<%dI" % (len(text) // 4), text, 0)
    return scan_words(words, seg_off, seg_va)


def find_candidates(path):
    """Read a BoringSSL .so and locate the live/reverify verify functions."""
    with open(path, "rb") as f:
        return find_in_bytes(f.read())


def main():
    if len(sys.argv) < 2:
        print("usage: find_verify.py <boringssl.so>", file=sys.stderr)
        return 2
    r = find_candidates(sys.argv[1])
    for c in r["candidates"]:
        print("  %-9s foff=0x%-7x vaddr=0x%-7x frame=0x%-3x reads_w1=%s"
              % (c["kind"], c["foff"], c["vaddr"], c["frame"], c["reads_w1"]))
    if r["live"] is not None:
        print("LIVE ssl_verify_peer_cert file offset: 0x%x" % r["live"])
    else:
        print("no live candidate found for the modern conscrypt/cronet shape "
              "(config->custom_verify at [x8,#0x30]).")
        print("If this is libflutter.so or an older BoringSSL, use declaw's Flutter "
              "signature patcher instead: declaw <app> --mode patch (it scans libflutter "
              "for ssl_verify_peer_cert directly). Otherwise patch a candidate above and "
              "confirm with a BRK-probe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
