"""declaw.build — apktool decode/build, signing and install."""
from __future__ import annotations

from pathlib import Path
import re
import shlex
import shutil
import subprocess as sp

from declaw.config import log
from declaw.shell import _java, _run


# --------------------------------------------------------------------------- #
#  apktool / signer                                                           #
# --------------------------------------------------------------------------- #

def apktool_decode(apk: Path, out_dir: Path, jar: Path, *, with_sources: bool) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    cmd = _java("-jar", str(jar), "d", "-f", "-o", str(out_dir))
    if not with_sources:
        cmd.append("-s")
    cmd.append(str(apk))
    log.info("Unpacking %s (sources=%s)", apk.name, "yes" if with_sources else "no")
    _run(cmd)


def apktool_build(unpacked: Path, out_apk: Path, jar: Path) -> None:
    log.info("Repacking -> %s", out_apk.name)
    _run(_java("-jar", str(jar), "b", "-f", str(unpacked), "-o", str(out_apk)))


_SIGNED_SUFFIX_RE = re.compile(r"-aligned-(?:debugSigned|signed)\.apk$")


def sign_apk(apk: Path, signer_jar: Path) -> Path:
    log.info("Signing %s", apk.name)
    _run(_java("-jar", str(signer_jar), "-a", str(apk), "--allowResign", "--overwrite"))
    if apk.exists():
        return apk
    for sib in apk.parent.iterdir():
        if _SIGNED_SUFFIX_RE.search(sib.name):
            sib.rename(apk)
            return apk
    raise RuntimeError(f"uber-apk-signer produced no output for {apk}")


# --------------------------------------------------------------------------- #
#  Install                                                                    #
# --------------------------------------------------------------------------- #

def install_apks(serial: str, apks: list[Path]) -> None:
    ordered = sorted(apks, key=lambda p: (0 if "base" in p.stem else 1, p.name))
    base_cmd = ["adb", "-s", serial, "install-multiple"]
    attempts = [
        base_cmd + ["-r", "-d", "-g", "-t"],
        base_cmd + ["-r", "-d"],
    ]
    for flags in attempts:
        try:
            _run(flags + list(map(str, ordered)), capture=True)
            log.info("Installed %d APK(s) on %s", len(ordered), serial)
            return
        except sp.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            stdout = (e.stdout or "").strip()
            detail = stderr or stdout or f"exit {e.returncode}"
            log.warning("install-multiple failed: %s. Trying next strategy.", detail)

    log.info("Falling back to pm install session …")
    total = sum(a.stat().st_size for a in ordered)
    session_out = _run(
        ["adb", "-s", serial, "shell", f"pm install-create -S {total}"],
        capture=True,
    ).stdout.strip()
    m = re.search(r"\[(\d+)\]", session_out)
    if not m:
        raise RuntimeError(f"Could not parse install-create output: {session_out!r}")
    sid = m.group(1)
    for idx, apk in enumerate(ordered):
        remote = f"/data/local/tmp/{apk.name}"
        # install-write/rm run through the device shell (adb space-joins the argv), so a
        # split name with a space would be mis-split there; quote it. push is sync-protocol
        # and takes the remote as one arg, so it needs no quoting.
        rq = shlex.quote(remote)
        _run(["adb", "-s", serial, "push", str(apk), remote])
        _run(["adb", "-s", serial, "shell",
              f"pm install-write -S {apk.stat().st_size} {sid} {idx} {rq}"])
        _run(["adb", "-s", serial, "shell", f"rm {rq}"], check=False)
    _run(["adb", "-s", serial, "shell", "pm", "install-commit", sid])
