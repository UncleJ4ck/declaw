"""declaw.cli — Argument parsing and the main entry point."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import argparse
import logging
import os
import subprocess as sp
import sys

import requests

from declaw.config import DEFAULT_CERT_PEM, DEFAULT_FRIDA_VERSION, FALLBACK_FRIDA_VERSION, ROOT_DIR, _frida_major, log
from declaw.bypass import have_frida_compile
from declaw.device import auto_detect_proxy_host, parse_proxy
from declaw.pipeline import run_pipeline


# --------------------------------------------------------------------------- #
#  CLI                                                                        #
# --------------------------------------------------------------------------- #

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="declaw",
        description=("Patch an Android APK to stop caring about SSL pinning, "
                     "then reinstall it."),
        epilog="TARGET is either a package name (adb mode) or a path to an "
               ".apk file / directory of split APKs (local mode). "
               "Local mode is selected automatically when TARGET is an "
               "existing filesystem path.",
    )
    p.add_argument("target", help="Package name on device, or path to APK / split-APK dir")
    p.add_argument("-s", "--serial",
                   help="ADB serial (optional if exactly one device is attached)")
    p.add_argument("-o", "--output",
                   help="Directory to copy patched APK(s) into (timestamped subdir)")
    p.add_argument("-c", "--cert",
                   help="Path to a PEM to embed as CERT_PEM (e.g. Burp / mitmproxy CA). "
                        "Overrides DECLAW_CERT_PEM env var.")
    p.add_argument("--proxy", metavar="HOST:PORT",
                   help="Proxy address baked into the bundled hooks. Required for "
                        "Flutter and any app that ignores the system proxy (the "
                        "native-connect hook redirects TCP here). Overrides "
                        "DECLAW_PROXY env var. Default 127.0.0.1:8000.")
    p.add_argument("--mode", choices=["auto", "patch", "minimal", "capture", "hwbp", "mempatch"],
                   default="auto",
                   help="What declaw does (default auto). "
                        "auto: analyze the app and pick the best strategy. "
                        "patch: repackage the APK with the bypass baked in (OkHttp/Flutter). "
                        "minimal: NSC only, skip the gadget, keep the APK small. "
                        "capture: friTap key+pcap capture for pinned apps like cronet (root). "
                        "hwbp: zero-injection hardware-breakpoint key capture (root+arm64). "
                        "mempatch: zero-footprint in-memory cert-verify patch (root+arm64+--offset).")
    p.add_argument("--offset", metavar="LIB[@OFFSET]", default="",
                   help="BoringSSL ssl_verify_peer_cert offset, used by --mode patch (baked "
                        "into the .so) and --mode mempatch (written into the running process). "
                        "e.g. libssl.so@0x1f13c. For --mode patch and --mode mempatch, LIB or "
                        "LIB@auto auto-locates the LIVE ssl_verify_peer_cert (not the "
                        "ssl_reverify_peer_cert decoy, which patches cleanly but does nothing). "
                        "Print it for any .so with `python -m declaw.find_verify <lib.so>`.")
    p.add_argument("--debug-bundle", action="store_true", help=argparse.SUPPRESS)
    # Power-user knobs kept off the default --help; each reads its DECLAW_* env var.
    p.add_argument("--gadget-abis", metavar="LIST", default="", help=argparse.SUPPRESS)
    p.add_argument("--frida-version", metavar="X.Y.Z", default="", help=argparse.SUPPRESS)
    p.add_argument("--keep-abi", metavar="ABI", default="auto",
                   help="Which native ABI to keep in a fat multi-arch APK. Default 'auto' "
                        "strips to the connected device's arch (much smaller, installs in "
                        "seconds); 'all' keeps every ABI; or name one (e.g. arm64-v8a, "
                        "x86_64). No-op on split bundles and in local-file mode.")
    p.add_argument("--minimal", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--refresh", action="store_true",
                   help="Force re-download of apktool, signer, gadget, and bypass script.")
    p.add_argument("--verify", action="store_true",
                   help="After --mode mempatch, confirm the patched ssl_verify_peer_cert "
                        "actually executes on a handshake (non-destructive HW breakpoint); "
                        "revert to the original bytes if it never fires. Drive the app during "
                        "the watch so it makes an HTTPS request.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Debug logging. Shows every subprocess and cache hit.")
    # deprecated single-purpose mode flags: still work (back-compat), folded into --mode.
    p.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--capture", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--patch-boringssl", metavar="LIB@OFFSET", default="", help=argparse.SUPPRESS)
    p.add_argument("--hwbp-capture", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--mempatch", metavar="LIB@OFFSET", default="", help=argparse.SUPPRESS)
    p.add_argument("--capture-seconds", type=int, default=90, metavar="N",
                   help="How long to capture in --capture mode (default 90). Drive the "
                        "app during this window so it makes the TLS calls you want.")
    return p.parse_args(argv)


def load_cert_pem(args: argparse.Namespace) -> str:
    src = args.cert or os.environ.get("DECLAW_CERT_PEM")
    if src:
        path = Path(src).expanduser()
        if not path.exists():
            log.error("--cert path does not exist: %s", path)
            sys.exit(2)
        try:
            text = path.read_bytes().decode("utf-8").strip()
        except (UnicodeDecodeError, IsADirectoryError, OSError):
            log.error("%s does not look like a PEM certificate "
                      "(not UTF-8 text; a DER cert or a directory?).", path)
            sys.exit(2)
        if "BEGIN CERTIFICATE" not in text:
            log.error("%s does not look like a PEM certificate.", path)
            sys.exit(2)
        log.info("Embedding user-provided CA from %s", path)
        return text
    return DEFAULT_CERT_PEM


def _resolve_mode(args: argparse.Namespace) -> tuple[str, str]:
    """Effective (mode, offset). The deprecated single-purpose flags still work and
    take precedence, so old commands keep running; otherwise use --mode / --offset."""
    if getattr(args, "hwbp_capture", False):
        return "hwbp", args.offset
    if getattr(args, "mempatch", ""):
        return "mempatch", args.mempatch or args.offset
    if getattr(args, "capture", False):
        return "capture", args.offset
    if getattr(args, "patch_boringssl", ""):
        return "patch", args.patch_boringssl or args.offset
    if getattr(args, "auto", False):
        return "auto", args.offset
    return args.mode, args.offset


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    mode, offset = _resolve_mode(args)

    if mode == "hwbp":
        from declaw.hwbp import run_hwbp_capture
        out_dir = Path(args.output) if args.output else (ROOT_DIR / "captures")
        try:
            return run_hwbp_capture(args.target, args.serial, out_dir,
                                    seconds=args.capture_seconds, refresh=args.refresh)
        except (sp.CalledProcessError, sp.TimeoutExpired) as exc:
            log.error("External tool failed or timed out: %s", exc)
            return 6
        except KeyboardInterrupt:
            log.error("Interrupted.")
            return 130

    if mode == "mempatch":
        if not offset.strip():
            log.error("--mode mempatch needs at least the lib: --offset LIB@auto auto-locates "
                      "the LIVE ssl_verify_peer_cert in the running app (skipping the "
                      "ssl_reverify_peer_cert decoy), or LIB@0xNNN for a known offset "
                      "(e.g. libssl.so@0x5aa30).")
            return 2
        from declaw.hwbp import run_mempatch
        try:
            return run_mempatch(args.target, args.serial, offset, refresh=args.refresh,
                                 verify=args.verify)
        except (sp.CalledProcessError, sp.TimeoutExpired) as exc:
            log.error("External tool failed or timed out: %s", exc)
            return 6
        except KeyboardInterrupt:
            log.error("Interrupted.")
            return 130

    if mode == "capture":
        from declaw.capture import run_capture
        out_dir = Path(args.output) if args.output else (ROOT_DIR / "captures")
        try:
            return run_capture(args.target, args.serial, out_dir,
                               seconds=args.capture_seconds, refresh=args.refresh)
        except requests.RequestException as exc:
            log.error("Network error: %s", exc)
            return 4
        except (sp.CalledProcessError, sp.TimeoutExpired) as exc:
            log.error("External tool failed or timed out: %s", exc)
            return 6
        except KeyboardInterrupt:
            log.error("Interrupted.")
            return 130

    cert_pem = load_cert_pem(args)

    proxy_spec = (args.proxy or os.environ.get("DECLAW_PROXY", "")).strip()
    if not proxy_spec:
        # No explicit proxy. Try to auto-detect from a connected device so
        # the bundled connect hook actually targets a reachable address.
        auto = auto_detect_proxy_host(args.serial)
        if auto is not None:
            proxy_host, proxy_port = auto
        else:
            proxy_host, proxy_port = parse_proxy("")
    else:
        proxy_host, proxy_port = parse_proxy(proxy_spec)
    if proxy_spec:
        log.info("Bypass hooks will redirect TCP to %s:%d", proxy_host, proxy_port)
    else:
        log.debug("Using default proxy header %s:%d", proxy_host, proxy_port)

    debug_bundle = bool(args.debug_bundle) or os.environ.get("DECLAW_DEBUG_BUNDLE", "").strip() not in ("", "0", "false", "False")
    if debug_bundle:
        log.info("DEBUG_MODE enabled in bundled script. Tail `adb logcat -s declaw:V`.")

    frida_version = (args.frida_version or os.environ.get("DECLAW_FRIDA_VERSION", "")).strip() or DEFAULT_FRIDA_VERSION
    if _frida_major(frida_version) >= 17:
        if have_frida_compile():
            log.info("Frida %s gadget + frida-compile (native bundle): works on "
                     "every Android, including 16+.", frida_version)
        else:
            log.warning("Frida %s needs frida-compile (node) which is missing; will "
                        "fall back to %s (Android <= 15 only). Install Node.js for "
                        "Android 16+ support.", frida_version, FALLBACK_FRIDA_VERSION)
    else:
        log.warning("Frida %s: its Gum SIGSEGVs on Android 16+. Use the default %s "
                    "(needs node) for new devices.", frida_version, DEFAULT_FRIDA_VERSION)

    abi_src = (args.gadget_abis or os.environ.get("DECLAW_GADGET_ABIS", "")).strip()
    extra_abis = {a.strip() for a in abi_src.split(",") if a.strip()}
    if extra_abis:
        log.info("Extra gadget ABIs requested: %s", ", ".join(sorted(extra_abis)))

    # --mode minimal folds the old --minimal flag: skip the gadget, NSC only.
    minimal = bool(args.minimal) or mode == "minimal"
    # The injected hooks trust ONLY the baked CERT_PEM. With the built-in placeholder
    # (no -c / DECLAW_CERT_PEM) the patched app trusts a dummy cert, so HTTPS never
    # decrypts and the app throws an opaque "Trust anchor not found". Warn loudly; the
    # gadget path is the only one that bakes the cert, so skip the warning for minimal.
    if not minimal and not (args.cert or os.environ.get("DECLAW_CERT_PEM")):
        log.warning("No proxy CA supplied (-c / DECLAW_CERT_PEM): the injected hooks will "
                    "trust only a placeholder cert, so traffic will NOT decrypt through your "
                    "proxy (the app reports 'Trust anchor not found'). Pass -c "
                    "<your-burp-or-mitmproxy-CA.pem> so the patched app trusts your proxy.")
    # "all"/"none" (or empty) keep every ABI; "auto" resolves per device; else one ABI.
    keep_abi = None if args.keep_abi.strip().lower() in ("all", "none", "") else args.keep_abi.strip()

    try:
        return run_pipeline(
            target=args.target,
            serial=args.serial,
            output=Path(args.output) if args.output else None,
            minimal=minimal,
            refresh=args.refresh,
            cert_pem=cert_pem,
            extra_abis=extra_abis,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            debug_bundle=debug_bundle,
            frida_version=frida_version,
            auto=(mode == "auto"),
            capture_seconds=args.capture_seconds,
            keep_abi=keep_abi,
            patch_boringssl=((offset.strip() or None) if mode in ("patch", "auto") else None),
        )
    except requests.RequestException as exc:
        log.error("Network error: %s", exc)
        return 4
    except sp.CalledProcessError as exc:
        log.error("External tool failed: %s", exc)
        return 6
    except KeyboardInterrupt:
        log.error("Interrupted.")
        return 130
    except Exception as exc:  # pragma: no cover
        log.exception("Unhandled error: %s", exc)
        return 1
