"""declaw.bypass — Bypass-fragment selection, frida-compile and the script header."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import json
import os
import shutil
import subprocess as sp

import requests

from declaw.config import FALLBACK_FRIDA_VERSION, UTILS_DIR, log, select_bypass_urls


def _cache_fragment(url: str, *, refresh: bool) -> str:
    """Return a bypass fragment's text, caching it per-file under utils/fragments
    so assembling a per-app bundle never re-downloads and works offline once
    each fragment has been fetched."""
    frag_dir = UTILS_DIR / "fragments"
    frag_dir.mkdir(exist_ok=True)
    cached = frag_dir / url.rsplit("/", 1)[-1]
    if cached.exists() and not refresh:
        return cached.read_text(encoding="utf-8")
    log.info("Fetching bypass fragment: %s", cached.name)
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    cached.write_text(r.text, encoding="utf-8")
    return r.text


def fetch_bypass_script(
    cert_pem: str,
    *,
    refresh: bool,
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
    frameworks: Optional[set[str]] = None,
    dest: Optional[Path] = None,
    native_only: bool = False,
) -> Path:
    """Assemble a bypass bundle tailored to the detected frameworks.

    DECLAW_BYPASS_URLS overrides selection entirely (all listed URLs, in
    order). Otherwise select_bypass_urls() picks core hooks plus, only when
    libflutter is present, the Flutter BoringSSL bypass. Fragments are cached
    individually; the bundle itself is assembled fresh each call (cheap) so it
    always reflects the current app, cert, proxy and debug flags.

    native_only drops ART-instrumenting (Java) fragments for the Frida 17.x
    gadget so the bundle stays GC-safe on Android 16+.
    """
    urls_env = os.environ.get("DECLAW_BYPASS_URLS", "").strip()
    if urls_env:
        urls = [u for u in urls_env.split(";") if u]
    else:
        urls = select_bypass_urls(frameworks or set(), native_only=native_only)

    chosen = [u.rsplit("/", 1)[-1] for u in urls]
    log.info("Bypass strategy (%s): %s",
             ", ".join(sorted(frameworks)) if frameworks else "all",
             ", ".join(chosen))

    parts = [(url, _cache_fragment(url, refresh=refresh)) for url in urls]
    # DECLAW_EXTRA_SCRIPT: a local .js prepended to the bundle (runs right after
    # the header, before the fragments). For custom per-target hooks, e.g. a
    # getaddrinfo override on an emulator whose system DNS is broken.
    extra = os.environ.get("DECLAW_EXTRA_SCRIPT", "").strip()
    if extra:
        ep = Path(extra)
        if ep.is_file():
            parts.insert(0, (f"local:{ep.name}", ep.read_text(encoding="utf-8")))
            log.info("Prepended custom script %s", ep.name)
        else:
            log.warning("DECLAW_EXTRA_SCRIPT=%s not found; ignoring", extra)
    out = dest or (UTILS_DIR / "universal-bypass.js")
    # The Java hardening hooks (NetCap/WebView/anti-debug) instrument ART methods,
    # which intermittently crash the concurrent mark-compact GC on Android 16+.
    # On the native_only (Frida 17.x) path skip them; the core unpinning is all
    # native and GC-safe. They stay on the 16.x path (old ART tolerates them).
    return _write_bypass(out, cert_pem, parts,
                         proxy_host=proxy_host, proxy_port=proxy_port,
                         debug_bundle=debug_bundle,
                         java_hardening=not native_only)


def _write_bypass(
    cached: Path,
    cert_pem: str,
    parts: list[tuple[str, str]],
    *,
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
    java_hardening: bool = True,
) -> Path:
    header = _bypass_header(cert_pem, proxy_host, proxy_port, debug_bundle,
                            java_hardening=java_hardening)
    with open(cached, "w", encoding="utf-8") as fh:
        fh.write(header)
        for url, body in parts:
            fh.write(f"\n// ==== {url} ====\n")
            fh.write(body)
            if not body.endswith("\n"):
                fh.write("\n")
    return cached


# --------------------------------------------------------------------------- #
#  Frida 17.x: compile the bundle so the gadget can run it on every Android    #
# --------------------------------------------------------------------------- #
#
# The 17.x gadget will not run a raw concatenated 16.x-style script: the language
# bridges were unbundled and several Module APIs moved. frida-compile bundles a
# shim that restores the `Java` global (from frida-java-bridge) and the moved
# Module APIs, plus a waitForModule polyfill, so the existing fragments run
# unchanged. Validated on Android 16/17 (Cuttlefish arm64): native fragments
# load and patch ssl_verify_peer_cert with the process staying alive.
_FC_SHIM = (
    "import Java from 'frida-java-bridge';\n"
    "globalThis.Java = Java;\n"
    "const P = Process;\n"
    "if (!Module.getExportByName) Module.getExportByName = (m, s) => m === null"
    " ? Module.getGlobalExportByName(s)"
    " : (P.findModuleByName(m)?.getExportByName(s) ?? null);\n"
    "if (!Module.findExportByName) Module.findExportByName = (m, s) => { try {"
    " return m === null ? (Module.getGlobalExportByName?.(s) ?? null)"
    " : (P.findModuleByName(m)?.findExportByName(s) ?? null); } catch (e) { return null; } };\n"
    "globalThis.waitForModule = function (name, cb) { const hit = P.findModuleByName(name);"
    " if (hit) { cb(hit); return; }"
    " const iv = setInterval(() => { const m = P.findModuleByName(name);"
    " if (m) { clearInterval(iv); cb(m); } }, 500); };\n"
)


def have_frida_compile() -> bool:
    return all(shutil.which(t) is not None for t in ("node", "npm", "npx"))


def _ensure_fc_project(*, refresh: bool = False) -> Path:
    """Create (once) and return the cached frida-compile project under utils/fc."""
    fc = UTILS_DIR / "fc"
    installed = fc / "node_modules" / "frida-compile"
    (fc / "shim.js").parent.mkdir(parents=True, exist_ok=True)
    (fc / "package.json").write_text(
        '{"name":"declaw-fc","version":"1.0.0","type":"module","private":true}\n',
        encoding="utf-8")
    (fc / "shim.js").write_text(_FC_SHIM, encoding="utf-8")
    (fc / "entry.js").write_text("import './shim.js';\nimport './declaw-bundle.js';\n",
                                 encoding="utf-8")
    if installed.exists() and not refresh:
        return fc
    log.info("Installing frida-compile + frida-java-bridge (one-time) ...")
    sp.run(["npm", "i", "--silent", "frida-compile@19", "frida-java-bridge@7"],
           cwd=fc, check=True)
    return fc


def frida_compile_bundle(bundle: Path) -> Optional[Path]:
    """Compile the raw bundle into a single script the Frida 17.x gadget runs.

    Returns the compiled .js path, or None if frida-compile is unavailable so the
    caller can fall back to the 16.x gadget + raw bundle.
    """
    if not have_frida_compile():
        log.warning("node/npx not found: cannot frida-compile for the 17.x gadget. "
                    "Falling back to Frida %s (works on Android <= 15 only). "
                    "Install Node.js for Android 16+ support.", FALLBACK_FRIDA_VERSION)
        return None
    try:
        fc = _ensure_fc_project()
        shutil.copy2(bundle, fc / "declaw-bundle.js")
        out = fc / "compiled.js"
        if out.exists():
            out.unlink()
        sp.run(["npx", "--yes", "frida-compile", "entry.js", "-o", str(out)],
               cwd=fc, check=True)
        if not out.exists():
            raise RuntimeError("frida-compile produced no output")
        log.info("frida-compiled bundle for the 17.x gadget (%d KB)",
                 out.stat().st_size // 1024)
        return out
    except Exception as exc:  # noqa: BLE001 - any failure -> fall back gracefully
        log.warning("frida-compile failed (%s). Falling back to Frida %s.",
                    exc, FALLBACK_FRIDA_VERSION)
        return None


def _bypass_header(cert_pem: str, proxy_host: str, proxy_port: int,
                   debug_bundle: bool = False, java_hardening: bool = True) -> str:
    escaped_pem = cert_pem.strip()
    debug_flag = "true" if debug_bundle else "false"
    # The connect-hook only SOCKS5-proxies redirected TCP when this is true; with
    # false it does a transparent redirect that needs SO_ORIGINAL_DST (lost by the
    # rewrite). declaw redirects arbitrary TCP to a host proxy, so SOCKS5 is the
    # correct default: run mitmproxy `--mode socks5` or Burp's SOCKS listener.
    # Override with DECLAW_PROXY_SOCKS5=0 for a transparent proxy.
    socks5_flag = ("false" if os.environ.get("DECLAW_PROXY_SOCKS5", "").lower()
                   in ("0", "false", "no") else "true")
    # When debug_bundle is on, route every console.log through android.util.Log
    # so output is visible under `adb logcat -s declaw:V`. Without this the
    # gadget's console output goes to a buffer that never reaches logcat.
    # File beacon written from the JS thread immediately, no Java needed.
    # Frida's File API is sync and always present, so this proves the script
    # actually executed. Path is the app's private files dir, world-unreadable
    # but readable via `adb shell run-as <pkg>` (works because manifest sets
    # debuggable=true).
    beacon_block = (
        "// ---- declaw debug beacon ----\n"
        "// Bridge console.log to logcat SYNCHRONOUSLY via libc __android_log_write\n"
        "// so the httptoolkit installer fragments that run on script load (before\n"
        "// any Java.perform completes) surface their messages too. Without this,\n"
        "// an installer that throws shows up later as an InvocationTargetException\n"
        "// at the call site instead of a clear [skip] line at install time.\n"
        "(function () { try {\n"
        "  const liblog = Module.findExportByName('liblog.so', '__android_log_write')\n"
        "    || Module.findExportByName(null, '__android_log_write');\n"
        "  if (liblog) {\n"
        "    const __wr = new NativeFunction(liblog, 'int', ['int', 'pointer', 'pointer']);\n"
        "    const __tag = Memory.allocUtf8String('declaw');\n"
        "    const __orig = console.log;\n"
        "    console.log = function () {\n"
        "      const m = Array.prototype.slice.call(arguments).join(' ');\n"
        "      try { __wr(3, __tag, Memory.allocUtf8String(m)); } catch (e) {}\n"
        "      try { __orig.apply(console, arguments); } catch (e) {}\n"
        "    };\n"
        "    console.warn = console.error = console.log;\n"
        "    console.log('bundle alive, proxy=' + PROXY_HOST + ':' + PROXY_PORT);\n"
        "  }\n"
        "} catch (e) {} })();\n"
        "// Java-side beacon (best effort once the VM is ready).\n"
        "setImmediate(function () { try { Java.perform(function () {\n"
        "  try { Java.use('android.util.Log').d('declaw', 'Java ready'); } catch (e) {}\n"
        "}); } catch (e) {} });\n"
        "// ---- end debug beacon ----\n"
    )
    debug_block = beacon_block if debug_bundle else ""

    # Small, high-value Java hooks the httptoolkit bundle does NOT cover.
    # All wrapped with safeHook so a missing class can never take down the
    # rest of the script (cf. "Too many hooks spoil the app", j4k0m, 2026).
    # These fire BEFORE the httptoolkit fragments via setImmediate(Java.perform).
    hardening_block = (
        "// ---- declaw hardening hooks (NetCap, WebView, anti-debug) ----\n"
        "setImmediate(function () { try { Java.perform(function () {\n"
        "  const __declawTag = 'declaw';\n"
        "  function safeHook(name, install) {\n"
        "    try {\n"
        "      install();\n"
        "      try { Java.use('android.util.Log').d(__declawTag, '[hook] ' + name); } catch (e) {}\n"
        "    } catch (error) {\n"
        "      try { Java.use('android.util.Log').d(__declawTag,\n"
        "        '[skip] ' + name + ': ' + (error.message || error)); } catch (e) {}\n"
        "    }\n"
        "  }\n"
        "\n"
        "  // 1) NetworkCapabilities.hasCapability(int), selective.\n"
        "  // An inspection proxy can leave NET_CAPABILITY_INTERNET (12) present\n"
        "  // but disturb NET_CAPABILITY_VALIDATED (16). Apps that gate requests\n"
        "  // on both report 'offline' and never make calls; the connect-hook\n"
        "  // then has nothing to redirect. Returning true for ONLY those two\n"
        "  // preserves every other capability check (VPN, metered, transport).\n"
        "  safeHook('NetworkCapabilities.hasCapability', function () {\n"
        "    const NetCap = Java.use('android.net.NetworkCapabilities');\n"
        "    const orig = NetCap.hasCapability.overload('int');\n"
        "    orig.implementation = function (cap) {\n"
        "      if (cap === 12 || cap === 16) return true;\n"
        "      return orig.call(this, cap);\n"
        "    };\n"
        "  });\n"
        "\n"
        "  // 2) WebViewClient.onReceivedSslError, handler.proceed().\n"
        "  // Covers any embedded WebView page that hits an SSL error against\n"
        "  // the Burp / mitmproxy CA. Cheap, broad, no false positives because\n"
        "  // it only runs when an SSL error already occurred.\n"
        "  safeHook('WebViewClient.onReceivedSslError', function () {\n"
        "    const WVC = Java.use('android.webkit.WebViewClient');\n"
        "    WVC.onReceivedSslError.implementation = function (view, handler, error) {\n"
        "      handler.proceed();\n"
        "    };\n"
        "  });\n"
        "\n"
        "  // 3) android.os.Debug status, suppress the reaction not the env.\n"
        "  // Setting debuggable=true in the manifest makes some apps refuse to\n"
        "  // run when isDebuggerConnected() / waitingForDebugger() return true.\n"
        "  // Returning false from both is the smallest behavioural change.\n"
        "  safeHook('Debug.isDebuggerConnected', function () {\n"
        "    Java.use('android.os.Debug').isDebuggerConnected.implementation = function () { return false; };\n"
        "  });\n"
        "  safeHook('Debug.waitingForDebugger', function () {\n"
        "    Java.use('android.os.Debug').waitingForDebugger.implementation = function () { return false; };\n"
        "  });\n"
        "}); } catch (e) {} });\n"
        "// ---- end declaw hardening ----\n"
    )

    return (
        "// declaw universal SSL-unpinning bundle\n"
        "// Generated header. Downstream hooks read these globals.\n"
        f"const CERT_PEM = {json.dumps(escaped_pem + chr(10))};\n"
        f"const PROXY_HOST = {json.dumps(proxy_host)};\n"
        f"const PROXY_PORT = {proxy_port};\n"
        f"const DEBUG_MODE = {debug_flag};\n"
        "const IGNORED_NON_HTTP_PORTS = [];\n"
        "const BLOCK_HTTP3 = true;\n"
        f"const PROXY_SUPPORTS_SOCKS5 = {socks5_flag};\n"
        f"{debug_block}"
        f"{hardening_block if java_hardening else ''}"
        "// ---- declaw header end ----\n"
    )
