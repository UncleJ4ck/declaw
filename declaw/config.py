"""declaw.config — Constants, defaults, logging, embedded NSC and CA."""
from __future__ import annotations

from pathlib import Path
import json
import logging
import os

from xml.etree import ElementTree as _stdlib_ET


# --------------------------------------------------------------------------- #
#  Constants                                                                  #
# --------------------------------------------------------------------------- #

ADB_HOST = os.environ.get("ADB_HOST", "127.0.0.1")
ADB_PORT = int(os.environ.get("ADB_PORT", "5037"))

APKTOOL_URL = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
UBER_APK_SIGNER_URL = "https://api.github.com/repos/patrickfav/uber-apk-signer/releases/latest"
BUNDLETOOL_URL = "https://api.github.com/repos/google/bundletool/releases/latest"

# Frida 17.x gadget script mode is BROKEN on Android. The gadget loads, parses
# the config, but never executes the JS script. Issue is tracked upstream:
#   https://github.com/frida/frida/issues/3526
#   https://github.com/frida/frida/issues/3645
# Symptom: console.log / Java.perform / setImmediate all silently no-op.
# Frida 16.7.19's Gum SIGSEGVs on Android 16+ the instant any hook executes
# (incompatible with the new ART/loader), so it is useless on current phones.
# Frida 17.x's Gum works there, but its gadget refuses to run a raw concatenated
# script (the language bridges were unbundled). The fix: ship the 17.x gadget and
# run the bundle through frida-compile (see _frida_compile), which inlines a shim
# providing the `Java` global + the moved Module APIs. That combination is the
# only one that works on EVERY Android. If node/frida-compile is unavailable we
# fall back to the 16.x gadget + raw bundle (fine for Android <= 15 only).
DEFAULT_FRIDA_VERSION = "17.15.2"
FALLBACK_FRIDA_VERSION = "16.7.19"  # used when frida-compile cannot run (no node)


def _frida_major(version: str) -> int:
    try:
        return int(version.lstrip("v").split(".")[0])
    except (ValueError, IndexError):
        return 0
FRIDA_RELEASES_TAG_URL = "https://api.github.com/repos/frida/frida/releases/tags/{tag}"
FRIDA_RELEASES_LATEST_URL = "https://api.github.com/repos/frida/frida/releases/latest"

# Bypass fragments grouped by category so the bundle is assembled per app
# from the frameworks actually detected, instead of always shipping every
# hook. (url, category). Categories:
#   "flutter-first" : Flutter BoringSSL bypass, must run before anything else
#   "core"          : Java/native TLS hooks that apply to almost any Android app
#   "flutter"       : extra Flutter hooks, only useful when libflutter is present
# The third field is the hook ENGINE:
#   "native" : pure Gum hooks (libc/BoringSSL/libflutter). GC-safe on every
#              Android, including 16+ under the 17.x gadget.
#   "java"   : instruments ART Java methods via frida-java-bridge. Crashes ART's
#              Concurrent Mark Compact GC on Android 16+ (frida-java-bridge#387),
#              so it is excluded unless explicitly requested or targeting old ART.
_NVISO = "https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js"
_HT = "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main"
BYPASS_FRAGMENTS = [
    # NVISO Flutter TLS bypass FIRST. It pattern-locates ssl_verify_peer_cert
    # in libflutter's BoringSSL and patches it to return success, the only
    # reliable defeat of Flutter's own-trust-store TLS. Native, GC-safe.
    (_NVISO, "flutter-first", "native"),
    (f"{_HT}/android/android-certificate-unpinning.js", "core", "java"),
    (f"{_HT}/android/android-certificate-unpinning-fallback.js", "core", "java"),
    # NB: httptoolkit's android-disable-flutter-certificate-pinning.js is omitted
    # on purpose: NVISO + the static libflutter patch already cover Flutter, and
    # it throws "multiple matches for CertificateCallback" on current engines.
    (f"{_HT}/android/android-disable-root-detection.js", "core", "java"),
    # Hooks Conscrypt/BoringSSL native verify -> defeats system-trust + native
    # pinning without touching Java. Covers most OkHttp apps (OkHttp uses
    # Conscrypt). Native, GC-safe.
    (f"{_HT}/native-tls-hook.js", "core", "native"),
    # Rewrites connect() at the libc level so all TCP lands on PROXY_HOST:PORT.
    # Required for Flutter and any app that ignores the system proxy. Native.
    (f"{_HT}/native-connect-hook.js", "core", "native"),
]
# Every fragment URL, in canonical order. Used for the DECLAW_BYPASS_URLS-less
# "include everything" path and as the back-compat default.
DEFAULT_BYPASS_URLS = [u for u, _, _ in BYPASS_FRAGMENTS]


def select_bypass_urls(frameworks: set[str], *, native_only: bool = False) -> list[str]:
    """Pick bypass fragments for the frameworks detected in this app.

    Core fragments (Java/native TLS, connect redirect, root detection) always
    apply. Flutter fragments are added only when libflutter is present, so an
    OkHttp app does not carry the Flutter BoringSSL scanner and a Flutter app
    gets NVISO first. When frameworks is empty (detection found nothing) every
    fragment is included, which is the safe superset.

    native_only drops the "java" (ART-instrumenting) fragments, which crash the
    GC on Android 16+. Used with the Frida 17.x gadget so the bundle works on
    every Android; the dropped Java pinning is covered statically by the NSC
    patch (and natively by native-tls-hook for Conscrypt/OkHttp).
    """
    def keep(engine: str) -> bool:
        return engine == "native" or not native_only
    is_flutter = "flutter" in frameworks or not frameworks
    first = [u for u, c, e in BYPASS_FRAGMENTS if c == "flutter-first" and is_flutter and keep(e)]
    core = [u for u, c, e in BYPASS_FRAGMENTS if c == "core" and keep(e)]
    flutter = [u for u, c, e in BYPASS_FRAGMENTS if c == "flutter" and is_flutter and keep(e)]
    return first + core + flutter

DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8000

ROOT_DIR = Path(__file__).resolve().parent.parent  # project root (package is one level down)
UTILS_DIR = ROOT_DIR / "utils"
PACKAGES_DIR = ROOT_DIR / "packages"
PATCHED_DIR = ROOT_DIR / "patched"
for _d in (UTILS_DIR, PACKAGES_DIR, PATCHED_DIR):
    _d.mkdir(exist_ok=True)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_stdlib_ET.register_namespace("android", ANDROID_NS)
QN_NSC = f"{{{ANDROID_NS}}}networkSecurityConfig"
QN_DEBUG = f"{{{ANDROID_NS}}}debuggable"
QN_CLEAR = f"{{{ANDROID_NS}}}usesCleartextTraffic"
QN_EXTRACT = f"{{{ANDROID_NS}}}extractNativeLibs"
QN_NAME = f"{{{ANDROID_NS}}}name"
QN_APP_COMPONENT_FACTORY = f"{{{ANDROID_NS}}}appComponentFactory"

FRIDA_ABI_MAP = {
    "arm64-v8a": "android-arm64",
    "armeabi-v7a": "android-arm",
    "armeabi": "android-arm",
    "x86": "android-x86",
    "x86_64": "android-x86_64",
}

# Stealth name for the gadget. Defeats /proc/self/maps grep-for-frida-gadget.
GADGET_LIBNAME = os.environ.get("DECLAW_GADGET_LIBNAME", "app-support")

BUNDLE_EXTENSIONS = {".xapk", ".apks", ".apkm", ".apkmos"}
AAB_EXTENSION = ".aab"

REFLUTTER_CSV_URL = "https://raw.githubusercontent.com/Impact-I/reFlutter/main/enginehash.csv"
REFLUTTER_RELEASE_URL = "https://github.com/Impact-I/reFlutter/releases/download/android-v2-{hash}/libflutter_{arch}.so"
REFLUTTER_ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
}
# Engines below 3.24.0 had a hardcoded Burp proxy baked in; we'd redirect
# traffic whether the user wanted it or not. Gate the static patch on this.
REFLUTTER_MIN_VERSION = (3, 24, 0)

SMALI_PIN_TARGETS = [
    ("okhttp3/CertificatePinner", "check"),
    ("com/datatheorem/android/trustkit/pinning/PinningTrustManager", "checkServerTrusted"),
    ("com/appmattus/certificatetransparency/internal/verifier/CertificateTransparencyTrustManager", "checkServerTrusted"),
]

NETWORK_SECURITY_CONFIG_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

# ISRG Root X1. Parses cleanly so CertificateFactory.generateCertificate
# inside the bundled hooks never throws when the user didn't pass --cert.
DEFAULT_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""

def _gadget_config_bytes() -> bytes:
    # NOTE: do NOT set on_change="reload". On Android the gadget would then
    # try to inotify the script directory under /data/app/<pkg>/lib/<abi>/,
    # which SELinux denies for untrusted_app (avc: denied { watch } tclass=dir).
    # The denial happens before the script ever runs, so every hook is silently
    # skipped. We don't need hot-reload at runtime; the gadget reads the script
    # once at process start and that's all that matters here.
    payload = {
        "interaction": {
            "type": "script",
            "path": f"./lib{GADGET_LIBNAME}.script.so",
        },
    }
    return json.dumps(payload, indent=2).encode("utf-8")


# --------------------------------------------------------------------------- #
#  Logging                                                                    #
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-5s %(message)s",
)
log = logging.getLogger("declaw")
