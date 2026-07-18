"""declaw.inject — Gadget injection, bundle extraction and smali pin patches."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import re
import shutil
import uuid
import zipfile

from defusedxml import ElementTree as ET
from xml.etree import ElementTree as _stdlib_ET

from declaw.config import ANDROID_NS, DEFAULT_FRIDA_VERSION, FRIDA_ABI_MAP, GADGET_LIBNAME, PACKAGES_DIR, QN_NAME, SMALI_PIN_TARGETS, _gadget_config_bytes, log
from declaw.gadget import _align_native_lib_16k, fetch_frida_gadget
from declaw.manifest import ApkInspection, ManifestPatchResult, _find_smali_for_class, _inject_load_library, _load_library_smali


def inject_frida_gadget(
    unpacked: Path,
    inspection: ApkInspection,
    manifest: ManifestPatchResult,
    *,
    bypass_script: Path,
    refresh: bool,
    extra_abis: Optional[set[str]] = None,
    frida_version: str = DEFAULT_FRIDA_VERSION,
) -> None:
    # Detected ABIs plus any caller-requested extras. Useful when the source
    # APK is single-arch (e.g. arm64-v8a from a Pixel) but we want to install
    # on a different-arch sandbox (e.g. x86_64 emulator). Android picks the
    # matching lib/<abi>/ at install time, so the unused gadget never loads.
    target_abis = set(inspection.abis)
    if extra_abis:
        target_abis |= extra_abis
    target_abis = sorted(target_abis) or ["arm64-v8a"]

    lib_root = unpacked / "lib"
    lib_root.mkdir(exist_ok=True)

    config_bytes = _gadget_config_bytes()
    gadget_file = f"lib{GADGET_LIBNAME}.so"
    config_file = f"lib{GADGET_LIBNAME}.config.so"
    script_file = f"lib{GADGET_LIBNAME}.script.so"

    for abi in target_abis:
        if abi not in FRIDA_ABI_MAP:
            log.warning("Skipping unsupported ABI for gadget: %s", abi)
            continue
        gadget_so = fetch_frida_gadget(abi, refresh=refresh, version=frida_version)
        abi_dir = lib_root / abi
        abi_dir.mkdir(parents=True, exist_ok=True)
        realigned = _align_native_lib_16k(gadget_so, abi_dir / gadget_file)
        (abi_dir / config_file).write_bytes(config_bytes)
        shutil.copy2(bypass_script, abi_dir / script_file)
        log.info(
            "Gadget + unpin script placed in lib/%s/ as %s%s",
            abi, gadget_file, " (re-aligned to 16 KB pages)" if realigned else "",
        )

    target_class = manifest.application_class or manifest.launcher_activity
    loaded = False
    if target_class:
        smali_path = _find_smali_for_class(unpacked, target_class)
        if smali_path is not None:
            if _inject_load_library(smali_path):
                log.info("Injected loadLibrary(\"%s\") into %s", GADGET_LIBNAME, target_class)
            else:
                log.info("Gadget loader already present in %s", target_class)
            loaded = True

    if not loaded:
        # Only synthesize the wrapper when there is no original Application
        # class. Subclassing one whose smali we couldn't locate would crash
        # at launch with NoClassDefFoundError.
        if manifest.application_class is None:
            inject_application_wrapper(unpacked, None)
            loaded = True
        else:
            log.warning(
                "Could not locate smali for %s. Skipping Application wrapper; "
                "the gadget will load via the ContentProvider path only.",
                manifest.application_class,
            )

    # Belt-and-braces: a ContentProvider is constructed before
    # Application.onCreate(), so it loads the gadget even if the
    # Application path is skipped.
    inject_content_provider(unpacked)


# --------------------------------------------------------------------------- #
#  Bundle input (.xapk, .apks, .apkm)                                         #
# --------------------------------------------------------------------------- #

def extract_bundle(bundle_path: Path) -> Path:
    """Unpack a .xapk / .apks / .apkm into a flat dir of .apk files."""
    out_dir = PACKAGES_DIR / f"{bundle_path.stem}_bundle"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    log.info("Extracting bundle %s", bundle_path.name)
    with zipfile.ZipFile(bundle_path) as zf:
        for name in zf.namelist():
            if name.lower().endswith(".apk"):
                zf.extract(name, out_dir)
    # Flatten: move any nested .apk to the top level.
    for apk in list(out_dir.rglob("*.apk")):
        if apk.parent != out_dir:
            target = out_dir / apk.name
            if target.exists():
                log.warning("Bundle has two splits named %s; keeping the later "
                            "one (%s). If install-multiple later fails, the "
                            "bundle nests distinct splits under the same name.",
                            apk.name, apk)
                target.unlink()
            shutil.move(str(apk), str(target))
    # Drop empty subdirs.
    for sub in sorted(out_dir.iterdir(), reverse=True):
        if sub.is_dir():
            try:
                sub.rmdir()
            except OSError:
                pass
    found = sorted(out_dir.glob("*.apk"))
    if not found:
        raise RuntimeError(
            f"No .apk files inside bundle {bundle_path.name}. "
            "Is this a valid .xapk / .apks / .apkm container?"
        )
    log.info("Extracted %d APK(s) from bundle", len(found))
    return out_dir


# --------------------------------------------------------------------------- #
#  Smali-level pinning patches (apk-mitm style backup layer)                  #
# --------------------------------------------------------------------------- #

def apply_smali_pin_patches(unpacked: Path) -> int:
    """Stub well-known pinning classes' methods to `return-void`.

    Runs in addition to the runtime Frida hooks. If the target app kills
    Frida, the static patch still disables the most common Java-layer
    pinning. Count of patched methods is returned for logging.
    """
    patched = 0
    for class_path, method_name in SMALI_PIN_TARGETS:
        rel = class_path + ".smali"
        for smali_root in sorted(unpacked.glob("smali*")):
            target = smali_root / rel
            if not target.is_file():
                continue
            if _patch_void_method_to_noop(target, method_name):
                log.info("Smali-patched %s.%s", class_path, method_name)
                patched += 1
    if patched == 0:
        log.debug("No smali pin-patch targets found in this APK.")
    return patched


def _patch_void_method_to_noop(smali_path: Path, method_name: str) -> bool:
    """Replace the body of every `<method_name>(...)V` in the file with `return-void`."""
    text = smali_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"(\.method\s+(?:\w+\s+)*{re.escape(method_name)}\([^)]*\)V[^\n]*\n)"
        r"(.*?)"
        r"(\.end method)",
        re.DOTALL,
    )
    def repl(m: "re.Match[str]") -> str:
        decl = m.group(1)
        # abstract/native methods have no body; injecting one fails apktool build.
        if re.search(r"\b(abstract|native)\b", decl):
            return m.group(0)
        return f"{decl}    .locals 0\n    return-void\n{m.group(3)}"

    new_text, n = pattern.subn(repl, text)
    if new_text != text:
        smali_path.write_text(new_text, encoding="utf-8")
        return True
    return False


# --------------------------------------------------------------------------- #
#  Application-class wrapper (fallback when we cannot patch the original)     #
# --------------------------------------------------------------------------- #

_WRAPPER_CLASS = "com/declaw/DeclawApp"
_PROVIDER_CLASS = "com/declaw/DeclawPreload"


def _apktool_min_sdk(unpacked: Path) -> int:
    """Best-effort minSdkVersion from apktool.yml. 0 if unknown."""
    yml = unpacked / "apktool.yml"
    if not yml.exists():
        return 0
    for line in yml.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = re.search(r"minSdkVersion:\s*['\"]?(\d+)", line)
        if m:
            return int(m.group(1))
    return 0


def _injection_smali_dir(unpacked: Path) -> Path:
    """Where to write an injected class.

    apktool maps `smali` -> classes.dex, `smali_classes2` -> classes2.dex, etc.
    Large apps (Signal, banking, social) fill their first dex right up to the
    64K method/field/type reference ceiling. Dropping a class into the existing
    `smali` folder then tips that dex over the limit and apktool fails the
    rebuild with "Unsigned short value out of range: 65536". Putting our class
    in a brand-new dex folder gives it a full 64K of headroom.

    But a *second* dex only loads at runtime when the app is multidex-capable:
    API 21+ loads every classesN.dex natively; older apps need the multidex
    support library, which a single-dex legacy app will not have. So only use a
    fresh dex when it is safe:
      - the app is already multidex (smali_classes2 exists), or
      - minSdkVersion >= 21.
    Otherwise fall back to `smali` (classes.dex). Single-dex legacy apps are
    small and nowhere near the 64K ceiling, so the overflow cannot happen there.
    """
    dex_dirs = sorted(
        p.name for p in unpacked.iterdir()
        if p.is_dir() and re.fullmatch(r"smali(_classes\d+)?", p.name)
    )
    already_multidex = any(d != "smali" for d in dex_dirs)
    min_sdk = _apktool_min_sdk(unpacked)

    if not (already_multidex or min_sdk >= 21):
        d = unpacked / "smali"
        d.mkdir(exist_ok=True)
        log.debug("Injecting into classes.dex (single-dex, minSdk=%d)", min_sdk)
        return d

    indices = [1]  # `smali` == dex index 1
    for name in dex_dirs:
        m = re.fullmatch(r"smali_classes(\d+)", name)
        if m:
            indices.append(int(m.group(1)))
    nxt = max(indices) + 1
    d = unpacked / f"smali_classes{nxt}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def inject_application_wrapper(unpacked: Path, orig_app_class: Optional[str]) -> None:
    """Create a subclass Application that loads the gadget in <clinit> and
    rewrite android:name to point at it. Used when there's no existing
    Application class to patch, or when its clinit couldn't be touched.
    """
    super_class = orig_app_class.replace(".", "/") if orig_app_class else "android/app/Application"
    rel = _WRAPPER_CLASS + ".smali"

    smali = (
        f".class public L{_WRAPPER_CLASS};\n"
        f".super L{super_class};\n"
        ".source \"DeclawApp.java\"\n\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        f"    invoke-direct {{p0}}, L{super_class};-><init>()V\n"
        "    return-void\n"
        ".end method\n\n"
        ".method static constructor <clinit>()V\n"
        "    .locals 1\n"
        f"{_load_library_smali()}"
        "    return-void\n"
        ".end method\n"
    )

    # Place into a fresh dex so a near-full classes.dex is never tipped over
    # the 64K reference ceiling by our injected class.
    smali_root = _injection_smali_dir(unpacked)
    out = smali_root / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(smali, encoding="utf-8")

    manifest_path = unpacked / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    application = root.find(".//application")
    if application is not None:
        application.set(QN_NAME, _WRAPPER_CLASS.replace("/", "."))
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        log.info("Injected Application wrapper %s (super=%s)",
                 _WRAPPER_CLASS.replace("/", "."), super_class.replace("/", "."))


def inject_content_provider(unpacked: Path) -> None:
    """Register a stub ContentProvider that loads the gadget in <clinit>.

    ContentProviders are constructed before Application.onCreate(), so this
    pulls the gadget load earlier than Application-only injection and gives
    us a second shot if something bypasses the Application path.
    """
    manifest_path = unpacked / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    application = root.find(".//application")
    if application is None:
        return

    # Authority must be unique across all installed apps, and must not start
    # with a dot (Android rejects that). apktool sometimes drops manifest@package
    # on modern builds, hence the empty-string fallback.
    pkg = (root.get("package") or "").strip()
    salt = uuid.uuid4().hex[:8]
    if pkg:
        authority = f"{pkg}.declaw.preload.{salt}"
    else:
        log.warning("Manifest@package is empty; using a self-contained "
                    "authority for the ContentProvider.")
        authority = f"declaw.preload.{salt}"

    # Don't inject twice.
    for prov in application.findall("provider"):
        if prov.get(QN_NAME) == _PROVIDER_CLASS.replace("/", "."):
            return

    # SubElement lives in stdlib ET (defusedxml only wraps parsing).
    provider = _stdlib_ET.SubElement(application, "provider")
    provider.set(QN_NAME, _PROVIDER_CLASS.replace("/", "."))
    provider.set(f"{{{ANDROID_NS}}}authorities", authority)
    provider.set(f"{{{ANDROID_NS}}}exported", "false")
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

    smali = (
        f".class public L{_PROVIDER_CLASS};\n"
        ".super Landroid/content/ContentProvider;\n"
        ".source \"DeclawPreload.java\"\n\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        "    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V\n"
        "    return-void\n"
        ".end method\n\n"
        ".method static constructor <clinit>()V\n"
        "    .locals 1\n"
        f"{_load_library_smali()}"
        "    return-void\n"
        ".end method\n\n"
        ".method public onCreate()Z\n"
        "    .registers 2\n"
        "    const/4 v0, 0x1\n"
        "    return v0\n"
        ".end method\n\n"
        ".method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;\n"
        "    .registers 6\n"
        "    const/4 v0, 0x0\n"
        "    return-object v0\n"
        ".end method\n\n"
        ".method public getType(Landroid/net/Uri;)Ljava/lang/String;\n"
        "    .registers 2\n"
        "    const/4 v0, 0x0\n"
        "    return-object v0\n"
        ".end method\n\n"
        ".method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;\n"
        "    .registers 3\n"
        "    const/4 v0, 0x0\n"
        "    return-object v0\n"
        ".end method\n\n"
        ".method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I\n"
        "    .registers 4\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method\n\n"
        ".method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I\n"
        "    .registers 5\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method\n"
    )

    # Fresh dex when safe (see _injection_smali_dir): the provider is a whole
    # class with a dozen method/type refs; appending it to a near-full
    # classes.dex is what overflowed the rebuild on large apps like Signal.
    smali_root = _injection_smali_dir(unpacked)
    out = smali_root / (_PROVIDER_CLASS + ".smali")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(smali, encoding="utf-8")
    log.info("Injected ContentProvider %s for early gadget load (%s)",
             _PROVIDER_CLASS.replace("/", "."), smali_root.name)
