"""declaw.manifest — APK inspection, manifest patching and load-library smali."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import re

from defusedxml import ElementTree as ET

from declaw.config import ANDROID_NS, GADGET_LIBNAME, NETWORK_SECURITY_CONFIG_XML, QN_APP_COMPONENT_FACTORY, QN_CLEAR, QN_DEBUG, QN_EXTRACT, QN_NAME, QN_NSC, log


# --------------------------------------------------------------------------- #
#  Inspection                                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class ApkInspection:
    frameworks: set[str] = field(default_factory=set)
    abis: set[str] = field(default_factory=set)


def inspect_unpacked(unpacked: Path) -> ApkInspection:
    info = ApkInspection()
    lib_dir = unpacked / "lib"
    if lib_dir.is_dir():
        for arch_dir in lib_dir.iterdir():
            if not arch_dir.is_dir():
                continue
            info.abis.add(arch_dir.name)
            for so in arch_dir.glob("*.so"):
                n = so.name.lower()
                if "libflutter" in n:
                    info.frameworks.add("flutter")
                elif "libreactnativejni" in n or "libhermes" in n or "libjsc" in n:
                    info.frameworks.add("react-native")
                elif "libmonodroid" in n or "libmono-" in n or "libxamarin" in n:
                    info.frameworks.add("xamarin")
                elif "libil2cpp" in n or "libunity" in n:
                    info.frameworks.add("unity")
    assets = unpacked / "assets"
    if assets.is_dir():
        if (assets / "flutter_assets").is_dir():
            info.frameworks.add("flutter")
        if any(assets.rglob("index.android.bundle")):
            info.frameworks.add("react-native")
        if (assets / "www").is_dir() or (assets / "cordova.js").exists():
            info.frameworks.add("cordova")
    return info


# --------------------------------------------------------------------------- #
#  Manifest / NSC                                                             #
# --------------------------------------------------------------------------- #

def _fq_class(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    if "." in name:
        return name
    return f"{package}.{name}"


@dataclass
class ManifestPatchResult:
    application_class: Optional[str]
    launcher_activity: Optional[str]


def patch_manifest(unpacked: Path) -> ManifestPatchResult:
    manifest_path = unpacked / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    package = root.get("package", "")

    application = root.find(".//application")
    if application is None:
        log.warning("Manifest has no <application>, skipping manifest patch.")
        return ManifestPatchResult(None, None)

    wanted = {
        QN_NSC: "@xml/network_security_config",
        QN_DEBUG: "true",
        QN_CLEAR: "true",
        QN_EXTRACT: "true",
    }
    changes: list[str] = []
    for attr, value in wanted.items():
        if application.get(attr) != value:
            application.set(attr, value)
            changes.append(attr.split("}")[1])

    # Apktool sometimes fails to resolve a resource-referenced
    # `android:appComponentFactory` and writes a bare integer instead of the
    # real class name. Reinstalling such an APK leaves Android trying to load
    # `<package>.<int>` and crashing on launch. Replacing the value with the
    # platform default keeps the app loadable; a pentested APK doesn't need a
    # custom component factory.
    acf = application.get(QN_APP_COMPONENT_FACTORY)
    if acf is not None and (acf.isdigit() or "." not in acf):
        application.set(QN_APP_COMPONENT_FACTORY, "androidx.core.app.CoreComponentFactory")
        changes.append("appComponentFactory(reset)")

    app_fq = None
    app_class = application.get(QN_NAME)
    if app_class:
        app_fq = _fq_class(app_class, package)

    launcher_fq = None
    for activity in application.findall(".//activity") + application.findall(".//activity-alias"):
        for ifilter in activity.findall("intent-filter"):
            actions = {a.get(QN_NAME) for a in ifilter.findall("action")}
            categories = {c.get(QN_NAME) for c in ifilter.findall("category")}
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                name = activity.get(QN_NAME) or activity.get(f"{{{ANDROID_NS}}}targetActivity")
                if name:
                    launcher_fq = _fq_class(name, package)
                    break
        if launcher_fq:
            break

    if changes:
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        log.info("Manifest patched: %s", ", ".join(changes))
    else:
        log.info("Manifest already correctly configured.")
    return ManifestPatchResult(app_fq, launcher_fq)


def add_network_security_config(unpacked: Path) -> None:
    out = unpacked / "res" / "xml"
    out.mkdir(parents=True, exist_ok=True)
    (out / "network_security_config.xml").write_text(
        NETWORK_SECURITY_CONFIG_XML, encoding="utf-8"
    )
    log.info("Wrote res/xml/network_security_config.xml")


# --------------------------------------------------------------------------- #
#  Gadget injection                                                           #
# --------------------------------------------------------------------------- #

def _find_smali_for_class(unpacked: Path, fq_class: str) -> Optional[Path]:
    rel = fq_class.replace(".", "/") + ".smali"
    for smali_root in sorted(unpacked.glob("smali*")):
        candidate = smali_root / rel
        if candidate.is_file():
            return candidate
    return None


_CLINIT_RE = re.compile(
    r"(\.method\s+static\s+constructor\s+<clinit>\(\)V\b.*?)(\.end method)",
    re.DOTALL,
)


def _load_library_smali() -> str:
    return (
        f"    const-string v0, \"{GADGET_LIBNAME}\"\n"
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
    )


def _new_clinit_smali() -> str:
    return (
        "\n.method static constructor <clinit>()V\n"
        "    .locals 1\n"
        f"{_load_library_smali()}"
        "    return-void\n"
        ".end method\n"
    )


def _inject_load_library(smali_path: Path) -> bool:
    text = smali_path.read_text(encoding="utf-8")
    if f'"{GADGET_LIBNAME}"' in text:
        return False
    load_snippet = _load_library_smali()
    m = _CLINIT_RE.search(text)
    if m:
        head, tail = m.group(1), m.group(2)
        head2 = re.sub(
            r"(\.(?:locals|registers)\s+)(\d+)",
            lambda mm: f"{mm.group(1)}{max(int(mm.group(2)), 1)}",
            head,
            count=1,
        )
        if head2 == head and ".locals" not in head and ".registers" not in head:
            head2 = head.replace(
                ".method static constructor <clinit>()V",
                ".method static constructor <clinit>()V\n    .locals 1",
                1,
            )
        # Inject *before* the final `return-void` so the new code actually runs.
        last_ret = head2.rfind("return-void")
        if last_ret == -1:
            new_head = head2 + load_snippet
        else:
            line_start = head2.rfind("\n", 0, last_ret) + 1
            new_head = head2[:line_start] + load_snippet + head2[line_start:]
        new_text = text.replace(m.group(0), new_head + tail, 1)
    else:
        new_clinit = _new_clinit_smali()
        anchor = text.find("\n.method")
        new_text = (text[:anchor] + new_clinit + text[anchor:]) if anchor >= 0 else text + new_clinit
    smali_path.write_text(new_text, encoding="utf-8")
    return True
