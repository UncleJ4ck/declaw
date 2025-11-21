#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess as sp
from datetime import datetime
from pathlib import Path
from sys import exit
from typing import Optional

import requests
from defusedxml import ElementTree as ET
from adbutils import AdbClient, AdbDevice

ADB_HOST = "127.0.0.1"
ADB_PORT = 5037

APKTOOL_URL = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
UBER_APK_SIGNER_URL = (
    "https://api.github.com/repos/patrickfav/uber-apk-signer/releases/latest"
)

ROOT_DIR = Path(__file__).resolve().parent
UTILS_DIR = ROOT_DIR / "utils"
UTILS_DIR.mkdir(exist_ok=True)

PACKAGES_DIR = ROOT_DIR / "packages"
PACKAGES_DIR.mkdir(exist_ok=True)

PATCHED_DIR = ROOT_DIR / "patched"
PATCHED_DIR.mkdir(exist_ok=True)

DEFAULT_SAVE_DIR = ROOT_DIR / "saved_apks"
DEFAULT_SAVE_DIR.mkdir(exist_ok=True)


def debug_log(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")


def download_latest_jar(download_url: str) -> Path:
    debug_log(f"Requesting latest release metadata from {download_url}")
    response = requests.get(download_url, timeout=30)
    response.raise_for_status()

    release_info = response.json()
    jar_asset = next(
        (asset for asset in release_info.get("assets", []) if asset["name"].endswith(".jar")),
        None,
    )
    if jar_asset is None:
        raise RuntimeError("No JAR file found in the release assets.")

    jar_file_path = UTILS_DIR / jar_asset["name"]
    if jar_file_path.exists():
        debug_log(f"Deleting existing {jar_file_path}")
        jar_file_path.unlink()

    debug_log(f"Downloading {jar_asset['name']} …")
    jar_response = requests.get(jar_asset["browser_download_url"], timeout=120)
    jar_response.raise_for_status()
    with open(jar_file_path, "wb") as fp:
        fp.write(jar_response.content)

    return jar_file_path


def pull_package(device: AdbDevice, package_name: str, output_path: Path) -> None:
    """Pull *all* split APK files for *package_name* from *device* to *output_path*."""
    debug_log(f"Pulling APK(s) for package: {package_name}")
    apks = device.shell(f"pm path {package_name}").splitlines()
    if not apks:
        print("Package not found on device")
        exit(1)

    output_path.mkdir(parents=True, exist_ok=True)
    for apk in apks:
        apk_path = apk.split(":", 1)[1]
        debug_log(f"Pulling {apk_path} …")
        device.sync.pull(apk_path, output_path / Path(apk_path).name)


def patch_manifest(unpacked_apk_path: Path) -> None:
    """Insert a <networkSecurityConfig> attribute into the base manifest."""
    manifest_path = unpacked_apk_path / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    application = root.find(".//application")
    if application is None:
        debug_log("No <application> tag found in manifest – nothing patched")
        return

    ns = {"android": "http://schemas.android.com/apk/res/android"}
    attr = f"{{{ns['android']}}}networkSecurityConfig"
    if application.get(attr) is None:
        application.set(attr, "@xml/network_security_config")
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        debug_log("Manifest patched with networkSecurityConfig attribute")
    else:
        debug_log("Manifest already contained networkSecurityConfig – skipped")


def add_network_security_config(unpacked_apk_path: Path) -> None:
    """Create *res/xml/network_security_config.xml* that trusts user certificates."""
    config_path = unpacked_apk_path / "res" / "xml"
    config_path.mkdir(parents=True, exist_ok=True)
    (config_path / "network_security_config.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
""",
        encoding="utf-8",
    )
    debug_log("Added network_security_config.xml")


def save_patched_apks(src_dir: Path, dest_root: Path) -> None:
    """Copy *src_dir* (containing *.apk files) into *dest_root/timestamped* directory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = dest_root / f"{src_dir.name}_{timestamp}"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src_dir, dest)
    debug_log(f"Patched APK(s) copied to {dest}")


def run_signer(apk_path: Path, signer_jar: Path) -> None:
    """Run uber-apk-signer with --allowResign on a single APK."""
    cmd = [
        "java",
        "-jar",
        str(signer_jar),
        "-a",
        str(apk_path),
        "--allowResign",
    ]
    debug_log(f"Signing with: {' '.join(cmd)}")
    sp.run(cmd, check=True)


def patch_package(
    device: AdbDevice,
    package_name: str,
    apktool_jar: Path,
    signer_jar: Path,
    save_dir: Optional[Path] = None,
) -> None:

    debug_log(f"Starting patch process for {package_name}")

    original_output = PACKAGES_DIR / package_name
    pull_package(device, package_name, original_output)

    patched_output = PATCHED_DIR / f"{package_name}_patched"
    shutil.rmtree(patched_output, ignore_errors=True)
    patched_output.mkdir()

    for apk in original_output.iterdir():
        file_name = apk.stem

        if file_name == "base":
            unpacked_apk_path = patched_output / file_name
            packed_apk_path = patched_output / f"{file_name}.repack.apk"
            signed_apk_path = (
                patched_output / f"{file_name}.repack-aligned-debugSigned.apk"
            )

            debug_log(f"Unpacking {file_name} …")
            sp.run(
                [
                    "java",
                    "-jar",
                    str(apktool_jar),
                    "d",
                    str(apk),
                    "-o",
                    str(unpacked_apk_path),
                    "-s",
                ],
                check=True,
            )

            patch_manifest(unpacked_apk_path)
            add_network_security_config(unpacked_apk_path)

            debug_log(f"Repacking {file_name} …")
            sp.run(
                [
                    "java",
                    "-jar",
                    str(apktool_jar),
                    "b",
                    str(unpacked_apk_path),
                    "-o",
                    str(packed_apk_path),
                ],
                check=True,
            )

            debug_log(f"Signing {file_name} …")
            run_signer(packed_apk_path, signer_jar)

            os.remove(packed_apk_path)
            shutil.rmtree(unpacked_apk_path)
            signed_apk_path.rename(patched_output / f"{file_name}_patched.apk")

        else:
            debug_log(f"Copying and signing split {file_name} …")

            tmp_apk = patched_output / f"{file_name}.orig.apk"
            shutil.copy2(apk, tmp_apk)

            run_signer(tmp_apk, signer_jar)

            signed_split = (
                patched_output / f"{file_name}.orig-aligned-debugSigned.apk"
            )
            signed_split.rename(patched_output / f"{file_name}_patched.apk")

            tmp_apk.unlink()

    if save_dir is not None:
        save_dir = save_dir.expanduser().resolve()
        save_dir.mkdir(parents=True, exist_ok=True)
        save_patched_apks(patched_output, save_dir)

    device.uninstall(package_name)
    debug_log("Uninstalled original APK(s)")

    apk_files = [str(apk) for apk in patched_output.glob("*.apk")]
    debug_log(f"Installing patched APK(s): {apk_files}")
    sp.run(["adb", "install-multiple", *apk_files], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Patch an installed APK so it trusts user certificates, then reinstall it, "
            "optionally saving a copy of the patched artifact(s)."
        ),
    )
    parser.add_argument("serial", help="ADB device serial (from 'adb devices')")
    parser.add_argument("package_name", help="Package name to patch (e.g. com.example.app)")
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help=(
            "Destination directory to copy patched APK(s). If omitted, patched APKs "
            "are only kept in the 'patched' folder."
        ),
        default=None,
    )

    args = parser.parse_args()

    client = AdbClient(host=ADB_HOST, port=ADB_PORT)
    device = client.device(args.serial)

    apktool_jar = download_latest_jar(APKTOOL_URL)
    signer_jar = download_latest_jar(UBER_APK_SIGNER_URL)

    package_name = args.package_name.removeprefix("package:")

    patch_package(
        device,
        package_name,
        apktool_jar,
        signer_jar,
        Path(args.output) if args.output else None,
    )


if __name__ == "__main__":
    main()

