"""declaw.pipeline — Base-APK patch orchestration and the run pipeline."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
import shutil
import sys


try:
    from adbutils import AdbClient
except ImportError as exc:  # pragma: no cover
    print(
        f"[fatal] adbutils import failed ({exc}). "
        "Run with `uv run declaw.py ...` or install deps from requirements.txt.",
        file=sys.stderr,
    )
    sys.exit(1)

from declaw.config import AAB_EXTENSION, ADB_HOST, ADB_PORT, BUNDLE_EXTENSIONS, DEFAULT_FRIDA_VERSION, FALLBACK_FRIDA_VERSION, PACKAGES_DIR, PATCHED_DIR, ROOT_DIR, _frida_major, log, safe_pkg
from declaw.analyze import analyze_apks, log_profile
from declaw.shell import convert_aab
from declaw.flutter import _static_patch_flutter_so
from declaw.bypass import fetch_bypass_script, frida_compile_bundle
from declaw.device import identify_base_apk, pull_package, resolve_device
from declaw.manifest import add_network_security_config, inspect_unpacked, patch_manifest
from declaw.inject import apply_smali_pin_patches, extract_bundle, inject_frida_gadget
from declaw.reflutter import try_patch_flutter_static
from declaw.build import apktool_build, apktool_decode, install_apks, sign_apk
from declaw.tools import Tools, abis_from_apks, frameworks_from_apks, prepare_tools


def _prune_lib_abis(unpacked: Path, keep: str) -> None:
    """Delete every lib/<abi> dir except `keep` from the unpacked tree, so the
    rebuilt fat APK carries only the target device's arch. Big single-arch-target
    win: a 3-arch bank app drops from ~360 MB to ~170 MB and installs in seconds.
    No-op for split bundles (their base has no lib/)."""
    lib_dir = unpacked / "lib"
    if not lib_dir.is_dir():
        return
    present = {d.name for d in lib_dir.iterdir() if d.is_dir()}
    if keep not in present:
        # Never strip everything. 'auto' left unresolved in local mode (no device
        # to query), a typo, or an ABI the APK does not ship would otherwise delete
        # ALL native libs and yield an APK that crashes at System.loadLibrary.
        log.warning("keep-abi %r is not among the APK's ABIs %s; skipping prune.",
                    keep, sorted(present))
        return
    removed = []
    for arch_dir in lib_dir.iterdir():
        if arch_dir.is_dir() and arch_dir.name != keep:
            shutil.rmtree(arch_dir, ignore_errors=True)
            removed.append(arch_dir.name)
    if removed:
        log.info("Pruned lib ABIs (keeping %s): dropped %s", keep, ", ".join(sorted(removed)))


def _pick_abi(abilist: list[str], app_abis: set[str]) -> Optional[str]:
    """The first device-preferred ABI (abilist is the device's priority order) that
    the app actually ships, or None when nothing matches. Pure, so it is unit-tested.

    This is why keep-abi=auto is safe to default: on a phone it keeps the primary
    arch, on an x86_64 emulator running an arm64-only app it keeps arm64-v8a (the
    translated lib) instead of the emulator's absent x86_64, and for a 32-bit-only
    app it keeps armeabi-v7a rather than the device's 64-bit primary. No match ->
    None -> _prune_lib_abis keeps every ABI, so a mismatch never strips to empty."""
    return next((a for a in abilist if a in app_abis), None)


def _resolve_auto_abi(device, app_abis: set[str]) -> Optional[str]:
    """Resolve keep-abi=auto to a single concrete ABI using the device's full abilist
    (priority order) against the ABIs the app ships. Returns None to keep everything."""
    abilist = [a.strip() for a in device.shell("getprop ro.product.cpu.abilist").split(",") if a.strip()]
    if not abilist:
        one = device.shell("getprop ro.product.cpu.abi").strip()
        abilist = [one] if one else []
    chosen = _pick_abi(abilist, app_abis)
    if chosen:
        log.info("keep-abi auto: device prefers [%s], app ships [%s] -> keeping %s",
                 ",".join(abilist), ",".join(sorted(app_abis)) or "none", chosen)
    else:
        log.info("keep-abi auto: no device ABI [%s] matches the app's [%s]; keeping all",
                 ",".join(abilist) or "none", ",".join(sorted(app_abis)) or "none")
    return chosen


def _patch_base_boringssl(unpacked: Path, spec: str) -> None:
    """Apply the ssl_verify_ok stub to a bundled BoringSSL that rides in the BASE apk
    (monolithic / base-resident libs), which the split-only raw-zip path never sees.
    Patches the unpacked lib in place, before apktool rebuilds+signs it. No-op for
    split bundles (their base has no lib/arm64-v8a)."""
    from declaw.boringssl_patch import parse_spec, patch_ssl_verify_peer_cert, resolve_offset
    lib_substr, off = parse_spec(spec)
    lib_dir = unpacked / "lib" / "arm64-v8a"
    if not lib_dir.is_dir():
        return
    for so in sorted(lib_dir.glob("*.so")):
        if lib_substr in so.name:
            try:
                real = off if off is not None else resolve_offset(so.read_bytes(), so.name)
                patch_ssl_verify_peer_cert(so, real)
                log.info("patch-boringssl: baked ssl_verify_ok stub into base %s", so.name)
            except ValueError as e:
                # explicit offset is user ground truth: fail loud; skip only an @auto miss.
                if off is not None:
                    raise
                log.warning("patch-boringssl: base %s not patched (%s)", so.name, e)


def patch_base_apk(
    base_apk: Path,
    out_dir: Path,
    tools: Tools,
    *,
    minimal: bool,
    refresh: bool,
    bundle_abis: Optional[set[str]] = None,
    bundle_frameworks: Optional[set[str]] = None,
    keep_abi: Optional[str] = None,
    patch_boringssl: Optional[str] = None,
) -> Path:
    unpacked = out_dir / "base.unpacked"

    apktool_decode(base_apk, unpacked, tools.apktool, with_sources=not minimal)
    if keep_abi:
        _prune_lib_abis(unpacked, keep_abi)
    if patch_boringssl:
        _patch_base_boringssl(unpacked, patch_boringssl)
    inspection = inspect_unpacked(unpacked)
    # Frameworks from the base plus those found in the arch splits (libflutter
    # lives in split_config.<abi>.apk, not the base, so base-only detection
    # misses Flutter on split bundles).
    frameworks = set(inspection.frameworks) | set(bundle_frameworks or set())
    if frameworks:
        log.info("Frameworks detected: %s", ", ".join(sorted(frameworks)))
    if inspection.abis:
        log.info("ABIs detected: %s", ", ".join(sorted(inspection.abis)))

    # ABIs the gadget must cover: those in the base plus those carried by the
    # sibling arch splits, plus any caller-requested extras. Whatever split
    # the user ends up installing, the base will carry the matching gadget.
    extra_abis = set(tools.extra_abis)
    if bundle_abis:
        split_only = bundle_abis - set(inspection.abis)
        if split_only:
            log.info("ABIs from arch splits: %s", ", ".join(sorted(split_only)))
        extra_abis |= bundle_abis
    # Narrow the gadget to keep_abi ONLY when it is a real ABI the bundle ships (same
    # guard the prune uses). Otherwise ('auto' left unresolved in local mode, a typo,
    # or an ABI the app does not carry) this would intersect to the empty set and the
    # gadget would land in NO ABI, silently shipping an APK with no bypass.
    if keep_abi and keep_abi in (set(inspection.abis) | (bundle_abis or set())):
        extra_abis &= {keep_abi}

    manifest_info = patch_manifest(unpacked)
    add_network_security_config(unpacked)

    if not minimal:
        apply_smali_pin_patches(unpacked)
        # Static libflutter swap first; if it lands, the Frida hooks below
        # become a backstop instead of the only line of defence.
        try_patch_flutter_static(unpacked, inspection, refresh=refresh)
        # Assemble the bypass bundle for the frameworks this app actually uses.
        # On Frida 17.x (the default, works on every Android) the bundle is
        # native-only and run through frida-compile; if compile is unavailable we
        # downgrade the gadget to 16.x + the raw bundle (Android <= 15 only).
        eff_frida = tools.frida_version
        want_v17 = _frida_major(eff_frida) >= 17
        bypass_script = None
        if tools.build_bypass:
            bypass_script = fetch_bypass_script(
                tools.cert_pem,
                refresh=tools.refresh,
                proxy_host=tools.proxy_host,
                proxy_port=tools.proxy_port,
                debug_bundle=tools.debug_bundle,
                frameworks=frameworks,
                dest=out_dir / "declaw-bypass.js",
                native_only=want_v17,
            )
            if want_v17:
                compiled = frida_compile_bundle(bypass_script)
                if compiled is not None:
                    bypass_script = compiled
                else:
                    # No frida-compile: drop to the 16.x gadget, which runs raw
                    # scripts AND tolerates the Java fragments (GC-safe on the
                    # Android <= 15 devices this fallback targets). Re-assemble the
                    # full bundle so we do not ship a needlessly degraded one.
                    eff_frida = FALLBACK_FRIDA_VERSION
                    bypass_script = fetch_bypass_script(
                        tools.cert_pem,
                        refresh=tools.refresh,
                        proxy_host=tools.proxy_host,
                        proxy_port=tools.proxy_port,
                        debug_bundle=tools.debug_bundle,
                        frameworks=frameworks,
                        dest=out_dir / "declaw-bypass.js",
                        native_only=False,
                    )
        inject_frida_gadget(
            unpacked,
            inspection,
            manifest_info,
            bypass_script=bypass_script,
            refresh=refresh,
            extra_abis=extra_abis,
            frida_version=eff_frida,
        )

    repacked = out_dir / "base.repack.apk"
    apktool_build(unpacked, repacked, tools.apktool)
    # Static Flutter TLS defeat for any libflutter.so carried in the base. Runs
    # in addition to the runtime NVISO hook so the bypass survives even where the
    # Frida gadget can't (e.g. 16 KB-page / new-SoC devices). No-op if not Flutter.
    _static_patch_flutter_so(repacked)
    sign_apk(repacked, tools.signer)

    final_base = out_dir / f"{base_apk.stem}_patched.apk"
    repacked.rename(final_base)
    shutil.rmtree(unpacked, ignore_errors=True)
    return final_base


def sign_splits(splits: list[Path], out_dir: Path, signer_jar: Path) -> list[Path]:
    if not splits:
        return []
    log.info("Re-signing %d split APK(s) in parallel", len(splits))
    tmps = []
    for s in splits:
        tmp = out_dir / f"{s.stem}.split.apk"
        shutil.copy2(s, tmp)
        # Flutter's libflutter.so usually rides in the arch split, not the base.
        _static_patch_flutter_so(tmp)
        tmps.append(tmp)

    errors: list[BaseException] = []
    with ThreadPoolExecutor(max_workers=min(4, len(tmps))) as pool:
        futures = {pool.submit(sign_apk, t, signer_jar): t for t in tmps}
        for fut in as_completed(futures):
            try:
                fut.result()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise errors[0]

    finals = []
    for t in tmps:
        target = out_dir / f"{t.name.removesuffix('.split.apk')}_patched.apk"
        t.rename(target)
        finals.append(target)
    return finals


def save_copy(patched_dir: Path, dest_root: Path, label: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = dest_root.expanduser().resolve() / f"{label}_{ts}"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(patched_dir, dest)
    log.info("Saved patched APK(s) to %s", dest)
    return dest


def run_pipeline(
    *,
    target: str,
    serial: Optional[str],
    output: Optional[Path],
    minimal: bool,
    refresh: bool,
    cert_pem: str,
    extra_abis: set[str],
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
    frida_version: str = DEFAULT_FRIDA_VERSION,
    auto: bool = False,
    capture_seconds: int = 90,
    keep_abi: Optional[str] = None,
    patch_boringssl: Optional[str] = None,
) -> int:
    target_path = Path(target)
    local_mode = target_path.exists()

    tools = prepare_tools(
        refresh=refresh,
        minimal=minimal,
        cert_pem=cert_pem,
        extra_abis=extra_abis,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        debug_bundle=debug_bundle,
        frida_version=frida_version,
    )

    if local_mode:
        return _run_local_mode(target_path, tools, output=output,
                               minimal=minimal, refresh=refresh,
                               auto=auto, capture_seconds=capture_seconds,
                               keep_abi=keep_abi, patch_boringssl=patch_boringssl)
    return _run_adb_mode(target, serial, tools, output=output,
                         minimal=minimal, refresh=refresh,
                         auto=auto, capture_seconds=capture_seconds,
                         keep_abi=keep_abi, patch_boringssl=patch_boringssl)


def _maybe_patch_boringssl(splits: list[Path], spec: Optional[str], work_root: Path) -> list[Path]:
    """Apply the static ssl_verify_ok stub to the split carrying the target lib,
    before it is re-signed. No-op when spec is None. EXPERIMENTAL: patches the
    given offset; does NOT verify it is really ssl_verify_peer_cert, and the
    end-to-end pinning bypass is unvalidated. NOT a PairIP bypass."""
    if not spec:
        return splits
    from declaw.boringssl_patch import patch_boringssl_in_apks
    log.warning("patch-boringssl is EXPERIMENTAL: the offset is trusted as-is and "
                "the pinning bypass is unvalidated. Confirm the offset (frida/RE) "
                "and MITM-test the result yourself.")
    out, n = patch_boringssl_in_apks(splits, spec, work_root / "_bssl")
    if n == 0:
        log.warning("patch-boringssl: no split carries an arm64 lib matching %r "
                    "(is it in the base apk, a different name, or not arm64?)",
                    spec.split("@")[0])
    else:
        log.info("patch-boringssl: baked ssl_verify_ok stub into %d arm64 lib(s) [%s]", n, spec)
    return out


def _collect_apks(path: Path, *, refresh: bool = False) -> list[Path]:
    if path.is_file():
        suffix = path.suffix.lower()
        if suffix == AAB_EXTENSION:
            # .aab: convert to universal .apks with bundletool, then extract.
            apks = convert_aab(path, refresh=refresh)
            bundle_dir = extract_bundle(apks)
            return sorted(bundle_dir.glob("*.apk"))
        if suffix in BUNDLE_EXTENSIONS:
            bundle_dir = extract_bundle(path)
            return sorted(bundle_dir.glob("*.apk"))
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.apk"))
    raise FileNotFoundError(path)


def _run_local_mode(
    target_path: Path,
    tools: Tools,
    *,
    output: Optional[Path],
    minimal: bool,
    refresh: bool,
    auto: bool = False,
    capture_seconds: int = 90,
    keep_abi: Optional[str] = None,
    patch_boringssl: Optional[str] = None,
) -> int:
    apks = _collect_apks(target_path, refresh=refresh)
    if not apks:
        log.error("No .apk files in %s", target_path)
        return 3

    mode, _reason = log_profile(analyze_apks(apks))
    if auto and mode == "capture":
        log.warning("--auto: this app needs friTap capture, which runs against an "
                    "INSTALLED app on a device. Install it, then run "
                    "`declaw <package> --capture`. Patching anyway so you still get "
                    "an APK for the non-pinned traffic.")

    label = target_path.stem if target_path.is_file() else target_path.name
    patched_out = PATCHED_DIR / f"{label}_patched"
    shutil.rmtree(patched_out, ignore_errors=True)
    patched_out.mkdir(parents=True)

    base_apk = identify_base_apk(apks)
    log.info("Local mode | base=%s, splits=%d", base_apk.name, len(apks) - 1)

    bundle_abis = abis_from_apks(apks)
    bundle_frameworks = frameworks_from_apks(apks)
    patch_base_apk(base_apk, patched_out, tools,
                   minimal=minimal, refresh=refresh,
                   bundle_abis=bundle_abis, bundle_frameworks=bundle_frameworks,
                   keep_abi=keep_abi, patch_boringssl=patch_boringssl)
    splits = _maybe_patch_boringssl([a for a in apks if a != base_apk],
                                    patch_boringssl, patched_out)
    sign_splits(splits, patched_out, tools.signer)

    target_root = (output or PATCHED_DIR).expanduser().resolve()
    if output is not None:
        save_copy(patched_out, target_root, label)
    log.info("Done. Patched APK(s) in %s", patched_out)
    return 0


def _run_adb_mode(
    package: str,
    serial: Optional[str],
    tools: Tools,
    *,
    output: Optional[Path],
    minimal: bool,
    refresh: bool,
    auto: bool = False,
    capture_seconds: int = 90,
    keep_abi: Optional[str] = None,
    patch_boringssl: Optional[str] = None,
) -> int:
    client = AdbClient(host=ADB_HOST, port=ADB_PORT)
    device = resolve_device(client, serial)

    pkg = safe_pkg(package.removeprefix("package:").strip())

    original_out = PACKAGES_DIR / pkg
    patched_out = PATCHED_DIR / f"{pkg}_patched"
    shutil.rmtree(patched_out, ignore_errors=True)
    patched_out.mkdir(parents=True)

    apks = pull_package(device, pkg, original_out)
    base_apk = identify_base_apk(apks)
    log.info("ADB mode | device=%s, base=%s, splits=%d",
             device.serial, base_apk.name, len(apks) - 1)

    profile = analyze_apks(apks)
    if keep_abi == "auto":
        keep_abi = _resolve_auto_abi(device, set(profile.abis))
    mode, _reason = log_profile(profile)
    if auto and mode == "capture":
        # A mixed app (cronet + a patchable stack) on a non-rooted device would otherwise
        # get nothing: capture needs root, and the hard capture return dropped the patch.
        # For that case, mirror local mode: still build the patch for the non-cronet
        # traffic. Keep capture-only for anti-tamper (a re-signed patch gets detected) and
        # for pure cronet (no patchable stack, so a patch would be an empty win).
        patchable = (profile.okhttp or profile.java_pinning or profile.conscrypt
                     or "flutter" in profile.frameworks or bool(profile.bundled_boringssl))
        if profile.cronet and not profile.anti_tamper and patchable:
            log.warning("--auto: %s bundles cronet (which needs friTap capture) but also "
                        "has a patchable stack; building the patched APK too so the "
                        "non-cronet traffic is covered. Run `declaw %s --capture` for the "
                        "cronet flows.", pkg, pkg)
            # fall through to the patch pipeline below
        else:
            # The app is already installed on the device; friTap spawns it directly.
            from declaw.capture import run_capture
            out_dir = (output.expanduser().resolve() if output else (ROOT_DIR / "captures"))
            log.info("--auto: routing to friTap capture for %s", pkg)
            return run_capture(pkg, device.serial, out_dir,
                               seconds=capture_seconds, refresh=refresh,
                               anti_pairip=bool(profile.anti_tamper))

    bundle_abis = abis_from_apks(apks)
    bundle_frameworks = frameworks_from_apks(apks)
    final_base = patch_base_apk(base_apk, patched_out, tools,
                                minimal=minimal, refresh=refresh,
                                bundle_abis=bundle_abis,
                                bundle_frameworks=bundle_frameworks,
                                keep_abi=keep_abi, patch_boringssl=patch_boringssl)
    final_splits = sign_splits(
        _maybe_patch_boringssl([a for a in apks if a != base_apk], patch_boringssl, patched_out),
        patched_out, tools.signer
    )

    if output is not None:
        save_copy(patched_out, output.expanduser().resolve(), pkg)

    try:
        device.uninstall(pkg)
        log.info("Uninstalled original %s", pkg)
    except Exception as e:
        log.warning("Uninstall failed (%s). Letting install-multiple -r handle it.", e)

    install_apks(device.serial, [final_base, *final_splits])
    log.info("Done. %s is patched and installed.", pkg)
    return 0
