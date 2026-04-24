# declaw

A script that patches an installed Android APK so it stops caring about SSL
pinning, then reinstalls it. Useful when you want to MITM an app during a
pentest and don't feel like chasing every obfuscated pinning library by
hand. Works without root.

I mostly built this because the previous version of the tool kept failing at
the install step on multi-device setups, and didn't do anything useful for
apps that pin in native code (Flutter, React Native). Fixing those two
things is where most of the work went.

## What it actually does

Given a package name or a local APK, declaw:

1. Pulls the base APK and every split off the device.
2. Decodes the base with apktool.
3. Writes a `network_security_config.xml` that trusts user CAs (so your
   proxy's CA works as soon as you install it on the device).
4. Flips `debuggable`, `usesCleartextTraffic`, and `extractNativeLibs` on
   in the manifest.
5. Downloads the Frida gadget for every ABI the APK ships, drops each
   gadget into `lib/<abi>/`, and places a universal unpinning script
   next to it (as `libfrida-gadget.script.so`, so Android extracts it
   with the rest of the native libs at install time).
6. Configures the gadget to auto-load that script at process start, then
   patches the Application class's smali `<clinit>` to call
   `System.loadLibrary("frida-gadget")`. If the app has no Application
   class, the launcher Activity gets the injection instead.
7. Repacks, re-signs the base and every split in parallel with
   uber-apk-signer, and runs `adb -s <serial> install-multiple` with the
   right flags. If that refuses, it falls back to a streamed
   `pm install-create / install-write / install-commit` session.

The universal unpinning script is assembled from the public scripts in
[`httptoolkit/frida-interception-and-unpinning`](https://github.com/httptoolkit/frida-interception-and-unpinning):
certificate unpinning, the fallback hooks, the Flutter BoringSSL
patcher, root-detection disable, and the native TLS hook. declaw
prepends a small config stub with a valid dummy `CERT_PEM` so the hooks
that read it don't throw; you can override the PEM with `-c` or
`DECLAW_CERT_PEM` to embed your Burp or mitmproxy CA directly.

All the downloaded tooling (apktool, uber-apk-signer, the gadget, the
script bundle) gets cached under `utils/`. First run is the slow one.

## Usage

```bash
declaw com.example.app                    # one device attached
declaw -s emulator-5554 com.example.app   # multiple devices
declaw ./app.apk                          # local APK, no install
declaw ./split_apks/ -o ~/pentest/out     # directory of splits, save a copy
declaw --minimal com.example.app          # NSC only, skip the gadget
declaw -c ~/.mitmproxy/ca.pem com.bank    # bake in your proxy's CA
declaw --refresh com.example.app          # re-download every cached tool
```

If the positional argument is an existing file or directory, declaw
runs in local mode and skips the device entirely. Otherwise it's a
package name and declaw will pull it over ADB.

### Flags

| Flag | What it does |
|---|---|
| `-s`, `--serial` | ADB serial. Only required when more than one device is attached. |
| `-o`, `--output` | Copy the patched APKs into this directory (timestamped). |
| `-c`, `--cert` | Path to a PEM to bake into `CERT_PEM` for the bundled hooks. |
| `--minimal` | NSC only. Skip the gadget. Patched APK stays close to the original size. |
| `--refresh` | Re-download everything cached in `utils/`. |
| `-v`, `--verbose` | DEBUG logging. Shows every subprocess and cache hit. |

### Environment variables

| Variable | Purpose |
|---|---|
| `DECLAW_BYPASS_URLS` | `;` separated list of JS URLs to concatenate into the bundle. Overrides the default. |
| `DECLAW_CERT_PEM` | Path to a PEM, used when `-c` is not passed. |
| `GITHUB_TOKEN` | Passed to the GitHub release API so the latest-release calls don't hit anonymous rate limits. |
| `ADB_HOST`, `ADB_PORT` | Point at a non-default adb server. |

## Install

Needs Python 3.10+, Java (apktool and uber-apk-signer run on the JVM),
and `adb` on your PATH.

With uv (the script has a PEP-723 header, so `uv run` will set up the
deps on its own):

```bash
uv run declaw.py com.example.app
```

Or the venv route:

```bash
uv venv
uv pip install -r requirements.txt
.venv/bin/python declaw.py com.example.app
```

Docker:

```bash
docker build -t declaw .
adb kill-server
# Named volume keeps apktool / signer / gadget / bypass script around
# between runs so the first slow download only happens once.
docker volume create declaw-cache
docker run -it --rm --privileged \
    -v /dev/bus/usb:/dev/bus/usb \
    -v declaw-cache:/app/utils \
    --name declaw declaw com.example.app
```

## Finding the pieces you need

```bash
$ adb devices
List of devices attached
emulator-5554  device

$ adb shell pm list packages | grep bank
package:com.example.bank
```

## MITM workflow after patching

1. Install your proxy's CA as a **user** cert on the device (Settings,
   Security, Install certificate). Or pass `--cert ca.pem` to declaw
   and skip the install step entirely (the bundled hooks add it to the
   app's own trust store).
2. Point the device at your proxy.
3. Open the app. The gadget loads, the bundled script runs, pinning
   stops mattering, your proxy sees cleartext.

If an app still doesn't talk to you after that, it's usually one of:

- A Play Integrity / SafetyNet check rejecting the debuggable build.
  Nothing declaw does about this yet. You'll need to patch those calls
  yourself or run on a Magisk device.
- An anti-Frida check looking for `frida-gadget` in `/proc/self/maps`.
  Renaming the gadget library would handle most of these. Not done by
  default because it complicates caching; open an issue if you want it.
- Pinning in a library the httptoolkit bundle doesn't cover. Add a URL
  to `DECLAW_BYPASS_URLS` that points at your own script.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Unhandled exception. Re-run with `-v`. |
| 2 | Bad args, wrong device, bad cert path. |
| 3 | Package not installed or no APKs in the given path. |
| 4 | Network error fetching tooling. |
| 6 | apktool, signer, or adb failed. |
| 130 | Ctrl-C. |

## What I haven't tested

The install path obviously needs a device. The runtime bypass needs a
device and a target app to try against. The static side of the pipeline
(pull, decode, patch, rebuild, sign) I've run end to end against
F-Droid's own APK and inspected the output. Smali injection, gadget
placement, and NSC all land correctly.

If you try it against a Flutter app and the BoringSSL patch doesn't
stick, grab `utils/universal-bypass.js` and check whether the Flutter
script actually matched your app's libflutter.so. The upstream pattern
matcher covers most versions but not every one.

## Credits

- [Apktool](https://ibotpeaches.github.io/Apktool/install)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
- [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning). The bundled hooks come straight from this repo.
- [Frida Gadget](https://frida.re/docs/gadget/)
