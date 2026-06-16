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
patcher, root-detection disable, the native TLS hook, and the native
`connect()` hook that redirects TCP to your proxy. The connect hook is
what makes Flutter (and any other app that ignores Android's system
proxy) reach Burp / mitmproxy in the first place. declaw prepends a
small config stub with a valid dummy `CERT_PEM` so the hooks that read
it don't throw; you can override the PEM with `-c` or `DECLAW_CERT_PEM`
to embed your Burp or mitmproxy CA directly, and you must pass
`--proxy HOST:PORT` (or `DECLAW_PROXY`) with the address of your
listener for the connect hook to send traffic to the right place.

On top of the httptoolkit fragments declaw prepends three small Java
hooks, each wrapped in a `safeHook(name, install)` so a missing class
cannot abort the rest of the bundle (logged as `[hook] X` or `[skip] X`
under `adb logcat -s declaw:V`):

- `NetworkCapabilities.hasCapability(int)`: returns true selectively
  for `NET_CAPABILITY_INTERNET` (12) and `NET_CAPABILITY_VALIDATED`
  (16) and falls through for every other capability. Android's
  validation probe can flip VALIDATED to false when an inspection
  proxy is in front, which makes apps gate their requests on a
  "no internet" state. Returning true only for those two preserves
  VPN, metered, transport and captive-portal accuracy. Without this,
  the connect hook has nothing to redirect because the app never
  attempts to connect.
- `WebViewClient.onReceivedSslError`: calls `handler.proceed()` for
  any embedded WebView that hits an SSL error against your proxy CA.
- `Debug.isDebuggerConnected` / `Debug.waitingForDebugger`: both
  return false so the `debuggable=true` flag declaw sets in the
  manifest does not trip apps that gate on either.

These three are useful for traffic interception and rarely cause side
effects. If you do need to disable them (debugging the bundle itself,
auditing one hook at a time), edit `_bypass_header` in `declaw.py`
between the `// ---- declaw hardening hooks` and `// ---- end declaw
hardening` markers.

All the downloaded tooling (apktool, uber-apk-signer, the gadget, the
script bundle) gets cached under `utils/`. First run is the slow one.

## Usage

```bash
declaw com.example.app                    # one device attached
declaw -s emulator-5554 com.example.app   # multiple devices
declaw ./app.apk                          # local APK, no install
declaw ./split_apks/ -o ~/pentest/out     # directory of splits, save a copy
declaw ./app.xapk                         # APKPure bundle, auto-extracted
declaw ./app.apks                         # SAI / bundletool split-APK set
declaw ./app.aab                          # Google App Bundle (uses bundletool)
declaw --minimal com.example.app          # NSC only, skip the gadget
declaw -c ~/.mitmproxy/ca.pem com.bank    # bake in your proxy's CA
declaw --proxy 192.168.1.10:8080 com.bank # redirect TCP to your laptop's proxy
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
| `--proxy` | `HOST:PORT` of your intercepting proxy. Baked into the bundled `connect()` hook so Flutter and other proxy-ignoring apps route to it. |
| `--frida-version` | Pin the Frida gadget version. Default `16.7.19` because Frida 17.x gadget script mode is broken on Android (silent no-op, upstream `frida/frida#3526`, `#3645`). Use `latest` only when upstream has shipped a fix. |
| `--debug-bundle` | Flip `DEBUG_MODE=true` in the bundled hooks and bridge `console.log` to `Log.d("declaw", ...)` so output is visible under `adb logcat -s declaw:V`. |
| `--minimal` | NSC only. Skip the gadget. Patched APK stays close to the original size. |
| `--refresh` | Re-download everything cached in `utils/`. |
| `-v`, `--verbose` | DEBUG logging. Shows every subprocess and cache hit. |

### Environment variables

| Variable | Purpose |
|---|---|
| `DECLAW_BYPASS_URLS` | `;` separated list of JS URLs to concatenate into the bundle. Overrides the default. |
| `DECLAW_CERT_PEM` | Path to a PEM, used when `-c` is not passed. |
| `DECLAW_PROXY` | `HOST:PORT` for the bundled `connect()` hook, used when `--proxy` is not passed. |
| `DECLAW_FRIDA_VERSION` | Override the pinned Frida gadget version, used when `--frida-version` is not passed. |
| `DECLAW_DEBUG_BUNDLE` | Truthy value (`1`, `true`) enables the debug bundle, used when `--debug-bundle` is not passed. |
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
2. Pass `--proxy HOST:PORT` to declaw with your laptop's IP and the
   Burp / mitmproxy listener port. The bundled `connect()` hook will
   redirect every outbound TCP connection from the app to that address,
   which is the only thing that gets Flutter and other proxy-ignoring
   apps through your interceptor.
3. (Optional) Also set Wi-Fi proxy on the device, so apps that *do*
   honour system proxy treat it normally.
4. Open the app. The gadget loads, the bundled script runs, pinning
   stops mattering, `connect()` lands on your proxy, you see cleartext.

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

## Credits

- [Apktool](https://ibotpeaches.github.io/Apktool/install)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
- [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning). The bundled hooks come straight from this repo.
- [Frida Gadget](https://frida.re/docs/gadget/)
