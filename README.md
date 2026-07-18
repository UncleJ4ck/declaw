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
auditing one hook at a time), edit `_bypass_header` in `declaw/bypass.py`
between the `// ---- declaw hardening hooks` and `// ---- end declaw
hardening` markers.

Where a gadget is the wrong tool, declaw patches the native libraries
directly at repack time, so the bypass survives when the gadget crashes or
the app ignores your proxy:

- Flutter carries its own BoringSSL inside `libflutter.so` and pins against a
  baked-in trust store, ignoring the system store and any user CA. declaw
  byte-patches `ssl_verify_peer_cert` in the bundled `libflutter.so` to return
  success (NVISO's `disable-flutter-tls` signatures), no Frida and no runtime.
- When the app's Flutter engine snapshot hash is one that reFlutter publishes
  a pre-patched engine for, declaw downloads that engine for the exact version
  and ABI and swaps the whole `.so` in, instead of byte-patching. It falls back
  to the byte-patch (or the Frida hooks) when the hash is unknown.
- For a non-Flutter app that bundles its own BoringSSL, the same eight-byte
  `ssl_verify_peer_cert` stub is written into the bundled `libssl.so` on disk,
  the static counterpart of `--mode mempatch` for a device with no root.

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
declaw --mode minimal com.example.app     # NSC only, skip the gadget
declaw -c ~/.mitmproxy/ca.pem com.bank    # bake in your proxy's CA
declaw --proxy 192.168.1.10:8080 com.bank # redirect TCP to your laptop's proxy
declaw --refresh com.example.app          # re-download every cached tool
declaw com.example.cronetapp              # default (auto): detect the stack, pick strategy
declaw --mode capture com.example.cronetapp        # force friTap key+pcap (pinned apps, root)
declaw --mode hwbp com.some.app                    # zero-injection HW-breakpoint keys (root+arm64)
declaw --mode mempatch --offset libssl.so@0x1f13c com.app  # zero-footprint in-memory bypass
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
| `--mode` | What declaw does (default `auto`). `auto`: analyze and pick. `patch`: repackage the APK with the bypass baked in. `minimal`: NSC only, skip the gadget, keep the APK small. `capture`: friTap key+pcap for pinned apps like cronet (root). `hwbp`: zero-injection hardware-breakpoint key capture (root+arm64). `mempatch`: zero-footprint in-memory cert-verify patch via `/proc/pid/mem`, no file change / no frida / no ptrace-attach (root+arm64, needs `--offset`). |
| `--keep-abi` | Which native ABI to keep in a fat multi-arch APK. Default `auto` strips to the connected device's arch (much smaller, installs in seconds); `all` keeps every ABI; or name one (`arm64-v8a`, `x86_64`). No-op on split bundles and in local-file mode. |
| `--offset` | `LIB@OFFSET` of `ssl_verify_peer_cert` in the app's BoringSSL, for `--mode patch` (baked into the `.so`) or `--mode mempatch` (written into the running process). e.g. `libssl.so@0x1f13c`. |
| `--verify` | After `--mode mempatch`, confirm the patched `ssl_verify_peer_cert` actually executes on a handshake (non-destructive HW breakpoint), and revert to the original bytes if it never fires. Drive the app during the watch so it makes an HTTPS request. |
| `--capture-seconds N` | Capture window for `--mode capture` (default 90). Drive the app during it. |
| `--refresh` | Re-download everything cached in `utils/`. |
| `-v`, `--verbose` | DEBUG logging. Shows every subprocess and cache hit. |

The old mode flags (`--auto`, `--capture`, `--hwbp-capture`, `--patch-boringssl`, `--mempatch`) still work as deprecated aliases, so existing commands keep running; new work should use `--mode` / `--offset`.

### Environment variables

| Variable | Purpose |
|---|---|
| `DECLAW_BYPASS_URLS` | `;` separated list of JS URLs to concatenate into the bundle. Overrides the default. |
| `DECLAW_CERT_PEM` | Path to a PEM, used when `-c` is not passed. |
| `DECLAW_PROXY` | `HOST:PORT` for the bundled `connect()` hook, used when `--proxy` is not passed. |
| `DECLAW_FRIDA_VERSION` | Override the pinned Frida gadget version (default `17.15.2`, falls back to `16.7.19` without node/frida-compile). |
| `DECLAW_GADGET_ABIS` | Comma-separated extra ABIs to inject the gadget into (e.g. `x86_64` when patching an arm64 APK for an x86_64 emulator), on top of what the APK ships. |
| `DECLAW_FRITAP_SPEC` | pip target for the bundled friTap (capture mode). Defaults to PyPI `friTap`. Set to a fork, e.g. `git+https://github.com/you/friTap`, to develop friTap yourself. `--refresh` reinstalls it. |
| `DECLAW_ANTI_PAIRIP` | Force-load the bundled anti-PairIP frida script in capture mode. Auto-enabled when the analyzer detects an anti-tamper packer (PairIP). Best-known generic native bypass; some hardened apps may still resist. |
| `DECLAW_STEALTH_FRIDA` | Harden the frida-server binary against anti-frida scans (rename frida symbols/strings/threads). Off by default: the patch can corrupt the frida-agent on some frida versions and crash the target. Use only when frida-server detection is the specific blocker. |
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

### Locked-down or rooted-emulator devices

On modern Android (14+) or a locked-down emulator the app's UID can be
firewalled off the LAN (no validated default network, per-UID eBPF egress
deny), so it never reaches a proxy on your laptop's IP. Loopback is exempt,
so route through it instead:

```
mitmdump --mode socks5 --listen-host 127.0.0.1 -p 8000 --ssl-insecure
adb reverse tcp:8000 tcp:8000
declaw --proxy 127.0.0.1:8000 --cert ~/.mitmproxy/mitmproxy-ca-cert.pem <app>
```

The connect hook sends every TCP to `127.0.0.1:8000`, `adb reverse` tunnels
it to mitmproxy on the host (which has real internet), and `--cert` makes
Conscrypt / OkHttp apps trust the proxy CA. The native bundle covers the rest.

If an app still doesn't talk to you after that, it's usually one of:

- A Play Integrity / SafetyNet check rejecting the debuggable build.
  Nothing declaw does about this yet. You'll need to patch those calls
  yourself or run on a Magisk device.
- An anti-Frida check looking for `frida-gadget` in `/proc/self/maps`.
  Renaming the gadget library would handle most of these. Not done by
  default because it complicates caching; open an issue if you want it.
- Pinning in a library the httptoolkit bundle doesn't cover. Add a URL
  to `DECLAW_BYPASS_URLS` that points at your own script.

## Decrypting cronet / hard-pinned apps (friTap)

Some apps cannot be beaten by patching. cronet (Chromium's network stack,
used by many Google-adjacent apps) statically links its own
BoringSSL and hard-pins its servers, so the CA + NSC patch is rejected and the
handshake aborts. Anti-tamper packers (PairIP, DexGuard, Jiagu) detect the
re-signed APK and refuse to run.

For these, declaw has a capture mode that never sits in the middle. It runs
[friTap](https://github.com/fkie-cad/friTap) against the **unmodified** app:
friTap hooks the app's own BoringSSL and logs the TLS session keys, so the real
pinned traffic decrypts afterward with no MITM, no cert, and nothing for the pin
or the tamper check to detect.

cronet and mempatch, precisely: cronet's cert check IS BoringSSL's
`ssl_verify_peer_cert` (Chromium registers its `net::CertVerifier` through
`SSL_set_custom_verify`, and `ssl_verify_peer_cert` calls that callback), so
`--mode mempatch` can bypass it for cronet-over-**TCP** (h2/h1). But a cronet
**HTTP/3** request rides QUIC over UDP 443, which a transparent TCP MITM cannot
see, so for HTTP/3 use the keylog path here regardless. `find_verify` picks the
live `ssl_verify_peer_cert` over the `ssl_reverify_peer_cert` decoy either way.

`--auto` detects which case you're in and routes for you:

```bash
declaw --auto com.example.cronetapp  # sees libcronet -> runs friTap capture
declaw --auto com.some.okhttp.app    # sees OkHttp    -> patches as usual
```

Or force it with `--capture`. friTap is provisioned automatically: on first use
declaw creates a managed venv at `utils/fritap-venv` (via `uv`, falling back to
`python -m venv`), installs friTap there, and downloads a `frida-server` matched
to that friTap's exact frida version. No manual install. It needs:

- **root** (an emulator, or a rooted device). friTap drives a `frida-server`
  that declaw pushes and starts; that needs root. On a non-rooted device use the
  patch mode instead.
- network on first run (to install friTap and fetch frida-server; both cached after).
- **tshark** (Wireshark CLI) to decode, optional.

```bash
declaw --capture --capture-seconds 90 com.example.cronetapp
# drive the app during the window so it makes the calls you want, then:
tshark -r captures/traffic.pcap -d tcp.port==443,http2 \
  -Y http2.headers.authority -T fields -e http2.headers.authority
```

Output lands in `captures/` (or `-o DIR`): `keys.log` (NSS key log) and
`traffic.pcap` (decrypted). Open the pcap in Wireshark or decode with tshark.

Worked example, a cronet app (pinned, gated behind login). The emulator's
Credential Manager blocks scripted login, so log in with the app's email magic
link fired straight into the app, then capture:

```bash
# 1. trigger "email me a login link" in the app, open the email, copy the link
adb shell am start -a android.intent.action.VIEW \
  -d '<magic_link_url>' com.example.cronetapp
# 2. once you're on the feed:
declaw --capture com.example.cronetapp
```

This decrypts the app's GraphQL and web hosts, all of which hard-pin and fail a
normal CA MITM.

### arm-only and anti-tamper apps

The x86_64 emulator cannot run arm-only builds, and its ARM translation layer
breaks Frida's native hooks (agent SIGSEGV). For arm apps, use a native arm64
Android: a physical arm64 device, or `redroid` (Android in Docker, no KVM) on an
arm64 host or an arm64 Linux VM. On an x86 host with no arm64 hardware,
[declaw-lab](https://github.com/UncleJ4ck/declaw-lab) boots a rooted arm64
Android 16 guest under QEMU TCG and drives a patched app's HTTPS into Burp. On
native arm64 `declaw --capture -s <serial>` captures cleanly (verified: 17
TLS secrets with decrypted SSL_read/write).

For anti-tamper packers, `--capture` auto-detects them and loads a bundled
anti-PairIP script (`fritap -c` + `--pairip-safe`): it hides Frida from PairIP's
strstr/maps scans, blocks its kill switch, and patches its `dl_iterate_phdr`
crash. This is the best-known generic native bypass. It keeps the app alive under
instrumentation, but PairIP's code-integrity check still crashes on the first
inline hook of the TLS libs, so the most hardened apps yield an encrypted capture
with no keys under friTap. For those, `--mode mempatch` wins: it flips the live
`ssl_verify_peer_cert` in memory via `/proc/pid/mem` with no file change, no code
hook, and no ptrace-attach, so PairIP's integrity check has nothing to detect and
the app keeps running while its TLS accepts your cert. `--mode hwbp` is the passive
alternative (TLS keys via a `perf_event_open` hardware breakpoint, also no inline
hook). Both auto-locate the BoringSSL offset (`LIB@auto`, or
`python -m declaw.find_verify <lib.so>`); a static PairIP strip is the other route.
Per-build, not one-click, but on-device and detection-resistant.

Note on env coverage. Verified end-to-end decryptions: a PairIP-hardened,
certificate-pinned app (driven to plaintext with `--mode mempatch` on conscrypt:
unpatched it dropped the MITM with `certificate_unknown`, patched it emitted
`POST https://<the app's API host>/graphql/...` in the clear), a cronet app (via
friTap), a Flutter banking app (static patch), and the conscrypt/OkHttp pinning
demo (mempatch).
A 32-bit `armeabi-v7a` app cannot run on the arm64-only test rig
([declaw-lab](https://github.com/UncleJ4ck/declaw-lab)); on an arm64 build it is
the same conscrypt mempatch path.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Unhandled exception. Re-run with `-v`. |
| 2 | Bad args, wrong device, bad cert path. |
| 3 | Package not installed or no APKs in the given path. |
| 4 | Network error fetching tooling. |
| 5 | Capture mode ran but extracted no TLS keys (app made no calls, or needs root). |
| 6 | apktool, signer, or adb failed. |
| 130 | Ctrl-C. |

## Credits

- [Apktool](https://ibotpeaches.github.io/Apktool/install)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
- [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning). The bundled hooks come straight from this repo.
- [Frida Gadget](https://frida.re/docs/gadget/)
