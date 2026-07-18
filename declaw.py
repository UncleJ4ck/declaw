#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "adbutils>=2.0",
#   "defusedxml>=0.7",
#   "requests>=2.30",
# ]
# ///
"""declaw: patch an Android APK so it stops caring about SSL pinning.

Pulls the app off the device (base + every split), decodes it, drops in
a network security config that trusts user CAs, patches the manifest,
optionally injects a Frida gadget wired up to run a universal unpinning
script at launch, repacks, resigns, and installs it back.

The gadget and the script live inside the APK. Nothing attaches at
runtime, no Frida client needed. If you only need NSC (system
TrustManager apps), pass --minimal and you skip the gadget entirely.

Quick usage:

    declaw com.example.app                  # one device attached
    declaw -s emulator-5554 com.example.app  # multiple devices
    declaw ./app.apk                         # patch a local APK, no install
    declaw --minimal com.example.app         # NSC only, no gadget
    declaw -c ~/.mitmproxy/ca.pem com.example.app

Env overrides (useful for air-gapped pentests):
    DECLAW_BYPASS_URLS   ; separated list of script URLs to fetch
    DECLAW_CERT_PEM      path to a PEM; baked into CERT_PEM in the bundle
"""

# Entry point only. The implementation lives in the declaw/ package; this file
# stays a thin shim so `uv run declaw.py` and the Docker ENTRYPOINT keep working.
from declaw.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
