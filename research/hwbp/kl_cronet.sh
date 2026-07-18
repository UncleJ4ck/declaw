#!/system/bin/sh
# End-to-end proof: extract real TLS secrets from a live, unmodified, uninjected
# a cronet app via an external hardware breakpoint on ssl_log_secret in the
# system BoringSSL. No frida, no ptrace-attach, no code patch inside the app.
PKG=com.example.cronetapp
am force-stop $PKG
am start -n $PKG/launcher.default >/dev/null 2>&1
sleep 6
P=$(pidof $PKG)
echo "app pid=$P"
[ -z "$P" ] && { echo NO_PID; exit 0; }
/data/local/tmp/hwbp_keylog $P /system/lib64/libssl.so 3038c 45 > /data/local/tmp/kl.out 2>&1 &
MON=$!
sleep 1
# continuous drive: scroll the feed to force fresh okhttp/conscrypt connections
for i in $(seq 1 30); do
  input swipe 540 1600 540 300 >/dev/null 2>&1
  sleep 1
done
wait $MON 2>/dev/null
echo "hits=$(grep -c '^HIT' /data/local/tmp/kl.out) reads_ok=$(grep -cE 'secret=[0-9a-f]{32}' /data/local/tmp/kl.out)"
grep -E "secret=[0-9a-f]{32}" /data/local/tmp/kl.out | head -6
echo "=== KL_CRONET_DONE ==="
