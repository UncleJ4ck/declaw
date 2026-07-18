#!/system/bin/sh
# Deterministic system-libssl TLS trigger: toggling airplane mode forces the
# NetworkStack to re-run its captive-portal validation, which does a fresh HTTPS
# probe (https://www.google.com/generate_204) through conscrypt ->
# /system/lib64/libssl.so. We arm the external HWBP on ALL of NetworkStack's
# threads first, then toggle to force the probe. Zero injection into NetworkStack.
PKG=com.android.networkstack.process
PID=$(pidof $PKG)
echo "netstack pid=$PID threads=$(ls /proc/$PID/task 2>/dev/null | wc -l)"
[ -z "$PID" ] && { echo NO_PID; exit 0; }
rm -f /data/local/tmp/kl.out
/data/local/tmp/hwbp_keylog $PID /system/lib64/libssl.so 3038c 30 > /data/local/tmp/kl.out 2>&1 &
MON=$!
sleep 2
# force revalidation -> captive portal HTTPS probe
cmd connectivity airplane-mode enable
sleep 3
cmd connectivity airplane-mode disable
# give the probe time to fire while the monitor polls
wait $MON 2>/dev/null
echo "=== monitor output ==="
cat /data/local/tmp/kl.out
echo "=== KL_NETSTACK_DONE ==="
