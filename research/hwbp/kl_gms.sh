#!/system/bin/sh
# External HWBP key extraction against a stable, always-on bionic system process
# (GMS persistent) that does TLS via /system/lib64/libssl.so. Zero injection.
PKG=com.google.android.gms.persistent
PID=$(pidof $PKG)
echo "target=$PKG pid=$PID"
[ -z "$PID" ] && { echo NO_PID; exit 0; }
rm -f /data/local/tmp/kl.out
/data/local/tmp/hwbp_keylog $PID /system/lib64/libssl.so 3038c 35 > /data/local/tmp/kl.out 2>&1 &
MON=$!
sleep 1
# churn the network to force revalidation + GMS re-sync (multiple triggers)
cmd connectivity airplane-mode enable 2>/dev/null
sleep 2
cmd connectivity airplane-mode disable 2>/dev/null
svc data enable 2>/dev/null; svc wifi enable 2>/dev/null
sleep 2
cmd connectivity reevaluate 100 2>/dev/null
cmd connectivity reevaluate 101 2>/dev/null
# nudge GMS to sync
am broadcast -a android.intent.action.SYNC 2>/dev/null >/dev/null
am broadcast -a com.google.android.gms.gcm.ACTION_SCHEDULE 2>/dev/null >/dev/null
wait $MON 2>/dev/null
echo "=== monitor output ==="
cat /data/local/tmp/kl.out
echo "=== KL_GMS_DONE ==="
