#!/system/bin/sh
# End-to-end decrypt proof for --hwbp-capture. Arm the HWBP on system libssl AND
# start rawcap on a SETTLED cronet app, then drive hard (open posts -> fresh okhttp/Coil
# image handshakes to the CDN) so new handshakes land inside the captured window.
# Off-device, tshark decrypts cap.pcap with the keylog.
PKG=com.example.cronetapp
P=$(pidof $PKG)
[ -z "$P" ] && { am start -n $PKG/launcher.default >/dev/null 2>&1; sleep 10; P=$(pidof $PKG); }
echo "app pid=$P"
[ -z "$P" ] && { echo NO_PID; exit 0; }
rm -f /data/local/tmp/cap.pcap /data/local/tmp/dk.log
/data/local/tmp/rawcap eth0 62 /data/local/tmp/cap.pcap 2>/data/local/tmp/rawcap.err &
/data/local/tmp/hwbp_keylog $P /system/lib64/libssl.so 3038c 62 /data/local/tmp/dk.log > /data/local/tmp/dk.out 2>&1 &
sleep 2
# aggressive drive: open a post, scroll inside, back, scroll feed, repeat
for i in $(seq 1 18); do
  input tap 540 900 >/dev/null 2>&1; sleep 1.2       # open a post (loads images)
  input swipe 540 1400 540 500 >/dev/null 2>&1; sleep 0.8
  input keyevent 4 >/dev/null 2>&1; sleep 0.5         # back to feed
  input swipe 540 1600 540 300 >/dev/null 2>&1; sleep 0.6
done
wait
echo "keys=$(grep -c . /data/local/tmp/dk.log 2>/dev/null)"
cat /data/local/tmp/rawcap.err 2>/dev/null
grep RESULT /data/local/tmp/dk.out 2>/dev/null
echo KL_DECRYPT_DONE
