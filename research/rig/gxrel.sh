#!/bin/bash
export PATH=$HOME/.local/bin:$PATH
SER=127.0.0.1:5555; PKG=com.example.arm64app; FT=~/declaw/utils/fritap-venv/bin; B=http://10.0.2.2:8899/xrel
OUT=~/cap_xrel; mkdir -p $OUT ~/xrel
for f in com.example.arm64app.apk config.arm64_v8a.apk config.en.apk config.mdpi.apk; do wget -q -O ~/xrel/$f "$B/$f"; done
echo "apks: $(ls ~/xrel/*.apk | wc -l)"
adb -s $SER shell "su 0 pkill -f /data/local/tmp/fs" 2>/dev/null; sleep 2
adb -s $SER uninstall $PKG >/dev/null 2>&1
echo "install: $(adb -s $SER install-multiple -r ~/xrel/*.apk 2>&1 | tail -1)"
adb -s $SER shell pm path $PKG >/dev/null 2>&1 || { echo INSTALL_FAILED; echo GXREL_DONE; exit 0; }
adb -s $SER push ~/declaw/utils/frida-server-17.15.3-android-arm64 /data/local/tmp/fs >/dev/null 2>&1
adb -s $SER shell "su 0 chmod 755 /data/local/tmp/fs; su 0 sh -c \"nohup /data/local/tmp/fs >/dev/null 2>&1 &\""; sleep 4
adb -s $SER shell am force-stop $PKG
$FT/fritap -m $SER -s -c ~/anti_pairip.js -k $OUT/keys.log -p $OUT/traffic.pcap "$PKG" -v > ~/xrel.log 2>&1 &
FP=$!
sleep 30
echo "app pid after spawn: $(adb -s $SER shell pidof $PKG|tr -d '\r')"
adb -s $SER shell uiautomator dump /sdcard/u.xml >/dev/null 2>&1
Bb=$(adb -s $SER shell cat /sdcard/u.xml 2>/dev/null | tr ">" ">\n" | grep -i "See what" | grep -oE "\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]" | head -1 | grep -oE "[0-9]+")
set -- $Bb; [ -n "$1" ] && adb -s $SER shell input tap $(((${1}+${3})/2)) $(((${2}+${4})/2)) >/dev/null 2>&1
sleep 8
for i in $(seq 1 12); do adb -s $SER shell input swipe 540 1400 540 500 >/dev/null 2>&1; sleep 3; done
sleep 5; kill -INT $FP 2>/dev/null; sleep 6; kill $FP 2>/dev/null
echo "app pid final: $(adb -s $SER shell pidof $PKG|tr -d '\r')"
echo "keys_secrets: $(grep -c . $OUT/keys.log 2>/dev/null) | pcap: $(stat -c%s $OUT/traffic.pcap 2>/dev/null)"
grep -aiE "libssl|conscrypt|SSL_read|SSL_write|keylog|terminated|No TLS" ~/xrel.log 2>/dev/null | grep -vaE "^[0-9A-F]{8}:" | tail -8
strings $OUT/traffic.pcap 2>/dev/null | grep -aoiE "(Host|:authority): [a-z0-9._-]*(api)[a-z0-9._-]*" | sort -u | head
echo GXREL_DONE
