#!/bin/bash
export PATH=$HOME/.local/bin:$PATH
SER=127.0.0.1:5555; PKG=com.example.arm64app; FT=~/declaw/utils/fritap-venv/bin
OUT=~/cap_tw_v2; mkdir -p $OUT
adb -s $SER shell "su 0 pkill -f /data/local/tmp/fs; su 0 pkill -f dsvc" 2>/dev/null; sleep 2
adb -s $SER push ~/declaw/utils/frida-server-17.15.3-android-arm64 /data/local/tmp/fs >/dev/null 2>&1
adb -s $SER shell "su 0 chmod 755 /data/local/tmp/fs; su 0 sh -c \"nohup /data/local/tmp/fs >/dev/null 2>&1 &\""; sleep 4
adb -s $SER shell am force-stop $PKG
$FT/fritap -m $SER -s -c ~/anti_pairip.js -k $OUT/keys.log -p $OUT/traffic.pcap "$PKG" -v > ~/tw_v2.log 2>&1 &
FP=$!
sleep 25
adb -s $SER shell uiautomator dump /sdcard/u.xml >/dev/null 2>&1
B=$(adb -s $SER shell cat /sdcard/u.xml 2>/dev/null | tr ">" ">\n" | grep -i "See what" | grep -oE "\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]" | head -1 | grep -oE "[0-9]+")
set -- $B
[ -n "$1" ] && adb -s $SER shell input tap $(((${1}+${3})/2)) $(((${2}+${4})/2)) >/dev/null 2>&1
sleep 10
echo "app pid after tap: $(adb -s $SER shell pidof $PKG|tr -d '\r')"
for i in $(seq 1 12); do adb -s $SER shell input swipe 540 1400 540 500 >/dev/null 2>&1; sleep 3; done
sleep 5; kill -INT $FP 2>/dev/null; sleep 6; kill $FP 2>/dev/null
echo "app pid final: $(adb -s $SER shell pidof $PKG|tr -d '\r')"
echo "keys_secrets: $(grep -c . $OUT/keys.log 2>/dev/null) | pcap_bytes: $(stat -c%s $OUT/traffic.pcap 2>/dev/null)"
grep -aiE "anti-pairip v2|pairip.*ptrace|pairip.*fork child|pairip.*swallow|libssl.*hook|keylog|terminated|No TLS" ~/tw_v2.log 2>/dev/null | grep -vaE "^[0-9A-F]{8}:" | tail -14
awk '{print $1}' $OUT/keys.log 2>/dev/null | sort | uniq -c
echo GTW_V2_DONE
