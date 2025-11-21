# adb-ssl-unpinning

Automated script to disable SSL certificate pinning without root using adb for applications that uses V1,2,3 and 4 Design scheme

## Usage

This script will pull the apk from the device, disable the SSL pinning, and push it back to the device through adb.

Be aware that this script will uninstall the app from the device, so make sure you have a backup of the app.

You can also find the original apk in the `com.example` and the modified apk in the `com.example_patched` folder.

```bash
$ python3 adb-ssl-unpinning.py <serial> <package_name>
```

Example:

```bash
$ python3 adb-ssl-unpinning.py emulator-5554 com.example
```

You can also use docker with it

```
docker build -t adb-ssl-unpinning .
adb kill-server
docker run -it --rm --privileged -v /dev/bus/usb:/dev/bus/usb --name adb-tool adb-ssl-unpinning <serial> <package>
```
## Find device serial

Connect your device to your computer and run `adb usb` to enable USB debugging, or use an emulator.

Then, find the serial of your device by running:

```bash
$ adb devices
List of devices attached
emulator-5554	device
```

Here `emulator-5554` is the serial number of the device.

## Find package name

```bash
$ adb shell pm list packages
$ adb shell pm list packages | grep example
```

## References

- [APKtool](https://ibotpeaches.github.io/Apktool/install)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
