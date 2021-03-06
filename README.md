# RetroFreak Toolkit

This is a toolkit intended to help players root their RetroFreak console to get more features out of it.

The RetroFreak has an rk3066 SoC and uses the Rockchip image format for updates; these updates can be modified and repackaged using imgRePackerRK.

##### Requirements:
* Python 3
* Pycryptodomex >= 3.9.0

##### RetroFreak.py
A script to unpack updates for the RetroFreak that you can download from the official website [here](https://www.cybergadget.co.jp/support/retrofreak/en/update.html).

##### RetroFreakROM.py
This file is used to encrypt/decrypt ROM's so you can play them on your RetroFreak or PC.

##### An example to enable ADB (build.prop inside system.img):
```
persist.service.adb.enable=1                                                    
persist.service.debuggable=1
persist.sys.usb.config=adb
```

##### RetroFreak.py Usage:
```
usage: RetroFreak.py [-h] [-i IN_FILE] [-o OUT_DIR] [-l] [-e] [-d]

A script to make unpacking RetroFreak updates easier (or even possible in the first place)

optional arguments:
  -h, --help            show this help message and exit
  -i IN_FILE, --in-file IN_FILE
                        The update file you want to unpack
  -o OUT_DIR, --out-dir OUT_DIR
                        The directory you want to extract the update to
  -l, --list            List files in the update package
  -e, --extract         Extract files from the update package
  -d, --debug           Print debug info
```

##### RetroFreakROM.py Usage:
```
usage: RetroFreakROM.py [-h] [-o O] [-s SERIAL] [-k KEYFILE] ifile

A script to encrypt/decrypt ROM's to/from the RetroFreak

positional arguments:
  ifile                 The ROM to read from

optional arguments:
  -h, --help            show this help message and exit
  -o O                  The ROM file to write to
  -s SERIAL, --serial SERIAL
                        The serial number you want to use
  -k KEYFILE, --keyfile KEYFILE
                        The update request file to read from
```

##### Credits:
> [RedScoripoXDA](https://forum.xda-developers.com/member.php?u=4582467) for [imgRePackerRK](https://forum.xda-developers.com/showthread.php?t=2257331)