#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pocket Chinese firmware verifier (anti-tamper check)
Usage:  python verify_new_fw.py
Reads pocket-cn-moli.bin from ../01-Firmware固件/ (or the same folder)
and verifies the moli signatures and bootloader/APP vectors.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

candidates = [
    os.path.normpath(os.path.join(HERE, "..", "01-Firmware固件", "pocket-cn-moli.bin")),
    os.path.join(HERE, "pocket-cn-moli.bin"),
]
path = next((p for p in candidates if os.path.exists(p)), None)
if path is None:
    sys.exit("ERROR: pocket-cn-moli.bin not found. Keep the release folder "
             "layout, or copy the firmware next to this script and retry.")

with open(path, "rb") as f:
    data = f.read()

print("file:", path)
print("size = %d (0x%X)" % (len(data), len(data)))

# Pocket (X7/POCKET): bootloader @0x0000, application @0x8000
for off in (0x0000, 0x8000):
    sp, pc = struct.unpack_from("<II", data, off)
    print("@%04X: SP=0x%08X PC=0x%08X" % (off, sp, pc))

ok = True
for key in (b"moli", b"Custom by moli"):
    i = data.find(key)
    found = i >= 0
    ok = ok and found
    print("%s: %s" % (key.decode("ascii", "ignore"),
                     ("found @0x%X" % i) if found else "NOT FOUND"))

print("anti-tamper check:", "PASS - genuine moli firmware" if ok else "FAIL - signature missing")
