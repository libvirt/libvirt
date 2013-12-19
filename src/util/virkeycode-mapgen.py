#!/usr/bin/python

"""
Generate the big keycodes table for virkeys.
It read keymaps.csv from stdin and put the generated code to stdout.

Please keep keymaps.csv be exactly the same as:
http://git.gnome.org/browse/gtk-vnc/plain/src/keymaps.csv.
If anything inconsistent happens, please change this file
instead of keymaps.csv which is a mirror.
"""

import sys
import re

cols = (
    ["linux", True],
    ["linux", False],
    ["os_x", True],
    ["os_x", False],
    ["atset1", False],

    ["atset2", False],
    ["atset3", False],
    ["xt", False],
    ["xt_kbd", False],
    ["usb", False],

    ["win32", True],
    ["win32", False],
    [None, False],
    [None, False],
    ["rfb", False],
)

xtkbdkey_index = 8

def quotestring(str):
    if str[0] != '"':
        return '"' + str + '"'
    return str

print '''
/* Generated file, DON'T edit it */

#ifndef VIRT_KEY_INTERNAL
# error do not use this; it is not a public header
#endif

'''

sys.stdin.readline() # eat the fist line.

keycodes = []

max = 0

for line in sys.stdin.xreadlines():
    values = re.match("([^,]*)," * 13 + "([^,]*)$", line[0:-1]).groups()

    data = []
    for v in values:
        data.append(v)

    # RFB keycodes are XT kbd keycodes with a slightly
    # different encoding of 0xe0 scan codes. RFB uses
    # the high bit of the first byte, instead of the low
    # bit of the second byte.
    rfbkey = int(data[xtkbdkey_index] or '0')
    rfbkey = (rfbkey & 0x100) >> 1 | (rfbkey & 0x7f)
    data.append("%d" % rfbkey)

    keycodes.append(data)
    max = max + 1

print "#define VIR_KEYMAP_ENTRY_MAX " + str(max)

for i in range(len(cols)):
    col=cols[i]
    name=col[0]
    isname=col[1]

    if name is None:
        continue

    if isname:
        print "const char *virKeymapNames_" + name + "[] = {"
    else:
        print "int virKeymapValues_" + name + "[] = {"

    for entry in keycodes:
        if isname:
            print "  " + quotestring(entry[i] or "NULL") + ","
        else:
            print "  " + (entry[i] or "-1") + ","

    print "};\n"
