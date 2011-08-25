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

namecolums = (0,2,10)
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

struct keycode virKeycodes[] = {
'''

sys.stdin.readline() # eat the fist line.

for line in sys.stdin.xreadlines():
    a = re.match("([^,]*)," * 13 + "([^,]*)$", line[0:-1]).groups()
    b = ""
    rfbkey = 0
    for i in namecolums:
        b = b + (a[i] and quotestring(a[i]) or 'NULL') + ','
    for i in [ x for x in range(12) if not x in namecolums ]:
        b = b + (a[i] or '0') + ','
        if i == xtkbdkey_index:
            # RFB keycodes are XT kbd keycodes with a slightly
            # different encoding of 0xe0 scan codes. RFB uses
            # the high bit of the first byte, instead of the low
            # bit of the second byte.
            rfbkey = int(a[i] or '0')
            rfbkey = (rfbkey & 0x100) >> 1 | (rfbkey & 0x7f)

    # Append RFB keycode as the last column
    b = b + str(rfbkey)
    print "    { " + b + "},"

print '};'
