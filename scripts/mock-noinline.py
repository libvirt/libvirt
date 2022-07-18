#!/usr/bin/env python3
#
# Copyright (C) 2017-2019 Red Hat, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

import re
import sys

noninlined = {}
mocked = {}

# Functions in public header don't get the noinline annotation
noninlined["virEventAddTimeout"] = True
# This one confuses the script as its defined in the mock file
# but is actually just a local helper
noninlined["virMockStatRedirect"] = True


def scan_annotations(filename):
    with open(filename, "r") as fh:
        func = None
        for line in fh:
            m = re.search(r'''^\s*(\w+)\(''', line)
            if m is None:
                m = re.search(r'''^(?:\w+\*?\s+)+(?:\*\s*)?(\w+)\(''', line)
            if m is not None:
                name = m.group(1)
                if "ATTRIBUTE" not in name and "G_GNUC_" not in name:
                    func = name
            elif line.isspace():
                func = None

            if "G_NO_INLINE" in line:
                if func is not None:
                    noninlined[func] = True


def scan_overrides(filename):
    with open(filename, "r") as fh:
        lineno = 0
        for line in fh:
            lineno = lineno + 1

            m = re.search(r'''^(\w+)\(''', line)
            if m is None:
                m = re.search(r'''^\w+\s*(?:\*\s*)?(\w+)\(''', line)
            if m is not None:
                name = m.group(1)
                if name.startswith("vir") or name.startswith("qemu") or name.startswith("libxl"):
                    mocked[name] = "%s:%d" % (filename, lineno)


for filename in sys.stdin.readlines():
    if filename.endswith(".h"):
        scan_annotations(filename)
    elif filename.endswith("mock.c"):
        scan_overrides(filename)

warned = False
for func in mocked.keys():
    if func not in noninlined:
        warned = True
        print("%s is mocked at %s but missing 'G_NO_INLINE' annotation" %
              (func, mocked[func]), file=sys.stderr)

if warned:
    sys.exit(1)
sys.exit(0)
