#!/usr/bin/env python3
#
# Copyright (C) 2012-2019 Red Hat, Inc.
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
import subprocess
import sys

if len(sys.argv) < 3:
    print("syntax: %s SYMFILE ELFLIB(S)" % sys.argv[0], file=sys.stderr)

symfile = sys.argv[1]
elflibs = sys.argv[2:]

wantsyms = {}
gotsyms = {}

ret = 0

with open(symfile, "r") as fh:
    for line in fh:
        line = line.strip()
        if "{" in line:
            continue
        if "}" in line:
            continue
        if line in ["global:", "local:"]:
            continue
        if line == "":
            continue
        if line[0] == '#':
            continue
        if "*" in line:
            continue

        line = line.strip(";")

        if line in wantsyms:
            print("Symbol %s is listed twice" % line, file=sys.stderr)
            ret = 1
        else:
            wantsyms[line] = True

for elflib in elflibs:
    nm = subprocess.Popen(["nm", elflib], shell=False,
                          stdout=subprocess.PIPE).stdout

    for line in nm:
        line = line.decode("utf-8")
        symmatch = re.search(r'''^\S+\s(?:[TBD])\s(\S+)\s*$''', line)
        if symmatch is None:
            continue

        gotsyms[symmatch.group(1)] = True


for sym in wantsyms.keys():
    if sym in gotsyms:
        continue

    print("Expected symbol '%s' is not in ELF library" % sym, file=sys.stderr)
    ret = 1

sys.exit(ret)
