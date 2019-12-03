#!/usr/bin/env python3

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

import os.path
import re
import sys

if len(sys.argv) < 3:
    print("syntax: %s SRCDIR SYMFILE..." % sys.argv[0], file=sys.stderr)
    sys.exit(1)


def check_sorting(group, symfile, line, groupfile, lastgroup):
    sortedgroup = sorted(group, key=str.lower)
    issorted = True
    first = None
    last = None

    err = False
    # Check that groups are in order and groupfile exists
    if lastgroup is not None and lastgroup.lower() > groupfile.lower():
        print("Symbol block at %s:%s: block not sorted" %
              (symfile, line), file=sys.stderr)
        print("Move %s block before %s block" %
              (groupfile, lastgroup), file=sys.stderr)
        print("", file=sys.stderr)
        err = True

    if not os.path.exists(os.path.join(srcdir, groupfile)):
        print("Symbol block at %s:%s: %s not found" %
              (symfile, line, groupfile), file=sys.stderr)
        print("", file=sys.stderr)
        err = True

    # Check that symbols within a group are in order
    for i in range(len(group)):
        if sortedgroup[i] != group[i]:
            if first is None:
                first = i

            last = i
            issorted = False

    if not issorted:
        actual = group[first:last]
        expect = sortedgroup[first:last]
        print("Symbol block at %s:%s: symbols not sorted" %
              (symfile, line), file=sys.stderr)
        for g in actual:
            print("  %s" % g, file=sys.stderr)
        print("Correct ordering", file=sys.stderr)
        for g in expect:
            print("  %s" % g, file=sys.stderr)
        print("", file=sys.stderr)
        err = True

    return err


ret = 0
srcdir = sys.argv[1]
lastgroup = None
for symfile in sys.argv[2:]:
    with open(symfile, "r") as fh:
        lineno = 0
        groupfile = ""
        group = []
        thisline = 0

        for line in fh:
            thisline = thisline + 1
            line = line.strip()

            filenamematch = re.search(r'''^#\s*((\w+\/)*(\w+\.h))\s*$''', line)
            if filenamematch is not None:
                groupfile = filenamematch.group(1)
            elif line == "":
                if len(group) > 0:
                    if check_sorting(group, symfile, lineno,
                                     groupfile, lastgroup):
                        ret = 1

                group = []
                lineno = thisline
                lastgroup = groupfile
            elif line[0] == '#':
                # Ignore comments
                pass
            else:
                line = line.strip(";")
                group.append(line)

        if len(group) > 0:
            if check_sorting(group, symfile, lineno,
                             groupfile, lastgroup):
                ret = 1

        lastgroup = None

sys.exit(ret)
