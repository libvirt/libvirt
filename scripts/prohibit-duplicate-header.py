#!/usr/bin/env python3
#
# Copyright (C) 2016-2019 Red Hat, Inc.
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


def check_file(filename):
    includes = {}
    lineno = 0
    errs = False
    with open(filename, "r") as fh:
        for line in fh:
            lineno = lineno + 1

            # skip non-matching lines early
            if line[0] != '#':
                continue

            headermatch = re.search(r'''^# *include *[<"]([^>"]*\.h)[">]''', line)
            if headermatch is not None:
                inc = headermatch.group(1)

                if inc in includes:
                    print("%s:%d: %s" % (filename, lineno, inc),
                          file=sys.stderr)
                    errs = True
                else:
                    includes[inc] = True

    return errs


ret = 0

for filename in sys.argv[1:]:
    if check_file(filename):
        ret = 1

if ret == 1:
    print("Do not include a header more than once per file", file=sys.stderr)

sys.exit(ret)
