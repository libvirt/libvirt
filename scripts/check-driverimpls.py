#!/usr/bin/env python3
#
# Copyright (C) 2013-2019 Red Hat, Inc.
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
#

import re
import sys


def checkdriverimpls(filename):
    intable = False
    mainprefix = None

    errs = False
    with open(filename, "r") as fh:
        lineno = 0
        for line in fh:
            lineno = lineno + 1
            if intable:
                if "}" in line:
                    intable = False
                    mainprefix = None
                    continue

                m = re.search(r'''\.(\w+)\s*=\s*(\w+),?''', line)
                if m is not None:
                    api = m.group(1)
                    impl = m.group(2)

                    if api in ["no", "name"]:
                        continue
                    if impl in ["NULL"]:
                        continue

                    suffix = impl
                    prefix = re.sub(r'''^([a-z]+)(.*?)$''', r'''\1''', impl)

                    if mainprefix is not None:
                        if mainprefix != prefix:
                            print(("%s:%d Bad prefix '%s' for API '%s', " +
                                   "expecting '%s'") %
                                  (filename, lineno, prefix, api, mainprefix),
                                  file=sys.stderr)
                            errs = True
                    else:
                        mainprefix = prefix

                    if not api.startswith(mainprefix):
                        suffix = re.sub(r'''^[a-z]+''', "", suffix)
                        suffix = re.sub(r'''^([A-Z]+)''',
                                        lambda m: m.group(1).lower(), suffix)

                    if api != suffix:
                        want = api
                        if want.startswith("nwf"):
                            want = "NWF" + want[3:]

                        if not api.startswith(mainprefix):
                            want = re.sub(r'''^([a-z])''',
                                          lambda m: m.group(1).upper(), want)
                            want = mainprefix + want

                        print(("%s:%d Bad impl name '%s' for API " +
                               "'%s', expecting '%s'") %
                              (filename, lineno, impl, api, want),
                              file=sys.stderr)
                        errs = True
            else:
                m = re.search(r'''^(?:static\s+)?(vir(?:\w+)?Driver)''' +
                              r'''\s+(?!.*;)''', line)
                if m is not None:
                    drv = m.group(1)
                    if drv in [
                            "virNWFilterCallbackDriver",
                            "virNWFilterTechDriver",
                            "virConnectDriver"]:
                        continue
                    intable = True

    return errs


status = 0
for filename in sys.argv[1:]:
    if checkdriverimpls(filename):
        status = 1
sys.exit(status)
