#!/usr/bin/env python3
#
# Copyright (C) 2011-2019 Red Hat, Inc.
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
#
# Generate a set of systemtap probe definitions corresponding to
# DTrace probe markers in libvirt.so
#
#  python dtrace2systemtap.py probes.d > libvirt_probes.stp
#

import re
import sys

file = None
filelist = []
files = {}

bindir = sys.argv[1]
sbindir = sys.argv[2]
libdir = sys.argv[3]
dtrace = sys.argv[4]

probe = None
args = None

# Read the DTraceprobes definition

with open(dtrace, "r") as fh:
    lineno = 0
    for line in fh:
        lineno = lineno + 1
        line = line.strip()
        if line == "":
            continue
        if "provider " in line and "{" in line:
            continue
        if "};" in line:
            continue

        if line.startswith("#"):
            m = re.search(r'''^\#\s*file:\s*(\S+)$''', line)
            if m is not None:
                file = m.group(1)
                filelist.append(file)
                files[file] = {"prefix": None, "probes": []}
                continue

            m = re.search(r'''^\#\s*prefix:\s*(\S+)$''', line)
            if m is not None:
                files[file]["prefix"] = m.group(1)
                continue

            m = re.search(r'''^\#\s*binary:\s*(\S+)$''', line)
            if m is not None:
                files[file]["binary"] = m.group(1)
                continue

            m = re.search(r'''^\#\s*module:\s*(\S+)$''', line)
            if m is not None:
                files[file]["module"] = m.group(1)

            # ignore unknown comments
        else:
            m = re.search(r'''probe\s+([a-zA-Z0-9_]+)\((.*?)(\);)?$''', line)
            if m is not None:
                probe = m.group(1)
                args = m.group(2)
                if m.group(3) is not None:
                    files[file]["probes"].append([probe, args])
                    probe = None
                    args = None
            elif probe is not None:
                m = re.search(r'''^(.*?)(\);)?$''', line)
                if m is not None:
                    args = args + m.group(1)
                    if m.group(2) is not None:
                        files[file]["probes"].append([probe, args])
                        probe = None
                        args = None
                else:
                    raise Exception("unexpected data %s on line %d" %
                                    (line, lineno))
            else:
                raise Exception("unexpected data %s on line %d" %
                                (line, lineno))

# Write out the SystemTap probes
for file in filelist:
    prefix = files[file]["prefix"]
    probes = files[file]["probes"]

    print("# %s\n" % file)
    for probe in probes:
        name = probe[0]
        args = probe[1]

        pname = name.replace(prefix + "_", "libvirt." + prefix + ".")

        binary = libdir + "/libvirt.so"
        if "binary" in files[file]:
            binary = sbindir + "/" + files[file]["binary"]
        if "module" in files[file]:
            binary = libdir + "/" + files[file]["module"]

        print("probe %s = process(\"%s\").mark(\"%s\") {" %
              (pname, binary, name))

        argbits = args.split(",")
        for idx in range(len(argbits)):
            arg = argbits[idx]
            isstr = False
            if 'char *' in arg:
                isstr = True

            m = re.search(r'''^.*\s\*?(\S+)$''', arg)
            if m is not None:
                arg = m.group(1)
            else:
                raise Exception("Malformed arg %s" % arg)

            if isstr:
                print("  %s = user_string($arg%d);" % (arg, idx + 1))
            else:
                print("  %s = $arg%d;" % (arg, idx + 1))
        print("}\n")
    print("")
