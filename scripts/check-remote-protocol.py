#!/usr/bin/env python3
#
# Copyright (C) 2019 Red Hat, Inc.
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
# This uses pdwtags to check remote protocol defs
#
# * the "split" splits on the /* DD */ comments, so that $p iterates
#     through the struct definitions.
# * process only "struct remote_..." entries
# * remove comments and preceding TAB throughout
# * remove empty lines throughout
# * remove white space at end of buffer

import os
import os.path
import re
import subprocess
import sys

cc = sys.argv[1]
objext = sys.argv[2]
proto_lo = sys.argv[3]
expected = sys.argv[4]

proto_lo = proto_lo.replace("/", "/.libs/")

ccargv = cc.split(" ")
ccargv.append("-v")
ccproc = subprocess.Popen(ccargv, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
out, err = ccproc.communicate()
out = out.decode("utf-8")
if out.find("clang") != -1:
    print("WARNING: skipping pdwtags test with Clang", file=sys.stderr)
    sys.exit(0)


def which(program):
    def is_exe(fpath):
        return (os.path.isfile(fpath) and
                os.access(fpath, os.X_OK))

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


pdwtags = which("pdwtags")
if pdwtags is None:
    print("WARNING: you lack pdwtags; skipping the protocol test",
          file=sys.stderr)
    print("WARNING: install the dwarves package to get pdwtags",
          file=sys.stderr)
    sys.exit(0)

proto_o = proto_lo.replace(".lo", ".o")

if not os.path.exists(proto_o):
    raise Exception("Missing %s", proto_o)

pdwtagsproc = subprocess.Popen(["pdwtags", "--verbose", proto_o],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = pdwtagsproc.communicate()
out = out.decode("utf-8")
err = err.decode("utf-8")

if out == "" or pdwtagsproc.returncode != 0:
    if out == "":
        print("WARNING: no output, pdwtags appears broken:", file=sys.stderr)
    else:
        print("WARNING: exit code %d, pdwtags appears broken:" %
              pdwtagsproc.returncode, file=sys.stderr)
    for line in err.strip().split("\n"):
        print("WARNING: %s" % line, file=sys.stderr)
    print("WARNING: skipping the remote protocol test", file=sys.stderr)
    sys.exit(0)

# With pdwtags 1.8, --verbose output includes separators like these:
# /* 93 */
# /* <0> (null):0 */
# with the second line omitted for intrinsic types.
# Whereas with pdwtags 1.3, they look like this:
# /* <2d2> /usr/include/libio.h:180 */
# The alternation of the following regexps matches both cases.
r1 = r'''/\* \d+ \*/'''
r2 = r'''/\* <[0-9a-fA-F]+> \S+:\d+ \*/'''

libs_prefix = "remote_|qemu_|lxc_|admin_"
other_prefix = "keepalive|vir(Net|LockSpace|LXCMonitor)"
struct_prefix = "(" + libs_prefix + "|" + other_prefix + ")"

n = 0
bits = re.split(r'''\n*(?:%s|%s)\n''' % (r1, r2), out)
actual = ["/* -*- c -*- */"]

for bit in bits:
    if re.search(r'''^(struct|enum)\s+''' + struct_prefix, bit):
        bit = re.sub(r'''\t*/\*.*?\*/''', "", bit)
        bit = re.sub(r'''\s+\n''', '''\n''', bit)
        bit = re.sub(r'''\s+$''', "", bit)
        bit = re.sub(r'''\t''', "        ", bit)
        actual.append(bit)
        n = n + 1

if n < 1:
    print("WARNING: No structs/enums matched. Your", file=sys.stderr)
    print("WARNING: pdwtags program is probably too old", file=sys.stderr)
    print("WARNING: skipping the remote protocol test", file=sys.stderr)
    print("WARNING: install dwarves-1.3 or newer", file=sys.stderr)
    sys.exit(8)

diff = subprocess.Popen(["diff", "-u", expected, "-"], stdin=subprocess.PIPE)
actualstr = "\n".join(actual) + "\n"
diff.communicate(input=actualstr.encode("utf-8"))

sys.exit(diff.returncode)
