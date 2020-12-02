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

name = sys.argv[1]
targetname = sys.argv[2]
libpath = sys.argv[3]
pdwtags = sys.argv[4]
expected = sys.argv[5]

builddir = os.path.dirname(libpath)
libname = os.path.basename(libpath)


def get_subdir(dirname, subdir):
    objectdir = ""
    reg = re.compile(subdir)
    for d in os.listdir(path=dirname):
        if reg.match(d):
            objectdir = d
            break

    if objectdir == "":
        raise Exception("Failed to find '{0}' in '{1}'".format(subdir, dirname))

    return os.path.join(dirname, objectdir)


# Figure out where is the meson target private directory that contains
# generated object files.
# With meson version < 0.55.0 the directory pattern is:
#
#   `hash_string@@target_name@bin_type` for example `25a6634@@vir_net_rpc@sta`
#
# but this was changed in meson 0.55.0 to a new pattern:
#
#   `output_file_name.p` for example `libvirt_net_rpc.a.p`
objectdir = get_subdir(
    builddir,
    r'(.*@{0}@.*|{1}\.p)'.format(targetname, re.escape(libname)))

proto_o = get_subdir(objectdir, r'.*{0}\.c\.o'.format(name))

pdwtagsproc = subprocess.Popen([pdwtags, "--verbose", proto_o],
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

diff = subprocess.Popen(["diff", "-b", "-u", expected, "-"], stdin=subprocess.PIPE)
actualstr = "\n".join(actual) + "\n"
# i686 builds on x86_64 host add __attribute__(packed)) to
# the structs. This doesn't matter functionally because we
# know our RPC structs are suitably aligned to not need
# packing, so we can just trim the attribute.
actualstr = re.sub(r'''} __attribute__\(\(__packed__\)\);''', "};", actualstr)

diff.communicate(input=actualstr.encode("utf-8"))

sys.exit(diff.returncode)
