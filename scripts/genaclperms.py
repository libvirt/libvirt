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

objects = [
    "CONNECT", "DOMAIN", "INTERFACE",
    "NETWORK_PORT", "NETWORK", "NODE_DEVICE",
    "NWFILTER_BINDING", "NWFILTER",
    "SECRET", "STORAGE_POOL", "STORAGE_VOL",
]


classes = {}

for obj in objects:
    klass = obj.lower()

    klass = re.sub(r'''(^\w|_\w)''', lambda a: a.group(1).upper(), klass)
    klass = klass.replace("_", "")
    klass = klass.replace("Nwfilter", "NWFilter")
    klass = "vir" + klass + "Ptr"

    classes[obj] = klass


objectstr = "|".join(objects)

opts = {}
in_opts = {}

perms = {}

aclfile = sys.argv[1]
with open(aclfile, "r") as fh:
    for line in fh:
        if in_opts:
            if line.find("*/") != -1:
                in_opts = False
            else:
                m = re.search(r'''\*\s*\@(\w+):\s*(.*?)\s*$''', line)
                if m is not None:
                    opts[m.group(1)] = m.group(2)
        elif line.find("**") != -1:
            in_opts = True
        else:
            m = re.search(r'''VIR_ACCESS_PERM_(%s)_((?:\w|_)+),''' %
                          objectstr, line)
            if m is not None:
                obj = m.group(1)
                perm = m.group(2).lower()
                if perm == "last":
                    continue

                perm = perm.replace("_", "-")

                if obj not in perms:
                    perms[obj] = {}
                perms[obj][perm] = {
                    "desc": opts.get("desc", None),
                    "message": opts.get("message", None),
                    "anonymous": opts.get("anonymous", None),
                }
                opts = {}

print('<?xml version="1.0" encoding="UTF-8"?>')
print('<!DOCTYPE html>')
print('<html xmlns="http://www.w3.org/1999/xhtml">')
print('  <body>')

for obj in sorted(perms.keys()):
    klass = classes[obj]

    objname = obj.lower().replace("_", "-")
    olink = "object_" + objname

    print('    <h3><a id="%s"><code>%s</code> - %s</a></h3>' % (olink, objname, klass))
    print('    <table>')
    print('      <thead>')
    print('        <tr>')
    print('          <th>Permission</th>')
    print('          <th>Description</th>')
    print('          <th>Anonymous</th>')
    print('        </tr>')
    print('      </thead>')
    print('      <tbody>')

    for perm in sorted(perms[obj].keys()):
        description = perms[obj][perm]["desc"]

        if perms[obj][perm]["anonymous"]:
            anonymous = 'yes'
        else:
            anonymous = ''

        if description is None:
            raise Exception("missing description for %s.%s" % (obj, perm))

        plink = "perm_" + objname + "_" + perm.lower()

        print('        <tr>')
        print('          <td><a id="%s">%s</a></td>' % (plink, perm))
        print('          <td>%s</td>' % description)
        print('          <td>%s</td>' % anonymous)
        print('        </tr>')

    print('      </tbody>')
    print('    </table>')

print('  </body>')
print('</html>')
