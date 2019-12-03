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
#

import re
import sys

objects = [
    "CONNECT", "DOMAIN", "INTERFACE", "NETWORK_PORT",
    "NETWORK", "NODE_DEVICE", "NWFILTER_BINDING",
    "NWFILTER", "SECRET", "STORAGE_POOL", "STORAGE_VOL",
]

objectstr = "|".join(objects)

# Data we're going to be generating looks like this
#
# <policyconfig>
#   <action id="org.libvirt.unix.monitor">
#     <description>Monitor local virtualized systems</description>
#     <message>System policy prevents monitoring of
#              local virtualized systems</message>
#     <defaults>
#       <allow_any>yes</allow_any>
#       <allow_inactive>yes</allow_inactive>
#       <allow_active>yes</allow_active>
#     </defaults>
#   </action>
#   ...more <action> rules...
# </policyconfig>

opts = {}
in_opts = False

perms = {}

aclfile = sys.argv[1]
with open(aclfile, "r") as fh:
    for line in fh:
        if in_opts:
            if "*/" in line:
                in_opts = False
            else:
                m = re.search(r'''\*\s*\@(\w+):\s*(.*?)\s*$''', line)
                if m is not None:
                    opts[m.group(1)] = m.group(2)
        elif "**" in line:
            in_opts = True
        else:
            m = re.search(r'''VIR_ACCESS_PERM_(%s)_((?:\w|_)+),''' %
                          objectstr, line)
            if m is not None:
                obj = m.group(1).lower()
                perm = m.group(2).lower()
                if perm == "last":
                    continue

                obj = obj.replace("_", "-")
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
print('<!DOCTYPE policyconfig PUBLIC ' +
      '"-//freedesktop//DTD polkit Policy Configuration 1.0//EN"')
print('    "http://www.freedesktop.org/software/polkit/policyconfig-1.dtd">')
print('<policyconfig>')
print('  <vendor>Libvirt Project</vendor>')
print('  <vendor_url>https://libvirt.org</vendor_url>')

for obj in sorted(perms.keys()):
    for perm in sorted(perms[obj].keys()):
        description = perms[obj][perm]["desc"]
        message = perms[obj][perm]["message"]
        anonymous = perms[obj][perm]["anonymous"]

        if description is None:
            raise Exception("missing description for %s.%s" % (obj, perm))
        if message is None:
            raise Exception("missing message for %s.%s" % (obj, perm))

        allow_any = "no"
        if anonymous:
            allow_any = "yes"
        allow_inactive = allow_any
        allow_active = allow_any

        print('  <action id="org.libvirt.api.%s.%s">' % (obj, perm))
        print('    <description>%s</description>' % description)
        print('    <message>%s</message>' % message)
        print('    <defaults>')
        print('      <allow_any>%s</allow_any>' % allow_any)
        print('      <allow_inactive>%s</allow_inactive>' % allow_inactive)
        print('      <allow_active>%s</allow_active>' % allow_active)
        print('    </defaults>')
        print('  </action>')

print('</policyconfig>')
