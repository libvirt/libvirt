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
# Generate a set of systemtap functions for translating various
# RPC enum values into strings
#
#   python gensystemtap.py */*.x > libvirt_functions.stp
#

import re
import sys

funcs = {}

types = {}
status = {}
auth = {}


def load_file(fh):
    instatus = False
    intype = False
    inauth = False

    for line in fh:
        if re.search(r'''enum\s+virNetMessageType''', line):
            intype = True
        elif re.search(r'''enum\s+virNetMessageStatus''', line):
            instatus = True
        elif re.search(r'''enum remote_auth_type''', line):
            inauth = True
        elif "}" in line:
            intype = False
            instatus = False
            inauth = False
        elif instatus:
            m = re.search(r'''^\s+VIR_NET_(\w+)\s*=\s*(\d+),?$''', line)
            if m is not None:
                status[m.group(2)] = m.group(1).lower()
        elif intype:
            m = re.search(r'''^\s+VIR_NET_(\w+)\s*=\s*(\d+),?$''', line)
            if m is not None:
                types[m.group(2)] = m.group(1).lower()
        elif inauth:
            m = re.search(r'''^\s+REMOTE_AUTH_(\w+)\s*=\s*(\d+),?$''', line)
            if m is not None:
                auth[m.group(2)] = m.group(1).lower()
        else:
            m = re.search(r'''(?:VIR_)?(\w+?)(?:_PROTOCOL)?''' +
                          r'''_PROGRAM\s*=\s*0x([a-fA-F0-9]+)\s*;''', line)
            if m is not None:
                funcs[m.group(1).lower()] = {
                    "id": int(m.group(2), 16),
                    "version": None,
                    "progs": []
                }
                continue

            m = re.search(r'''(?:VIR_)?(\w+?)(?:_PROTOCOL)?_''' +
                          r'''(?:PROGRAM|PROTOCOL)_VERSION\s*=\s*(\d+)\s*;''',
                          line)
            if m is not None:
                funcs[m.group(1).lower()]["version"] = m.group(2)
                continue

            m = re.search(r'''(?:VIR_)?(\w+?)(?:_PROTOCOL)?''' +
                          r'''_PROC_(.*?)\s+=\s+(\d+)''', line)
            if m is not None:
                funcs[m.group(1).lower()]["progs"].insert(
                    int(m.group(3)), m.group(2).lower())


for file in sys.argv[1:]:
    with open(file, "r") as fh:
        load_file(fh)


def genfunc(name, varname, types):
    print("function %s(%s, verbose)" % (name, varname))
    print("{")

    first = True
    for typename in sorted(types.keys()):
        cond = "} else if"
        if first:
            cond = "if"
            first = False

        print("  %s (%s == %s) {" % (cond, varname, typename))
        print("      %sstr = \"%s\"" % (varname, types[typename]))

    print("  } else {")
    print("      %sstr = \"unknown\";" % varname)
    print("      verbose = 1;")
    print("  }")
    print("  if (verbose) {")
    print("      %sstr = %sstr . sprintf(\":%%d\", %s)" %
          (varname, varname, varname))
    print("  }")
    print("  return %sstr;" % varname)
    print("}")


genfunc("libvirt_rpc_auth_name", "type", auth)
genfunc("libvirt_rpc_type_name", "type", types)
genfunc("libvirt_rpc_status_name", "status", status)

print("function libvirt_rpc_program_name(program, verbose)")
print("{")

first = True
for funcname in sorted(funcs.keys()):
    cond = "} else if"
    if first:
        cond = "if"
        first = False

    print("  %s (program == %s) {" % (cond, funcs[funcname]["id"]))
    print("      programstr = \"%s\"" % funcname)

print("  } else {")
print("      programstr = \"unknown\";")
print("      verbose = 1;")
print("  }")
print("  if (verbose) {")
print("      programstr = programstr . sprintf(\":%d\", program)")
print("  }")
print("  return programstr;")
print("}")

print("function libvirt_rpc_procedure_name(program, version, proc, verbose)")
print("{")

first = True
for prog in sorted(funcs.keys()):
    cond = "} else if"
    if first:
        cond = "if"
        first = False

    print("  %s (program == %s && version == %s) {" %
          (cond, funcs[prog]["id"], funcs[prog]["version"]))

    pfirst = True
    for id in range(len(funcs[prog]["progs"])):
        pcond = "} else if"
        if pfirst:
            pcond = "if"
            pfirst = False

        print("      %s (proc == %s) {" % (pcond, id + 1))
        print("          procstr = \"%s\";" % funcs[prog]["progs"][id])

    print("      } else {")
    print("          procstr = \"unknown\";")
    print("          verbose = 1;")
    print("      }")

print("  } else {")
print("      procstr = \"unknown\";")
print("      verbose = 1;")
print("  }")
print("  if (verbose) {")
print("      procstr = procstr . sprintf(\":%d\", proc)")
print("  }")
print("  return procstr;")
print("}")
