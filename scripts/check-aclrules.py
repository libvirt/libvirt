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
# This script validates that the driver implementation of any
# public APIs contain ACL checks.
#
# As the script reads each source file, it attempts to identify
# top level function names.
#
# When reading the body of the functions, it looks for anything
# that looks like an API called named  XXXEnsureACL. It will
# validate that the XXX prefix matches the name of the function
# it occurs in.
#
# When it later finds the virDriverPtr table, for each entry
# point listed, it will validate if there was a previously
# detected EnsureACL call recorded.
#

import re
import sys

permitted = {
    "connectClose": True,
    "connectIsEncrypted": True,
    "connectIsSecure": True,
    "connectIsAlive": True,
    "networkOpen": True,
    "networkClose": True,
    "nwfilterOpen": True,
    "nwfilterClose": True,
    "secretOpen": True,
    "secretClose": True,
    "storageOpen": True,
    "storageClose": True,
    "interfaceOpen": True,
    "interfaceClose": True,
    "connectURIProbe": True,
    "localOnly": True,
    "domainQemuAttach": True,
}

# XXX this vzDomainMigrateConfirm3Params looks
# bogus - determine why it doesn't have a valid
# ACL check.
implpermitted = {
    "vzDomainMigrateConfirm3Params": True,
}

aclFuncHelpers = {
    "virDomainDriverNodeDeviceDetachFlags": True,
    "virDomainDriverNodeDeviceReset": True,
    "virDomainDriverNodeDeviceReAttach": True,
}

aclFuncHelperFile = "domain_driver.c"

lastfile = None


def fixup_name(name):
    name.replace("Nwfilter", "NWFilter")
    name.replace("Pm", "PM")
    name.replace("Scsi", "SCSI")
    if name.endswith("Xml"):
        name = name[:-3] + "XML"
    elif name.endswith("Uri"):
        name = name[:-3] + "URI"
    elif name.endswith("Uuid"):
        name = name[:-4] + "UUID"
    elif name.endswith("Id"):
        name = name[:-2] + "ID"
    elif name.endswith("Mac"):
        name = name[:-3] + "MAC"
    elif name.endswith("Cpu"):
        name = name[:-3] + "MAC"
    elif name.endswith("Os"):
        name = name[:-2] + "OS"
    elif name.endswith("Nmi"):
        name = name[:-3] + "NMI"
    elif name.endswith("Fstrim"):
        name = name[:-6] + "FSTrim"
    elif name.endswith("Wwn"):
        name = name[:-3] + "WWN"

    return name


def name_to_ProcName(name):
    elems = []
    if "_" in name or name.lower() in ["open", "close"]:
        elems = [n.lower().capitalize() for n in name.split("_")]
    else:
        elems = [name]

    elems = [fixup_name(n) for n in elems]
    procname = "".join(elems)

    return procname[0:1].lower() + procname[1:]


proto = sys.argv[1]

filteredmap = {}
with open(proto, "r") as fh:
    incomment = False
    filtered = False

    for line in fh:
        if "/**" in line:
            incomment = True
            filtered = False
        elif incomment:
            if "* @aclfilter" in line:
                filtered = True
            elif filtered:
                m = re.search(r'''REMOTE_PROC_(.*)\s+=\s*\d+''', line)
                if m is not None:
                    api = name_to_ProcName(m.group(1))
                    # Event filtering is handled in daemon/remote.c
                    # instead of drivers
                    if "_EVENT_REGISTER" not in line:
                        filteredmap[api] = True
                    incomment = False


def process_file(filename):
    brace = 0
    maybefunc = None
    intable = False
    table = None
    aclHelperFileCheck = False

    acls = aclFuncHelpers

    if aclFuncHelperFile in filename:
        acls = {}
        aclHelperFileCheck = True

    aclfilters = {}
    errs = False
    with open(filename, "r") as fh:
        lineno = 0
        for line in fh:
            lineno = lineno + 1
            if brace == 0:
                # Looks for anything which appears to be a function
                # body name. Doesn't matter if we pick up bogus stuff
                # here, as long as we don't miss valid stuff
                m = None
                if "(" in line:
                    m = re.search(r'''\b(\w+)\(''', line)
                if m is not None:
                    maybefunc = m.group(1)
            elif brace > 0:
                ensureacl = None
                checkacl = None
                stub = None
                if "EnsureACL" in line:
                    ensureacl = re.search(r'''(\w+)EnsureACL''', line)
                if "CheckACL" in line:
                    checkacl = re.search(r'''(\w+)CheckACL''', line)
                if "(" in line:
                    stub = re.search(r'''\b(\w+)\(''', line)
                if ensureacl is not None:
                    # Record the fact that maybefunc contains an
                    # ACL call, and make sure it is the right call!
                    func = ensureacl.group(1)
                    if func.startswith("vir"):
                        func = func[3:]

                    if maybefunc is None:
                        print("%s:%d Unexpected check '%s' outside function" %
                              (filename, lineno, func), file=sys.stderr)
                        errs = True
                    else:
                        if not maybefunc.lower().endswith(func.lower()):
                            print(("%s:%d Mismatch check 'vir%sEnsureACL'" +
                                   "for function '%s'") %
                                  (filename, lineno, func, maybefunc),
                                  file=sys.stderr)
                            errs = True
                    acls[maybefunc] = True
                elif checkacl:
                    # Record the fact that maybefunc contains an
                    # ACL filter call, and make sure it is the right call!
                    func = checkacl.group(1)
                    if func.startswith("vir"):
                        func = func[3:]

                    if maybefunc is None:
                        print("%s:%d Unexpected check '%s' outside function" %
                              (filename, lineno, func), file=sys.stderr)
                        errs = True
                    else:
                        if not maybefunc.lower().endswith(func.lower()):
                            print(("%s:%d Mismatch check 'vir%sCheckACL' " +
                                   "for function '%s'") %
                                  (filename, lineno, func, maybefunc),
                                  file=sys.stderr)
                            errs = True
                    aclfilters[maybefunc] = True
                elif stub:
                    # Handles case where we replaced an API with a new
                    # one which  adds new parameters, and we're left with
                    # a simple stub calling the new API.
                    callfunc = stub.group(1)
                    if callfunc in acls:
                        acls[maybefunc] = True

                    if callfunc in aclfilters:
                        aclfilters[maybefunc] = True

            # Pass the vir*DriverPtr tables and make sure that
            # every func listed there, has an impl which calls
            # an ACL function
            if intable:
                assign = None
                if "=" in line:
                    assign = re.search(r'''\.(\w+)\s*=\s*(\w+),?''', line)
                if "}" in line:
                    intable = False
                    table = None
                elif assign is not None:
                    api = assign.group(1)
                    impl = assign.group(2)

                    if (impl != "NULL" and
                            api not in ["no", "name"] and
                            table != "virStateDriver"):
                        if (impl not in acls and
                                api not in permitted and
                                impl not in implpermitted):
                            print(("%s:%d Missing ACL check in " +
                                   "function '%s' for '%s'") %
                                  (filename, lineno, impl, api),
                                  file=sys.stderr)
                            errs = True

                        if api in filteredmap and impl not in aclfilters:
                            print(("%s:%d Missing ACL filter in " +
                                   "function '%s' for '%s'") %
                                  (filename, lineno, impl, api),
                                  file=sys.stderr)
                            errs = True
            else:
                m = None
                if "Driver" in line:
                    m = re.search(r'''^(?:static\s+)?(vir(?:\w+)?Driver)\s+''',
                                  line)
                if m is not None:
                    name = m.group(1)
                    if name not in ["virNWFilterCallbackDriver",
                                    "virNWFilterTechDriver",
                                    "virDomainConfNWFilterDriver"]:
                        intable = True
                        table = name

            if "{" in line:
                brace = brace + 1
            if "}" in line:
                brace = brace - 1

    if aclHelperFileCheck:
        for helper in aclFuncHelpers:
            if helper not in acls:
                print(("%s:%d Missing ACL check in helper function '%s'") %
                      (filename, lineno, helper),
                      file=sys.stderr)

                errs = True

    return errs


status = 0
for filename in sys.argv[2:]:
    if process_file(filename):
        status = 1

sys.exit(status)
