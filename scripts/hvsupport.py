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

import os.path
import re
import sys

if len(sys.argv) != 3:
    print("syntax: %s TOP-SRCDIR TOP-BUILDDIR\n" % sys.argv[0], file=sys.stderr)

srcdir = sys.argv[1]
builddir = sys.argv[2]

symslibvirt = os.path.join(srcdir, "src", "libvirt_public.syms")
symsqemu = os.path.join(srcdir, "src", "libvirt_qemu.syms")
symslxc = os.path.join(srcdir, "src", "libvirt_lxc.syms")
drivertablefiles = [
    os.path.join(srcdir, "src", "driver-hypervisor.h"),
    os.path.join(srcdir, "src", "driver-interface.h"),
    os.path.join(srcdir, "src", "driver-network.h"),
    os.path.join(srcdir, "src", "driver-nodedev.h"),
    os.path.join(srcdir, "src", "driver-nwfilter.h"),
    os.path.join(srcdir, "src", "driver-secret.h"),
    os.path.join(srcdir, "src", "driver-state.h"),
    os.path.join(srcdir, "src", "driver-storage.h"),
    os.path.join(srcdir, "src", "driver-stream.h"),
]

groupheaders = {
    "virHypervisorDriver": "Hypervisor APIs",
    "virNetworkDriver": "Virtual Network APIs",
    "virInterfaceDriver": "Host Interface APIs",
    "virNodeDeviceDriver": "Host Device APIs",
    "virStorageDriver": "Storage Pool APIs",
    "virSecretDriver": "Secret APIs",
    "virNWFilterDriver": "Network Filter APIs",
    "commonapis": "Common driver APIs",
}

# List of common APIs used with all driver kinds
commonapis = [
    "virConnectOpen",
    "virConnectClose",
    "virConnectIsAlive",
    "virConnectIsEncrypted",
    "virConnectIsSecure",
    "virConnectSupportsFeature",
    "virConnectGetCapabilities",
]

srcs = []
for root, dirs, files in os.walk(os.path.join(srcdir, "src")):
    for file in files:
        if ((file.endswith("driver.c") and
             not file.endswith("vbox_driver.c")) or
                file.endswith("common.c") or
                file.endswith("tmpl.c") or
                file.endswith("monitor.c") or
                file.endswith("udev.c")):
            srcs.append(os.path.join(root, file))


# Map API functions to the header and documentation files they're in
# so that we can generate proper hyperlinks to their documentation.
#
# The function names are grep'd from the XML output of apibuild.py.
def getAPIFilenames(filename):
    files = {}

    with open(filename) as fh:
        for line in fh:
            res = re.search(r"function name='([^']+)' file='([^']+)'", line)
            if res is not None:
                files[res.group(1)] = res.group(2)

    if len(files) == 0:
        raise Exception(("No functions found in %s. " +
                         "Has the apibuild.py output changed?") %
                        filename)

    return files


def parseSymsFile(apisref, prefix, filename, xmlfilename):
    vers = None
    prevvers = None

    filenames = getAPIFilenames(xmlfilename)

    with open(filename) as fh:
        for line in fh:
            line = line.strip()

            if line == "":
                continue
            if line[0] == '#':
                continue
            if line.startswith("global:"):
                continue
            if line.startswith("local:"):
                continue

            groupstartmatch = re.search(r"^\s*%s_(\d+\.\d+\.\d+)\s*{\s*$" %
                                        prefix, line)
            groupendmatch1 = re.search(r"^\s*}\s*;\s*$", line)
            groupendmatch2 = re.search(r"^\s*}\s*%s_(\d+\.\d+\.\d+)\s*;\s*$" %
                                       prefix, line)
            symbolmatch = re.search(r"^\s*(\w+)\s*;\s*$", line)
            if groupstartmatch is not None:
                if vers is not None:
                    raise Exception("malformed syms file when starting group")

                vers = groupstartmatch.group(1)
            elif groupendmatch1 is not None:
                if prevvers is not None:
                    raise Exception("malformed syms file when ending group")

                prevvers = vers
                vers = None
            elif groupendmatch2 is not None:
                if groupendmatch2.group(1) != prevvers:
                    raise Exception(("malformed syms file %s != %s " +
                                     "when ending group") %
                                    (groupendmatch2.group(1), prevvers))

                prevvers = vers
                vers = None
            elif symbolmatch is not None:
                name = symbolmatch.group(1)
                apisref[name] = {
                    "vers": vers,
                    "file": filenames.get(name),
                }
            else:
                raise Exception("unexpected data %s" % line)


apis = {}
# Get the list of all public APIs and their corresponding version
parseSymsFile(apis, "LIBVIRT", symslibvirt,
              os.path.join(builddir, "docs", "libvirt-api.xml"))

# And the same for the QEMU specific APIs
parseSymsFile(apis, "LIBVIRT_QEMU", symsqemu,
              os.path.join(builddir, "docs", "libvirt-qemu-api.xml"))

# And the same for the LXC specific APIs
parseSymsFile(apis, "LIBVIRT_LXC", symslxc,
              os.path.join(builddir, "docs", "libvirt-lxc-api.xml"))


# Some special things which aren't public APIs,
# but we want to report
apis["virConnectSupportsFeature"] = {
    "vers": "0.3.2"
}
apis["virDomainMigratePrepare"] = {
    "vers": "0.3.2"
}
apis["virDomainMigratePerform"] = {
    "vers": "0.3.2"
}
apis["virDomainMigrateFinish"] = {
    "vers": "0.3.2"
}
apis["virDomainMigratePrepare2"] = {
    "vers": "0.5.0"
}
apis["virDomainMigrateFinish2"] = {
    "vers": "0.5.0"
}
apis["virDomainMigratePrepareTunnel"] = {
    "vers": "0.7.2"
}

apis["virDomainMigrateBegin3"] = {
    "vers": "0.9.2"
}
apis["virDomainMigratePrepare3"] = {
    "vers": "0.9.2"
}
apis["virDomainMigratePrepareTunnel3"] = {
    "vers": "0.9.2"
}
apis["virDomainMigratePerform3"] = {
    "vers": "0.9.2"
}
apis["virDomainMigrateFinish3"] = {
    "vers": "0.9.2"
}
apis["virDomainMigrateConfirm3"] = {
    "vers": "0.9.2"
}

apis["virDomainMigrateBegin3Params"] = {
    "vers": "1.1.0"
}
apis["virDomainMigratePrepare3Params"] = {
    "vers": "1.1.0"
}
apis["virDomainMigratePrepareTunnel3Params"] = {
    "vers": "1.1.0"
}
apis["virDomainMigratePerform3Params"] = {
    "vers": "1.1.0"
}
apis["virDomainMigrateFinish3Params"] = {
    "vers": "1.1.0"
}
apis["virDomainMigrateConfirm3Params"] = {
    "vers": "1.1.0"
}


# Now we want to get the mapping between public APIs
# and driver struct fields. This lets us later match
# update the driver impls with the public APis.

# Group name -> hash of APIs { fields -> api name }
groups = {}
groups["commonapis"] = {
    "apis": {},
    "drivers": {}
}
ingrp = None
for drivertablefile in drivertablefiles:
    with open(drivertablefile) as fh:
        for line in fh:
            starttablematch = re.search(r"struct _(vir\w*Driver)", line)
            if starttablematch is not None:
                grp = starttablematch.group(1)
                if grp != "virStateDriver" and grp != "virStreamDriver":
                    ingrp = grp
                    groups[ingrp] = {
                        "apis": {},
                        "drivers": {}
                    }
            elif ingrp is not None:
                callbackmatch = re.search(r"^\s*vir(?:Drv)(\w+)\s+(\w+);\s*$",
                                          line)
                if callbackmatch is not None:
                    name = callbackmatch.group(1)
                    field = callbackmatch.group(2)

                    api = "vir" + name
                    if api in apis:
                        if api in commonapis:
                            groups["commonapis"]["apis"][field] = api
                        else:
                            groups[ingrp]["apis"][field] = api
                    elif re.search(r"\w+(Open|Close|URIProbe)", api) is not None:
                        continue
                    else:
                        raise Exception(("driver %s does not have " +
                                         "a public API") % name)
                elif re.search(r"};", line):
                    ingrp = None


# Finally, we read all the primary driver files and extract
# the driver API tables from each one.

for src in srcs:
    with open(src) as fh:
        groupsre = "|".join(groups.keys())

        ingrp = None
        impl = None
        for line in fh:
            if ingrp is None:
                m = re.search(r"^\s*(static\s+)?(" +
                              groupsre +
                              r")\s+(\w+)\s*=\s*{", line)
                if m is None:
                    m = re.search(r"^\s*(static\s+)?(" +
                                  groupsre +
                                  r")\s+NAME\(\w+\)\s*=\s*{", line)
                if m is not None:
                    ingrp = m.group(2)
                    impl = src

                    implmatch = re.search(r".*/node_device_(\w+)\.c", impl)
                    if implmatch is None:
                        implmatch = re.search(r".*/(\w+?)_((\w+)_)?(\w+)\.c", impl)
                    if implmatch is None:
                        raise Exception("Unexpected impl format '%s'" % impl)
                    impl = implmatch.group(1)

                    if impl in groups[ingrp]["drivers"]:
                        raise Exception(
                            "Group %s already contains %s" % (ingrp, impl))

                    groups[ingrp]["drivers"][impl] = {}

                    if impl not in groups["commonapis"]["drivers"]:
                        groups["commonapis"]["drivers"][impl] = {}
            else:
                callbackmatch = re.search(r"\s*\.(\w+)\s*=\s*(\w+)\s*,?\s*" +
                                          r"(?:/\*\s*(\d+\.\d+\.\d+)\s*" +
                                          r"(?:-\s*(\d+\.\d+\.\d+))?\s*\*/\s*)?$",
                                          line)
                if callbackmatch is not None:
                    api = callbackmatch.group(1)
                    meth = callbackmatch.group(2)
                    vers = callbackmatch.group(3)
                    deleted = callbackmatch.group(4)

                    if api == "no" or api == "name":
                        continue

                    if meth == "NULL" and deleted is None:
                        raise Exception(
                            ("Method impl for %s is NULL, but " +
                             "no deleted version is provided") % api)

                    if meth != "NULL" and deleted is not None:
                        raise Exception(
                            ("Method impl for %s is non-NULL, but " +
                             "deleted version is provided") % api)

                    if vers is None and api != "connectURIProbe":
                        raise Exception(
                            "Method %s in %s is missing version" %
                            (meth, src))

                    if api in groups["commonapis"]["apis"]:
                        groups["commonapis"]["drivers"][impl][api] = {
                            "vers": vers,
                            "deleted": deleted,
                        }
                    elif api in groups[ingrp]["apis"]:
                        groups[ingrp]["drivers"][impl][api] = {
                            "vers": vers,
                            "deleted": deleted,
                        }
                    else:
                        if re.search(r"\w+(Open|Close|URIProbe)", api):
                            continue

                        raise Exception("Found unexpected method " +
                                        "%s in %s" % (api, ingrp))

                    if (api == "domainMigratePrepare" or
                            api == "domainMigratePrepare2" or
                            api == "domainMigratePrepare3"):
                        if ("domainMigrate" not in
                                groups[ingrp]["drivers"][impl]):
                            groups[ingrp]["drivers"][impl]["domainMigrate"] = {
                                "vers": vers,
                            }
                elif line.find("}") != -1:
                    ingrp = None


# The '.open' driver method is used for 3 public APIs, so we
# have a bit of manual fixup todo with the per-driver versioning
# and support matrix

groups["commonapis"]["apis"]["connectOpenAuth"] = \
    "virConnectOpenAuth"
groups["commonapis"]["apis"]["connectOpenReadOnly"] = \
    "virConnectOpenReadOnly"
groups["virHypervisorDriver"]["apis"]["domainMigrate"] = \
    "virDomainMigrate"

openAuthVers = (0 * 1000 * 1000) + (4 * 1000) + 0

drivers = groups["commonapis"]["drivers"]
for drv in drivers.keys():
    openVersStr = drivers[drv]["connectOpen"]["vers"]
    openVers = 0
    if openVersStr != "Y":
        openVersBits = openVersStr.split(".")
        if len(openVersBits) != 3:
            raise Exception("Expected 3 digit version for %s" % openVersStr)
        openVers = ((int(openVersBits[0]) * 1000 * 1000) +
                    (int(openVersBits[1]) * 1000) +
                    int(openVersBits[2]))

    # virConnectOpenReadOnly always matches virConnectOpen version
    drivers[drv]["connectOpenReadOnly"] = \
        drivers[drv]["connectOpen"]

    # virConnectOpenAuth is always 0.4.0 if the driver existed
    # before this time, otherwise it matches the version of
    # the driver's virConnectOpen entry
    if openVersStr == "Y" or openVers >= openAuthVers:
        vers = openVersStr
    else:
        vers = "0.4.0"
    drivers[drv]["connectOpenAuth"] = {
        "vers": vers,
    }

drivers = groups["virHypervisorDriver"]["drivers"]
# Another special case for the virDomainCreateLinux which was replaced
# with virDomainCreateXML
groups["virHypervisorDriver"]["apis"]["domainCreateLinux"] = \
    "virDomainCreateLinux"

createAPIVers = (0 * 1000 * 1000) + (0 * 1000) + 3

for drv in list(drivers.keys()):
    # drop drivers from the "virHypervisorDriver" group which have only common APIs
    if len(drivers[drv]) == 0:
        drivers.pop(drv)
        continue

    if "domainCreateXML" not in drivers[drv]:
        continue
    createVersStr = drivers[drv]["domainCreateXML"]["vers"]
    createVers = 0
    if createVersStr != "Y":
        createVersBits = createVersStr.split(".")
        if len(createVersBits) != 3:
            raise Exception("Expected 3 digit version for %s" % createVersStr)
        createVers = ((int(createVersBits[0]) * 1000 * 1000) +
                      (int(createVersBits[1]) * 1000) +
                      int(createVersBits[2]))

    # virCreateLinux is always 0.0.3 if the driver existed
    # before this time, otherwise it matches the version of
    # the driver's virCreateXML entry
    if createVersStr == "Y" or createVers >= createAPIVers:
        vers = createVersStr
    else:
        vers = "0.0.3"

    drivers[drv]["domainCreateLinux"] = {
        "vers": vers,
    }

# Finally we generate the HTML file with the tables

print('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<body>
<div id="hvsupport" class="document">
<h1>libvirt API support matrix</h1>

<nav class="contents" id="contents">
<ul>
''')

for grp in sorted(groups.keys()):
    print("<li><p><a href=\"#%s\">%s</a></p></li>" % (grp, groupheaders[grp]))

print('''</ul>
</nav>

<p>
This page documents which libvirt calls work on
which libvirt drivers / hypervisors, and which version the API appeared
in. If a hypervisor driver later dropped support for the API, the version
when it was removed is also mentioned (highlighted in
<span class="removedhv">dark red</span>).
</p>
''')

for grp in sorted(groups.keys()):
    print("<h2><a id=\"%s\">%s</a></h2>" % (grp, groupheaders[grp]))
    print('''<table class="top_table">
<thead>
<tr>
<th>API</th>
<th>Version</th>''')

    for drv in sorted(groups[grp]["drivers"].keys()):
        print("  <th>%s</th>" % drv)

    print('''</tr>
</thead>
<tbody>''')

    row = 0

    def sortkey(field):
        return groups[grp]["apis"][field]

    for field in sorted(groups[grp]["apis"].keys(), key=sortkey):
        api = groups[grp]["apis"][field]
        vers = apis[api]["vers"]
        htmlgrp = apis[api].get("file")
        print("<tr>")

        if htmlgrp is not None:
            print(('''<td>\n<a href=\"html/libvirt-%s.html#%s\">''' +
                   '''%s</a>\n</td>''') %
                  (htmlgrp, api, api))
        else:
            print("<td>\n%s</td>" % api)

        print("<td>%s</td>" % vers)

        for drv in sorted(groups[grp]["drivers"].keys()):
            info = ""
            if field in groups[grp]["drivers"][drv]:
                vers = groups[grp]["drivers"][drv][field]["vers"]
                if vers is not None:
                    info = info + vers

                deleted = groups[grp]["drivers"][drv][field].get("deleted")
                if deleted is not None:
                    info = info + (''' - <span class="removedhv">''' +
                                   '''%s</span>''' % deleted)

            print("<td>%s</td>" % info)

        print("</tr>")

        row = row + 1
        if (row % 15) == 0:
            print('''<tr>
<th>API</th>
<th>Version</th>''')

            for drv in sorted(groups[grp]["drivers"].keys()):
                print("  <th>%s</th>" % drv)

            print("</tr>")

    print("</tbody>\n</table>")

print("</div>\n</body>\n</html>")
