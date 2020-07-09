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

drvfiles = []
symfiles = []
for arg in sys.argv:
    if arg.endswith(".h"):
        drvfiles.append(arg)
    else:
        symfiles.append(arg)

symbols = {}

for symfile in symfiles:
    with open(symfile, "r") as fh:
        for line in fh:
            m = re.search(r'''^\s*(vir\w+)\s*;\s*$''', line)
            if m is not None:
                symbols[m.group(1)] = True

status = 0
for drvfile in drvfiles:
    with open(drvfile, "r") as fh:
        for line in fh:
            m = re.search(r'''\*(virDrv\w+)\s*\)''', line)
            if m is not None:
                drv = m.group(1)

                skip = [
                    "virDrvStateInitialize",
                    "virDrvStateCleanup",
                    "virDrvStateReload",
                    "virDrvStateStop",
                    "virDrvStateShutdownPrepare",
                    "virDrvStateShutdownWait",
                    "virDrvConnectSupportsFeature",
                    "virDrvConnectURIProbe",
                    "virDrvDomainMigratePrepare",
                    "virDrvDomainMigratePrepare2",
                    "virDrvDomainMigratePrepare3",
                    "virDrvDomainMigratePrepare3Params",
                    "virDrvDomainMigratePrepareTunnel",
                    "virDrvDomainMigratePrepareTunnelParams",
                    "virDrvDomainMigratePrepareTunnel3",
                    "virDrvDomainMigratePrepareTunnel3Params",
                    "virDrvDomainMigratePerform",
                    "virDrvDomainMigratePerform3",
                    "virDrvDomainMigratePerform3Params",
                    "virDrvDomainMigrateConfirm",
                    "virDrvDomainMigrateConfirm3",
                    "virDrvDomainMigrateConfirm3Params",
                    "virDrvDomainMigrateBegin",
                    "virDrvDomainMigrateBegin3",
                    "virDrvDomainMigrateBegin3Params",
                    "virDrvDomainMigrateFinish",
                    "virDrvDomainMigrateFinish2",
                    "virDrvDomainMigrateFinish3",
                    "virDrvDomainMigrateFinish3Params",
                    "virDrvStreamInData",
                ]
                if drv in skip:
                    continue

                sym = drv.replace("virDrv", "vir")

                if sym not in symbols:
                    print("Driver method name %s doesn't match public API" %
                          drv)
                    status = 1
                continue

            m = re.search(r'''(\*vir\w+)\s*\)''', line)
            if m is not None:
                name = m.group(1)
                print("Bogus name %s" % name)
                status = 1
                continue

            m = re.search(r'''^\s*(virDrv\w+)\s+(\w+);\s*''', line)
            if m is not None:
                drv = m.group(1)
                field = m.group(2)

                tmp = drv.replace("virDrv", "")
                if tmp.startswith("NWFilter"):
                    tmp = "nwfilter" + tmp[8:]
                tmp = tmp[0:1].lower() + tmp[1:]

                if tmp != field:
                    print("Driver struct field %s should be named %s" %
                          (field, tmp))
                    status = 1

sys.exit(status)
