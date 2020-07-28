#!/usr/bin/env python3
#
# Copyright (C) 2016-2019 Red Hat, Inc.
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
# This script is supposed to check test_file_access.txt file and
# warn about file accesses outside our working tree.
#
#

import os
import re
import sys
import tempfile

abs_builddir = os.environ.get('abs_builddir', '')
abs_srcdir = os.environ.get('abs_srcdir', '')

access_fd, access_file = tempfile.mkstemp(dir=abs_builddir,
                                          prefix='file-access-',
                                          suffix='.txt')
permitted_file = os.path.join(abs_srcdir, 'permitted_file_access.txt')

os.environ['VIR_TEST_FILE_ACCESS_OUTPUT'] = access_file

test = ' '.join(sys.argv[1:])

ret = os.system(test)

if ret != 0 or os.read(access_fd, 10) == b'':
    os.close(access_fd)
    os.remove(access_file)
    sys.exit(ret)

known_actions = ["open", "fopen", "access", "stat", "lstat", "connect"]

files = []
permitted = []

with os.fdopen(access_fd, "r") as fh:
    for line in fh:
        line = line.rstrip("\n")

        m = re.search(r'''^(\S*):\s*(\S*):\s*(\S*)(\s*:\s*(.*))?$''', line)
        if m is not None:
            rec = {
                "path": m.group(1),
                "action": m.group(2),
                "progname": m.group(3),
                "testname": m.group(5),
            }
            files.append(rec)
        else:
            raise Exception("Malformed line %s" % line)

with open(permitted_file, "r") as fh:
    for line in fh:
        line = line.rstrip("\n")

        if re.search(r'''^\s*#.*$''', line):
            continue  # comment
        if line == "":
            continue

        m = re.search(r'''^(\S*):\s*(\S*)(:\s*(\S*)(\s*:\s*(.*))?)?$''', line)
        if m is not None and m.group(2) in known_actions:
            # $path: $action: $progname: $testname
            rec = {
                "path": m.group(1),
                "action": m.group(3),
                "progname": m.group(4),
                "testname": m.group(6),
            }
            permitted.append(rec)
        else:
            m = re.search(r'''^(\S*)(:\s*(\S*)(\s*:\s*(.*))?)?$''', line)
            if m is not None:
                # $path: $progname: $testname
                rec = {
                    "path": m.group(1),
                    "action": None,
                    "progname": m.group(3),
                    "testname": m.group(5),
                }
                permitted.append(rec)
            else:
                raise Exception("Malformed line %s" % line)


# Now we should check if %traces is included in $permitted. For
# now checking just keys is sufficient
err = False
for file in files:
    match = False

    for rule in permitted:
        if not re.match("^" + rule["path"] + "$", file["path"]):
            continue

        if (rule["action"] is not None and
                not re.match("^" + rule["action"] + "$", file["action"])):
            continue

        if (rule["progname"] is not None and
                not re.match("^" + rule["progname"] + "$", file["progname"])):
            continue

        if (rule["testname"] is not None and
                file["testname"] is not None and
                not re.match("^" + rule["testname"] + "$", file["testname"])):
            continue

        match = True

    if not match:
        err = True
        print("%s: %s: %s" %
              (file["path"], file["action"], file["progname"]),
              end="")
        if file["testname"] is not None:
            print(": %s" % file["testname"], end="")
        print("")

os.remove(access_file)

if err:
    sys.exit(1)
sys.exit(0)
