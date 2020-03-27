#!/usr/bin/env python3

# require-dco.py: validate all commits are signed off
#
# Copyright (C) 2020 Red Hat, Inc.
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

import os
import os.path
import sys
import subprocess

cwd = os.getcwd()
reponame = os.path.basename(cwd)
repourl = "https://gitlab.com/libvirt/%s.git" % reponame

subprocess.check_call(["git", "remote", "add", "dcocheck", repourl])
subprocess.check_call(["git", "fetch", "dcocheck", "master"],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL)

ancestor = subprocess.check_output(["git", "merge-base", "dcocheck/master", "HEAD"],
                                   universal_newlines=True)

ancestor = ancestor.strip()

subprocess.check_call(["git", "remote", "rm", "dcocheck"])

errors = False

print("\nChecking for 'Signed-off-by: NAME <EMAIL>' on all commits since %s...\n" % ancestor)

log = subprocess.check_output(["git", "log", "--format=%H %s", ancestor + "..."],
                              universal_newlines=True)

if log == "":
    commits = []
else:
    commits = [[c[0:40], c[41:]] for c in log.strip().split("\n")]

for sha, subject in commits:

    msg = subprocess.check_output(["git", "show", "-s", sha],
                                  universal_newlines=True)
    lines = msg.strip().split("\n")

    print("🔍 %s %s" % (sha, subject))
    sob = False
    for line in lines:
        if "Signed-off-by:" in line:
            sob = True
            if "localhost" in line:
                print("    ❌ FAIL: bad email in %s" % line)
                errors = True

    if not sob:
        print("    ❌ FAIL missing Signed-off-by tag")
        errors = True

if errors:
    print("""

❌ ERROR: One or more commits are missing a valid Signed-off-By tag.


This project requires all contributors to assert that their contributions
are provided in compliance with the terms of the Developer's Certificate
of Origin 1.1 (DCO):

  https://developercertificate.org/

To indicate acceptance of the DCO every commit must have a tag

  Signed-off-by: REAL NAME <EMAIL>

This can be achieved by passing the "-s" flag to the "git commit" command.

To bulk update all commits on current branch "git rebase" can be used:

  git rebase -i master -x 'git commit --amend --no-edit -s'

""")

    sys.exit(1)

sys.exit(0)
