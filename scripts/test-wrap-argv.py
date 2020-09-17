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
# This script is intended to be passed a list of .args files, used
# to store command line ARGV for the test suites. It will reformat
# them such that there is at most one '-param value' on each line
# of the file. Parameter values that are longer than 80 chars will
# also be split.
#
# If --in-place is supplied as the first parameter of this script,
# the files will be changed in place.
# If --check is the first parameter, the script will return
# a non-zero value if a file is not wrapped correctly.
# Otherwise the rewrapped files are printed to the standard output.

import argparse
import subprocess
import sys


def rewrap_line(line):
    bits = line.split(" ")

    # bits contains env vars, then the command line
    # and then the arguments
    env = []
    cmd = None
    args = []

    if "=" not in bits[0]:
        cmd = bits[0]
        bits = bits[1:]

    for bit in bits:
        # If no command is defined yet, we must still
        # have env vars
        if cmd is None:
            # Look for leading / to indicate command name
            if bit.startswith("/"):
                cmd = bit
            else:
                env.append(bit)
        else:
            # If there's a leading '-' then this is a new
            # parameter, otherwise its a value for the prev
            # parameter.
            if bit.startswith("-") or len(args) == 0:
                args.append(bit)
            else:
                args[-1] = args[-1] + " " + bit

    # We might have to split line argument values...
    args = [rewrap_arg(arg) for arg in args]

    # Print env + command first
    return " \\\n".join(env + [cmd] + args) + "\n"


def rewrap_arg(arg):
    ret = []
    max_len = 78

    while len(arg) > max_len:
        split = arg.rfind(",", 0, max_len + 1)
        if split == -1:
            split = arg.rfind(":", 0, max_len + 1)
        if split == -1:
            split = arg.rfind(" ", 0, max_len + 1)
        if split == -1:
            print("cannot find nice place to split '%s' below 80 chars" %
                  arg, file=sys.stderr)
            split = max_len - 1

        split = split + 1

        ret.append(arg[0:split])
        arg = arg[split:]

    ret.append(arg)
    return "\\\n".join(ret)


def rewrap(filename, in_place, check):
    # Read the original file
    with open(filename, 'r') as fh:
        orig_lines = []
        for line in fh:
            orig_lines.append(line)

    if len(orig_lines) == 0:
        return

    lines = []
    for line in orig_lines:
        if line.endswith("\\\n"):
            line = line[:-2]
        lines.append(line)

    # Kill the last new line in the file
    lines[-1] = lines[-1].rstrip("\n")

    # Reconstruct the master data by joining all lines
    # and then split again based on the real desired
    # newlines
    lines = "".join(lines).split("\n")

    # Now each 'lines' entry represents a single command, we
    # can process them
    new_lines = []
    for line in lines:
        new_lines.append(rewrap_line(line))

    if in_place:
        with open(filename, "w") as fh:
            for line in new_lines:
                print(line, file=fh, end='')
    elif check:
        orig = "".join(orig_lines)
        new = "".join(new_lines)
        if new != orig:
            diff = subprocess.Popen(["diff", "-u", filename, "-"],
                                    stdin=subprocess.PIPE)
            diff.communicate(input=new.encode('utf-8'))

            print("Incorrect line wrapping in $file",
                  file=sys.stderr)
            print("Use test-wrap-argv.py to wrap test data files",
                  file=sys.stderr)
            return False
    else:
        for line in new_lines:
            print(line, end='')

    return True


parser = argparse.ArgumentParser(description='Test arg line wrapper')
parser.add_argument('--in-place', '-i', action="store_true",
                    help='modify files in-place')
parser.add_argument('--check', action="store_true",
                    help='check existing files only')
parser.add_argument('files', nargs="+",
                    help="filenames to check")
args = parser.parse_args()

errs = False
for filename in args.files:
    if not rewrap(filename, args.in_place, args.check):
        errs = True

if errs:
    sys.exit(1)
sys.exit(0)
