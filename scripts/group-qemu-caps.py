#!/usr/bin/env python3
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
#
# Regroup array values into smaller groups separated by numbered comments.
#
# If --check is the first parameter, the script will return
# a non-zero value if a file is not grouped correctly.
# Otherwise the files are regrouped in place.

import argparse
import re
import subprocess
import sys


def load_caps_flags(filename, start_regex, end_regex):
    capsflags = []
    game_on = False

    with open(filename, "r") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if game_on:
                if re.search(r'''.*/\* [0-9]+ \*/.*''', line):
                    continue
                if re.search(r'''^\s*$''', line):
                    continue
                match = re.search(r'''[ ]+([A-Z0-9_]+)''', line)

                if match:
                    capsflags.append(match[1])

            if re.search(start_regex, line):
                game_on = True
            elif game_on and re.search(end_regex, line):
                game_on = False

    return capsflags


def regroup_caps(check, filename, start_regex, end_regex,
                 trailing_newline, counter_prefix, capsflags):
    step = 5

    original = []
    with open(filename, "r") as fh:
        for line in fh:
            original.append(line)

    fixed = []
    game_on = False
    counter = 0
    for line in original:
        line = line.rstrip("\n")
        if game_on:
            if re.search(r'''.*/\* [0-9]+ \*/.*''', line):
                continue
            if re.search(r'''^\s*$''', line):
                continue
            if counter % step == 0:
                if counter != 0:
                    fixed.append("\n")
                fixed.append("%s/* %d */\n" % (counter_prefix, counter))

            if not (line.find("/*") != -1 and line.find("*/") == -1):
                # count two-line comments as one line
                counter = counter + 1

        if re.search(start_regex, line):
            game_on = True
        elif game_on and re.search(end_regex, line):
            if (counter - 1) % step == 0:
                fixed = fixed[:-1]  # /* $counter */
                if counter != 1:
                    fixed = fixed[:-1]  # \n

            if trailing_newline:
                fixed.append("\n")

            game_on = False

        # ensure that flag names in the .c file have the correct flag in the comment
        if game_on and capsflags:
            flagname = re.search(r'''.*".*",''', line)
            if flagname:
                line = flagname[0] + " /* %s */" % capsflags[counter - 1]

        fixed.append(line + "\n")

    if check:
        orig = "".join(original)
        new = "".join(fixed)
        if new != orig:
            diff = subprocess.Popen(["diff", "-u", filename, "-"],
                                    stdin=subprocess.PIPE)
            diff.communicate(input=new.encode('utf-8'))

            print("Incorrect line wrapping in '%s'" %
                  filename, file=sys.stderr)
            print("Use group-qemu-caps.py to generate data files",
                  file=sys.stderr)
            return False
    else:
        with open(filename, "w") as fh:
            for line in fixed:
                print(line, file=fh, end='')

    return True


parser = argparse.ArgumentParser(description='QEMU capabilities group formatter')
parser.add_argument('--check', action="store_true",
                    help='check existing files only')
parser.add_argument('--prefix', default='',
                    help='source code tree prefix')
args = parser.parse_args()

errs = False

capsflags = load_caps_flags(args.prefix + 'src/qemu/qemu_capabilities.h',
                            r'virQEMUCapsFlags grouping marker',
                            r'QEMU_CAPS_LAST \/\* this must')

if not regroup_caps(args.check,
                    args.prefix + 'src/qemu/qemu_capabilities.c',
                    r'virQEMUCaps grouping marker',
                    r'\);',
                    0,
                    "              ",
                    capsflags):
    errs = True

if not regroup_caps(args.check,
                    args.prefix + 'src/qemu/qemu_capabilities.h',
                    r'virQEMUCapsFlags grouping marker',
                    r'QEMU_CAPS_LAST \/\* this must',
                    1,
                    "    ",
                    None):
    errs = True

if errs:
    sys.exit(1)
sys.exit(0)
