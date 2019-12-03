#!/usr/bin/env python3
#
# Copyright (C) 2012-2019 Red Hat, Inc.
#
# augeas-gentest.py: Generate an augeas test file, from an
#                    example config file + test file template
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

import re
import sys

if len(sys.argv) != 3:
    print("syntax: %s CONFIG TEMPLATE" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

config = sys.argv[1]
template = sys.argv[2]


def expand_config(config):
    with open(config) as fh:
        group = False
        for line in fh:
            if re.search(r'''^#\w''', line) is not None:
                line = line[1:]
                line = line.replace('"', '\\"')
                print(line, end='')
                if re.search(r'''\[\s$''', line):
                    group = True
            elif group:
                line = line.replace('"', '\\"')

                if re.search(r'''#\s*\]''', line):
                    group = False

                if line[0] == '#':
                    line = line[1:]
                    print(line, end='')


def expand_template(template, config):
    with open(template) as fh:
        for line in fh:
            if '@CONFIG@' in line:
                print('   let conf = "', end='')
                expand_config(config)
                print('"')
            else:
                print(line, end='')


expand_template(template, config)
