#!/usr/bin/env python

# reformat-news.py: Reformat the NEWS file properly
#
# Copyright (C) 2017 Red Hat, Inc.
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
# Authors:
#     Andrea Bolognani <abologna@redhat.com>

import sys

COLUMNS = 80

def reformat_with_indent(text, initial_indent, indent):

    res = ""
    line = initial_indent

    for word in text.split():

        # If adding one more word (plus a whitespace, plus a newline)
        # to the current line would push us over the desired number
        # of columns we start a new line instead
        if len(line) + len(word) > (COLUMNS - 2):
            res = res + line + "\n"
            line = indent

        # We need to take care when we've just started a  new line,
        # as we don't want to add any additional leading whitespace
        # in that case
        if line == indent or line == initial_indent:
            line = line + word
        else:
            line = line + " " + word

    # Append whatever's left
    res = res + line

    return res


def reformat(line):

    # Empty lines don't need to be reformatted or even inspected
    if len(line) == 0:
        return line

    # For all non-empty lines, we decide the indentation level based
    # on the first character
    marker = line[0]

    # Release
    if marker == '#':
        initial_indent = 0
        indent = 2
    # Section
    elif marker == '*':
        initial_indent = 2
        indent = 4
    # Change summary
    elif marker == '-':
        initial_indent = 4
        indent = 6
    # Change description
    elif marker == '|':
        initial_indent = 8
        indent = 8
        # In this one case, the marker should not ultimately show
        # up in the output file, so we strip it before moving on
        line = line[1:]
    # Anything else should be left as-is
    else:
        return line

    return reformat_with_indent(line, " " * initial_indent, " " * indent)


def main(args):

    if len(args) < 2:
        sys.stdout.write("Usage: " + args[0] + " FILE\n")
        sys.exit(1)

    with open(args[1], 'r') as f:
        for line in f:
            print(reformat(line.strip()))


if __name__ == "__main__":
    main(sys.argv)
