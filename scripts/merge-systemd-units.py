#!/usr/bin/env python3

# Copyright (C) 2023 Red Hat, Inc.
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys

SECTIONS = [
    "[Unit]",
    "[Service]",
    "[Socket]",
    "[Install]",
]


def parse_unit(unit_path):
    unit = {}
    current_section = "[Invalid]"

    with open(unit_path) as f:
        for line in f:
            line = line.strip()

            if line == "":
                continue

            if line[0] == "[" and line[-1] == "]":
                if line not in SECTIONS:
                    print("Unknown section {}".format(line))
                    sys.exit(1)

                current_section = line
                continue

            if current_section not in unit:
                unit[current_section] = []

            unit[current_section].append(line)

    if "[Invalid]" in unit:
        print("Contents found outside of any section")
        sys.exit(1)

    return unit


def format_unit(unit):
    lines = []

    for section in SECTIONS:
        if section not in unit:
            continue

        lines.append(section)

        for line in unit[section]:
            lines.append(line)

        lines.append("")

    return "\n".join(lines)


def merge_units(base, extra):
    merged = {}

    for section in SECTIONS:
        if section in extra and section not in base:
            print("Section {} in extra but not in base".format(section))
            sys.exit(1)

        if section not in base:
            continue

        merged[section] = base[section]

        if section not in extra:
            continue

        merged[section].extend(extra[section])

    return merged


if len(sys.argv) < 2:
    print("usage: {} BASE EXTRA".format(sys.argv[0]))
    sys.exit(1)

base = parse_unit(sys.argv[1])
extra = parse_unit(sys.argv[2])

merged = merge_units(base, extra)

sys.stdout.write(format_unit(merged))
