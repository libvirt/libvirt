#!/usr/bin/env python3

import re
import sys

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} POTFILE", file=sys.stderr)
    sys.exit(1)

potfile = sys.argv[1]

failed = 0


def print_msg(files, msgs):
    if len(msgs) == 0:
        return

    print("\n".join(files))

    for m in msgs:
        print(f"  {m}")

    global failed
    failed += 1


with open(potfile, "r") as pot:
    files = []
    msgs = []
    cFormat = False

    for line in pot:
        if not line or line.startswith("msgstr "):
            print_msg(files, msgs)
            files = []
            msgs = []
            cFormat = False
            continue

        if line.startswith("#: "):
            files.extend(line[3:].split())
            continue

        if line.startswith("#,"):
            cFormat = " c-format" in line
            continue

        m = re.search(r'^(msgid )?"(.*%[^%$ ]*[a-zA-Z].*)"', line)
        if cFormat and m is not None:
            msgs.append(m.group(2))

if failed:
    print(f"Found {failed} messages without permutable format strings!",
          file=sys.stderr)
    sys.exit(1)
