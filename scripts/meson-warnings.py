#!/usr/bin/env python3

import sys

with open(sys.argv[1], "w") as out:
    for w in sys.argv[2:]:
        print(w, file=out)
