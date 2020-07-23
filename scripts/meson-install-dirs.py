#!/usr/bin/env python3

import os
import sys

destdir = os.environ.get('DESTDIR', os.sep)

for dirname in sys.argv[1:]:
    os.makedirs(os.path.join(destdir, dirname.strip(os.sep)), exist_ok=True)
