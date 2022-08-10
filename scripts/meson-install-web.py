#!/usr/bin/env python3

import os
import shutil
import sys

destdir = os.environ.get('DESTDIR', os.sep)

for desc in sys.argv[1:]:
    inst = desc.split(':')
    src = inst[0]
    dst = os.path.join(destdir, inst[1].strip(os.sep))
    os.makedirs(dst, exist_ok=True)
    shutil.copy(src, dst)
