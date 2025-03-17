#!/usr/bin/env python3

import os
import sys

destdir = os.environ.get('DESTDIR', os.sep)
dirname = sys.argv[1]
target = sys.argv[2]
link = sys.argv[3]

workdir = os.path.join(destdir, dirname.strip(os.sep))

os.makedirs(workdir, exist_ok=True)
os.chdir(workdir)

if os.path.exists(link):
    os.remove(link)

os.symlink(target, link)
