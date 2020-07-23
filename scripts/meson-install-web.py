#!/usr/bin/env python3

import os
import shutil
import sys

for desc in sys.argv[1:]:
    inst = desc.split(':')
    os.makedirs(inst[1], exist_ok=True)
    shutil.copy(inst[0], inst[1])
