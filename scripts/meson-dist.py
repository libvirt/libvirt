#!/usr/bin/env python3

import os
import shutil
import sys

meson_build_root = sys.argv[1]
file_name = sys.argv[2]

meson_dist_root = os.environ['MESON_DIST_ROOT']

shutil.copy(os.path.join(meson_build_root, file_name),
            os.path.join(meson_dist_root, file_name))
