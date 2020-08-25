#!/usr/bin/env python3

import os

meson_source_root = os.environ['MESON_SOURCE_ROOT']

os.chdir(meson_source_root)
os.system('git log --pretty=format:"* %aN <%aE>" | sort -u')
