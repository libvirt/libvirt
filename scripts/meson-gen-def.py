#!/usr/bin/env python3

import re
import sys

if len(sys.argv) != 3:
    print('invalid arguments')
    print('usage: {0} INPUT OUTPUT'.format(sys.argv[0]))
    sys.exit(1)

infilepath = sys.argv[1]
outfilepath = sys.argv[2]

with open(infilepath) as f:
    text = f.read()

text = re.sub(r'^(|.*[#:}*].*|LIBVIRT_.*)\n?', '', text, flags=re.M)
text = re.sub(r'\n$', '', text)
text = re.sub(r'^[ ]*(.*);', r'    \1', text, flags=re.M)

with open(outfilepath, 'w') as f:
    f.write('EXPORTS\n')
    f.write(text)
