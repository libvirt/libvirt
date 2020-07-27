#!/usr/bin/env python3

import sys

if len(sys.argv) < 5:
    print('invalid arguments')
    print('usage: {0} OUTPUT VERSION PUBLIC PRIVATE ...')
    sys.exit(1)

outfilepath = sys.argv[1]
version = sys.argv[2]
public = sys.argv[3]
private = sys.argv[4:]

with open(outfilepath, 'w') as out:
    out.write('# WARNING: generated from the following files:\n\n')

    with open(public) as tmp:
        out.write(tmp.read())

    out.write('\n\n# Private symbols\n\n')
    out.write('{0} {{\n\n'.format(version))
    out.write('global:\n\n')

    for priv in private:
        with open(priv) as tmp:
            out.write(tmp.read())

    out.write('\n\nlocal:\n*;\n\n};')
