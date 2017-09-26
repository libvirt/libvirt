#!/usr/bin/env python2

import sys
import json

dec = json.JSONDecoder()
data, pos = dec.raw_decode(sys.stdin.read())
json.dump(data, sys.stdout, indent = 2, separators = (',', ': '))
print
