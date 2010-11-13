#!/usr/bin/env python
# domstart - make sure a given domU is running, if not start it

import libvirt
import sys
import os
import libxml2
import pdb

def usage():
   print 'Usage: %s DIR' % sys.argv[0]
   print '       Save all currently running domU\'s into DIR'
   print '       DIR must exist and be writable by this process'

if len(sys.argv) != 2:
    usage()
    sys.exit(2)

dir = sys.argv[1]

conn = libvirt.open(None)
if conn == None:
    print 'Failed to open connection to the hypervisor'
    sys.exit(1)

doms = conn.listDomainsID()
for id in doms:
    if id == 0:
        continue
    dom = conn.lookupByID(id)
    print "Saving %s[%d] ... " % (dom.name(), id),
    sys.stdout.flush()
    path = os.path.join(dir, dom.name())
    ret = dom.save(path)
    if ret == 0:
        print "done"
    else:
        print "error %d" % ret

#pdb.set_trace()
