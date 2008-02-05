#!/usr/bin/python -u
import libvirt
import sys
import os

if not os.access("/proc/xen", os.R_OK):
    print 'System is not running a Xen kernel'
    sys.exit(1)

conn = libvirt.openReadOnly(None)
if conn == None:
    print 'Failed to open connection to the hypervisor'
    sys.exit(1)

ids = conn.listDomainsID()
if ids == None or len(ids) == 0:
    print 'Failed to list running domains'
    sys.exit(1)

id = ids[-1]

try:
    dom = conn.lookupByID(id)
except:
    print 'Failed to find the domain %d'
    sys.exit(1)

name0 = dom.name()
uuid = dom.UUID()
print "Using domain %s" % (name0)
try:
    dom2 = conn.lookupByUUID(uuid)
except:
    print 'Failed to lookup domain %d based on its UUID'
    sys.exit(1)
if dom2.name() != name0:
    print 'lookup of %s based on UUID brings a different domain %s' % (
           name0, dom2.name())

print "OK"
sys.exit(0)
