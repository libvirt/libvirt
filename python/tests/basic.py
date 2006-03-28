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

# print conn

try:
    dom0 = conn.lookupByName("Domain-0")
except:
    print 'Failed to find the main domain'
    sys.exit(1)

# print dom0

print "Domain 0: id %d running %s" % (dom0.ID(), dom0.OSType())
print dom0.info()
del dom0
del conn
print "OK"

sys.exit(0)
