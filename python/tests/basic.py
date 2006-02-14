#!/usr/bin/python -u
import libvirt
import sys

conn = libvirt.openReadOnly(None)
if conn == None:
    print 'Failed to open connection to the hypervisor'
    sys.exit(1)

# print conn

dom0 = conn.lookupByName("Domain-0")
if dom0 == None:
    print 'Failed to find the main domain'
    sys.exit(1)

# print dom0

print "Domain 0: id %d running %s" % (dom0.ID(), dom0.OSType())
print dom0.info()
del dom0
del conn
print "OK"

sys.exit(0)
