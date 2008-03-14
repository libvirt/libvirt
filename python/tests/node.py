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

try:
    (model, memory, cpus, mhz, nodes, socket, cores, threads) = conn.getInfo()
except:
    print 'Failed to extract the current node information'
    sys.exit(1)

print "Xen running on %d %s processors at %d MHz, %d MBytes of memory" % (
       cpus, model, mhz, memory)

if cpus > nodes * socket * cores * threads:
    print "Erroneous CPU information"
    sys.exit(1)

if cpus < nodes * socket * cores * threads:
    print "Strange, running in degrated mode, some CPU are not available"

del conn
print "OK"

sys.exit(0)
