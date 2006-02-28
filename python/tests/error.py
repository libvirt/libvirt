#!/usr/bin/python -u
#
# Tests global error handlers at the python level.
#
import libvirt
import sys
import os

errno = None

def handler(ctxt, err):
    global errno

    #print "handler(%s, %s)" % (ctxt, err)
    errno = err

libvirt.registerErrorHandler(handler, 'context')

conn = libvirt.openReadOnly(None)
if conn == None:
    print 'Failed to open connection to the hypervisor'
    sys.exit(1)

try:
    dom0 = conn.lookupByName("Does_not_exist")
    print 'strange found a Does_not_exist domain'
    sys.exit(1)
except:
    pass

del conn

if errno == None:
    print 'failed to get an error'
elif errno[0] == libvirt.VIR_ERR_NO_CONNECT or \
     errno[0] == libvirt.VIR_ERR_INVALID_DOMAIN or \
     errno[0] == libvirt.VIR_ERR_GET_FAILED:
    print "OK"
else:
    print 'got unexpected error:', errno

sys.exit(0)
