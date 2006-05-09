#!/usr/bin/env python

#
# xmlrpcserver.py: simple server for XML-RPC tests
#
# Copyright (C) 2005 Red Hat, Inc.
#
# See COPYING.LIB for the License of this software
#
# Karel Zak <kzak@redhat.com>
#
# $Id$
#
#
# simple client:
#
# >>> import xmlrpclib
# >>> s=xmlrpclib.Server('http://localhost:8000')
# >>> s.plus(10,10)
# 20
#

import sys
from SimpleXMLRPCServer import SimpleXMLRPCServer

SERVER_PORT = 8000


class VirtRPCServer(SimpleXMLRPCServer):
    def _dispatch(self, method, params):
        try:
            func = getattr(self, 'test_' + method)
        except AttributeError:
            raise Exception('method "%s" is not supported' % method)
        else:
            return func(*params)

    def test_plus(self, x, y):
        return x + y


server = VirtRPCServer(("localhost", SERVER_PORT))
server.serve_forever()



# vim: set tabstop=4:
# vim: set shiftwidth=4:
# vim: set expandtab:
