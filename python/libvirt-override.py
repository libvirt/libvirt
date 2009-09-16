#
# Manually written part of python bindings for libvirt
#

# On cygwin, the DLL is called cygvirtmod.dll
try:
    import libvirtmod
except ImportError, lib_e:
    try:
        import cygvirtmod as libvirtmod
    except ImportError, cyg_e:
        if str(cyg_e).count("No module named"):
            raise lib_e

import types

# The root of all libvirt errors.
class libvirtError(Exception):
    def __init__(self, defmsg, conn=None, dom=None, net=None, pool=None, vol=None):

        if dom is not None:
            conn = dom._conn
        elif net is not None:
            conn = net._conn
        elif pool is not None:
            conn = pool._conn
        elif vol is not None:
            conn = vol._conn

        # Never call virConnGetLastError().
        # virGetLastError() is now thread local
        err = virGetLastError()
        if err is None:
            msg = defmsg
        else:
            msg = err[2]

        Exception.__init__(self, msg)

        self.err = err

    def get_error_code(self):
        if self.err is None:
            return None
        return self.err[0]

    def get_error_domain(self):
        if self.err is None:
            return None
        return self.err[1]

    def get_error_message(self):
        if self.err is None:
            return None
        return self.err[2]

    def get_error_level(self):
        if self.err is None:
            return None
        return self.err[3]

    def get_str1(self):
        if self.err is None:
            return None
        return self.err[4]

    def get_str2(self):
        if self.err is None:
            return None
        return self.err[5]

    def get_str3(self):
        if self.err is None:
            return None
        return self.err[6]

    def get_int1(self):
        if self.err is None:
            return None
        return self.err[7]

    def get_int2(self):
        if self.err is None:
            return None
        return self.err[8]

#
# register the libvirt global error handler
#
def registerErrorHandler(f, ctx):
    """Register a Python written function to for error reporting.
       The function is called back as f(ctx, error), with error
       being a list of information about the error being raised.
       Returns 1 in case of success."""
    return libvirtmod.virRegisterErrorHandler(f,ctx)

def openAuth(uri, auth, flags):
    ret = libvirtmod.virConnectOpenAuth(uri, auth, flags)
    if ret is None:raise libvirtError('virConnectOpenAuth() failed')
    return virConnect(_obj=ret)


#
# Return library version.
#
def getVersion (name = None):
    """If no name parameter is passed (or name is None) then the
    version of the libvirt library is returned as an integer.

    If a name is passed and it refers to a driver linked to the
    libvirt library, then this returns a tuple of (library version,
    driver version).

    If the name passed refers to a non-existent driver, then you
    will get the exception 'no support for hypervisor'.

    Versions numbers are integers: 1000000*major + 1000*minor + release."""
    if name is None:
        ret = libvirtmod.virGetVersion ();
    else:
        ret = libvirtmod.virGetVersion (name);
    if ret is None: raise libvirtError ("virGetVersion() failed")
    return ret


#
# Invoke an EventHandle callback
#
def eventInvokeHandleCallback (watch, fd, event, callback, opaque):
    """
    Invoke the Event Impl Handle Callback in C
    """
    libvirtmod.virEventInvokeHandleCallback(watch, fd, event, callback, opaque);

#
# Invoke an EventTimeout callback
#
def eventInvokeTimeoutCallback (timer, callback, opaque):
    """
    Invoke the Event Impl Timeout Callback in C
    """
    libvirtmod.virEventInvokeTimeoutCallback(timer, callback, opaque);
