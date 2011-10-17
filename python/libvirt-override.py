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
    """Register a Python function for error reporting.
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
def _eventInvokeHandleCallback(watch, fd, event, opaque, opaquecompat=None):
    """
    Invoke the Event Impl Handle Callback in C
    """
    # libvirt 0.9.2 and earlier required custom event loops to know
    # that opaque=(cb, original_opaque) and pass the values individually
    # to this wrapper. This should handle the back compat case, and make
    # future invocations match the virEventHandleCallback prototype
    if opaquecompat:
        callback = opaque
        opaque = opaquecompat
    else:
        callback = opaque[0]
        opaque = opaque[1]

    libvirtmod.virEventInvokeHandleCallback(watch, fd, event, callback, opaque);

#
# Invoke an EventTimeout callback
#
def _eventInvokeTimeoutCallback(timer, opaque, opaquecompat=None):
    """
    Invoke the Event Impl Timeout Callback in C
    """
    # libvirt 0.9.2 and earlier required custom event loops to know
    # that opaque=(cb, original_opaque) and pass the values individually
    # to this wrapper. This should handle the back compat case, and make
    # future invocations match the virEventTimeoutCallback prototype
    if opaquecompat:
        callback = opaque
        opaque = opaquecompat
    else:
        callback = opaque[0]
        opaque = opaque[1]

    libvirtmod.virEventInvokeTimeoutCallback(timer, callback, opaque);

def _dispatchEventHandleCallback(watch, fd, events, cbData):
    cb = cbData["cb"]
    opaque = cbData["opaque"]

    cb(watch, fd, events, opaque)
    return 0

def _dispatchEventTimeoutCallback(timer, cbData):
    cb = cbData["cb"]
    opaque = cbData["opaque"]

    cb(timer, opaque)
    return 0

def virEventAddHandle(fd, events, cb, opaque):
    """
    register a callback for monitoring file handle events

    @fd: file handle to monitor for events
    @events: bitset of events to watch from virEventHandleType constants
    @cb: callback to invoke when an event occurs
    @opaque: user data to pass to callback

    Example callback prototype is:
        def cb(watch,   # int id of the handle
               fd,      # int file descriptor the event occurred on
               events,  # int bitmap of events that have occurred
               opaque): # opaque data passed to eventAddHandle
    """
    cbData = {"cb" : cb, "opaque" : opaque}
    ret = libvirtmod.virEventAddHandle(fd, events, cbData)
    if ret == -1: raise libvirtError ('virEventAddHandle() failed')
    return ret

def virEventAddTimeout(timeout, cb, opaque):
    """
    register a callback for a timer event

    @timeout: time between events in milliseconds
    @cb: callback to invoke when an event occurs
    @opaque: user data to pass to callback

    Setting timeout to -1 will disable the timer. Setting the timeout
    to zero will cause it to fire on every event loop iteration.

    Example callback prototype is:
        def cb(timer,   # int id of the timer
               opaque): # opaque data passed to eventAddTimeout
    """
    cbData = {"cb" : cb, "opaque" : opaque}
    ret = libvirtmod.virEventAddTimeout(timeout, cbData)
    if ret == -1: raise libvirtError ('virEventAddTimeout() failed')
    return ret
