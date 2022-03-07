==================
Handling of errors
==================

The main goals of libvirt when it comes to error handling are:

-  provide as much detail as possible
-  provide the information as soon as possible
-  dont force the library user into one style of error handling

As result the library provide both synchronous, callback based and asynchronous
error reporting. When an error happens in the library code the error is logged,
allowing to retrieve it later and if the user registered an error callback it
will be called synchronously. Once the call to libvirt ends the error can be
detected by the return value and the full information for the last logged error
can be retrieved.

To avoid as much as possible troubles with a global variable in a multithreaded
environment, libvirt will associate when possible the errors to the current
connection they are related to, that way the error is stored in a dynamic
structure which can be made thread specific. Error callback can be set
specifically to a connection with

So error handling in the code is the following:

#. if the error can be associated to a connection for example when failing to
   look up a domain

   #. if there is a callback associated to the connection set with
      `virConnSetErrorFunc <html/libvirt-virterror.html#virConnSetErrorFunc>`__,
      call it with the error information
   #. otherwise if there is a global callback set with
      `virSetErrorFunc <html/libvirt-virterror.html#virSetErrorFunc>`__, call it
      with the error information
   #. otherwise call
      `virDefaultErrorFunc <html/libvirt-virterror.html#virDefaultErrorFunc>`__
      which is the default error function of the library issuing the error on
      stderr
   #. save the error in the connection for later retrieval with
      `virConnGetLastError <html/libvirt-virterror.html#virConnGetLastError>`__

#. otherwise like when failing to create a hypervisor connection:

   #. if there is a global callback set with
      `virSetErrorFunc <html/libvirt-virterror.html#virSetErrorFunc>`__, call it
      with the error information
   #. otherwise call
      `virDefaultErrorFunc <html/libvirt-virterror.html#virDefaultErrorFunc>`__
      which is the default error function of the library issuing the error on
      stderr
   #. save the error in the connection for later retrieval with
      `virGetLastError <html/libvirt-virterror.html#virGetLastError>`__

In all cases the error information is provided as a
`virErrorPtr <html/libvirt-virterror.html#virErrorPtr>`__ pointer to read-only
structure `virError <html/libvirt-virterror.html#virError>`__ containing the
following fields:

-  code: an error number from the
   `virErrorNumber <html/libvirt-virterror.html#virErrorNumber>`__ enum
-  domain: an enum indicating which part of libvirt raised the error see
   `virErrorDomain <html/libvirt-virterror.html#virErrorDomain>`__
-  level: the error level, usually VIR_ERR_ERROR, though there is room for
   warnings like VIR_ERR_WARNING
-  message: the full human-readable formatted string of the error
-  conn: if available a pointer to the
   `virConnectPtr <html/libvirt-libvirt-host.html#virConnectPtr>`__ connection
   to the hypervisor where this happened
-  dom: if available a pointer to the
   `virDomainPtr <html/libvirt-libvirt-domain.html#virDomainPtr>`__ domain
   targeted in the operation

and then extra raw information about the error which may be initialized to 0 or
NULL if unused

-  str1, str2, str3: string information, usually str1 is the error message
   format
-  int1, int2: integer information

So usually, setting up specific error handling with libvirt consist of
registering a handler with
`virSetErrorFunc <html/libvirt-virterror.html#virSetErrorFunc>`__ or with
`virConnSetErrorFunc <html/libvirt-virterror.html#virConnSetErrorFunc>`__, check
the value of the code value, take appropriate action, if needed let libvirt
print the error on stderr by calling
`virDefaultErrorFunc <html/libvirt-virterror.html#virDefaultErrorFunc>`__. For
asynchronous error handing, set such a function doing nothing to avoid the error
being reported on stderr, and call virConnGetLastError or virGetLastError when
an API call returned an error value. It can be a good idea to use
`virResetError <html/libvirt-virterror.html#virResetLastError>`__ or
`virConnResetLastError <html/libvirt-virterror.html#virConnResetLastError>`__
once an error has been processed fully.

At the python level, there only a global reporting callback function at this
point, see the error.py example about it:

::

   def handler(ctxt, err):
       global errno

       #print "handler(%s, %s)" % (ctxt, err)
       errno = err

   libvirt.registerErrorHandler(handler, 'context')

the second argument to the registerErrorHandler function is passed as the first
argument of the callback like in the C version. The error is a tuple containing
the same field as a virError in C, but cast to Python.
