=============================
Secret information management
=============================

The secrets driver in libvirt provides a simple interface for storing and
retrieving secret information.

Connections to SECRET driver
----------------------------

The libvirt SECRET driver is a multi-instance driver, providing a single system
wide privileged driver (the "system" instance), and per-user unprivileged
drivers (the "session" instance). A connection to the secret driver is
automatically available when opening a connection to one of the stateful primary
hypervisor drivers. It is none the less also possible to explicitly open just
the secret driver, using the URI protocol "secret" Some example connection URIs
for the driver are:

::

   secret:///session                      (local access to per-user instance)
   secret+unix:///session                 (local access to per-user instance)

   secret:///system                       (local access to system instance)
   secret+unix:///system                  (local access to system instance)
   secret://example.com/system            (remote access, TLS/x509)
   secret+tcp://example.com/system        (remote access, SASl/Kerberos)
   secret+ssh://root@example.com/system   (remote access, SSH tunnelled)

Embedded driver
~~~~~~~~~~~~~~~

Since 6.1.0 the secret driver has experimental support for operating in an
embedded mode. In this scenario, rather than connecting to the libvirtd daemon,
the secret driver runs in the client application process directly. To open the
driver in embedded mode the app use the new URI path and specify a virtual root
directory under which the driver will create content.

::

         secret:///embed?root=/some/dir

Under the specified root directory the following locations will be used

::

   /some/dir
     |
     +- etc
     |   |
     |   +- secrets
     |
     +- run
         |
         +- secrets

The application is responsible for recursively purging the contents of this
directory tree once they no longer require a connection, though it can also be
left intact for reuse when opening a future connection.

The range of functionality is intended to be on a par with that seen when using
the traditional system or session libvirt connections to QEMU. Normal practice
would be to open the secret driver in embedded mode any time one of the other
drivers is opened in embedded mode so that the two drivers can interact
in-process.
