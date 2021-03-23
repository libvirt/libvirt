==================
D-Bus API bindings
==================

.. contents::

Description
-----------

libvirt-dbus wraps libvirt API to provide a high-level object-oriented API
better suited for dbus-based applications.

GIT source repository
---------------------

The D-Bus bindings source code is maintained in a `git <https://git-scm.com/>`__
repository available on
`gitlab.com <https://gitlab.com/libvirt/libvirt-dbus>`__:

::

   git clone https://gitlab.com/libvirt/libvirt-dbus.git

Usage
-----

libvirt-dbus exports libvirt API using D-Bus objects with methods and properties
described by interfaces. Currently only local connection to libvirt is exported
and the list of supported drivers depends on the type of the bus connection
(session or system).

The name of the libvirt-dbus service is ``org.libvirt``. libvirt-dbus
distributes an interface XML descriptions which can be usually found at
``/usr/share/dbus-1/interfaces/``.

By default unprivileged user has access only to the session D-Bus connection. In
order to allow specific user "foo" to access the system D-Bus connection you
need to create a file ``/etc/dbus-1/system.d/org.libvirt.conf`` that contains:

::

   <?xml version="1.0"?>
   <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
    "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

   <busconfig>

     <policy user="foo">
       <allow send_destination="org.libvirt"/>
     </policy>

   </busconfig>

To get a list of supported drivers for the specific bus connection you can run
these commands (not all drivers may be available on the host):

::

   gdbus introspect --xml --session --dest org.libvirt --object-path /org/libvirt
   gdbus introspect --xml --system --dest org.libvirt --object-path /org/libvirt

Every object is introspectable so you can get a list of available interfaces
with methods, signals and properties running this command:

::

   gdbus introspect --xml --system --dest org.libvirt --object-path /org/libvirt/QEMU

To get a list of domains for specific connection driver you can run this
command:

::

   gdbus call --system --dest org.libvirt --object-path /org/libvirt/QEMU \
       --method org.libvirt.Connect.ListDomains 0
