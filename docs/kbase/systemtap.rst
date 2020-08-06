====================
Systemtap of Libvirt
====================

.. contents::

`Systemtap <https://sourceware.org/systemtap/>`__ is a scripting
language and tool for dynamically probing or tracing in Linux kernel
space or user space. This page is about the usage of systemtap
in libvirt tracing.

Preparation
===========

Libvirt
-------

Libvirt should be configured with the systemtap option to support libvirt
probing events in systemtap.

For libvirt before **6.7.0**, it can be configured by:

::

    mkdir build
    cd build
   ../configure --with-dtrace

For libvirt **6.7.0** or later, configure it by the ``meson`` (seeing
`libvirt compiling <https://libvirt.org/compiling.html>`__):

::

   meson build -Ddtrace=enabled

For the libvirt binaries installed by the package manager like ``dnf`` or
``apt``, if libvirt systemtap tapset ``/usr/share/systemtap/tapset/libvirt_*``
exists, it means the libvirt enables the systemtap feature.

Systemtap
---------

For most of linux distributions, execute ``stap-prep`` by root to prepare the
environment for systemtap after installing the systemtap. If your distribution
doesn't have ``stap-prep``, install the ``kernel debuginfo`` packages manually.

After these above, run this test command to confirm the systemtap works well:

::

   stap -e 'probe oneshot{ printf("hello world\n")}'


Tracing events
==============

The libvirt systemtap tracing events are defined in tapset
``/usr/share/systemtap/tapset/libvirt_*``. Libvirt support these type of tracing
events: ``dbus``, ``event_glib``, ``object``, ``qemu``, ``rpc``.

List all tracing events in libvirt:

::

   grep 'probe libvirt.[a-z_0-9.]*' /usr/share/systemtap/tapset/libvirt_* -o|cut -f 2 -d :


Tracing examples
================

Here is an example of the systemtap script to trace the QMP messages sent from libvirtd
daemon to the qemu process.
``qmp.stp``:

::

   probe begin
   {
     printf("Start tracing\n")
   }
   probe libvirt.qemu.monitor_send_msg
   {
     printf("QMPs: %s", msg);
   }

Then run the systemtap script attaching to the libvirtd process:

::

   stap qmp.stp -x `pidof libvirtd`


To trace a libvirtd started from command line, use the option ``-c``

::

   stap qmp.stp -c "/usr/sbin/libvirtd"


Then after seeing the welcome message "Start tracing" from systemtap, then execute a virsh
command associated with QMP, for example ``virsh domstats``. Then get the QMP tracing logs
from systemtap. For example, the result from ``virsh domstats``

::

   QMPs: {"execute":"query-balloon","id":"libvirt-393"}
   QMPs: {"execute":"qom-get","arguments":{"path":"/machine/peripheral/balloon0","property":"guest-stats"},"id":"libvirt-394"}
   QMPs: {"execute":"query-blockstats","id":"libvirt-395"}
   QMPs: {"execute":"query-named-block-nodes","id":"libvirt-396"}
   QMPs: {"execute":"query-iothreads","id":"libvirt-397"}

For more examples of libvirt systemtap scripts, see the scripts in ``/usr/share/doc/libvirt-docs/examples/systemtap``
For more details of systemtap language, see `document of systemtap <https://sourceware.org/systemtap/documentation.html>`__
