.. role:: since

=============
macOS support
=============

.. contents::

Libvirt works both as client (for most drivers) and server (for the
`QEMU driver <drvqemu.html>`__) on macOS.

:since:`Since 8.1.0`, the "hvf" domain type can be used to run
hardware-accelerated VMs on macOS via
`Hypervisor.framework <https://developer.apple.com/documentation/hypervisor>`__.
QEMU version 2.12 or newer is needed for this to work.


Installation
============

libvirt client (virsh), server (libvirtd) and development headers can be
installed from `Homebrew <https://brew.sh>`__:

::

   brew install libvirt


Running libvirtd locally
========================

The server can be started manually:

::

   $ libvirtd

or on system boot:

::

   $ brew services start libvirt

Once started, you can use virsh as you would on Linux.
