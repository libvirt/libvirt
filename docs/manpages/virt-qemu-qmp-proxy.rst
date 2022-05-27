===================
virt-qemu-qmp-proxy
===================

--------------------------------------------------
Expose a QMP proxy server for a libvirt QEMU guest
--------------------------------------------------

:Manual section: 1
:Manual group: Virtualization Support

.. contents::


SYNOPSIS
========

``virt-qemu-qmp-proxy`` [*OPTION*]... *DOMAIN* *QMP-SOCKET-PATH*


DESCRIPTION
===========

This tool provides a way to expose a QMP proxy server that communicates
with a QEMU guest managed by libvirt. This enables standard QMP client
tools to interact with libvirt managed guests.

**NOTE: use of this tool will result in the running QEMU guest being
marked as tainted.** It is strongly recommended that this tool *only be
used to send commands which query information* about the running guest.
If this tool is used to make changes to the state of the guest, this
may have negative interactions with the QEMU driver, resulting in an
inability to manage the guest operation thereafter, and in the worst
case **potentially lead to data loss or corruption**.

The ``virt-qemu-qmp-proxy`` program will listen on a UNIX socket for incoming
client connections, and run the QMP protocol over the connection. Any
commands received will be sent to the running libvirt guest, and replies
sent back.

The ``virt-qemu-qmp-proxy`` program may be interrupted (eg Ctrl-C) when it
is no longer required. The libvirt QEMU guest will continue running.


OPTIONS
=======

*DOMAIN*

The ID or UUID or Name of the libvirt QEMU guest.

*QMP-SOCKET-PATH*

The filesystem path at which to run the QMP server, listening for
incoming connections.

``-c`` *CONNECTION-URI*
``--connect``\ =\ *CONNECTION-URI*

The URI for the connection to the libvirt QEMU driver. If omitted,
a URI will be auto-detected.

``-v``, ``--verbose``

Run in verbose mode, printing all QMP commands and replies that
are handled.

``-h``, ``--help``

Display the command line help.


EXIT STATUS
===========

Upon successful shutdown, an exit status of 0 will be set. Upon
failure a non-zero status will be set.


AUTHOR
======

Daniel P. Berrangé


BUGS
====

Please report all bugs you discover.  This should be done via either:

#. the mailing list

   `https://libvirt.org/contact.html <https://libvirt.org/contact.html>`_

#. the bug tracker

   `https://libvirt.org/bugs.html <https://libvirt.org/bugs.html>`_

Alternatively, you may report bugs to your software distributor / vendor.

COPYRIGHT
=========

Copyright (C) 2022 by Red Hat, Inc.


LICENSE
=======

``virt-qemu-qmp-proxy`` is distributed under the terms of the GNU LGPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), `https://libvirt.org/ <https://libvirt.org/>`_,
`QMP reference <https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html>`_
