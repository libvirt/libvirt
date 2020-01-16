====================
virt-sanlock-cleanup
====================

-----------------------------------------
remove stale sanlock resource lease files
-----------------------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virt-sanlock-cleanup``


DESCRIPTION
===========

This tool removes any resource lease files created by the sanlock
lock manager plugin. The resource lease files only need to exist
on disks when a guest using the resource is active. This script
reclaims the disk space used by resources which are not currently
active.


EXIT STATUS
===========

Upon successful processing of leases cleanup, an exit status
of 0 will be set. Upon fatal error a non-zero status will
be set.


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

Copyright (C) 2011, 2013 Red Hat, Inc.


LICENSE
=======

``virt-sanlock-cleanup`` is distributed under the terms of the GNU GPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), `online instructions <https://libvirt.org/locking.html>`_,
`https://libvirt.org/ <https://libvirt.org/>`_
