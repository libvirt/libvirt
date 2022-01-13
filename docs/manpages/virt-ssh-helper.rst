===============
virt-ssh-helper
===============

--------------------
libvirt socket proxy
--------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::


SYNOPSIS
========

``virt-ssh-helper`` [*OPTION*]... *URI*


DESCRIPTION
===========

``virt-ssh-helper`` is an internal tool used to handle connections
coming from remote clients, and it's not intended to be called
directly by the user.


OPTIONS
=======

*URI*

Local libvirt URI to connect the remote client to.

``-r``, ``--readonly``

Make the connection read-only.

``-h``, ``--help``

Display command line help usage then exit.

``-V``, ``--version``

Display version information then exit.


EXIT STATUS
===========

The exit status will be zero on success, non-zero on failure.


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

Copyright (C) 2020 Red Hat, Inc.


LICENSE
=======

``virt-ssh-helper`` is distributed under the terms of the GNU LGPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.


SEE ALSO
========

virsh(1), `https://libvirt.org/ <https://libvirt.org/>`_
