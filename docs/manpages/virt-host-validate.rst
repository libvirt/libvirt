==================
virt-host-validate
==================

----------------------------------
validate host virtualization setup
----------------------------------

:Manual section: 1
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virt-host-validate`` [*OPTIONS*...] [*HV-TYPE*]


DESCRIPTION
===========

This tool validates that the host is configured in a suitable
way to run libvirt hypervisor drivers. If invoked without any
arguments it will check support for all hypervisor drivers it
is aware of. Optionally it can be given a particular hypervisor
type (``qemu``, ``lxc`` or ``bhyve``) to restrict the checks
to those relevant for that virtualization technology


OPTIONS
=======

``-v``, ``--version``

Display the command version

``-h``, ``--help``

Display the command line help

``-q``, ``--quiet``

Don't display details of individual checks being performed.
Only display output if a check does not pass.


EXIT STATUS
===========

Upon successful validation, an exit status of 0 will be set. Upon
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

Copyright (C) 2012 by Red Hat, Inc.


LICENSE
=======

``virt-host-validate`` is distributed under the terms of the GNU GPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), virt-pki-validate(1), virt-xml-validate(1),
`https://libvirt.org/ <https://libvirt.org/>`_
