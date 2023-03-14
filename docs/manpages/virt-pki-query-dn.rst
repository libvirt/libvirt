=================
virt-pki-query-dn
=================

-------------------------------------------------
extract Distinguished Name from a PEM certificate
-------------------------------------------------

:Manual section: 1
:Manual group: Virtualization Support

.. contents::


SYNOPSIS
========

``virt-pki-query-dn`` [*OPTION*]... *FILE*


DESCRIPTION
===========

Extract Distinguished Name from a PEM certificate.

The output is meant to be used in the ``tls_allowed_dn_list``
configuration option in the ``libvirtd.conf`` file.


OPTIONS
=======

``-h``, ``--help``

Display command line help usage then exit.

``-V``, ``--version``

Display version information then exit.


EXIT STATUS
===========

The exit status will be zero on success, non-zero on failure.


AUTHOR
======

Martin Kletzander


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

Copyright (C) 2021 Red Hat, Inc.


LICENSE
=======

``virt-pki-query-dn`` is distributed under the terms of the GNU GPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.


SEE ALSO
========

virsh(1), virt-pki-validate(1),
`online PKI setup instructions <https://libvirt.org/remote.html>`_,
`https://libvirt.org/ <https://libvirt.org/>`_
