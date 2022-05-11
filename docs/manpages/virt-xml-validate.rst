=================
virt-xml-validate
=================

-------------------------------------------
validate libvirt XML files against a schema
-------------------------------------------

:Manual section: 1
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========


``virt-xml-validate`` *XML-FILE* [*SCHEMA-NAME*]

``virt-xml-validate`` *OPTION*


DESCRIPTION
===========

Validates a libvirt XML for compliance with the published schema.
The first compulsory argument is the path to the XML file to be
validated. The optional second argument is the name of the schema
to validate against. If omitted, the schema name will be inferred
from the name of the root element in the XML document.

Valid schema names currently include

- ``cpu``

The schema for the XML format of cpu

- ``domainsnapshot``

The schema for the XML format used by domain snapshot configuration

- ``domaincheckpoint``

The schema for the XML format used by domain checkpoint configuration

- ``domainbackup``

The schema for the XML format used by domain backup configuration

- ``domaincaps``

The schema for the XML format of domain capabilities

- ``domain``

The schema for the XML format used by guest domains configuration

- ``networkport``

The schema for the XML format used by network port configuration

- ``network``

The schema for the XML format used by virtual network configuration

- ``storagepoolcaps``

The schema for the XML format of storage pool capabilities

- ``storagepool``

The schema for the XML format used by storage pool configuration

- ``storagevol``

The schema for the XML format used by storage volume descriptions

- ``nodedev``

The schema for the XML format used by node device descriptions

- ``capability``

The schema for the XML format used to declare driver capabilities

- ``nwfilter``

The schema for the XML format used by network traffic filters

- ``nwfilterbinding``

The schema for XML format used by network filter bindings.

- ``secret``

The schema for the XML format used by secrets descriptions

- ``interface``

The schema for the XML format used by physical host interfaces


OPTIONS
=======

``-h``, ``--help``

Display command line help usage then exit.

``-V``, ``--version``

Display version information then exit.


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

Copyright (C) 2009-2013 by Red Hat, Inc.
Copyright (C) 2009 by Daniel P. Berrangé


LICENSE
=======

``virt-xml-validate`` is distributed under the terms of the GNU GPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), `online XML format descriptions <https://libvirt.org/format.html>`_,
`https://libvirt.org/ <https://libvirt.org/>`_
