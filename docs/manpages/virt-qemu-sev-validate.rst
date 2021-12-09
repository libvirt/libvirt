======================
virt-qemu-sev-validate
======================

--------------------------------------------
validate a domain AMD SEV launch measurement
--------------------------------------------

:Manual section: 1
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========


``virt-qemu-sev-validate`` [*OPTIONS*]


DESCRIPTION
===========

This program validates the reported measurement for a domain launched with AMD
SEV. If the program exits with a status of zero, the guest owner can be
confident that their guest OS is running under the protection offered by the
SEV / SEV-ES platform.

Note that the level of protection varies depending on the AMD SEV platform
generation and describing the differences is outside the scope of this
document.

For the results of this program to be considered trustworthy, it is required to
be run on a machine that is already trusted by the guest owner. This could be a
machine that the guest owner has direct physical control over, or it could be
another virtual machine protected by AMD SEV that has already had its launch
measurement validated. Running this program on the virtualization host will not
produce an answer that can be trusted.

OPTIONS
=======

Common options
--------------

``-h``, ``--help``

Display command line help usage then exit.

``-d``, ``--debug``

Show debug information while running

``-q``, ``--quiet``

Don't print information about the attestation result.

Guest state options
-------------------

These options provide information about the state of the guest that needs its
boot attested.

``--measurement BASE64-STRING``

The launch measurement reported by the hypervisor of the domain to be validated.
The measurement must be 48 bytes of binary data encoded as a base64 string.

``--api-major VERSION``

The SEV API major version of the hypervisor the domain is running on.

``--api-minor VERSION``

The SEV API major version of the hypervisor the domain is running on.

``--build-id ID``

The SEV build ID of the hypervisor the domain is running on.

``--policy POLiCY``

The policy bitmask associated with the session launch data of the domain to be
validated.

Guest config options
--------------------

These options provide items needed to calculate the expected domain launch
measurement. This will then be compared to the reported launch measurement.

``-f PATH``, ``--firmware=PATH``

Path to the firmware loader binary. This is the EDK2 build that knows how to
initialize AMD SEV. For the validation to be trustworthy it important that the
firmware build used has no support for loading non-volatile variables from
NVRAM, even if NVRAM is expose to the guest.

``--tik PATH``

TIK file for domain. This file must be exactly 16 bytes in size and contains the
unique transport integrity key associated with the domain session launch data.
This is mutually exclusive with the ``--tk`` argument.

``--tek PATH``

TEK file for domain. This file must be exactly 16 bytes in size and contains the
unique transport encryption key associated with the domain session launch data.
This is mutually exclusive with the ``--tk`` argument.

``--tk PATH``

TEK/TIK combined file for the domain. This file must be exactly 32 bytes in
size, with the first 16 bytes containing the TEK and the last 16 bytes
containing the TIK.  This is mutually exclusive with the ``--tik`` and ``--tek``
arguments.

EXAMPLES
========

Fully offline execution
-----------------------

This scenario allows a measurement to be securely validated in a completely
offline state without any connection to the hypervisor host. All required
data items must be provided as command line parameters. This usage model is
considered secure, because all input data is provided by the user.

Validate the measurement of a SEV guest booting from disk:

::

   # virt-qemu-sev-validate \
       --firmware OVMF.sev.fd \
       --tk this-guest-tk.bin \
       --measurement Zs2pf19ubFSafpZ2WKkwquXvACx9Wt/BV+eJwQ/taO8jhyIj/F8swFrybR1fZ2ID \
       --api-major 0 \
       --api-minor 24 \
       --build-id 13 \
       --policy 3

EXIT STATUS
===========

Upon successful attestation of the launch measurement, an exit status of 0 will
be set.

Upon failure to attest the launch measurement one of the following codes will
be set:

* **1** - *Guest measurement did not validate*

  Assuming the inputs to this program are correct, the virtual machine launch
  has been compromised and it should not be trusted henceforth.

* **2** - *Usage scenario cannot be supported*

  The way in which this program has been invoked prevent it from being able to
  validate the launch measurement.

* **3** - *unexpected error occurred in the code*

  A logic flaw in this program means it is unable to complete the validation of
  the measurement. This is a bug which should be reported to the maintainers.

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

``virt-qemu-sev-validate`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), `SEV launch security usage <https://libvirt.org/kbase/launch_security_sev.html>`_,
`https://www.libvirt.org/ <https://www.libvirt.org/>`_
