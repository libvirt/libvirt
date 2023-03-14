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

If told to connect to libvirt, it will refuse to use a libvirt connection that
is local to the machine, since that cannot be trusted. For the sake of testing
or demonstration purposes, however, it can be forced to run in this scenario
using the ``--insecure`` flag. The result will, of course, still not be
trustworthy.

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

``-k PATH``, ``--kernel=PATH``

Path to the kernel binary if doing direct kernel boot.

``-r PATH``, ``--initrd=PATH``

Path to the initrd binary if doing direct kernel boot. Defaults to zero length
content if omitted.

``-e STRING``, ``--cmdline=STRING``

String containing any kernel command line parameters used during boot of the
domain. Defaults to the empty string if omitted.

``-n COUNT``, ``--num-cpus=COUNT``

The number of virtual CPUs for the domain. This is required when the
domain policy is set to require SEV-ES.

``-0 PATH``, ``--vmsa-cpu0=PATH``

Path to the VMSA initial state for the boot CPU. This is required when
the domain policy is set to require SEV-ES. The file contents must be
exactly 4096 bytes in length.

``-1 PATH``, ``--vmsa-cpu1=PATH``

Path to the VMSA initial state for the non-boot CPU. This is required when
the domain policy is set to require SEV-ES and the domain has more than one
CPU present. The file contents must be exactly 4096 bytes in length.

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

Libvirt options
---------------

These options are used when connecting to libvirt to automatically obtain
state and configuration information about the domain to be attested.

``-c``, ``--connect URI``

Libvirt connection URI. For the validation to be trustworthy this must be a URI
resolving to a remote virtualization host. This requirement can be overridden
using the ``--insecure`` argument.

``-o``, ``--domain ID|NAME|UUID``

Domain ID, or domain name or domain UUID. Used to identify which libvirt domain
is to have its launch measured. The domain must be running, and would usually
have been started in a paused state, to allow validation to be performed before
guest CPUs begin execution.

``-i``, ``--insecure``

Proceed even if usage scenario is known to be insecure. This allows the program
to connect to a local libvirt hypervisor and rely on file content from the
virtualization host. It also allows the validation to proceed even if the
virtual machine CPUs are not in the initial paused state. The result of the
validation must not be trusted.

``-g``, ``--ignore-config``

Do not attempt to sanity check the domain config. The default behaviour is to
print out errors if identifying configuration elements in the guest XML that
would invalidate the launch measurement. This can help the guest owner to
understand any configuration mistakes that have been made. If the
``--ignore-config`` argument is given, this sanity checking of configuration
will be skipped. The result is that the validation will likely be reported as
failed.

Secret injection options
------------------------

These options provide a way to inject a secret if validation of the
launch measurement passes.

``--inject-secret ALIAS-OR-GUID:PATH``

Path to a file containing a secret to inject into the guest OS. Typical
usage would be to supply a password for unlocking the root filesystem
full disk encryption. ``ALIAS`` can be one of the well known secrets:

* ``luks-key`` - bytes to use as a key for unlocking a LUKS key slot.
  GUID of ``736869e5-84f0-4973-92ec-06879ce3da0b``.

Alternatively ``GUID`` refers to an arbitrary UUID of the callers
choosing. The contents of ``PATH`` are defined by the requirements
of the associated GUID, and will used as-is without modification.
In particular be aware:

  * Avoid unwanted trailing newline characters in ``PATH`` unless
    mandated by the ``GUID``.
  * Any trailing ``NUL`` byte must be explicitly included in ``PATH``
    if mandated by the ``GUID``.

This argument can be repeated multiple times, provided a different
``GUID`` is given for each instance.

``--secret-header PATH``

Path to a file in which the injected secret header will be written in base64
format and later injected into the domain. This is required if there is no
connection to libvirt, otherwise the secret will be directly injected.

``--secret-payload PATH``

Path to a file in which the injected secret payload will be written in base64
format and later injected into the domain. This is required if there is no
connection to libvirt, otherwise the secret will be directly injected.

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

Validate the measurement of a SEV guest with direct kernel boot:

::

   # virt-qemu-sev-validate \
       --firmware OVMF.sev.fd \
       --kernel vmlinuz-5.11.12 \
       --initrd initramfs-5.11.12 \
       --cmdline "root=/dev/vda1" \
       --tk this-guest-tk.bin \
       --measurement Zs2pf19ubFSafpZ2WKkwquXvACx9Wt/BV+eJwQ/taO8jhyIj/F8swFrybR1fZ2ID \
       --api-major 0 \
       --api-minor 24 \
       --build-id 13 \
       --policy 3

Validate the measurement of a SEV-ES SMP guest booting from disk:

::

   # virt-qemu-sev-validate \
       --firmware OVMF.sev.fd \
       --num-cpus 2 \
       --vmsa-cpu0 vmsa0.bin \
       --vmsa-cpu1 vmsa1.bin \
       --tk this-guest-tk.bin \
       --measurement Zs2pf19ubFSafpZ2WKkwquXvACx9Wt/BV+eJwQ/taO8jhyIj/F8swFrybR1fZ2ID \
       --api-major 0 \
       --api-minor 24 \
       --build-id 13 \
       --policy 7

Validate the measurement of a SEV-ES SMP guest booting from disk, with
automatically constructed VMSA:

::

   # virt-qemu-sev-validate \
       --firmware OVMF.sev.fd \
       --num-cpus 2 \
       --cpu-family 23 \
       --cpu-model 49 \
       --cpu-stepping 0 \
       --tk this-guest-tk.bin \
       --measurement Zs2pf19ubFSafpZ2WKkwquXvACx9Wt/BV+eJwQ/taO8jhyIj/F8swFrybR1fZ2ID \
       --api-major 0 \
       --api-minor 24 \
       --build-id 13 \
       --policy 7

Validate the measurement of a SEV guest booting from disk and
inject a disk password on success:

::

   # virt-qemu-sev-validate \
       --firmware OVMF.sev.fd \
       --tk this-guest-tk.bin \
       --measurement Zs2pf19ubFSafpZ2WKkwquXvACx9Wt/BV+eJwQ/taO8jhyIj/F8swFrybR1fZ2ID \
       --api-major 0 \
       --api-minor 24 \
       --build-id 13 \
       --policy 3 \
       --inject-secret 736869e5-84f0-4973-92ec-06879ce3da0b:passwd.txt \
       --secret-header secret-header.b64 \
       --secret-payload secret-payload.b64

The ``secret-header.b64`` and ``secret-payload.b64`` files can now be sent to
the virtualization host for injection.

Fetch from remote libvirt
-------------------------

This scenario allows fetching certain data from a remote hypervisor via a
connection to libvirt. It will aid in debugging by analysing the guest
configuration and reporting anything that could invalidate the measurement
of the guest. This usage model is considered secure, because the limited
information obtained from the untrusted hypervisor cannot be used to change
the result.

Validate the measurement of a SEV guest booting from disk:

::

   # virt-qemu-sev-validate \
       --connect qemu+ssh://root@some.remote.host/system \
       --firmware OVMF.sev.fd \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV guest with direct kernel boot:

::

   # virt-qemu-sev-validate \
       --connect qemu+ssh://root@some.remote.host/system \
       --firmware OVMF.sev.fd \
       --kernel vmlinuz-5.11.12 \
       --initrd initramfs-5.11.12 \
       --cmdline "root=/dev/vda1" \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV-ES SMP guest booting from disk:

::

   # virt-qemu-sev-validate \
       --connect qemu+ssh://root@some.remote.host/system \
       --firmware OVMF.sev.fd \
       --num-cpus 2 \
       --vmsa-cpu0 vmsa0.bin \
       --vmsa-cpu1 vmsa1.bin \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV-ES SMP guest booting from disk, with
automatically constructed VMSA:

::

   # virt-qemu-sev-validate \
       --connect qemu+ssh://root@some.remote.host/system \
       --firmware OVMF.sev.fd \
       --cpu-family 23 \
       --cpu-model 49 \
       --cpu-stepping 0 \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV guest booting from disk and
inject a disk password on success:

::

   # virt-qemu-sev-validate \
       --connect qemu+ssh://root@some.remote.host/system \
       --firmware OVMF.sev.fd \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64 \
       --inject-secret 736869e5-84f0-4973-92ec-06879ce3da0b:passwd.txt

Fetch from local libvirt
------------------------

This scenario allows fetching all data from the local hypervisor via a
connection to libvirt. It is only to be used for the purpose of testing,
debugging, or demonstrations, because running on the local hypervisor is not
a secure scenario. To enable this usage, the ``--insecure`` flag must be
specified. Given a pointer to the libvirt guest to validate, all information
needed to perform a validation, except the TIK/TEK pair can be acquired
automatically.

Validate the measurement of a SEV guest booting from disk:

::

   # virt-qemu-sev-validate \
       --insecure \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV guest with direct kernel boot:

::

   # virt-qemu-sev-validate \
       --insecure \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV-ES SMP guest booting from disk:

::

   # virt-qemu-sev-validate \
       --insecure \
       --vmsa-cpu0 vmsa0.bin \
       --vmsa-cpu1 vmsa1.bin \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV-ES SMP guest booting from disk, with
automatically constructed VMSA:

::

   # virt-qemu-sev-validate \
       --insecure \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64

Validate the measurement of a SEV guest booting from disk and
inject a disk password on success:

::

   # virt-qemu-sev-validate \
       --insecure \
       --tk this-guest-tk.bin \
       --domain fedora34x86_64 \
       --inject-secret 736869e5-84f0-4973-92ec-06879ce3da0b:passwd.txt

COMMON MISTAKES CHECKLIST
=========================

The complexity of configuring a guest and validating its boot measurement
means it is very likely to see the failure::

   ERROR: Measurement does not match, VM is not trustworthy

This error message assumes the worst, but in most cases will failure will be
a result of either mis-configuring the guest, or passing the wrong information
when trying to validate it. The following information is a guide for what
items to check in order to stand the best chance of diagnosing the problem

* Check the VM configuration for the DH certificate and session
  blob in the libvirt guest XML.

  The content for these fields should be in base64 format, which is
  what ``sevctl session`` generates. Other tools may generate the files
  in binary format, so ensure it has been correctly converted to base64.

* Check the VM configuration policy value matches the session blob

  The ``<policy>`` value in libvirt guest XML has to match the value
  passed to the ``sevctl session`` command. If this is mismatched
  then the guest will not even start, and QEMU will show an error
  such as::

   sev_launch_start: LAUNCH_START ret=1 fw_error=11 'Bad measurement'

* Check the correct TIK/TEK keypair are passed

  The TIK/TEK keypair are uniquely tied to each DH cert and session
  blob. Make sure that the TIK/TEK keypair passed to this program
  the ones matched to the DH cert and session blob configured for
  the libvirt guest XML. This is one of the most common mistakes.
  Further ensure that the TIK and TEK files are not swapped.

* Check the firmware binary matches the one used to boot

  The firmware binary content is part of the data covered by the
  launch measurement. Ensure that the firmware binary passed to
  this program matches the one used to launch the guest. The
  hypervisor host will periodically get software updates which
  introduce a new firmware binary version.

* Check the kernel, initrd and cmdline match the one used to boot

  If the guest is configured to use direct kernel boot, check that
  the kernel, initrd and cmdline passed to this program match the
  ones used to boot the guest. In the kernel cmdline whitespace
  must be preserved exactly, including any leading or trailing
  spaces.

* Check whether the kernel hash measurement is enabled

  The ``kernelHashes`` property in the libvirt guest XML controls
  whether hashes of the kernel, initrd and cmdline content are
  covered by the boot measurement. If enabled, then the matching
  content must be passed to this program. UIf disabled, then
  the content must **NOT** be passed.

* Check that the correct measurement hash is passed

  The measurement hash includes a nonce, so it will be different
  on every boot attempt. Thus when validating the measuremnt it
  is important ensure the most recent measurement is used.

* Check the correct VMSA blobs / CPU SKU values for the host are used

  The VMSA blobs provide the initial register state for the
  boot CPU and any additional CPUs. One of the registers
  encodes the CPU SKU (family, model, stepping) of the physical
  host CPU. Make sure that the VMSA blob used for validation
  is one that matches the SKU of the host the guest is booted
  on. Passing the CPU SKU values directly to the tool can
  reduce the likelihood of using the wrong ones.

* Check the CPU count is correct

  When passing VMSA blobs for SEV-ES guests, the number of CPUs
  present will influence the measurement result. Ensure that the
  correct vCPU count is used corresponding to the guest boot
  attempt.


Best practice is to run this tool in completely offline mode and pass
all information as explicit command line parameters. When debugging
failures, however, it can be useful to tell it to connect to libvirt
and fetch information. If connecting to a remote libvirt instance,
it will fetch any information that can be trusted, which is the basic
VM launch state data. It will also sanity check the XML configuration
to identify some common mistakes. If the ``--insecure`` flag is passed
it can extract some configuration information and use that for the
attestation process.

If the mistake still can't be identified, then this tool can be run
on the virtualization host. In that scenario the only three command
line parameters required are for the TIK, TEK and libvirt domain
name. It should be able to automatically determine all the other
information required. If it still reports a failure, this points
very strongly to the TIK/TEK pair not matching the configured
DH certificate and session blob.

The ``--debug`` flag will display hashes and/or hex dumps for various
pieces of information used in the attestation process. Comparing the
``--debug`` output from running on the hypervisor host, against that
obtained when running in offline mode can give further guidance to
which parameter is inconsistent.

As mentioned earlier in this document, bear in mind that in general
any attestation answers obtained from running on the hypervisor host
should not be trusted. So if a configuration mistake is identified
it is strongly recommended to re-run the attestation in offline mode
on a trusted machine.


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

* **3** - *Usage scenario is not secure*

  The way in which this program has been invoked means that the result of any
  launch measurement validation will not be secure.

  The program can be reinvoked with ``--insecure`` argument to force a
  validation, however, the results of this should not be trusted. This should
  only be used for testing, debugging or demonstration purposes, never in a
  production deployment.

* **4** - *Domain has incorrect configuration to be measured*

  The way in which the guest has been configured prevent this program from being
  able to validate the launch measurement. Note that in general the guest
  configuration reported by the hypervisor is not trustworthy, so it is
  possible this error could be a false positive designed to cause a denial of
  service.

  This program can be reinvoked with the ``--ignore-config`` argument to skip
  the sanity checks on the domain XML. This will likely result in it failing
  with an exit code of **1** indicating the measurement is invalid

* **5** - *Domain is in incorrect state to be measured*

  The domain has to be running in order to validate a launch measurement.

* **6** - *unexpected error occurred in the code*

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
`https://libvirt.org/ <https://libvirt.org/>`_
