===========
Secure Boot
===========

.. contents::

Quick configuration
===================

If you have libvirt 8.6.0 or newer, when creating a new VM you can
ask for Secure Boot to be enabled with

::

  <os firmware='efi'>
    <firmware>
      <feature enabled='yes' name='secure-boot'/>
      <feature enabled='yes' name='enrolled-keys'/>
    </firmware>
  </os>

and for it to be disabled with either

::

  <os firmware='efi'>
    <firmware>
      <feature enabled='no' name='secure-boot'/>
    </firmware>
  </os>

or

::

  <os firmware='efi'>
    <firmware>
      <feature enabled='yes' name='secure-boot'/>
      <feature enabled='no' name='enrolled-keys'/>
    </firmware>
  </os>

The first configuration will cause unsigned guest operating systems
to be rejected, while the remaining two will allow running them. See
below for a more detailed explanation of how each knob affects the
firmware selection process.


Older libvirt versions
======================

If your libvirt version is older than 8.6.0 but newer than 7.2.0,
then enabling Secure Boot requires a slightly more verbose XML
snippet:

::

  <os firmware='efi'>
    <loader secure='yes'/>
    <firmware>
      <feature enabled='yes' name='secure-boot'/>
      <feature enabled='yes' name='enrolled-keys'/>
    </firmware>
  </os>

Versions older than 7.2.0 require manually providing all information
about the firmware and are not covered here. Please refer to `the
relevant documentation
<../formatdomain.html#operating-system-booting>`__ for details.


Changing an existing VM
=======================

Once the VM has been created, updating the XML configuration as
described above is **not** enough to change the Secure Boot status:
the NVRAM file associated with the VM has to be regenerated from its
template as well.

In order to do that, update the XML and then start the VM with

::

  $ virsh start $vm --reset-nvram

This option is only available starting with libvirt 8.1.0, so if your
version of libvirt is older than that you will have to delete the
NVRAM file manually before starting the VM.

Most guest operating systems will be able to cope with the NVRAM file
being reinitialized, but in some cases the VM will be unable to boot
after the change.


Additional information
======================

There are two parts to enabling Secure Boot: the firmware supporting
the feature, and it being active.

Most host operating systems ship a build of EDKII (the open source
EFI implementation used for QEMU VMs) that supports the Secure Boot
feature, but simply using such a build will not result in unsigned
guest operating systems being rejected: for that to happen, keys that
can be used to validate the operating system signature need to be
provided as well.

Asking for the ``enrolled-keys`` firmware feature to be enabled will
cause libvirt to initialize the NVRAM file associated with the VM
from a template that contains a suitable set of keys. These keys
being present will cause the firmware to enforce the Secure Boot
signing requirements.

The opposite configuration, where the feature is explicitly disabled,
will result in no keys being present in the NVRAM file. Unable to
verify signatures, the firmware will allow even unsigned operating
systems to run.

If running unsigned code is desired, it's also possible to ask for
the ``secure-boot`` feature to be disabled, which will cause libvirt
to pick a build of EDKII that doesn't have Secure Boot support at
all.

The main difference between using a build of EDKII that has Secure
Boot support but without keys enrolled and one that doesn't have
Secure Boot support at all is that, with the former, you could enroll
your own keys and securely run an operating system that you've built
and signed yourself. If you are only planning to run existing,
off-the-shelf operating system images, then the two configurations
are functionally equivalent.
