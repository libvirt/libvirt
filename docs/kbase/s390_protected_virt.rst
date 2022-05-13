================================
Protected Virtualization on s390
================================

.. contents::

Overview
========

Protected virtualization, also known as IBM Secure Execution is a
hardware-based privacy protection technology for s390x (IBM Z).
It allows to execute virtual machines such that the host system
has no access to a VM's state and memory contents.

Unlike other similar technologies, the memory of a running guest
is not encrypted but protected by hardware access controls, which
may only be manipulated by trusted system firmware, called
ultravisor.

For the cases where the host needs access to guest memory (e.g. for
paging), it can request pages to be exported to it. The exported page
will be encrypted with a unique key for the running guest by the
ultravisor. The ultravisor also computes an integrity value for
the page, and stores it in a special table, together with the page
index and a counter. This way it can verify the integrity of
the page content upon re-import into the guest.

In other cases it may be necessary for a guest to grant the host access
to dedicated memory regions (e.g. for I/O). The guest can request
that the ultravisor removes the memory protection from individual
pages, so that they can be shared with the host. Likewise, the
guest can undo the sharing.

A secure guest will initially start in a regular non-protected VM.
The start-up is controlled by a small bootstrap program loaded
into memory together with encrypted operating system components and
a control structure (the PV header).
The operating system components (e.g. Linux kernel, initial RAM
file system, kernel parameters) are encrypted and integrity
protected. The component encryption keys and integrity values are
stored in the PV header.
The PV header is wrapped with a public key belonging to a specific
system (in fact it can be wrapped with multiple such keys). The
matching private key is only accessible by trusted hardware and
firmware in that specific system.
Consequently, such a secure guest boot image can only be run on the
systems it has been prepared for. Its contents can't be decrypted
without access to the private key and it can't be modified as
it is integrity protected.

Host Requirements
=================

IBM Secure Execution for Linux has some hardware and firmware
requirements. The system hardware must be an IBM z15 (or newer),
or an IBM LinuxONE III (or newer).

It is also necessary that the IBM Secure Execution feature is
enabled for that system. With libvirt >= 6.5.0 you can run
``virt-host-validate`` or otherwise check for facility '158', e.g.

::

   $ grep facilities /proc/cpuinfo | grep 158

The kernel must include the protected virtualization support
which can be verified by checking for the presence of directory
``/sys/firmware/uv``. It will only be present when both the
hardware and the kernel support are available.

Finally, the host operating system must donate some memory to
the ultravisor needed to store memory security information.
This is achieved by specifying the following kernel command
line parameter to the host boot configuration

::

   prot_virt=1


Guest Requirements
==================

Guest Boot
----------

To start a guest in protected virtualization secure mode, the
boot image must have been prepared first with the program
``genprotimg`` using the correct public key for this host.
``genprotimg`` is part of the package ``s390-tools``, or
``s390-utils``, depending on the Linux distribution being used.
It can also be found at
`<https://github.com/ibm-s390-tools/s390-tools/tree/master/genprotimg>`_

The guests have to be configured to use the host CPU model, which
must contain the ``unpack`` facility indicating ultravisor guest support.

With the following command it's possible to check whether the host
CPU model satisfies the requirement

::

   $ virsh domcapabilities | grep unpack

which should return

::

   <feature policy='require' name='unpack'/>

Note that on hosts with libvirt < 6.5.0 if the check fails despite
the host system actually supporting protected virtualization guests,
this can be caused by a stale libvirt capabilities cache.
To recover, run the following commands

::

   $ systemctl stop libvirtd
   $ rm /var/cache/libvirt/qemu/capabilities/*.xml
   $ systemctl start libvirtd


Guest I/O
---------

Protected virtualization guests support I/O using virtio devices.
As the virtio data structures of secure guests are not accessible
by the host, it is necessary to use shared memory ('bounce buffers').

Since libvirt 7.6.0 the
`<launchSecurity> <https://libvirt.org/formatdomain.html#launch-security>`__
element with type ``s390-pv`` should be used on protected virtualization guests.
Without ``launchSecurity`` you must enable all virtio devices to use shared
buffers by configuring them with platform_iommu enabled.
This can done by adding ``iommu='on'`` to the driver element of a virtio
device definition in the guest's XML, e.g.

::

   <interface type='network'>
     <source network='default'/>
     <model type='virtio'/>
     <driver name='vhost' iommu='on'/>
   </interface>

Unless you are using ``launchSecurity`` you must define all virtio bus
devices in this way to prevent the host from attempting to access
protected memory.

Ballooning will not work and is fenced by QEMU. It should be
disabled by specifying

::

   <memballoon model='none'/>

Finally, the guest Linux must be instructed to allocate I/O
buffers using memory shared between host and guest using SWIOTLB.
This is done by adding ``swiotlb=nnn`` to the guest's kernel command
line string, where ``nnn`` stands for the number of statically
allocated 2K entries. A commonly used value for swiotlb is 262144.

Example guest definition
========================

Minimal domain XML for a protected virtualization guest with
the ``launchSecurity`` element of type ``s390-pv``

::

   <domain type='kvm'>
     <name>protected</name>
     <memory unit='KiB'>2048000</memory>
     <currentMemory unit='KiB'>2048000</currentMemory>
     <vcpu>1</vcpu>
     <os>
       <type arch='s390x'>hvm</type>
     </os>
     <cpu mode='host-model'/>
     <devices>
       <disk type='file' device='disk'>
         <driver name='qemu' type='qcow2' cache='none' io='native'>
         <source file='/var/lib/libvirt/images/protected.qcow2'/>
         <target dev='vda' bus='virtio'/>
       </disk>
       <interface type='network'>
         <source network='default'/>
         <model type='virtio'/>
       </interface>
       <console type='pty'/>
       <memballoon model='none'/>
     </devices>
     <launchSecurity type='s390-pv'/>
   </domain>


Example guest definition without launchSecurity
===============================================

Minimal domain XML for a protected virtualization guest using the
``iommu='on'`` setting for each virtio device.

::

   <domain type='kvm'>
     <name>protected</name>
     <memory unit='KiB'>2048000</memory>
     <currentMemory unit='KiB'>2048000</currentMemory>
     <vcpu>1</vcpu>
     <os>
       <type arch='s390x'>hvm</type>
     </os>
     <cpu mode='host-model'/>
     <devices>
       <disk type='file' device='disk'>
         <driver name='qemu' type='qcow2' cache='none' io='native' iommu='on'>
         <source file='/var/lib/libvirt/images/protected.qcow2'/>
         <target dev='vda' bus='virtio'/>
       </disk>
       <interface type='network'>
         <driver iommu='on'/>
         <source network='default'/>
         <model type='virtio'/>
       </interface>
       <console type='pty'/>
       <memballoon model='none'/>
     </devices>
   </domain>
