========================================
PCI addresses in domain XML and guest OS
========================================

.. contents::

Looking at the configuration for a guest, it would be reasonable
to expect that each PCI device would show up in the guest OS with
a PCI address that matches the one present in the corresponding
``<address>`` element of the domain XML, but that's not guaranteed
to happen and will in fact not be the case in all but the simplest
scenarios.


Simple cases
============

When the PCI topology of the VM is very simple, the PCI addresses
will usually match.

For example, the domain XML snippet

::

  <controller type='pci' index='0' model='pcie-root'/>
  <controller type='pci' index='1' model='pcie-root-port'>
    <model name='pcie-root-port'/>
    <target chassis='1' port='0x8'/>
    <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
  </controller>
  <interface type='network'>
    <source network='default'/>
    <model type='virtio'/>
    <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
  </interface>

will result in the PCI topology

::

  0000:00:00.0 Host bridge: Intel Corporation 82G33/G31/P35/P31 Express DRAM Controller
  0000:00:01.0 PCI bridge: Red Hat, Inc. QEMU PCIe Root port
  0000:01:00.0 Ethernet controller: Red Hat, Inc. Virtio network device (rev 01)

showing up in the guest OS.

The PCI address of the ``virtio-net`` adapter, ``0000:01:00.0``, is
the same in both cases, so there's no confusion.


More complex cases
==================

In more complex cases, the PCI address visible in the domain XML will
correlate to the one seen by the guest OS in a less obvious way.

pcie-expander-bus
-----------------

This fairly uncommon device, which can be used with ``x86_64/q35``
guests, will help illustrate one such scenario.

For example, the domain XML snippet

::

  <controller type='pci' index='0' model='pcie-root'/>
  <controller type='pci' index='1' model='pcie-expander-bus'>
    <model name='pxb-pcie'/>
    <target busNr='254'/>
    <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
  </controller>
  <controller type='pci' index='2' model='pcie-root-port'>
    <model name='pcie-root-port'/>
    <target chassis='2' port='0x0'/>
    <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
  </controller>
  <interface type='network'>
    <source network='default'/>
    <model type='virtio'/>
    <address type='pci' domain='0x0000' bus='0x02' slot='0x00' function='0x0'/>
  </interface>

will result in the PCI topology

::

  0000:00:00.0 Host bridge: Intel Corporation 82G33/G31/P35/P31 Express DRAM Controller
  0000:00:01.0 Host bridge: Red Hat, Inc. QEMU PCIe Expander bridge
  0000:fe:00.0 PCI bridge: Red Hat, Inc. QEMU PCIe Root port
  0000:ff:00.0 Ethernet controller: Red Hat, Inc. Virtio network device (rev 01)

showing up in the guest OS.

This time the addresses don't match: this is because the ``busNr``
property for the ``pcie-expander-bus`` controller causes it to show
up as bus 254 (``0xfe`` in hexadecimal) instead of bus 1 as one might
expect based on its ``index`` property.

How can the domain XML shown above work at all, then? Surely the
``pcie-root-port`` controller and the ``virtio-net`` adapter should
use ``bus=0xfe`` and ``bus=0xff`` respectively for the configuration
to be accepted by libvirt?

As it turns out, that's not the case. The reason for this is that
QEMU, and consequently libvirt, uses the ``bus`` property of a
device's PCI address only to match it with the PCI controller that
has the same ``index`` property, and not to set the actual PCI
address, which is decided by the guest OS.

So, by looking at the XML snippet above, we can see that the
``virtio-net`` adapter plugs into the ``pcie-root-port`` controller,
which plugs into the ``pcie-expander-bus`` controller, which plugs
into ``pcie-root``: the guest OS sees the same topology, but assigns
different PCI addresses to some of its component.

The takeaway is that the *relationship* between controllers are the
very same whether you look at the domain XML or at the guest OS, but
the *actual PCI addresses* are not guaranteed to match and in fact,
except for the very simplest cases, they usually will not.

spapr-pci-host-bridge
---------------------

This device, which is unique to ``ppc64/pseries`` guests, will help
illustrate another scenario.

For example, the domain XML snippet

::

  <controller type='pci' index='0' model='pci-root'>
     <model name='spapr-pci-host-bridge'/>
     <target index='0'/>
   </controller>
   <controller type='pci' index='1' model='pci-root'>
     <model name='spapr-pci-host-bridge'/>
     <target index='1'/>
   </controller>
   <interface type='network'>
     <source network='default'/>
     <model type='virtio'/>
     <address type='pci' domain='0x0000' bus='0x01' slot='0x01' function='0x0'/>
   </interface>

will result in the PCI topology

::

  0001:00:01.0 Ethernet controller: Red Hat, Inc. Virtio network device

showing up in the guest OS. Note that the two
``spapr-pci-host-bridge`` controllers are not listed.

This time, in addition to the bus not matching just like in the
previous example, the interesting part is that the domain doesn't
match either: this is because each ``spapr-pci-host-bridge``
controller creates a separate PCI domain.

Once again, while the PCI addresses seen in the domain XML and those
seen by the guest OS do not match, the relationships between the
various devices are preserved.

zPCI addresses
--------------

For s390x machines, PCI addresses are handled yet differently. No
topology information is relayed in the PCI addresses; instead, the
``fid`` and ``uid`` elements of the ``zpci`` device convey information.
In the simplest case, the following XML snippet

::

  <controller type='pci' index='0' model='pci-root'/>
  <controller type='pci' index='1' model='pci-bridge'>
    <model name='pci-bridge'/>
    <target chassisNr='1'/>
    <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'>
      <zpci uid='0x0001' fid='0x00000000'/>
    </address>
  </controller>
  <interface type='bridge'>
    <source bridge='virbr0'/>
    <model type='virtio'/>
    <address type='pci' domain='0x0000' bus='0x01' slot='0x01' function='0x0'>
      <zpci uid='0x0007' fid='0x00000003'/>
    </address>
  </interface>

will result in the following in a Linux guest:

::

  0007:00:00.0 Ethernet controller: Red Hat, Inc. Virtio network device

Note that the PCI bridge is not visible in the guest; s390x always has a flat
topology. The PCI address in the guest is generated from the information
provided via the ``zpci`` element: more specifically, ``uid`` is used as the
PCI domain. ``fid`` doesn't appear in the PCI address itself, but it will be
used in sysfs (``/sys/bus/pci/slots/$fid/...``).

Any changes in the PCI address are not visible in the guest; replacing the PCI
address for the ``virtio-net`` device with

::

  <address type='pci' domain='0x0000' bus='0x01' slot='0x06' function='0x4'>

will result in the exactly same view in the guest, as the ``fid`` and ``uid``
values in the ``zpci`` element remain unchanged.


Device assignment
=================

When using VFIO to assign host devices to a guest, an additional
caveat to keep in mind that the guest OS will base its decisions upon
the *target address* (guest side) rather than the *source address*
(host side).

For example, the domain XML snippet

::

  <hostdev mode='subsystem' type='pci' managed='yes'>
    <driver name='vfio'/>
    <source>
      <address domain='0x0001' bus='0x08' slot='0x00' function='0x0'/>
    </source>
    <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
  </hostdev>

will result in the device showing up as ``0000:00:01.0`` in the
guest OS rather than as ``0001:08:00.1``, which is the address of the
device on the host.

Of course, all the rules and behaviors described above still apply.


Reserved addresses
==================

Due to some historical reasons hypervisors might expect some PCI
devices to appear at certain addresses instead of 'random' ones.
For QEMU this is machine type and guest architecture dependent.
But to give you at least a gist here is list of reserved PCI
addresses:

For the x86_64 architecture's ``I440FX``-based machine types the following
devices are hard coded into QEMU and can't be moved or eliminated:

============  ======================
0000:00:00.0  Host bridge
0000:00:01.0  ISA bridge
0000:00:01.1  primary IDE controller
0000:00:01.2  PIIX3 USB controller
0000:00:01.3  ACPI (power management) and SMBus controller
============  ======================

The following addresses will be used as default ones for the corresponding
devices (if the address is free or a different address wasn't provided for the
device). It is okay to use this address for any other device.

============  ==================
0000:00:02.0  primary video card
============  ==================


For the x86_64 architecture's ``Q35``-based machine types the following
devices are hard coded into QEMU and can't be moved or eliminated:

============  =======================
0000:00:00.0  Host bridge
0000:00:1f.2  primary SATA controller
0000:00:1f.0  ISA bridge
0000:00:1f.3  SMBus
============  =======================

The following addresses will be used as default ones for the corresponding
devices (if the address is free or a different address wasn't provided for the
device) because that's how real ``Q35`` would do it:

============  ===============
0000:00:1a.0  USB2 controller
0000:00:1b.0  ICH9 sound chip
0000:00:1d.0  USB2 controller
============  ===============
