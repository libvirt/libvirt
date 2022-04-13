========================
PCI topology and hotplug
========================

.. contents::

Perhaps surprisingly, most libvirt guests support only limited PCI device
hotplug out of the box, or even none at all.

The reason for this apparent limitation is the fact that each hotplugged PCI
device might require additional PCI controllers to be added to the guest. Since
most PCI controllers can't be hotplugged, they need to be added before the guest
is started; however, libvirt has no way of knowing in advance how many devices
will be hotplugged during the guest's lifetime, thus making it impossible to
automatically provide the right amount of PCI controllers: any arbitrary number
would end up being too big for some users, and too small for others.

Ultimately, the user is the only one who knows how much the guest will need to
grow dynamically, so the responsibility of planning a suitable PCI topology in
advance falls on them.

This document aims at providing all the information needed to successfully plan
the PCI topology of a guest. Note that the details can vary a lot between
architectures and even machine types, hence the way it's organized.

x86_64 architecture
-------------------

q35 machine type
~~~~~~~~~~~~~~~~

This is a PCI Express native machine type. The default PCI topology looks like

::

   <controller type='pci' index='0' model='pcie-root'/>
   <controller type='pci' index='1' model='pcie-root-port'>
     <model name='pcie-root-port'/>
     <target chassis='1' port='0x10'/>
     <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
   </controller>

and supports hotplugging a single PCI Express device, either emulated or
assigned from the host.

If you have a very specific use case, such as the appliances used by
`libguestfs <https://libguestfs.org/>`__ behind the scenes to access disk
images, and this automatically-added ``pcie-root-port`` controller ends up being
a nuisance, you can prevent libvirt from adding it by manually managing PCI
controllers and addresses according to your needs.

Slots on the ``pcie-root`` controller do not support hotplug, so the device will
be hotplugged into the ``pcie-root-port`` controller. If you plan to hotplug
more than a single PCI Express device, you should add a suitable number of
``pcie-root-port`` controllers when defining the guest: for example, add

::

   <controller type='pci' model='pcie-root'/>
   <controller type='pci' model='pcie-root-port'/>
   <controller type='pci' model='pcie-root-port'/>
   <controller type='pci' model='pcie-root-port'/>

if you expect to hotplug up to three PCI Express devices, either emulated or
assigned from the host. That's all the information you need to provide: libvirt
will fill in the remaining details automatically. Note that you need to add the
``pcie-root`` controller along with the ``pcie-root-port`` controllers or you
will get an error.

Note that if you're adding PCI controllers to a guest and at the same time
you're also adding PCI devices, some of the controllers will be used for the
newly-added devices and won't be available for hotplug once the guest has been
started.

If you expect to hotplug legacy PCI devices, then you will need specialized
controllers, since all those mentioned above are intended for PCI Express
devices only: add

::

   <controller type='pci' model='pcie-to-pci-bridge'/>

and you'll be able to hotplug up to 31 legacy PCI devices, either emulated or
assigned from the host, in the slots from 0x01 to 0x1f of the
``pcie-to-pci-bridge`` controller.

i440fx (pc) machine type
~~~~~~~~~~~~~~~~~~~~~~~~

This is a legacy PCI native machine type. The default PCI topology looks like

::

   <controller type='pci' index='0' model='pci-root'/>

where each of the 31 slots (from 0x01 to 0x1f) on the ``pci-root`` controller is
hotplug capable and can accept a legacy PCI device, either emulated or assigned
from the guest.

ppc64 architecture
------------------

pseries machine type
~~~~~~~~~~~~~~~~~~~~

The default PCI topology for the ``pseries`` machine type looks like

::

   <controller type='pci' index='0' model='pci-root'>
     <model name='spapr-pci-host-bridge'/>
     <target index='0'/>
   </controller>

The 31 slots, from 0x01 to 0x1f, on a ``pci-root`` controller are all hotplug
capable and, despite the name suggesting otherwise, starting with QEMU 2.9 all
of them can accept PCI Express devices in addition to legacy PCI devices;
however, libvirt will only place emulated devices on the default ``pci-root``
controller.

In order to take advantage of improved error reporting and recovering
capabilities, PCI devices assigned from the host need to be isolated by placing
each on a separate ``pci-root`` controller, which has to be prepared in advance
for hotplug to work: for example, add

::

   <controller type='pci' model='pci-root'/>
   <controller type='pci' model='pci-root'/>
   <controller type='pci' model='pci-root'/>

if you expect to hotplug up to three PCI devices assigned from the host.

aarch64 architecture
--------------------

mach-virt (virt) machine type
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This machine type mostly behaves the same as the `q35 machine type`_,
so you can just refer to that section for information.

The only difference worth mentioning is that using legacy PCI for ``mach-virt``
guests is extremely uncommon, so you'll probably never need to add controllers
other than ``pcie-root-port``.
