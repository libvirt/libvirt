.. role:: since

======================
Host device management
======================

.. contents::

Libvirt provides management of both physical and virtual host devices
(historically also referred to as node devices) like USB, PCI, SCSI, and network
devices. This also includes various virtualization capabilities which the
aforementioned devices provide for utilization, for example SR-IOV, NPIV, MDEV,
DRM, etc.

The node device driver provides means to list and show details about host
devices (``virsh nodedev-list``, ``virsh nodedev-info``, and
``virsh nodedev-dumpxml``), which are generic and can be used with all devices.
It also provides the means to manage virtual devices. Persistently-defined
virtual devices are only supported for mediated devices, while transient devices
are supported by both mediated devices and NPIV (`more info about
NPIV) <https://wiki.libvirt.org/page/NPIV_in_libvirt>`__).

Persistent virtual devices are managed with ``virsh nodedev-define`` and
``virsh nodedev-undefine``. Persistent devices can be configured to start
manually or automatically using ``virsh nodedev-autostart``. Inactive devices
can be made active with ``virsh nodedev-start``.

Transient virtual devices are started and stopped with the commands
``virsh nodedev-create`` and ``virsh nodedev-destroy``.

Devices on the host system are arranged in a tree-like hierarchy, with the root
node being called ``computer``. The node device driver supports udev backend
(HAL backend was removed in ``6.8.0``).

Details of the XML format of a host device can be found
`here <formatnode.html>`__. Of particular interest is the ``capability``
element, which describes features supported by the device. Some specific device
types are addressed in more detail below.

Basic structure of a node device
--------------------------------

::

   <device>
     <name>pci_0000_00_17_0</name>
     <path>/sys/devices/pci0000:00/0000:00:17.0</path>
     <parent>computer</parent>
     <driver>
       <name>ahci</name>
     </driver>
     <capability type='pci'>
   ...
     </capability>
   </device>

PCI host devices
----------------

``capability``
   When used as top level element, the supported values for the ``type``
   attribute are ``pci`` and ``phys_function`` (see `SR-IOV capability`_ below).

::

   <device>
     <name>pci_0000_04_00_1</name>
     <path>/sys/devices/pci0000:00/0000:00:06.0/0000:04:00.1</path>
     <parent>pci_0000_00_06_0</parent>
     <driver>
       <name>igb</name>
     </driver>
     <capability type='pci'>
       <domain>0</domain>
       <bus>4</bus>
       <slot>0</slot>
       <function>1</function>
       <product id='0x10c9'>82576 Gigabit Network Connection</product>
       <vendor id='0x8086'>Intel Corporation</vendor>
       <iommuGroup number='15'>
         <address domain='0x0000' bus='0x04' slot='0x00' function='0x1'/>
       </iommuGroup>
       <numa node='0'/>
       <pci-express>
         <link validity='cap' port='1' speed='2.5' width='2'/>
         <link validity='sta' speed='2.5' width='2'/>
       </pci-express>
     </capability>
   </device>

The XML format for a PCI device stays the same for any further capabilities it
supports, a single nested ``<capability>`` element will be included for each
capability the device supports.

SR-IOV capability
~~~~~~~~~~~~~~~~~

Single root input/output virtualization (SR-IOV) allows sharing of the PCIe
resources by multiple virtual environments. That is achieved by slicing up a
single full-featured physical resource called physical function (PF) into
multiple devices called virtual functions (VFs) sharing their configuration with
the underlying PF. Despite the SR-IOV specification, the amount of VFs that can
be created on a PF varies among manufacturers.

Suppose the NIC above in `PCI host devices`_ was also SR-IOV capable, it would
also include a nested ``<capability>`` element enumerating all virtual
functions available on the physical device (physical port) like in the example
below.

::

   <capability type='pci'>
   ...
     <capability type='virt_functions' maxCount='7'>
       <address domain='0x0000' bus='0x04' slot='0x10' function='0x1'/>
       <address domain='0x0000' bus='0x04' slot='0x10' function='0x3'/>
       <address domain='0x0000' bus='0x04' slot='0x10' function='0x5'/>
       <address domain='0x0000' bus='0x04' slot='0x10' function='0x7'/>
       <address domain='0x0000' bus='0x04' slot='0x11' function='0x1'/>
       <address domain='0x0000' bus='0x04' slot='0x11' function='0x3'/>
       <address domain='0x0000' bus='0x04' slot='0x11' function='0x5'/>
     </capability>
   ...
   </capability>

A SR-IOV child device on the other hand, would then report its top level
capability type as a ``phys_function`` instead:

::

   <device>
   ...
     <capability type='phys_function'>
       <address domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
     </capability>
   ...
   </device>

MDEV capability
~~~~~~~~~~~~~~~

A device capable of creating mediated devices will include a nested capability
``mdev_types`` which enumerates all supported mdev types on the physical device,
along with the type attributes available through sysfs. A detailed description
of the XML format for the ``mdev_types`` capability can be found
`here <formatnode.html#mdev-types-capability>`__.

The following example shows how we might represent an NVIDIA GPU device that
supports mediated devices. See below for more info on
`Mediated devices (MDEVs)`_.

::

   <device>
   ...
     <driver>
       <name>nvidia</name>
     </driver>
     <capability type='pci'>
   ...
       <capability type='mdev_types'>
         <type id='nvidia-11'>
           <name>GRID M60-0B</name>
           <deviceAPI>vfio-pci</deviceAPI>
           <availableInstances>16</availableInstances>
         </type>
         <!-- Here would come the rest of the available mdev types -->
       </capability>
   ...
     </capability>
   </device>

VPD capability
~~~~~~~~~~~~~~

A device that exposes a PCI/PCIe VPD capability will include a nested capability
``vpd`` which presents data stored in the Vital Product Data (VPD). VPD provides
a device name and a number of other standard-defined read-only fields (change
level, manufacture id, part number, serial number) and vendor-specific read-only
fields. Additionally, if a device supports it, read-write fields (asset tag,
vendor-specific fields or system fields) may also be present. The VPD capability
is optional for PCI/PCIe devices and the set of exposed fields may vary
depending on a device. The XML format follows the binary format described in
"I.3. VPD Definitions" in PCI Local Bus (2.2+) and the identical format in PCIe
4.0+. At the time of writing, the support for exposing this capability is only
present on Linux-based systems (kernel version v2.6.26 is the first one to
expose VPD via sysfs which Libvirt relies on). Reading the VPD contents requires
root privileges, therefore, ``virsh nodedev-dumpxml`` must be executed
accordingly. A description of the XML format for the ``vpd`` capability can be
found `here <formatnode.html#vpd-capability>`__.

The following example shows a VPD representation for a device that exposes the
VPD capability with read-only and read-write fields. Among other things, the VPD
of this particular device includes a unique board serial number.

::

   <device>
     <name>pci_0000_42_00_0</name>
     <capability type='pci'>
       <class>0x020000</class>
       <domain>0</domain>
       <bus>66</bus>
       <slot>0</slot>
       <function>0</function>
       <product id='0xa2d6'>MT42822 BlueField-2 integrated ConnectX-6 Dx network controller</product>
       <vendor id='0x15b3'>Mellanox Technologies</vendor>
       <capability type='virt_functions' maxCount='16'/>
       <capability type='vpd'>
         <name>BlueField-2 DPU 25GbE Dual-Port SFP56, Crypto Enabled, 16GB on-board DDR, 1GbE OOB management, Tall Bracket</name>
         <fields access='readonly'>
           <change_level>B1</change_level>
           <manufacture_id>foobar</manufacture_id>
           <part_number>MBF2H332A-AEEOT</part_number>
           <serial_number>MT2113X00000</serial_number>
           <vendor_field index='0'>PCIeGen4 x8</vendor_field>
           <vendor_field index='2'>MBF2H332A-AEEOT</vendor_field>
           <vendor_field index='3'>3c53d07eec484d8aab34dabd24fe575aa</vendor_field>
           <vendor_field index='A'>MLX:MN=MLNX:CSKU=V2:UUID=V3:PCI=V0:MODL=BF2H332A</vendor_field>
         </fields>
         <fields access='readwrite'>
           <asset_tag>fooasset</asset_tag>
           <vendor_field index='0'>vendorfield0</vendor_field>
           <vendor_field index='2'>vendorfield2</vendor_field>
           <vendor_field index='A'>vendorfieldA</vendor_field>
           <system_field index='B'>systemfieldB</system_field>
           <system_field index='0'>systemfield0</system_field>
         </fields>
       </capability>
       <iommuGroup number='65'>
         <address domain='0x0000' bus='0x42' slot='0x00' function='0x0'/>
       </iommuGroup>
       <numa node='0'/>
       <pci-express>
         <link validity='cap' port='0' speed='16' width='8'/>
         <link validity='sta' speed='8' width='8'/>
       </pci-express>
     </capability>
   </device>

Mediated devices (MDEVs)
------------------------

Mediated devices ( :since:`Since 3.2.0` ) are software devices defining resource
allocation on the backing physical device which in turn allows the parent
physical device's resources to be divided into several mediated devices, thus
sharing the physical device's performance among multiple guests. Unlike SR-IOV
however, where a PCIe device appears as multiple separate PCIe devices on the
host's PCI bus, mediated devices only appear on the mdev virtual bus. Therefore,
no detach/reattach procedure from/to the host driver procedure is involved even
though mediated devices are used in a direct device assignment manner. A
detailed description of the XML format for the ``mdev`` capability can be found
`here <formatnode.html#mdev>`__.

Example of a mediated device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <device>
     <name>mdev_4b20d080_1b54_4048_85b3_a6a62d165c01</name>
     <path>/sys/devices/pci0000:00/0000:00:02.0/4b20d080-1b54-4048-85b3-a6a62d165c01</path>
     <parent>pci_0000_06_00_0</parent>
     <driver>
       <name>vfio_mdev</name>
     </driver>
     <capability type='mdev'>
       <type id='nvidia-11'/>
       <uuid>4b20d080-1b54-4048-85b3-a6a62d165c01</uuid>
       <iommuGroup number='12'/>
     </capability>
   </device>

The support of mediated device's framework in libvirt's node device driver
covers the following features:

-  list available mediated devices on the host ( :since:`Since 3.4.0` )
-  display device details ( :since:`Since 3.4.0` )
-  create transient mediated devices ( :since:`Since 6.5.0` )
-  define persistent mediated devices ( :since:`Since 7.3.0` )

Because mediated devices are instantiated from vendor specific templates, simply
called 'types', information describing these types is contained within the
parent device's capabilities (see the example in `PCI host devices`_).
To list all devices capable of creating mediated devices, the following command
can be used.

::

   $ virsh nodedev-list --cap mdev_types

To see the supported mediated device types on a specific physical device use the
following:

::

   $ virsh nodedev-dumpxml <device>

Before creating a mediated device, unbind the device from the respective device
driver, eg. subchannel I/O driver for a CCW device. Then bind the device to the
respective VFIO driver. For a CCW device, also unbind the corresponding
subchannel of the CCW device from the subchannel I/O driver and then bind the
subchannel (instead of the CCW device) to the vfio_ccw driver. The below example
shows the unbinding and binding steps for a CCW device.

::

   device="0.0.1234"
   subchannel="0.0.0123"
   echo $device > /sys/bus/ccw/devices/$device/driver/unbind
   echo $subchannel > /sys/bus/css/devices/$subchannel/driver/unbind
   echo $subchannel > /sys/bus/css/drivers/vfio_ccw/bind

To instantiate a transient mediated device, create an XML file representing the
device. See above for information about the mediated device xml format.

::

   $ virsh nodedev-create <xml-file>
   Node device '<device-name>' created from '<xml-file>'

If you would like to persistently define the device so that it will be
maintained across host reboots, use ``virsh nodedev-define`` instead of
``nodedev-create``:

::

   $ virsh nodedev-define <xml-file>
   Node device '<device-name>' defined from '<xml-file>'

To start an instance of this device definition, use the following command:

::

   $ virsh nodedev-start <device-name>

Active mediated device instances can be stopped using
``virsh       nodedev-destroy``, and persistent device definitions can be
removed using ``virsh nodedev-undefine``.

If a mediated device is defined persistently, it can also be set to be
automatically started whenever the host reboots or when the parent device
becomes available. In order to autostart a mediated device, use the following
command:

::

   $ virsh nodedev-autostart <device-name>
