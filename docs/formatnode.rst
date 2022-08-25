.. role:: since

=======================
Node devices XML format
=======================

.. contents::

Node Device XML
---------------

There are several libvirt functions, all with the prefix ``virNodeDevice``,
which deal with management of host devices that can be handed to guests via
passthrough as <hostdev> elements in `the domain
XML <formatdomain.html#host-device-assignment>`__. These devices are represented as a
hierarchy, where a device on a bus has a parent of the bus controller device;
the root of the hierarchy is the node named "computer".

When represented in XML, a node device uses the top-level ``device`` element,
with the following elements present according to the type of device:

``name``
   The name for this device. The name will be alphanumeric, with words separated
   by underscore. For many devices, the name is just the bus type and address,
   as in "pci_0000_00_02_1" or "usb_1_5_3", but some devices are able to provide
   more specific names, such as "net_eth1_00_27_13_6a_fe_00". This is a
   read-only field that is reported by the device driver. If this element is set
   when defining a new device, it will be ignored.
``path``
   Fully qualified sysfs path to the device. This is a read-only field that is
   reported by the device driver. If this element is set when defining a new
   device, it will be ignored.
``parent``
   This element identifies the parent node in the device hierarchy. The value of
   the element will correspond with the device parent's ``name`` element or
   ``computer`` if the device does not have any parent.
``driver``
   This elements reports the driver in use for this device. The presence of this
   element in the output XML depends on whether the underlying device manager
   (most likely udev) exposes information about the driver.
``devnode``
   This node appears for each associated ``/dev`` special file. A mandatory
   attribute ``type`` specify the kind of file path, which may be either ``dev``
   for the main name, or ``link`` for additional symlinks.
``capability``
   This node appears for each capability that libvirt associates with a node. A
   mandatory attribute ``type`` lists which category the device belongs to.
   The `capability types`_ section below describes them further.

``capability`` types
~~~~~~~~~~~~~~~~~~~~

Based on the capbility type there are further more specific attributes to a
device described below.

``system``
^^^^^^^^^^

Describes the overall host. Sub-elements include:

``product``
    If present, a simple text string giving the product name of the system.
``hardware``
    Describes the hardware of the system, including sub-elements for
    ``vendor``, ``version``, ``serial``, and ``uuid``.
``firmware``
    Describes the firmware of the system, including sub-elements for
    ``vendor``, ``version``, and ``release_date``.

``pci``
^^^^^^^

Describes a device on the host's PCI bus. Sub-elements include:

``class``
   Optional element for combined class, subclass and programming interface
   codes as 6-digit hexadecimal number. :since:`Since 5.2.0`
``domain``
   Which domain the device belongs to.
``bus``
   Which bus within the domain.
``slot``
   Which slot within the bus.
``function``
   Which function within the slot.
``product``
   Product details from the device ROM, including an attribute ``id`` with
   the hexadecimal product id, and an optional text description of that
   id.
``vendor``
   Vendor details from the device ROM, including an attribute ``id`` with
   the hexadecimal vendor id, and an optional text name of that vendor.
``iommuGroup``
   This optional element describes the "IOMMU group" this device belongs
   to. If the element exists, it has a mandatory ``number`` attribute
   which tells the group number used for management of the group (all
   devices in group "n" will be found in "/sys/kernel/iommu_groups/n"). It
   will also have a list of ``address`` subelements, each containing the
   PCI address of a device in the same group. The toplevel device will
   itself be included in this list.
``capability``
   This optional element can occur multiple times. If it exists, it has a
   mandatory ``type`` attribute which will be set to:

   ``phys_function``
      That means there will be a single ``address`` subelement which
      contains the PCI address of the SRIOV Physical Function (PF) that is
      the parent of this device (and this device is, by implication, an
      SRIOV Virtual Function (VF)).
   ``virt_functions``
      In this case this device is an SRIOV PF, and the capability element
      will have a list of ``address`` subelements, one for each VF on this
      PF. If the host system supports reporting it (via the
      "sriov_totalvfs" file in the device's sysfs directory) the
      capability element will also have an attribute named ``maxCount``
      which is the maximum number of SRIOV VFs supported by this device,
      which could be higher than the number of VFs that are currently
      active :since:`since 1.3.0` ; in this case, even if there are
      currently no active VFs the virtual_functions capabililty will still
      be shown.
   ``pci-bridge`` or ``cardbus-bridge``
      This shows merely that the lower 7 bits of PCI header type have
      either value of 1 or 2 respectively. Usually this means such device
      cannot be used for PCI passthrough. :since:`Since 1.3.3`
   ``mdev_types``
      This device is capable of creating mediated devices. The
      sub-elements are summarized in `mdev_types capability`_.
   ``vpd``
      This device exposes a VPD PCI/PCIe capability. The sub-elements are
      summarized in `vpd capability`_.
``numa``
   This optional element contains information on the PCI device with
   respect to NUMA. For example, the optional ``node`` attribute tells
   which NUMA node is the PCI device associated with.
``pci-express``
   This optional element contains information on PCI Express part of the
   device. For example, it can contain a child element ``link`` which
   addresses the PCI Express device's link. While a device has its own
   capabilities (``validity='cap'``), the actual run time capabilities are
   negotiated on the device initialization (``validity='sta'``). The
   ``link`` element then contains three attributes: ``port`` which says in
   which port is the device plugged in, ``speed`` (in GigaTransfers per
   second) and ``width`` for the number of lanes used. Since the port
   can't be negotiated, it's not exposed in
   ``./pci-express/link/[`validity='sta']``.

``usb_device``
^^^^^^^^^^^^^^

Describes a device on the host's USB bus, based on its location within the bus.
Sub-elements include:

``bus``
   Which bus the device belongs to.
``device``
   Which device within the bus.
``product``
   Product details from the device ROM, including an attribute ``id`` with
   the hexadecimal product id, and an optional text description of that
   id.
``vendor``
   Vendor details from the device ROM, including an attribute ``id`` with
   the hexadecimal vendor id, and an optional text name of that vendor.

``usb``
^^^^^^^

Describes a USB device, based on its advertised driver interface.  Sub-elements
include:

``number``
   The device number.
``class``
   The device class.
``subclass``
   The device subclass.
``protocol``
   The device protocol.
``description``
   If present, a description of the device.

``net``
^^^^^^^

Describes a device capable for use as a network interface. Sub-elements
include:

``interface``
   The interface name tied to this device.
``address``
   If present, the MAC address of the device.
``link``
   Optional to reflect the status of the link. It has two optional
   attributes: ``speed`` in Mbits per second and ``state`` to tell the
   state of the link. So far, the whole element is just for output, not
   setting.
``feature``
   If present, the hw offloads supported by this network interface.
   Possible features are:

   ``rx``
      rx-checksumming
   ``tx``
      tx-checksumming
   ``sg``
      scatter-gather
   ``tso``
      tcp-segmentation-offload
   ``ufo``
      udp-fragmentation-offload
   ``gso``
      generic-segmentation-offload
   ``gro``
      generic-receive-offload
   ``lro``
      large-receive-offload
   ``rxvlan``
      rx-vlan-offload
   ``txvlan``
      tx-vlan-offload
   ``ntuple``
      ntuple-filters
   ``rxhash``
      receive-hashing
   ``rdma``
      remote-direct-memory-access
   ``txudptnl``
      tx-udp-tunnel-segmentation
   ``switchdev``
      kernel-forward-plane-offload
``capability``
   A network protocol exposed by the device, where the attribute ``type``
   can be "80203" for IEEE 802.3, or "80211" for various flavors of IEEE
   802.11.

``scsi_host``
^^^^^^^^^^^^^

Describes a SCSI host device. Sub-elements include:

``host``
   The SCSI host number.
``unique_id``
   On input, this optionally provides the value from the 'unique_id' file
   found in the scsi_host's directory. To view the values of all
   'unique_id' files, use
   ``find -H /sys/class/scsi_host/host{0..9}/unique_id | xargs grep '[0-9]'``.
   On output, if the unique_id file exists, the value from the file will
   be displayed. This can be used in order to help uniquely identify the
   scsi_host adapter in a `Storage Pool <formatstorage.html>`__.
   :since:`Since 1.2.7`
``capability``
   Current capabilities include "vport_ops" (indicates vport operations
   are supported) and "fc_host". "vport_ops" could contain two optional
   sub-elements: ``vports``, and ``max_vports``. ``vports`` shows the
   number of vport in use. ``max_vports`` shows the maximum vports the HBA
   supports. "fc_host" implies following sub-elements: ``wwnn``, ``wwpn``,
   and optionally ``fabric_wwn``.

``scsi``
^^^^^^^^

Describes a SCSI device. Sub-elements include:

``host``
   The SCSI host containing the device.
``bus``
   The bus within the host.
``target``
   The target within the bus.
``lun``
   The lun within the target.
``type``
   The type of SCSI device.

``storage``
^^^^^^^^^^^

Describes a device usable for storage. Sub-elements include:

``block``
   A block device file name that accesses the storage present on the
   device.
``bus``
   If present, the name of the bus the device is found on.
``drive_type``
   The type of the drive, such as "disk" or "cdrom".
``model``
   Any model information available from the device.
``vendor``
   Any vendor information available from the device.
``serial``
   Any serial number information available from the device.
``size``
   For fixed-size storage, the amount of storage available.
``capability``
   If present, an additional capability is listed via the attribute
   ``type``. Current capabilities include "hotpluggable" and "removable",
   with the latter implying the following sub-elements:
   ``media_available`` (0 or 1), ``media_size``, and ``media_label``.

``drm``
^^^^^^^

Describes a Direct Rendering Manager (DRM) device. Sub-elements include:

``type``
   The type of DRM device. Could be ``primary``, ``control`` or ``render``.

``mdev``
^^^^^^^^

Describes a mediated device. :since:`Since 3.4.0` Sub-elements include:

``type``
   Describes a mediated device type which acts as an abstract template
   defining a resource allocation for instances of this device type. The
   element has one attribute ``id`` which holds an official
   vendor-supplied identifier for the type.
``iommuGroup``
   This element supports a single attribute ``number`` which holds the
   IOMMU group number to which the mediated device belongs. This is a
   read-only field that is reported by the device driver.
``attr``
   This optional element can occur multiple times. It represents a
   vendor-specific attribute that is used to configure this mediated
   device. It has two required attributes: ``name`` and ``value``. Note
   that the order in which attributes are set may be important for some
   devices. The order that they appear in the xml definition determines
   the order that they will be written to the device.
``uuid``
   This element represents the UUID of the mediated device.

``ccw``
^^^^^^^

Describes a Command Channel Word (CCW) device commonly found on the S390
architecture. Sub-elements include:

``cssid``
   The channel subsystem identifier.
``ssid``
   The subchannel-set identifier.
``devno``
   The device number.

``css``
^^^^^^^

Describes a subchannel in the Channel SubSystem (CSS) commonly found on the
S390 architecture. Sub-elements include:

``cssid``
   The channel subsystem identifier.
``ssid``
   The subchannel-set identifier.
``devno``
   The subchannel number.
``capability``
   This optional element can occur multiple times. If it exists, it has a
   mandatory ``type`` attribute which will be set to:

   ``mdev_types``
      :since:`Since 6.10.0` This device is capable of creating mediated
      devices. The sub-elements are summarized in `mdev_types capability`_.

``vdpa``
^^^^^^^^

Describes a virtual datapath acceleration (vDPA) network device.  :since:`Since
6.9.0` . Sub-elements include:

``chardev``
   The path to the character device that is used to access the device.

``ap_card``
^^^^^^^^^^^

Describes the Adjunct Processor (AP) Card device on a S390 host.  Sub-elements
include:

``ap-adapter``
   AP Card identifier.

``ap_queue``
^^^^^^^^^^^^

Describes the AP queue on a s390 host. An AP queue is an AP domain on an AP
adapter which is specified by an adapter identifier and a domain identifier.
Sub-elements include:

``ap-adapter``
   The ap-adapter of an AP queue identifies the AP card to which this AP
   queue belongs.
``ap-domain``
   The ap-domain of an AP queue identifies the AP domain to which this AP
   queue belongs.
   AP Queue identifier.

``ap_matrix``
^^^^^^^^^^^^^

Describes an AP Matrix device on a S390 architecture providing cryptographic
host resources usable for virtualization. Sub-elements include:

``capability``
   This optional element can occur multiple times. If it exists, it has a
   mandatory ``type`` attribute which will be set to:

   ``mdev_types``
      :since:`Since 6.10.0` This device is capable of creating mediated
      devices. The sub-elements are summarized in `mdev_types capability`_

``mdev_types`` capability
~~~~~~~~~~~~~~~~~~~~~~~~~

`pci`_, `css`_ and `ap_matrix`_ devices can be capable of creating mediated
devices. If they indeed are capable, then the parent ``capability`` element for
``mdev_types`` type will contain a list of ``type`` elements, which list all
mdev types supported on the physical device. :since:`Since 3.4.0` Each ``type``
element has a single ``id`` attribute that holds an official vendor-supplied
identifier for the type. It supports the following sub-elements:

``name``
   The ``name`` element holds a vendor-supplied code name for the given mediated
   device type. This is an optional element.
``deviceAPI``
   The value of this element describes how an instance of the given type will be
   presented to the guest by the VFIO framework.
``availableInstances``
   This element reports the current state of resource allocation. In other
   words, how many instances of the given type can still be successfully created
   on the physical device.

``vpd`` capability
~~~~~~~~~~~~~~~~~~

`pci`_ devices can expose a VPD capability which is optional per
PCI Local Bus 2.2+ and PCIe 4.0+ specifications. If the VPD capability is
present, then the parent ``capability`` element with the ``vpd`` type will
contain a ``name`` element (containing a manufacturer-provided device name) and
optionally one or two ``fields`` elements with an ``access`` attribute set to
``readonly`` or ``readwrite``.

The read-only ``fields`` element may contain the following elements:

``change_level``
   An engineering change level for this add-in card.
``manufacture_id``
   An extension to the Vendor ID (or Subsystem Vendor ID) in the Configuration
   Space header which allows vendors the flexibility to identify an additional
   level of detail pertaining to the sourcing of a PCI device.
``part_number``
   An extension to the Device ID (or Subsystem ID) in the Configuration Space
   header specifying a part number of an add-in card.
``serial_number``
   A unique add-in card Serial Number.
``vendor_field``
   Zero or many of those elements with an ``index`` attribute (since-character
   upper-case ASCII alphanumeric indexes). Contents will vary depending on a
   vendor.

All fields are optional and are not guaranteed to be present for a generic PCI
device.

The read-write ``fields`` element may contain the following elements:

``asset_tag``
   A system asset identifier provided by the system owner.
``vendor_field``
   Zero or many of those elements with an ``index`` attribute (since-character
   upper-case ASCII alphanumeric indexes). Contents will vary depending on a
   vendor.
``system_field``
   Zero or many of those elements with an ``index`` attribute (since-character
   upper-case ASCII alphanumeric indexes, except for letter 'A'). May store
   system-specific data related to a PCI device.

All fields are optional and are not guaranteed to be present for a generic PCI
device. Read-write fields are not possible to alter via Libvirt at the time of
writing but their content is refreshed on each invocation in case this is done
by means external to Libvirt.

The device name and all fields may contain only the following characters:
``[0-9a-zA-F -_,.:;=]``. The device name may be as large as 65535 bytes while
fields are limited with 255 bytes.

Examples
--------

The following are some example node device XML outputs:

::

   <device>
     <name>computer</name>
     <capability type='system'>
       <product>2241B36</product>
       <hardware>
         <vendor>LENOVO</vendor>
         <version>ThinkPad T500</version>
         <serial>R89055N</serial>
         <uuid>c9488981-5049-11cb-9c1c-993d0230b4cd</uuid>
       </hardware>
       <firmware>
         <vendor>LENOVO</vendor>
         <version>6FET82WW (3.12 )</version>
         <release_date>11/26/2009</release_date>
       </firmware>
     </capability>
   </device>

   <device>
     <name>net_eth1_00_27_13_6a_fe_00</name>
     <parent>pci_0000_00_19_0</parent>
     <capability type='net'>
       <interface>eth1</interface>
       <address>00:27:13:6a:fe:00</address>
       <capability type='80203'/>
     </capability>
   </device>

   <device>
     <name>pci_0000_02_00_0</name>
     <path>/sys/devices/pci0000:00/0000:00:04.0/0000:02:00.0</path>
     <parent>pci_0000_00_04_0</parent>
     <driver>
       <name>igb</name>
     </driver>
     <capability type='pci'>
       <class>0x020000</class>
       <domain>0</domain>
       <bus>2</bus>
       <slot>0</slot>
       <function>0</function>
       <product id='0x10c9'>82576 Gigabit Network Connection</product>
       <vendor id='0x8086'>Intel Corporation</vendor>
       <capability type='virt_functions'>
         <address domain='0x0000' bus='0x02' slot='0x10' function='0x0'/>
         <address domain='0x0000' bus='0x02' slot='0x10' function='0x2'/>
         <address domain='0x0000' bus='0x02' slot='0x10' function='0x4'/>
         <address domain='0x0000' bus='0x02' slot='0x10' function='0x6'/>
         <address domain='0x0000' bus='0x02' slot='0x11' function='0x0'/>
         <address domain='0x0000' bus='0x02' slot='0x11' function='0x2'/>
         <address domain='0x0000' bus='0x02' slot='0x11' function='0x4'/>
       </capability>
       <iommuGroup number='12'>
         <address domain='0x0000' bus='0x02' slot='0x00' function='0x0'/>
         <address domain='0x0000' bus='0x02' slot='0x00' function='0x1'/>
       </iommuGroup>
       <pci-express>
         <link validity='cap' port='1' speed='2.5' width='1'/>
         <link validity='sta' speed='2.5' width='1'/>
       </pci-express>
     </capability>
   </device>
