.. role:: since

=================
Domain XML format
=================

.. contents::

This section describes the XML format used to represent domains, there are
variations on the format based on the kind of domains run and the options used
to launch them. For hypervisor specific details consult the `driver
docs <drivers.html>`__


Element and attribute overview
==============================

The root element required for all virtual machines is named ``domain``. It has
two attributes, the ``type`` specifies the hypervisor used for running the
domain. The allowed values are driver specific, but include "xen", "kvm",
"hvf" (:since:`since 8.1.0 and QEMU 2.12`), "qemu"
and "lxc". The second attribute is ``id`` which is a unique integer identifier
for the running guest machine. Inactive machines have no id value.


General metadata
----------------

::

   <domain type='kvm' id='1'>
     <name>MyGuest</name>
     <uuid>4dea22b3-1d52-d8f3-2516-782e98ab3fa0</uuid>
     <genid>43dc0cf8-809b-4adb-9bea-a9abb5f3d90e</genid>
     <title>A short description - title - of the domain</title>
     <description>Some human readable description</description>
     <metadata>
       <app1:foo xmlns:app1="http://app1.org/app1/">..</app1:foo>
       <app2:bar xmlns:app2="http://app1.org/app2/">..</app2:bar>
     </metadata>
     ...

``name``
   The content of the ``name`` element provides a short name for the virtual
   machine. This name should consist only of alphanumeric characters and is
   required to be unique within the scope of a single host. It is often used to
   form the filename for storing the persistent configuration file.
   :since:`Since 0.0.1`
``uuid``
   The content of the ``uuid`` element provides a globally unique identifier for
   the virtual machine. The format must be RFC 4122 compliant, eg
   ``3e3fce45-4f53-4fa7-bb32-11f34168b82b``. If omitted when defining/creating a
   new machine, a random UUID is generated. It is also possible to provide the
   UUID via a `SMBIOS System Information`_ specification. :since:`Since 0.0.1,
   sysinfo since 0.8.7`
``genid``
   :since:`Since 4.4.0` , the ``genid`` element can be used to add a Virtual
   Machine Generation ID which exposes a 128-bit, cryptographically random,
   integer value identifier, referred to as a Globally Unique Identifier (GUID)
   using the same format as the ``uuid``. The value is used to help notify the
   guest operating system when the virtual machine is re-executing something
   that has already executed before, such as:

   -  VM starts executing a snapshot
   -  VM is recovered from backup
   -  VM is failover in a disaster recovery environment
   -  VM is imported, copied, or cloned

   The guest operating system notices the change and is then able to react as
   appropriate by marking its copies of distributed databases as dirty,
   re-initializing its random number generator, etc.

   The libvirt XML parser will accept both a provided GUID value or just
   <genid/> in which case a GUID will be generated and saved in the XML. For the
   transitions such as above, libvirt will change the GUID before re-executing.

``title``
   The optional element ``title`` provides space for a short description of the
   domain. The title should not contain any newlines. :since:`Since 0.9.10` .
``description``
   The content of the ``description`` element provides a human readable
   description of the virtual machine. This data is not used by libvirt in any
   way, it can contain any information the user wants. :since:`Since 0.7.2`
``metadata``
   The ``metadata`` node can be used by applications to store custom metadata in
   the form of XML nodes/trees. Applications must use custom namespaces on their
   XML nodes/trees, with only one top-level element per namespace (if the
   application needs structure, they should have sub-elements to their namespace
   element). :since:`Since 0.9.10`


Operating system booting
------------------------

There are a number of different ways to boot virtual machines each with their
own pros and cons.


BIOS bootloader
~~~~~~~~~~~~~~~

Booting via the BIOS is available for hypervisors supporting full
virtualization. In this case the BIOS has a boot order priority (floppy,
harddisk, cdrom, network) determining where to obtain/find the boot image.

::

   <!-- Xen with fullvirt loader -->
   ...
   <os>
     <type>hvm</type>
     <loader>/usr/lib/xen/boot/hvmloader</loader>
     <boot dev='hd'/>
   </os>
   ...

   <!-- QEMU with default firmware, serial console and SMBIOS -->
   ...
   <os>
     <type>hvm</type>
     <boot dev='cdrom'/>
     <bootmenu enable='yes' timeout='3000'/>
     <smbios mode='sysinfo'/>
     <bios useserial='yes' rebootTimeout='0'/>
   </os>
   ...

   <!-- QEMU with UEFI manual firmware and secure boot -->
   ...
   <os>
     <type>hvm</type>
     <loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader>
     <nvram template='/usr/share/OVMF/OVMF_VARS.fd'>/var/lib/libvirt/nvram/guest_VARS.fd</nvram>
     <boot dev='hd'/>
   </os>
   ...

   <!-- QEMU with UEFI manual firmware, secure boot and with NVRAM type 'file'-->
   ...
   <os>
     <type>hvm</type>
     <loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader>
     <nvram type='file' template='/usr/share/OVMF/OVMF_VARS.fd'>
       <source file='/var/lib/libvirt/nvram/guest_VARS.fd'/>
     </nvram>
     <boot dev='hd'/>
   </os>
   ...

   <!-- QEMU with UEFI manual firmware, secure boot and with network backed NVRAM'-->
   ...
   <os>
     <type>hvm</type>
     <loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader>
     <nvram type='network'>
       <source protocol='iscsi' name='iqn.2013-07.com.example:iscsi-nopool/0'>
         <host name='example.com' port='6000'/>
         <auth username='myname'>
           <secret type='iscsi' usage='mycluster_myname'/>
         </auth>
       </source>
     </nvram>
     <boot dev='hd'/>
   </os>
   ...

   <!-- QEMU with automatic UEFI firmware and secure boot -->
   ...
   <os firmware='efi'>
     <type>hvm</type>
     <loader secure='yes'/>
     <boot dev='hd'/>
   </os>
   ...

   <!-- QEMU with automatic UEFI stateless firmware for AMD SEV -->
   ...
   <os firmware='efi'>
     <type>hvm</type>
     <loader stateless='yes'/>
     <boot dev='hd'/>
   </os>
   ...

``firmware``
   The ``firmware`` attribute allows management applications to automatically
   fill ``<loader/>`` and ``<nvram/>`` elements and possibly enable some
   features required by selected firmware. Accepted values are ``bios`` and
   ``efi``.
   The selection process scans for files describing installed firmware images in
   specified location and uses the most specific one which fulfills domain
   requirements. The locations in order of preference (from generic to most
   specific one) are:

   -  ``/usr/share/qemu/firmware``
   -  ``/etc/qemu/firmware``
   -  ``$XDG_CONFIG_HOME/qemu/firmware``

   For more information refer to firmware metadata specification as described in
   ``docs/interop/firmware.json`` in QEMU repository. Regular users do not need
   to bother. :since:`Since 5.2.0 (QEMU and KVM only)`
   For VMware guests, this is set to ``efi`` when the guest uses UEFI, and it is
   not set when using BIOS. :since:`Since 5.3.0 (VMware ESX and
   Workstation/Player)`
``type``
   The content of the ``type`` element specifies the type of operating system to
   be booted in the virtual machine. ``hvm`` indicates that the OS is one
   designed to run on bare metal, so requires full virtualization. ``linux``
   (badly named!) refers to an OS that supports the Xen 3 hypervisor guest ABI.
   There are also two optional attributes, ``arch`` specifying the CPU
   architecture to virtualization, and ``machine`` referring to the machine
   type. The `Capabilities XML <formatcaps.html>`__ provides details on allowed
   values for these. If ``arch`` is omitted then for most hypervisor drivers,
   the host native arch will be chosen. For the ``test``, ``ESX`` and ``VMWare``
   hypervisor drivers, however, the ``i686`` arch will always be chosen even on
   an ``x86_64`` host. :since:`Since 0.0.1`
``firmware``
   :since:`Since 7.2.0 QEMU/KVM only`

   When using firmware auto-selection there are different features enabled in
   the firmwares. The list of features can be used to limit what firmware should
   be automatically selected for the VM. The list of features can be specified
   using zero or more ``feature`` elements. Libvirt will take into consideration
   only the listed features and ignore the rest when selecting the firmware.

   ``feature``
      The list of mandatory attributes:

      - ``enabled`` (accepted values are ``yes`` and ``no``) is used to tell libvirt
        if the feature must be enabled or not in the automatically selected firmware

      - ``name`` the name of the feature, the list of the features:

        - ``enrolled-keys`` whether the selected nvram template has default
          certificate enrolled. Firmware with Secure Boot feature but without
          enrolled keys will successfully boot non-signed binaries as well.
          Valid only for firmwares with Secure Boot feature.

        - ``secure-boot`` whether the firmware implements UEFI Secure boot feature.
``loader``
   The optional ``loader`` tag refers to a firmware blob, which is specified by
   absolute path, used to assist the domain creation process. It is used by Xen
   fully virtualized domains as well as setting the QEMU BIOS file path for
   QEMU/KVM domains. :since:`Xen since 0.1.0, QEMU/KVM since 0.9.12` Then,
   :since:`since 1.2.8` it's possible for the element to have two optional
   attributes: ``readonly`` (accepted values are ``yes`` and ``no``) to reflect
   the fact that the image should be writable or read-only. The second attribute
   ``type`` accepts values ``rom`` and ``pflash``. It tells the hypervisor where
   in the guest memory the file should be mapped. For instance, if the loader
   path points to an UEFI image, ``type`` should be ``pflash``. Moreover, some
   firmwares may implement the Secure boot feature. Attribute ``secure`` can be
   used to tell the hypervisor that the firmware is capable of Secure Boot feature.
   It cannot be used to enable or disable the feature itself in the firmware.
   :since:`Since 2.1.0`. If the loader is marked as read-only, then with UEFI it
   is assumed that there will be a writable NVRAM available. In some cases,
   however, it may be desirable for the loader to run without any NVRAM, discarding
   any config changes on shutdown. The ``stateless`` flag (:since:`Since 8.6.0`)
   can be used to control this behaviour, when set to ``yes`` NVRAM will never
   be created.

   When firmware autoselection is enabled, the ``format`` attribute can be
   used to tell libvirt to only consider firmware builds that are in a
   specific format. Supported values are ``raw`` and ``qcow2``.
   :since:`Since 9.2.0 (QEMU only)`

``nvram``
   Some UEFI firmwares may want to use a non-volatile memory to store some
   variables. In the host, this is represented as a file and the absolute path
   to the file is stored in this element. Moreover, when the domain is started
   up libvirt copies so called master NVRAM store file defined in ``qemu.conf``.
   If needed, the ``template`` attribute can be used to per domain override map
   of master NVRAM stores from the config file. Note, that for transient domains
   if the NVRAM file has been created by libvirt it is left behind and it is
   management application's responsibility to save and remove file (if needed to
   be persistent). :since:`Since 1.2.8`

   :since:`Since 8.5.0`,  it's possible for the element to have ``type`` attribute
   (accepts values ``file``, ``block`` and ``network``) in that case the NVRAM
   storage is described by a ``<source>`` sub-element with the same syntax as
   ``disk``'s source. See `Hard drives, floppy disks, CDROMs`_.

   **Note:** ``network`` backed NVRAM the variables are not instantiated from
   the ``template`` and it's user's responsibility to provide a valid NVRAM image.

   This element supports a ``format`` attribute, which has the same semantics
   as the attribute of the same name for the ``<loader>`` element.
   :since:`Since 9.2.0 (QEMU only)`

   It is not valid to provide this element if the loader is marked as
   stateless.

``boot``
   The ``dev`` attribute takes one of the values "fd", "hd", "cdrom" or
   "network" and is used to specify the next boot device to consider. The
   ``boot`` element can be repeated multiple times to setup a priority list of
   boot devices to try in turn. Multiple devices of the same type are sorted
   according to their targets while preserving the order of buses. After
   defining the domain, its XML configuration returned by libvirt (through
   virDomainGetXMLDesc) lists devices in the sorted order. Once sorted, the
   first device is marked as bootable. Thus, e.g., a domain configured to boot
   from "hd" with vdb, hda, vda, and hdc disks assigned to it will boot from vda
   (the sorted list is vda, vdb, hda, hdc). Similar domain with hdc, vda, vdb,
   and hda disks will boot from hda (sorted disks are: hda, hdc, vda, vdb). It
   can be tricky to configure in the desired way, which is why per-device boot
   elements (see `Hard drives, floppy disks, CDROMs`_, `Network interfaces`_,
   and `Host device assignment`_ sections below) were introduced and they are
   the preferred way providing full control over booting order.
   The ``boot`` element and per-device boot elements are mutually exclusive.
   :since:`Since 0.1.3, per-device boot since 0.8.8`
``smbios``
   How to populate SMBIOS information visible in the guest. The ``mode``
   attribute must be specified, and is either "emulate" (let the hypervisor
   generate all values), "host" (copy all of Block 0 and Block 1, except for the
   UUID, from the host's SMBIOS values; the
   `virConnectGetSysinfo <html/libvirt-libvirt-host.html#virConnectGetSysinfo>`__
   call can be used to see what values are copied), or "sysinfo" (use the values
   in the `SMBIOS System Information`_ element). If not specified, the
   hypervisor default is used. :since:`Since 0.8.7`

Up till here the BIOS/UEFI configuration knobs are generic enough to be
implemented by majority (if not all) firmwares out there. However, from now on
not every single setting makes sense to all firmwares. For instance,
``rebootTimeout`` doesn't make sense for UEFI, ``useserial`` might not be usable
with a BIOS firmware that doesn't produce any output onto serial line, etc.
Moreover, firmwares don't usually export their capabilities for libvirt (or
users) to check. And the set of their capabilities can change with every new
release. Hence users are advised to try the settings they use before relying on
them in production.

``bootmenu``
   Whether or not to enable an interactive boot menu prompt on guest startup.
   The ``enable`` attribute can be either "yes" or "no". If not specified, the
   hypervisor default is used. :since:`Since 0.8.3` Additional attribute
   ``timeout`` takes the number of milliseconds the boot menu should wait until
   it times out. Allowed values are numbers in range [0, 65535] inclusive and it
   is ignored unless ``enable`` is set to "yes". :since:`Since 1.2.8`
``bios``
   This element has attribute ``useserial`` with possible values ``yes`` or
   ``no``. It enables or disables Serial Graphics Adapter which allows users to
   see BIOS messages on a serial port. Therefore, one needs to have `Serial port`_
   defined. :since:`Since 0.9.4` . :since:`Since
   0.10.2 (QEMU only)` there is another attribute, ``rebootTimeout`` that
   controls whether and after how long the guest should start booting again in
   case the boot fails (according to BIOS). The value is in milliseconds with
   maximum of ``65535`` and special value ``-1`` disables the reboot.

Host bootloader
~~~~~~~~~~~~~~~

Hypervisors employing paravirtualization do not usually emulate a BIOS, and
instead the host is responsible to kicking off the operating system boot. This
may use a pseudo-bootloader in the host to provide an interface to choose a
kernel for the guest. An example is ``pygrub`` with Xen. The Bhyve hypervisor
also uses a host bootloader, either ``bhyveload`` or ``grub-bhyve``.

::

   ...
   <bootloader>/usr/bin/pygrub</bootloader>
   <bootloader_args>--append single</bootloader_args>
   ...

``bootloader``
   The content of the ``bootloader`` element provides a fully qualified path to
   the bootloader executable in the host OS. This bootloader will be run to
   choose which kernel to boot. The required output of the bootloader is
   dependent on the hypervisor in use. :since:`Since 0.1.0`
``bootloader_args``
   The optional ``bootloader_args`` element allows command line arguments to be
   passed to the bootloader. :since:`Since 0.2.3`

Direct kernel boot
~~~~~~~~~~~~~~~~~~

When installing a new guest OS it is often useful to boot directly from a kernel
and initrd stored in the host OS, allowing command line arguments to be passed
directly to the installer. This capability is usually available for both para
and full virtualized guests.

::

   ...
   <os>
     <type>hvm</type>
     <loader>/usr/lib/xen/boot/hvmloader</loader>
     <kernel>/root/f8-i386-vmlinuz</kernel>
     <initrd>/root/f8-i386-initrd</initrd>
     <cmdline>console=ttyS0 ks=http://example.com/f8-i386/os/</cmdline>
     <dtb>/root/ppc.dtb</dtb>
   </os>
   ...

``type``
   This element has the same semantics as described earlier in the
   `BIOS bootloader`_ section.
``loader``
   This element has the same semantics as described earlier in the
   `BIOS bootloader`_ section.
``kernel``
   The contents of this element specify the fully-qualified path to the kernel
   image in the host OS.
``initrd``
   The contents of this element specify the fully-qualified path to the
   (optional) ramdisk image in the host OS.
``cmdline``
   The contents of this element specify arguments to be passed to the kernel (or
   installer) at boot time. This is often used to specify an alternate primary
   console (eg serial port), or the installation media source / kickstart file
``dtb``
   The contents of this element specify the fully-qualified path to the
   (optional) device tree binary (dtb) image in the host OS. :since:`Since
   1.0.4`

Container boot
~~~~~~~~~~~~~~

When booting a domain using container based virtualization, instead of a kernel
/ boot image, a path to the init binary is required, using the ``init`` element.
By default this will be launched with no arguments. To specify the initial argv,
use the ``initarg`` element, repeated as many time as is required. The
``cmdline`` element, if set will be used to provide an equivalent to
``/proc/cmdline`` but will not affect init argv.

To set environment variables, use the ``initenv`` element, one for each
variable.

To set a custom work directory for the init, use the ``initdir`` element.

To run the init command as a given user or group, use the ``inituser`` or
``initgroup`` elements respectively. Both elements can be provided either a user
(resp. group) id or a name. Prefixing the user or group id with a ``+`` will
force it to be considered like a numeric value. Without this, it will be first
tried as a user or group name.

::

   <os>
     <type arch='x86_64'>exe</type>
     <init>/bin/systemd</init>
     <initarg>--unit</initarg>
     <initarg>emergency.service</initarg>
     <initenv name='MYENV'>some value</initenv>
     <initdir>/my/custom/cwd</initdir>
     <inituser>tester</inituser>
     <initgroup>1000</initgroup>
   </os>

If you want to enable user namespace, set the ``idmap`` element. The ``uid`` and
``gid`` elements have three attributes:

``start``
   First user ID in container. It must be '0'.
``target``
   The first user ID in container will be mapped to this target user ID in host.
``count``
   How many users in container are allowed to map to host's user.

::

   <idmap>
     <uid start='0' target='1000' count='10'/>
     <gid start='0' target='1000' count='10'/>
   </idmap>

Common ``<os>`` element configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These options apply to any form of booting of the guest OS.

::

   ...
   <os>
     ...
     <acpi>
       <table type='slic'>/path/to/slic.dat</table>
     </acpi>
   </os>
   ...

``acpi``
   The ``table`` element contains a fully-qualified path to the ACPI table. The
   ``type`` attribute contains the ACPI table type (currently only ``slic`` is
   supported) :since:`Since 1.3.5 (QEMU)` :since:`Since 5.9.0 (Xen)`


SMBIOS System Information
-------------------------

Some hypervisors allow control over what system information is presented to the
guest (for example, SMBIOS fields can be populated by a hypervisor and inspected
via the ``dmidecode`` command in the guest). The optional ``sysinfo`` element
covers all such categories of information. :since:`Since 0.8.7`

::

   ...
   <os>
     <smbios mode='sysinfo'/>
     ...
   </os>
   <sysinfo type='smbios'>
     <bios>
       <entry name='vendor'>LENOVO</entry>
     </bios>
     <system>
       <entry name='manufacturer'>Fedora</entry>
       <entry name='product'>Virt-Manager</entry>
       <entry name='version'>0.9.4</entry>
     </system>
     <baseBoard>
       <entry name='manufacturer'>LENOVO</entry>
       <entry name='product'>20BE0061MC</entry>
       <entry name='version'>0B98401 Pro</entry>
       <entry name='serial'>W1KS427111E</entry>
     </baseBoard>
     <chassis>
       <entry name='manufacturer'>Dell Inc.</entry>
       <entry name='version'>2.12</entry>
       <entry name='serial'>65X0XF2</entry>
       <entry name='asset'>40000101</entry>
       <entry name='sku'>Type3Sku1</entry>
     </chassis>
     <oemStrings>
       <entry>myappname:some arbitrary data</entry>
       <entry>otherappname:more arbitrary data</entry>
     </oemStrings>
   </sysinfo>
   <sysinfo type='fwcfg'>
     <entry name='opt/com.example/name'>example value</entry>
     <entry name='opt/com.coreos/config' file='/tmp/provision.ign'/>
   </sysinfo>
   ...

The ``sysinfo`` element has a mandatory attribute ``type`` that determine the
layout of sub-elements, with supported values of:

``smbios``
   Sub-elements call out specific SMBIOS values, which will affect the guest if
   used in conjunction with the ``smbios`` sub-element of the ``os`` element
   (see `Operating system booting`_). Each sub-element of ``sysinfo`` names a SMBIOS
   block, and within those elements can be a list of ``entry`` elements that
   describe a field within the block. The following blocks and entries are
   recognized:

   ``bios``
      This is block 0 of SMBIOS, with entry names drawn from:

      ``vendor``
         BIOS Vendor's Name
      ``version``
         BIOS Version
      ``date``
         BIOS release date. If supplied, is in either mm/dd/yy or mm/dd/yyyy
         format. If the year portion of the string is two digits, the year is
         assumed to be 19yy.
      ``release``
         System BIOS Major and Minor release number values concatenated together
         as one string separated by a period, for example, 10.22.

   ``system``
      This is block 1 of SMBIOS, with entry names drawn from:

      ``manufacturer``
         Manufacturer of BIOS
      ``product``
         Product Name
      ``version``
         Version of the product
      ``serial``
         Serial number
      ``uuid``
         Universal Unique ID number. If this entry is provided alongside a
         top-level ``uuid`` element (see `General metadata`_), then the two
         values must match.
      ``sku``
         SKU number to identify a particular configuration.
      ``family``
         Identify the family a particular computer belongs to.

   ``baseBoard``
      This is block 2 of SMBIOS. This element can be repeated multiple times to
      describe all the base boards; however, not all hypervisors necessarily
      support the repetition. The element can have the following children:

      ``manufacturer``
         Manufacturer of BIOS
      ``product``
         Product Name
      ``version``
         Version of the product
      ``serial``
         Serial number
      ``asset``
         Asset tag
      ``location``
         Location in chassis

      NB: Incorrectly supplied entries for the ``bios``, ``system`` or
      ``baseBoard`` blocks will be ignored without error. Other than ``uuid``
      validation and ``date`` format checking, all values are passed as strings
      to the hypervisor driver.
   ``chassis``
      :since:`Since 4.1.0,` this is block 3 of SMBIOS, with entry names drawn
      from:

      ``manufacturer``
         Manufacturer of Chassis
      ``version``
         Version of the Chassis
      ``serial``
         Serial number
      ``asset``
         Asset tag
      ``sku``
         SKU number

   ``oemStrings``
      This is block 11 of SMBIOS. This element should appear once and can have
      multiple ``entry`` child elements, each providing arbitrary string data.
      There are no restrictions on what data can be provided in the entries,
      however, if the data is intended to be consumed by an application in the
      guest, it is recommended to use the application name as a prefix in the
      string. ( :since:`Since 4.1.0` )

``fwcfg``
   Some hypervisors provide unified way to tweak how firmware configures itself,
   or may contain tables to be installed for the guest OS, for instance boot
   order, ACPI, SMBIOS, etc.

   It even allows users to define their own config blobs. In case of QEMU,
   these then appear under domain's sysfs (if the guest kernel has FW_CFG_SYSFS
   config option enabled), under ``/sys/firmware/qemu_fw_cfg``. Note, that
   these values apply regardless the ``<smbios/>`` mode under ``<os/>``.
   :since:`Since 6.5.0`

   **Please note that because of limited number of data slots use of fwcfg is
   strongly discouraged and <oemStrings/> should be used instead**.

   ::

        <sysinfo type='fwcfg'>
          <entry name='opt/com.example/name'>example value</entry>
          <entry name='opt/com.example/config' file='/tmp/provision.ign'/>
        </sysinfo>

   The ``sysinfo`` element can have multiple ``entry`` child elements. Each
   element then has mandatory ``name`` attribute, which defines the name of the
   blob and must begin with ``opt/`` and to avoid clashing with other names is
   advised to be in form ``opt/$RFQDN/$name`` where ``$RFQDN`` is a reverse
   fully qualified domain name you control. Then, the element can either contain
   the value (to set the blob value directly), or ``file`` attribute (to set the
   blob value from the file).


CPU Allocation
--------------

::

   <domain>
     ...
     <vcpu placement='static' cpuset="1-4,^3,6" current="1">2</vcpu>
     <vcpus>
       <vcpu id='0' enabled='yes' hotpluggable='no' order='1'/>
       <vcpu id='1' enabled='no' hotpluggable='yes'/>
     </vcpus>
     ...
   </domain>

``vcpu``
   The content of this element defines the maximum number of virtual CPUs
   allocated for the guest OS, which must be between 1 and the maximum supported
   by the hypervisor.

   ``cpuset``
      The optional attribute ``cpuset`` is a comma-separated list of physical
      CPU numbers that domain process and virtual CPUs can be pinned to by
      default. (NB: The pinning policy of domain process and virtual CPUs can be
      specified separately by ``cputune``. If the attribute ``emulatorpin`` of
      ``cputune`` is specified, the ``cpuset`` specified by ``vcpu`` here will
      be ignored. Similarly, for virtual CPUs which have the ``vcpupin``
      specified, the ``cpuset`` specified by ``cpuset`` here will be ignored.
      For virtual CPUs which don't have ``vcpupin`` specified, each will be
      pinned to the physical CPUs specified by ``cpuset`` here). Each element in
      that list is either a single CPU number, a range of CPU numbers, or a
      caret followed by a CPU number to be excluded from a previous range.
      :since:`Since 0.4.4`
   ``current``
      The optional attribute ``current`` can be used to specify whether fewer
      than the maximum number of virtual CPUs should be enabled. :since:`Since
      0.8.5`
   ``placement``
      The optional attribute ``placement`` can be used to indicate the CPU
      placement mode for domain process. The value can be either "static" or
      "auto", but defaults to ``placement`` of ``numatune`` or "static" if
      ``cpuset`` is specified. Using "auto" indicates the domain process will be
      pinned to the advisory nodeset from querying numad and the value of
      attribute ``cpuset`` will be ignored if it's specified. If both ``cpuset``
      and ``placement`` are not specified or if ``placement`` is "static", but
      no ``cpuset`` is specified, the domain process will be pinned to all the
      available physical CPUs. :since:`Since 0.9.11 (QEMU and KVM only)`

``vcpus``
   The vcpus element allows to control state of individual vCPUs. The ``id``
   attribute specifies the vCPU id as used by libvirt in other places such as
   vCPU pinning, scheduler information and NUMA assignment. Note that the vCPU
   ID as seen in the guest may differ from libvirt ID in certain cases. Valid
   IDs are from 0 to the maximum vCPU count as set by the ``vcpu`` element minus
   1. The ``enabled`` attribute allows to control the state of the vCPU. Valid
   values are ``yes`` and ``no``. ``hotpluggable`` controls whether given vCPU
   can be hotplugged and hotunplugged in cases when the CPU is enabled at boot.
   Note that all disabled vCPUs must be hotpluggable. Valid values are ``yes``
   and ``no``. ``order`` allows to specify the order to add the online vCPUs.
   For hypervisors/platforms that require to insert multiple vCPUs at once the
   order may be duplicated across all vCPUs that need to be enabled at once.
   Specifying order is not necessary, vCPUs are then added in an arbitrary
   order. If order info is used, it must be used for all online vCPUs.
   Hypervisors may clear or update ordering information during certain
   operations to assure valid configuration. Note that hypervisors may create
   hotpluggable vCPUs differently from boot vCPUs thus special initialization
   may be necessary. Hypervisors may require that vCPUs enabled on boot which
   are not hotpluggable are clustered at the beginning starting with ID 0. It
   may be also required that vCPU 0 is always present and non-hotpluggable. Note
   that providing state for individual CPUs may be necessary to enable support
   of addressable vCPU hotplug and this feature may not be supported by all
   hypervisors. For QEMU the following conditions are required. vCPU 0 needs to
   be enabled and non-hotpluggable. On PPC64 along with it vCPUs that are in the
   same core need to be enabled as well. All non-hotpluggable CPUs present at
   boot need to be grouped after vCPU 0. :since:`Since 2.2.0 (QEMU only)`


IOThreads Allocation
--------------------

IOThreads are dedicated event loop threads for supported disk devices to perform
block I/O requests in order to improve scalability especially on an SMP
host/guest with many LUNs. :since:`Since 1.2.8 (QEMU only)`

::

   <domain>
     ...
     <iothreads>4</iothreads>
     ...
   </domain>

::

   <domain>
     ...
     <iothreadids>
       <iothread id="2"/>
       <iothread id="4"/>
       <iothread id="6"/>
       <iothread id="8" thread_pool_min="2" thread_pool_max="32">
         <poll max='123' grow='456' shrink='789'/>
       </iothread>
     </iothreadids>
     <defaultiothread thread_pool_min="8" thread_pool_max="16"/>
     ...
   </domain>

``iothreads``
   The content of this optional element defines the number of IOThreads to be
   assigned to the domain for use by supported target storage devices. There
   should be only 1 or 2 IOThreads per host CPU. There may be more than one
   supported device assigned to each IOThread. :since:`Since 1.2.8`
``iothreadids``
   The optional ``iothreadids`` element provides the capability to specifically
   define the IOThread ID's for the domain. By default, IOThread ID's are
   sequentially numbered starting from 1 through the number of ``iothreads``
   defined for the domain. The ``id`` attribute is used to define the IOThread
   ID. The ``id`` attribute must be a positive integer greater than 0. If there
   are less ``iothreadids`` defined than ``iothreads`` defined for the domain,
   then libvirt will sequentially fill ``iothreadids`` starting at 1 avoiding
   any predefined ``id``. If there are more ``iothreadids`` defined than
   ``iothreads`` defined for the domain, then the ``iothreads`` value will be
   adjusted accordingly. :since:`Since 1.2.15`
   The element has two optional attributes ``thread_pool_min`` and
   ``thread_pool_max`` which allow setting lower and upper boundary for number
   of worker threads for given IOThread. While the former can be value of zero,
   the latter can't. :since:`Since 8.5.0`
   :since:`Since 9.4.0` an optional sub-element ``poll`` with can be used to
   override the hypervisor-default interval of polling for the iothread before
   it switches back to events. The optional attribute ``max`` sets the maximum
   time polling should be used in nanoseconds. Setting ``max`` to ``0`` disables
   polling. Attributes ``grow`` and ``shrink`` override (or disable when set to
   ``0`` the default steps for increasing/decreasing the polling interval if
   the set interval is deemed insufficient or extensive.
``defaultiothread``
   This element represents the default event loop within hypervisor, where I/O
   requests from devices not assigned to a specific IOThread are processed.
   The element then can have ``thread_pool_min`` and/or ``thread_pool_max``
   attributes, which control the lower and upper boundary for number of worker
   threads of the default event loop. Emulator might be multithreaded and spawn
   so called worker threads on demand. In general neither of these attributes
   should be set (leaving the emulator use its own default values), unless the
   emulator runs in a real time workload and thus can't afford unpredictability
   of time it takes to spawn new worker threads. :since:`Since 8.5.0`


CPU Tuning
----------

::

   <domain>
     ...
     <cputune>
       <vcpupin vcpu="0" cpuset="1-4,^2"/>
       <vcpupin vcpu="1" cpuset="0,1"/>
       <vcpupin vcpu="2" cpuset="2,3"/>
       <vcpupin vcpu="3" cpuset="0,4"/>
       <emulatorpin cpuset="1-3"/>
       <iothreadpin iothread="1" cpuset="5,6"/>
       <iothreadpin iothread="2" cpuset="7,8"/>
       <shares>2048</shares>
       <period>1000000</period>
       <quota>-1</quota>
       <global_period>1000000</global_period>
       <global_quota>-1</global_quota>
       <emulator_period>1000000</emulator_period>
       <emulator_quota>-1</emulator_quota>
       <iothread_period>1000000</iothread_period>
       <iothread_quota>-1</iothread_quota>
       <vcpusched vcpus='0-4,^3' scheduler='fifo' priority='1'/>
       <iothreadsched iothreads='2' scheduler='batch'/>
       <cachetune vcpus='0-3'>
         <cache id='0' level='3' type='both' size='3' unit='MiB'/>
         <cache id='1' level='3' type='both' size='3' unit='MiB'/>
         <monitor level='3' vcpus='1'/>
         <monitor level='3' vcpus='0-3'/>
       </cachetune>
       <cachetune vcpus='4-5'>
         <monitor level='3' vcpus='4'/>
         <monitor level='3' vcpus='5'/>
       </cachetune>
       <memorytune vcpus='0-3'>
         <node id='0' bandwidth='60'/>
       </memorytune>

     </cputune>
     ...
   </domain>

``cputune``
   The optional ``cputune`` element provides details regarding the CPU tunable
   parameters for the domain. Note: for the qemu driver, the optional
   ``vcpupin`` and ``emulatorpin`` pinning settings are honored after the
   emulator is launched and NUMA constraints considered. This means that it is
   expected that other physical CPUs of the host will be used during this time
   by the domain, which will be reflected by the output of ``virsh cpu-stats``.
   :since:`Since 0.9.0`
``vcpupin``
   The optional ``vcpupin`` element specifies which of host's physical CPUs the
   domain vCPU will be pinned to. If this is omitted, and attribute ``cpuset``
   of element ``vcpu`` is not specified, the vCPU is pinned to all the physical
   CPUs by default. It contains two required attributes, the attribute ``vcpu``
   specifies vCPU id, and the attribute ``cpuset`` is same as attribute
   ``cpuset`` of element ``vcpu``.
   :since:`QEMU driver support since 0.9.0, Xen driver support since 0.9.1`
``emulatorpin``
   The optional ``emulatorpin`` element specifies which of host physical CPUs
   the "emulator", a subset of a domain not including vCPU or iothreads will be
   pinned to. If this is omitted, and attribute ``cpuset`` of element ``vcpu``
   is not specified, "emulator" is pinned to all the physical CPUs by default.
   It contains one required attribute ``cpuset`` specifying which physical CPUs
   to pin to.
``iothreadpin``
   The optional ``iothreadpin`` element specifies which of host physical CPUs
   the IOThreads will be pinned to. If this is omitted and attribute ``cpuset``
   of element ``vcpu`` is not specified, the IOThreads are pinned to all the
   physical CPUs by default. There are two required attributes, the attribute
   ``iothread`` specifies the IOThread ID and the attribute ``cpuset``
   specifying which physical CPUs to pin to. See the `IOThreads Allocation`_
   section documenting valid values of ``iothread``. :since:`Since 1.2.9`
``shares``
   The optional ``shares`` element specifies the proportional weighted share for
   the domain. If this is omitted, it defaults to the OS provided defaults. NB,
   There is no unit for the value, it's a relative measure based on the setting
   of other VM, e.g. A VM configured with value 2048 will get twice as much CPU
   time as a VM configured with value 1024. The value should be in range
   [2, 262144] using cgroups v1, [1, 10000] using cgroups v2. :since:`Since 0.9.0`
``period``
   The optional ``period`` element specifies the enforcement interval (unit:
   microseconds). Within ``period``, each vCPU of the domain will not be allowed
   to consume more than ``quota`` worth of runtime. The value should be in range
   [1000, 1000000]. A period with value 0 means no value. :since:`Only QEMU
   driver support since 0.9.4, LXC since 0.9.10`
``quota``
   The optional ``quota`` element specifies the maximum allowed bandwidth (unit:
   microseconds). A domain with ``quota`` as any negative value indicates that
   the domain has infinite bandwidth for vCPU threads, which means that it is
   not bandwidth controlled. The value should be in range [1000,
   17592186044415] or less than 0. A quota with value 0 means no value. You
   can use this feature to ensure that all vCPUs run at the same speed.
   :since:`Only QEMU driver support since 0.9.4, LXC since 0.9.10`
``global_period``
   The optional ``global_period`` element specifies the enforcement CFS
   scheduler interval (unit: microseconds) for the whole domain in contrast with
   ``period`` which enforces the interval per vCPU. The value should be in range
   1000, 1000000]. A ``global_period`` with value 0 means no value. :since:`Only
   QEMU driver support since 1.3.3`
``global_quota``
   The optional ``global_quota`` element specifies the maximum allowed bandwidth
   (unit: microseconds) within a period for the whole domain. A domain with
   ``global_quota`` as any negative value indicates that the domain has infinite
   bandwidth, which means that it is not bandwidth controlled. The value should
   be in range [1000, 17592186044415] or less than 0. A ``global_quota`` with
   value 0 means no value. :since:`Only QEMU driver support since 1.3.3`
``emulator_period``
   The optional ``emulator_period`` element specifies the enforcement interval
   (unit: microseconds). Within ``emulator_period``, emulator threads (those
   excluding vCPUs) of the domain will not be allowed to consume more than
   ``emulator_quota`` worth of runtime. The value should be in range [1000,
   1000000]. A period with value 0 means no value. :since:`Only QEMU driver
   support since 0.10.0`
``emulator_quota``
   The optional ``emulator_quota`` element specifies the maximum allowed
   bandwidth (unit: microseconds) for domain's emulator threads (those excluding
   vCPUs). A domain with ``emulator_quota`` as any negative value indicates that
   the domain has infinite bandwidth for emulator threads (those excluding
   vCPUs), which means that it is not bandwidth controlled. The value should be
   in range [1000, 17592186044415] or less than 0. A quota with value 0 means
   no value. :since:`Only QEMU driver support since 0.10.0`
``iothread_period``
   The optional ``iothread_period`` element specifies the enforcement interval
   (unit: microseconds) for IOThreads. Within ``iothread_period``, each IOThread
   of the domain will not be allowed to consume more than ``iothread_quota``
   worth of runtime. The value should be in range [1000, 1000000]. An
   iothread_period with value 0 means no value. :since:`Only QEMU driver support
   since 2.1.0`
``iothread_quota``
   The optional ``iothread_quota`` element specifies the maximum allowed
   bandwidth (unit: microseconds) for IOThreads. A domain with
   ``iothread_quota`` as any negative value indicates that the domain IOThreads
   have infinite bandwidth, which means that it is not bandwidth controlled. The
   value should be in range [1000, 17592186044415] or less than 0. An
   ``iothread_quota`` with value 0 means no value. You can use this feature to
   ensure that all IOThreads run at the same speed. :since:`Only QEMU driver
   support since 2.1.0`
``vcpusched``, ``iothreadsched`` and ``emulatorsched``
   The optional ``vcpusched``, ``iothreadsched`` and ``emulatorsched`` elements
   specify the scheduler type (values ``batch``, ``idle``, ``fifo``, ``rr``) for
   particular vCPU, IOThread and emulator threads respectively. For ``vcpusched``
   and ``iothreadsched`` the attributes ``vcpus`` and ``iothreads`` select which
   vCPUs/IOThreads this setting applies to, leaving them out sets the default.
   The element ``emulatorsched`` does not have that attribute. Valid ``vcpus``
   values start at 0 through one less than the number of vCPU's defined for the
   domain. Valid ``iothreads`` values are described in the `IOThreads Allocation`_
   section. If no ``iothreadids`` are
   defined, then libvirt numbers IOThreads from 1 to the number of ``iothreads``
   available for the domain. For real-time schedulers (``fifo``, ``rr``),
   priority must be specified as well (and is ignored for non-real-time ones).
   The value range for the priority depends on the host kernel (usually 1-99).
   :since:`Since 1.2.13` ``emulatorsched`` :since:`since 5.3.0`
``cachetune`` :since:`Since 4.1.0`
   Optional ``cachetune`` element can control allocations for CPU caches using
   the resctrl on the host. Whether or not is this supported can be gathered
   from capabilities where some limitations like minimum size and required
   granularity are reported as well. The required attribute ``vcpus`` specifies
   to which vCPUs this allocation applies. A vCPU can only be member of one
   ``cachetune`` element allocation. The vCPUs specified by cachetune can be
   identical with those in memorytune, however they are not allowed to overlap.
   The optional, output only ``id`` attribute identifies cache uniquely.
   Supported subelements are:

   ``cache``
      This optional element controls the allocation of CPU cache and has the
      following attributes:

      ``level``
         Host cache level from which to allocate.
      ``id``
         Host cache id from which to allocate.
      ``type``
         Type of allocation. Can be ``code`` for code (instructions), ``data``
         for data or ``both`` for both code and data (unified). Currently the
         allocation can be done only with the same type as the host supports,
         meaning you cannot request ``both`` for host with CDP (code/data
         prioritization) enabled.
      ``size``
         The size of the region to allocate. The value by default is in bytes,
         but the ``unit`` attribute can be used to scale the value.
      ``unit`` (optional)
         If specified it is the unit such as KiB, MiB, GiB, or TiB (described in
         the ``memory`` element for `Memory Allocation`_) in which ``size`` is
         specified, defaults to bytes.

   ``monitor`` :since:`Since 4.10.0`
      The optional element ``monitor`` creates the cache monitor(s) for current
      cache allocation and has the following required attributes:

      ``level``
         Host cache level the monitor belongs to.
      ``vcpus``
         vCPU list the monitor applies to. A monitor's vCPU list can only be the
         member(s) of the vCPU list of the associated allocation. The default
         monitor has the same vCPU list as the associated allocation. For
         non-default monitors, overlapping vCPUs are not permitted.

``memorytune`` :since:`Since 4.7.0`
   Optional ``memorytune`` element can control allocations for memory bandwidth
   using the resctrl on the host. Whether or not is this supported can be
   gathered from capabilities where some limitations like minimum bandwidth and
   required granularity are reported as well. The required attribute ``vcpus``
   specifies to which vCPUs this allocation applies. A vCPU can only be member
   of one ``memorytune`` element allocation. The ``vcpus`` specified by
   ``memorytune`` can be identical to those specified by ``cachetune``. However
   they are not allowed to overlap each other. Supported subelements are:

   ``node``
      This element controls the allocation of CPU memory bandwidth and has the
      following attributes:

      ``id``
         Host node id from which to allocate memory bandwidth.
      ``bandwidth``
         The memory bandwidth to allocate from this node. The value by default
         is in percentage.


Memory Allocation
-----------------

::

   <domain>
     ...
     <maxMemory slots='16' unit='KiB'>1524288</maxMemory>
     <memory unit='KiB'>524288</memory>
     <currentMemory unit='KiB'>524288</currentMemory>
     ...
   </domain>

``memory``
   The maximum allocation of memory for the guest at boot time. The memory
   allocation includes possible additional memory devices specified at start or
   hotplugged later. The units for this value are determined by the optional
   attribute ``unit``, which defaults to "KiB" (kibibytes, 2\ :sup:`10` or
   blocks of 1024 bytes). Valid units are "b" or "bytes" for bytes, "KB" for
   kilobytes (10\ :sup:`3` or 1,000 bytes), "k" or "KiB" for kibibytes (1024
   bytes), "MB" for megabytes (10\ :sup:`6` or 1,000,000 bytes), "M" or "MiB" for
   mebibytes (2\ :sup:`20` or 1,048,576 bytes), "GB" for gigabytes (10\ :sup:`9` or
   1,000,000,000 bytes), "G" or "GiB" for gibibytes (2\ :sup:`30` or 1,073,741,824
   bytes), "TB" for terabytes (10\ :sup:`12` or 1,000,000,000,000 bytes), or "T"
   or "TiB" for tebibytes (2\ :sup:`40` or 1,099,511,627,776 bytes). However, the
   value will be rounded up to the nearest kibibyte by libvirt, and may be
   further rounded to the granularity supported by the hypervisor. Some
   hypervisors also enforce a minimum, such as 4000KiB. In case NUMA is
   configured for the guest (See `CPU model and topology`_) the ``memory`` element
   can be omitted. In the case of crash, optional attribute ``dumpCore`` can be
   used to control whether the guest memory should be included in the generated
   coredump or not (values "on", "off"). ``unit`` :since:`since 0.9.11` ,
   ``dumpCore`` :since:`since 0.10.2 (QEMU only)`
``maxMemory``
   The run time maximum memory allocation of the guest. The initial memory
   specified by either the ``<memory>`` element or the NUMA cell size
   configuration can be increased by hot-plugging of memory to the limit
   specified by this element. The ``unit`` attribute behaves the same as for
   ``<memory>``. The ``slots`` attribute specifies the number of slots available
   for adding memory to the guest. The bounds are hypervisor specific. Note that
   due to alignment of the memory chunks added via memory hotplug the full size
   allocation specified by this element may be impossible to achieve.
   :since:`Since 1.2.14 supported by the QEMU driver.`
``currentMemory``
   The actual allocation of memory for the guest. This value can be less than
   the maximum allocation, to allow for ballooning up the guests memory on the
   fly. If this is omitted, it defaults to the same value as the ``memory``
   element. The ``unit`` attribute behaves the same as for ``memory``.


Memory Backing
--------------

::

   <domain>
     ...
     <memoryBacking>
       <hugepages>
         <page size="1" unit="G" nodeset="0-3,5"/>
         <page size="2" unit="M" nodeset="4"/>
       </hugepages>
       <nosharepages/>
       <locked/>
       <source type="file|anonymous|memfd"/>
       <access mode="shared|private"/>
       <allocation mode="immediate|ondemand" threads='8'/>
       <discard/>
     </memoryBacking>
     ...
   </domain>

The optional ``memoryBacking`` element may contain several elements that
influence how virtual memory pages are backed by host pages.

``hugepages``
   This tells the hypervisor that the guest should have its memory allocated
   using hugepages instead of the normal native page size. :since:`Since 1.2.5`
   it's possible to set hugepages more specifically per numa node. The ``page``
   element is introduced. It has one compulsory attribute ``size`` which
   specifies which hugepages should be used (especially useful on systems
   supporting hugepages of different sizes). The default unit for the ``size``
   attribute is kilobytes (multiplier of 1024). If you want to use different
   unit, use optional ``unit`` attribute. For systems with NUMA, the optional
   ``nodeset`` attribute may come handy as it ties given guest's NUMA nodes to
   certain hugepage sizes. From the example snippet, one gigabyte hugepages are
   used for every NUMA node except node number four. For the correct syntax see
   `NUMA Node Tuning`_.
``nosharepages``
   Instructs hypervisor to disable shared pages (memory merge, KSM) for this
   domain. :since:`Since 1.0.6`
``locked``
   When set and supported by the hypervisor, memory pages belonging to the
   domain will be locked in host's memory and the host will not be allowed to
   swap them out, which might be required for some workloads such as real-time.
   For QEMU/KVM guests, the memory used by the QEMU process itself will be
   locked too: unlike guest memory, this is an amount libvirt has no way of
   figuring out in advance, so it has to remove the limit on locked memory
   altogether. Thus, enabling this option opens up to a potential security risk:
   the host will be unable to reclaim the locked memory back from the guest when
   it's running out of memory, which means a malicious guest allocating large
   amounts of locked memory could cause a denial-of-service attack on the host.
   Because of this, using this option is discouraged unless your workload
   demands it; even then, it's highly recommended to set a ``hard_limit`` (see
   `Memory Tuning`_) on memory allocation suitable for
   the specific environment at the same time to mitigate the risks described
   above. :since:`Since 1.0.6`
``source``
   Using the ``type`` attribute, it's possible to provide "file" to utilize file
   memorybacking or keep the default "anonymous". :since:`Since 4.10.0` , you
   may choose "memfd" backing. (QEMU/KVM only)
``access``
   Using the ``mode`` attribute, specify if the memory is to be "shared" or
   "private". This can be overridden per numa node by ``memAccess``.
``allocation``
   Using the optional ``mode`` attribute, specify when to allocate the memory by
   supplying either "immediate" or "ondemand". :since:`Since 8.2.0` it is
   possible to set the number of threads that hypervisor uses to allocate
   memory via ``threads`` attribute. To speed allocation process up, when
   pinning emulator thread it's recommended to include CPUs from desired NUMA
   nodes so that allocation threads can have their affinity set.
``discard``
   When set and supported by hypervisor the memory content is discarded just
   before guest shuts down (or when DIMM module is unplugged). Please note that
   this is just an optimization and is not guaranteed to work in all cases (e.g.
   when hypervisor crashes). :since:`Since 4.4.0` (QEMU/KVM only)


Memory Tuning
-------------

::

   <domain>
     ...
     <memtune>
       <hard_limit unit='G'>1</hard_limit>
       <soft_limit unit='M'>128</soft_limit>
       <swap_hard_limit unit='G'>2</swap_hard_limit>
       <min_guarantee unit='bytes'>67108864</min_guarantee>
     </memtune>
     ...
   </domain>

``memtune``
   The optional ``memtune`` element provides details regarding the memory
   tunable parameters for the domain. If this is omitted, it defaults to the OS
   provided defaults. For QEMU/KVM, the parameters are applied to the QEMU
   process as a whole. Thus, when counting them, one needs to add up guest RAM,
   guest video RAM, and some memory overhead of QEMU itself. The last piece is
   hard to determine so one needs guess and try. For each tunable, it is
   possible to designate which unit the number is in on input, using the same
   values as for ``<memory>``. For backwards compatibility, output is always in
   KiB. ``unit`` :since:`since 0.9.11` Possible values for all \*_limit
   parameters are in range from 0 to VIR_DOMAIN_MEMORY_PARAM_UNLIMITED.
``hard_limit``
   The optional ``hard_limit`` element is the maximum memory the guest can use.
   The units for this value are kibibytes (i.e. blocks of 1024 bytes). Users of
   QEMU and KVM are strongly advised not to set this limit as domain may get
   killed by the kernel if the guess is too low, and determining the memory
   needed for a process to run is an `undecidable
   problem <https://en.wikipedia.org/wiki/Undecidable_problem>`__; that said, if
   you already set ``locked`` in `Memory Backing`_
   because your workload demands it, you'll have to take into account the
   specifics of your deployment and figure out a value for ``hard_limit`` that
   is large enough to support the memory requirements of your guest, but small
   enough to protect your host against a malicious guest locking all memory.
``soft_limit``
   The optional ``soft_limit`` element is the memory limit to enforce during
   memory contention. The units for this value are kibibytes (i.e. blocks of
   1024 bytes)
``swap_hard_limit``
   The optional ``swap_hard_limit`` element is the maximum memory plus swap the
   guest can use. The units for this value are kibibytes (i.e. blocks of 1024
   bytes). This has to be more than hard_limit value provided
``min_guarantee``
   The optional ``min_guarantee`` element is the guaranteed minimum memory
   allocation for the guest. The units for this value are kibibytes (i.e. blocks
   of 1024 bytes). This element is only supported by VMware ESX and OpenVZ
   drivers.


NUMA Node Tuning
----------------

::

   <domain>
     ...
     <numatune>
       <memory mode="strict" nodeset="1-4,^3"/>
       <memnode cellid="0" mode="strict" nodeset="1"/>
       <memnode cellid="2" mode="preferred" nodeset="2"/>
     </numatune>
     ...
   </domain>

``numatune``
   The optional ``numatune`` element provides details of how to tune the
   performance of a NUMA host via controlling NUMA policy for domain process.
   NB, only supported by QEMU driver. :since:`Since 0.9.3`
``memory``
   The optional ``memory`` element specifies how to allocate memory for the
   domain process on a NUMA host. It contains several optional attributes.
   Attribute ``mode`` is either 'interleave', 'strict', 'preferred', or
   'restrictive', defaults to 'strict'. The value 'restrictive' specifies
   using system default policy and only cgroups is used to restrict the
   memory nodes, and it requires setting mode to 'restrictive' in ``memnode``
   elements (see quirk below).  This exists solely for the purpose of being able
   to request movement of such memory for a running domain using ``virsh
   numatune`` or ``virDomainSetNumaParameters`` and is not guaranteed to happen.
   Attribute ``nodeset`` specifies the NUMA nodes, using the same
   syntax as attribute ``cpuset`` of element ``vcpu``. Attribute ``placement`` (
   :since:`since 0.9.12` ) can be used to indicate the memory placement mode for
   domain process, its value can be either "static" or "auto", defaults to
   ``placement`` of ``vcpu``, or "static" if ``nodeset`` is specified. "auto"
   indicates the domain process will only allocate memory from the advisory
   nodeset returned from querying numad, and the value of attribute ``nodeset``
   will be ignored if it's specified. If ``placement`` of ``vcpu`` is 'auto',
   and ``numatune`` is not specified, a default ``numatune`` with ``placement``
   'auto' and ``mode`` 'strict' will be added implicitly. :since:`Since 0.9.3`
   See `virDomainSetNumaParameters
   <html/libvirt-libvirt-domain.html#virDomainSetNumaParameters>`__ for more
   information on update of this element.
``memnode``
   Optional ``memnode`` elements can specify memory allocation policies per each
   guest NUMA node. For those nodes having no corresponding ``memnode`` element,
   the default from element ``memory`` will be used. Attribute ``cellid``
   addresses guest NUMA node for which the settings are applied. Attributes
   ``mode`` and ``nodeset`` have the same meaning and syntax as in ``memory``
   element. This setting is not compatible with automatic placement.
   Note that for ``memnode`` this will only guide the memory access for the vCPU
   threads or similar mechanism and is very hypervisor-specific.  This does not
   guarantee the placement of the node's memory allocation.  For proper
   restriction other means should be used (e.g. different mode, preallocated
   hugepages).

   :since:`QEMU Since 1.2.7`


Block I/O Tuning
----------------

::

   <domain>
     ...
     <blkiotune>
       <weight>800</weight>
       <device>
         <path>/dev/sda</path>
         <weight>1000</weight>
       </device>
       <device>
         <path>/dev/sdb</path>
         <weight>500</weight>
         <read_bytes_sec>10000</read_bytes_sec>
         <write_bytes_sec>10000</write_bytes_sec>
         <read_iops_sec>20000</read_iops_sec>
         <write_iops_sec>20000</write_iops_sec>
       </device>
     </blkiotune>
     ...
   </domain>

``blkiotune``
   The optional ``blkiotune`` element provides the ability to tune Blkio cgroup
   tunable parameters for the domain. If this is omitted, it defaults to the OS
   provided defaults. :since:`Since 0.8.8`
``weight``
   The optional ``weight`` element is the overall I/O weight of the guest. The
   value should be in the range [100, 1000]. After kernel 2.6.39, the value
   could be in the range [10, 1000].
``device``
   The domain may have multiple ``device`` elements that further tune the
   weights for each host block device in use by the domain. Note that multiple
   disks (See `Hard drives, floppy disks, CDROMs`_) can share a single host
   block device, if they are backed by files within the same host file system,
   which is why this tuning parameter is at the global domain level rather than
   associated with each guest disk device (contrast this to the <iotune>
   element of a disk definition (See `Hard drives, floppy disks, CDROMs`_)
   which can applies to an individual disk).  Each ``device`` element has
   two mandatory sub-elements, ``path`` describing the absolute path of the
   device, and ``weight`` giving the relative weight of that device, in the
   range [100, 1000]. After kernel 2.6.39, the value could be in the range [10,
   1000]. :since:`Since 0.9.8`
   Additionally, the following optional sub-elements can be used:

   ``read_bytes_sec``
      Read throughput limit in bytes per second. :since:`Since 1.2.2`
   ``write_bytes_sec``
      Write throughput limit in bytes per second. :since:`Since 1.2.2`
   ``read_iops_sec``
      Read I/O operations per second limit. :since:`Since 1.2.2`
   ``write_iops_sec``
      Write I/O operations per second limit. :since:`Since 1.2.2`

Resource partitioning
---------------------

Hypervisors may allow for virtual machines to be placed into resource
partitions, potentially with nesting of said partitions. The ``resource``
element groups together configuration related to resource partitioning. It
currently supports a child element ``partition`` whose content defines the
absolute path of the resource partition in which to place the domain. If no
partition is listed, then the domain will be placed in a default partition. It
is the responsibility of the app/admin to ensure that the partition exists prior
to starting the guest. Only the (hypervisor specific) default partition can be
assumed to exist by default.

::

   ...
   <resource>
     <partition>/virtualmachines/production</partition>
   </resource>
   ...

Resource partitions are currently supported by the QEMU and LXC drivers, which
map partition paths to cgroups directories, in all mounted controllers.
:since:`Since 1.0.5`

Fibre Channel VMID
-------------------

The FC SAN can provide various QoS levels and access control depending on the
VMID. It can also collect telemetry data at per-VM level which can be used
to enhance the IO performance of the VM. This can be configured by using
the ``appid`` attribute of ``fibrechannel`` element. The attribute contains
single string (max 128 bytes) and it is used by kernel to create VMID.

::

   ...
   <resource>
     <fibrechannel appid='userProvidedID'/>
   </resource>
   ...

Using this feature requires Fibre Channel capable HW, kernel compiled with
option ``CONFIG_BLK_CGROUP_FC_APPID`` and ``nvme_fc`` kernel module loaded.
:since:`Since 7.7.0`


CPU model and topology
----------------------

Requirements for CPU model, its features and topology can be specified using the
following collection of elements. :since:`Since 0.7.5`

::

   ...
   <cpu match='exact'>
     <model fallback='allow'>core2duo</model>
     <vendor>Intel</vendor>
     <topology sockets='1' dies='1' cores='2' threads='1'/>
     <cache level='3' mode='emulate'/>
     <maxphysaddr mode='emulate' bits='42'/>
     <feature policy='disable' name='lahf_lm'/>
   </cpu>
   ...

::

   <cpu mode='host-model'>
     <model fallback='forbid'/>
     <topology sockets='1' dies='1' cores='2' threads='1'/>
   </cpu>
   ...

::

   <cpu mode='host-passthrough' migratable='off'>
     <cache mode='passthrough'/>
     <maxphysaddr mode='passthrough' limit='39'/>
     <feature policy='disable' name='lahf_lm'/>
   ...

::

   <cpu mode='maximum' migratable='off'>
     <cache mode='passthrough'/>
     <feature policy='disable' name='lahf_lm'/>
   ...

In case no restrictions need to be put on CPU model and its features, a simpler
``cpu`` element can be used. :since:`Since 0.7.6`

::

   ...
   <cpu>
     <topology sockets='1' dies='1' cores='2' threads='1'/>
   </cpu>
   ...

``cpu``
   The ``cpu`` element is the main container for describing guest CPU
   requirements. Its ``match`` attribute specifies how strictly the virtual CPU
   provided to the guest matches these requirements. :since:`Since 0.7.6` the
   ``match`` attribute can be omitted if ``topology`` is the only element within
   ``cpu``. Possible values for the ``match`` attribute are:

   ``minimum``
      The specified CPU model and features describes the minimum requested CPU.
      A better CPU will be provided to the guest if it is possible with the
      requested hypervisor on the current host. This is a constrained
      ``host-model`` mode; the domain will not be created if the provided
      virtual CPU does not meet the requirements.
   ``exact``
      The virtual CPU provided to the guest should exactly match the
      specification. If such CPU is not supported, libvirt will refuse to start
      the domain.
   ``strict``
      The domain will not be created unless the host CPU exactly matches the
      specification. This is not very useful in practice and should only be used
      if there is a real reason.

   :since:`Since 0.8.5` the ``match`` attribute can be omitted and will default
   to ``exact``. Sometimes the hypervisor is not able to create a virtual CPU
   exactly matching the specification passed by libvirt. :since:`Since 3.2.0` ,
   an optional ``check`` attribute can be used to request a specific way of
   checking whether the virtual CPU matches the specification. It is usually
   safe to omit this attribute when starting a domain and stick with the default
   value. Once the domain starts, libvirt will automatically change the
   ``check`` attribute to the best supported value to ensure the virtual CPU
   does not change when the domain is migrated to another host. The following
   values can be used:

   ``none``
      Libvirt does no checking and it is up to the hypervisor to refuse to start
      the domain if it cannot provide the requested CPU. With QEMU this means no
      checking is done at all since the default behavior of QEMU is to emit
      warnings, but start the domain anyway.
   ``partial``
      Libvirt will check the guest CPU specification before starting a domain,
      but the rest is left on the hypervisor. It can still provide a different
      virtual CPU.
   ``full``
      The virtual CPU created by the hypervisor will be checked against the CPU
      specification and the domain will not be started unless the two CPUs
      match.

   :since:`Since 0.9.10` , an optional ``mode`` attribute may be used to make it
   easier to configure a guest CPU to be as close to host CPU as possible.
   Possible values for the ``mode`` attribute are:

   ``custom``
      In this mode, the ``cpu`` element describes the CPU that should be
      presented to the guest. This is the default when no ``mode`` attribute is
      specified. This mode makes it so that a persistent guest will see the same
      hardware no matter what host the guest is booted on.
   ``host-model``
      The ``host-model`` mode is essentially a shortcut to copying host CPU
      definition from capabilities XML into domain XML. Since the CPU definition
      is copied just before starting a domain, exactly the same XML can be used
      on different hosts while still providing the best guest CPU each host
      supports. The ``match`` attribute can't be used in this mode. Specifying
      CPU model is not supported either, but ``model``'s ``fallback`` attribute
      may still be used. Using the ``feature`` element, specific flags may be
      enabled or disabled specifically in addition to the host model. This may
      be used to fine tune features that can be emulated. :since:`(Since 1.1.1)`
      . Libvirt does not model every aspect of each CPU so the guest CPU will
      not match the host CPU exactly. On the other hand, the ABI provided to the
      guest is reproducible. During migration, complete CPU model definition is
      transferred to the destination host so the migrated guest will see exactly
      the same CPU model for the running instance of the guest, even if the
      destination host contains more capable CPUs or newer kernel; but shutting
      down and restarting the guest may present different hardware to the guest
      according to the capabilities of the new host. Prior to libvirt 3.2.0 and
      QEMU 2.9.0 detection of the host CPU model via QEMU is not supported. Thus
      the CPU configuration created using ``host-model`` may not work as
      expected. :since:`Since 3.2.0 and QEMU 2.9.0` this mode works the way it
      was designed and it is indicated by the ``fallback`` attribute set to
      ``forbid`` in the host-model CPU definition advertised in `domain
      capabilities XML <formatdomaincaps.html#cpu-configuration>`__. When
      ``fallback`` attribute is set to ``allow`` in the domain capabilities
      XML, it is recommended to use ``custom`` mode with just the CPU model
      from the host capabilities XML. :since:`Since 1.2.11` PowerISA allows
      processors to run VMs in binary compatibility mode supporting an older
      version of ISA.  Libvirt on PowerPC architecture uses the ``host-model``
      to signify a guest mode CPU running in binary compatibility mode.
      Example: When a user needs a power7 VM to run in compatibility mode on a
      Power8 host, this can be described in XML as follows :

      ::

         <cpu mode='host-model'>
           <model>power7</model>
         </cpu>
         ...

   ``host-passthrough``
      With this mode, the CPU visible to the guest should be exactly the same as
      the host CPU even in the aspects that libvirt does not understand. Though
      the downside of this mode is that the guest environment cannot be
      reproduced on different hardware. Thus, if you hit any bugs, you are on
      your own. Further details of that CPU can be changed using ``feature``
      elements. Migration of a guest using host-passthrough is dangerous if the
      source and destination hosts are not identical in both hardware, QEMU
      version, microcode version and configuration. If such a migration is
      attempted then the guest may hang or crash upon resuming execution on the
      destination host. Depending on hypervisor version the virtual CPU may or
      may not contain features which may block migration even to an identical
      host. :since:`Since 6.5.0` optional ``migratable`` attribute may be used
      to explicitly request such features to be removed from (``on``) or kept in
      (``off``) the virtual CPU. This attribute does not make migration to
      another host safer: even with ``migratable='on'`` migration will be
      dangerous unless both hosts are identical as described above.

   ``maximum``
      When running a guest with hardware virtualization this CPU model is
      functionally identical to ``host-passthrough``, so refer to the docs
      above.

      When running a guest with CPU emulation, this CPU model will enable
      the maximum set of features that the emulation engine is able to support.
      Note that even with ``migratable='on'`` migration will be dangerous
      unless both hosts are running identical versions of the emulation code.

      :since:`Since 7.1.0` with the QEMU driver.

   Both ``host-model`` and ``host-passthrough`` modes make sense when a domain
   can run directly on the host CPUs (for example, domains with type ``kvm``
   or ``hvf``).
   The actual host CPU is irrelevant for domains with emulated virtual CPUs
   (such as domains with type ``qemu``). However, for backward compatibility
   ``host-model`` may be implemented even for domains running on emulated CPUs
   in which case the best CPU the hypervisor is able to emulate may be used
   rather then trying to mimic the host CPU model.

   If an application does not care about a specific CPU, just wants the
   best feature set without a need for migration compatibility, the
   ``maximum`` model is a good choice on hypervisors where it is available.

``model``
   The content of the ``model`` element specifies CPU model requested by the
   guest. The list of available CPU models and their definition can be found in
   directory ``cpu_map``, installed in libvirt's data directory. If a hypervisor
   is not able to use the exact CPU model, libvirt automatically falls back to a
   closest model supported by the hypervisor while maintaining the list of CPU
   features. :since:`Since 0.9.10` , an optional ``fallback`` attribute can be
   used to forbid this behavior, in which case an attempt to start a domain
   requesting an unsupported CPU model will fail. Supported values for
   ``fallback`` attribute are: ``allow`` (this is the default), and ``forbid``.
   The optional ``vendor_id`` attribute ( :since:`Since 0.10.0` ) can be used to
   set the vendor id seen by the guest. It must be exactly 12 characters long.
   If not set the vendor id of the host is used. Typical possible values are
   "AuthenticAMD" and "GenuineIntel".
``vendor``
   :since:`Since 0.8.3` the content of the ``vendor`` element specifies CPU
   vendor requested by the guest. If this element is missing, the guest can be
   run on a CPU matching given features regardless on its vendor. The list of
   supported vendors can be found in ``cpu_map/*_vendors.xml``.
``topology``
   The ``topology`` element specifies requested topology of virtual CPU provided
   to the guest. Four attributes, ``sockets``, ``dies``, ``cores``, and
   ``threads``, accept non-zero positive integer values. They refer to the
   total number of CPU sockets, number of dies per socket, number of cores per
   die, and number of threads per core, respectively. The ``dies`` attribute is
   optional and will default to 1 if omitted, while the other attributes are all
   mandatory. Hypervisors may require that the maximum number of vCPUs specified
   by the ``cpus`` element equals to the number of vcpus resulting from the
   topology.
``feature``
   The ``cpu`` element can contain zero or more ``feature`` elements used to
   fine-tune features provided by the selected CPU model. The list of known
   feature names can be found in the same file as CPU models. The meaning of
   each ``feature`` element depends on its ``policy`` attribute, which has to be
   set to one of the following values:

   ``force``
      The virtual CPU will claim the feature is supported regardless of it being
      supported by host CPU.
   ``require``
      Guest creation will fail unless the feature is supported by the host CPU
      or the hypervisor is able to emulate it.
   ``optional``
      The feature will be supported by virtual CPU if and only if it is
      supported by host CPU.
   ``disable``
      The feature will not be supported by virtual CPU.
   ``forbid``
      Guest creation will fail if the feature is supported by host CPU.

   :since:`Since 0.8.5` the ``policy`` attribute can be omitted and will default
   to ``require``.

   Individual CPU feature names are specified as part of the ``name`` attribute.
   For example, to explicitly specify the 'pcid' feature with Intel IvyBridge
   CPU model:

   ::

      ...
      <cpu match='exact'>
        <model fallback='forbid'>IvyBridge</model>
        <vendor>Intel</vendor>
        <feature policy='require' name='pcid'/>
      </cpu>
      ...

``cache``
   :since:`Since 3.3.0` the ``cache`` element describes the virtual CPU cache.
   If the element is missing, the hypervisor will use a sensible default.

   ``level``
      This optional attribute specifies which cache level is described by the
      element. Missing attribute means the element describes all CPU cache
      levels at once. Mixing ``cache`` elements with the ``level`` attribute set
      and those without the attribute is forbidden.
   ``mode``
      The following values are supported:

      ``emulate``
         The hypervisor will provide a fake CPU cache data.
      ``passthrough``
         The real CPU cache data reported by the host CPU will be passed through
         to the virtual CPU.
      ``disable``
         The virtual CPU will report no CPU cache of the specified level (or no
         cache at all if the ``level`` attribute is missing).

``maxphysaddr``
   :since:`Since 8.7.0` the ``maxphysaddr`` element describes the virtual CPU
   address size in bits. The hypervisor default is used if the element is missing.

   ``mode``
      This mandatory attribute specifies how the address size is presented. The
      follow modes are supported:

      ``passthrough``
         The number of physical address bits reported by the host CPU will be
         passed through to the virtual CPUs
      ``emulate``
         The hypervisor will define a specific value for the number of bits
         of physical addresses via the ``bits`` attribute, (optional
         :since:`since 9.2.0`)
	 The number of bits cannot exceed the number of physical address bits
	 supported by the hypervisor.

   ``bits``
      The ``bits`` attribute is mandatory if the ``mode`` attribute is set to
      ``emulate`` and specifies the virtual CPU address size in bits.

   ``limit``
     The ``limit`` attribute can be used to restrict the maximum value of
     address bits for ``passthrough`` mode, i.e. in case the host CPU reports
     more bits than that, ``limit`` is used. :since:`Since 9.3.0`

Guest NUMA topology can be specified using the ``numa`` element. :since:`Since
0.9.8`

::

   ...
   <cpu>
     ...
     <numa>
       <cell id='0' cpus='0-3' memory='512000' unit='KiB' discard='yes'/>
       <cell id='1' cpus='4-7' memory='512000' unit='KiB' memAccess='shared'/>
     </numa>
     ...
   </cpu>
   ...

Each ``cell`` element specifies a NUMA cell or a NUMA node. ``cpus`` specifies
the CPU or range of CPUs that are part of the node. :since:`Since 6.5.0` For the
qemu driver, if the emulator binary supports disjointed ``cpus`` ranges in each
``cell``, the sum of all CPUs declared in each ``cell`` will be matched with the
maximum number of virtual CPUs declared in the ``vcpu`` element. This is done by
filling any remaining CPUs into the first NUMA ``cell``. Users are encouraged to
supply a complete NUMA topology, where the sum of the NUMA CPUs matches the
maximum virtual CPUs number declared in ``vcpus``, to make the domain consistent
across qemu and libvirt versions. ``memory`` specifies the node memory in
kibibytes (i.e. blocks of 1024 bytes). :since:`Since 6.6.0` the ``cpus``
attribute is optional and if omitted a CPU-less NUMA node is created.
:since:`Since 1.2.11` one can use an additional ``unit`` attribute
(See `Memory Allocation`_) to define units in which
``memory`` is specified. :since:`Since 1.2.7` all cells should have ``id``
attribute in case referring to some cell is necessary in the code, otherwise the
cells are assigned ``id``\ s in the increasing order starting from 0. Mixing
cells with and without the ``id`` attribute is not recommended as it may result
in unwanted behaviour. :since:`Since 1.2.9` the optional attribute ``memAccess``
can control whether the memory is to be mapped as "shared" or "private". This is
valid only for hugepages-backed memory and nvdimm modules. Each ``cell`` element
can have an optional ``discard`` attribute which fine tunes the discard feature
for given numa node as described under `Memory Backing`_.
Accepted values are ``yes`` and ``no``.
:since:`Since 4.4.0`

This guest NUMA specification is currently available only for QEMU/KVM and Xen.

A NUMA hardware architecture supports the notion of distances between NUMA
cells. :since:`Since 3.10.0` it is possible to define the distance between NUMA
cells using the ``distances`` element within a NUMA ``cell`` description. The
``sibling`` sub-element is used to specify the distance value between sibling
NUMA cells. For more details, see the chapter explaining the system's SLIT
(System Locality Information Table) within the ACPI (Advanced Configuration and
Power Interface) specification.

::

   ...
   <cpu>
     ...
     <numa>
       <cell id='0' cpus='0,4-7' memory='512000' unit='KiB'>
         <distances>
           <sibling id='0' value='10'/>
           <sibling id='1' value='21'/>
           <sibling id='2' value='31'/>
           <sibling id='3' value='41'/>
         </distances>
       </cell>
       <cell id='1' cpus='1,8-10,12-15' memory='512000' unit='KiB' memAccess='shared'>
         <distances>
           <sibling id='0' value='21'/>
           <sibling id='1' value='10'/>
           <sibling id='2' value='21'/>
           <sibling id='3' value='31'/>
         </distances>
       </cell>
       <cell id='2' cpus='2,11' memory='512000' unit='KiB' memAccess='shared'>
         <distances>
           <sibling id='0' value='31'/>
           <sibling id='1' value='21'/>
           <sibling id='2' value='10'/>
           <sibling id='3' value='21'/>
         </distances>
       </cell>
       <cell id='3' cpus='3' memory='512000' unit='KiB'>
         <distances>
           <sibling id='0' value='41'/>
           <sibling id='1' value='31'/>
           <sibling id='2' value='21'/>
           <sibling id='3' value='10'/>
         </distances>
       </cell>
     </numa>
     ...
   </cpu>
   ...

Describing distances between NUMA cells is currently only supported by Xen and
QEMU. If no ``distances`` are given to describe the SLIT data between different
cells, it will default to a scheme using 10 for local and 20 for remote
distances.


ACPI Heterogeneous Memory Attribute Table
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   ...
   <cpu>
     ...
     <numa>
       <cell id='0' cpus='0-3' memory='2097152' unit='KiB' discard='yes'>
         <cache level='1' associativity='direct' policy='writeback'>
           <size value='10' unit='KiB'/>
           <line value='8' unit='B'/>
         </cache>
       </cell>
       <cell id='1' cpus='4-7' memory='512000' unit='KiB' memAccess='shared'/>
       <interconnects>
         <latency initiator='0' target='0' type='access' value='5'/>
         <latency initiator='0' target='0' cache='1' type='access' value='10'/>
         <bandwidth initiator='0' target='0' type='access' value='204800' unit='KiB'/>
       </interconnects>
     </numa>
     ...
   </cpu>
   ...

:since:`Since 6.6.0` the ``cell`` element can have a ``cache`` child element
which describes memory side cache for memory proximity domains. The ``cache``
element has a ``level`` attribute describing the cache level and thus the
element can be repeated multiple times to describe different levels of the
cache.

The ``cache`` element then has following mandatory attributes:

``level``
   Level of the cache this description refers to.
``associativity``
   Describes cache associativity (accepted values are ``none``, ``direct`` and
   ``full``).
``policy``
   Describes cache write associativity (accepted values are ``none``,
   ``writeback`` and ``writethrough``).

The ``cache`` element has two mandatory child elements then: ``size`` and
``line`` which describe cache size and cache line size. Both elements accept two
attributes: ``value`` and ``unit`` which set the value of corresponding cache
attribute.

The NUMA description has an optional ``interconnects`` element that describes
the normalized memory read/write latency, read/write bandwidth between Initiator
Proximity Domains (Processor or I/O) and Target Proximity Domains (Memory).

The ``interconnects`` element can have zero or more ``latency`` child elements
to describe latency between two memory nodes and zero or more ``bandwidth``
child elements to describe bandwidth between two memory nodes. Both these have
the following mandatory attributes:

``initiator``
   Refers to the source NUMA node
``target``
   Refers to the target NUMA node
``type``
   The type of the access. Accepted values: ``access``, ``read``, ``write``
``value``
   The actual value. For latency this is delay in nanoseconds, for bandwidth
   this value is in kibibytes per second. Use additional ``unit`` attribute to
   change the units.

To describe latency from one NUMA node to a cache of another NUMA node the
``latency`` element has optional ``cache`` attribute which in combination with
``target`` attribute creates full reference to distant NUMA node's cache level.
For instance, ``target='0' cache='1'`` refers to the first level cache of NUMA
node 0.


Events configuration
--------------------

It is sometimes necessary to override the default actions taken on various
events. Not all hypervisors support all events and actions. The actions may be
taken as a result of calls to libvirt APIs
`virDomainReboot <html/libvirt-libvirt-domain.html#virDomainReboot>`__ ,
`virDomainShutdown <html/libvirt-libvirt-domain.html#virDomainShutdown>`__ , or
`virDomainShutdownFlags <html/libvirt-libvirt-domain.html#virDomainShutdownFlags>`__
. Using ``virsh reboot`` or ``virsh shutdown`` would also trigger the event.

::

   ...
   <on_poweroff>destroy</on_poweroff>
   <on_reboot>restart</on_reboot>
   <on_crash>restart</on_crash>
   <on_lockfailure>poweroff</on_lockfailure>
   ...

The following collections of elements allow the actions to be specified when a
guest OS triggers a lifecycle operation. A common use case is to force a reboot
to be treated as a poweroff when doing the initial OS installation. This allows
the VM to be re-configured for the first post-install bootup.

``on_poweroff``
   The content of this element specifies the action to take when the guest
   requests a poweroff.
``on_reboot``
   The content of this element specifies the action to take when the guest
   requests a reboot.
``on_crash``
   The content of this element specifies the action to take when the guest
   crashes.

Each of these states allow for the same four possible actions.

``destroy``
   The domain will be terminated completely and all resources released.
``restart``
   The domain will be terminated and then restarted with the same configuration.
``preserve``
   The domain will be terminated and its resource preserved to allow analysis.
``rename-restart``
   The domain will be terminated and then restarted with a new name. (Only
   supported by the libxl hypervisor driver.)

QEMU/KVM/HVF supports the ``on_poweroff`` and ``on_reboot`` events handling the
``destroy`` and ``restart`` actions, but the combination of ``on_poweroff`` set
to ``restart`` and ``on_reboot`` set to ``destroy`` is forbidden.

The ``on_crash`` event supports these additional actions :since:`since 0.8.4` .

``coredump-destroy``
   The crashed domain's core will be dumped, and then the domain will be
   terminated completely and all resources released
``coredump-restart``
   The crashed domain's core will be dumped, and then the domain will be
   restarted with the same configuration

:since:`Since 3.9.0` , the lifecycle events can be configured via the
`virDomainSetLifecycleAction <html/libvirt-libvirt-domain.html#virDomainSetLifecycleAction>`__
API.

The ``on_lockfailure`` element ( :since:`since 1.0.0` ) may be used to configure
what action should be taken when a lock manager loses resource locks. The
following actions are recognized by libvirt, although not all of them need to be
supported by individual lock managers. When no action is specified, each lock
manager will take its default action.

``poweroff``
   The domain will be forcefully powered off.
``restart``
   The domain will be powered off and started up again to reacquire its locks.
``pause``
   The domain will be paused so that it can be manually resumed when lock issues
   are solved.
``ignore``
   Keep the domain running as if nothing happened.

Power Management
----------------

:since:`Since 0.10.2` it is possible to forcibly enable or disable BIOS
advertisements to the guest OS. (NB: Only qemu driver support)

::

   ...
   <pm>
     <suspend-to-disk enabled='no'/>
     <suspend-to-mem enabled='yes'/>
   </pm>
   ...

``pm``
   These elements enable ('yes') or disable ('no') BIOS support for S3
   (suspend-to-mem) and S4 (suspend-to-disk) ACPI sleep states. If nothing is
   specified, then the hypervisor will be left with its default value.
   Note: This setting cannot prevent the guest OS from performing a suspend as
   the guest OS itself can choose to circumvent the unavailability of the sleep
   states (e.g. S4 by turning off completely).


Hypervisor features
-------------------

Hypervisors may allow certain CPU / machine features to be toggled on/off.

::

   ...
   <features>
     <pae/>
     <acpi/>
     <apic/>
     <hap/>
     <privnet/>
     <hyperv mode='custom'>
       <relaxed state='on'/>
       <vapic state='on'/>
       <spinlocks state='on' retries='4096'/>
       <vpindex state='on'/>
       <runtime state='on'/>
       <synic state='on'/>
       <stimer state='on'>
         <direct state='on'/>
       </stimer>
       <reset state='on'/>
       <vendor_id state='on' value='KVM Hv'/>
       <frequencies state='on'/>
       <reenlightenment state='on'/>
       <tlbflush state='on'/>
       <ipi state='on'/>
       <evmcs state='on'/>
     </hyperv>
     <kvm>
       <hidden state='on'/>
       <hint-dedicated state='on'/>
       <poll-control state='on'/>
       <pv-ipi state='off'/>
       <dirty-ring state='on' size='4096'/>
     </kvm>
     <xen>
       <e820_host state='on'/>
       <passthrough state='on' mode='share_pt'/>
     </xen>
     <pvspinlock state='on'/>
     <gic version='2'/>
     <ioapic driver='qemu'/>
     <hpt resizing='required'>
       <maxpagesize unit='MiB'>16</maxpagesize>
     </hpt>
     <vmcoreinfo state='on'/>
     <smm state='on'>
       <tseg unit='MiB'>48</tseg>
     </smm>
     <htm state='on'/>
     <ccf-assist state='on'/>
     <msrs unknown='ignore'/>
     <cfpc value='workaround'/>
     <sbbc value='workaround'/>
     <ibs value='fixed-na'/>
     <tcg>
       <tb-cache unit='MiB'>128</tb-cache>
     </tcg>
     <async-teardown enabled='yes'/>
   </features>
   ...

All features are listed within the ``features`` element, omitting a togglable
feature tag turns it off. The available features can be found by asking for the
`capabilities XML <formatcaps.html>`__ and `domain capabilities
XML <formatdomaincaps.html>`__, but a common set for fully virtualized domains
are:

``pae``
   Physical address extension mode allows 32-bit guests to address more than 4
   GB of memory.
``acpi``
   ACPI is useful for power management, for example, with KVM or HVF guests it
   is required for graceful shutdown to work.
``apic``
   APIC allows the use of programmable IRQ management. :since:`Since 0.10.2
   (QEMU only)` there is an optional attribute ``eoi`` with values ``on`` and
   ``off`` which toggles the availability of EOI (End of Interrupt) for the
   guest.
``hap``
   Depending on the ``state`` attribute (values ``on``, ``off``) enable or
   disable use of Hardware Assisted Paging. The default is ``on`` if the
   hypervisor detects availability of Hardware Assisted Paging.
``viridian``
   Enable Viridian hypervisor extensions for paravirtualizing guest operating
   systems
``privnet``
   Always create a private network namespace. This is automatically set if any
   interface devices are defined. This feature is only relevant for container
   based virtualization drivers, such as LXC.
``hyperv``
   Enable various features improving behavior of guests running Microsoft
   Windows.

   =============== ====================================================================== ============================================ =======================================================
   Feature         Description                                                            Value                                        Since
   =============== ====================================================================== ============================================ =======================================================
   relaxed         Relax constraints on timers                                            on, off                                      :since:`1.0.0 (QEMU 2.0)`
   vapic           Enable virtual APIC                                                    on, off                                      :since:`1.1.0 (QEMU 2.0)`
   spinlocks       Enable spinlock support                                                on, off; retries - at least 4095             :since:`1.1.0 (QEMU 2.0)`
   vpindex         Virtual processor index                                                on, off                                      :since:`1.3.3 (QEMU 2.5)`
   runtime         Processor time spent on running guest code and on behalf of guest code on, off                                      :since:`1.3.3 (QEMU 2.5)`
   synic           Enable Synthetic Interrupt Controller (SynIC)                          on, off                                      :since:`1.3.3 (QEMU 2.6)`
   stimer          Enable SynIC timers, optionally with Direct Mode support               on, off; direct - on,off                     :since:`1.3.3 (QEMU 2.6), direct mode 5.7.0 (QEMU 4.1)`
   reset           Enable hypervisor reset                                                on, off                                      :since:`1.3.3 (QEMU 2.5)`
   vendor_id       Set hypervisor vendor id                                               on, off; value - string, up to 12 characters :since:`1.3.3 (QEMU 2.5)`
   frequencies     Expose frequency MSRs                                                  on, off                                      :since:`4.7.0 (QEMU 2.12)`
   reenlightenment Enable re-enlightenment notification on migration                      on, off                                      :since:`4.7.0 (QEMU 3.0)`
   tlbflush        Enable PV TLB flush support                                            on, off                                      :since:`4.7.0 (QEMU 3.0)`
   ipi             Enable PV IPI support                                                  on, off                                      :since:`4.10.0 (QEMU 3.1)`
   evmcs           Enable Enlightened VMCS                                                on, off                                      :since:`4.10.0 (QEMU 3.1)`
   avic            Enable use Hyper-V SynIC with hardware APICv/AVIC                      on, off                                      :since:`8.10.0 (QEMU 6.2)`
   =============== ====================================================================== ============================================ =======================================================

   :since:`Since 8.0.0` , the hypervisor can be configured further by setting
   the ``mode`` attribute to one of the following values:

   ``custom``
      Set exactly the specified features.

   ``passthrough``
      Enable all features currently supported by the hypervisor, even those that
      libvirt does not understand. Migration of a guest using passthrough is
      dangerous if the source and destination hosts are not identical in both
      hardware, QEMU version, microcode version and configuration. If such a
      migration is attempted then the guest may hang or crash upon resuming
      execution on the destination host. Depending on hypervisor version the
      virtual CPU may or may not contain features which may block migration
      even to an identical host.

   The ``mode`` attribute can be omitted and will default to ``custom``.

``pvspinlock``
   Notify the guest that the host supports paravirtual spinlocks for example by
   exposing the pvticketlocks mechanism. This feature can be explicitly disabled
   by using ``state='off'`` attribute.
``kvm``
   Various features to change the behavior of the KVM hypervisor.

   ============== ============================================================================ ====================================================== ============================
   Feature        Description                                                                  Value                                                  Since
   ============== ============================================================================ ====================================================== ============================
   hidden         Hide the KVM hypervisor from standard MSR based discovery                    on, off                                                :since:`1.2.8 (QEMU 2.1.0)`
   hint-dedicated Allows a guest to enable optimizations when running on dedicated vCPUs       on, off                                                :since:`5.7.0 (QEMU 2.12.0)`
   poll-control   Decrease IO completion latency by introducing a grace period of busy waiting on, off                                                :since:`6.10.0 (QEMU 4.2)`
   pv-ipi         Paravirtualized send IPIs                                                    on, off                                                :since:`7.10.0 (QEMU 3.1)`
   dirty-ring     Enable dirty ring feature                                                    on, off; size - must be power of 2, range [1024,65536] :since:`8.0.0 (QEMU 6.1)`
   ============== ============================================================================ ====================================================== ============================

``xen``
   Various features to change the behavior of the Xen hypervisor.

   =========== ============================================== =================================================== ==============
   Feature     Description                                    Value                                               Since
   =========== ============================================== =================================================== ==============
   e820_host   Expose the host e820 to the guest (PV only)    on, off                                             :since:`6.3.0`
   passthrough Enable IOMMU mappings allowing PCI passthrough on, off; mode - optional string sync_pt or share_pt :since:`6.3.0`
   =========== ============================================== =================================================== ==============

``pmu``
   Depending on the ``state`` attribute (values ``on``, ``off``, default ``on``)
   enable or disable the performance monitoring unit for the guest.
   :since:`Since 1.2.12`
``vmport``
   Depending on the ``state`` attribute (values ``on``, ``off``, default ``on``)
   enable or disable the emulation of VMware IO port, for vmmouse etc.
   :since:`Since 1.2.16`
``gic``
   Enable for architectures using a General Interrupt Controller instead of APIC
   in order to handle interrupts. For example, the 'aarch64' architecture uses
   ``gic`` instead of ``apic``. The optional attribute ``version`` specifies the
   GIC version; however, it may not be supported by all hypervisors. Accepted
   values are ``2``, ``3`` and ``host``. :since:`Since 1.2.16`
``smm``
   Depending on the ``state`` attribute (values ``on``, ``off``, default ``on``)
   enable or disable System Management Mode. :since:`Since 2.1.0`

   Optional sub-element ``tseg`` can be used to specify the amount of memory
   dedicated to SMM's extended TSEG. That offers a fourth option size apart from
   the existing ones (1 MiB, 2 MiB and 8 MiB) that the guest OS (or rather
   loader) can choose from. The size can be specified as a value of that
   element, optional attribute ``unit`` can be used to specify the unit of the
   aforementioned value (defaults to 'MiB'). If set to 0 the extended size is
   not advertised and only the default ones (see above) are available.

   **If the VM is booting you should leave this option alone, unless you are
   very certain you know what you are doing.**

   This value is configurable due to the fact that the calculation cannot be
   done right with the guarantee that it will work correctly. In QEMU, the
   user-configurable extended TSEG feature was unavailable up to and including
   ``pc-q35-2.9``. Starting with ``pc-q35-2.10`` the feature is available, with
   default size 16 MiB. That should suffice for up to roughly 272 vCPUs, 5 GiB
   guest RAM in total, no hotplug memory range, and 32 GiB of 64-bit PCI MMIO
   aperture. Or for 48 vCPUs, with 1TB of guest RAM, no hotplug DIMM range, and
   32GB of 64-bit PCI MMIO aperture. The values may also vary based on the
   loader the VM is using.

   Additional size might be needed for significantly higher vCPU counts or
   increased address space (that can be memory, maxMemory, 64-bit PCI MMIO
   aperture size; roughly 8 MiB of TSEG per 1 TiB of address space) which can
   also be rounded up.

   Due to the nature of this setting being similar to "how much RAM should the
   guest have" users are advised to either consult the documentation of the
   guest OS or loader (if there is any), or test this by trial-and-error
   changing the value until the VM boots successfully. Yet another guiding value
   for users might be the fact that 48 MiB should be enough for pretty large
   guests (240 vCPUs and 4TB guest RAM), but it is on purpose not set as default
   as 48 MiB of unavailable RAM might be too much for small guests (e.g. with
   512 MiB of RAM).

   See `Memory Allocation`_ for more details about
   the ``unit`` attribute. :since:`Since 4.5.0` (QEMU only)

``ioapic``
   Tune the I/O APIC. Possible values for the ``driver`` attribute are: ``kvm``
   (default for KVM domains) and ``qemu`` which puts I/O APIC in userspace which
   is also known as a split I/O APIC mode. :since:`Since 3.4.0` (QEMU/KVM only)
``hpt``
   Configure the HPT (Hash Page Table) of a pSeries guest. Possible values for
   the ``resizing`` attribute are ``enabled``, which causes HPT resizing to be
   enabled if both the guest and the host support it; ``disabled``, which causes
   HPT resizing to be disabled regardless of guest and host support; and
   ``required``, which prevents the guest from starting unless both the guest
   and the host support HPT resizing. If the attribute is not defined, the
   hypervisor default will be used. :since:`Since 3.10.0` (QEMU/KVM only).

   The optional ``maxpagesize`` subelement can be used to limit the usable page
   size for HPT guests. Common values are 64 KiB, 16 MiB and 16 GiB; when not
   specified, the hypervisor default will be used. :since:`Since 4.5.0`
   (QEMU/KVM only).

``vmcoreinfo``
   Enable QEMU vmcoreinfo device to let the guest kernel save debug details.
   :since:`Since 4.4.0` (QEMU only)
``htm``
   Configure HTM (Hardware Transactional Memory) availability for pSeries guests.
   Possible values for the ``state`` attribute are ``on`` and ``off``. If the
   attribute is not defined, the hypervisor default will be used. :since:`Since
   4.6.0` (QEMU/KVM only)
``nested-hv``
   Configure nested HV availability for pSeries guests. This needs to be enabled
   from the host (L0) in order to be effective; having HV support in the (L1)
   guest is very desirable if it's planned to run nested (L2) guests inside
   it, because it will result in those nested guests having much better
   performance than they would when using KVM PR or TCG. Possible values for the
   ``state`` attribute are ``on`` and ``off``. If the attribute is not defined,
   the hypervisor default will be used. :since:`Since 4.10.0` (QEMU/KVM only)
``msrs``
   Some guests might require ignoring unknown Model Specific Registers (MSRs)
   reads and writes. It's possible to switch this by setting ``unknown``
   attribute of ``msrs`` to ``ignore``. If the attribute is not defined, or set
   to ``fault``, unknown reads and writes will not be ignored. :since:`Since
   5.1.0` (bhyve only)
``ccf-assist``
   Configure ccf-assist (Count Cache Flush Assist) availability for pSeries
   guests. Possible values for the ``state`` attribute are ``on`` and ``off``.
   If the attribute is not defined, the hypervisor default will be used.
   :since:`Since 5.9.0` (QEMU/KVM only)
``cfpc``
   Configure cfpc (Cache Flush on Privilege Change) availability for pSeries
   guests. Possible values for the ``value`` attribute are ``broken`` (no
   protection), ``workaround`` (software workaround available) and ``fixed``
   (fixed in hardware). If the attribute is not defined, the hypervisor default
   will be used. :since:`Since 6.3.0` (QEMU/KVM only)
``sbbc``
   Configure sbbc (Speculation Barrier Bounds Checking) availability for pSeries
   guests. Possible values for the ``value`` attribute are ``broken`` (no
   protection), ``workaround`` (software workaround available) and ``fixed``
   (fixed in hardware). If the attribute is not defined, the hypervisor default
   will be used. :since:`Since 6.3.0` (QEMU/KVM only)
``ibs``
   Configure ibs (Indirect Branch Speculation) availability for pSeries guests.
   Possible values for the ``value`` attribute are ``broken`` (no protection),
   ``workaround`` (count cache flush), ``fixed-ibs`` (fixed by serializing
   indirect branches), ``fixed-ccd`` (fixed by disabling the cache count) and
   ``fixed-na (fixed in           hardware - no longer applicable)``. If the
   attribute is not defined, the hypervisor default will be used. :since:`Since
   6.3.0` (QEMU/KVM only)
``tcg``
   Various features to change the behavior of the TCG accelerator.

   =========== ============================================== =================================================== ==============
   Feature     Description                                    Value                                               Since
   =========== ============================================== =================================================== ==============
   tb-cache    The size of translation block cache size       an integer (a multiple of MiB)                      :since:`8.0.0`
   =========== ============================================== =================================================== ==============

``async-teardown``
   Depending on the ``enabled`` attribute (values ``yes``, ``no``) enable or
   disable QEMU asynchronous teardown to improve memory reclaiming on a guest.
   :since:`Since 9.6.0` (QEMU only)

Time keeping
------------

The guest clock is typically initialized from the host clock. Most operating
systems expect the hardware clock to be kept in UTC, and this is the default.
Windows, however, expects it to be in so called 'localtime'.

::

   ...
   <clock offset='localtime'>
     <timer name='rtc' tickpolicy='catchup' track='guest'>
       <catchup threshold='123' slew='120' limit='10000'/>
     </timer>
     <timer name='pit' tickpolicy='delay'/>
   </clock>
   ...

``clock``
   The ``offset`` attribute takes four possible values, allowing fine grained
   control over how the guest clock is synchronized to the host. NB, not all
   hypervisors support all modes.

   ``utc``
      The guest clock will always be synchronized to UTC when booted.
      :since:`Since 0.9.11` 'utc' mode can be converted to 'variable' mode,
      which can be controlled by using the ``adjustment`` attribute. If the
      value is 'reset', the conversion is never done (not all hypervisors can
      synchronize to UTC on each boot; use of 'reset' will cause an error on
      those hypervisors). A numeric value forces the conversion to 'variable'
      mode using the value as the initial adjustment. The default ``adjustment``
      is hypervisor specific.
   ``localtime``
      The guest clock will be synchronized to the host's configured timezone
      when booted, if any. :since:`Since 0.9.11,` the ``adjustment`` attribute
      behaves the same as in 'utc' mode.
   ``timezone``
      The guest clock will be synchronized to the requested timezone using the
      ``timezone`` attribute. :since:`Since 0.7.7`
   ``variable``
      The guest clock will have an arbitrary offset applied relative to UTC or
      localtime, depending on the ``basis`` attribute. The delta relative to UTC
      (or localtime) is specified in seconds, using the ``adjustment``
      attribute. The guest is free to adjust the RTC over time and expect that
      it will be honored at next reboot. This is in contrast to 'utc' and
      'localtime' mode (with the optional attribute adjustment='reset'), where
      the RTC adjustments are lost at each reboot. :since:`Since 0.7.7`
      :since:`Since 0.9.11` the ``basis`` attribute can be either 'utc'
      (default) or 'localtime'.
   ``absolute``
      The guest clock will be always set to the value of the ``start``
      attribute at startup of the domain. The ``start`` attribute takes an
      epoch timestamp.
      :since:`Since 8.4.0`.

   A ``clock`` may have zero or more ``timer`` sub-elements. :since:`Since
   0.8.0`

``timer``
   Each timer element requires a ``name`` attribute, and has other optional
   attributes that depend on the ``name`` specified. Various hypervisors support
   different combinations of attributes.

   ``name``
      The ``name`` attribute selects which timer is being modified, and can be
      one of "platform" (currently unsupported), "hpet" (xen, qemu, lxc),
      "kvmclock" (qemu), "pit" (qemu), "rtc" (qemu, lxc), "tsc" (xen, qemu -
      :since:`since 3.2.0` ), "hypervclock" (qemu - :since:`since 1.2.2` ) or
      "armvtimer" (qemu - :since:`since 6.1.0` ). The ``hypervclock`` timer adds
      support for the reference time counter and the reference page for iTSC
      feature for guests running the Microsoft Windows operating system.
   ``track``
      The ``track`` attribute specifies what the timer tracks, and can be
      "boot", "guest", or "wall", or "realtime". Only valid for ``name="rtc"`` or
      ``name="platform"``.
   ``tickpolicy``
      The ``tickpolicy`` attribute determines what happens when QEMU misses a
      deadline for injecting a tick to the guest. This can happen, for example,
      because the guest was paused.

      ``delay``
         Continue to deliver ticks at the normal rate. The guest OS will not
         notice anything is amiss, as from its point of view time will have
         continued to flow normally. The time in the guest should now be behind
         the time in the host by exactly the amount of time during which ticks
         have been missed.
      ``catchup``
         Deliver ticks at a higher rate to catch up with the missed ticks. The
         guest OS will not notice anything is amiss, as from its point of view
         time will have continued to flow normally. Once the timer has managed
         to catch up with all the missing ticks, the time in the guest and in
         the host should match.
      ``merge``
         Merge the missed tick(s) into one tick and inject. The guest time may
         be delayed, depending on how the OS reacts to the merging of ticks
      ``discard``
         Throw away the missed ticks and continue with future injection
         normally. The guest OS will see the timer jump ahead by a potentially
         quite significant amount all at once, as if the intervening chunk of
         time had simply not existed; needless to say, such a sudden jump can
         easily confuse a guest OS which is not specifically prepared to deal
         with it. Assuming the guest OS can deal correctly with the time jump,
         the time in the guest and in the host should now match.

      If the policy is "catchup", there can be further details in the
      ``catchup`` sub-element.

      ``catchup``
         The ``catchup`` element has three optional attributes, each a positive
         integer. The attributes are ``threshold``, ``slew``, and ``limit``.

      Note that hypervisors are not required to support all policies across all
      time sources

   ``frequency``
      The ``frequency`` attribute is an unsigned integer specifying the
      frequency at which ``name="tsc"`` runs.
   ``mode``
      The ``mode`` attribute controls how the ``name="tsc"`` timer is managed,
      and can be "auto", "native", "emulate", "paravirt", or "smpsafe". Other
      timers are always emulated.
   ``present``
      The ``present`` attribute can be "yes" or "no" to specify whether a
      particular timer is available to the guest.

Performance monitoring events
-----------------------------

Some platforms allow monitoring of performance of the virtual machine and the
code executed inside. To enable the performance monitoring events you can either
specify them in the ``perf`` element or enable them via
``virDomainSetPerfEvents`` API. The performance values are then retrieved using
the virConnectGetAllDomainStats API. :since:`Since 2.0.0`

::

   ...
   <perf>
     <event name='cmt' enabled='yes'/>
     <event name='mbmt' enabled='no'/>
     <event name='mbml' enabled='yes'/>
     <event name='cpu_cycles' enabled='no'/>
     <event name='instructions' enabled='yes'/>
     <event name='cache_references' enabled='no'/>
     <event name='cache_misses' enabled='no'/>
     <event name='branch_instructions' enabled='no'/>
     <event name='branch_misses' enabled='no'/>
     <event name='bus_cycles' enabled='no'/>
     <event name='stalled_cycles_frontend' enabled='no'/>
     <event name='stalled_cycles_backend' enabled='no'/>
     <event name='ref_cpu_cycles' enabled='no'/>
     <event name='cpu_clock' enabled='no'/>
     <event name='task_clock' enabled='no'/>
     <event name='page_faults' enabled='no'/>
     <event name='context_switches' enabled='no'/>
     <event name='cpu_migrations' enabled='no'/>
     <event name='page_faults_min' enabled='no'/>
     <event name='page_faults_maj' enabled='no'/>
     <event name='alignment_faults' enabled='no'/>
     <event name='emulation_faults' enabled='no'/>
   </perf>
   ...

=========================== ======================================================================================================================================================================================= ================================
event name                  Description                                                                                                                                                                             stats parameter name
=========================== ======================================================================================================================================================================================= ================================
``cmt``                     usage of l3 cache in bytes by applications running on the platform                                                                                                                      ``perf.cmt``
``mbmt``                    total system bandwidth from one level of cache                                                                                                                                          ``perf.mbmt``
``mbml``                    bandwidth of memory traffic for a memory controller                                                                                                                                     ``perf.mbml``
``cpu_cycles``              the count of CPU cycles (total/elapsed)                                                                                                                                                 ``perf.cpu_cycles``
``instructions``            the count of instructions by applications running on the platform                                                                                                                       ``perf.instructions``
``cache_references``        the count of cache hits by applications running on the platform                                                                                                                         ``perf.cache_references``
``cache_misses``            the count of cache misses by applications running on the platform                                                                                                                       ``perf.cache_misses``
``branch_instructions``     the count of branch instructions by applications running on the platform                                                                                                                ``perf.branch_instructions``
``branch_misses``           the count of branch misses by applications running on the platform                                                                                                                      ``perf.branch_misses``
``bus_cycles``              the count of bus cycles by applications running on the platform                                                                                                                         ``perf.bus_cycles``
``stalled_cycles_frontend`` the count of stalled CPU cycles in the frontend of the instruction processor pipeline by applications running on the platform                                                           ``perf.stalled_cycles_frontend``
``stalled_cycles_backend``  the count of stalled CPU cycles in the backend of the instruction processor pipeline by applications running on the platform                                                            ``perf.stalled_cycles_backend``
``ref_cpu_cycles``          the count of total CPU cycles not affected by CPU frequency scaling by applications running on the platform                                                                             ``perf.ref_cpu_cycles``
``cpu_clock``               the count of CPU clock time, as measured by a monotonic high-resolution per-CPU timer, by applications running on the platform                                                          ``perf.cpu_clock``
``task_clock``              the count of task clock time, as measured by a monotonic high-resolution CPU timer, specific to the task that is run by applications running on the platform                            ``perf.task_clock``
``page_faults``             the count of page faults by applications running on the platform. This includes minor, major, invalid and other types of page faults                                                    ``perf.page_faults``
``context_switches``        the count of context switches by applications running on the platform                                                                                                                   ``perf.context_switches``
``cpu_migrations``          the count of CPU migrations, that is, where the process moved from one logical processor to another, by applications running on the platform                                            ``perf.cpu_migrations``
``page_faults_min``         the count of minor page faults, that is, where the page was present in the page cache, and therefore the fault avoided loading it from storage, by applications running on the platform ``perf.page_faults_min``
``page_faults_maj``         the count of major page faults, that is, where the page was not present in the page cache, and therefore had to be fetched from storage, by applications running on the platform        ``perf.page_faults_maj``
``alignment_faults``        the count of alignment faults, that is when the load or store is not aligned properly, by applications running on the platform                                                          ``perf.alignment_faults``
``emulation_faults``        the count of emulation faults, that is when the kernel traps on unimplemented instructions and emulates them for user space, by applications running on the platform                     ``perf.emulation_faults``
=========================== ======================================================================================================================================================================================= ================================


Devices
-------

The final set of XML elements are all used to describe devices provided to the
guest domain. All devices occur as children of the main ``devices`` element.
:since:`Since 0.1.3`

::

   ...
   <devices>
     <emulator>/usr/lib/xen/bin/qemu-dm</emulator>
   </devices>
   ...

``emulator``
   The contents of the ``emulator`` element specify the fully qualified path to
   the device model emulator binary. The `capabilities XML <formatcaps.html>`__
   specifies the recommended default emulator to use for each particular domain
   type / architecture combination.

To help users identifying devices they care about, every device can have direct
child ``alias`` element which then has ``name`` attribute where users can store
identifier for the device. The identifier has to have "ua-" prefix and must be
unique within the domain. Additionally, the identifier must consist only of the
following characters: ``[a-zA-Z0-9_-]``. :since:`Since 3.9.0`

::

   <devices>
     <disk type='file'>
       <alias name='ua-myDisk'/>
     </disk>
     <interface type='network' trustGuestRxFilters='yes'>
       <alias name='ua-myNIC'/>
     </interface>
     ...
   </devices>


Hard drives, floppy disks, CDROMs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Any device that looks like a disk, be it a floppy, harddisk, cdrom, or
paravirtualized driver is specified via the ``disk`` element.

::

   ...
   <devices>
     <disk type='file' snapshot='external'>
       <driver name="tap" type="aio" cache="default"/>
       <source file='/var/lib/xen/images/fv0' startupPolicy='optional'>
         <seclabel relabel='no'/>
       </source>
       <target dev='hda' bus='ide'/>
       <iotune>
         <total_bytes_sec>10000000</total_bytes_sec>
         <read_iops_sec>400000</read_iops_sec>
         <write_iops_sec>100000</write_iops_sec>
       </iotune>
       <boot order='2'/>
       <encryption type='...'>
         ...
       </encryption>
       <shareable/>
       <serial>
         ...
       </serial>
     </disk>
       ...
     <disk type='network'>
       <driver name="qemu" type="raw" io="threads" ioeventfd="on" event_idx="off"/>
       <source protocol="sheepdog" name="image_name">
         <host name="hostname" port="7000"/>
       </source>
       <target dev="hdb" bus="ide"/>
       <boot order='1'/>
       <transient/>
       <address type='drive' controller='0' bus='1' unit='0'/>
     </disk>
     <disk type='network'>
       <driver name="qemu" type="raw"/>
       <source protocol="rbd" name="image_name2">
         <host name="hostname" port="7000"/>
         <snapshot name="snapname"/>
         <config file="/path/to/file"/>
         <auth username='myuser'>
           <secret type='ceph' usage='mypassid'/>
         </auth>
       </source>
       <target dev="hdc" bus="ide"/>
     </disk>
     <disk type='block' device='cdrom'>
       <driver name='qemu' type='raw'/>
       <target dev='hdd' bus='ide' tray='open'/>
       <readonly/>
     </disk>
     <disk type='network' device='cdrom'>
       <driver name='qemu' type='raw'/>
       <source protocol="http" name="url_path" query="foo=bar&amp;baz=flurb>
         <host name="hostname" port="80"/>
         <cookies>
           <cookie name="test">somevalue</cookie>
         </cookies>
         <readahead size='65536'/>
         <timeout seconds='6'/>
       </source>
       <target dev='hde' bus='ide' tray='open'/>
       <readonly/>
     </disk>
     <disk type='network' device='cdrom'>
       <driver name='qemu' type='raw'/>
       <source protocol="https" name="url_path">
         <host name="hostname" port="443"/>
         <ssl verify="no"/>
       </source>
       <target dev='hdf' bus='ide' tray='open'/>
       <readonly/>
     </disk>
     <disk type='network' device='cdrom'>
       <driver name='qemu' type='raw'/>
       <source protocol="ftp" name="url_path">
         <host name="hostname" port="21"/>
       </source>
       <target dev='hdg' bus='ide' tray='open'/>
       <readonly/>
     </disk>
     <disk type='network' device='cdrom'>
       <driver name='qemu' type='raw'/>
       <source protocol="ftps" name="url_path">
         <host name="hostname" port="990"/>
       </source>
       <target dev='hdh' bus='ide' tray='open'/>
       <readonly/>
     </disk>
     <disk type='network' device='cdrom'>
       <driver name='qemu' type='raw'/>
       <source protocol="tftp" name="url_path">
         <host name="hostname" port="69"/>
       </source>
       <target dev='hdi' bus='ide' tray='open' rotation_rate='7200'/>
       <readonly/>
     </disk>
     <disk type='block' device='lun'>
       <driver name='qemu' type='raw'/>
       <source dev='/dev/sda'>
         <slices>
           <slice type='storage' offset='12345' size='123'/>
         </slices>
         <reservations managed='no'>
           <source type='unix' path='/path/to/qemu-pr-helper' mode='client'/>
         </reservations>
       </source>
       <target dev='sda' bus='scsi' rotation_rate='1'/>
       <address type='drive' controller='0' bus='0' target='3' unit='0'/>
     </disk>
     <disk type='block' device='disk'>
       <driver name='qemu' type='raw'/>
       <source dev='/dev/sda'/>
       <geometry cyls='16383' heads='16' secs='63' trans='lba'/>
       <blockio logical_block_size='512' physical_block_size='4096' discard_granularity='4096'/>
       <target dev='hdj' bus='ide'/>
     </disk>
     <disk type='volume' device='disk'>
       <driver name='qemu' type='raw'/>
       <source pool='blk-pool0' volume='blk-pool0-vol0'/>
       <target dev='hdk' bus='ide'/>
     </disk>
     <disk type='network' device='disk'>
       <driver name='qemu' type='raw'/>
       <source protocol='iscsi' name='iqn.2013-07.com.example:iscsi-nopool/2'>
         <host name='example.com' port='3260'/>
         <auth username='myuser'>
           <secret type='iscsi' usage='libvirtiscsi'/>
         </auth>
       </source>
       <target dev='vda' bus='virtio'/>
     </disk>
     <disk type='network' device='lun'>
       <driver name='qemu' type='raw'/>
       <source protocol='iscsi' name='iqn.2013-07.com.example:iscsi-nopool/1'>
         <host name='example.com' port='3260'/>
         <auth username='myuser'>
           <secret type='iscsi' usage='libvirtiscsi'/>
         </auth>
       </source>
       <target dev='sdb' bus='scsi'/>
     </disk>
     <disk type='network' device='disk'>
       <driver name='qemu' type='raw'/>
       <source protocol='nfs' name='PATH'>
         <host name='example.com'/>
         <identity user='USER' group='GROUP'/>
       </source>
       <target dev='vda' bus='virtio'/>
     </disk>
     <disk type='network' device='lun'>
       <driver name='qemu' type='raw'/>
       <source protocol='iscsi' name='iqn.2013-07.com.example:iscsi-nopool/0'>
         <host name='example.com' port='3260'/>
         <initiator>
           <iqn name='iqn.2013-07.com.example:client'/>
         </initiator>
       </source>
       <target dev='sdb' bus='scsi'/>
     </disk>
     <disk type='dir' device='floppy'>
       <driver name='qemu' type='fat'/>
       <source dir='/var/somefiles'>
       <target dev='fda'/>
       <readonly/>
     </disk>
     <disk type='volume' device='disk'>
       <driver name='qemu' type='raw'/>
       <source pool='iscsi-pool' volume='unit:0:0:1' mode='host'/>
       <target dev='vdb' bus='virtio'/>
     </disk>
     <disk type='volume' device='disk'>
       <driver name='qemu' type='raw'/>
       <source pool='iscsi-pool' volume='unit:0:0:2' mode='direct'/>
       <target dev='vdc' bus='virtio'/>
     </disk>
     <disk type='file' device='disk'>
       <driver name='qemu' type='qcow2' queues='4' queue_size='256' />
       <source file='/var/lib/libvirt/images/domain.qcow'/>
       <backingStore type='file'>
         <format type='qcow2'/>
         <source file='/var/lib/libvirt/images/snapshot.qcow'/>
         <backingStore type='block'>
           <format type='raw'/>
           <source dev='/dev/mapper/base'/>
           <backingStore/>
         </backingStore>
       </backingStore>
       <target dev='vdd' bus='virtio'/>
     </disk>
     <disk type='nvme' device='disk'>
       <driver name='qemu' type='raw'/>
       <source type='pci' managed='yes' namespace='1'>
         <address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
       </source>
       <target dev='vde' bus='virtio'/>
     </disk>
     <disk type='vhostuser' device='disk'>
       <driver name='qemu' type='raw'/>
       <source type='unix' path='/tmp/vhost-blk.sock'>
         <reconnect enabled='yes' timeout='10'/>
       </source>
       <target dev='vdf' bus='virtio'/>
     </disk>
     <disk type='vhostvdpa' device='disk'>
       <driver name='qemu' type='raw'/>
       <source dev='/dev/vhost-vdpa-0' />
       <target dev='vdg' bus='virtio'/>
     </disk>
   </devices>
   ...

``disk``
   The ``disk`` element is the main container for describing disks and supports
   the following attributes:

   ``type``
      Valid values are "file", "block", "dir" ( :since:`since 0.7.5` ),
      "network" ( :since:`since 0.8.7` ), or "volume" ( :since:`since 1.0.5` ),
      or "nvme" ( :since:`since 6.0.0` ), or "vhostuser" ( :since:`since 7.1.0` ),
      or "vhostvdpa" ( :since:`since 9.8.0 (QEMU 8.1.0)`) and refer to the
      underlying source for the disk. :since:`Since 0.0.3`
   ``device``
      Indicates how the disk is to be exposed to the guest OS. Possible values
      for this attribute are "floppy", "disk", "cdrom", and "lun", defaulting to
      "disk".

      Using "lun" ( :since:`since 0.9.10` ) is only valid when the ``type`` is
      "block" or "network" for ``protocol='iscsi'`` or when the ``type`` is
      "volume" when using an iSCSI source ``pool`` for ``mode`` "host" or as an
      `NPIV <https://wiki.libvirt.org/page/NPIV_in_libvirt>`__ virtual Host Bus
      Adapter (vHBA) using a Fibre Channel storage pool. Configured in this
      manner, the LUN behaves identically to "disk", except that generic SCSI
      commands from the guest are accepted and passed through to the physical
      device. Also note that device='lun' will only be recognized for actual raw
      devices, but never for individual partitions or LVM partitions (in those
      cases, the kernel will reject the generic SCSI commands, making it
      identical to device='disk'). :since:`Since 0.1.4`

   ``model``
      Indicates the emulated device model of the disk. Typically this is
      indicated solely by the ``bus`` property but for ``bus`` "virtio" the
      model can be specified further with "virtio-transitional",
      "virtio-non-transitional", or "virtio". See `Virtio transitional devices`_
      for more details. :since:`Since 5.2.0`
   ``rawio``
      Indicates whether the disk needs rawio capability. Valid settings are
      "yes" or "no" (default is "no"). If any one disk in a domain has
      rawio='yes', rawio capability will be enabled for all disks in the domain
      (because, in the case of QEMU, this capability can only be set on a
      per-process basis). This attribute is only valid when device is "lun". NB,
      ``rawio`` intends to confine the capability per-device, however, current
      QEMU implementation gives the domain process broader capability than that
      (per-process basis, affects all the domain disks). To confine the
      capability as much as possible for QEMU driver as this stage, ``sgio`` is
      recommended, it's more secure than ``rawio``. :since:`Since 0.9.10`
   ``sgio``
      If supported by the hypervisor and OS, indicates whether unprivileged
      SG_IO commands are filtered for the disk. Valid settings are "filtered" or
      "unfiltered" where the default is "filtered". Only available when the
      ``device`` is 'lun'. :since:`Since 1.0.2`
   ``snapshot``
      Indicates the default behavior of the disk during disk snapshots:
      ``internal`` requires a file format such as qcow2 that can store both
      the snapshot and the data changes since the snapshot; ``external`` will
      separate the snapshot from the live data; ``no`` means the disk will
      not participate in snapshots; and ``manual`` allows snapshotting done via
      an unmanaged storage provider. Read-only disks default to ``no``, while
      the default for other disks depends on the hypervisor's capabilities.
      Some hypervisors allow a per-snapshot choice as well, during `domain
      snapshot creation <formatsnapshot.html>`__. Not all snapshot modes are
      supported; for example, enabling snapshots with a transient disk
      generally does not make sense. :since:`Since 0.9.5`

``source``
   Representation of the disk ``source`` depends on the disk ``type`` attribute
   value as follows:

   ``file``
      The ``file`` attribute specifies the fully-qualified path to the file
      holding the disk. :since:`Since 0.0.3`

      :since:`Since 9.0.0` a new optional attribute ``fdgroup`` can be added
      instructing to access the disk via file descriptors associated to the
      domain object via the ``virDomainFDAssociate()`` API rather than opening
      the files. The files do not necessarily have to be accessible by libvirt
      via the filesystem. The filename passed via ``file`` can still be used
      to generate paths to write into image metadata when doing block operations
      but libvirt will not access these natively.
   ``block``
      The ``dev`` attribute specifies the fully-qualified path to the host
      device to serve as the disk. :since:`Since 0.0.3`
   ``dir``
      The ``dir`` attribute specifies the fully-qualified path to the directory
      to use as the disk. :since:`Since 0.7.5`

      Note that most hypervisors that support ``dir`` disks do that by exposing
      an emulated block device with an emulated filesystem populated with
      contents of the configured directory. As guest operating system may cache
      the filesystem metadata, outside changes to the directory may not appear
      in the guest and/or may result in corrupted data being observable from
      the VM.

      The format of the emulated filesystem is controlled by the ``format``
      attribute of the ``<driver>`` driver element. Currently only the ``fat``
      format is supported. Hypervisors may only support ``<readonly/>`` mode.

   ``network``
      The ``protocol`` attribute specifies the protocol to access to the
      requested image. Possible values are "nbd", "iscsi", "rbd", "sheepdog",
      "gluster", "vxhs", "nfs", "http", "https", "ftp", ftps", "tftp", or "ssh".

      For any ``protocol`` other than ``nbd`` an additional attribute ``name``
      is mandatory to specify which volume/image will be used.

      For "nbd", the ``name`` attribute is optional. TLS transport for NBD can
      be enabled by setting the ``tls`` attribute to ``yes``. For the QEMU
      hypervisor, usage of a TLS environment can also be globally controlled on
      the host by the ``nbd_tls`` and ``nbd_tls_x509_cert_dir`` in
      /etc/libvirt/qemu.conf. ('tls' :since:`Since 4.5.0` ) :since:`Since 8.2.0`
      the optional attribute ``tlsHostname`` can be used to override the
      expected host name of the NBD server used for TLS certificate verification.

      For protocols ``http`` and ``https`` an optional attribute ``query``
      specifies the query string. ( :since:`Since 6.2.0` )

      For "iscsi" ( :since:`since 1.0.4` ), the ``name`` attribute may include a
      logical unit number, separated from the target's name by a slash (e.g.,
      ``iqn.2013-07.com.example:iscsi-pool/1``). If not specified, the default
      LUN is zero.

      For "vxhs" ( :since:`since 3.8.0` ), the ``name`` is the UUID of the
      volume, assigned by the HyperScale server. Additionally, an optional
      attribute ``tls`` (QEMU only) can be used to control whether a VxHS block
      device would utilize a hypervisor configured TLS X.509 certificate
      environment in order to encrypt the data channel. For the QEMU hypervisor,
      usage of a TLS environment can also be globally controlled on the host by
      the ``vxhs_tls`` and ``vxhs_tls_x509_cert_dir`` or
      ``default_tls_x509_cert_dir`` settings in the file /etc/libvirt/qemu.conf.
      If ``vxhs_tls`` is enabled, then unless the domain ``tls`` attribute is
      set to "no", libvirt will use the host configured TLS environment. If the
      ``tls`` attribute is set to "yes", then regardless of the qemu.conf
      setting, TLS authentication will be attempted.

      :since:`Since 0.8.7`

   ``volume``
      The underlying disk source is represented by attributes ``pool`` and
      ``volume``. Attribute ``pool`` specifies the name of the `storage
      pool <formatstorage.html>`__ (managed by libvirt) where the disk source
      resides. Attribute ``volume`` specifies the name of storage volume
      (managed by libvirt) used as the disk source. The value for the ``volume``
      attribute will be the output from the "Name" column of a
      ``virsh vol-list [pool-name]`` command.

      Use the attribute ``mode`` ( :since:`since 1.1.1` ) to indicate how to
      represent the LUN as the disk source. Valid values are "direct" and
      "host". If ``mode`` is not specified, the default is to use "host". Using
      "direct" as the ``mode`` value indicates to use the `storage
      pool's <formatstorage.html>`__ ``source`` element ``host`` attribute as
      the disk source to generate the libiscsi URI (e.g.
      'file=iscsi://example.com:3260/iqn.2013-07.com.example:iscsi-pool/1').
      Using "host" as the ``mode`` value indicates to use the LUN's path as it
      shows up on host (e.g.
      'file=/dev/disk/by-path/ip-example.com:3260-iscsi-iqn.2013-07.com.example:iscsi-pool-lun-1').
      Using a LUN from an iSCSI source pool provides the same features as a
      ``disk`` configured using ``type`` 'block' or 'network' and ``device`` of
      'lun' with respect to how the LUN is presented to and may be used by the
      guest. :since:`Since 1.0.5`

   ``nvme``
      To specify disk source for NVMe disk the ``source`` element has the
      following attributes:

      ``type``
         The type of address specified in ``address`` sub-element. Currently,
         only ``pci`` value is accepted.
      ``managed``
         This attribute instructs libvirt to detach NVMe controller
         automatically on domain startup (``yes``) or expect the controller to
         be detached by system administrator (``no``).
      ``namespace``
         The namespace ID which should be assigned to the domain. According to
         NVMe standard, namespace numbers start from 1, including.

      The difference between ``<disk type='nvme'>`` and ``<hostdev/>`` is that
      the latter is plain host device assignment with all its limitations (e.g.
      no live migration), while the former makes hypervisor to run the NVMe disk
      through hypervisor's block layer thus enabling all features provided by
      the layer (e.g. snapshots, domain migration, etc.). Moreover, since the
      NVMe disk is unbinded from its PCI driver, the host kernel storage stack
      is not involved (compared to passing say ``/dev/nvme0n1`` via
      ``<disk type='block'>`` and therefore lower latencies can be achieved.

   ``vhostuser``
      Enables the hypervisor to connect to another process using vhost-user
      protocol. Requires shared memory configured for the VM, for more details
      see ``access`` mode for ``memoryBacking`` element (See `Memory Backing`_).

      The ``source`` element has following mandatory attributes:

      ``type``
         The type of char device. Currently only ``unix`` type is supported.
      ``path``
         Path to the unix socket to be used as disk source.

      Note that the vhost server replaces both the disk frontend and backend
      thus almost all of the disk properties can't be configured via the
      ``<disk>`` XML for this disk type. Additionally features such as blockjobs,
      incremental backups and snapshots are not supported for this disk type.

   ``vhostvdpa``
      Enables the hypervisor to connect to a vDPA block device. Requires shared
      memory configured for the VM, for more details see ``access`` mode for
      ``memoryBacking`` element (See `Memory Backing`_).

      The ``source`` element has a mandatory attribute ``dev`` that specifies
      the fully-qualified path to the vhost-vdpa character device (e.g.
      ``/dev/vhost-vdpa-0``).

   With "file", "block", and "volume", one or more optional sub-elements
   ``seclabel`` (See `Security label`_) can be used to override the domain
   security labeling policy for just that source file.
   (NB, for "volume" type disk, ``seclabel`` is only valid when the
   specified storage volume is of 'file' or 'block' type).
   :since:`since 0.9.9`

   The ``source`` element may also have the ``index`` attribute with same
   semantics the ``index`` attribute of ``backingStore``.

   The ``source`` element may contain the following sub elements:

   ``host``
      When the disk ``type`` is "network", the ``source`` may have zero or more
      ``host`` sub-elements used to specify the hosts to connect. The ``host``
      element supports 4 attributes, viz. "name", "port", "transport" and
      "socket", which specify the hostname, the port number, transport type and
      path to socket, respectively. The meaning of this element and the number
      of the elements depend on the protocol attribute.

      ======== ======================================================= ============================================================ ================
      Protocol Meaning                                                 Number of hosts                                              Default port
      ======== ======================================================= ============================================================ ================
      nbd      a server running nbd-server                             only one                                                     10809
      iscsi    an iSCSI server                                         only one                                                     3260
      rbd      monitor servers of RBD                                  one or more                                                  librados default
      sheepdog one of the sheepdog servers (default is localhost:7000) zero or one                                                  7000
      gluster  a server running glusterd daemon                        one or more ( :since:`Since 2.1.0` ), just one prior to that 24007
      vxhs     a server running Veritas HyperScale daemon              only one                                                     9999
      nfs      a server running Network File System                    only one ( :since:`Since 7.0.0` )                            must be omitted
      ======== ======================================================= ============================================================ ================

      gluster supports "tcp", "rdma", "unix" as valid values for the transport
      attribute. nbd supports "tcp" and "unix". Others only support "tcp". If
      nothing is specified, "tcp" is assumed. If the transport is "unix", the
      socket attribute specifies the path to an AF_UNIX socket. nfs only
      supports the use of a "tcp" transport, and does not support using a
      port at all so it must be omitted.

   ``snapshot``
      The ``name`` attribute of ``snapshot`` element can optionally specify an
      internal snapshot name to be used as the source for storage protocols.
      Supported for 'rbd' :since:`since 1.2.11 (QEMU only).`
   ``config``
      The ``file`` attribute for the ``config`` element provides a fully
      qualified path to a configuration file to be provided as a parameter to
      the client of a networked storage protocol. Supported for 'rbd'
      :since:`since 1.2.11 (QEMU only).`
   ``auth``
      :since:`Since libvirt 3.9.0` , the ``auth`` element is supported for a
      disk ``type`` "network" that is using a ``source`` element with the
      ``protocol`` attributes "rbd", "iscsi", or "ssh". If present, the
      ``auth`` element provides the authentication credentials needed to access
      the source. It includes a mandatory attribute ``username``, which
      identifies the username to use during authentication, as well as a
      sub-element ``secret`` with mandatory attribute ``type``, to tie back to
      a `libvirt secret object <formatsecret.html>`__ that holds the actual
      password or other credentials (the domain XML intentionally does not
      expose the password, only the reference to the object that does manage
      the password). Known secret types are "ceph" for Ceph RBD network sources
      and "iscsi" for CHAP authentication of iSCSI targets. Both will require
      either a ``uuid`` attribute with the UUID of the secret object or a
      ``usage`` attribute matching the key that was specified in the secret
      object.
   ``encryption``
      :since:`Since libvirt 3.9.0` , the ``encryption`` can be a sub-element of
      the ``source`` element for encrypted storage sources. If present,
      specifies how the storage source is encrypted See the `Storage
      Encryption <formatstorageencryption.html>`__ page for more information.
      Note that the 'qcow' format of encryption is broken and thus is no longer
      supported for use with disk images. ( :since:`Since libvirt 4.5.0` )
   ``reservations``
      :since:`Since libvirt 4.4.0` , the ``reservations`` can be a sub-element
      of the ``source`` element for storage sources (QEMU driver only). If
      present it enables persistent reservations for SCSI based disks. The
      element has one mandatory attribute ``managed`` with accepted values
      ``yes`` and ``no``. If ``managed`` is enabled libvirt prepares and manages
      any resources needed. When the persistent reservations are unmanaged, then
      the hypervisor acts as a client and the path to the server socket must be
      provided in the child element ``source``, which currently accepts only the
      following attributes: ``type`` with one value ``unix``, ``path`` path to
      the socket, and finally ``mode`` which accepts one value ``client``
      specifying the role of hypervisor. It's recommended to allow libvirt
      manage the persistent reservations.
   ``initiator``
      :since:`Since libvirt 4.7.0` , the ``initiator`` element is supported for
      a disk ``type`` "network" that is using a ``source`` element with the
      ``protocol`` attribute "iscsi". If present, the ``initiator`` element
      provides the initiator IQN needed to access the source via mandatory
      attribute ``name``.
   ``address``
      For disk of type ``nvme`` this element specifies the PCI address of the
      host NVMe controller. :since:`Since 6.0.0`
   ``slices``
      The ``slices`` element using its ``slice`` sub-elements allows configuring
      offset and size of either the location of the image format
      (``slice type='storage'``) inside the storage source or the guest data
      inside the image format container (future expansion). The ``offset`` and
      ``size`` values are in bytes. :since:`Since 6.1.0`
   ``ssl``
      For ``https`` and ``ftps`` accessed storage it's possible to tweak the SSL
      transport parameters with this element. The ``verify`` attribute allows to
      turn on or off SSL certificate validation. Supported values are ``yes``
      and ``no``. :since:`Since 6.2.0`
   ``cookies``
      For ``http`` and ``https`` accessed storage it's possible to pass one or
      more cookies. The cookie name and value must conform to the HTTP
      specification. :since:`Since 6.2.0`
   ``readahead``
      The ``readahead`` element has a ``size`` attribute which specifies the
      size of the readahead buffer in bytes for protocols which support it.
      Note that '0' is considered as if the value is not provided.
      :since:`Since 6.2.0`
   ``timeout``
      The ``timeout`` element has a ``seconds`` attribute which specifies the
      connection timeout in seconds for protocols which support it. Note that
      '0' is considered as if the value is not provided. :since:`Since 6.2.0`
   ``identity``
      When using an ``nfs`` protocol, this is used to provide information on the
      configuration of the user and group. The element has two attributes,
      ``user`` and ``group``. The user can provide these elements as user or
      group strings, or as user and group ID numbers directly if the string
      is formatted using a "+" at the beginning of the ID number. If either
      of these attributes is omitted, then that field is assumed to be the
      default value for the current system. If both ``user`` and ``group``
      are intended to be default, then the entire element may be omitted.

      When using an ``ssh`` protocol, this element is used to enable
      authentication via ssh keys. In this configuration, the element has three
      possible attributes. The ``username`` attribute is required and specifies
      the name of the user on the remote server. ssh keys can be specified in
      one of two ways. The first way is by adding them to an ssh-agent and
      providing the path to the ssh-agent socket in the ``agentsock``
      attribute. This method works for ssh keys with or without password
      protection. Alternatively, for ssh keys without a password, the ssh key
      can be specified directly by setting the ``keyfile`` attribute.
   ``reconnect``
      For disk type ``vhostuser`` configures reconnect timeout if the connection
      is lost. This is set with the two mandatory attributes ``enabled`` and
      ``timeout``.
      For disk type ``network`` and protocol ``nbd`` the QEMU NBD reconnect delay
      can be set via attribute ``delay``:

      ``enabled``
         If the reconnect feature is enabled, accepts ``yes`` and ``no``
      ``timeout``
         The amount of seconds after which hypervisor tries to reconnect.
      ``delay``
         Only for NBD hosts. The amount of seconds during which all requests are
         paused and will be rerun after a successful reconnect. After that time, any
         delayed requests and all future requests before a successful reconnect
         will immediately fail. If not set the default QEMU value is 0.
   ``knownHosts``
      For storage accessed via the ``ssh`` protocol, this element configures a
      path to a file that will be used to verify the remote host. This file
      must contain the expected host key for the remote host or the connection
      will fail. The location of the file is specified via the ``path``
      attribute.
      :since:`Since 9.8.0`


   For a "file" or "volume" disk type which represents a cdrom or floppy (the
   ``device`` attribute), it is possible to define policy what to do with the
   disk if the source file is not accessible. (NB, ``startupPolicy`` is not
   valid for "volume" disk unless the specified storage volume is of "file"
   type). This is done by the ``startupPolicy`` attribute ( :since:`since 0.9.7`
   ), accepting these values:

   ========= =====================================================================
   mandatory fail if missing for any reason (the default)
   requisite fail if missing on boot up, drop if missing on migrate/restore/revert
   optional  drop if missing at any start attempt
   ========= =====================================================================

   :since:`Since 1.1.2` the ``startupPolicy`` is extended to support hard disks
   besides cdrom and floppy. On guest cold bootup, if a certain disk is not
   accessible or its disk chain is broken, with startupPolicy 'optional' the
   guest will drop this disk. This feature doesn't support migration currently.

``backingStore``
   This element describes the backing store used by the disk specified by
   sibling ``source`` element. :since:`Since 1.2.4.` If the hypervisor driver
   does not support the
   `backingStoreInput <formatdomaincaps.html#backingstoreinput>`__ (
   :since:`Since 5.10.0` ) domain feature the ``backingStore`` is ignored on
   input and only used for output to describe the detected backing chains of
   running domains. If ``backingStoreInput`` is supported the ``backingStore``
   is used as the backing image of ``source`` or other ``backingStore``
   overriding any backing image information recorded in the image metadata. An
   empty ``backingStore`` element means the sibling source is self-contained and
   is not based on any backing store. For the detected backing chain information
   to be accurate, the backing format must be correctly specified in the
   metadata of each file of the chain (files created by libvirt satisfy this
   property, but using existing external files for snapshot or block copy
   operations requires the end user to pre-create the file correctly). The
   following attributes are supported in ``backingStore``:

   ``type``
      The ``type`` attribute represents the type of disk used by the backing
      store, see disk type attribute above for more details and possible values.
   ``index``
      This attribute is only valid in output (and ignored on input) and it can
      be used to refer to a specific part of the disk chain when doing block
      operations (such as via the ``virDomainBlockRebase`` API). For example,
      ``vda[2]`` refers to the backing store with ``index='2'`` of the disk with
      ``vda`` target.

   Moreover, ``backingStore`` supports the following sub-elements:

   ``format``
      The ``format`` element contains ``type`` attribute which specifies the
      internal format of the backing store, such as ``raw`` or ``qcow2``.

      The ``format`` element can contain ``metadata_cache`` subelement, which
      has identical semantics to the identically named subelement of ``driver``
      of a ``disk``.

   ``source``
      This element has the same structure as the ``source`` element in ``disk``.
      It specifies which file, device, or network location contains the data of
      the described backing store.
   ``backingStore``
      If the backing store is not self-contained, the next element in the chain
      is described by nested ``backingStore`` element.

``mirror``
   This element is present if the hypervisor has started a long-running block
   job operation, where the mirror location in the ``source`` sub-element will
   eventually have the same contents as the source, and with the file format in
   the sub-element ``format`` (which might differ from the format of the
   source). The details of the ``source`` sub-element are determined by the
   ``type`` attribute of the mirror, similar to what is done for the overall
   ``disk`` device element. The ``job`` attribute mentions which API started the
   operation ("copy" for the ``virDomainBlockRebase`` API, or "active-commit"
   for the ``virDomainBlockCommit`` API), :since:`since 1.2.7` . The attribute
   ``ready``, if present, tracks progress of the job: ``yes`` if the disk is
   known to be ready to pivot, or, :since:`since 1.2.7` , ``abort`` or ``pivot``
   if the job is in the process of completing. If ``ready`` is not present, the
   disk is probably still copying. For now, this element only valid in output;
   it is ignored on input. The ``source`` sub-element exists for all two-phase
   jobs :since:`since 1.2.6` . Older libvirt supported only block copy to a
   file, :since:`since 0.9.12` ; for compatibility with older clients, such jobs
   include redundant information in the attributes ``file`` and ``format`` in
   the ``mirror`` element.
``target``
   The ``target`` element controls the bus / device under which the disk is
   exposed to the guest OS. The ``dev`` attribute indicates the "logical" device
   name. The actual device name specified is not guaranteed to map to the device
   name in the guest OS. Treat it as a device ordering hint. The optional
   ``bus`` attribute specifies the type of disk device to emulate; possible
   values are driver specific, with typical values being "ide", "scsi",
   "virtio", "xen", "usb", "sata", or "sd" :since:`"sd" since 1.1.2` . If
   omitted, the bus type is inferred from the style of the device name (e.g. a
   device named 'sda' will typically be exported using a SCSI bus). The optional
   attribute ``tray`` indicates the tray status of the removable disks (i.e.
   CDROM or Floppy disk), the value can be either "open" or "closed", defaults
   to "closed". NB, the value of ``tray`` could be updated while the domain is
   running. The optional attribute ``removable`` sets the removable flag for USB
   or SCSI disks, and its value can be either "on" or "off", defaulting to "off".
   The optional attribute ``rotation_rate`` sets the rotation rate of the
   storage for disks on a SCSI, IDE, or SATA bus. Values in the range 1025 to
   65534 are used to indicate rotational media speed in revolutions per minute.
   A value of one is used to indicate solid state, or otherwise non-rotational,
   storage. These values are not required to match the values of the underlying
   host storage.
   :since:`Since 0.0.3`; ``bus`` attribute :since:`since 0.4.3`; ``tray``
   attribute :since:`since 0.9.11`; "usb" attribute value
   :since:`since after 0.4.4`; "sata" attribute value :since:`since 0.9.7`;
   "removable" attribute value :since:`since 1.1.3`;
   "rotation_rate" attribute value :since:`since 7.3.0`
``iotune``
   The optional ``iotune`` element provides the ability to provide additional
   per-device I/O tuning, with values that can vary for each device (contrast
   this to the ``blkiotune`` element (See `Block I/O Tuning`_), which applies
   globally to the domain). Currently, the only tuning available is Block I/O
   throttling for qemu. This element has optional sub-elements; any sub-element
   not specified or given with a value of 0 implies no limit. :since:`Since
   0.9.8`

   ``total_bytes_sec``
      The optional ``total_bytes_sec`` element is the total throughput limit in
      bytes per second. This cannot appear with ``read_bytes_sec`` or
      ``write_bytes_sec``.
   ``read_bytes_sec``
      The optional ``read_bytes_sec`` element is the read throughput limit in
      bytes per second.
   ``write_bytes_sec``
      The optional ``write_bytes_sec`` element is the write throughput limit in
      bytes per second.
   ``total_iops_sec``
      The optional ``total_iops_sec`` element is the total I/O operations per
      second. This cannot appear with ``read_iops_sec`` or ``write_iops_sec``.
   ``read_iops_sec``
      The optional ``read_iops_sec`` element is the read I/O operations per
      second.
   ``write_iops_sec``
      The optional ``write_iops_sec`` element is the write I/O operations per
      second.
   ``total_bytes_sec_max``
      The optional ``total_bytes_sec_max`` element is the maximum total
      throughput limit in bytes per second. This cannot appear with
      ``read_bytes_sec_max`` or ``write_bytes_sec_max``.
   ``read_bytes_sec_max``
      The optional ``read_bytes_sec_max`` element is the maximum read throughput
      limit in bytes per second.
   ``write_bytes_sec_max``
      The optional ``write_bytes_sec_max`` element is the maximum write
      throughput limit in bytes per second.
   ``total_iops_sec_max``
      The optional ``total_iops_sec_max`` element is the maximum total I/O
      operations per second. This cannot appear with ``read_iops_sec_max`` or
      ``write_iops_sec_max``.
   ``read_iops_sec_max``
      The optional ``read_iops_sec_max`` element is the maximum read I/O
      operations per second.
   ``write_iops_sec_max``
      The optional ``write_iops_sec_max`` element is the maximum write I/O
      operations per second.
   ``size_iops_sec``
      The optional ``size_iops_sec`` element is the size of I/O operations per
      second.

      :since:`Throughput limits since 1.2.11 and QEMU 1.7`

   ``group_name``
      The optional ``group_name`` provides the ability to share I/O throttling
      quota between multiple drives. This prevents end-users from circumventing
      a hosting provider's throttling policy by splitting 1 large drive in N
      small drives and getting N times the normal throttling quota. Any name may
      be used.

      :since:`group_name since 3.0.0 and QEMU 2.4`

   ``total_bytes_sec_max_length``
      The optional ``total_bytes_sec_max_length`` element is the maximum
      duration in seconds for the ``total_bytes_sec_max`` burst period. Only
      valid when the ``total_bytes_sec_max`` is set.
   ``read_bytes_sec_max_length``
      The optional ``read_bytes_sec_max_length`` element is the maximum duration
      in seconds for the ``read_bytes_sec_max`` burst period. Only valid when
      the ``read_bytes_sec_max`` is set.
   ``write_bytes_sec_max``
      The optional ``write_bytes_sec_max_length`` element is the maximum
      duration in seconds for the ``write_bytes_sec_max`` burst period. Only
      valid when the ``write_bytes_sec_max`` is set.
   ``total_iops_sec_max_length``
      The optional ``total_iops_sec_max_length`` element is the maximum duration
      in seconds for the ``total_iops_sec_max`` burst period. Only valid when
      the ``total_iops_sec_max`` is set.
   ``read_iops_sec_max_length``
      The optional ``read_iops_sec_max_length`` element is the maximum duration
      in seconds for the ``read_iops_sec_max`` burst period. Only valid when the
      ``read_iops_sec_max`` is set.
   ``write_iops_sec_max``
      The optional ``write_iops_sec_max_length`` element is the maximum duration
      in seconds for the ``write_iops_sec_max`` burst period. Only valid when
      the ``write_iops_sec_max`` is set.

      :since:`Throughput length since 2.4.0 and QEMU 2.6`

``driver``
   The optional driver element allows specifying further details related to the
   hypervisor driver used to provide the disk. :since:`Since 0.1.8`

   -  If the hypervisor supports multiple backend drivers, then the ``name``
      attribute selects the primary backend driver name, while the optional
      ``type`` attribute provides the sub-type. For example, xen supports a name
      of "tap", "tap2", "phy", or "file", with a type of "aio", while qemu only
      supports a name of "qemu", but multiple types including "raw", "bochs",
      "qcow2", and "qed".
   -  The optional ``cache`` attribute controls the cache mechanism, possible
      values are "default", "none", "writethrough", "writeback", "directsync"
      (like "writethrough", but it bypasses the host page cache) and "unsafe"
      (host may cache all disk io, and sync requests from guest are ignored).
      :since:`Since 0.6.0, "directsync" since 0.9.5, "unsafe" since 0.9.7`
   -  The optional ``error_policy`` attribute controls how the hypervisor will
      behave on a disk read or write error, possible values are "stop",
      "report", "ignore", and "enospace". :since:`Since 0.8.0, "report" since
      0.9.7` The default is left to the discretion of the hypervisor. There is
      also an optional ``rerror_policy`` that controls behavior for read errors
      only. :since:`Since 0.9.7` . If no rerror_policy is given, error_policy is
      used for both read and write errors. If rerror_policy is given, it
      overrides the ``error_policy`` for read errors. Also note that "enospace"
      is not a valid policy for read errors, so if ``error_policy`` is set to
      "enospace" and no ``rerror_policy`` is given, the read error policy will
      be left at its default.
   -  The optional ``io`` attribute controls specific policies on I/O; qemu
      guests support "threads" and "native" :since:`Since 0.8.8` , io_uring
      :since:`Since 6.3.0 (QEMU 5.0)` .
   -  The optional ``ioeventfd`` attribute allows users to set `domain I/O
      asynchronous handling <https://patchwork.kernel.org/patch/43390/>`__ for
      disk device. The default is left to the discretion of the hypervisor.
      Accepted values are "on" and "off". Enabling this allows qemu to execute
      VM while a separate thread handles I/O. Typically guests experiencing high
      system CPU utilization during I/O will benefit from this. On the other
      hand, on overloaded host it could increase guest I/O latency.
      :since:`Since 0.9.3 (QEMU and KVM only)` **In general you should leave
      this option alone, unless you are very certain you know what you are
      doing.**
   -  The optional ``event_idx`` attribute controls some aspects of device event
      processing. The value can be either 'on' or 'off' - if it is on, it will
      reduce the number of interrupts and exits for the guest. The default is
      determined by QEMU; usually if the feature is supported, default is on. In
      case there is a situation where this behavior is suboptimal, this
      attribute provides a way to force the feature off. :since:`Since 0.9.5
      (QEMU and KVM only)` **In general you should leave this option alone,
      unless you are very certain you know what you are doing.**
   -  The optional ``copy_on_read`` attribute controls whether to copy read
      backing file into the image file. The value can be either "on" or "off".
      Copy-on-read avoids accessing the same backing file sectors repeatedly and
      is useful when the backing file is over a slow network. By default
      copy-on-read is off. :since:`Since 0.9.10 (QEMU and KVM only)`
   -  The optional ``discard`` attribute controls whether discard requests (also
      known as "trim" or "unmap") are ignored or passed to the filesystem. The
      value can be either "unmap" (allow the discard request to be passed) or
      "ignore" (ignore the discard request). :since:`Since 1.0.6 (QEMU and KVM
      only)`
   -  The optional ``detect_zeroes`` attribute controls whether to detect zero
      write requests. The value can be "off", "on" or "unmap". First two values
      turn the detection off and on, respectively. The third value ("unmap")
      turns the detection on and additionally tries to discard such areas from
      the image based on the value of ``discard`` above (it will act as "on" if
      ``discard`` is set to "ignore"). NB enabling the detection is a compute
      intensive operation, but can save file space and/or time on slow media.
      :since:`Since 2.0.0`
   -  The optional ``iothread`` attribute assigns the disk to an IOThread as
      defined by the range for the domain ``iothreads`` value. (See
      `IOThreads Allocation`_). Multiple disks may be
      assigned to the same IOThread and are numbered from 1 to the domain
      iothreads value. Available for a disk device ``target`` configured to use
      "virtio" ``bus`` and "pci" or "ccw" ``address`` types. :since:`Since 1.2.8
      (QEMU 2.1)`
   -  The optional ``queues`` attribute specifies the number of virt queues for
      virtio-blk ( :since:`Since 3.9.0` ) or vhost-user-blk
      ( :since `Since 7.1.0` )
   -  The optional ``queue_size`` attribute specifies the size of each virt
      queue for virtio-blk or vhost-user-blk. ( :since:`Since 7.8.0` )
   -  For virtio disks, `Virtio-related options`_ can also
      be set. ( :since:`Since 3.5.0` )
   -  The optional ``metadata_cache`` subelement controls aspects related to the
      format specific caching of storage image metadata. Note that this setting
      applies only on the top level image; the identically named subelement of
      ``backingStore``'s ``format`` element can be used to specify cache
      settings for the backing image.

      :since:`Since 7.0.0` the maximum size of the metadata cache of ``qcow2``
      format driver of the ``qemu`` hypervisor can be controlled via the
      ``max_size`` subelement (see example below).

      The optional ``discard_no_unref`` attribute can be set to control the way
      the ``qemu`` hypervisor handles guest discard commands inside the qcow2
      image. When enabled, a discard request from within the guest will mark the
      qcow2 cluster as zero, but will keep the reference/offset of that cluster.
      But it will still pass the discard further to the lower layer.
      This will resolve fragmentation within the qcow2 image. :since:`Since 9.5.0
      (QEMU 8.1)`

      In the majority of cases the default configuration used by the hypervisor
      is sufficient so modifying this setting should not be necessary. For
      specifics on how the metadata cache of ``qcow2`` in ``qemu`` behaves refer
      to the ``qemu``
      `qcow2 cache docs <https://git.qemu.org/?p=qemu.git;a=blob;f=docs/qcow2-cache.txt>`__

      **Example**::

        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'>
            <metadata_cache>
              <max_size unit='bytes'>1234</max_size>
            </metadata_cache>
          </driver>
          <source file='/var/lib/libvirt/images/domain.qcow'/>
          <backingStore type='file'>
            <format type='qcow2'>
              <metadata_cache>
                <max_size unit='bytes'>1234</max_size>
              </metadata_cache>
            </format>
            <source file='/var/lib/libvirt/images/snapshot.qcow'/>
            <backingStore/>
          </backingStore>
          <target dev='vdd' bus='virtio'/>
        </disk>

``backenddomain``
   The optional ``backenddomain`` element allows specifying a backend domain
   (aka driver domain) hosting the disk. Use the ``name`` attribute to specify
   the backend domain name. :since:`Since 1.2.13 (Xen only)`
``boot``
   Specifies that the disk is bootable. The ``order`` attribute determines the
   order in which devices will be tried during boot sequence. On the S390
   architecture only the first boot device is used. The optional ``loadparm``
   attribute is an 8 character string which can be queried by guests on S390 via
   sclp or diag 308. Linux guests on S390 can use ``loadparm`` to select a boot
   entry. :since:`Since 3.5.0` The per-device ``boot`` elements cannot be used
   together with general boot elements in `BIOS bootloader`_
   section. :since:`Since 0.8.8`
``encryption``
   Starting with :since:`libvirt 3.9.0` the ``encryption`` element is preferred
   to be a sub-element of the ``source`` element. If present, specifies how the
   volume is encrypted using "qcow". See the `Storage
   Encryption <formatstorageencryption.html>`__ page for more information.
``readonly``
   If present, this indicates the device cannot be modified by the guest. For
   now, this is the default for disks with attribute ``device='cdrom'``.
``shareable``
   If present, this indicates the device is expected to be shared between
   domains (assuming the hypervisor and OS support this), which means that
   caching should be deactivated for that device.
``transient``
   If present, this indicates that changes to the device contents should be
   reverted automatically when the guest exits. With some hypervisors, marking a
   disk transient prevents the domain from participating in migration,
   snapshots, or blockjobs. Only supported in vmx hypervisor
   (:since:`Since 0.9.5`) and ``qemu`` hypervisor (:since:`Since 6.9.0`).

   In cases where the source image of the ``<transient/>`` disk is supposed to
   be shared between multiple concurrently running VMs the optional
   ``shareBacking`` attribute should be set to ``yes``. Note that hypervisor
   drivers may need to hotplug such disk and thus it works only with
   configurations supporting hotplug. :since:`Since 7.4.0`
``serial``
   If present, this specify serial number of virtual hard drive. For example, it
   may look like ``<serial>WD-WMAP9A966149</serial>``. Not supported for
   scsi-block devices, that is those using disk ``type`` 'block' using
   ``device`` 'lun' on ``bus`` 'scsi'. :since:`Since 0.7.1`

   Note that depending on hypervisor and device type the serial number may be
   truncated silently. IDE/SATA devices are commonly limited to 20 characters.
   SCSI devices depending on hypervisor version are limited to 20, 36 or 247
   characters.

   Hypervisors may also start rejecting overly long serials instead of
   truncating them in the future so it's advised to avoid the implicit
   truncation by testing the desired serial length range with the desired device
   and hypervisor combination.
``wwn``
   If present, this element specifies the WWN (World Wide Name) of a virtual
   hard disk or CD-ROM drive. It must be composed of 16 hexadecimal digits.
   :since:`Since 0.10.1`
``vendor``
   If present, this element specifies the vendor of a virtual hard disk or
   CD-ROM device. It must not be longer than 8 printable characters.
   :since:`Since 1.0.1`
``product``
   If present, this element specifies the product of a virtual hard disk or
   CD-ROM device. It must not be longer than 16 printable characters.
   :since:`Since 1.0.1`
``address``
   If present, the ``address`` element ties the disk to a given slot of a
   controller (the actual ``<controller>`` device can often be inferred by
   libvirt, although it can be be explicitly specified. See `Controllers`_).
   The ``type`` attribute is mandatory, and is typically "pci" or "drive". For a
   "pci" controller, additional attributes for ``bus``, ``slot``, and
   ``function`` must be present, as well as optional ``domain`` and
   ``multifunction``. Multifunction defaults to 'off'; any other value requires
   QEMU 0.1.3 and :since:`libvirt 0.9.7` . For a "drive" controller, additional
   attributes ``controller``, ``bus``, ``target`` ( :since:`libvirt 0.9.11` ),
   and ``unit`` are available, each defaulting to 0.
``auth``
   Starting with :since:`libvirt 3.9.0` the ``auth`` element is preferred to be
   a sub-element of the ``source`` element. The element is still read and
   managed as a ``disk`` sub-element. It is invalid to use ``auth`` as both a
   sub-element of ``disk`` and ``source``. The ``auth`` element was introduced
   as a ``disk`` sub-element in :since:`libvirt 0.9.7.`
``geometry``
   The optional ``geometry`` element provides the ability to override geometry
   settings. This mostly useful for S390 DASD-disks or older DOS-disks.
   :since:`0.10.0`

   ``cyls``
      The ``cyls`` attribute is the number of cylinders.
   ``heads``
      The ``heads`` attribute is the number of heads.
   ``secs``
      The ``secs`` attribute is the number of sectors per track.
   ``trans``
      The optional ``trans`` attribute is the BIOS-Translation-Modus (none, lba
      or auto)

``blockio``
   If present, the ``blockio`` element allows to override any of the block
   device properties listed below. :since:`Since 0.10.2 (QEMU and KVM)`

   ``logical_block_size``
      The logical block size the disk will report to the guest OS. For Linux
      this would be the value returned by the BLKSSZGET ioctl and describes the
      smallest units for disk I/O.
   ``physical_block_size``
      The physical block size the disk will report to the guest OS. For Linux
      this would be the value returned by the BLKPBSZGET ioctl and describes the
      disk's hardware sector size which can be relevant for the alignment of
      disk data.
   ``discard_granularity``
      The smallest amount of data that can be discarded in a single operation.
      It impacts the unmap operations and it must be a multiple of a
      ``logical_block_size``. This is usually properly configured by the
      hypervisor.

Filesystems
~~~~~~~~~~~

A directory on the host that can be accessed directly from the guest.
:since:`since 0.3.3, since 0.8.5 for QEMU/KVM`

::

   ...
   <devices>
     <filesystem type='template'>
       <source name='my-vm-template'/>
       <target dir='/'/>
     </filesystem>
     <filesystem type='mount' accessmode='passthrough' multidevs='remap'>
       <driver type='path' wrpolicy='immediate'/>
       <source dir='/export/to/guest'/>
       <target dir='/import/from/host'/>
       <readonly/>
     </filesystem>
     <filesystem type='mount' accessmode='mapped' fmode='644' dmode='755'>
       <driver type='path'/>
       <source dir='/export/to/guest'/>
       <target dir='/import/from/host'/>
       <readonly/>
     </filesystem>
     <filesystem type='file' accessmode='passthrough'>
       <driver type='loop' format='raw'/>
       <source file='/export/to/guest.img'/>
       <target dir='/import/from/host'/>
       <readonly/>
     </filesystem>
     <filesystem type='mount' accessmode='passthrough'>
         <driver type='virtiofs' queue='1024'/>
         <binary path='/usr/libexec/virtiofsd' xattr='on'>
            <cache mode='always'/>
            <sandbox mode='namespace'/>
            <lock posix='on' flock='on'/>
            <thread_pool size='16'/>
         </binary>
         <source dir='/path'/>
         <target dir='mount_tag'/>
     </filesystem>
     <filesystem type='mount'>
         <driver type='virtiofs' queue='1024'/>
         <source socket='/tmp/sock'/>
         <target dir='tag'/>
     </filesystem>
     ...
   </devices>
   ...

``filesystem``
   The filesystem attribute ``type`` specifies the type of the ``source``. The
   possible values are:

   ``mount``
      A host directory to mount in the guest. Used by LXC, OpenVZ :since:`(since
      0.6.2)` and QEMU/KVM :since:`(since 0.8.5)` . This is the default ``type``
      if one is not specified. This mode also has an optional sub-element
      ``driver``, with an attribute ``type='path'`` or ``type='handle'``
      :since:`(since 0.9.7)` . The driver block has an optional attribute
      ``wrpolicy`` that further controls interaction with the host page cache;
      omitting the attribute gives default behavior, while the value
      ``immediate`` means that a host writeback is immediately triggered for all
      pages touched during a guest file write operation :since:`(since 0.9.10)`
      . :since:`Since 6.2.0` , ``type='virtiofs'`` is also supported. Using
      virtiofs requires setting up shared memory, see the guide:
      `Virtiofs <kbase/virtiofs.html>`__
   ``template``
      OpenVZ filesystem template. Only used by OpenVZ driver.
   ``file``
      A host file will be treated as an image and mounted in the guest. The
      filesystem format will be autodetected. Only used by LXC driver.
   ``block``
      A host block device to mount in the guest. The filesystem format will be
      autodetected. Only used by LXC driver :since:`(since 0.9.5)` .
   ``ram``
      An in-memory filesystem, using memory from the host OS. The source element
      has a single attribute ``usage`` which gives the memory usage limit in
      KiB, unless units are specified by the ``units`` attribute. Only used by
      LXC driver. :since:`(since 0.9.13)`
   ``bind``
      A directory inside the guest will be bound to another directory inside the
      guest. Only used by LXC driver :since:`(since 0.9.13)`

   The filesystem element has an optional attribute ``accessmode`` which
   specifies the security mode for accessing the source :since:`(since 0.8.5)` .
   Currently this only works with ``type='mount'`` for the QEMU/KVM driver. For
   driver type ``virtiofs``, only ``passthrough`` is supported. For other driver
   types, the possible values are:

   ``passthrough``
      The ``source`` is accessed with the permissions of the user inside the
      guest. This is the default ``accessmode`` if one is not specified. `More
      info <https://lists.gnu.org/archive/html/qemu-devel/2010-05/msg02673.html>`__
   ``mapped``
      The ``source`` is accessed with the permissions of the hypervisor (QEMU
      process). `More
      info <https://lists.gnu.org/archive/html/qemu-devel/2010-05/msg02673.html>`__
   ``squash``
      Similar to 'passthrough', the exception is that failure of privileged
      operations like 'chown' are ignored. This makes a passthrough-like mode
      usable for people who run the hypervisor as non-root. `More
      info <https://lists.gnu.org/archive/html/qemu-devel/2010-09/msg00121.html>`__

   :since:`Since 5.2.0` , the filesystem element has an optional attribute
   ``model`` with supported values "virtio-transitional",
   "virtio-non-transitional", or "virtio". See `Virtio transitional devices`_
   for more details.

   The filesystem element has optional attributes ``fmode`` and ``dmode``.
   These two attributes control the creation mode for files and directories
   when used with the ``mapped`` value for ``accessmode`` (:since:`since 6.10.0,
   requires QEMU 2.10` ).  If not specified, QEMU creates files with mode
   ``600`` and directories with mode ``700``. The setuid, setgid, and sticky
   bit are unsupported.

   The filesystem element has an optional attribute ``multidevs`` which
   specifies how to deal with a filesystem export containing more than one
   device, in order to avoid file ID collisions on guest when using 9pfs (
   :since:`since 6.3.0, requires QEMU 4.2` ). This attribute is not available
   for virtiofs. The possible values are:

   ``default``
      Use QEMU's default setting (which currently is ``warn``).
   ``remap``
      This setting allows guest to access multiple devices per export without
      encountering misbehaviours. Inode numbers from host are automatically
      remapped on guest to actively prevent file ID collisions if guest accesses
      one export containing multiple devices.
   ``forbid``
      Only allow to access one device per export by guest. Attempts to access
      additional devices on the same export will cause the individual filesystem
      access by guest to fail with an error and being logged (once) as error on
      host side.
   ``warn``
      This setting resembles the behaviour of 9pfs prior to QEMU 4.2, that is no
      action is performed to prevent any potential file ID collisions if an
      export contains multiple devices, with the only exception: a warning is
      logged (once) on host side now. This setting may lead to misbehaviours on
      guest side if more than one device is exported per export, due to the
      potential file ID collisions this may cause on guest side in that case.

``driver``
   The optional driver element allows specifying further details related to the
   hypervisor driver used to provide the filesystem. :since:`Since 1.0.6`

   -  If the hypervisor supports multiple backend drivers, then the ``type``
      attribute selects the primary backend driver name, while the ``format``
      attribute provides the format type. For example, LXC supports a type of
      "loop", with a format of "raw" or "nbd" with any format. QEMU supports a
      type of "path" or "handle", but no formats. Virtuozzo driver supports a
      type of "ploop" with a format of "ploop".
   -  For virtio-backed devices, `Virtio-related options`_
      can also be set. ( :since:`Since 3.5.0` )
   -  For ``virtiofs``, the ``queue`` attribute can be used to specify the queue
      size (i.e. how many requests can the queue fit). ( :since:`Since 6.2.0` )

``binary``
   The optional ``binary`` element can tune the options for virtiofsd. All of
   the following attributes and elements are optional. The attribute ``path``
   can be used to override the path to the daemon. Attribute ``xattr`` enables
   the use of filesystem extended attributes. Caching can be tuned via the
   ``cache`` element, possible ``mode`` values being ``none`` and ``always``.
   Locking can be controlled via the ``lock`` element - attributes ``posix`` and
   ``flock`` both accepting values ``on`` or ``off``. ( :since:`Since 6.2.0` )
   The sandboxing method used by virtiofsd can be configured with the ``sandbox``
   element, possible ``mode`` values being ``namespace`` and
   ``chroot``, see the
   `virtiofsd documentation <https://qemu.readthedocs.io/en/latest/tools/virtiofsd.html>`__
   for more details. ( :since:`Since 7.2.0` )
   Element ``thread_pool`` accepts one attribute ``size`` which defines the
   maximum thread pool size. A value of "0" disables the pool.
   The thread pool helps increase the number of requests in flight when used with
   storage that has a higher latency.  However, it has an overhead, and so for
   fast, low latency filesystems, it may be best to turn it off. ( :since:`Since 8.5.0` )
``source``
   The resource on the host that is being accessed in the guest. The ``name``
   attribute must be used with ``type='template'``, and the ``dir`` attribute
   must be used with ``type='mount'``. For ``virtiofs``, the ``socket`` attribute
   can be used to connect to a virtiofsd daemon launched outside of libvirt.
   In that case, the ``target`` element does not apply and neither do most
   virtiofs-related options, since they are controlled by virtiofsd, not libvirtd.
   The ``usage`` attribute is used with
   ``type='ram'`` to set the memory limit in KiB, unless units are specified by
   the ``units`` attribute.
``target``
   Where the ``source`` can be accessed in the guest. For most drivers this is
   an automatic mount point, but for QEMU/KVM this is merely an arbitrary string
   tag that is exported to the guest as a hint for where to mount.
``readonly``
   Enables exporting filesystem as a readonly mount for guest, by default
   read-write access is given (currently only works for QEMU/KVM driver; not
   with virtiofs).
``space_hard_limit``
   Maximum space available to this guest's filesystem. :since:`Since 0.9.13`
   Only supported by the OpenVZ driver.
``space_soft_limit``
   Maximum space available to this guest's filesystem. The container is
   permitted to exceed its soft limits for a grace period of time. Afterwards
   the hard limit is enforced. :since:`Since 0.9.13`
   Only supported by the OpenVZ driver.


Device Addresses
~~~~~~~~~~~~~~~~

Many devices have an optional ``<address>`` sub-element to describe where the
device is placed on the virtual bus presented to the guest. If an address (or
any optional attribute within an address) is omitted on input, libvirt will
generate an appropriate address; but an explicit address is required if more
control over layout is required. See below for device examples including an
address element.

Every address has a mandatory attribute ``type`` that describes which bus the
device is on. The choice of which address to use for a given device is
constrained in part by the device and the architecture of the guest. For
example, a ``<disk>`` device uses ``type='drive'``, while a ``<console>`` device
would use ``type='pci'`` on i686 or x86_64 guests, or ``type='spapr-vio'`` on
PowerPC64 pseries guests. Each address type has further optional attributes that
control where on the bus the device will be placed:

``pci``
   PCI addresses have the following additional attributes: ``domain`` (a 2-byte
   hex integer, not currently used by qemu), ``bus`` (a hex value between 0 and
   0xff, inclusive), ``slot`` (a hex value between 0x0 and 0x1f, inclusive), and
   ``function`` (a value between 0 and 7, inclusive). Also available is the
   ``multifunction`` attribute, which controls turning on the multifunction bit
   for a particular slot/function in the PCI control register ( :since:`since
   0.9.7, requires QEMU 0.13` ). ``multifunction`` defaults to 'off', but should
   be set to 'on' for function 0 of a slot that will have multiple functions
   used. ( :since:`Since 4.10.0` ), PCI address extensions depending on the
   architecture are supported. For example, PCI addresses for S390 guests will
   have a ``zpci`` child element, with two attributes: ``uid`` (a hex value
   between 0x0001 and 0xffff, inclusive), and ``fid`` (a hex value between
   0x00000000 and 0xffffffff, inclusive) used by PCI devices on S390 for
   User-defined Identifiers and Function Identifiers.
   :since:`Since 1.3.5` , some hypervisor drivers may accept an
   ``<address type='pci'/>`` element with no other attributes as an explicit
   request to assign a PCI address for the device rather than some other type of
   address that may also be appropriate for that same device (e.g. virtio-mmio).
   The relationship between the PCI addresses configured in the domain XML and
   those seen by the guest OS can sometime seem confusing: a separate document
   describes `how PCI addresses work <pci-addresses.html>`__ in more detail.
``drive``
   Drive addresses have the following additional attributes: ``controller`` (a
   2-digit controller number), ``bus`` (a 2-digit bus number), ``target`` (a
   2-digit target number), and ``unit`` (a 2-digit unit number on the bus).
``virtio-serial``
   Each virtio-serial address has the following additional attributes:
   ``controller`` (a 2-digit controller number), ``bus`` (a 2-digit bus number),
   and ``slot`` (a 2-digit slot within the bus).
``ccid``
   A CCID address, for smart-cards, has the following additional attributes:
   ``bus`` (a 2-digit bus number), and ``slot`` attribute (a 2-digit slot within
   the bus). :since:`Since 0.8.8.`
``usb``
   USB addresses have the following additional attributes: ``bus`` (a hex value
   between 0 and 0xfff, inclusive), and ``port`` (a dotted notation of up to
   four octets, such as 1.2 or 2.1.3.1).
``spapr-vio``
   On PowerPC pseries guests, devices can be assigned to the SPAPR-VIO bus. It
   has a flat 32-bit address space; by convention, devices are generally
   assigned at a non-zero multiple of 0x00001000, but other addresses are valid
   and permitted by libvirt. Each address has the following additional
   attribute: ``reg`` (the hex value address of the starting register).
   :since:`Since 0.9.9.`
``ccw``
   S390 guests with a ``machine`` value of s390-ccw-virtio use the native CCW
   bus for I/O devices. CCW bus addresses have the following additional
   attributes: ``cssid`` (a hex value between 0 and 0xfe, inclusive), ``ssid``
   (a value between 0 and 3, inclusive) and ``devno`` (a hex value between 0 and
   0xffff, inclusive). Partially specified bus addresses are not allowed. If
   omitted, libvirt will assign a free bus address with cssid=0xfe and ssid=0.
   Virtio-ccw devices must have their cssid set to 0xfe. :since:`Since 1.0.4`
``virtio-mmio``
   This places the device on the virtio-mmio transport, which is currently only
   available for some ``armv7l`` and ``aarch64`` virtual machines. virtio-mmio
   addresses do not have any additional attributes. :since:`Since 1.1.3`
   If the guest architecture is ``aarch64`` and the machine type is ``virt``,
   libvirt will automatically assign PCI addresses to devices; however, the
   presence of a single device with virtio-mmio address in the guest
   configuration will cause libvirt to assign virtio-mmio addresses to all
   further devices. :since:`Since 3.0.0`
``isa``
   ISA addresses have the following additional attributes: ``iobase`` and
   ``irq``. :since:`Since 1.2.1`
``unassigned``
   For PCI hostdevs, ``<address type='unassigned'/>`` allows the admin to
   include a PCI hostdev in the domain XML definition, without making it
   available for the guest. This allows for configurations in which Libvirt
   manages the device as a regular PCI hostdev, regardless of whether the guest
   will have access to it. ``<address type='unassigned'/>`` is an invalid
   address type for all other device types. :since:`Since 6.0.0`


Virtio-related options
~~~~~~~~~~~~~~~~~~~~~~

QEMU's virtio devices have some attributes related to the virtio transport under
the ``driver`` element: The ``iommu`` attribute enables the use of emulated
IOMMU by the device. The attribute ``ats`` controls the Address Translation
Service support for PCIe devices. This is needed to make use of IOTLB support
(see `IOMMU devices`_). Possible values are ``on`` or ``off``.
:since:`Since 3.5.0`

The attribute ``packed`` controls if QEMU should try to use packed virtqueues.
Compared to regular split queues, packed queues consist of only a single
descriptor ring replacing available and used ring, index and descriptor buffer.
This can result in better cache utilization and performance. If packed
virtqueues are actually used depends on the feature negotiation between QEMU,
vhost backends and guest drivers. Possible values are ``on`` or ``off``.
:since:`Since 6.3.0 (QEMU and KVM only)`

This optional attribute ``page_per_vq`` controls the layout of the notification
capabilities exposed to the guest. When enabled, each virtio queue will have a
dedicated page on the device BAR exposed to the guest. It is recommended to be
used when vDPA is enabled on the hypervisor, as it enables mapping the
notification area to the physical device, which is only supported in page
granularity. The default is determined by QEMU. :since:`Since 7.9.0 (QEMU 2.8)`
Note: In general you should leave this option alone, unless you are very certain
you know what you are doing.


Virtio transitional devices
~~~~~~~~~~~~~~~~~~~~~~~~~~~

:since:`Since 5.2.0` , some of QEMU's virtio devices, when used with PCI/PCIe
machine types, accept the following ``model`` values:

``virtio-transitional``
   This device can work both with virtio 0.9 and virtio 1.0 guest drivers, so
   it's the best choice when compatibility with older guest operating systems is
   desired. libvirt will plug the device into a conventional PCI slot.
``virtio-non-transitional``
   This device can only work with virtio 1.0 guest drivers, and it's the
   recommended option unless compatibility with older guest operating systems is
   necessary. libvirt will plug the device into either a PCI Express slot or a
   conventional PCI slot based on the machine type, resulting in a more
   optimized PCI topology.
``virtio``
   This device will work like a ``virtio-non-transitional`` device when plugged
   into a PCI Express slot, and like a ``virtio-transitional`` device otherwise;
   libvirt will pick one or the other based on the machine type. This is the
   best choice when compatibility with libvirt versions older than 5.2.0 is
   necessary, but it's otherwise not recommended to use it.

While the information outlined above applies to most virtio devices, there are a
few exceptions:

-  for SCSI controllers, there is no ``virtio`` model available due to
   historical reasons: use ``virtio-scsi`` instead, which behaves the same as
   ``virtio`` does for other devices. Both ``virtio-transitional`` and
   ``virtio-non-transitional`` work with SCSI controllers;
-  some devices, such as GPUs and input devices (keyboard, tablet and mouse),
   are only defined in the virtio 1.0 spec and as such don't have a transitional
   variant: the only accepted model is ``virtio``, which will result in a
   non-transitional device.

For more details see the `qemu patch
posting <https://lists.gnu.org/archive/html/qemu-devel/2018-12/msg00923.html>`__
and the `virtio-1.0
spec <https://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html>`__.


Controllers
~~~~~~~~~~~

Depending on the guest architecture, some device buses can appear more than
once, with a group of virtual devices tied to a virtual controller. Normally,
libvirt can automatically infer such controllers without requiring explicit XML
markup, but sometimes it is necessary to provide an explicit controller element,
notably when planning the `PCI topology <pci-hotplug.html>`__ for guests where
device hotplug is expected.

::

   ...
   <devices>
     <controller type='ide' index='0'/>
     <controller type='virtio-serial' index='0' ports='16' vectors='4'/>
     <controller type='virtio-serial' index='1'>
       <address type='pci' domain='0x0000' bus='0x00' slot='0x0a' function='0x0'/>
     </controller>
     <controller type='scsi' index='0' model='virtio-scsi'>
       <driver iothread='4'/>
       <address type='pci' domain='0x0000' bus='0x00' slot='0x0b' function='0x0'/>
     </controller>
     <controller type='xenbus' maxGrantFrames='64' maxEventChannels='2047'/>
     ...
   </devices>
   ...

Each controller has a mandatory attribute ``type``, which must be one of 'ide',
'fdc', 'scsi', 'sata', 'usb', 'ccid', 'virtio-serial' or 'pci', and a mandatory
attribute ``index`` which is the decimal integer describing in which order the
bus controller is encountered (for use in ``controller`` attributes of
``<address>`` elements). :since:`Since 1.3.5` the index is optional; if not
specified, it will be auto-assigned to be the lowest unused index for the given
controller type. Some controller types have additional attributes that control
specific features, such as:

``virtio-serial``
   The ``virtio-serial`` controller has two additional optional attributes
   ``ports`` and ``vectors``, which control how many devices can be connected
   through the controller. :since:`Since 5.2.0` , it supports an optional
   attribute ``model`` which can be 'virtio', 'virtio-transitional', or
   'virtio-non-transitional'. See `Virtio transitional devices`_ for more details.
``scsi``
   A ``scsi`` controller has an optional attribute ``model``, which is one of
   'auto', 'buslogic', 'ibmvscsi', 'lsilogic', 'lsisas1068', 'lsisas1078',
   'virtio-scsi', 'vmpvscsi', 'virtio-transitional', 'virtio-non-transitional',
   'ncr53c90' (as builtin implicit controller only), 'am53c974', 'dc390'.
   See `Virtio transitional devices`_ for more details.
``usb``
   A ``usb`` controller has an optional attribute ``model``, which is one of
   "piix3-uhci", "piix4-uhci", "ehci", "ich9-ehci1", "ich9-uhci1", "ich9-uhci2",
   "ich9-uhci3", "vt82c686b-uhci", "pci-ohci", "nec-xhci", "qusb1" (xen pvusb
   with qemu backend, version 1.1), "qusb2" (xen pvusb with qemu backend,
   version 2.0) or "qemu-xhci". Additionally, :since:`since 0.10.0` , if the USB
   bus needs to be explicitly disabled for the guest, ``model='none'`` may be
   used. :since:`Since 1.0.5` , no default USB controller will be built on s390.
   :since:`Since 1.3.5` , USB controllers accept a ``ports`` attribute to
   configure how many devices can be connected to the controller.
``ide``
   :since:`Since 3.10.0` for the vbox driver, the ``ide`` controller has an
   optional attribute ``model``, which is one of "piix3", "piix4" or "ich6".
``xenbus``
   :since:`Since 5.2.0` , the ``xenbus`` controller has an optional attribute
   ``maxGrantFrames``, which specifies the maximum number of grant frames the
   controller makes available for connected devices. :since:`Since 6.3.0` , the
   xenbus controller supports the optional ``maxEventChannels`` attribute, which
   specifies maximum number of event channels (PV interrupts) that can be used
   by the guest.

Note: The PowerPC64 "spapr-vio" addresses do not have an associated controller.

For controllers that are themselves devices on a PCI or USB bus, an optional
sub-element ``<address>`` can specify the exact relationship of the controller
to its master bus, with semantics described in the `Device Addresses`_ section.

An optional sub-element ``driver`` can specify the driver specific options:

``queues``
   The optional ``queues`` attribute specifies the number of queues for the
   controller. For best performance, it's recommended to specify a value
   matching the number of vCPUs. :since:`Since 1.0.5 (QEMU and KVM only)`
``cmd_per_lun``
   The optional ``cmd_per_lun`` attribute specifies the maximum number of
   commands that can be queued on devices controlled by the host. :since:`Since
   1.2.7 (QEMU and KVM only)`
``max_sectors``
   The optional ``max_sectors`` attribute specifies the maximum amount of data
   in bytes that will be transferred to or from the device in a single command.
   The transfer length is measured in sectors, where a sector is 512 bytes.
   :since:`Since 1.2.7 (QEMU and KVM only)`
``ioeventfd``
   The optional ``ioeventfd`` attribute specifies whether the controller should
   use `I/O asynchronous handling <https://patchwork.kernel.org/patch/43390/>`__
   or not. Accepted values are "on" and "off". :since:`Since 1.2.18`
``iothread``
   Supported for controller type ``scsi`` using model ``virtio-scsi`` for
   ``address`` types ``pci`` and ``ccw`` :since:`since 1.3.5 (QEMU 2.4)` . The
   optional ``iothread`` attribute assigns the controller to an IOThread as
   defined by the range for the domain ``iothreads`` (See `IOThreads Allocation`_).
   Each SCSI ``disk``
   assigned to use the specified ``controller`` will utilize the same IOThread.
   If a specific IOThread is desired for a specific SCSI ``disk``, then multiple
   controllers must be defined each having a specific ``iothread`` value. The
   ``iothread`` value must be within the range 1 to the domain iothreads value.
virtio options
   For virtio controllers, `Virtio-related options`_ can
   also be set. ( :since:`Since 3.5.0` )

USB companion controllers have an optional sub-element ``<master>`` to specify
the exact relationship of the companion to its master controller. A companion
controller is on the same bus as its master, so the companion ``index`` value
should be equal. Not all controller models can be used as companion controllers
and libvirt might provide some sensible defaults (settings of
``master startport`` and ``function`` of an address) for some particular models.
Preferred companion controllers are ``ich-uhci[123]``.

::

   ...
   <devices>
     <controller type='usb' index='0' model='ich9-ehci1'>
       <address type='pci' domain='0' bus='0' slot='4' function='7'/>
     </controller>
     <controller type='usb' index='0' model='ich9-uhci1'>
       <master startport='0'/>
       <address type='pci' domain='0' bus='0' slot='4' function='0' multifunction='on'/>
     </controller>
     ...
   </devices>
   ...

PCI controllers have an optional ``model`` attribute; possible values for this
attribute are

-  ``pci-root``, ``pci-bridge`` ( :since:`since 1.0.5` )
-  ``pcie-root``, ``dmi-to-pci-bridge`` ( :since:`since 1.1.2` )
-  ``pcie-root-port``, ``pcie-switch-upstream-port``,
   ``pcie-switch-downstream-port`` ( :since:`since 1.2.19` )
-  ``pci-expander-bus``, ``pcie-expander-bus`` ( :since:`since 1.3.4` )
-  ``pcie-to-pci-bridge`` ( :since:`since 4.3.0` )

The root controllers (``pci-root`` and ``pcie-root``) have an optional
``pcihole64`` element specifying how big (in kilobytes, or in the unit specified
by ``pcihole64``'s ``unit`` attribute) the 64-bit PCI hole should be. Some
guests (like Windows XP or Windows Server 2003) might crash when QEMU and
Seabios are recent enough to support 64-bit PCI holes, unless this is disabled
(set to 0). :since:`Since 1.1.2 (QEMU only)`

PCI controllers also have an optional subelement ``<model>`` with an attribute
``name``. The name attribute holds the name of the specific device that qemu is
emulating (e.g. "i82801b11-bridge") rather than simply the class of device
("pcie-to-pci-bridge", "pci-bridge"), which is set in the controller element's
model **attribute**. In almost all cases, you should not manually add a
``<model>`` subelement to a controller, nor should you modify one that is
automatically generated by libvirt. :since:`Since 1.2.19 (QEMU only).`

PCI controllers also have an optional subelement ``<target>`` with the
attributes and subelements listed below. These are configurable items that 1)
are visible to the guest OS so must be preserved for guest ABI compatibility,
and 2) are usually left to default values or derived automatically by libvirt.
In almost all cases, you should not manually add a ``<target>`` subelement to a
controller, nor should you modify the values in the those that are automatically
generated by libvirt. :since:`Since 1.2.19 (QEMU only).`

``chassisNr``
   PCI controllers that have attribute model="pci-bridge", can also have a
   ``chassisNr`` attribute in the ``<target>`` subelement, which is used to
   control QEMU's "chassis_nr" option for the pci-bridge device (normally
   libvirt automatically sets this to the same value as the index attribute of
   the pci controller). If set, chassisNr must be between 1 and 255.
``chassis``
   pcie-root-port and pcie-switch-downstream-port controllers can also have a
   ``chassis`` attribute in the ``<target>`` subelement, which is used to set
   the controller's "chassis" configuration value, which is visible to the
   virtual machine. If set, chassis must be between 0 and 255.
``port``
   pcie-root-port and pcie-switch-downstream-port controllers can also have a
   ``port`` attribute in the ``<target>`` subelement, which is used to set the
   controller's "port" configuration value, which is visible to the virtual
   machine. If set, port must be between 0 and 255.
``hotplug``
   pci-root (:since:`Since 7.9.0`), pcie-root-port (:since:`Since 6.3.0`) and
   pcie-switch-downstream-port controllers (:since:`Since 6.3.0`) can
   also have a ``hotplug`` attribute in the ``<target>`` subelement, which is
   used to disable hotplug/unplug of devices on a particular controller. For
   the pci-root controller, the setting affects the ACPI based hotplug. For the
   rest, the setting affects both ACPI based hotplug as well as PCIE native
   hotplug. The default setting of ``hotplug`` is ``on``; it should be set to
   ``off`` to disable hotplug/unplug of devices on a particular controller.

``busNr``
   pci-expander-bus and pcie-expander-bus controllers can have an optional
   ``busNr`` attribute (1-254). This will be the bus number of the new bus; All
   bus numbers between that specified and 255 will be available only for
   assignment to PCI/PCIe controllers plugged into the hierarchy starting with
   this expander bus, and bus numbers less than the specified value will be
   available to the next lower expander-bus (or the root-bus if there are no
   lower expander buses). If you do not specify a busNumber, libvirt will find
   the lowest existing busNumber in all other expander buses (or use 256 if
   there are no others) and auto-assign the busNr of that found bus - 2, which
   provides one bus number for the pci-expander-bus and one for the pci-bridge
   that is automatically attached to it (if you plan on adding more pci-bridges
   to the hierarchy of the bus, you should manually set busNr to a lower value).

   A similar algorithm is used for automatically determining the busNr attribute
   for pcie-expander-bus, but since the pcie-expander-bus doesn't have any
   built-in pci-bridge, the 2nd bus-number is just being reserved for the
   pcie-root-port that must necessarily be connected to the bus in order to
   actually plug in an endpoint device. If you intend to plug multiple devices
   into a pcie-expander-bus, you must connect a pcie-switch-upstream-port to the
   pcie-root-port that is plugged into the pcie-expander-bus, and multiple
   pcie-switch-downstream-ports to the pcie-switch-upstream-port, and of course
   for this to work properly, you will need to decrease the pcie-expander-bus'
   busNr accordingly so that there are enough unused bus numbers above it to
   accommodate giving out one bus number for the upstream-port and one for each
   downstream-port (in addition to the pcie-root-port and the pcie-expander-bus
   itself).

``node``
   Some PCI controllers (``pci-expander-bus`` for the pc machine type,
   ``pcie-expander-bus`` for the q35 machine type and, :since:`since 3.6.0` ,
   ``pci-root`` for the pseries machine type) can have an optional ``<node>``
   subelement within the ``<target>`` subelement, which is used to set the NUMA
   node reported to the guest OS for that bus - the guest OS will then know that
   all devices on that bus are a part of the specified NUMA node (it is up to
   the user of the libvirt API to attach host devices to the correct
   pci-expander-bus when assigning them to the domain).
``index``
   pci-root controllers for pSeries guests use this attribute to record the
   order they will show up in the guest. :since:`Since 3.6.0`

For machine types which provide an implicit PCI bus, the pci-root controller
with index=0 is auto-added and required to use PCI devices. pci-root has no
address. PCI bridges are auto-added if there are too many devices to fit on the
one bus provided by pci-root, or a PCI bus number greater than zero was
specified. PCI bridges can also be specified manually, but their addresses
should only refer to PCI buses provided by already specified PCI controllers.
Leaving gaps in the PCI controller indexes might lead to an invalid
configuration.

::

   ...
   <devices>
     <controller type='pci' index='0' model='pci-root'/>
     <controller type='pci' index='1' model='pci-bridge'>
       <address type='pci' domain='0' bus='0' slot='5' function='0' multifunction='off'/>
     </controller>
   </devices>
   ...

For machine types which provide an implicit PCI Express (PCIe) bus (for example,
the machine types based on the Q35 chipset), the pcie-root controller with
index=0 is auto-added to the domain's configuration. pcie-root has also no
address, provides 31 slots (numbered 1-31) that can be used to attach PCIe or
PCI devices (although libvirt will never auto-assign a PCI device to a PCIe
slot, it will allow manual specification of such an assignment). Devices
connected to pcie-root cannot be hotplugged. If traditional PCI devices are
present in the guest configuration, a ``pcie-to-pci-bridge`` controller will
automatically be added: this controller, which plugs into a ``pcie-root-port``,
provides 31 usable PCI slots (1-31) with hotplug support ( :since:`since 4.3.0`
). If the QEMU binary doesn't support the corresponding device, then a
``dmi-to-pci-bridge`` controller will be added instead, usually at the defacto
standard location of slot=0x1e. A dmi-to-pci-bridge controller plugs into a PCIe
slot (as provided by pcie-root), and itself provides 31 standard PCI slots
(which also do not support device hotplug). In order to have hot-pluggable PCI
slots in the guest system, a pci-bridge controller will also be automatically
created and connected to one of the slots of the auto-created dmi-to-pci-bridge
controller; all guest PCI devices with addresses that are auto-determined by
libvirt will be placed on this pci-bridge device. ( :since:`since 1.1.2` ).

Domains with an implicit pcie-root can also add controllers with
``model='pcie-root-port'``, ``model='pcie-switch-upstream-port'``, and
``model='pcie-switch-downstream-port'``. pcie-root-port is a simple type of
bridge device that can connect only to one of the 31 slots on the pcie-root bus
on its upstream side, and makes a single (PCIe, hotpluggable) port available on
the downstream side (at slot='0'). pcie-root-port can be used to provide a
single slot to later hotplug a PCIe device (but is not itself hotpluggable - it
must be in the configuration when the domain is started). ( :since:`since
1.2.19` )

pcie-switch-upstream-port is a more flexible (but also more complex) device that
can only plug into a pcie-root-port or pcie-switch-downstream-port on the
upstream side (and only before the domain is started - it is not hot-pluggable),
and provides 32 ports on the downstream side (slot='0' - slot='31') that accept
only pcie-switch-downstream-port devices; each pcie-switch-downstream-port
device can only plug into a pcie-switch-upstream-port on its upstream side
(again, not hot-pluggable), and on its downstream side provides a single
hotpluggable pcie port that can accept any standard pci or pcie device (or
another pcie-switch-upstream-port), i.e. identical in function to a
pcie-root-port. ( :since:`since 1.2.19` )

::

   ...
   <devices>
     <controller type='pci' index='0' model='pcie-root'/>
     <controller type='pci' index='1' model='pcie-root-port'>
       <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
     </controller>
     <controller type='pci' index='2' model='pcie-to-pci-bridge'>
       <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
     </controller>
   </devices>
   ...

Device leases
~~~~~~~~~~~~~

When using a lock manager, it may be desirable to record device leases against a
VM. The lock manager will ensure the VM won't start unless the leases can be
acquired.

::

   ...
   <devices>
     ...
     <lease>
       <lockspace>somearea</lockspace>
       <key>somekey</key>
       <target path='/some/lease/path' offset='1024'/>
     </lease>
     ...
   </devices>
   ...

``lockspace``
   This is an arbitrary string, identifying the lockspace within which the key
   is held. Lock managers may impose extra restrictions on the format, or length
   of the lockspace name.
``key``
   This is an arbitrary string, uniquely identifying the lease to be acquired.
   Lock managers may impose extra restrictions on the format, or length of the
   key.
``target``
   This is the fully qualified path of the file associated with the lockspace.
   The offset specifies where the lease is stored within the file. If the lock
   manager does not require an offset, just pass 0.


Host device assignment
~~~~~~~~~~~~~~~~~~~~~~

USB / PCI / SCSI devices
^^^^^^^^^^^^^^^^^^^^^^^^

USB, PCI and SCSI devices attached to the host can be passed through to the
guest using the ``hostdev`` element. :since:`since after 0.4.4 for USB, 0.6.0
for PCI (KVM only) and 1.0.6 for SCSI (KVM only)` :

::

   ...
   <devices>
     <hostdev mode='subsystem' type='usb'>
       <source startupPolicy='optional' guestReset='off'>
         <vendor id='0x1234'/>
         <product id='0xbeef'/>
       </source>
       <boot order='2'/>
     </hostdev>
   </devices>
   ...

or:

::

   ...
   <devices>
     <hostdev mode='subsystem' type='pci' managed='yes'>
       <source writeFiltering='no'>
         <address domain='0x0000' bus='0x06' slot='0x02' function='0x0'/>
       </source>
       <boot order='1'/>
       <rom bar='on' file='/etc/fake/boot.bin'/>
     </hostdev>
   </devices>
   ...

or:

::

   ...
   <devices>
     <hostdev mode='subsystem' type='scsi' sgio='filtered' rawio='yes'>
       <source>
         <adapter name='scsi_host0'/>
         <address bus='0' target='0' unit='0'/>
       </source>
       <readonly/>
       <address type='drive' controller='0' bus='0' target='0' unit='0'/>
     </hostdev>
   </devices>
   ...

or:

::

   ...
   <devices>
     <hostdev mode='subsystem' type='scsi'>
       <source protocol='iscsi' name='iqn.2014-08.com.example:iscsi-nopool/1'>
         <host name='example.com' port='3260'/>
         <auth username='myuser'>
           <secret type='iscsi' usage='libvirtiscsi'/>
         </auth>
         <initiator>
           <iqn name='iqn.2020-07.com.example:test'/>
         </initiator>
       </source>
       <address type='drive' controller='0' bus='0' target='0' unit='0'/>
     </hostdev>
   </devices>
   ...

or:

::

     ...
     <devices>
       <hostdev mode='subsystem' type='scsi_host'>
         <source protocol='vhost' wwpn='naa.50014057667280d8'/>
       </hostdev>
     </devices>
     ...

or:

::

     ...
     <devices>
       <hostdev mode='subsystem' type='mdev' model='vfio-pci'>
       <source>
         <address uuid='c2177883-f1bb-47f0-914d-32a22e3a8804'/>
       </source>
       </hostdev>
       <hostdev mode='subsystem' type='mdev' model='vfio-ccw'>
       <source>
         <address uuid='9063cba3-ecef-47b6-abcf-3fef4fdcad85'/>
       </source>
       <address type='ccw' cssid='0xfe' ssid='0x0' devno='0x0001'/>
       </hostdev>
     </devices>
     ...

``hostdev``
   The ``hostdev`` element is the main container for describing host devices.
   For each device, the ``mode`` is always "subsystem" and the ``type`` is one
   of the following values with additional attributes noted.

   ``usb``
      USB devices are detached from the host on guest startup and reattached
      after the guest exits or the device is hot-unplugged.
   ``pci``
      For PCI devices, when ``managed`` is "yes" it is detached from the host
      before being passed on to the guest and reattached to the host after the
      guest exits. If ``managed`` is omitted or "no", the user is responsible to
      call ``virNodeDeviceDetachFlags`` (or ``virsh nodedev-detach`` before
      starting the guest or hot-plugging the device and
      ``virNodeDeviceReAttach`` (or ``virsh nodedev-reattach``) after hot-unplug
      or stopping the guest.
   ``scsi``
      For SCSI devices, user is responsible to make sure the device is not used
      by host. If supported by the hypervisor and OS, the optional ``sgio`` (
      :since:`since 1.0.6` ) attribute indicates whether unprivileged SG_IO
      commands are filtered for the disk. Valid settings are "filtered" or
      "unfiltered", where the default is "filtered". The optional ``rawio`` (
      :since:`since 1.2.9` ) attribute indicates whether the lun needs the rawio
      capability. Valid settings are "yes" or "no". See the rawio description
      within the `Hard drives, floppy disks, CDROMs`_ section. If a disk lun in the domain
      already has the rawio capability, then this setting not required.
   ``scsi_host``
      :since:`since 2.5.0` For SCSI devices, user is responsible to make sure
      the device is not used by host. This ``type`` passes all LUNs presented by
      a single HBA to the guest. :since:`Since 5.2.0,` the ``model`` attribute
      can be specified further with "virtio-transitional",
      "virtio-non-transitional", or "virtio". `Virtio transitional devices`_
      for more details.
   ``mdev``
      For mediated devices ( :since:`Since 3.2.0` ) the ``model`` attribute
      specifies the device API which determines how the host's vfio driver will
      expose the device to the guest. Currently, ``model='vfio-pci'``,
      ``model='vfio-ccw'`` ( :since:`Since 4.4.0` ) and ``model='vfio-ap'`` (
      :since:`Since 4.9.0` ) is supported.
      `MDEV <drvnodedev.html#mediated-devices-mdevs>`__
      section provides more information about mediated devices as well as how to
      create mediated devices on the host. :since:`Since 4.6.0 (QEMU 2.12)` an
      optional ``display`` attribute may be used to enable or disable support
      for an accelerated remote desktop backed by a mediated device (such as
      NVIDIA vGPU or Intel GVT-g) as an alternative to emulated `Video devices`_.
      This attribute is limited to ``model='vfio-pci'`` only. Supported values
      are either ``on`` or ``off`` (default is 'off'). It is required to use a
      graphical framebuffer (See `Graphical framebuffers`_) in order to use this
      attribute, currently only supported with VNC, Spice and egl-headless graphics
      devices. :since:`Since version 5.10.0` , there is an optional ``ramfb``
      attribute for devices with ``model='vfio-pci'``. Supported values are
      either ``on`` or ``off`` (default is 'off'). When enabled, this attribute
      provides a memory framebuffer device to the guest. This framebuffer will
      be used as a boot display when a vgpu device is the primary display.

      Note: There are also some implications on the usage of guest's address
      type depending on the ``model`` attribute, see the ``address`` element
      below.

   Note: The ``managed`` attribute is only used with ``type='pci'`` and is
   ignored by all the other device types, thus setting ``managed`` explicitly
   with other than a PCI device has the same effect as omitting it. Similarly,
   ``model`` attribute is only supported by mediated devices and ignored by all
   other device types.

``source``
   The source element describes the device as seen from the host using the
   following mechanism to describe:

   ``usb``
      The USB device can either be addressed by vendor / product id using the
      ``vendor`` and ``product`` elements or by the device's address on the host
      using the ``address`` element.

      :since:`Since 1.0.0` , the ``source`` element of USB devices may contain
      ``startupPolicy`` attribute which can be used to define policy what to do
      if the specified host USB device is not found. The attribute accepts the
      following values:

      ========= =====================================================================
      mandatory fail if missing for any reason (the default)
      requisite fail if missing on boot up, drop if missing on migrate/restore/revert
      optional  drop if missing at any start attempt
      ========= =====================================================================

      :since:`Since 8.6.0`, the ``source`` element can contain ``guestReset``
      attribute with the following value:

      ============= =====================================================
      off           all guest initiated device reset requests are ignored
      uninitialized device request is ignored if device is initialized,
                    otherwise reset is performed
      on            device is reset on every guest initiated request
      ============= =====================================================

      This attribute can be helpful when assigning an USB device with a
      firmware that crashes on reset.

   ``pci``
      PCI devices can only be described by their ``address``.
      :since:`Since 6.8.0 (Xen only)` , the ``source`` element of a PCI device
      may contain the ``writeFiltering`` attribute to control write access to
      the PCI configuration space. By default Xen only allows writes of known
      safe values to the configuration space. Setting ``writeFiltering='no'``
      will allow all writes to the device's PCI configuration space.
   ``scsi``
      SCSI devices are described by both the ``adapter`` and ``address``
      elements. The ``address`` element includes a ``bus`` attribute (a 2-digit
      bus number), a ``target`` attribute (a 10-digit target number), and a
      ``unit`` attribute (a 20-digit unit number on the bus). Not all
      hypervisors support larger ``target`` and ``unit`` values. It is up to
      each hypervisor to determine the maximum value supported for the adapter.

      :since:`Since 1.2.8` , the ``source`` element of a SCSI device may contain
      the ``protocol`` attribute. When the attribute is set to "iscsi", the host
      device XML follows the network disk device
      (See `Hard drives, floppy disks, CDROMs`_) using the
      same ``name`` attribute and optionally using the ``auth`` element to
      provide the authentication credentials to the iSCSI server.

      :since:`Since 6.7.0`, the optional ``initiator`` sub-element controls the
      IQN of the initiator ran by the hypervisor via it's ``<iqn name='iqn...'``
      subelement.

   ``scsi_host``
      :since:`Since 2.5.0` , multiple LUNs behind a single SCSI HBA are
      described by a ``protocol`` attribute set to "vhost" and a ``wwpn``
      attribute that is the vhost_scsi wwpn (16 hexadecimal digits with a prefix
      of "naa.") established in the host configfs.
   ``mdev``
      Mediated devices ( :since:`Since 3.2.0` ) are described by the ``address``
      element. The ``address`` element contains a single mandatory attribute
      ``uuid``.

``vendor``, ``product``
   The ``vendor`` and ``product`` elements each have an ``id`` attribute that
   specifies the USB vendor and product id. The ids can be given in decimal,
   hexadecimal (starting with 0x) or octal (starting with 0) form.
``boot``
   Specifies that the device is bootable. The ``order`` attribute determines the
   order in which devices will be tried during boot sequence. The per-device
   ``boot`` elements cannot be used together with general boot elements in
   `BIOS bootloader`_ section. :since:`Since 0.8.8` for PCI
   devices, :since:`Since 1.0.1` for USB devices.
``rom``
   The ``rom`` element is used to change how a PCI device's ROM is presented to
   the guest. The optional ``bar`` attribute can be set to "on" or "off", and
   determines whether or not the device's ROM will be visible in the guest's
   memory map. (In PCI documentation, the "rombar" setting controls the presence
   of the Base Address Register for the ROM). If no rom bar is specified, the
   qemu default will be used (older versions of qemu used a default of "off",
   while newer qemus have a default of "on"). :since:`Since 0.9.7 (QEMU and KVM
   only)` . The optional ``file`` attribute contains an absolute path to a
   binary file to be presented to the guest as the device's ROM BIOS. This can
   be useful, for example, to provide a PXE boot ROM for a virtual function of
   an sr-iov capable ethernet device (which has no boot ROMs for the VFs).
   :since:`Since 0.9.10 (QEMU and KVM only)` . The optional ``enabled``
   attribute can be set to ``no`` to disable PCI ROM loading completely for the
   device; if PCI ROM loading is disabled through this attribute, attempts to
   tweak the loading process further using the ``bar`` or ``file`` attributes
   will be rejected. :since:`Since 4.3.0 (QEMU and KVM only)` .
``address``
   The ``address`` element for USB devices has a ``bus`` and ``device``
   attribute to specify the USB bus and device number the device appears at on
   the host. The values of these attributes can be given in decimal, hexadecimal
   (starting with 0x) or octal (starting with 0) form. For PCI devices the
   element carries 4 attributes allowing to designate the device as can be found
   with the ``lspci`` or with ``virsh nodedev-list``. For SCSI devices a 'drive'
   address type must be used. For mediated devices, which are software-only
   devices defining an allocation of resources on the physical parent device,
   the address type used must conform to the ``model`` attribute of element
   ``hostdev``, e.g. any address type other than PCI for ``vfio-pci`` device API
   or any address type other than CCW for ``vfio-ccw`` device API will result in
   an error. See the `Device Addresses`_ section for more details on the address
   element.
``driver``
   PCI devices can have an optional ``driver`` subelement that specifies which
   backend driver to use for PCI device assignment. Use the ``name`` attribute
   to select either "vfio" (for the new VFIO device assignment backend, which is
   compatible with UEFI SecureBoot) or "kvm" (the legacy device assignment
   handled directly by the KVM kernel module) :since:`Since 1.0.5 (QEMU and KVM
   only, requires kernel 3.6 or newer)` . When specified, device assignment will
   fail if the requested method of device assignment isn't available on the
   host. When not specified, the default is "vfio" on systems where the VFIO
   driver is available and loaded, and "kvm" on older systems, or those where
   the VFIO driver hasn't been loaded :since:`Since 1.1.3` (prior to that the
   default was always "kvm").
``readonly``
   Indicates that the device is readonly, only supported by SCSI host device
   now. :since:`Since 1.0.6 (QEMU and KVM only)`
``shareable``
   If present, this indicates the device is expected to be shared between
   domains (assuming the hypervisor and OS support this). Only supported by SCSI
   host device. :since:`Since 1.0.6`

   Note: Although ``shareable`` was introduced :since:`in 1.0.6` , it did not
   work as as expected until :since:`1.2.2` .

Block / character devices
^^^^^^^^^^^^^^^^^^^^^^^^^

Block / character devices from the host can be passed through to the guest using
the ``hostdev`` element. This is only possible with container based
virtualization. Devices are specified by a fully qualified path. :since:`since
after 1.0.1 for LXC` :

::

   ...
   <hostdev mode='capabilities' type='storage'>
     <source>
       <block>/dev/sdf1</block>
     </source>
   </hostdev>
   ...

::

   ...
   <hostdev mode='capabilities' type='misc'>
     <source>
       <char>/dev/input/event3</char>
     </source>
   </hostdev>
   ...

::

   ...
   <hostdev mode='capabilities' type='net'>
     <source>
       <interface>eth0</interface>
     </source>
   </hostdev>
   ...

``hostdev``
   The ``hostdev`` element is the main container for describing host devices.
   For block/character device passthrough ``mode`` is always "capabilities" and
   ``type`` is "storage" for a block device, "misc" for a character device and
   "net" for a host network interface.
``source``
   The source element describes the device as seen from the host. For block
   devices, the path to the block device in the host OS is provided in the
   nested "block" element, while for character devices the "char" element is
   used. For network interfaces, the name of the interface is provided in the
   "interface" element.

Redirected devices
~~~~~~~~~~~~~~~~~~

USB device redirection through a character device is supported :since:`since
after 0.9.5 (KVM only)` :

::

   ...
   <devices>
     <redirdev bus='usb' type='spicevmc'/>
     <redirdev bus='usb' type='tcp'>
       <source mode='connect' host='localhost' service='4000'/>
       <boot order='1'/>
     </redirdev>
     <redirfilter>
       <usbdev class='0x08' vendor='0x1234' product='0xbeef' version='2.56' allow='yes'/>
       <usbdev allow='no'/>
     </redirfilter>
   </devices>
   ...

``redirdev``
   The ``redirdev`` element is the main container for describing redirected
   devices. ``bus`` must be "usb" for a USB device. An additional attribute
   ``type`` is required, matching one of the supported serial device types
   (See `Consoles, serial, parallel & channel devices`_), to describe the host
   side of the tunnel; ``type='tcp'`` or ``type='spicevmc'`` (which uses the
   usbredir channel of a  SPICE graphics device (See `Graphical framebuffers`_))
   are typical.

   The redirdev element has an optional sub-element ``<address>`` which can tie
   the device to  a particular controller. Further sub-elements, such as
   ``<source>``, may be required according to the given type, although a
   ``<target>`` sub-element is not required (since the consumer of the
   character device is the hypervisor itself, rather than a device visible in
   the guest).
``boot``
   Specifies that the device is bootable. The ``order`` attribute determines the
   order in which devices will be tried during boot sequence. The per-device
   ``boot`` elements cannot be used together with general boot elements in
   `BIOS bootloader`_ section. ( :since:`Since 1.0.1` )
``redirfilter``
   The\ ``redirfilter``\ element is used for creating the filter rule to filter
   out certain devices from redirection. It uses sub-element ``<usbdev>`` to
   define each filter rule. ``class`` attribute is the USB Class code, for
   example, 0x08 represents mass storage devices. The USB device can be
   addressed by vendor / product id using the ``vendor`` and ``product``
   attributes. ``version`` is the device revision from the bcdDevice field (not
   the version of the USB protocol). These four attributes are optional and
   ``-1`` can be used to allow any value for them. ``allow`` attribute is
   mandatory, 'yes' means allow, 'no' for deny.

Smartcard devices
~~~~~~~~~~~~~~~~~

A virtual smartcard device can be supplied to the guest via the ``smartcard``
element. A USB smartcard reader device on the host cannot be used on a guest
with simple device passthrough, since it will then not be available on the host,
possibly locking the host computer when it is "removed". Therefore, some
hypervisors provide a specialized virtual device that can present a smartcard
interface to the guest, with several modes for describing how credentials are
obtained from the host or even a from a channel created to a third-party
smartcard provider. :since:`Since 0.8.8`

::

   ...
   <devices>
     <smartcard mode='host'/>
     <smartcard mode='host-certificates'>
       <certificate>cert1</certificate>
       <certificate>cert2</certificate>
       <certificate>cert3</certificate>
       <database>/etc/pki/nssdb/</database>
     </smartcard>
     <smartcard mode='passthrough' type='tcp'>
       <source mode='bind' host='127.0.0.1' service='2001'/>
       <protocol type='raw'/>
       <address type='ccid' controller='0' slot='0'/>
     </smartcard>
     <smartcard mode='passthrough' type='spicevmc'/>
   </devices>
   ...

The ``<smartcard>`` element has a mandatory attribute ``mode``. The following
modes are supported; in each mode, the guest sees a device on its USB bus that
behaves like a physical USB CCID (Chip/Smart Card Interface Device) card.

``host``
   The simplest operation, where the hypervisor relays all requests from the
   guest into direct access to the host's smartcard via NSS. No other attributes
   or sub-elements are required. See below about the use of an optional
   ``<address>`` sub-element.
``host-certificates``
   Rather than requiring a smartcard to be plugged into the host, it is possible
   to provide three NSS certificate names residing in a database on the host.
   These certificates can be generated via the command
   ``certutil -d /etc/pki/nssdb -x -t       CT,CT,CT -S -s CN=cert1 -n cert1``,
   and the resulting three certificate names must be supplied as the content of
   each of three ``<certificate>`` sub-elements. An additional sub-element
   ``<database>`` can specify the absolute path to an alternate directory
   (matching the ``-d`` option of the ``certutil`` command when creating the
   certificates); if not present, it defaults to /etc/pki/nssdb.
``passthrough``
   Rather than having the hypervisor directly communicate with the host, it is
   possible to tunnel all requests through a secondary character device to a
   third-party provider (which may in turn be talking to a smartcard or using
   three certificate files). In this mode of operation, an additional attribute
   ``type`` is required, matching one of the supported serial device types
   (See `Consoles, serial, parallel & channel devices`_),
   to describe the host side of the tunnel;
   ``type='tcp'`` or ``type='spicevmc'`` (which uses the smartcard channel of a
   SPICE graphics device (See `Graphical framebuffers`_)) are typical. Further
   sub-elements, such as ``<source>``, may be required according to the given
   type, although a ``<target>`` sub-element is not required (since the consumer
   of the character device is the hypervisor itself, rather than a device
   visible in the guest).

Each mode supports an optional sub-element ``<address>`` (See `Device Addresses`_),
which fine-tunes the correlation between the smartcard and a ccid bus controller.
For now, qemu only supports at most one smartcard, with an address of bus=0 slot=0.


Network interfaces
~~~~~~~~~~~~~~~~~~

::

   ...
   <devices>
     <interface type='direct' trustGuestRxFilters='yes'>
       <source dev='eth0'/>
       <mac address='52:54:00:5d:c7:9e'/>
       <boot order='1'/>
       <rom bar='off'/>
       <acpi index='4'/>
     </interface>
   </devices>
   ...

There are several possibilities for specifying a network interface visible to
the guest. Each subsection below provides more details about common setup
options.

:since:`Since 1.2.10` ), the ``interface`` element property
``trustGuestRxFilters`` provides the capability for the host to detect and trust
reports from the guest regarding changes to the interface mac address and
receive filters by setting the attribute to ``yes``. The default setting for the
attribute is ``no`` for security reasons and support depends on the guest
network device model as well as the type of connection on the host - currently
it is only supported for the virtio device model and for macvtap connections on
the host.

Each ``<interface>`` element has an optional ``<address>`` sub-element that can
tie the interface to a particular pci slot, with attribute ``type='pci'`` as
documented in the `Device Addresses`_ section.

:since:`Since 6.6.0` , one can force libvirt to keep the provided MAC address
when it's in the reserved VMware range by adding a ``type="static"`` attribute
to the ``<mac/>`` element. Note that this attribute is useless if the provided
MAC address is outside of the reserved VMWare ranges.

:since:`Since 7.3.0`, one can set the ACPI index against network interfaces.
With some operating systems (eg Linux with systemd), the ACPI index is used
to provide network interface device naming, that is stable across changes
in PCI addresses assigned to the device. This value is required to be unique
across all devices and be between 1 and (16*1024-1).

Virtual network
^^^^^^^^^^^^^^^

**This is the recommended config for general guest connectivity on hosts with
dynamic / wireless networking configs.** (or multi-host environments where the
host hardware details are described separately in a ``<network>`` definition
:since:`Since 0.9.4` ).

Provides a connection whose details are described by the named network
definition. Depending on the virtual network's "forward mode" configuration, the
network may be totally isolated (no ``<forward>`` element given), NAT'ing to an
explicit network device or to the default route (``<forward mode='nat'>``),
routed with no NAT (``<forward mode='route'/>``), or connected directly to one
of the host's network interfaces (via macvtap) or bridge devices
((``<forward       mode='bridge|private|vepa|passthrough'/>`` :since:`Since
0.9.4` )

For networks with a forward mode of bridge, private, vepa, and passthrough, it
is assumed that the host has any necessary DNS and DHCP services already setup
outside the scope of libvirt. In the case of isolated, nat, and routed networks,
DHCP and DNS are provided on the virtual network by libvirt, and the IP range
can be determined by examining the virtual network config with
'``virsh net-dumpxml [networkname]``'. There is one virtual network called
'default' setup out of the box which does NAT'ing to the default route and has
an IP range of ``192.168.122.0/255.255.255.0``. Each guest will have an
associated tun device created with a name of vnetN, which can also be overridden
with the <target> element (see `Overriding the target element`_).

When the source of an interface is a network, a ``portgroup`` can be specified
along with the name of the network; one network may have multiple portgroups
defined, with each portgroup containing slightly different configuration
information for different classes of network connections. :since:`Since 0.9.4` .

When a guest is running an interface of type ``network`` may include a
``portid`` attribute. This provides the UUID of an associated virNetworkPortPtr
object that records the association between the domain interface and the
network. This attribute is read-only since port objects are create and deleted
automatically during startup and shutdown. :since:`Since 5.1.0`

Also, similar to ``direct`` network connections (described below), a connection
of type ``network`` may specify a ``virtualport`` element, with configuration
data to be forwarded to a vepa (802.1Qbg) or 802.1Qbh compliant switch (
:since:`Since 0.8.2` ), or to an Open vSwitch virtual switch ( :since:`Since
0.9.11` ).

Since the actual type of switch may vary depending on the configuration in the
``<network>`` on the host, it is acceptable to omit the virtualport ``type``
attribute, and specify attributes from multiple different virtualport types (and
also to leave out certain attributes); at domain startup time, a complete
``<virtualport>`` element will be constructed by merging together the type and
attributes defined in the network and the portgroup referenced by the interface.
The newly-constructed virtualport is a combination of them. The attributes from
lower virtualport can't make change on the ones defined in higher virtualport.
Interface takes the highest priority, portgroup is lowest priority. (
:since:`Since 0.10.0` ). For example, in order to work properly with both an
802.1Qbh switch and an Open vSwitch switch, you may choose to specify no type,
but both a ``profileid`` (in case the switch is 802.1Qbh) and an ``interfaceid``
(in case the switch is Open vSwitch) (you may also omit the other attributes,
such as managerid, typeid, or profileid, to be filled in from the network's
``<virtualport>``). If you want to limit a guest to connecting only to certain
types of switches, you can specify the virtualport type, but still omit some/all
of the parameters - in this case if the host's network has a different type of
virtualport, connection of the interface will fail.

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
     </interface>
     ...
     <interface type='network'>
       <source network='default' portgroup='engineering'/>
       <target dev='vnet7'/>
       <mac address="00:11:22:33:44:55"/>
       <virtualport>
         <parameters instanceid='09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f'/>
       </virtualport>
     </interface>
   </devices>
   ...

Bridge to LAN
^^^^^^^^^^^^^

**This is the recommended config for general guest connectivity on hosts with
static wired networking configs.**

Provides a bridge from the VM directly to the LAN. This assumes there is a
bridge device on the host which has one or more of the hosts physical NICs
attached. The guest VM will have an associated tun device created with a name of
vnetN, which can also be overridden with the <target> element (see
`Overriding the target element`_). The tun device will be
attached to the bridge. The IP range / network configuration is whatever is used
on the LAN. This provides the guest VM full incoming & outgoing net access just
like a physical machine.

On Linux systems, the bridge device is normally a standard Linux host bridge. On
hosts that support Open vSwitch, it is also possible to connect to an Open
vSwitch bridge device by adding a ``<virtualport type='openvswitch'/>`` to the
interface definition. ( :since:`Since 0.9.11` ). The Open vSwitch type
virtualport accepts two parameters in its ``<parameters>`` element - an
``interfaceid`` which is a standard uuid used to uniquely identify this
particular interface to Open vSwitch (if you do not specify one, a random
interfaceid will be generated for you when you first define the interface), and
an optional ``profileid`` which is sent to Open vSwitch as the interfaces
"port-profile".

::

   ...
   <devices>
     ...
     <interface type='bridge'>
       <source bridge='br0'/>
     </interface>
     <interface type='bridge'>
       <source bridge='br1'/>
       <target dev='vnet7'/>
       <mac address="00:11:22:33:44:55"/>
     </interface>
     <interface type='bridge'>
       <source bridge='ovsbr'/>
       <virtualport type='openvswitch'>
         <parameters profileid='menial' interfaceid='09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f'/>
       </virtualport>
     </interface>
     ...
   </devices>
   ...

On hosts that support Open vSwitch on the kernel side and have the Midonet Host
Agent configured, it is also possible to connect to the 'midonet' bridge device
by adding a ``<virtualport type='midonet'/>`` to the interface definition. (
:since:`Since 1.2.13` ). The Midonet virtualport type requires an
``interfaceid`` attribute in its ``<parameters>`` element. This interface id is
the UUID that specifies which port in the virtual network topology will be bound
to the interface.

::

   ...
   <devices>
     ...
     <interface type='bridge'>
       <source bridge='br0'/>
     </interface>
     <interface type='bridge'>
       <source bridge='br1'/>
       <target dev='vnet7'/>
       <mac address="00:11:22:33:44:55"/>
     </interface>
     <interface type='bridge'>
       <source bridge='midonet'/>
       <virtualport type='midonet'>
         <parameters interfaceid='0b2d64da-3d0e-431e-afdd-804415d6ebbb'/>
       </virtualport>
     </interface>
     ...
   </devices>
   ...

Userspace (SLIRP or passt) connection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``user`` type connects the guest interface to the outside via a
transparent userspace proxy that doesn't require any special system
privileges, making it usable in cases when libvirt itself is running
with no privileges (e.g. libvirt's "session mode" daemon, or when
libvirt is run inside an unprivileged container).

By default, this user proxy is done with QEMU's internal SLIRP driver
which has DHCP & DNS services that give the guest IP addresses
starting from ``10.0.2.15``, a default route of ``10.0.2.2`` and DNS
server of ``10.0.2.3``. :since:`Since 3.8.0` it is possible to override
the default network address by including an ``ip`` element specifying
an IPv4 address in its one mandatory attribute,
``address``. Optionally, a second ``ip`` element with a ``family``
attribute set to "ipv6" can be specified to add an IPv6 address to the
interface. ``address``. Optionally, address ``prefix`` can be
specified.

::

   ...
   <devices>
     <interface type='user'/>
     ...
     <interface type='user'>
       <mac address="00:11:22:33:44:55"/>
       <ip family='ipv4' address='172.17.2.0' prefix='24'/>
       <ip family='ipv6' address='2001:db8:ac10:fd01::' prefix='64'/>
     </interface>
   </devices>
   ...

:since:`Since 9.0.0` an alternate backend implementation of the
``user`` interface type can be selected by setting the interface's
``<backend>`` subelement ``type`` attribute to ``passt``. In this
case, the passt transport (https://passt.top) is used. Similar to
SLIRP, passt has an internal DHCP server that provides a requesting
guest with one ipv4 and one ipv6 address; it then uses userspace
proxies and a separate network namespace to provide outgoing
UDP/TCP/ICMP sessions, and optionally redirect incoming traffic
destined for the host toward the guest instead.

When the passt backend is used, the ``<backend>`` attribute
``logFile`` can be used to tell the passt process for this interface
where to write its message log, and the ``<source>`` attribute ``dev``
can tell it to use a particular host interface to derive the routes
given to the guest for forwarding traffic upstream.  Due to the design
decisions of passt, if using SELinux, the log file is recommended to
reside in the runtime directory of a user under which the passt
process will run, most probably ``/run/user/$UID`` where ``$UID`` is
the UID of the user, e.g. ``qemu``.  Beware that libvirt does not
create this directory if it does not already exist to avoid possible,
however unlikely, issues, especially since this logfile attribute is
meant mostly for debugging.

Additionally, when passt is used, multiple ``<portForward>`` elements
can be added to forward incoming network traffic for the host to this
guest interface. Each ``<portForward>`` must have a ``proto``
attribute (set to ``tcp`` or ``udp``), optional original ``address``
(if not specified, then all incoming sessions to any host IP for the
given proto/port(s) will be forwarded to the guest), and an optional
``dev`` attribute to limit the forwarded traffic to a specific host
interface.

The decision of which ports to forward is described with zero or more
``<range>`` subelements of ``<portForward>`` (if there is no
``<range>`` then **all** ports for the given proto/address will be
forwarded). Each ``<range>`` has a ``start`` and optional ``end``
attribute. If ``end`` is omitted then a single port will be forwarded,
otherwise all ports between ``start`` and ``end`` (inclusive) will be
forwarded. If the port number(s) should remain unmodified as the
session is forwarded, no further options are needed, but if the guest
is expecting the sessions on a different port, then this should be
specified with the ``to`` attribute of ``<range>`` - the port number
of each forwarded session in the range will be offeset by "``to`` -
``start``".  A ``<range>`` element can also be used to specify a range
of ports that should **not** be forwarded. This is done by setting the
range's ``exclude`` attribute to ``yes``. This may not seem very
useful, but can be when it is desirable to forward a long range of
ports **with the exception of some subset**.

::

   ...
   <devices>
     ...
     <interface type='user'>
       <backend type='passt' logFile='/run/user/$UID/passt-domain.log'/>
       <mac address="00:11:22:33:44:55"/>
       <source dev='eth0'/>
       <ip family='ipv4' address='172.17.2.4' prefix='24'/>
       <ip family='ipv6' address='2001:db8:ac10:fd01::20'/>
       <portForward proto='tcp'>
         <range start='2022' to='22'/>
       </portForward>
       <portForward proto='udp' address='1.2.3.4'>
         <range start='5000' end='5020' to='6000'/>
         <range start='5010' end='5015' exclude='yes'/>
       </portForward>
       <portForward proto='tcp' address='2001:db8:ac10:fd01::1:10' dev='eth0'>
         <range start='80'/>
         <range start='443' to='344'/>
       </portForward>
     </interface>
   </devices>
   ...

Generic ethernet connection
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Provides a means to use a new or existing tap device (or veth device pair,
depending on the needs of the hypervisor driver) that is partially or wholly
setup external to libvirt (either prior to the guest starting, or while the
guest is being started via an optional script specified in the config).

The name of the tap device can optionally be specified with the ``dev``
attribute of the ``<target>`` element. If no target dev is specified, libvirt
will create a new standard tap device with a name of the pattern "vnetN", where
"N" is replaced with a number. If a target dev is specified and that device
doesn't exist, then a new standard tap device will be created with the exact dev
name given. If the specified target dev does exist, then that existing device
will be used. Usually some basic setup of the device is done by libvirt,
including setting a MAC address, and the IFF_UP flag, but if the ``dev`` is a
pre-existing device, and the ``managed`` attribute of the ``target`` element is
also set to "no" (the default value is "yes"), even this basic setup will not be
performed - libvirt will simply pass the device on to the hypervisor with no
setup at all. :since:`Since 5.7.0` Using managed='no' with a pre-created tap
device is useful because it permits a virtual machine managed by an unprivileged
libvirtd to have emulated network devices based on tap devices.

After creating/opening the tap device, an optional shell script (given in the
``path`` attribute of the ``<script>`` element) will be run. :since:`Since
0.2.1` Also, after detaching/closing the tap device, an optional shell script
(given in the ``path`` attribute of the ``<downscript>`` element) will be run.
:since:`Since 6.4.0` These can be used to do whatever extra host network
integration is required.

::

   ...
   <devices>
     <interface type='ethernet'>
       <script path='/etc/qemu-ifup-mynet'/>
       <downscript path='/etc/qemu-ifdown-mynet'/>
     </interface>
     ...
     <interface type='ethernet'>
       <target dev='mytap1' managed='no'/>
       <model type='virtio'/>
     </interface>
   </devices>
   ...


Direct attachment to physical interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

| Provides direct attachment of the virtual machine's NIC to the given physical
  interface of the host. :since:`Since 0.7.7 (QEMU and KVM only)`
| This setup requires the Linux macvtap driver to be available. :since:`(Since
  Linux 2.6.34.)` One of the modes 'vepa' ( `'Virtual Ethernet Port
  Aggregator' <https://www.ieee802.org/1/files/public/docs2009/new-evb-congdon-vepa-modular-0709-v01.pdf>`__),
  'bridge' or 'private' can be chosen for the operation mode of the macvtap
  device, 'vepa' being the default mode. The individual modes cause the delivery
  of packets to behave as follows:

If the model type is set to ``virtio`` and interface's ``trustGuestRxFilters``
attribute is set to ``yes``, changes made to the interface mac address,
unicast/multicast receive filters, and vlan settings in the guest will be
monitored and propagated to the associated macvtap device on the host (
:since:`Since 1.2.10` ). If ``trustGuestRxFilters`` is not set, or is not
supported for the device model in use, an attempted change to the mac address
originating from the guest side will result in a non-working network connection.

``vepa``
   All VMs' packets are sent to the external bridge. Packets whose destination
   is a VM on the same host as where the packet originates from are sent back to
   the host by the VEPA capable bridge (today's bridges are typically not VEPA
   capable).
``bridge``
   Packets whose destination is on the same host as where they originate from
   are directly delivered to the target macvtap device. Both origin and
   destination devices need to be in bridge mode for direct delivery. If either
   one of them is in ``vepa`` mode, a VEPA capable bridge is required.
``private``
   All packets are sent to the external bridge and will only be delivered to a
   target VM on the same host if they are sent through an external router or
   gateway and that device sends them back to the host. This procedure is
   followed if either the source or destination device is in ``private`` mode.
``passthrough``
   This feature attaches a virtual function of a SRIOV capable NIC directly to a
   VM without losing the migration capability. All packets are sent to the VF/IF
   of the configured network device. Depending on the capabilities of the device
   additional prerequisites or limitations may apply; for example, on Linux this
   requires kernel 2.6.38 or newer. :since:`Since 0.9.2`

::

   ...
   <devices>
     ...
     <interface type='direct' trustGuestRxFilters='no'>
       <source dev='eth0' mode='vepa'/>
     </interface>
   </devices>
   ...

The network access of direct attached virtual machines can be managed by the
hardware switch to which the physical interface of the host machine is connected
to.

The interface can have additional parameters as shown below, if the switch is
conforming to the IEEE 802.1Qbg standard. The parameters of the virtualport
element are documented in more detail in the IEEE 802.1Qbg standard. The values
are network specific and should be provided by the network administrator. In
802.1Qbg terms, the Virtual Station Interface (VSI) represents the virtual
interface of a virtual machine. :since:`Since 0.8.2`

Please note that IEEE 802.1Qbg requires a non-zero value for the VLAN ID.

``managerid``
   The VSI Manager ID identifies the database containing the VSI type and
   instance definitions. This is an integer value and the value 0 is reserved.
``typeid``
   The VSI Type ID identifies a VSI type characterizing the network access. VSI
   types are typically managed by network administrator. This is an integer
   value.
``typeidversion``
   The VSI Type Version allows multiple versions of a VSI Type. This is an
   integer value.
``instanceid``
   The VSI Instance ID Identifier is generated when a VSI instance (i.e. a
   virtual interface of a virtual machine) is created. This is a globally unique
   identifier.

::

   ...
   <devices>
     ...
     <interface type='direct'>
       <source dev='eth0.2' mode='vepa'/>
       <virtualport type="802.1Qbg">
         <parameters managerid="11" typeid="1193047" typeidversion="2" instanceid="09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f"/>
       </virtualport>
     </interface>
   </devices>
   ...

The interface can have additional parameters as shown below if the switch is
conforming to the IEEE 802.1Qbh standard. The values are network specific and
should be provided by the network administrator. :since:`Since 0.8.2`

``profileid``
   The profile ID contains the name of the port profile that is to be applied to
   this interface. This name is resolved by the port profile database into the
   network parameters from the port profile, and those network parameters will
   be applied to this interface.

::

   ...
   <devices>
     ...
     <interface type='direct'>
       <source dev='eth0' mode='private'/>
       <virtualport type='802.1Qbh'>
         <parameters profileid='finance'/>
       </virtualport>
     </interface>
   </devices>
   ...

PCI Passthrough
^^^^^^^^^^^^^^^

A PCI network device (specified by the <source> element) is directly assigned to
the guest using generic device passthrough, after first optionally setting the
device's MAC address to the configured value, and associating the device with an
802.1Qbh capable switch using an optionally specified <virtualport> element (see
the examples of virtualport given above for type='direct' network devices). Note
that - due to limitations in standard single-port PCI ethernet card driver
design - only SR-IOV (Single Root I/O Virtualization) virtual function (VF)
devices can be assigned in this manner; to assign a standard single-port PCI or
PCIe ethernet card to a guest, use the traditional <hostdev> device definition
and :since:`Since 0.9.11`

To use VFIO device assignment rather than traditional/legacy KVM device
assignment (VFIO is a new method of device assignment that is compatible with
UEFI Secure Boot), a type='hostdev' interface can have an optional ``driver``
sub-element with a ``name`` attribute set to "vfio". To use legacy KVM device
assignment you can set ``name`` to "kvm" (the default is "vfio" on systems
where the VFIO driver is available, and "kvm" on older systems. :since:`Since
1.1.3` (prior to that the default was always "kvm").

Note that this "intelligent passthrough" of network devices is very similar to
the functionality of a standard <hostdev> device, the difference being that this
method allows specifying a MAC address and <virtualport> for the passed-through
device. If these capabilities are not required, if you have a standard
single-port PCI, PCIe, or USB network card that doesn't support SR-IOV (and
hence would anyway lose the configured MAC address during reset after being
assigned to the guest domain), or if you are using a version of libvirt older
than 0.9.11, you should use standard <hostdev> to assign the device to the guest
instead of <interface type='hostdev'/>.

Similar to the functionality of a standard <hostdev> device, when ``managed`` is
"yes", it is detached from the host before being passed on to the guest, and
reattached to the host after the guest exits. If ``managed`` is omitted or "no",
the user is responsible to call ``virNodeDeviceDettach`` (or
``virsh nodedev-detach``) before starting the guest or hot-plugging the device,
and ``virNodeDeviceReAttach`` (or ``virsh nodedev-reattach``) after hot-unplug
or stopping the guest.

::

   ...
   <devices>
     <interface type='hostdev' managed='yes'>
       <driver name='vfio'/>
       <source>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
       </source>
       <mac address='52:54:00:6d:90:02'/>
       <virtualport type='802.1Qbh'>
         <parameters profileid='finance'/>
       </virtualport>
     </interface>
   </devices>
   ...

vDPA devices
^^^^^^^^^^^^

A vDPA network device can be used to provide wire speed network performance
within a domain. A vDPA device is a specialized type of network device that
uses a datapath that complies with the virtio specification but has a
vendor-specific control path.  To use such a device with libvirt, the host
device must already be bound to the appropriate device-specific vDPA driver.
This creates a vDPA char device (e.g. /dev/vhost-vdpa-0) that can be used to
assign the device to a libvirt domain.  :since:`Since 6.9.0 (QEMU only,
requires QEMU 5.1.0 or newer)`

::

   ...
   <devices>
     <interface type='vdpa'>
       <source dev='/dev/vhost-vdpa-0'/>
     </interface>
   </devices>
   ...

Teaming a virtio/hostdev NIC pair
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:since:`Since 6.1.0 (QEMU and KVM only, requires QEMU 4.2.0 or newer and a guest
virtio-net driver supporting the "failover" feature, such as the one included in
Linux kernel 4.18 and newer)` The ``<teaming>`` element of two interfaces can
be used to connect them as a team/bond device in the guest (assuming proper
support in the hypervisor and the guest network driver).

::

   ...
   <devices>
     <interface type='network'>
       <source network='mybridge'/>
       <mac address='00:11:22:33:44:55'/>
       <model type='virtio'/>
       <teaming type='persistent'/>
       <alias name='ua-backup0'/>
     </interface>
     <interface type='network'>
       <source network='hostdev-pool'/>
       <mac address='00:11:22:33:44:55'/>
       <model type='virtio'/>
       <teaming type='transient' persistent='ua-backup0'/>
     </interface>
   </devices>
   ...

The second interface in this example is referencing a network that is
a pool of SRIOV VFs (i.e. a "hostdev network"). You could instead
directly reference an SRIOV VF device:

::

   ...
     <interface type='hostdev'>
       <source>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
       </source>
       <mac address='00:11:22:33:44:55'/>
       <teaming type='transient' persistent='ua-backup0'/>
     </interface>
   ...

The ``<teaming>`` element required attribute ``type`` will be set to either
``persistent`` to indicate a device that should always be present in the
domain, or ``transient`` to indicate a device that may periodically be
removed, then later re-added to the domain. When type="transient", there should
be a second attribute to ``<teaming>`` called ``persistent`` - this attribute
should be set to the alias name of the other device in the pair (the one that
has ``<teaming       type="persistent'/>``).

In the particular case of QEMU, libvirt's ``<teaming>`` element is used to setup
a virtio-net "failover" device pair. For this setup, the persistent device must
be an interface with ``<model       type="virtio"/>``, and the transient device
must be ``<interface type='hostdev'/>`` (or ``<interface type='network'/>``
where the referenced network defines a pool of SRIOV VFs). The guest will then
have a simple network team/bond device made of the virtio NIC + hostdev NIC
pair. In this configuration, the higher-performing hostdev NIC will normally be
preferred for all network traffic, but when the domain is migrated, QEMU will
automatically unplug the VF from the guest, and then hotplug a similar device
once migration is completed; while migration is taking place, network traffic
will use the virtio NIC. (Of course the emulated virtio NIC and the hostdev NIC
must be connected to the same subnet for bonding to work properly).

:since:`Since 7.1.0` The ``<teaming>`` element can also be added to a
plain ``<hostdev>`` device.

::

   ...
     <hostdev mode='subsystem' type='pci' managed='no'>
       <source>
         <address domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
       </source>
       <teaming type='transient' persistent='ua-backup0'/>
     </hostdev>
   ...

This device must be a network device, but not necessarily an SRIOV
VF. Using plain ``<hostdev>`` rather than ``<interface
type='hostdev'>`` or ``<interface type='network'>`` is useful if the
device that will be assigned with VFIO is a standard NIC (not a VF) or
if libvirt doesn't have the necessary resources and privileges to set
the VF's MAC address (e.g. if libvirt is running unprivileged, or in a
container). This of course means that the user (or another
application) is responsible for setting the MAC address of the device
in a way such that it will survive guest driver initialization. For
standard NICs (i.e. not an SRIOV VF) this probably means that the
NIC's factory-programmed MAC address will need to be used for the
teaming pair (since any driver init in the guest will reset the MAC
back to factory). If it is an SRIOV VF, then its MAC address will need
to be set via the VF's PF, e.g. if you are going to use VF 2 of the PF
enp2s0f1, you would use something like this command:

::

  ip link set enp2s0f1 vf 2 mac 52:54:00:11:22:33

NB1: Since you must know the alias name of the virtio NIC when configuring the
hostdev NIC, it will need to be manually set in the virtio NIC's configuration
(as with all other manually set alias names, this means it must start with
"ua-").

NB2: Currently the only implementation of the guest OS virtio-net driver
supporting virtio-net failover requires that the MAC addresses of the virtio and
hostdev NIC must match. Since that may not always be a requirement in the
future, libvirt doesn't enforce this limitation - it is up to the
person/management application that is creating the configuration to assure the
MAC addresses of the two devices match.

NB3: Since the PCI addresses of the SRIOV VFs on the hosts that are the source
and destination of the migration will almost certainly be different, either
higher level management software will need to modify the ``<source>`` of the
hostdev NIC (``<interface type='hostdev'>``) at the start of migration, or (a
simpler solution) the configuration will need to use a libvirt "hostdev" virtual
network that maintains a pool of such devices, as is implied in the example's
use of the libvirt network named "hostdev-pool" - as long as the hostdev network
pools on both hosts have the same name, libvirt itself will take care of
allocating an appropriate device on both ends of the migration. Similarly the
XML for the virtio interface must also either work correctly unmodified on both
the source and destination of the migration (e.g. by connecting to the same
bridge device on both hosts, or by using the same virtual network), or the
management software must properly modify the interface XML during migration so
that the virtio device remains connected to the same network segment before and
after migration.

Multicast tunnel
^^^^^^^^^^^^^^^^

A multicast group is setup to represent a virtual network. Any VMs whose network
devices are in the same multicast group can talk to each other even across
hosts. This mode is also available to unprivileged users. There is no default
DNS or DHCP support and no outgoing network access. To provide outgoing network
access, one of the VMs should have a 2nd NIC which is connected to one of the
first 4 network types and do the appropriate routing. The multicast protocol is
compatible with that used by user mode linux guests too. The source address used
must be from the multicast address block.

::

   ...
   <devices>
     <interface type='mcast'>
       <mac address='52:54:00:6d:90:01'/>
       <source address='230.0.0.1' port='5558'/>
     </interface>
   </devices>
   ...

TCP tunnel
^^^^^^^^^^

A TCP client/server architecture provides a virtual network. One VM provides the
server end of the network, all other VMS are configured as clients. All network
traffic is routed between the VMs via the server. This mode is also available to
unprivileged users. There is no default DNS or DHCP support and no outgoing
network access. To provide outgoing network access, one of the VMs should have a
2nd NIC which is connected to one of the first 4 network types and do the
appropriate routing.

::

   ...
   <devices>
     <interface type='server'>
       <mac address='52:54:00:22:c9:42'/>
       <source address='192.168.0.1' port='5558'/>
     </interface>
     ...
     <interface type='client'>
       <mac address='52:54:00:8b:c9:51'/>
       <source address='192.168.0.1' port='5558'/>
     </interface>
   </devices>
   ...

UDP unicast tunnel
^^^^^^^^^^^^^^^^^^

A UDP unicast architecture provides a virtual network which enables connections
between QEMU instances using QEMU's UDP infrastructure. The xml "source" address
is the endpoint address to which the UDP socket packets will be sent from the
host running QEMU. The xml "local" address is the address of the interface from
which the UDP socket packets will originate from the QEMU host. :since:`Since
1.2.20`

::

   ...
   <devices>
     <interface type='udp'>
       <mac address='52:54:00:22:c9:42'/>
       <source address='127.0.0.1' port='11115'>
         <local address='127.0.0.1' port='11116'/>
       </source>
     </interface>
   </devices>
   ...

Null network interface
^^^^^^^^^^^^^^^^^^^^^^^

An unconnected network interface sounds pretty pointless, but can show up for
example with VMWare without any specified network to be connected to.
:since:`Since 8.7.0`

::

   ...
   <devices>
     <interface type='null'>
       <mac address='52:54:00:22:c9:42'/>
     </interface>
   </devices>
   ...

VMWare Distributed Switch
^^^^^^^^^^^^^^^^^^^^^^^^^

Interface can be connected to VMWare Distributed Switch, but since libvirt
cannot provide information about that architecture, the information presented
here is only what can be gathered from the VM configuration.  VMs with this
interface type can be created, so that editing of the XML works properly,
however libvirt cannot guarantee that any changes in these parameters will be
valid in the hypervisor. :since:`Since 8.7.0`

::

   ...
   <devices>
     <interface type='vds'>
       <mac address='52:54:00:22:c9:42'/>
       <source switchid='12345678-1234-1234-1234-123456789abc' portid='6' portgroupid='pg-4321' connectionid='12345'/>
     </interface>
   </devices>
   ...

Setting the NIC model
^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet1'/>
       <model type='ne2k_pci'/>
     </interface>
   </devices>
   ...

For hypervisors which support this, you can set the model of emulated network
interface card.

The values for ``type`` aren't defined specifically by libvirt, but by what the
underlying hypervisor supports (if any). For QEMU and KVM you can get a list of
supported models with these commands:

::

   qemu -net nic,model=? /dev/null
   qemu-kvm -net nic,model=? /dev/null

Typical values for QEMU and KVM include: ne2k_isa i82551 i82557b i82559er
ne2k_pci pcnet rtl8139 e1000 virtio. :since:`Since 5.2.0` ,
``virtio-transitional`` and ``virtio-non-transitional`` values are supported.
See `Virtio transitional devices`_ for more details.
:since:`Since 9.3.0` igb is also supported.

Setting NIC driver-specific options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet1'/>
       <model type='virtio'/>
       <driver name='vhost' txmode='iothread' ioeventfd='on' event_idx='off' queues='5' rx_queue_size='256' tx_queue_size='256'>
         <host csum='off' gso='off' tso4='off' tso6='off' ecn='off' ufo='off' mrg_rxbuf='off'/>
         <guest csum='off' tso4='off' tso6='off' ecn='off' ufo='off'/>
       </driver>
       </interface>
   </devices>
   ...

Some NICs may have tunable driver-specific options. These are set as attributes
of the ``driver`` sub-element of the interface definition. Currently the
following attributes are available for the ``virtio`` NIC driver:

``name``
   The optional ``name`` attribute forces which type of backend driver to use.
   The value can be either 'qemu' (a user-space backend) or 'vhost' (a kernel
   backend, which requires the vhost module to be provided by the kernel); an
   attempt to require the vhost driver without kernel support will be rejected.
   If this attribute is not present, then the domain defaults to 'vhost' if
   present, but silently falls back to 'qemu' without error. :since:`Since 0.8.8
   (QEMU and KVM only)`
   For interfaces of type='hostdev' (PCI passthrough devices) the ``name``
   attribute can optionally be set to "vfio" or "kvm". "vfio" tells libvirt to
   use VFIO device assignment rather than traditional KVM device assignment
   (VFIO is a new method of device assignment that is compatible with UEFI
   Secure Boot), and "kvm" tells libvirt to use the legacy device assignment
   performed directly by the kvm kernel module (the default is currently "kvm",
   but is subject to change). :since:`Since 1.0.5 (QEMU and KVM only, requires
   kernel 3.6 or newer)`
   For interfaces of type='vhostuser', the ``name`` attribute is ignored. The
   backend driver used is always vhost-user.
``txmode``
   The ``txmode`` attribute specifies how to handle transmission of packets when
   the transmit buffer is full. The value can be either 'iothread' or 'timer'.
   :since:`Since 0.8.8 (QEMU and KVM only)`
   If set to 'iothread', packet tx is all done in an iothread in the bottom half
   of the driver (this option translates into adding "tx=bh" to the qemu
   commandline -device virtio-net-pci option).
   If set to 'timer', tx work is done in qemu, and if there is more tx data than
   can be sent at the present time, a timer is set before qemu moves on to do
   other things; when the timer fires, another attempt is made to send more
   data.
   The resulting difference, according to the qemu developer who added the
   option is: "bh makes tx more asynchronous and reduces latency, but
   potentially causes more processor bandwidth contention since the CPU doing
   the tx isn't necessarily the CPU where the guest generated the packets."
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing.**
``ioeventfd``
   This optional attribute allows users to set `domain I/O asynchronous
   handling <https://patchwork.kernel.org/patch/43390/>`__ for interface device.
   The default is left to the discretion of the hypervisor. Accepted values are
   "on" and "off". Enabling this allows qemu to execute VM while a separate
   thread handles I/O. Typically guests experiencing high system CPU utilization
   during I/O will benefit from this. On the other hand, on overloaded host it
   could increase guest I/O latency. :since:`Since 0.9.3 (QEMU and KVM only)`
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing.**
``event_idx``
   The ``event_idx`` attribute controls some aspects of device event processing.
   The value can be either 'on' or 'off' - if it is on, it will reduce the
   number of interrupts and exits for the guest. The default is determined by
   QEMU; usually if the feature is supported, default is on. In case there is a
   situation where this behavior is suboptimal, this attribute provides a way to
   force the feature off. :since:`Since 0.9.5 (QEMU and KVM only)`
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing.**
``queues``
   The optional ``queues`` attribute controls the number of queues to be used
   for either `Multiqueue
   virtio-net <https://www.linux-kvm.org/page/Multiqueue>`__ or vhost-user (See
   `vhost-user interface`_) network interfaces. Use of multiple packet
   processing queues requires the interface having the
   ``<model type='virtio'/>`` element. Each queue will potentially be handled by
   a different processor, resulting in much higher throughput.
   :since:`virtio-net since 1.0.6 (QEMU and KVM only)` :since:`vhost-user since
   1.2.17 (QEMU and KVM only)`
``rx_queue_size``
   The optional ``rx_queue_size`` attribute controls the size of virtio ring for
   each queue as described above. The default value is hypervisor dependent and
   may change across its releases. Moreover, some hypervisors may pose some
   restrictions on actual value. For instance, latest QEMU (as of 2016-09-01)
   requires value to be a power of two from [256, 1024] range. :since:`Since
   2.3.0 (QEMU and KVM only)`
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing.**
``tx_queue_size``
   The optional ``tx_queue_size`` attribute controls the size of virtio ring for
   each queue as described above. The default value is hypervisor dependent and
   may change across its releases. Moreover, some hypervisors may pose some
   restrictions on actual value. For instance, QEMU v2.9 requires value to be a
   power of two from [256, 1024] range. In addition to that, this may work only
   for a subset of interface types, e.g. aforementioned QEMU enables this option
   only for ``vhostuser`` type. :since:`Since 3.7.0 (QEMU and KVM only)`
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing.**
``rss``
   The ``rss`` option enables in-qemu/ebpf RSS for virtio NIC. RSS works with
   virtio and tap backends only. Virtio NIC will be launched with "rss"
   property. For now "in-qemu" RSS is supported by libvirt.
   QEMU may load eBPF RSS if it has CAP_SYS_ADMIN permissions, which is
   not supported by default in libvirt. :since:`Since 8.3.0 and QEMU 5.1`
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing. Proper RSS configuration depends from vcpu,
   tap, and vhost settings.**
``rss_hash_report``
   The ``rss_hash_report`` option enables in-qemu RSS hash report for virtio
   NIC. Virtio NIC will be launched with a "hash" property. Network packets provided
   to VM will contain a hash of the packet in the virt header. Usually enabled
   alongside with ``rss``. Without ``rss`` option, the hash report doesn't affect
   steering itself but provides vnet header with a calculated hash.
   :since:`Since 8.3.0 and QEMU 5.1`
   **In general you should leave this option alone, unless you are very certain
   you know what you are doing. Proper RSS configuration depends from vcpu,
   tap, and vhost settings.**
virtio options
   For virtio interfaces, `Virtio-related options`_ can also
   be set. ( :since:`Since 3.5.0` )

Offloading options for the host and guest can be configured using the following
sub-elements:

``host``
   The ``csum``, ``gso``, ``tso4``, ``tso6``, ``ecn`` and ``ufo`` attributes
   with possible values ``on`` and ``off`` can be used to turn off host
   offloading options. By default, the supported offloads are enabled by QEMU.
   :since:`Since 1.2.9 (QEMU only)` The ``mrg_rxbuf`` attribute can be used to
   control mergeable rx buffers on the host side. Possible values are ``on``
   (default) and ``off``. :since:`Since 1.2.13 (QEMU only)`
``guest``
   The ``csum``, ``tso4``, ``tso6``, ``ecn`` and ``ufo`` attributes with
   possible values ``on`` and ``off`` can be used to turn off guest offloading
   options. By default, the supported offloads are enabled by QEMU.
   :since:`Since 1.2.9 (QEMU only)`

Setting network backend-specific options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet1'/>
       <model type='virtio'/>
       <backend tap='/dev/net/tun' vhost='/dev/vhost-net'/>
       <driver name='vhost' txmode='iothread' ioeventfd='on' event_idx='off' queues='5'/>
       <tune>
         <sndbuf>1600</sndbuf>
       </tune>
     </interface>
   </devices>
   ...

For tuning the backend of the network, the ``backend`` element can be used. The
``vhost`` attribute can override the default vhost device path
(``/dev/vhost-net``) for devices with ``virtio`` model. The ``tap`` attribute
overrides the tun/tap device path (default: ``/dev/net/tun``) for network and
bridge interfaces. This does not work in session mode. :since:`Since 1.2.9`

For tap devices there is also ``sndbuf`` element which can adjust the size of
send buffer in the host. :since:`Since 0.8.8`


Overriding the target element
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet1'/>
     </interface>
   </devices>
   ...

If no target is specified, certain hypervisors will automatically generate a
name for the created tun device. This name can be manually specified, however
the name *should not start with either 'vnet', 'vif', 'macvtap', or 'macvlan'*,
which are prefixes reserved by libvirt and certain hypervisors. Manually
specified targets using these prefixes may be ignored.

Note that for LXC containers, this defines the name of the interface on the host
side. :since:`Since 1.2.7` , to define the name of the device on the guest side,
the ``guest`` element should be used, as in the following snippet:

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <guest dev='myeth'/>
     </interface>
   </devices>
   ...

Specifying boot order
^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet1'/>
       <boot order='1'/>
     </interface>
   </devices>
   ...

For hypervisors which support this, you can set a specific NIC to be used for
network boot. The ``order`` attribute determines the order in which devices will
be tried during boot sequence. The per-device ``boot`` elements cannot be used
together with general boot elements in `BIOS bootloader`_
section. :since:`Since 0.8.8`

Interface ROM BIOS configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet1'/>
       <rom bar='on' file='/etc/fake/boot.bin'/>
     </interface>
   </devices>
   ...

For hypervisors which support this, you can change how a PCI Network device's
ROM is presented to the guest. The ``bar`` attribute can be set to "on" or
"off", and determines whether or not the device's ROM will be visible in the
guest's memory map. (In PCI documentation, the "rombar" setting controls the
presence of the Base Address Register for the ROM). If no rom bar is specified,
the qemu default will be used (older versions of qemu used a default of "off",
while newer qemus have a default of "on"). The optional ``file`` attribute is
used to point to a binary file to be presented to the guest as the device's ROM
BIOS. This can be useful to provide an alternative boot ROM for a network
device. :since:`Since 0.9.10 (QEMU and KVM only)` .

Setting up a network backend in a driver domain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     ...
     <interface type='bridge'>
       <source bridge='br0'/>
       <backenddomain name='netvm'/>
     </interface>
     ...
   </devices>
   ...

The optional ``backenddomain`` element allows specifying a backend domain (aka
driver domain) for the interface. Use the ``name`` attribute to specify the
backend domain name. You can use it to create a direct network link between
domains (so data will not go through host system). Use with type 'ethernet' to
create plain network link, or with type 'bridge' to connect to a bridge inside
the backend domain. :since:`Since 1.2.13 (Xen only)`


Quality of service
^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet0'/>
       <bandwidth>
         <inbound average='1000' peak='5000' floor='200' burst='1024'/>
         <outbound average='128' peak='256' burst='256'/>
       </bandwidth>
     </interface>
   </devices>
   ...

This part of interface XML provides setting quality of service. Incoming and
outgoing traffic can be shaped independently. The ``bandwidth`` element and its
child elements are described in the `QoS <formatnetwork.html#quality-of-service>`__
section of the Network XML.


Setting VLAN tag (on supported network types only)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='bridge'>
       <vlan>
         <tag id='42'/>
       </vlan>
       <source bridge='ovsbr0'/>
       <virtualport type='openvswitch'>
         <parameters interfaceid='09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f'/>
       </virtualport>
     </interface>
     <interface type='bridge'>
       <vlan trunk='yes'>
         <tag id='42'/>
         <tag id='123' nativeMode='untagged'/>
       </vlan>
       ...
     </interface>
   </devices>
   ...

If (and only if) the network connection used by the guest supports VLAN tagging
transparent to the guest, an optional ``<vlan>`` element can specify one or more
VLAN tags to apply to the guest's network traffic :since:`Since 0.10.0` .
Network connections that support guest-transparent VLAN tagging include 1)
type='bridge' interfaces connected to an Open vSwitch bridge :since:`Since
0.10.0` , 2) SRIOV Virtual Functions (VF) used via type='hostdev' (direct device
assignment) :since:`Since 0.10.0` , and 3) SRIOV VFs used via type='direct' with
mode='passthrough' (macvtap "passthru" mode) :since:`Since 1.3.5` . All other
connection types, including standard linux bridges and libvirt's own virtual
networks, **do not** support it. 802.1Qbh (vn-link) and 802.1Qbg (VEPA) switches
provide their own way (outside of libvirt) to tag guest traffic onto a specific
VLAN. Each tag is given in a separate ``<tag>`` subelement of ``<vlan>`` (for
example: ``<tag       id='42'/>``). For VLAN trunking of multiple tags (which is
supported only on Open vSwitch connections), multiple ``<tag>`` subelements can
be specified, which implies that the user wants to do VLAN trunking on the
interface for all the specified tags. In the case that VLAN trunking of a single
tag is desired, the optional attribute ``trunk='yes'`` can be added to the
toplevel ``<vlan>`` element to differentiate trunking of a single tag from
normal tagging.

For network connections using Open vSwitch it is also possible to configure
'native-tagged' and 'native-untagged' VLAN modes :since:`Since 1.1.0.` This is
done with the optional ``nativeMode`` attribute on the ``<tag>`` subelement:
``nativeMode`` may be set to 'tagged' or 'untagged'. The ``id`` attribute of the
``<tag>`` subelement containing ``nativeMode`` sets which VLAN is considered to
be the "native" VLAN for this interface, and the ``nativeMode`` attribute
determines whether or not traffic for that VLAN will be tagged.


Isolating guests' network traffic from each other
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <port isolated='yes'/>
     </interface>
   </devices>
   ...

:since:`Since 6.1.0.` The ``port`` element property ``isolated``, when set to
``yes`` (default setting is ``no``) is used to isolate this interface's network
traffic from that of other guest interfaces connected to the same network that
also have ``<port isolated='yes'/>``. This setting is only supported for
emulated interface devices that use a standard tap device to connect to the
network via a Linux host bridge. This property can be inherited from a libvirt
network, so if all guests that will be connected to the network should be
isolated, it is better to put the setting in the network configuration. (NB:
this only prevents guests that have ``isolated='yes'`` from communicating with
each other; if there is a guest on the same bridge that doesn't have
``isolated='yes'``, even the isolated guests will be able to communicate with
it.)

Modifying virtual link state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet0'/>
       <link state='down'/>
     </interface>
   </devices>
   ...

This element provides means of setting state of the virtual network link.
Possible values for attribute ``state`` are ``up`` and ``down``. If ``down`` is
specified as the value, the interface behaves as if it had the network cable
disconnected. Default behavior if this element is unspecified is to have the
link state ``up``. :since:`Since 0.9.5`


MTU configuration
^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet0'/>
       <mtu size='1500'/>
     </interface>
   </devices>
   ...

This element provides means of setting MTU of the virtual network link.
Currently there is just one attribute ``size`` which accepts a non-negative
integer which specifies the MTU size for the interface. :since:`Since 3.1.0`


Coalesce settings
^^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet0'/>
       <coalesce>
         <rx>
           <frames max='7'/>
         </rx>
       </coalesce>
     </interface>
   </devices>
   ...

This element provides means of setting coalesce settings for some interface
devices (currently only type ``network`` and ``bridge``. Currently there is just
one attribute, ``max``, to tweak, in element ``frames`` for the ``rx`` group,
which accepts a non-negative integer that specifies the maximum number of
packets that will be received before an interrupt. :since:`Since 3.3.0`

IP configuration
^^^^^^^^^^^^^^^^

::

   ...
   <devices>
     <interface type='network'>
       <source network='default'/>
       <target dev='vnet0'/>
       <ip address='192.168.122.5' prefix='24'/>
       <ip address='192.168.122.5' prefix='24' peer='10.0.0.10'/>
       <route family='ipv4' address='192.168.122.0' prefix='24' gateway='192.168.122.1'/>
       <route family='ipv4' address='192.168.122.8' gateway='192.168.122.1'/>
     </interface>
     ...
     <hostdev mode='capabilities' type='net'>
       <source>
         <interface>eth0</interface>
       </source>
       <ip address='192.168.122.6' prefix='24'/>
       <route family='ipv4' address='192.168.122.0' prefix='24' gateway='192.168.122.1'/>
       <route family='ipv4' address='192.168.122.8' gateway='192.168.122.1'/>
     </hostdev>
     ...
   </devices>
   ...

:since:`Since 1.2.12` network devices and hostdev devices with network
capabilities can optionally be provided one or more IP addresses to set on the
network device in the guest. Note that some hypervisors or network device types
will simply ignore them or only use the first one. The ``family`` attribute can
be set to either ``ipv4`` or ``ipv6``, and the ``address`` attribute contains
the IP address. The optional ``prefix`` is the number of 1 bits in the netmask,
and will be automatically set if not specified - for IPv4 the default prefix is
determined according to the network "class" (A, B, or C - see RFC870), and for
IPv6 the default prefix is 64. The optional ``peer`` attribute holds the IP
address of the other end of a point-to-point network device :since:`(since
2.1.0)` .

:since:`Since 1.2.12` route elements can also be added to define IP routes to
add in the guest. The attributes of this element are described in the
documentation for the ``route`` element in `network
definitions <formatnetwork.html#static-routes>`__. This is used by the LXC
driver.

::

   ...
   <devices>
     <interface type='ethernet'>
       <source/>
         <ip address='192.168.123.1' prefix='24'/>
         <ip address='10.0.0.10' prefix='24' peer='192.168.122.5'/>
         <route family='ipv4' address='192.168.42.0' prefix='24' gateway='192.168.123.4'/>
       <source/>
       ...
     </interface>
     ...
   </devices>
   ...

:since:`Since 2.1.0` network devices of type "ethernet" can optionally be
provided one or more IP addresses and one or more routes to set on the **host**
side of the network device. These are configured as subelements of the
``<source>`` element of the interface, and have the same attributes as the
similarly named elements used to configure the guest side of the interface
(described above).


vhost-user interface
^^^^^^^^^^^^^^^^^^^^

:since:`Since 1.2.7` the vhost-user enables the communication between a QEMU
virtual machine and other userspace process using the Virtio transport protocol.
A char dev (e.g. Unix socket) is used for the control plane, while the data
plane is based on shared memory.

::

   ...
   <devices>
     <interface type='vhostuser'>
       <mac address='52:54:00:3b:83:1a'/>
       <source type='unix' path='/tmp/vhost1.sock' mode='server'/>
       <model type='virtio'/>
     </interface>
     <interface type='vhostuser'>
       <mac address='52:54:00:3b:83:1b'/>
       <source type='unix' path='/tmp/vhost2.sock' mode='client'>
         <reconnect enabled='yes' timeout='10'/>
       </source>
       <model type='virtio'/>
       <driver queues='5'/>
     </interface>
   </devices>
   ...

The ``<source>`` element has to be specified along with the type of char device.
Currently, only type='unix' is supported, where the path (the directory path of
the socket) and mode attributes are required. Both ``mode='server'`` and
``mode='client'`` are supported. vhost-user requires the virtio model type, thus
the ``<model>`` element is mandatory. :since:`Since 4.1.0` the element has an
optional child element ``reconnect`` which configures reconnect timeout if the
connection is lost. It has two attributes ``enabled`` (which accepts ``yes`` and
``no``) and ``timeout`` which specifies the amount of seconds after which
hypervisor tries to reconnect.

Traffic filtering with NWFilter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:since:`Since 0.8.0` an ``nwfilter`` profile can be assigned to a domain
interface, which allows configuring traffic filter rules for the virtual
machine. See the `nwfilter <formatnwfilter.html>`__ documentation for more
complete details.

::

   ...
   <devices>
     <interface ...>
       ...
       <filterref filter='clean-traffic'/>
     </interface>
     <interface ...>
       ...
       <filterref filter='myfilter'>
         <parameter name='IP' value='104.207.129.11'/>
         <parameter name='IP6_ADDR' value='2001:19f0:300:2102::'/>
         <parameter name='IP6_MASK' value='64'/>
         ...
       </filterref>
     </interface>
   </devices>
   ...

The ``filter`` attribute specifies the name of the nwfilter to use. Optional
``<parameter>`` elements may be specified for passing additional info to the
nwfilter via the ``name`` and ``value`` attributes. See the
`nwfilter <formatnwfilter.html#usage-of-variables-in-filters>`__ docs for info
on parameters.

Input devices
~~~~~~~~~~~~~

Input devices allow interaction with the graphical framebuffer in the guest
virtual machine. When enabling the framebuffer, an input device is automatically
provided. It may be possible to add additional devices explicitly, for example,
to provide a graphics tablet for absolute cursor movement.

::

   ...
   <devices>
     <input type='mouse' bus='usb'/>
     <input type='keyboard' bus='usb'/>
     <input type='mouse' bus='virtio'/>
     <input type='keyboard' bus='virtio'/>
     <input type='tablet' bus='virtio'/>
     <input type='passthrough' bus='virtio'>
       <source evdev='/dev/input/event1'/>
     </input>
     <input type='evdev'>
       <source dev='/dev/input/event1234' grab='all' repeat='on' grabToggle='ctrl-ctrl'/>
     </input>
   </devices>
   ...

``input``
   The ``input`` element has one mandatory attribute, the ``type`` whose value
   can be 'mouse', 'tablet', ( :since:`since 1.2.2` ) 'keyboard', (
   :since:`since 1.3.0` ) 'passthrough' or ( :since:`since 7.4.0` ) 'evdev'.
   The tablet provides absolute cursor movement, while the mouse uses relative
   movement. The optional ``bus`` attribute can be used to refine the exact
   device type. It takes values "xen" (paravirtualized), "ps2" and "usb" or (
   :since:`since 1.3.0` ) "virtio".

The ``input`` element has an optional sub-element ``<address>`` which can tie
the device to a particular PCI slot, documented in the `Device Addresses`_ section.
On S390, ``address`` can be used to provide a CCW address for an input device (
:since:`since 4.2.0` ). For types ``passthrough`` and ``evdev``, the mandatory
sub-element ``source`` must have an ``evdev`` (for ``passthrough``) or ``dev``
(for ``evdev``) attribute containing the absolute path to the event device
passed through to guests.
For type ``evdev``, ``source`` has three optional attributes ``grab`` with
value 'all' which when enabled grabs all input devices instead of just one,
``repeat`` with value 'on'/'off' to enable/disable auto-repeat events and
``grabToggle`` (:since:`since 7.6.0`) with values ``ctrl-ctrl``, ``alt-alt``,
``shift-shift``, ``meta-meta``, ``scrolllock`` or ``ctrl-scrolllock`` to
change the grab key combination.
``input`` type ``evdev`` is currently supported only on linux devices.
(KVM only) :since:`Since 5.2.0` , the ``input`` element accepts a
``model`` attribute which has the values 'virtio', 'virtio-transitional' and
'virtio-non-transitional'. See `Virtio transitional devices`_ for more details.

The subelement ``driver`` can be used to tune the virtio options of the device:
`Virtio-related options`_ can also be set. ( :since:`Since 3.5.0` )

Hub devices
~~~~~~~~~~~

A hub is a device that expands a single port into several so that there are more
ports available to connect devices to a host system.

::

   ...
   <devices>
     <hub type='usb'/>
   </devices>
   ...

``hub``
   The ``hub`` element has one mandatory attribute, the ``type`` whose value can
   only be 'usb'.

The ``hub`` element has an optional sub-element ``<address>``
(See `Device Addresses`_) ``type='usb'`` which can tie the device to a
particular controller.


Graphical framebuffers
~~~~~~~~~~~~~~~~~~~~~~

A graphics device allows for graphical interaction with the guest OS. A guest
will typically have either a framebuffer or a text console configured to allow
interaction with the admin.

::

   ...
   <devices>
     <graphics type='sdl' display=':0.0'/>
     <graphics type='vnc' port='5904' sharePolicy='allow-exclusive'>
       <listen type='address' address='1.2.3.4'/>
     </graphics>
     <graphics type='rdp' autoport='yes' multiUser='yes' />
     <graphics type='desktop' fullscreen='yes'/>
     <graphics type='spice'>
       <listen type='network' network='rednet'/>
     </graphics>
   </devices>
   ...

``graphics``
   The ``graphics`` element has a mandatory ``type`` attribute which takes the
   value ``sdl``, ``vnc``, ``spice``, ``rdp``, ``desktop`` or ``egl-headless``:

   ``sdl``
      This displays a window on the host desktop, it can take 3 optional
      arguments: a ``display`` attribute for the display to use, an ``xauth``
      attribute for the authentication identifier, and an optional
      ``fullscreen`` attribute accepting values ``yes`` or ``no``.

      You can use a ``gl`` with the ``enable="yes"`` property to enable OpenGL
      support in SDL. Likewise you can explicitly disable OpenGL support with
      ``enable="no"``.

   ``vnc``
      Starts a VNC server. The ``port`` attribute specifies the TCP port number
      (with -1 as legacy syntax indicating that it should be auto-allocated).
      The ``autoport`` attribute is the new preferred syntax for indicating
      auto-allocation of the TCP port to use. The ``passwd`` attribute provides
      a VNC password in clear text. If the ``passwd`` attribute is set to an
      empty string, then VNC access is disabled. The ``keymap`` attribute
      specifies the keymap to use. It is possible to set a limit on the validity
      of the password by giving a timestamp
      ``passwdValidTo='2010-04-09T15:51:00'`` assumed to be in UTC. The
      ``connected`` attribute allows control of connected client during password
      changes. VNC accepts ``keep`` value only :since:`since 0.9.3` . NB, this
      may not be supported by all hypervisors.

      The optional ``sharePolicy`` attribute specifies vnc server display
      sharing policy. ``allow-exclusive`` allows clients to ask for exclusive
      access by dropping other connections. Connecting multiple clients in
      parallel requires all clients asking for a shared session (vncviewer:
      -Shared switch). This is the default value. ``force-shared`` disables
      exclusive client access, every connection has to specify -Shared switch
      for vncviewer. ``ignore`` welcomes every connection unconditionally
      :since:`since 1.0.6` .

      Rather than using listen/port, QEMU supports a ``socket`` attribute for
      listening on a unix domain socket path :since:`Since 0.8.8` .

      For VNC WebSocket functionality, ``websocket`` attribute may be used to
      specify port to listen on (with -1 meaning auto-allocation and
      ``autoport`` having no effect due to security reasons) :since:`Since
      1.0.6` .

      For VNC, the ``powerControl`` attribute can be used to enable VM shutdown,
      reboot and reset power control features for the VNC client. This is
      appropriate if the authenticated VNC client user already has administrator
      privileges in the guest :since:`Since 7.1.0`.

      Although VNC doesn't support OpenGL natively, it can be paired with
      graphics type ``egl-headless`` (see below) which will instruct QEMU to
      open and use drm nodes for OpenGL rendering.

      A VNC server could be optionally mapped to the specific host audio
      backend using the ``<audio>`` sub-element:

      ::

         <graphics type='vnc' ...>
           <audio id='1'>
         </graphics>

      Where ``1`` is an id of the audio device (See`Audio backends`_). If no
      ID is specified, then the default audio backend will be used.
      :since:`Since 7.2.0, qemu`.

   ``spice`` :since:`Since 0.8.6`
      Starts a SPICE server. The ``port`` attribute specifies the TCP port
      number (with -1 as legacy syntax indicating that it should be
      auto-allocated), while ``tlsPort`` gives an alternative secure port
      number. The ``autoport`` attribute is the new preferred syntax for
      indicating auto-allocation of needed port numbers. The ``passwd``
      attribute provides a SPICE password in clear text. If the ``passwd``
      attribute is set to an empty string, then SPICE access is disabled. The
      ``keymap`` attribute specifies the keymap to use. It is possible to set a
      limit on the validity of the password by giving a timestamp
      ``passwdValidTo='2010-04-09T15:51:00'`` assumed to be in UTC.

      The ``connected`` attribute allows control of connected client during
      password changes. SPICE accepts ``keep`` to keep client connected,
      ``disconnect`` to disconnect client and ``fail`` to fail changing password
      . NB, this may not be supported by all hypervisors. :since:`Since 0.9.3`

      The ``defaultMode`` attribute sets the default channel security policy,
      valid values are ``secure``, ``insecure`` and the default ``any`` (which
      is secure if possible, but falls back to insecure rather than erroring out
      if no secure path is available). :since:`Since 0.9.12`

      When SPICE has both a normal and TLS secured TCP port configured, it can
      be desirable to restrict what channels can be run on each port. This is
      achieved by adding one or more ``<channel>`` elements inside the main
      ``<graphics>`` element and setting the ``mode`` attribute to either
      ``secure`` or ``insecure``. Setting the mode attribute overrides the
      default value as set by the ``defaultMode`` attribute. (Note that
      specifying ``any`` as mode discards the entry as the channel would inherit
      the default mode anyways.) Valid channel names include ``main``,
      ``display``, ``inputs``, ``cursor``, ``playback``, ``record`` (all
      :since:`since 0.8.6` ); ``smartcard`` ( :since:`since 0.8.8` ); and
      ``usbredir`` ( :since:`since 0.9.12` ).

      ::

         <graphics type='spice' port='-1' tlsPort='-1' autoport='yes'>
           <channel name='main' mode='secure'/>
           <channel name='record' mode='insecure'/>
           <image compression='auto_glz'/>
           <streaming mode='filter'/>
           <clipboard copypaste='no'/>
           <mouse mode='client'/>
           <filetransfer enable='no'/>
           <gl enable='yes' rendernode='/dev/dri/by-path/pci-0000:00:02.0-render'/>
         </graphics>

      Spice supports variable compression settings for audio, images and
      streaming. These settings are accessible via the ``compression`` attribute
      in all following elements: ``image`` to set image compression (accepts
      ``auto_glz``, ``auto_lz``, ``quic``, ``glz``, ``lz``, ``off``), ``jpeg``
      for JPEG compression for images over wan (accepts ``auto``, ``never``,
      ``always``), ``zlib`` for configuring wan image compression (accepts
      ``auto``, ``never``, ``always``) and ``playback`` for enabling audio
      stream compression (accepts ``on`` or ``off``). :since:`Since 0.9.1`

      Streaming mode is set by the ``streaming`` element, settings its ``mode``
      attribute to one of ``filter``, ``all`` or ``off``. :since:`Since 0.9.2`

      Copy & Paste functionality (via Spice agent) is set by the ``clipboard``
      element. It is enabled by default, and can be disabled by setting the
      ``copypaste`` property to ``no``. :since:`Since 0.9.3`

      Mouse mode is set by the ``mouse`` element, setting its ``mode`` attribute
      to one of ``server`` or ``client``. If no mode is specified, the qemu
      default will be used (client mode). :since:`Since 0.9.11`

      File transfer functionality (via Spice agent) is set using the
      ``filetransfer`` element. It is enabled by default, and can be disabled by
      setting the ``enable`` property to ``no``. :since:`Since 1.2.2`

      Spice may provide accelerated server-side rendering with OpenGL. You can
      enable or disable OpenGL support explicitly with the ``gl`` element, by
      setting the ``enable`` property. (QEMU only, :since:`since 1.3.3` ). Note
      that this only works locally, since this requires usage of UNIX sockets,
      i.e. using ``listen`` types 'socket' or 'none'. For accelerated OpenGL
      with remote support, consider pairing this element with type
      ``egl-headless`` (see below). However, this will deliver weaker
      performance compared to native Spice OpenGL support.

      By default, QEMU will pick the first available GPU DRM render node. You
      may specify a DRM render node path to use instead. (QEMU only,
      :since:`since 3.1.0` ).

   ``rdp``
      Starts a RDP server. The ``port`` attribute specifies the TCP port number
      (with -1 as legacy syntax indicating that it should be auto-allocated).
      The ``autoport`` attribute is the new preferred syntax for indicating
      auto-allocation of the TCP port to use. In the VirtualBox driver, the
      ``autoport`` will make the hypervisor pick available port from 3389-3689
      range when the VM is started. The chosen port will be reflected in the
      ``port`` attribute. The ``multiUser`` attribute is a boolean deciding
      whether multiple simultaneous connections to the VM are permitted. The
      ``replaceUser`` attribute is a boolean deciding whether the existing
      connection must be dropped and a new connection must be established by the
      VRDP server, when a new client connects in single connection mode.

   ``desktop``
      This value is reserved for VirtualBox domains for the moment. It displays
      a window on the host desktop, similarly to "sdl", but using the VirtualBox
      viewer. Just like "sdl", it accepts the optional attributes ``display``
      and ``fullscreen``.

   ``egl-headless`` :since:`Since 4.6.0`
      This display type provides support for an OpenGL accelerated display
      accessible both locally and remotely (for comparison, Spice's native
      OpenGL support only works locally using UNIX sockets at the moment, but
      has better performance). Since this display type doesn't provide any
      window or graphical console like the other types, for practical reasons it
      should be paired with either ``vnc`` or ``spice`` graphics types. This
      display type is only supported by QEMU domains (needs QEMU :since:`2.10`
      or newer). :since:`5.0.0` this element accepts a ``<gl/>`` sub-element
      with an optional attribute ``rendernode`` which can be used to specify an
      absolute path to a host's DRI device to be used for OpenGL rendering.

      ::

         <graphics type='spice' autoport='yes'/>
         <graphics type='egl-headless'>
           <gl rendernode='/dev/dri/renderD128'/>
         </graphics>

   ``dbus``:since:`Since 8.4.0`
      Export the display over D-Bus. By default, it will use a private bus,
      except when ``p2p`` or ``address`` are specified.

      ::

        <graphics type='dbus'/>

      ``p2p`` (accepts ``on`` or ``off``) enables peer-to-peer connections,
      established through virDomainOpenGraphics() APIs.

      ``address`` (accepts a `D-Bus address
      <https://dbus.freedesktop.org/doc/dbus-specification.html#addresses>`_),
      will connect to the specified bus address.

      This element accepts a ``<gl/>`` sub-element with an optional attribute
      ``rendernode`` which can be used to specify an absolute path to a host's
      DRI device to be used for OpenGL rendering.

      Copy & Paste functionality is provided thanks to the QEMU clipboard
      manager and the SPICE vdagent protocol. See ``qemu-vdagent`` for more
      details.

      D-Bus can export an audio backend using the ``<audio>`` sub-element:

      ::

         <graphics type='dbus' ...>
           <audio id='1'>
         </graphics>

      Where ``1`` is an id of the audio device (See `Audio backends`_).

Graphics device uses a ``<listen>`` to set up where the device should listen for
clients. It has a mandatory attribute ``type`` which specifies the listen type.
Only ``vnc``, ``spice`` and ``rdp`` supports ``<listen>`` element. :since:`Since
0.9.4` . Available types are:

``address``
   Tells a graphics device to use an address specified in the ``address``
   attribute, which will contain either an IP address or hostname (which will be
   resolved to an IP address via a DNS query) to listen on.

   It is possible to omit the ``address`` attribute in order to use an address
   from config files :since:`Since 1.3.5` .

   The ``address`` attribute is duplicated as ``listen`` attribute in
   ``graphics`` element for backward compatibility. If both are provided they
   must be equal.

``network``
   This is used to specify an existing network in the ``network`` attribute from
   libvirt's list of configured networks. The named network configuration will
   be examined to determine an appropriate listen address and the address will
   be stored in live XML in ``address`` attribute. For example, if the network
   has an IPv4 address in its configuration (e.g. if it has a forward type of
   ``route``, ``nat``, or no forward type (isolated)), the first IPv4 address
   listed in the network's configuration will be used. If the network is
   describing a host bridge, the first IPv4 address associated with that bridge
   device will be used, and if the network is describing one of the 'direct'
   (macvtap) modes, the first IPv4 address of the first forward dev will be
   used.

``socket`` :since:`since 2.0.0 (QEMU only)`
   This listen type tells a graphics server to listen on unix socket. Attribute
   ``socket`` contains a path to unix socket. If this attribute is omitted
   libvirt will generate this path for you. Supported by graphics type ``vnc``
   and ``spice``.

   For ``vnc`` graphics be backward compatible the ``socket`` attribute of first
   ``listen`` element is duplicated as ``socket`` attribute in ``graphics``
   element. If ``graphics`` element contains a ``socket`` attribute all
   ``listen`` elements are ignored.

``none`` :since:`since 2.0.0 (QEMU only)`
   This listen type doesn't have any other attribute. Libvirt supports passing a
   file descriptor through our APIs virDomainOpenGraphics() and
   virDomainOpenGraphicsFD(). No other listen types are allowed if this one is
   used and the graphics device doesn't listen anywhere. You need to use one of
   the two APIs to pass a FD to QEMU in order to connect to this graphics
   device. Supported by graphics type ``vnc`` and ``spice``.


Video devices
~~~~~~~~~~~~~

A video device.

::

   ...
   <devices>
     <video>
       <model type='vga' vram='16384' heads='1'>
         <acceleration accel3d='yes' accel2d='yes'/>
       </model>
       <driver name='qemu'/>
     </video>
   </devices>
   ...

``video``
   The ``video`` element is the container for describing video devices. For
   backwards compatibility, if no ``video`` is set but there is a ``graphics``
   in domain xml, then libvirt will add a default ``video`` according to the
   guest type.

   For a guest of type "kvm", the default ``video`` is: ``type`` with value
   "cirrus", ``vram`` with value "16384" and ``heads`` with value "1". By
   default, the first video device in domain xml is the primary one, but the
   optional attribute ``primary`` ( :since:`since 1.0.2` ) with value 'yes' can
   be used to mark the primary in cases of multiple video device. The
   non-primary must be type of "qxl" or ( :since:`since 2.4.0` ) "virtio".

``model``
   The ``model`` element has a mandatory ``type`` attribute which takes the
   value "vga", "cirrus", "vmvga", "xen", "vbox", "qxl" ( :since:`since 0.8.6`
   ), "virtio" ( :since:`since 1.3.0` ), "gop" ( :since:`since 3.2.0` ), "bochs"
   ( :since:`since 5.6.0` ), "ramfb" ( :since:`since 5.9.0` ), or "none" (
   :since:`since 4.6.0` ), depending on the hypervisor features available.

   Note: The purpose of the type ``none`` is to instruct libvirt not to add a
   default video device in the guest (see the ``video`` element description
   above), since such behaviour is inconvenient in cases where GPU mediated
   devices are meant to be the only rendering device within a guest. If this
   is your use case specify a ``none`` type ``video`` device in the XML to stop
   the default behaviour. Refer to `Host device assignment`_ to see how to add
   a mediated device into a guest.

   You can provide the amount of video memory in kibibytes (blocks of 1024
   bytes) using ``vram``. This is supported only for guest type of "vz", "qemu",
   "kvm", "hvf", "vbox", "vmx" and "xen".
   If no value is provided the default is used. If the
   size is not a power of two it will be rounded to closest one.

   The number of screen can be set using ``heads``. This is supported only for
   guests type of "vz", "kvm", "hvf", "vbox" and "vmx".

   For guest type of "kvm", "hvf" or "qemu" and model type "qxl" there are
   optional attributes.
   Attribute ``ram`` ( :since:`since 1.0.2` ) specifies the size of
   the primary bar, while the attribute ``vram`` specifies the secondary bar
   size. If ``ram`` or ``vram`` are not supplied a default value is used. The
   ``ram`` should also be rounded to power of two as ``vram``. There is also
   optional attribute ``vgamem`` ( :since:`since 1.2.11` ) to set the size of
   VGA framebuffer for fallback mode of QXL device. Attribute ``vram64`` (
   :since:`since 1.3.3` ) extends secondary bar and makes it addressable as
   64bit memory.

   :since:`Since 9.2.0` (QEMU driver only), devices with type "virtio" have an
   optional ``blob`` attribute that can be set to "on" or "off". Setting
   ``blob`` to "on" will enable the use of blob resources in the device. This
   can accelerate the display path by reducing or eliminating copying of pixel
   data between the guest and host. Note that blob resource support requires
   QEMU version 6.1 or newer.

   :since:`Since 5.9.0` , the ``model`` element may also have an optional
   ``resolution`` sub-element. The ``resolution`` element has attributes ``x``
   and ``y`` to set the minimum resolution for the video device. This
   sub-element is valid for model types "vga", "qxl", "bochs", "gop",
   and "virtio".

``acceleration``
   Configure if video acceleration should be enabled.

   ``accel2d``
      Enable 2D acceleration (for vbox driver only, :since:`since 0.7.1` )
   ``accel3d``
      Enable 3D acceleration (for vbox driver :since:`since 0.7.1` , qemu driver
      :since:`since 1.3.0` )
   ``rendernode``
      Absolute path to a host's DRI device to be used for rendering (for
      'vhostuser' driver only, :since:`since 5.8.0` ). If none is specified,
      libvirt will pick one available.

``address``
   The optional ``address`` sub-element can be used to tie the video device to a
   particular PCI slot. On S390, ``address`` can be used to provide the CCW
   address for the video device ( :since:`since 4.2.0` ).
``driver``
   The subelement ``driver`` can be used to tune the device:

   ``name``
      Specify the backend driver to use, either "qemu" or "vhostuser" depending
      on the hypervisor features available ( :since:`since 5.8.0` ). "qemu" is
      the default QEMU backend. "vhostuser" will use a separate vhost-user
      process backend (for ``virtio`` device).
   virtio options
      `Virtio-related options`_ can also be set (:since:`Since 3.5.0`)
   VGA configuration
      Control how the video devices exposed to the guest using the ``vgaconf``
      attribute which takes the value "io", "on" or "off". At present, it's only
      applicable to the bhyve's "gop" video model type ( :since:`Since 3.5.0` )


Consoles, serial, parallel & channel devices
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A character device provides a way to interact with the virtual machine.
Paravirtualized consoles, serial ports, parallel ports and channels are all
classed as character devices and so represented using the same syntax.

::

   ...
   <devices>
     <parallel type='pty'>
       <source path='/dev/pts/2'/>
       <target port='0'/>
     </parallel>
     <serial type='pty'>
       <source path='/dev/pts/3'/>
       <target port='0'/>
     </serial>
     <serial type='file'>
       <source path='/tmp/file' append='on'>
         <seclabel model='dac' relabel='no'/>
       </source>
       <target port='0'/>
     </serial>
     <console type='pty'>
       <source path='/dev/pts/4'/>
       <target port='0'/>
     </console>
     <channel type='unix'>
       <source mode='bind' path='/tmp/guestfwd'/>
       <target type='guestfwd' address='10.0.2.1' port='4600'/>
     </channel>
   </devices>
   ...

In each of these directives, the top-level element name (parallel, serial,
console, channel) describes how the device is presented to the guest. The guest
interface is configured by the ``target`` element.

The interface presented to the host is given in the ``type`` attribute of the
top-level element. The host interface is configured by the ``source`` element.

The ``source`` element may contain an optional ``seclabel`` to override the way
that labelling is done on the socket path. If this element is not present, the
`Security label`_ is inherited from the per-domain setting.

If the interface ``type`` presented to the host is "file", then the ``source``
element may contain an optional attribute ``append`` that specifies whether or
not the information in the file should be preserved on domain restart. Allowed
values are "on" and "off" (default). :since:`Since 1.3.1` .

Regardless of the ``type``, character devices can have an optional log file
associated with them. This is expressed via a ``log`` sub-element, with a
``file`` attribute. There can also be an ``append`` attribute which takes the
same values described above. :since:`Since 1.3.3` .

::

   ...
   <log file="/var/log/libvirt/qemu/guestname-serial0.log" append="off"/>
   ...

Each character device element has an optional sub-element ``<address>`` which
can tie the device to a particular controller (See `Controllers`_) or PCI slot.

For character device with type ``unix`` or ``tcp`` the ``source`` has an
optional element ``reconnect`` which configures reconnect timeout if the
connection is lost. There are two attributes, ``enabled`` where possible values
are "yes" and "no" and ``timeout`` which is in seconds. The ``reconnect``
attribute is valid only for ``connect`` mode. :since:`Since 3.7.0 (QEMU driver
only)` .

Guest interface
^^^^^^^^^^^^^^^

A character device presents itself to the guest as one of the following types.

Parallel port
'''''''''''''

::

   ...
   <devices>
     <parallel type='pty'>
       <source path='/dev/pts/2'/>
       <target port='0'/>
     </parallel>
   </devices>
   ...

``target`` can have a ``port`` attribute, which specifies the port number. Ports
are numbered starting from 0. There are usually 0, 1 or 2 parallel ports.


Serial port
'''''''''''

::

   ...
   <devices>
     <!-- Serial port -->
     <serial type='pty'>
       <source path='/dev/pts/3'/>
       <target port='0'/>
     </serial>
     <!-- Debug port for SeaBIOS / EDK II -->
     <serial type='file'>
       <target type='isa-debug'/>
       <address type='isa' iobase='0x402'/>
       <source path='/tmp/DOMAIN-ovmf.log'/>
     </serial>

   </devices>
   ...

::

   ...
   <devices>
     <!-- USB serial port -->
     <serial type='pty'>
       <target type='usb-serial' port='0'>
         <model name='usb-serial'/>
       </target>
       <address type='usb' bus='0' port='1'/>
     </serial>
   </devices>
   ...

The ``target`` element can have an optional ``port`` attribute, which specifies
the port number (starting from 0), and an optional ``type`` attribute: valid
values are, :since:`since 1.0.2` , ``isa-serial`` (usable with x86 guests),
``usb-serial`` (usable whenever USB support is available) and ``pci-serial``
(usable whenever PCI support is available); :since:`since 3.10.0` ,
``spapr-vio-serial`` (usable with ppc64/pseries guests), ``system-serial``
(usable with aarch64/virt and, :since:`since 4.7.0` , riscv/virt guests),
``sclp-serial`` (usable with s390 and s390x guests) are available as well
and :since:`since 8.1.0` ``isa-debug`` (usable with x86 guests).

:since:`Since 3.10.0` , the ``target`` element can have an optional ``model``
subelement; valid values for its ``name`` attribute are: ``isa-serial`` (usable
with the ``isa-serial`` target type); ``usb-serial`` (usable with the
``usb-serial`` target type); ``pci-serial`` (usable with the ``pci-serial``
target type); ``spapr-vty`` (usable with the ``spapr-vio-serial`` target type);
``pl011`` and, :since:`since 4.7.0` , ``16550a`` (usable with the
``system-serial`` target type); ``sclpconsole`` and ``sclplmconsole`` (usable
with the ``sclp-serial`` target type). :since:`Since: 8.1.0`, ``isa-debugcon``
(usable with the ``isa-debug`` target type); provides a virtual console for
receiving debug messages from the firmware on x86 platforms.
Providing a target model is usually unnecessary: libvirt will automatically
pick one that's suitable for the chosen target type, and overriding that
value is generally not recommended.

If any of the attributes is not specified by the user, libvirt will choose a
value suitable for most users.

Most target types support configuring the guest-visible device address as
documented in the `Device Addresses`_ section; more specifically, acceptable address
types are ``isa`` (for ``isa-serial``), ``usb`` (for ``usb-serial``), ``pci``
(for ``pci-serial``) and ``spapr-vio`` (for ``spapr-vio-serial``). The
``system-serial`` and ``sclp-serial`` target types don't support specifying an
address.

For the relationship between serial ports and consoles, refer to the
`Relationship between serial ports and consoles`_ section.

Console
'''''''

::

   ...
   <devices>
     <!-- Serial console -->
     <console type='pty'>
       <source path='/dev/pts/2'/>
      <target type='serial' port='0'/>
     </console>
   </devices>
   ...

::

   ...
   <devices>
     <!-- KVM virtio console -->
     <console type='pty'>
       <source path='/dev/pts/5'/>
       <target type='virtio' port='0'/>
     </console>
   </devices>
   ...

The ``console`` element is used to represent interactive serial consoles.
Depending on the type of guest in use and the specifics of the configuration,
the ``console`` element might represent the same device as an existing
``serial`` element or a separate device.

A ``target`` subelement is supported and works the same way as with the
``serial`` element (See `Serial port`_ for details). Valid
values for the ``type`` attribute are: ``serial`` (described below); ``virtio``
(usable whenever VirtIO support is available); ``xen``, ``lxc`` and ``openvz``
(available when the corresponding hypervisor is in use). ``sclp`` and ``sclplm``
(usable for s390 and s390x QEMU guests) are supported for compatibility reasons
but should not be used for new guests: use the ``sclpconsole`` and
``sclplmconsole`` target models, respectively, with the ``serial`` element
instead.

Of the target types listed above, ``serial`` is special in that it doesn't
represents a separate device, but rather the same device as the first ``serial``
element. Due to this, there can only be a single ``console`` element with target
type ``serial`` per guest.

Virtio consoles are usually accessible as ``/dev/hvc[0-7]`` from inside the
guest; for more information, see
https://fedoraproject.org/wiki/Features/VirtioSerial. :since:`Since 0.8.3`

For the relationship between serial ports and consoles, refer to the
`Relationship between serial ports and consoles`_ section.

Relationship between serial ports and consoles
''''''''''''''''''''''''''''''''''''''''''''''

Due to historical reasons, the ``serial`` and ``console`` elements have
partially overlapping scopes.

In general, both elements are used to configure one or more serial consoles to
be used for interacting with the guest. The main difference between the two is
that ``serial`` is used for emulated, usually native, serial consoles, whereas
``console`` is used for paravirtualized ones.

Both emulated and paravirtualized serial consoles have advantages and
disadvantages:

-  emulated serial consoles are usually initialized much earlier than
   paravirtualized ones, so they can be used to control the bootloader and
   display both firmware and early boot messages;
-  on several platforms, there can only be a single emulated serial console per
   guest but paravirtualized consoles don't suffer from the same limitation.

A configuration such as:

::

   ...
   <devices>
     <console type='pty'>
       <target type='serial'/>
     </console>
     <console type='pty'>
       <target type='virtio'/>
     </console>
   </devices>
   ...

will work on any platform and will result in one emulated serial console for
early boot logging / interactive / recovery use, and one paravirtualized serial
console to be used eg. as a side channel. Most people will be fine with having
just the first ``console`` element in their configuration, but if a specific
configuration is desired then both elements should be specified.

Note that, due to the compatibility concerns mentioned earlier, all the
following configurations:

::

   ...
   <devices>
     <serial type='pty'/>
   </devices>
   ...

::

   ...
   <devices>
     <console type='pty'/>
   </devices>
   ...

::

   ...
   <devices>
     <serial type='pty'/>
     <console type='pty'/>
   </devices>
   ...

will be treated the same and will result in a single emulated serial console
being available to the guest.

Channel
'''''''

This represents a private communication channel between the host and the guest.

::

   ...
   <devices>
     <channel type='unix'>
       <source mode='bind' path='/tmp/guestfwd'/>
       <target type='guestfwd' address='10.0.2.1' port='4600'/>
     </channel>

     <!-- KVM virtio channel -->
     <channel type='pty'>
       <target type='virtio' name='arbitrary.virtio.serial.port.name'/>
     </channel>
     <channel type='unix'>
       <source mode='bind' path='/var/lib/libvirt/qemu/f16x86_64.agent'/>
       <target type='virtio' name='org.qemu.guest_agent.0' state='connected'/>
     </channel>
     <channel type='spicevmc'>
       <target type='virtio' name='com.redhat.spice.0'/>
     </channel>
   </devices>
   ...

This can be implemented in a variety of ways. The specific type of channel is
given in the ``type`` attribute of the ``target`` element. Different channel
types have different ``target`` attributes.

``guestfwd``
   TCP traffic sent by the guest to a given IP address and port is forwarded to
   the channel device on the host. The ``target`` element must have ``address``
   and ``port`` attributes. :since:`Since 0.7.3`
``virtio``
   Paravirtualized virtio channel. Channel is exposed in the guest under
   /dev/vport*, and if the optional element ``name`` is specified,
   /dev/virtio-ports/$name (for more info, please see
   https://fedoraproject.org/wiki/Features/VirtioSerial). The optional element
   ``address`` can tie the channel to a particular ``type='virtio-serial'``
   controller, as documented in the `Device Addresses`_ section. With qemu, if ``name``
   is "org.qemu.guest_agent.0", then libvirt can interact with a guest agent
   installed in the guest, for actions such as guest shutdown or file system
   quiescing. :since:`Since 0.7.7, guest agent interaction since 0.9.10`
   Moreover, :since:`since 1.0.6` it is possible to have source path auto
   generated for virtio unix channels. This is very useful in case of a qemu
   guest agent, where users don't usually care about the source path since it's
   libvirt who talks to the guest agent. In case users want to utilize this
   feature, they should leave ``<source>`` element out. :since:`Since 1.2.11`
   the active XML for a virtio channel may contain an optional ``state``
   attribute that reflects whether a process in the guest is active on the
   channel. This is an output-only attribute. Possible values for the ``state``
   attribute are ``connected`` and ``disconnected``.
``xen``
   Paravirtualized Xen channel. Channel is exposed in the guest as a Xen console
   but identified with a name. Setup and consumption of a Xen channel depends on
   software and configuration in the guest. See the xen-pv-channel(7) man page
   for more information. Channel source path semantics are the same as the virtio
   target type. The ``state`` attribute is not supported since Xen channels lack
   the necessary probing mechanism. :since:`Since 2.3.0`
``spicevmc``
   Paravirtualized SPICE channel. The domain must also have a SPICE server as a
   graphics device (See `Graphical framebuffers`_), at which point the host piggy-backs
   messages across the ``main`` channel. The ``target`` element must be present,
   with attribute ``type='virtio'``; an optional attribute ``name`` controls how
   the guest will have access to the channel, and defaults to
   ``name='com.redhat.spice.0'``. The optional ``address`` element can tie the
   channel to a particular ``type='virtio-serial'`` controller. :since:`Since
   0.8.8`
``qemu-vdagent``
   Paravirtualized qemu vdagent channel. This channel implements the SPICE
   vdagent protocol, but is handled internally by qemu and therefore does not
   require a SPICE graphics device. Like the spicevmc channel, the ``target``
   element must be present, with attribute ``type='virtio'``; an optional
   attribute ``name`` controls how the guest will have access to the channel,
   and defaults to ``name='com.redhat.spice.0'``. The optional ``address``
   element can tie the channel to a particular ``type='virtio-serial'``
   controller. Certain vdagent protocol features can by enabled or disabled
   using the ``source`` element.

   Copy & Paste functionality is set by the ``clipboard`` element. It is
   disabled by default, and can be enabled by setting the ``copypaste``
   property to ``yes``. This allows the guest's clipboard to be synchronized
   with the qemu clipboard manager. This can enable copy and paste between a
   guest and a client when using a VNC graphics device (See `Graphical framebuffers`_)
   (when using a VNC client that supports the copy/paste feature) or other
   graphics types that support the qemu clipboard manager.

   Mouse mode is set by the ``mouse`` element, setting its ``mode`` attribute
   to one of ``server`` or ``client``. If no mode is specified, the qemu
   default will be used (client mode).
   :since:`Since 8.4.0`


Host interface
^^^^^^^^^^^^^^

A character device presents itself to the host as one of the following types.

Domain logfile
''''''''''''''

This disables all input on the character device, and sends output into the
virtual machine's logfile

::

   ...
   <devices>
     <console type='stdio'>
       <target port='1'/>
     </console>
   </devices>
   ...

Device logfile
''''''''''''''

A file is opened and all data sent to the character device is written to the
file.

::

   ...
   <devices>
     <serial type="file">
       <source path="/var/log/vm/vm-serial.log"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

Virtual console
'''''''''''''''

Connects the character device to the graphical framebuffer in a virtual console.
This is typically accessed via a special hotkey sequence such as "ctrl+alt+3"

::

   ...
   <devices>
     <serial type='vc'>
       <target port="1"/>
     </serial>
   </devices>
   ...

Null device
'''''''''''

Connects the character device to the void. No data is ever provided to the
input. All data written is discarded.

::

   ...
   <devices>
     <serial type='null'>
       <target port="1"/>
     </serial>
   </devices>
   ...

Pseudo TTY
''''''''''

A Pseudo TTY is allocated using /dev/ptmx. A suitable client such as 'virsh
console' can connect to interact with the serial port locally.

::

   ...
   <devices>
     <serial type="pty">
       <source path="/dev/pts/3"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

NB special case if <console type='pty'>, then the TTY path is also duplicated as
an attribute tty='/dev/pts/3' on the top level <console> tag. This provides
compat with existing syntax for <console> tags.


Host device proxy
'''''''''''''''''

The character device is passed through to the underlying physical character
device. The device types must match, eg the emulated serial port should only be
connected to a host serial port - don't connect a serial port to a parallel
port.

::

   ...
   <devices>
     <serial type="dev">
       <source path="/dev/ttyS0"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

Named pipe
''''''''''

The character device writes output to a named pipe. See pipe(7) for more info.

::

   ...
   <devices>
     <serial type="pipe">
       <source path="/tmp/mypipe"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

TCP client/server
'''''''''''''''''

The character device acts as a TCP client connecting to a remote server.

::

   ...
   <devices>
     <serial type="tcp">
       <source mode="connect" host="0.0.0.0" service="2445"/>
       <protocol type="raw"/>
       <target port="1"/>
     </serial>
   </devices>
    ...

Or as a TCP server waiting for a client connection.

::

   ...
   <devices>
     <serial type="tcp">
       <source mode="bind" host="127.0.0.1" service="2445"/>
       <protocol type="raw"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

Alternatively you can use ``telnet`` instead of ``raw`` TCP in order to utilize
the telnet protocol for the connection.

:since:`Since 0.8.5,` some hypervisors support use of either ``telnets`` (secure
telnet) or ``tls`` (via secure sockets layer) as the transport protocol for
connections.

::

   ...
   <devices>
     <serial type="tcp">
       <source mode="connect" host="0.0.0.0" service="2445"/>
       <protocol type="telnet"/>
       <target port="1"/>
     </serial>
     ...
     <serial type="tcp">
       <source mode="bind" host="127.0.0.1" service="2445"/>
       <protocol type="telnet"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

:since:`Since 2.4.0,` the optional attribute ``tls`` can be used to control
whether a chardev TCP communication channel would utilize a hypervisor
configured TLS X.509 certificate environment in order to encrypt the data
channel. For the QEMU hypervisor, usage of a TLS environment can be controlled
on the host by the ``chardev_tls`` and ``chardev_tls_x509_cert_dir`` or
``default_tls_x509_cert_dir`` settings in the file /etc/libvirt/qemu.conf. If
``chardev_tls`` is enabled, then unless the ``tls`` attribute is set to "no",
libvirt will use the host configured TLS environment. If ``chardev_tls`` is
disabled, but the ``tls`` attribute is set to "yes", then libvirt will attempt
to use the host TLS environment if either the ``chardev_tls_x509_cert_dir`` or
``default_tls_x509_cert_dir`` TLS directory structure exists.

::

   ...
   <devices>
     <serial type="tcp">
       <source mode='connect' host="127.0.0.1" service="5555" tls="yes"/>
       <protocol type="raw"/>
       <target port="0"/>
     </serial>
   </devices>
   ...

UDP network console
'''''''''''''''''''

The character device acts as a UDP netconsole service, sending and receiving
packets. This is a lossy service.

::

   ...
   <devices>
     <serial type="udp">
       <source mode="bind" host="0.0.0.0" service="2445"/>
       <source mode="connect" host="0.0.0.0" service="2445"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

UNIX domain socket client/server
''''''''''''''''''''''''''''''''

The character device acts as a UNIX domain socket server, accepting connections
from local clients.

::

   ...
   <devices>
     <serial type="unix">
       <source mode="bind" path="/tmp/foo"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

Spice channel
'''''''''''''

The character device is accessible through spice connection under a channel name
specified in the ``channel`` attribute. :since:`Since 1.2.2`

Note: depending on the hypervisor, spiceports might (or might not) be enabled on
domains with or without spice graphics (See `Graphical framebuffers`_).

::

   ...
   <devices>
     <serial type="spiceport">
       <source channel="org.qemu.console.serial.0"/>
       <target port="1"/>
     </serial>
   </devices>
   ...

Nmdm device
'''''''''''

The nmdm device driver, available on FreeBSD, provides two tty devices connected
together by a virtual null modem cable. :since:`Since 1.2.4`

::

   ...
   <devices>
     <serial type="nmdm">
       <source master="/dev/nmdm0A" slave="/dev/nmdm0B"/>
     </serial>
   </devices>
   ...

The ``source`` element has these attributes:

``master``
   Master device of the pair, that is passed to the hypervisor. Device is
   specified by a fully qualified path.
``slave``
   Slave device of the pair, that is passed to the clients for connection to the
   guest console. Device is specified by a fully qualified path.

Sound devices
~~~~~~~~~~~~~

A virtual sound card can be attached to the host via the ``sound`` element.
:since:`Since 0.4.3`

::

   ...
   <devices>
     <sound model='es1370'/>
   </devices>
   ...

``sound``
   The ``sound`` element has one mandatory attribute, ``model``, which specifies
   what real sound device is emulated. Valid values are specific to the
   underlying hypervisor, though typical choices are ``sb16``, ``es1370``,
   ``pcspk``, ``ac97`` (:since:`Since 0.6.0`), ``ich6`` (:since:`Since 0.8.8`),
   ``ich9`` (:since:`Since 1.1.3`), ``usb`` (:since:`Since 1.2.8`) and ``ich7``
   (:since:`Since 6.7.0`, bhyve only).

:since:`Since 0.9.13` , a sound element with ``ich6`` or ``ich9`` models can have
optional sub-elements ``<codec>`` to attach various audio codecs to the audio
device. If not specified, a default codec will be attached to allow playback
and recording.

Valid values are:

-  ``duplex`` - advertise a line-in and a line-out
-  ``micro`` - advertise a speaker and a microphone
-  ``output`` - advertise a line-out :since:`Since 4.4.0`

::

   ...
   <devices>
     <sound model='ich6'>
       <codec type='micro'/>
     </sound>
   </devices>
   ...

:since:`Since 9.4.0` the ``usb`` sound device can be optionally switched into
multi-channel mode by using the ``multichannel`` attribute::

  <sound model='usb' multichannel='yes'/>

Each ``sound`` element has an optional sub-element ``<address>`` which can tie
the device to a particular PCI slot. See `Device Addresses`_.

A sound device could be optionally mapped to the specific host audio
backend using the ``<audio>`` sub-element:

::

   ...
   <devices>
     <sound model='ich7'>
        <audio id='1'>
     </sound>
   </devices>
   ...

Where ``1`` is an id of the audio device (See `Audio backends`_). If no
ID is specified, then the default audio backend will be used.
:since:`Since 6.7.0, bhyve; Since 7.2.0, qemu`.


Audio backends
~~~~~~~~~~~~~~

A virtual audio device corresponds to a host audio backend that is mapped
to the guest sound device.

``type``
   The required ``type`` attribute specifies audio backend type.
   Currently, the supported values are ``none``, ``alsa``, ``coreaudio``,
   ``dbus``, ``jack``, ``oss``, ``pulseaudio``, ``sdl``, ``spice``, ``file``.

``id``
   Integer id of the audio device. Must be greater than 0.

``timerPeriod``
   Timer period in microseconds. Must be greater than 0. If omitted,
   the lowest possible period is used.

All the backends support child element for configuring input and
output properties

::

   ...
   <devices>
     <audio id='1' type='pulseaudio' timerPeriod='40'>
       <input mixingEngine='yes' fixedSettings='yes' voices='1' bufferLength='100'>
         <settings frequency='44100' channels='2' format='s16'/>
       </input>
       <output mixingEngine='yes' fixedSettings='yes' voices='2' bufferLength='100'>
         <settings frequency='22050' channels='4' format='f32'/>
       </output>
     </audio>
   </devices>
   ...

The input and output elements support the same set of attributes and
elements

* ``mixingEngine``

  Control whether the host mixing engine is used to convert between
  different audio formats and sampling rates. When the mixing engine
  is disabled it is possible to make use of improved audio formats
  such as 5.1/7.1. If not specified, a hypervisor default applies.

* ``fixedSettings``

  Control whether the mixing engine can dynamically choose settings
  to minimize format conversion. This is only valid when the
  mixing engine is explicitly enabled.

* ``voices``

  The number of voices voices to use, usually defaults to 1

* ``bufferLength``

  The length of the audio buffer in microseconds. Default is
  backend specific.

The ``<input>`` and ``<output>`` elements may also permit backend
specific options.

When fixed settings are enabled, the ``<settings>`` child element
is permitted with the following attributes.

* ``frequency``

  The frequency in HZ, usually defaulting to 44100

* ``channels``

  The number of channels, usually defaulting to 2. The permitted
  max number of channels is hypervisor specific.

* ``format``

  The audio format, one of ``s8``, ``u8``, ``s16``, ``u16``,
  ``s32``, ``u32``, ``f32``. The default is hypervisor specific.

Note:
If no ``<audio/>`` element is defined, and the ``graphics`` element is set to
either ``vnc`` or ``sdl``, the libvirtd or virtqemud process will honor the
following environment variables:

* ``SDL_AUDIODRIVER``

  Valid values are ``pulseaudio``, ``esd``, ``alsa`` or ``arts``.

* ``QEMU_AUDIO_DRV``

  Valid values are ``pa``, ``none``, ``alsa``, ``coreaudio``, ``jack``, ``oss``,
  ``sdl``, ``spice`` or ``wav``.

None audio backend
^^^^^^^^^^^^^^^^^^

The ``none`` audio backend is a dummy backend that does not connect to
any host audio framework. It still allows a remote desktop server
like VNC to send and receive audio though. This is the default backend
when VNC graphics are enabled in QEMU.

:since:`Since 7.2.0, qemu`

ALSA audio backend
^^^^^^^^^^^^^^^^^^

The ``alsa`` audio type uses the ALSA host audio device framework.

The following additional attributes are permitted on the ``<input>``
and ``<output>`` elements

* ``dev``

  Path to the host device node to connect the backend to. A hypervisor
  specific default applies if not specified.

::

   <audio id="1" type="alsa">
     <input dev="/dev/dsp0"/>
     <output dev="/dev/dsp1"/>
   </audio>

:since:`Since 7.2.0, qemu`

Coreaudio audio backend
^^^^^^^^^^^^^^^^^^^^^^^

The ``coreaudio`` audio backend delegates to a CoreAudio host audio framework
for input and output on macOS.

The following additional attributes are permitted on the ``<input>``
and ``<output>`` elements

* ``bufferCount``

  The number of buffers. It is recommended to set the ``bufferLength``
  attribute at the same time.

::

   <audio id="1" type="coreaudio">
     <input bufferCount="50"/>
     <output bufferCount="42"/>
   </audio>

:since:`Since 7.2.0, qemu`

D-Bus audio backend
^^^^^^^^^^^^^^^^^^^

The ``dbus`` audio backend does not connect to any host audio framework. It
exports a D-Bus interface when associated with a D-Bus display.

:since:`Since 8.4.0, qemu`

Jack audio backend
^^^^^^^^^^^^^^^^^^

The ``jack`` audio backend delegates to a Jack daemon for audio input
and output.

The following additional attributes are permitted on the ``<input>``
and ``<output>`` elements

* ``serverName``

  Select the Jack server instance to connect to.

* ``clientName``

  The client name to identify as. The server may modify this to
  ensure uniqueness unless ``exactName`` is enabled

* ``connectPorts``

  A regular expression of Jack client port names to monitor and
  connect to.

* ``exactName``

  Use the exact ``clientName`` requested

::

   <audio id="1" type="jack">
     <input serverName="fish" clientName="food" connectPorts="system:capture_[13]" exactName="yes"/>
     <output serverName="fish" clientName="food" connectPorts="system:playback_[13]" exactName="yes"/>
   </audio>

:since:`Since 7.2.0, qemu`

OSS audio backend
^^^^^^^^^^^^^^^^^

The ``oss`` audio type uses the OSS host audio device framework.

The following additional attributes are permitted on the ``<audio>``
element

* ``tryMMap``

  Attempt to use mmap for data transfer

* ``exclusive``

  Enforce exclusive access to the host device

* ``dspPolicy``

  Set the timing policy of the device, values between -1 and 10.
  Smaller numbers result in lower latency but higher CPU usage.
  A negative value requests use of fragment mode.

The following additional attributes are permitted on the ``<input>``
and ``<output>`` elements

* ``dev``

  Path to the host device node to connect the backend to. A hypervisor
  specific default applies if not specified.

* ``bufferCount``

  The number of buffers. It is recommended to set the ``bufferLength``
  attribute at the same time.

* ``tryPoll``

  Attempt to use polling mode

::

   <audio type='oss' id='1' tryMMap='yes' exclusive='yes' dspPolicy='4'>
     <input dev='/dev/dsp0' bufferCount='40' tryPoll='yes'/>
     <output dev='/dev/dsp0' bufferCount='40' tryPoll='yes'/>
   </audio>

:since:`Since 6.7.0, bhyve; Since 7.2.0, qemu`

PulseAudio audio backend
^^^^^^^^^^^^^^^^^^^^^^^^

The ``pulseaudio`` audio backend delegates to a PulseAudio daemon audio input
and output.

The following additional attributes are permitted on the ``<audio>``
element

* ``serverName``

  Hostname of the PulseAudio server

The following additional attributes are permitted on the ``<input>``
and ``<output>`` elements

* ``name``

  The sink/source name to use

* ``streamName``

  The name to identify the stream associated with the VM

* ``latency``

  Desired latency for the server to target in microseconds

::

   <audio id="1" type="pulseaudio" serverName="acme.example.org">
     <input name="fish" streamName="food" latency="100"/>
     <output name="fish" streamName="food" latency="200"/>
   </audio>

:since:`Since 7.2.0, qemu`

SDL audio backend
^^^^^^^^^^^^^^^^^

The ``sdl`` audio backend delegates to the SDL library for audio input
and output.

The following additional attributes are permitted on the ``<audio>``
element

* ``driver``

  SDL audio driver. The ``name`` attribute specifies SDL driver name,
  one of ``esd``, ``alsa``, ``arts``, ``pulseaudio``.

The following additional attributes are permitted on the ``<input>``
and ``<output>`` elements

* ``bufferCount``

  The number of buffers. It is recommended to set the ``bufferLength``
  attribute at the same time.

::

   <audio type='sdl' id='1' driver='pulseaudio'>
     <input bufferCount='40'/>
     <output bufferCount='40'/>
   </audio>

:since:`Since 7.2.0, qemu`

Spice audio backend
^^^^^^^^^^^^^^^^^^^

The ``spice`` audio backend is similar to the ``none`` backend in that
it does not connect to any host audio framework. It exclusively
allows a SPICE server to send and receive audio. This is the default
backend when SPICE graphics are enabled in QEMU.

::

   <audio type='spice' id='1'/>

:since:`Since 7.2.0, qemu`

File audio backend
^^^^^^^^^^^^^^^^^^

The ``file`` audio backend is an output only driver which records
audio to a file. The file format is implementation defined, and
defaults to ``WAV`` with QEMU.

::

   <audio id="1" type="file" path="audio.wav"/>

:since:`Since 7.2.0, qemu`

Watchdog devices
~~~~~~~~~~~~~~~~

A virtual hardware watchdog device can be added to the guest via the
``watchdog`` element. :since:`Since 0.7.3, QEMU and KVM only`

The watchdog device requires an additional driver and management daemon in the
guest. Just enabling the watchdog in the libvirt configuration does not do
anything useful on its own.

Currently libvirt does not support notification when the watchdog fires. This
feature is planned for a future version of libvirt.

Having multiple watchdogs is usually not something very common, but be aware
that this might happen, for example, when an implicit watchdog device is added
as part of another device.  For example the iTCO watchdog being part of the ich9
southbridge, which is used with the q35 machine type. :since:`Since 9.1.0`

::

   ...
   <devices>
     <watchdog model='i6300esb'/>
   </devices>
   ...

::

     ...
     <devices>
       <watchdog model='i6300esb' action='poweroff'/>
     </devices>
   </domain>

``model``
   The required ``model`` attribute specifies what real watchdog device is
   emulated. Valid values are specific to the underlying hypervisor.

   QEMU and KVM support:

   -  'itco' - included by default with q35 machine type :since:`Since 9.1.0`
   -  'i6300esb' - the recommended device, emulating a PCI Intel 6300ESB
   -  'ib700' - emulating an ISA iBase IB700
   -  'diag288' - emulating an S390 DIAG288 device :since:`Since 1.2.17`

``action``
   The optional ``action`` attribute describes what action to take when the
   watchdog expires. Valid values are specific to the underlying hypervisor.

   QEMU and KVM support:

   -  'reset' - default, forcefully reset the guest
   -  'shutdown' - gracefully shutdown the guest (not recommended)
   -  'poweroff' - forcefully power off the guest
   -  'pause' - pause the guest
   -  'none' - do nothing
   -  'dump' - automatically dump the guest :since:`Since 0.8.7`
   -  'inject-nmi' - inject a non-maskable interrupt into the guest
      :since:`Since 1.2.17`

   Note 1: the 'shutdown' action requires that the guest is responsive to ACPI
   signals. In the sort of situations where the watchdog has expired, guests are
   usually unable to respond to ACPI signals. Therefore using 'shutdown' is not
   recommended.

   Note 2: the directory to save dump files can be configured by
   ``auto_dump_path`` in file /etc/libvirt/qemu.conf.

Memory balloon device
~~~~~~~~~~~~~~~~~~~~~

A virtual memory balloon device is added to all Xen and KVM/QEMU guests. It will
be seen as ``memballoon`` element. It will be automatically added when
appropriate, so there is no need to explicitly add this element in the guest XML
unless a specific PCI slot needs to be assigned. :since:`Since 0.8.3, Xen, QEMU
and KVM only` Additionally, :since:`since 0.8.4` , if the memballoon device
needs to be explicitly disabled, ``model='none'`` may be used.

Example: automatically added device with KVM

::

   ...
   <devices>
     <memballoon model='virtio'/>
   </devices>
   ...

Example: manually added device with static PCI slot 2 requested

::

     ...
     <devices>
       <memballoon model='virtio'>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
         <stats period='10'/>
         <driver iommu='on' ats='on'/>
       </memballoon>
     </devices>
   </domain>

``model``
   The required ``model`` attribute specifies what type of balloon device is
   provided. Valid values are specific to the virtualization platform

   -  'virtio' - default with QEMU/KVM
   -  'virtio-transitional' :since:`Since 5.2.0`
   -  'virtio-non-transitional' :since:`Since 5.2.0`
   -  'xen' - default with Xen

   See `Virtio transitional devices`_ for more details.

``autodeflate``
   The optional ``autodeflate`` attribute allows to enable/disable (values
   "on"/"off", respectively) the ability of the QEMU virtio memory balloon to
   release some memory at the last moment before a guest's process get killed by
   Out of Memory killer. :since:`Since 1.3.1, QEMU and KVM only`

``freePageReporting``
   The optional ``freePageReporting`` attribute allows to enable/disable
   ("on"/"off", respectively) the ability of the QEMU virtio memory balloon to
   return unused pages back to the hypervisor to be used by other guests or
   processes. Please note that despite its name it has no effect on free memory
   as reported by ``virDomainMemoryStats()`` and/or ``virsh dommemstat``.
   :since:`Since 6.9.0, QEMU and KVM only`

``period``
   The optional ``period`` allows the QEMU virtio memory balloon driver to
   provide statistics through the ``virsh dommemstat           [domain]``
   command. By default, collection is not enabled. In order to enable, use the
   ``virsh dommemstat [domain] --period           [number]`` command or
   ``virsh edit`` command to add the option to the XML definition. The
   ``virsh dommemstat`` will accept the options ``--live``, ``--current``, or
   ``--config``. If an option is not provided, the change for a running domain
   will only be made to the active guest. If the QEMU driver is not at the right
   revision, the attempt to set the period will fail. Large values (e.g. many
   years) might be ignored. :since:`Since 1.1.1, requires QEMU 1.5`

``driver``
   For model ``virtio`` memballoon, `Virtio-related options`_ can also be set.
   ( :since:`Since 3.5.0` )

Random number generator device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The virtual random number generator device allows the host to pass through
entropy to guest operating systems. :since:`Since 1.0.3`

Example: usage of the RNG device:

::

   ...
   <devices>
     <rng model='virtio'>
       <rate period="2000" bytes="1234"/>
       <backend model='random'>/dev/random</backend>
       <!-- OR -->
       <backend model='egd' type='udp'>
         <source mode='bind' service='1234'/>
         <source mode='connect' host='1.2.3.4' service='1234'/>
       </backend>
       <!-- OR -->
       <backend model='builtin'/>
     </rng>
   </devices>
   ...

``model``
   The required ``model`` attribute specifies what type of RNG device is
   provided. Valid values are specific to the virtualization platform:

   -  'virtio' - supported by qemu and virtio-rng kernel module
   -  'virtio-transitional' :since:`Since 5.2.0`
   -  'virtio-non-transitional' :since:`Since 5.2.0`

   See `Virtio transitional devices`_ for more details.

``rate``
   The optional ``rate`` element allows limiting the rate at which entropy can
   be consumed from the source. The mandatory attribute ``bytes`` specifies how
   many bytes are permitted to be consumed per period. An optional ``period``
   attribute specifies the duration of a period in milliseconds; if omitted, the
   period is taken as 1000 milliseconds (1 second). :since:`Since 1.0.4`

``backend``
   The ``backend`` element specifies the source of entropy to be used for the
   domain. The source model is configured using the ``model`` attribute.
   Supported source models are:

   ``random``
      This backend type expects a non-blocking character device as input. The
      file name is specified as contents of the ``backend`` element.
      :since:`Since 1.3.4` any path is accepted. Before that ``/dev/random`` and
      ``/dev/hwrng`` were the only accepted paths. When no file name is
      specified, the hypervisor default is used. For QEMU, the default is
      ``/dev/random``. However, the recommended source of entropy is
      ``/dev/urandom`` (as it doesn't have the limitations of ``/dev/random``).

   ``egd``
      This backend connects to a source using the EGD protocol. The source is
      specified as a character device. Refer to the `Host interface`_ for more
      information.

   ``builtin``
      This backend uses qemu builtin random generator, which uses
      ``getrandom()`` syscall as the source of entropy. ( :since:`Since 6.1.0
      and QEMU 4.2` )

``driver``
   The subelement ``driver`` can be used to tune the device:

   virtio options
      `Virtio-related options`_ can also be set. ( :since:`Since 3.5.0` )


TPM device
~~~~~~~~~~

The TPM device enables a QEMU guest to have access to TPM functionality. The TPM
device may either be a TPM 1.2 or a TPM 2.0.

The TPM passthrough device type provides access to the host's TPM for one QEMU
guest. No other software may be using the TPM device, typically /dev/tpm0, at
the time the QEMU guest is started. :since:`'passthrough' since 1.0.5`

Example: usage of the TPM passthrough device

::

   ...
   <devices>
     <tpm model='tpm-tis'>
       <backend type='passthrough'>
         <device path='/dev/tpm0'/>
       </backend>
     </tpm>
   </devices>
   ...

The emulator device type gives access to a TPM emulator providing TPM
functionality for each VM. QEMU talks to it over a Unix socket. With the
emulator device type each guest gets its own private TPM. :since:`'emulator'
since 4.5.0` The state of the TPM emulator can be encrypted by providing an
``encryption`` element. :since:`'encryption' since 5.6.0`

Example: usage of the TPM Emulator

::

     ...
     <devices>
       <tpm model='tpm-tis'>
         <backend type='emulator' version='2.0'>
           <encryption secret='6dd3e4a5-1d76-44ce-961f-f119f5aad935'/>
           <active_pcr_banks>
               <sha256/>
           </active_pcr_banks>
         </backend>
       </tpm>
     </devices>
     ...

``model``
   The ``model`` attribute specifies what device model QEMU provides to the
   guest. If no model name is provided, ``tpm-tis`` will automatically be chosen
   for non-PPC64 architectures. :since:`Since 4.4.0` , another available choice
   is the ``tpm-crb``, which should only be used when the backend device is a
   TPM 2.0. :since:`Since 6.1.0` , pSeries guests on PPC64 are supported and the
   default is ``tpm-spapr``. :since:`Since 6.5.0` , a new model called
   ``spapr-tpm-proxy`` was added for pSeries guests. This model only works with
   the ``passthrough`` backend. It creates a TPM Proxy device that communicates
   with an existing TPM Resource Manager in the host, for example
   ``/dev/tpmrm0``, enabling the guest to run in secure virtual machine mode
   with the help of an Ultravisor. Adding a TPM Proxy to a pSeries guest brings
   no security benefits unless the guest is running on a PPC64 host that has an
   Ultravisor and a TPM Resource Manager. Only one TPM Proxy device is allowed
   per guest, but a TPM Proxy device can be added together with other TPM
   devices.

``backend``
   The ``backend`` element specifies the type of TPM device. The following types
   are supported:

   ``passthrough``
      Use the host's TPM or TPM Resource Manager device.

      This backend type requires exclusive access to a TPM device on the host.
      An example for such a device is /dev/tpm0. The fully qualified file name
      is specified by path attribute of the ``source`` element. If no file name
      is specified then /dev/tpm0 is automatically used. :since:`Since 6.5.0` ,
      when choosing the ``spapr-tpm-proxy`` model, the file name specified is
      expected to be a TPM Resource Manager device, e.g. ``/dev/tpmrm0``.

   ``emulator``
      For this backend type the 'swtpm' TPM Emulator must be installed on the
      host. Libvirt will automatically start an independent TPM emulator for
      each QEMU guest requesting access to it.

``version``
   The ``version`` attribute indicates the version of the TPM. This attribute
   only works with the ``emulator`` backend. The following versions are
   supported:

   -  '1.2' : creates a TPM 1.2
   -  '2.0' : creates a TPM 2.0

   The default version used depends on the combination of hypervisor, guest
   architecture, TPM model and backend.

``persistent_state``
   The ``persistent_state`` attribute indicates whether 'swtpm' TPM state is
   kept or not when a transient domain is powered off or undefined. This
   option can be used for preserving TPM state. By default the value is ``no``.
   This attribute only works with the ``emulator`` backend. The accepted values
   are ``yes`` and ``no``. :since:`Since 7.0.0`

``active_pcr_banks``
   The ``active_pcr_banks`` node is used to define which of the PCR banks
   of a TPM 2.0 to activate. Valid names are for example sha1, sha256, sha384,
   and sha512. If this node is provided, the set of PCR banks are activated
   before every start of a VM and this step is logged in the swtpm's log.
   If this node is removed or omitted then libvirt will not modify the
   active PCR banks upon VM start but leave them at their last configuration.
   This attribute requires that swtpm_setup v0.7 or later is installed
   and may not have any effect otherwise. The selection of PCR banks only works
   with the ``emulator`` backend. :since:`Since 7.10.0`

``encryption``
   The ``encryption`` element allows the state of a TPM emulator to be
   encrypted. The ``secret`` must reference a secret object that holds the
   passphrase from which the encryption key will be derived.

NVRAM device
~~~~~~~~~~~~

nvram device is always added to pSeries guest on PPC64, and its address is
allowed to be changed. Element ``nvram`` (only valid for pSeries guest,
:since:`since 1.0.5` ) is provided to enable the address setting.

Example: usage of NVRAM configuration

::

   ...
   <devices>
     <nvram>
       <address type='spapr-vio' reg='0x00003000'/>
     </nvram>
   </devices>
   ...

``spapr-vio``
   VIO device address type, only valid for PPC64.

``reg``
   Device address

panic device
~~~~~~~~~~~~

panic device enables libvirt to receive panic notification from a QEMU guest.
:since:`Since 1.2.1, QEMU and KVM only`

This feature is always enabled for:

-  pSeries guests, since it's implemented by the guest firmware
-  S390 guests, since it's an integral part of the S390 architecture

For the guest types listed above, libvirt automatically adds a ``panic`` element
to the domain XML.

Example: usage of panic configuration

::

   ...
   <devices>
     <panic model='hyperv'/>
     <panic model='isa'>
       <address type='isa' iobase='0x505'/>
     </panic>
   </devices>
   ...

``model``
   The optional ``model`` attribute specifies what type of panic device is
   provided. The panic model used when this attribute is missing depends on the
   hypervisor and guest arch.

   -  'isa' - for ISA pvpanic device
   -  'pseries' - default and valid only for pSeries guests.
   -  'hyperv' - for Hyper-V crash CPU feature. :since:`Since 1.3.0, QEMU and
      KVM only`
   -  's390' - default for S390 guests. :since:`Since 1.3.5`
   -  'pvpanic' - for PCI pvpanic device :since:`Since 9.1.0, QEMU only`

``address``
   address of panic. The default ioport is 0x505. Most users don't need to
   specify an address, and doing so is forbidden altogether for s390, pseries
   and hyperv models.

Shared memory device
~~~~~~~~~~~~~~~~~~~~

A shared memory device allows to share a memory region between different virtual
machines and the host. :since:`Since 1.2.10, QEMU and KVM only`

::

   ...
   <devices>
     <shmem name='my_shmem0' role='peer'>
       <model type='ivshmem-plain'/>
       <size unit='M'>4</size>
     </shmem>
     <shmem name='shmem_server'>
       <model type='ivshmem-doorbell'/>
       <size unit='M'>2</size>
       <server path='/tmp/socket-shmem'/>
       <msi vectors='32' ioeventfd='on'/>
     </shmem>
   </devices>
   ...

``shmem``
   The ``shmem`` element has one mandatory attribute, ``name`` to identify the
   shared memory. This attribute cannot be directory specific to ``.`` or ``..``
   as well as it cannot involve path separator ``/``.

   The optional ``role`` (:since:`since 6.6.0`) attribute specifies the shared
   memory is migratable or not. The value can be either "master" or "peer", the
   former will mean that upon migration, the data in the shared memory is
   migrated with the domain. There should be only one "master" per shared
   memory object. Migration with "peer" role is disabled. If migration of such
   domain is required, the shmem device needs to be unplugged before migration
   and plugged in at the destination upon successful migration. If the role not
   specified, the hypervisor default is used. This attribute is currently
   available only for ``model`` type ``ivshmem-plain`` and
   ``ivshmem-doorbell``.
``model``
   Attribute ``type`` of the optional element ``model`` specifies the model of
   the underlying device providing the ``shmem`` device. The models currently
   supported are ``ivshmem`` (supports both server and server-less shmem, but is
   deprecated by newer QEMU in favour of the -plain and -doorbell variants),
   ``ivshmem-plain`` (only for server-less shmem) and ``ivshmem-doorbell`` (only
   for shmem with the server).
``size``
   The optional ``size`` element specifies the size of the shared memory. This
   must be power of 2 and greater than or equal to 1 MiB.
``server``
   The optional ``server`` element can be used to configure a server socket the
   device is supposed to connect to. The optional ``path`` attribute specifies
   the absolute path to the unix socket and defaults to
   ``/var/lib/libvirt/shmem/$shmem-$name-sock``.
``msi``
   The optional ``msi`` element enables/disables (values "on"/"off",
   respectively) MSI interrupts. This option can currently be used only together
   with the ``server`` element. The ``vectors`` attribute can be used to specify
   the number of interrupt vectors. The ``ioeventd`` attribute enables/disables
   (values "on"/"off", respectively) ioeventfd.


Memory devices
~~~~~~~~~~~~~~

In addition to the initial memory assigned to the guest, memory devices allow
additional memory to be assigned to the guest in the form of memory modules. A
memory device can be hot-plugged or hot-unplugged depending on the guests'
memory resource needs. Some hypervisors may require NUMA configured for the
guest.

Example: usage of the memory devices

::

   ...
   <devices>
     <memory model='dimm' access='private' discard='yes'>
       <target>
         <size unit='KiB'>524287</size>
         <node>0</node>
       </target>
     </memory>
     <memory model='dimm'>
       <source>
         <pagesize unit='KiB'>2048</pagesize>
         <nodemask>1-3</nodemask>
       </source>
       <target>
         <size unit='KiB'>524287</size>
         <node>1</node>
       </target>
     </memory>
     <memory model='nvdimm'>
       <uuid>9066901e-c90a-46ad-8b55-c18868cf92ae</uuid>
       <source>
         <path>/tmp/nvdimm</path>
       </source>
       <target>
         <size unit='KiB'>524288</size>
         <node>1</node>
         <label>
           <size unit='KiB'>128</size>
         </label>
         <readonly/>
       </target>
     </memory>
     <memory model='nvdimm' access='shared'>
       <uuid>e39080c8-7f99-4b12-9c43-d80014e977b8</uuid>
       <source>
         <path>/dev/dax0.0</path>
         <alignsize unit='KiB'>2048</alignsize>
         <pmem/>
       </source>
       <target>
         <size unit='KiB'>524288</size>
         <node>1</node>
         <label>
           <size unit='KiB'>128</size>
         </label>
       </target>
     </memory>
     <memory model='virtio-pmem' access='shared'>
       <source>
         <path>/tmp/virtio_pmem</path>
       </source>
       <target>
         <size unit='KiB'>524288</size>
         <address base='0x140000000'/>
       </target>
     </memory>
     <memory model='virtio-mem'>
       <source>
         <nodemask>1-3</nodemask>
         <pagesize unit='KiB'>2048</pagesize>
       </source>
       <target>
         <size unit='KiB'>2097152</size>
         <node>0</node>
         <block unit='KiB'>2048</block>
         <requested unit='KiB'>1048576</requested>
         <current unit='KiB'>524288</current>
         <address base='0x150000000'/>
       </target>
     </memory>
     <memory model='sgx-epc'>
       <source>
         <nodemask>0-1</nodemask>
       </source>
       <target>
         <size unit='KiB'>16384</size>
         <node>0</node>
       </target>
     </memory>
     <memory model='sgx-epc'>
       <target>
         <size unit='KiB'>16384</size>
       </target>
     </memory>
   </devices>
   ...

``model``
   Provide ``dimm`` to add a virtual DIMM module to the guest. :since:`Since
   1.2.14` Provide ``nvdimm`` model that adds a Non-Volatile DIMM module.
   :since:`Since 3.2.0` Provide ``virtio-pmem`` model to add a paravirtualized
   persistent memory device. :since:`Since 7.1.0` Provide ``virtio-mem`` model
   to add paravirtualized memory device. :since:`Since 7.9.0` Provide
   ``sgx-epc`` model to add a SGX enclave page cache (EPC) memory to the guest.
   :since:`Since 8.10.0 and QEMU 7.0.0`

``access``
   An optional attribute ``access`` ( :since:`since 3.2.0` ) that provides
   capability to fine tune mapping of the memory on per module basis. Values are
   the same as `Memory Backing`_: ``shared`` and
   ``private``. For ``nvdimm`` model, if using real NVDIMM DAX device as
   backend, ``shared`` is required. For ``virtio-pmem`` model ``shared`` is
   required.

``discard``
   An optional attribute ``discard`` ( :since:`since 4.4.0` ) that provides
   capability to fine tune discard of data on per module basis. Accepted values
   are ``yes`` and ``no``. The feature is described here: `Memory Backing`_.
   This attribute is allowed only for ``model='dimm'``.

``uuid``
   For pSeries guests, an uuid can be set to identify the nvdimm module. If
   absent, libvirt will generate an uuid automatically. This attribute is
   allowed only for ``model='nvdimm'`` for pSeries guests. :since:`Since 6.2.0`

``source``
   For model ``dimm`` and model ``virtio-mem`` this element is optional and
   allows to fine tune the source of the memory used for the given memory
   device. If the element is not provided defaults configured via ``numatune``
   are used. If the element is provided, then the following optional elements
   can be provided:

   ``pagesize``
      This element can be used to override the default host page size used for
      backing the memory device. The configured value must correspond to a page
      size supported by the host.

   ``nodemask``
      This element can be used to override the default set of NUMA nodes where
      the memory would be allocated.

   For model ``nvdimm`` the ``source`` element is mandatory. The mandatory
   child element ``path`` represents a path in the host that backs the nvdimm
   module in the guest. The following optional elements may be used:

   ``alignsize``
      The ``alignsize`` element defines the page size alignment used to mmap the
      address range for the backend ``path``. If not supplied the host page size
      is used. For example, to mmap a real NVDIMM device a 2M-aligned page may
      be required, and host page size is 4KB, then we need to set this element
      to 2MB. :since:`Since 5.0.0`

   ``pmem``
      If persistent memory is supported and enabled by the hypervisor in order
      to guarantee the persistence of writes to the vNVDIMM backend, then use
      the ``pmem`` element in order to utilize the feature. :since:`Since 5.0.0`

   For model ``virtio-pmem`` the ``source`` element is mandatory. The following
   optional elements may be used:

   ``path``
     Represents a path in the host that backs the virtio memory module in the
     guest. It is mandatory.

   For model ``sgx-epc`` this element is optional. The following optional
   elements may be used:

   ``nodemask``
      This element can be used to override the default set of NUMA nodes where
      the memory would be allocated. :since:`Since 8.10.0 and QEMU 7.0.0`

``target``
   The mandatory ``target`` element configures the placement and sizing of the
   added memory from the perspective of the guest.

   The mandatory ``size`` subelement configures the size of the added memory as
   a scaled integer. For ``virtio-mem`` this represents the maximum possible
   size exposed to the guest.

   The ``node`` subelement configures the guest NUMA node to attach the memory
   to. The element shall be used only if the guest has NUMA nodes configured.

   The following optional elements may be used:

   ``label``
      For NVDIMM type devices one can use ``label`` and its subelement ``size``
      to configure the size of namespaces label storage within the NVDIMM
      module. The ``size`` element has usual meaning described in the
      `Memory Allocation`_ section. ``label`` is mandatory for pSeries
      guests and optional for all other architectures. For QEMU domains the
      following restrictions apply:

      #. the minimum label size is 128KiB,
      #. the remaining size (total-size - label-size), also called guest area,
         will be aligned to 4KiB as default. For pSeries guests, the guest area
         will be aligned down to 256MiB, and the minimum size of the guest area
         must be at least 256MiB.

   ``readonly``
      The ``readonly`` element is used to mark the vNVDIMM as read-only. Only
      the real NVDIMM device backend can guarantee the guest write persistence,
      so other backend types should use the ``readonly`` element. :since:`Since
      5.0.0`

   ``block``
     For ``virtio-mem`` only.
     The size of an individual block, granularity of division of memory block.
     Must be power of two and at least equal to size of a transparent hugepage
     (2MiB on x84_64). The default is hypervisor dependent.

   ``requested``
     For ``virtio-mem`` only.
     The total size exposed to the guest. Must respect ``block`` granularity
     and be smaller than or equal to ``size``.

   ``current``
     Active XML for ``virtio-mem`` model may contain ``current`` element that
     reflects the current size of the corresponding virtio memory device. The
     element is formatted into live XML and never parsed, i.e. it is
     output-only element.

   ``address``
     For ``virtio-mem`` and ``virtio-pmem`` only.
     The physical address in memory, where device is mapped. :since:`Since
     9.4.0`


IOMMU devices
~~~~~~~~~~~~~

The ``iommu`` element can be used to add an IOMMU device. :since:`Since 2.1.0`

Example:

::

   ...
   <devices>
     <iommu model='intel'>
       <driver intremap='on'/>
     </iommu>
   </devices>
   ...

``model``
   Supported values are ``intel`` (for Q35 guests) ``smmuv3``
   (:since:`since 5.5.0`, for ARM virt guests), and ``virtio``
   (:since:`since 8.3.0`, for Q35 and ARM virt guests).

``driver``
   The ``driver`` subelement can be used to configure additional options, some
   of which might only be available for certain IOMMU models:

   ``intremap``
      The ``intremap`` attribute with possible values ``on`` and ``off`` can be
      used to turn on interrupt remapping, a part of the VT-d functionality.
      Currently this requires split I/O APIC (``<ioapic driver='qemu'/>``).
      :since:`Since 3.4.0` (QEMU/KVM only)

   ``caching_mode``
      The ``caching_mode`` attribute with possible values ``on`` and ``off`` can
      be used to turn on the VT-d caching mode (useful for assigned devices).
      :since:`Since 3.4.0` (QEMU/KVM only)

   ``eim``
      The ``eim`` attribute (with possible values ``on`` and ``off``) can be
      used to configure Extended Interrupt Mode. A q35 domain with split I/O
      APIC (as described in `Hypervisor features`_), and
      both interrupt remapping and EIM turned on for the IOMMU, will be able to
      use more than 255 vCPUs. :since:`Since 3.4.0` (QEMU/KVM only)

   ``iotlb``
      The ``iotlb`` attribute with possible values ``on`` and ``off`` can be
      used to turn on the IOTLB used to cache address translation requests from
      devices. :since:`Since 3.5.0` (QEMU/KVM only)

   ``aw_bits``
      The ``aw_bits`` attribute can be used to set the address width to allow
      mapping larger iova addresses in the guest. :since:`Since 6.5.0` (QEMU/KVM
      only)

The ``virtio`` IOMMU devices can further have ``address`` element as described
in `Device addresses`_ (address has to by type of ``pci``).


Vsock
~~~~~

A vsock host/guest interface. The ``model`` attribute defaults to ``virtio``.
:since:`Since 5.2.0` ``model`` can also be 'virtio-transitional' and
'virtio-non-transitional', see `Virtio transitional devices`_  for more details.
The optional attribute ``address`` of the ``cid`` element specifies the CID
assigned to the guest. If the attribute ``auto`` is set to ``yes``, libvirt will
assign a free CID automatically on domain startup. :since:`Since 4.4.0`
The optional ``driver`` element allows to specify virtio options, see
`Virtio-related options`_  for more details. :since:`Since 7.1.0`

::

   ...
   <devices>
     <vsock model='virtio'>
       <cid auto='no' address='3'/>
     </vsock>
   </devices>
   ...


Crypto
~~~~~~

A crypto device. The ``model`` attribute defaults to ``virtio``.
:since:`Since v9.0.0` ``model`` supports ``virtio`` only. The ``type`` attribute
defaults to ``qemu``. :since:`Since v9.0.0` ``type`` supports ``qemu`` only.
The optional attribute ``backend`` is required if the ``type`` is ``qemu``, the
``model`` attribute can be ``builtint`` and ``lkcf``, the optional attribute
``queues`` specifies the number of virt queues for virtio crypto.

::

   ...
   <devices>
     <crypto model='virtio' type='qemu'>
       <backend model='builtin' queues='1'/>
     </crypto>
   </devices>
   ...


Security label
--------------

The ``seclabel`` element allows control over the operation of the security
drivers. There are three basic modes of operation, 'dynamic' where libvirt
automatically generates a unique security label, 'static' where the
application/administrator chooses the labels, or 'none' where confinement is
disabled. With dynamic label generation, libvirt will always automatically
relabel any resources associated with the virtual machine. With static label
assignment, by default, the administrator or application must ensure labels are
set correctly on any resources, however, automatic relabeling can be enabled if
desired. :since:`'dynamic' since 0.6.1, 'static' since 0.6.2, and 'none' since
0.9.10.`

If more than one security driver is used by libvirt, multiple ``seclabel`` tags
can be used, one for each driver and the security driver referenced by each tag
can be defined using the attribute ``model``

Valid input XML configurations for the top-level security label are:

::

   <seclabel type='dynamic' model='selinux'/>

   <seclabel type='dynamic' model='selinux'>
     <baselabel>system_u:system_r:my_svirt_t:s0</baselabel>
   </seclabel>

   <seclabel type='static' model='selinux' relabel='no'>
     <label>system_u:system_r:svirt_t:s0:c392,c662</label>
   </seclabel>

   <seclabel type='static' model='selinux' relabel='yes'>
     <label>system_u:system_r:svirt_t:s0:c392,c662</label>
   </seclabel>

   <seclabel type='none'/>

If no 'type' attribute is provided in the input XML, then the security driver
default setting will be used, which may be either 'none' or 'dynamic'. If a
'baselabel' is set but no 'type' is set, then the type is presumed to be
'dynamic'

When viewing the XML for a running guest with automatic resource relabeling
active, an additional XML element, ``imagelabel``, will be included. This is an
output-only element, so will be ignored in user supplied XML documents

``type``
   Either ``static``, ``dynamic`` or ``none`` to determine whether libvirt
   automatically generates a unique security label or not.
``model``
   A valid security model name, matching the currently activated security model.
   Model ``dac`` is not available when guest is run by unprivileged user.
``relabel``
   Either ``yes`` or ``no``. This must always be ``yes`` if dynamic label
   assignment is used. With static label assignment it will default to ``no``.
``label``
   If static labelling is used, this must specify the full security label to
   assign to the virtual domain. The format of the content depends on the
   security driver in use:

   -  SELinux: a SELinux context.
   -  AppArmor: an AppArmor profile.
   -  DAC: owner and group separated by colon. They can be defined both as
      user/group names or uid/gid. The driver will first try to parse these
      values as names, but a leading plus sign can used to force the driver to
      parse them as uid or gid.

``baselabel``
   If dynamic labelling is used, this can optionally be used to specify the base
   security label that will be used to generate the actual label. The format of
   the content depends on the security driver in use. The SELinux driver uses
   only the ``type`` field of the baselabel in the generated label. Other fields
   are inherited from the parent process when using SELinux baselabels. (The
   example above demonstrates the use of ``my_svirt_t`` as the value for the
   ``type`` field.)
``imagelabel``
   This is an output only element, which shows the security label used on
   resources associated with the virtual domain. The format of the content
   depends on the security driver in use

When relabeling is in effect, it is also possible to fine-tune the labeling done
for specific source file names, by either disabling the labeling (useful if the
file lives on NFS or other file system that lacks security labeling) or
requesting an alternate label (useful when a management application creates a
special label to allow sharing of some, but not all, resources between domains),
:since:`since 0.9.9` . When a ``seclabel`` element is attached to a specific
path rather than the top-level domain assignment, only the attribute ``relabel``
or the sub-element ``label`` are supported. Additionally, :since:`since 1.1.2` ,
an output-only element ``labelskip`` will be present for active domains on disks
where labeling was skipped due to the image being on a file system that lacks
security labeling.


Key Wrap
--------

The content of the optional ``keywrap`` element specifies whether the guest will
be allowed to perform the S390 cryptographic key management operations. A clear
key can be protected by encrypting it under a unique wrapping key that is
generated for each guest VM running on the host. Two variations of wrapping keys
are generated: one version for encrypting protected keys using the DEA/TDEA
algorithm, and another version for keys encrypted using the AES algorithm. If a
``keywrap`` element is not included, the guest will be granted access to both
AES and DEA/TDEA key wrapping by default.

::

   <domain>
     ...
     <keywrap>
       <cipher name='aes' state='off'/>
     </keywrap>
     ...
   </domain>

At least one ``cipher`` element must be nested within the ``keywrap`` element.

``cipher``
   The ``name`` attribute identifies the algorithm for encrypting a protected
   key. The values supported for this attribute are ``aes`` for encryption under
   the AES wrapping key, or ``dea`` for encryption under the DEA/TDEA wrapping
   key. The ``state`` attribute indicates whether the cryptographic key
   management operations should be turned on for the specified encryption
   algorithm. The value can be set to ``on`` or ``off``.

Note: DEA/TDEA is synonymous with DES/TDES.


Launch Security
---------------

Specifying ``<launchSecurity type='s390-pv'/>`` in a s390 domain prepares
the guest to run in protected virtualization secure mode, also known as
IBM Secure Execution. For more required host and guest preparation steps, see
`Protected Virtualization on s390 <kbase/s390_protected_virt.html>`__
:since:`Since 7.6.0`


The contents of the ``<launchSecurity type='sev'>`` element is used to provide
the guest owners input used for creating an encrypted VM using the AMD SEV
feature (Secure Encrypted Virtualization). SEV is an extension to the AMD-V
architecture which supports running encrypted virtual machine (VMs) under the
control of KVM. Encrypted VMs have their pages (code and data) secured such that
only the guest itself has access to the unencrypted version. Each encrypted VM
is associated with a unique encryption key; if its data is accessed to a
different entity using a different key the encrypted guests data will be
incorrectly decrypted, leading to unintelligible data. For more information see
various input parameters and its format see the `SEV API
spec <https://support.amd.com/TechDocs/55766_SEV-KM_API_Specification.pdf>`__
:since:`Since 4.4.0`

::

   <domain>
     ...
     <launchSecurity type='sev' kernelHashes='yes'>
       <policy>0x0001</policy>
       <cbitpos>47</cbitpos>
       <reducedPhysBits>1</reducedPhysBits>
       <dhCert>RBBBSDDD=FDDCCCDDDG</dhCert>
       <session>AAACCCDD=FFFCCCDSDS</session>
     </launchSecurity>
     ...
   </domain>

``kernelHashes``
   The optional ``kernelHashes`` attribute indicates whether the
   hashes of the kernel, ramdisk and command line should be included
   in the measurement done by the firmware. This is only valid if
   using direct kernel boot. :since:`Since 8.0.0`
``cbitpos``
   The required ``cbitpos`` element provides the C-bit (aka encryption bit)
   location in guest page table entry. The value of ``cbitpos`` is hypervisor
   dependent and can be obtained through the ``sev`` element from the domain
   capabilities.
``reducedPhysBits``
   The required ``reducedPhysBits`` element provides the physical address bit
   reduction. Similar to ``cbitpos`` the value of ``reduced-phys-bit`` is
   hypervisor dependent and can be obtained through the ``sev`` element from the
   domain capabilities.
``policy``
   The required ``policy`` element provides the guest policy which must be
   maintained by the SEV firmware. This policy is enforced by the firmware and
   restricts what configuration and operational commands can be performed on
   this guest by the hypervisor. The guest policy provided during guest launch
   is bound to the guest and cannot be changed throughout the lifetime of the
   guest. The policy is also transmitted during snapshot and migration flows and
   enforced on the destination platform. The guest policy is a 4 unsigned byte
   with the fields shown in Table:

   ====== =========================================================================================
   Bit(s) Description
   ====== =========================================================================================
   0      Debugging of the guest is disallowed when set
   1      Sharing keys with other guests is disallowed when set
   2      SEV-ES is required when set
   3      Sending the guest to another platform is disallowed when set
   4      The guest must not be transmitted to another platform that is not in the domain when set.
   5      The guest must not be transmitted to another platform that is not SEV capable when set.
   6:15   reserved
   16:32  The guest must not be transmitted to another platform with a lower firmware version.
   ====== =========================================================================================

``dhCert``
   The optional ``dhCert`` element provides the guest owners base64 encoded
   Diffie-Hellman (DH) key. The key is used to negotiate a master secret key
   between the SEV firmware and guest owner. This master secret key is then used
   to establish a trusted channel between SEV firmware and guest owner.
``session``
   The optional ``session`` element provides the guest owners base64 encoded
   session blob defined in the SEV API spec. See SEV spec LAUNCH_START section
   for the session blob format.

Example configs
===============

Example configurations for each driver are provide on the driver specific pages
listed below

-  `Xen examples <drvxen.html#example-domain-xml-config>`__
-  `QEMU/KVM examples <drvqemu.html#example-domain-xml-config>`__
