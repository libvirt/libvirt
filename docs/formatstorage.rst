.. role:: since
.. role:: removed

==================================
Storage pool and volume XML format
==================================

.. contents::

Storage pool XML
----------------

Although all storage pool backends share the same public APIs and XML format,
they have varying levels of capabilities. Some may allow creation of volumes,
others may only allow use of pre-existing volumes. Some may have constraints on
volume size, or placement.

The top level tag for a storage pool document is 'pool'. It has a single
attribute ``type``, which is one of ``dir``, ``fs``, ``netfs``, ``disk``,
``iscsi``, ``logical``, ``scsi`` (all :since:`since 0.4.1` ), ``mpath`` (
:since:`since 0.7.1` ), ``rbd`` ( :since:`since 0.9.13` ),
``sheepdog`` (:since:`since 0.10.0`, :removed:`removed in 8.8.0` ),
``gluster`` ( :since:`since 1.2.0` ), ``zfs`` (
:since:`since 1.2.8` ), ``vstorage`` ( :since:`since 3.1.0` ), or
``iscsi-direct`` ( :since:`since 4.7.0` ). This corresponds to the storage
backend drivers listed further along in this document.

Storage pool general metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="iscsi">
     <name>virtimages</name>
     <uuid>3e3fce45-4f53-4fa7-bb32-11f34168b82b</uuid>
     <allocation>10000000</allocation>
     <capacity>50000000</capacity>
     <available>40000000</available>
     ...

``name``
   Providing a name for the pool which is unique to the host. This is mandatory
   when defining a pool. :since:`Since 0.4.1`
``uuid``
   Providing an identifier for the pool which is globally unique. This is
   optional when defining a pool, a UUID will be generated if omitted.
   :since:`Since 0.4.1`
``allocation``
   Providing the total storage allocation for the pool. This may be larger than
   the sum of the allocation of all volumes due to metadata overhead. This value
   is in bytes. This is not applicable when creating a pool. :since:`Since
   0.4.1`
``capacity``
   Providing the total storage capacity for the pool. Due to underlying device
   constraints it may not be possible to use the full capacity for storage
   volumes. This value is in bytes. This is not applicable when creating a pool.
   :since:`Since 0.4.1`
``available``
   Providing the free space available for allocating new volumes in the pool.
   Due to underlying device constraints it may not be possible to allocate the
   entire free space to a single volume. This value is in bytes. This is not
   applicable when creating a pool. :since:`Since 0.4.1`

Features
~~~~~~~~

Some pools support optional features:

::

   ...
   <features>
     <cow state='no'>
   </features>
   ...

Valid features are:

``cow``
    Controls whether the filesystem performs copy-on-write (COW) for images in
    the pool. This may only be set for directory / filesystem pools on the
    ``btrfs`` filesystem. If not set then libvirt will attempt to disable COW
    on any btrfs filesystems. :since:`Since 6.6.0`.

Source elements
~~~~~~~~~~~~~~~

A single ``source`` element is contained within the top level ``pool`` element.
This tag is used to describe the source of the storage pool. The set of child
elements that it will contain depend on the pool type, but come from the
following child elements:

::

   ...
   <source>
     <host name="iscsi.example.com"/>
     <device path="iqn.2013-06.com.example:iscsi-pool"/>
     <auth type='chap' username='myname'>
       <secret usage='mycluster_myname'/>
     </auth>
     <vendor name="Acme"/>
     <product name="model"/>
   </source>
   ...

::

   ...
   <source>
     <device path='/dev/mapper/mpatha' part_separator='no'/>
     <format type='gpt'/>
   </source>
   ...

::

   ...
   <source>
     <adapter type='scsi_host' name='scsi_host1'/>
   </source>
   ...

::

   ...
   <source>
     <adapter type='scsi_host'>
       <parentaddr unique_id='1'>
         <address domain='0x0000' bus='0x00' slot='0x1f' addr='0x2'/>
       </parentaddr>
     </adapter>
   </source>
   ...

::

   ...
   <source>
     <adapter type='fc_host' parent='scsi_host5' wwnn='20000000c9831b4b' wwpn='10000000c9831b4b'/>
   </source>
   ...

::

   ...
     <source>
       <host name='localhost'/>
       <dir path='/var/lib/libvirt/images'/>
       <format type='nfs'/>
       <protocol ver='3'/>
     </source>
   ...

``device``
   Provides the source for pools backed by physical devices (pool types ``fs``,
   ``logical``, ``disk``, ``iscsi``, ``iscsi-direct``, ``zfs``, ``vstorage``).
   May be repeated multiple times depending on backend driver. Contains a
   required attribute ``path`` which is either the fully qualified path to the
   block device node or for ``iscsi`` or ``iscsi-direct`` the iSCSI Qualified
   Name (IQN). :since:`Since 0.4.1`

   An optional attribute ``part_separator`` for each ``path`` may be supplied.
   Valid values for the attribute may be either "yes" or "no". This attribute is
   to be used for a ``disk`` pool type using a ``path`` to a device mapper
   multipath device. Setting the attribute to "yes" causes libvirt to attempt to
   generate and find target volume path's using a "p" separator. The default
   algorithm used by device mapper is to add the "p" separator only when the
   source device path ends with a number; however, it's possible to configure
   the devmapper device to not use 'user_friendly_names' thus creating
   partitions with the "p" separator even when the device source path does not
   end with a number. :since:`Since 1.3.1`

``dir``
   Provides the source for pools backed by directories (pool types ``dir``,
   ``netfs``, ``gluster``), or optionally to select a subdirectory within a pool
   that resembles a filesystem (pool type ``gluster``). May only occur once.
   Contains a single attribute ``path`` which is the fully qualified path to the
   backing directory or for a ``netfs`` pool type using ``format`` type "cifs",
   the path to the Samba share without the leading slash. :since:`Since 0.4.1`
``adapter``
   Provides the source for pools backed by SCSI adapters (pool type ``scsi``).
   May only occur once.

   ``name``
      The SCSI adapter name (e.g. "scsi_host1", although a name such as "host1"
      is still supported for backwards compatibility, it is not recommended).
      The scsi_host name to be used can be determined from the output of a
      ``virsh nodedev-list             scsi_host`` command followed by a
      combination of ``lspci`` and
      ``virsh nodedev-dumpxml             scsi_hostN`` commands to find the
      ``scsi_hostN`` to be used. :since:`Since 0.6.2`

      It is further recommended to utilize the ``parentaddr`` element since it's
      possible to have the path to which the scsi_hostN uses change between
      system reboots. :since:`Since 1.2.7`

   ``type``
      Specifies the adapter type. Valid values are "scsi_host" or "fc_host". If
      omitted and the ``name`` attribute is specified, then it defaults to
      "scsi_host". To keep backwards compatibility, this attribute is optional
      **only** for the "scsi_host" adapter, but is mandatory for the "fc_host"
      adapter. :since:`Since 1.0.5` A "fc_host" capable scsi_hostN can be
      determined by using ``virsh nodedev-list --cap fc_host``. :since:`Since
      1.2.8`

      Note: Regardless of whether a "scsi_host" adapter type is defined using a
      ``name`` or a ``parentaddr``, it should refer to a real scsi_host adapter
      as found through a ``virsh nodedev-list scsi_host`` and
      ``virsh             nodedev-dumpxml scsi_hostN`` on one of the scsi_host's
      displayed. It should not refer to a "fc_host" capable scsi_hostN nor
      should it refer to the vHBA created for some "fc_host" adapter. For a vHBA
      the ``nodedev-dumpxml`` output parent setting will be the "fc_host"
      capable scsi_hostN value. Additionally, do not refer to an iSCSI
      scsi_hostN for the "scsi_host" source. An iSCSI scsi_hostN's
      ``nodedev-dumpxml`` output parent field is generally "computer". This is a
      libvirt created parent value indicating no parent was defined for the node
      device.

   ``wwnn`` and ``wwpn``
      The required "World Wide Node Name" (``wwnn``) and "World Wide Port Name"
      (``wwpn``) are used by the "fc_host" adapter to uniquely identify the vHBA
      device in the Fibre Channel storage fabric. If the vHBA device already
      exists as a Node Device, then libvirt will use it; otherwise, the vHBA
      will be created using the provided values. It is considered a
      configuration error use the values from the HBA as those would be for a
      "scsi_host" ``type`` pool instead. The ``wwnn`` and ``wwpn`` have very
      specific format requirements based on the hypervisor being used, thus care
      should be taken if you decide to generate your own to follow the
      standards; otherwise, the pool will fail to start with an opaque error
      message indicating failure to write to the vport_create file during vport
      create/delete due to "No such file or directory". :since:`Since 1.0.4`

   ``parent``
      Used by the "fc_host" adapter type to optionally specify the parent
      scsi_host device defined in the `Node Device <formatnode.html>`__ database
      as the `NPIV <https://wiki.libvirt.org/page/NPIV_in_libvirt>`__ virtual
      Host Bus Adapter (vHBA). The value provided must be a vport capable
      scsi_host. The value is not the scsi_host of the vHBA created by 'virsh
      nodedev-create', rather it is the parent of that vHBA. If the value is not
      provided, libvirt will determine the parent based either finding the
      wwnn,wwpn defined for an existing scsi_host or by creating a vHBA.
      Providing the parent attribute is also useful for the duplicate pool
      definition checks. This is more important in environments where both the
      "fc_host" and "scsi_host" source adapter pools are being used in order to
      ensure a new definition doesn't duplicate using the scsi_hostN of some
      existing storage pool. :since:`Since 1.0.4`
   ``parent_wwnn`` and ``parent_wwpn``
      Instead of the ``parent`` to specify which scsi_host to use by name, it's
      possible to provide the wwnn and wwpn of the parent to be used for the
      vHBA in order to ensure that between reboots or after a hardware
      configuration change that the scsi_host parent name doesn't change. Both
      the parent_wwnn and parent_wwpn must be provided. :since:`Since 3.0.0`
   ``parent_fabric_wwn``
      Instead of the ``parent`` to specify which scsi_host to use by name, it's
      possible to provide the fabric_wwn on which the scsi_host exists. This
      provides flexibility for choosing a scsi_host that may be available on the
      fabric rather than requiring a specific parent by wwnn or wwpn to be
      available. :since:`Since 3.0.0`
   ``managed``
      An optional attribute to instruct the SCSI storage backend to manage
      destroying the vHBA when the pool is destroyed. For configurations that do
      not provide an already created vHBA from a 'virsh nodedev-create', libvirt
      will set this property to "yes". For configurations that have already
      created a vHBA via 'virsh nodedev-create' and are using the wwnn/wwpn from
      that vHBA and optionally the scsi_host parent, setting this attribute to
      "yes" will allow libvirt to destroy the node device when the pool is
      destroyed. If this attribute is set to "no" or not defined in the XML,
      then libvirt will not destroy the vHBA. :since:`Since 1.2.11`

   ``parentaddr``
      Used by the "scsi_host" adapter type instead of the ``name`` attribute to
      more uniquely identify the SCSI host. Using a combination of the
      ``unique_id`` attribute and the ``address`` element to formulate a PCI
      address, a search will be performed of the ``/sys/class/scsi_host/hostNN``
      links for a matching PCI address with a matching ``unique_id`` value in
      the ``/sys/class/scsi_host/hostNN/unique_id`` file. The value in the
      "unique_id" file will be unique enough for the specific PCI address. The
      ``hostNN`` will be used by libvirt as the basis to define which SCSI host
      is to be used for the currently booted system. :since:`Since 1.2.7`

      ``address``
         The PCI address of the scsi_host device to be used. Using a PCI address
         provides consistent naming across system reboots and kernel reloads.
         The address will have four attributes: ``domain`` (a 2-byte hex
         integer, not currently used by qemu), ``bus`` (a hex value between 0
         and 0xff, inclusive), ``slot`` (a hex value between 0x0 and 0x1f,
         inclusive), and ``function`` (a value between 0 and 7, inclusive). The
         PCI address can be determined by listing the ``/sys/bus/pci/devices``
         and the ``/sys/class/scsi_host`` directories in order to find the
         expected scsi_host device. The address will be provided in a format
         such as "0000:00:1f:2" which can be used to generate the expected PCI
         address "domain='0x0000' bus='0x00' slot='0x1f' function='0x0'".
         Optionally, using the combination of the commands 'virsh nodedev-list
         scsi_host' and 'virsh nodedev-dumpxml' for a specific list entry and
         converting the resulting ``path`` element as the basis to formulate the
         correctly formatted PCI address.

      ``unique_id``
         Required ``parentaddr`` attribute used to determine which of the
         scsi_host adapters for the provided PCI address should be used. The
         value is determine by contents of the ``unique_id`` file for the
         specific scsi_host adapter. For a PCI address of "0000:00:1f:2", the
         unique identifier files can be found using the command
         ``find -H /sys/class/scsi_host/host*/unique_id |                 xargs grep '[0-9]'``.
         Optionally, the ``virsh nodedev-dumpxml scsi_hostN``' of a specific
         scsi_hostN list entry will list the ``unique_id`` value.
``host``
   Provides the source for pools backed by storage from a remote server (pool
   types ``netfs``, ``iscsi``, ``iscsi-direct``, ``rbd``, ``sheepdog``,
   ``gluster``). Will be used in combination with a ``directory`` or ``device``
   element. Contains an attribute ``name`` which is the hostname or IP address
   of the server. May optionally contain a ``port`` attribute for the protocol
   specific port number. Duplicate storage pool definition checks may perform a
   cursory check that the same host name by string comparison in the new pool
   does not match an existing pool's source host name when combined with the
   ``directory`` or ``device`` element. Name resolution of the provided hostname
   or IP address is left to the storage driver backend interactions with the
   remote server. See the `storage driver page <storage.html>`__ for any
   restrictions for specific storage backends. :since:`Since 0.4.1`
``initiator``
   Required by the ``iscsi-direct`` pool in order to provide the iSCSI Qualified
   Name (IQN) to communicate with the pool's ``device`` target IQN. There is one
   sub-element ``iqn`` with the ``name`` attribute to describe the IQN for the
   initiator. :since:`Since 4.7.0`
``auth``
   If present, the ``auth`` element provides the authentication credentials
   needed to access the source by the setting of the ``type`` attribute (pool
   types ``iscsi``, ``iscsi-direct``, ``rbd``). The ``type`` must be either
   "chap" or "ceph". Use "ceph" for Ceph RBD (Rados Block Device) network
   sources and use "iscsi" for CHAP (Challenge-Handshake Authentication
   Protocol) iSCSI targets. Additionally a mandatory attribute ``username``
   identifies the username to use during authentication as well as a sub-element
   ``secret`` with a mandatory attribute ``type``, to tie back to a `libvirt
   secret object <formatsecret.html>`__ that holds the actual password or other
   credentials. The domain XML intentionally does not expose the password, only
   the reference to the object that manages the password. The ``secret`` element
   requires either a ``uuid`` attribute with the UUID of the secret object or a
   ``usage`` attribute matching the key that was specified in the secret object.
   :since:`Since 0.9.7 for "ceph" and 1.1.1 for "chap"`
``name``
   Provides the source for pools backed by storage from a named element (pool
   types ``logical``, ``rbd``, ``sheepdog``, ``gluster``). Contains a string
   identifier. :since:`Since 0.4.5`
``format``
   Provides information about the format of the pool (pool types ``fs``,
   ``netfs``, ``disk``, ``logical``). This contains a single attribute ``type``
   whose value is backend specific. This is typically used to indicate
   filesystem type, or network filesystem type, or partition table type, or LVM
   metadata type. All drivers are required to have a default value for this, so
   it is optional. :since:`Since 0.4.1`
``protocol``
   For a ``netfs`` Storage Pool provide a mechanism to define which NFS protocol
   version number will be used to contact the server's NFS service. The
   attribute ``ver`` accepts the version number to use.
   :since:`Since 5.1.0`
``vendor``
   Provides optional information about the vendor of the storage device. This
   contains a single attribute ``name`` whose value is backend specific.
   :since:`Since 0.8.4`
``product``
   Provides an optional product name of the storage device. This contains a
   single attribute ``name`` whose value is backend specific. :since:`Since
   0.8.4`

Storage pool target elements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single ``target`` element is contained within the top level ``pool`` element
for some types of pools (pool types ``dir``, ``fs``, ``netfs``, ``logical``,
``disk``, ``iscsi``, ``scsi``, ``mpath``, ``zfs``). This tag is used to describe
the mapping of the storage pool into the host filesystem. It can contain the
following child elements:

::

     ...
     <target>
       <path>/dev/disk/by-path</path>
       <permissions>
         <owner>107</owner>
         <group>107</group>
         <mode>0744</mode>
         <label>virt_image_t</label>
       </permissions>
     </target>
   </pool>

``path``
   Provides the location at which the pool will be mapped into the local
   filesystem namespace, as an absolute path. For a filesystem/directory based
   pool it will be a fully qualified name of the directory in which volumes will
   be created. For device based pools it will be a fully qualified name of the
   directory in which devices nodes exist. For the latter ``/dev/`` may seem
   like the logical choice, however, devices nodes there are not guaranteed
   stable across reboots, since they are allocated on demand. It is preferable
   to use a stable location such as one of the
   ``/dev/disk/by-{path|id|uuid|label}`` locations. For ``logical`` and ``zfs``
   pool types, a provided value is ignored and a default path generated. For a
   Multipath pool (type ``mpath``), the provided value is ignored and the
   default value of "/dev/mapper" is used. :since:`Since 0.4.1`
``permissions``
   This is currently only useful for directory or filesystem based pools, which
   are mapped as a directory into the local filesystem namespace. It provides
   information about the permissions to use for the final directory when the
   pool is built. There are 4 child elements. The ``mode`` element contains the
   octal permission set. The ``mode`` defaults to 0711 when not provided. The
   ``owner`` element contains the numeric user ID. The ``group`` element
   contains the numeric group ID. If ``owner`` or ``group`` aren't specified
   when creating a directory, the UID and GID of the libvirtd process are used.
   The ``label`` element contains the MAC (eg SELinux) label string.
   :since:`Since 0.4.1` For running directory or filesystem based pools, these
   fields will be filled with the values used by the existing directory.
   :since:`Since 1.2.16`

Device extents
~~~~~~~~~~~~~~

If a storage pool exposes information about its underlying placement /
allocation scheme, the ``device`` element within the ``source`` element may
contain information about its available extents. Some pools have a constraint
that a volume must be allocated entirely within a single constraint (eg disk
partition pools). Thus the extent information allows an application to determine
the maximum possible size for a new volume

For storage pools supporting extent information, within each ``device`` element
there will be zero or more ``freeExtent`` elements. Each of these elements
contains two attributes, ``start`` and ``end`` which provide the boundaries of
the extent on the device, measured in bytes. :since:`Since 0.4.1`

Refresh overrides
~~~~~~~~~~~~~~~~~

The optional ``refresh`` element can control how the pool and associated volumes
are refreshed (pool type ``rbd``). The ``allocation`` attribute of the
``volume`` child element controls the method used for computing the allocation
of a volume. The valid attribute values are ``default`` to compute the actual
usage or ``capacity`` to use the logical capacity for cases where computing the
allocation is too expensive. The following XML snippet shows the syntax:

::

   <pool type="rbd">
     <name>myrbdpool</name>
   ...
     <source/>
   ...
     <refresh>
       <volume allocation='capacity'/>
     </refresh>
   ...
   </pool>

:since:`Since 5.2.0`

Storage Pool Namespaces
~~~~~~~~~~~~~~~~~~~~~~~

Usage of Storage Pool Namespaces provides a mechanism to provide pool type
specific data in a free form or arbitrary manner via XML syntax targeted solely
for the needs of the specific pool type which is not otherwise supported in
standard XML. For the "fs" and "netfs" pool types this provides a mechanism to
provide additional mount options on the command line. For the "rbd" pool this
provides a mechanism to override default settings for RBD configuration options.

Usage of namespaces comes with no support guarantees. It is intended for
developers testing out a concept prior to requesting an explicitly supported XML
option in libvirt, and thus should never be used in production.

``fs:mount_opts``
   Provides an XML namespace mechanism to optionally utilize specifically named
   options for the mount command via the "-o" option for the ``fs`` or ``netfs``
   type storage pools. In order to designate that the Storage Pool will be using
   the mechanism, the ``pool`` element must be modified to provide the XML
   namespace attribute syntax as follows::

      xmlns:fs='http://libvirt.org/schemas/storagepool/fs/1.0'

   The ``fs:mount_opts`` defines the mount options by specifying multiple
   ``fs:option`` subelements with the attribute ``name`` specifying the mount
   option to be added. The value of the named option is not checked since it's
   possible options don't exist on all distributions. It is expected that proper
   and valid options will be supplied for the target host.

   The following XML snippet shows the syntax required in order to utilize for a
   netfs pool:

   ::

      <pool type="netfs" xmlns:fs='http://libvirt.org/schemas/storagepool/fs/1.0'>
        <name>nfsimages</name>
      ...
        <source>
      ...
        </source>
      ...
        <target>
      ...
        </target>
        <fs:mount_opts>
          <fs:option name='sync'/>
          <fs:option name='lazytime'/>
        </fs:mount_opts>
      </pool>
      ...

   :since:`Since 5.1.0.`

``rbd:config_opts``
   Provides an XML namespace mechanism to optionally utilize specifically named
   options for the RBD configuration options via the rados_conf_set API for the
   ``rbd`` type storage pools. In order to designate that the Storage Pool will
   be using the mechanism, the ``pool`` element must be modified to provide the
   XML namespace attribute syntax as follows:

   xmlns:rbd='http://libvirt.org/schemas/storagepool/rbd/1.0'

   The ``rbd:config_opts`` defines the configuration options by specifying
   multiple ``rbd:option`` subelements with the attribute ``name`` specifying
   the configuration option to be added and ``value`` specifying the
   configuration option value. The name and value for each option is only
   checked to be not empty. The name and value provided are not checked since
   it's possible options don't exist on all distributions. It is expected that
   proper and valid options will be supplied for the target host.

   The following XML snippet shows the syntax required in order to utilize

   ::

      <pool type="rbd" xmlns:rbd='http://libvirt.org/schemas/storagepool/rbd/1.0'>
        <name>myrbdpool</name>
      ...
        <source>
      ...
        </source>
      ...
        <target>
      ...
        </target>
      ...
        <rbd:config_opts>
          <rbd:option name='client_mount_timeout' value='45'/>
          <rbd:option name='rados_mon_op_timeout' value='20'/>
          <rbd:option name='rados_osd_op_timeout' value='10'/>
        </rbd:config_opts>
      </pool>

   :since:`Since 5.1.0.`

Storage volume XML
------------------

A storage volume will generally be either a file or a device node; :since:`since
1.2.0` , an optional output-only attribute ``type`` lists the actual type (file,
block, dir, network, netdir or ploop), which is also available from
``virStorageVolGetInfo()``. The storage volume XML format is available
:since:`since 0.4.1`

Storage volume general metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <volume type='file'>
     <name>sparse.img</name>
     <key>/var/lib/xen/images/sparse.img</key>
     <allocation>0</allocation>
     <capacity unit="T">1</capacity>
     ...

``name``
   Providing a name for the volume which is unique to the pool. This is
   mandatory when defining a volume. For a disk pool, the name must be
   combination of the ``source`` device path device and next partition number to
   be created. For example, if the ``source`` device path is /dev/sdb and there
   are no partitions on the disk, then the name must be sdb1 with the next name
   being sdb2 and so on. :since:`Since 0.4.1`
``key``
   Providing an identifier for the volume which identifies a single volume. In
   some cases it's possible to have two distinct keys identifying a single
   volume. This field cannot be set when creating a volume: it is always
   generated. :since:`Since 0.4.1`
``allocation``
   Providing the total storage allocation for the volume. This may be smaller
   than the logical capacity if the volume is sparsely allocated. It may also be
   larger than the logical capacity if the volume has substantial metadata
   overhead. This value is in bytes. If omitted when creating a volume, the
   volume will be fully allocated at time of creation. If set to a value smaller
   than the capacity, the pool has the **option** of deciding to sparsely
   allocate a volume. It does not have to honour requests for sparse allocation
   though. Different types of pools may treat sparse volumes differently. For
   example, the ``logical`` pool will not automatically expand volume's
   allocation when it gets full; the user is responsible for doing that or
   configuring dmeventd to do so automatically.
   By default this is specified in bytes, but an optional attribute ``unit`` can
   be specified to adjust the passed value. Values can be: 'B' or 'bytes' for
   bytes, 'KB' (kilobytes, 10\ :sup:`3` or 1000 bytes), 'K' or 'KiB' (kibibytes,
   2\ :sup:`10` or 1024 bytes), 'MB' (megabytes, 10\ :sup:`6` or 1,000,000
   bytes), 'M' or 'MiB' (mebibytes, 2\ :sup:`20` or 1,048,576 bytes), 'GB'
   (gigabytes, 10\ :sup:`9` or 1,000,000,000 bytes), 'G' or 'GiB' (gibibytes,
   2\ :sup:`30` or 1,073,741,824 bytes), 'TB' (terabytes, 10\ :sup:`12` or
   1,000,000,000,000 bytes), 'T' or 'TiB' (tebibytes, 2\ :sup:`40` or
   1,099,511,627,776 bytes), 'PB' (petabytes, 10\ :sup:`15` or
   1,000,000,000,000,000 bytes), 'P' or 'PiB' (pebibytes, 2\ :sup:`50` or
   1,125,899,906,842,624 bytes), 'EB' (exabytes, 10\ :sup:`18` or
   1,000,000,000,000,000,000 bytes), or 'E' or 'EiB' (exbibytes, 2\ :sup:`60` or
   1,152,921,504,606,846,976 bytes). :since:`Since 0.4.1`, multi-character
   ``unit`` :since:`since 0.9.11`.
``capacity``
   Providing the logical capacity for the volume. This value is in bytes by
   default, but a ``unit`` attribute can be specified with the same semantics as
   for ``allocation`` This is compulsory when creating a volume. :since:`Since
   0.4.1`
``physical``
   This output only element provides the host physical size of the target
   storage volume. The default output ``unit`` will be in bytes. :since:`Since
   3.0.0`
``source``
   Provides information about the underlying storage allocation of the volume.
   This may not be available for some pool types. :since:`Since 0.4.1`
``target``
   Provides information about the representation of the volume on the local
   host. :since:`Since 0.4.1`

Storage volume target elements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single ``target`` element is contained within the top level ``volume``
element. This tag is used to describe the mapping of the storage volume into the
host filesystem. It can contain the following child elements:

::

   ...
   <target>
     <path>/var/lib/virt/images/sparse.img</path>
     <format type='qcow2'/>
     <permissions>
       <owner>107</owner>
       <group>107</group>
       <mode>0744</mode>
       <label>virt_image_t</label>
     </permissions>
     <timestamps>
       <atime>1341933637.273190990</atime>
       <mtime>1341930622.047245868</mtime>
       <ctime>1341930622.047245868</ctime>
     </timestamps>
     <encryption type='...'>
       ...
     </encryption>
     <compat>1.1</compat>
     <nocow/>
     <clusterSize unit='KiB'>64</clusterSize>
     <features>
       <lazy_refcounts/>
       <extended_l2/>
     </features>
   </target>

``path``
   Provides the location at which the volume can be accessed on the local
   filesystem, as an absolute path. This is a readonly attribute, so shouldn't
   be specified when creating a volume. :since:`Since 0.4.1`
``format``
   Provides information about the pool specific volume format. For disk pools it
   will provide the partition table format type, but is not preserved after a
   pool refresh or libvirtd restart. Use extended in order to create an extended
   disk extent partition. For filesystem or directory pools it will provide the
   file format type, eg cow, qcow, vmdk, raw. If omitted when creating a volume,
   the pool's default format will be used. The actual format is specified via
   the ``type`` attribute. Consult the `storage driver page <storage.html>`__
   for the list of valid volume format type values for each specific pool. The
   ``format`` will be ignored on input for pools without a volume format type
   value and the default pool format will be used. :since:`Since 0.4.1`
``permissions``
   Provides information about the permissions to use when creating volumes. This
   is currently only useful for directory or filesystem based pools, where the
   volumes allocated are simple files. For pools where the volumes are device
   nodes, the hotplug scripts determine permissions. There are 4 child elements.
   The ``mode`` element contains the octal permission set. The ``mode`` defaults
   to 0600 when not provided. The ``owner`` element contains the numeric user
   ID. The ``group`` element contains the numeric group ID. If ``owner`` or
   ``group`` aren't specified when creating a supported volume, the UID and GID
   of the libvirtd process are used. The ``label`` element contains the MAC (eg
   SELinux) label string. For existing directory or filesystem based volumes,
   these fields will be filled with the values used by the existing file.
   :since:`Since 0.4.1`
``timestamps``
   Provides timing information about the volume. Up to four sub-elements are
   present, where ``atime``, ``btime``, ``ctime`` and ``mtime`` hold the access,
   birth, change and modification time of the volume, where known. The used time
   format is <seconds>.<nanoseconds> since the beginning of the epoch (1 Jan
   1970). If nanosecond resolution is 0 or otherwise unsupported by the host OS
   or filesystem, then the nanoseconds part is omitted. This is a readonly
   attribute and is ignored when creating a volume. :since:`Since 0.10.0`
``encryption``
   If present, specifies how the volume is encrypted. See the `Storage
   Encryption <formatstorageencryption.html>`__ page for more information.
``compat``
   Specify compatibility level. So far, this is only used for ``type='qcow2'``
   volumes. Valid values are ``0.10`` and ``1.1`` so far, specifying QEMU
   version the images should be compatible with. If the ``feature`` element is
   present, 1.1 is used. :since:`Since 1.1.0` If omitted, 0.10 is used.
   :since:`Since 1.1.2`
``nocow``
   Turn off COW of the newly created volume. So far, this is only valid for a
   file image in btrfs file system. It will improve performance when the file
   image is used in VM. To create non-raw file images, it requires QEMU version
   since 2.1. :since:`Since 1.2.7`
``clusterSize``
   Changes the qcow2 cluster size which can affect image file size and
   performance. :since:`Since 7.4.0`
``features``
   Format-specific features. Only used for ``qcow2`` now. Valid sub-elements
   are:

   -  ``<lazy_refcounts/>`` - allow delayed reference counter updates.
      :since:`Since 1.1.0`
   - ``<extended_l2/>`` - enables subcluster allocation for qcow2 images. QCOW2
     clusters are split into 32 subclusters decreasing the size of L2 cache
     needed. It's recommended to increase ``clusterSize``.

Backing store elements
~~~~~~~~~~~~~~~~~~~~~~

A single ``backingStore`` element is contained within the top level ``volume``
element. This tag is used to describe the optional copy on write, backing store
for the storage volume. It can contain the following child elements:

::

     ...
     <backingStore>
       <path>/var/lib/virt/images/master.img</path>
       <format type='raw'/>
       <permissions>
         <owner>107</owner>
         <group>107</group>
         <mode>0744</mode>
         <label>virt_image_t</label>
       </permissions>
     </backingStore>
   </volume>

``path``
   Provides the location at which the backing store can be accessed on the local
   filesystem, as an absolute path. If omitted, there is no backing store for
   this volume. :since:`Since 0.6.0`
``format``
   Provides information about the pool specific backing store format. For disk
   pools it will provide the partition type. For filesystem or directory pools
   it will provide the file format type, eg cow, qcow, vmdk, raw. The actual
   format is specified via the type attribute. Consult the pool-specific docs
   for the list of valid values. Most file formats require a backing store of
   the same format, however, the qcow2 format allows a different backing store
   format. :since:`Since 0.6.0`
``permissions``
   Provides information about the permissions of the backing file. See volume
   ``permissions`` documentation for explanation of individual fields.
   :since:`Since 0.6.0`

Example configuration
---------------------

Here are a couple of examples, for a more complete set demonstrating every type
of storage pool, consult the `storage driver page <storage.html>`__

File based storage pool
~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="dir">
     <name>virtimages</name>
     <target>
       <path>/var/lib/virt/images</path>
     </target>
   </pool>

iSCSI based storage pool
~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="iscsi">
     <name>virtimages</name>
     <source>
       <host name="iscsi.example.com"/>
       <device path="iqn.2013-06.com.example:iscsi-pool"/>
       <auth type='chap' username='myuser'>
         <secret usage='libvirtiscsi'/>
       </auth>
     </source>
     <target>
       <path>/dev/disk/by-path</path>
     </target>
   </pool>

Storage volume
~~~~~~~~~~~~~~

::

   <volume>
     <name>sparse.img</name>
     <allocation>0</allocation>
     <capacity unit="T">1</capacity>
     <target>
       <path>/var/lib/virt/images/sparse.img</path>
       <permissions>
         <owner>107</owner>
         <group>107</group>
         <mode>0744</mode>
         <label>virt_image_t</label>
       </permissions>
     </target>
   </volume>

Storage volume using LUKS
~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <volume>
     <name>MyLuks.img</name>
     <capacity unit="G">5</capacity>
     <target>
       <path>/var/lib/virt/images/MyLuks.img</path>
       <format type='raw'/>
       <encryption format='luks'>
         <secret type='passphrase' uuid='f52a81b2-424e-490c-823d-6bd4235bc572'/>
       </encryption>
     </target>
   </volume>
