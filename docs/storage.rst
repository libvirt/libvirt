.. role:: since
.. role:: removed

==================
Storage Management
==================

Libvirt provides storage management on the physical host through storage pools
and volumes.

A storage pool is a quantity of storage set aside by an administrator, often a
dedicated storage administrator, for use by virtual machines. Storage pools are
divided into storage volumes either by the storage administrator or the system
administrator, and the volumes are assigned to VMs as block devices.

For example, the storage administrator responsible for an NFS server creates a
share to store virtual machines' data. The system administrator defines a pool
on the virtualization host with the details of the share (e.g.
nfs.example.com:/path/to/share should be mounted on /vm_data). When the pool is
started, libvirt mounts the share on the specified directory, just as if the
system administrator logged in and executed 'mount
nfs.example.com:/path/to/share /vmdata'. If the pool is configured to autostart,
libvirt ensures that the NFS share is mounted on the directory specified when
libvirt is started.

Once the pool is started, the files in the NFS share are reported as volumes,
and the storage volumes' paths may be queried using the libvirt APIs. The
volumes' paths can then be copied into the section of a VM's XML definition
describing the source storage for the VM's block devices. In the case of NFS, an
application using the libvirt APIs can create and delete volumes in the pool
(files in the NFS share) up to the limit of the size of the pool (the storage
capacity of the share). Not all pool types support creating and deleting
volumes. Stopping the pool (somewhat unfortunately referred to by virsh and the
API as "pool-destroy") undoes the start operation, in this case, unmounting the
NFS share. The data on the share is not modified by the destroy operation,
despite the name. See man virsh for more details.

A second example is an iSCSI pool. A storage administrator provisions an iSCSI
target to present a set of LUNs to the host running the VMs. When libvirt is
configured to manage that iSCSI target as a pool, libvirt will ensure that the
host logs into the iSCSI target and libvirt can then report the available LUNs
as storage volumes. The volumes' paths can be queried and used in VM's XML
definitions as in the NFS example. In this case, the LUNs are defined on the
iSCSI server, and libvirt cannot create and delete volumes.

Storage pools and volumes are not required for the proper operation of VMs.
Pools and volumes provide a way for libvirt to ensure that a particular piece of
storage will be available for a VM, but some administrators will prefer to
manage their own storage and VMs will operate properly without any pools or
volumes defined. On systems that do not use pools, system administrators must
ensure the availability of the VMs' storage using whatever tools they prefer,
for example, adding the NFS share to the host's fstab so that the share is
mounted at boot time.

If at this point the value of pools and volumes over traditional system
administration tools is unclear, note that one of the features of libvirt is its
remote protocol, so it's possible to manage all aspects of a virtual machine's
lifecycle as well as the configuration of the resources required by the VM.
These operations can be performed on a remote host entirely within the libvirt
API. In other words, a management application using libvirt can enable a user to
perform all the required tasks for configuring the host for a VM: allocating
resources, running the VM, shutting it down and deallocating the resources,
without requiring shell access or any other control channel.

Libvirt supports the following storage pool types:

.. contents::

Directory pool
--------------

A pool with a type of ``dir`` provides the means to manage files within a
directory. The files can be fully allocated raw files, sparsely allocated raw
files, or one of the special disk formats such as ``qcow2``, ``vmdk``, etc as
supported by the ``qemu-img`` program. If the directory does not exist at the
time the pool is defined, the ``build`` operation can be used to create it.

Example directory pool input definition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="dir">
     <name>virtimages</name>
     <target>
       <path>/var/lib/virt/images</path>
     </target>
   </pool>

Valid directory pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The directory pool does not use the pool format type element.

Valid directory volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One of the following options:

-  ``raw``: a plain file

-  ``bochs``: Bochs disk image format

-  ``cloop``: compressed loopback disk image format

-  ``cow``: User Mode Linux disk image format

-  ``dmg``: Mac disk image format

-  ``iso``: CDROM disk image format

-  ``qcow``: QEMU v1 disk image format

-  ``qcow2``: QEMU v2 disk image format

-  ``qed``: QEMU Enhanced Disk image format

-  ``vmdk``: VMware disk image format

-  ``vpc``: VirtualPC disk image format

When listing existing volumes all these formats are supported natively. When
creating new volumes, only a subset may be available. The ``raw`` type is
guaranteed always available. The ``qcow2`` type can be created if the
``qemu-img`` tool is present. The others are dependent on support of the
``qemu-img`` tool.

Filesystem pool
---------------

This is a variant of the directory pool. Instead of creating a directory on an
existing mounted filesystem though, it expects a source block device to be
named. This block device will be mounted and files managed in the directory of
its mount point. It will default to allowing the kernel to automatically
discover the filesystem type, though it can be specified manually if required.

Example filesystem pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="fs">
     <name>virtimages</name>
     <source>
       <device path="/dev/VolGroup00/VirtImages"/>
     </source>
     <target>
       <path>/var/lib/virt/images</path>
     </target>
   </pool>

Valid filesystem pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The filesystem pool supports the following formats:

-  ``auto`` - automatically determine format

-  ``ext2``

-  ``ext3``

-  ``ext4``

-  ``ufs``

-  ``iso9660``

-  ``udf``

-  ``gfs``

-  ``gfs2``

-  ``vfat``

-  ``hfs+``

-  ``xfs``

-  ``ocfs2``

-  ``vmfs``

Valid filesystem volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The valid volume types are the same as for the ``directory`` pool type.

Network filesystem pool
-----------------------

This is a variant of the filesystem pool. Instead of requiring a local block
device as the source, it requires the name of a host and path of an exported
directory. It will mount this network filesystem and manage files within the
directory of its mount point. It will default to using ``auto`` as the protocol,
which generally tries a mount via NFS first.

Example network filesystem pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="netfs">
     <name>virtimages</name>
     <source>
       <host name="nfs.example.com"/>
       <dir path="/var/lib/virt/images"/>
       <format type='nfs'/>
     </source>
     <target>
       <path>/var/lib/virt/images</path>
     </target>
   </pool>

Valid network filesystem pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The network filesystem pool supports the following formats:

-  ``auto`` - automatically determine format

-  ``nfs``

-  ``glusterfs`` - use the glusterfs FUSE file system. For now, the ``dir``
   specified as the source can only be a gluster volume name, as gluster does
   not provide a way to directly mount subdirectories within a volume. (To
   bypass the file system completely, see the `Gluster pool`_).

-  ``cifs`` - use the SMB (samba) or CIFS file system. The mount will use "-o
   guest" to mount the directory anonymously.

Valid network filesystem volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The valid volume types are the same as for the ``directory`` pool type.

Logical volume pool
-------------------

This provides a pool based on an LVM volume group. For a pre-defined LVM volume
group, simply providing the group name is sufficient, while to build a new group
requires providing a list of source devices to serve as physical volumes.
Volumes will be allocated by carving out chunks of storage from the volume
group.

Example logical pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="logical">
     <name>HostVG</name>
     <source>
       <device path="/dev/sda1"/>
       <device path="/dev/sdb1"/>
       <device path="/dev/sdc1"/>
     </source>
     <target>
       <path>/dev/HostVG</path>
     </target>
   </pool>

Valid logical pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The logical volume pool supports only the ``lvm2`` format, although not
supplying a format value will result in automatic selection of the\ ``lvm2``
format.

Valid logical volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The logical volume pool does not use the volume format type element.

Disk pool
---------

This provides a pool based on a physical disk. Volumes are created by adding
partitions to the disk. Disk pools have constraints on the size and placement of
volumes. The 'free extents' information will detail the regions which are
available for creating new volumes. A volume cannot span across two different
free extents. It will default to using ``dos`` as the pool source format.

Example disk pool input
~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="disk">
     <name>sda</name>
     <source>
       <device path='/dev/sda'/>
     </source>
     <target>
       <path>/dev</path>
     </target>
   </pool>

Valid disk pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The disk volume pool accepts the following pool format types, representing the
common partition table types:

-  ``dos``

-  ``dvh``

-  ``gpt``

-  ``mac``

-  ``bsd``

-  ``pc98``

-  ``sun``

-  ``lvm2``

The formats ``dos`` ("msdos" in parted terminology, good for BIOS systems) or
``gpt`` (good for UEFI systems) are recommended for best portability - the
latter is needed for disks larger than 2TB. Note that the ``lvm2`` format refers
to the physical volume format (i.e. the whole disk is a physical volume - not
the usual usage of LVM where physical volumes are partitions). This is not
really a partition table and such pool cannot be built by libvirt, only
detected.

Building a pool of a certain format depends on its availability in ``parted``.

Valid disk volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The disk volume pool accepts the following volume format types, representing the
common partition entry types:

-  ``none``

-  ``linux``

-  ``fat16``

-  ``fat32``

-  ``linux-swap``

-  ``linux-lvm``

-  ``linux-raid``

-  ``extended``

iSCSI pool
----------

This provides a pool based on an iSCSI target. Volumes must be pre-allocated on
the iSCSI server, and cannot be created via the libvirt APIs. Since /dev/XXX
names may change each time libvirt logs into the iSCSI target, it is recommended
to configure the pool to use ``/dev/disk/by-path`` or ``/dev/disk/by-id`` for
the target path. These provide persistent stable naming for LUNs

The libvirt iSCSI storage backend does not resolve the provided host name or IP
address when finding the available target IQN's on the host; therefore, defining
two pools to use the same IQN on the same host will fail the duplicate source
pool checks.

Example iSCSI pool input
~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="iscsi">
     <name>virtimages</name>
     <source>
       <host name="iscsi.example.com"/>
       <device path="iqn.2013-06.com.example:iscsi-pool"/>
     </source>
     <target>
       <path>/dev/disk/by-path</path>
     </target>
   </pool>

Valid iSCSI pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The iSCSI volume pool does not use the pool format type element.

Valid iSCSI volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The iSCSI volume pool does not use the volume format type element.

iSCSI direct pool
-----------------

This is a variant of the iSCSI pool. Instead of using iscsiadm, it uses
libiscsi. It requires a host, a path which is the target IQN, and an initiator
IQN.

Example iSCSI direct pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="iscsi-direct">
     <name>virtimages</name>
     <source>
       <host name="iscsi.example.com"/>
       <device path="iqn.2013-06.com.example:iscsi-pool"/>
       <initiator>
         <iqn name="iqn.2013-06.com.example:iscsi-initiator"/>
       </initiator>
     </source>
   </pool>

Valid iSCSI direct pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The iSCSI direct volume pool does not use the pool format type element.

Valid iSCSI direct volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The iSCSI direct volume pool does not use the volume format type element.

SCSI pool
---------

This provides a pool based on a SCSI HBA. Volumes are preexisting SCSI LUNs, and
cannot be created via the libvirt APIs. Since /dev/XXX names aren't generally
stable, it is recommended to configure the pool to use ``/dev/disk/by-path`` or
``/dev/disk/by-id`` for the target path. These provide persistent stable naming
for LUNs :since:`Since 0.6.2`

Example SCSI pool input
~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="scsi">
     <name>virtimages</name>
     <source>
       <adapter name="host0"/>
     </source>
     <target>
       <path>/dev/disk/by-path</path>
     </target>
   </pool>

Valid SCSI pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The SCSI volume pool does not use the pool format type element.

Valid SCSI volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The SCSI volume pool does not use the volume format type element.

Multipath pool
--------------

This provides a pool that contains all the multipath devices on the host.
Therefore, only one Multipath pool may be configured per host. Volume creating
is not supported via the libvirt APIs. The target element is actually ignored,
but one is required to appease the libvirt XML parser.

Configuring multipathing is not currently supported, this just covers the case
where users want to discover all the available multipath devices, and assign
them to guests. :since:`Since 0.7.1`

Example multipath pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="mpath">
     <name>virtimages</name>
     <target>
       <path>/dev/mapper</path>
     </target>
   </pool>

Valid multipath pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Multipath volume pool does not use the pool format type element.

Valid multipath volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Multipath volume pool does not use the volume format type element.

RBD pool
--------

This storage driver provides a pool which contains all RBD images in a RADOS
pool. RBD (RADOS Block Device) is part of the Ceph distributed storage project.

This backend *only* supports QEMU with RBD support. Kernel RBD which exposes RBD
devices as block devices in /dev is *not* supported. RBD images created with
this storage backend can be accessed through kernel RBD if configured manually,
but this backend does not provide mapping for these images.

Images created with this backend can be attached to QEMU guests when QEMU is
build with RBD support (Since QEMU 0.14.0). The backend supports cephx
authentication for communication with the Ceph cluster. Storing the cephx
authentication key is done with the libvirt secret mechanism. The UUID in the
example pool input refers to the UUID of the stored secret.

The port attribute for a Ceph monitor does not have to be provided. If not
provided librados will use the default Ceph monitor port. :since:`Since 0.9.13`

Example RBD pool input
~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="rbd">
     <name>myrbdpool</name>
     <source>
       <name>rbdpool</name>
       <host name='1.2.3.4'/>
       <host name='my.ceph.monitor'/>
       <host name='third.ceph.monitor' port='6789'/>
       <auth username='admin' type='ceph'>
         <secret uuid='2ec115d7-3a88-3ceb-bc12-0ac909a6fd87'/>
       </auth>
     </source>
   </pool>

Example RBD volume output
~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <volume>
     <name>myvol</name>
     <key>rbd/myvol</key>
     <source>
     </source>
     <capacity unit='bytes'>53687091200</capacity>
     <allocation unit='bytes'>53687091200</allocation>
     <target>
       <path>rbd:rbd/myvol</path>
       <format type='unknown'/>
       <permissions>
         <mode>00</mode>
         <owner>0</owner>
         <group>0</group>
       </permissions>
     </target>
   </volume>

Example RBD disk attachment
~~~~~~~~~~~~~~~~~~~~~~~~~~~

RBD images can be attached to QEMU guests when QEMU is built with RBD support.
Information about attaching a RBD image to a guest can be found at `format
domain <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ page.

Valid RBD pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The RBD pool does not use the pool format type element.

Valid RBD volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Only raw volumes are supported.

Sheepdog pool
-------------

This provides a pool based on a Sheepdog Cluster. Sheepdog is a distributed
storage system for QEMU/KVM. It provides highly available block level storage
volumes that can be attached to QEMU/KVM virtual machines. The cluster must
already be formatted. :since:`Introduced in 0.9.13` :removed:`removed in 8.8.0.`

Example Sheepdog pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="sheepdog">
     <name>mysheeppool</name>
     <source>
       <name>mysheeppool</name>
       <host name='localhost' port='7000'/>
     </source>
   </pool>

Example Sheepdog volume output
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   <volume>
     <name>myvol</name>
     <key>sheep/myvol</key>
     <source>
     </source>
     <capacity unit='bytes'>53687091200</capacity>
     <allocation unit='bytes'>53687091200</allocation>
     <target>
       <path>sheepdog:myvol</path>
       <format type='unknown'/>
       <permissions>
         <mode>00</mode>
         <owner>0</owner>
         <group>0</group>
       </permissions>
     </target>
   </volume>

Example Sheepdog disk attachment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sheepdog images can be attached to QEMU guests. Information about attaching a
Sheepdog image to a guest can be found at the `format
domain <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ page.

Valid Sheepdog pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Sheepdog pool does not use the pool format type element.

Valid Sheepdog volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Sheepdog pool does not use the volume format type element.

Gluster pool
------------

This provides a pool based on native Gluster access. Gluster is a distributed
file system that can be exposed to the user via FUSE, NFS or SMB (see the
`Network filesystem pool`_ for that usage); but for minimal overhead,
the ideal access is via native access (only possible for QEMU/KVM compiled with
libgfapi support). The cluster and storage volume must already be running, and
it is recommended that the volume be configured with
``gluster       volume set $volname storage.owner-uid=$uid`` and
``gluster volume set $volname       storage.owner-gid=$gid`` for the uid and gid
that qemu will be run as. It may also be necessary to set
``rpc-auth-allow-insecure on`` for the glusterd service, as well as
``gluster set $volname       server.allow-insecure on``, to allow access to the
gluster volume. :since:`Since 1.2.0`

Example Gluster pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~

A gluster volume corresponds to a libvirt storage pool. If a gluster volume
could be mounted as ``mount -t glusterfs       localhost:/volname /some/path``,
then the following example will describe the same pool without having to create
a local mount point. Remember that with gluster, the mount point can be through
any machine in the cluster, and gluster will automatically pick the ideal
transport to the actual bricks backing the gluster volume, even if on a
different host than the one named in the ``host`` designation. The ``<name>``
element is always the volume name (no slash). The pool source also supports an
optional ``<dir>`` element with a ``path`` attribute that lists the absolute
name of a subdirectory relative to the gluster volume to use instead of the
top-level directory of the volume.

::

   <pool type="gluster">
     <name>myglusterpool</name>
     <source>
       <name>volname</name>
       <host name='localhost'/>
       <dir path='/'/>
     </source>
   </pool>

Example Gluster volume output
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Libvirt storage volumes associated with a gluster pool correspond to the files
that can be found when mounting the gluster volume. The ``name`` is the path
relative to the effective mount specified for the pool; and the ``key`` is a
string that identifies a single volume uniquely. Currently the ``key`` attribute
consists of the URI of the volume but it may be changed to a UUID of the volume
in the future.

::

   <volume>
     <name>myfile</name>
     <key>gluster://localhost/volname/myfile</key>
     <source>
     </source>
     <capacity unit='bytes'>53687091200</capacity>
     <allocation unit='bytes'>53687091200</allocation>
   </volume>

Example Gluster disk attachment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Files within a gluster volume can be attached to QEMU guests. Information about
attaching a Gluster image to a guest can be found at the `format
domain <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ page.

Valid Gluster pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Gluster pool does not use the pool format type element.

Valid Gluster volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The valid volume types are the same as for the ``directory`` pool type.

ZFS pool
--------

This provides a pool based on the ZFS filesystem. Initially it was developed for
FreeBSD, and :since:`since 1.3.2` experimental support for `ZFS on
Linux <https://zfsonlinux.org/>`__ version 0.6.4 or newer is available.

A pool could either be created manually using the ``zpool create`` command and
its name specified in the source section or :since:` since 1.2.9` source devices
could be specified to create a pool using libvirt.

Please refer to the ZFS documentation for details on a pool creation.

:since:`Since 1.2.8`

Example ZFS pool input
~~~~~~~~~~~~~~~~~~~~~~

::

   <pool type="zfs">
     <name>myzfspool</name>
     <source>
       <name>zpoolname</name>
       <device path="/dev/ada1"/>
       <device path="/dev/ada2"/>
     </source>
   </pool>

Valid ZFS pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ZFS volume pool does not use the pool format type element.

Valid ZFS volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ZFS volume pool does not use the volume format type element.

Vstorage pool
-------------

This provides a pool based on Virtuozzo storage. Virtuozzo Storage is a highly
available distributed software-defined storage with built-in replication and
disaster recovery. More detailed information about Virtuozzo storage and its
management can be found here: `Virtuozzo
Storage <https://openvz.org/Virtuozzo_Storage>`__).

Please refer to the Virtuozzo Storage documentation for details on storage
management and usage.

Example vstorage pool input
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to create storage pool with Virtuozzo Storage backend you have to
provide cluster name and be authorized within the cluster.

::

   <pool type="vstorage">
     <name>myvstoragepool</name>
     <source>
       <name>clustername</name>
     </source>
     <target>
       <path>/mnt/clustername</path>
     </target>
   </pool>

Valid vstorage pool format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Vstorage volume pool does not use the pool format type element.

Valid vstorage volume format types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The valid volume types are the same as for the directory pool.
