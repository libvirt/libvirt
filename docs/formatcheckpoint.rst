.. role:: since

Checkpoint XML format
=====================

.. contents::

Checkpoint XML
--------------

One method of capturing domain disk backups is via the use of incremental
backups. Right now, incremental backups are only supported for the QEMU
hypervisor when using qcow2 disks at the active layer; if other disk formats are
in use, capturing disk backups requires different libvirt APIs (see `domain
state capture <kbase/domainstatecapture.html>`__ for a comparison between APIs).

Libvirt is able to facilitate incremental backups by tracking disk checkpoints,
which are points in time against which it is easy to compute which portion of
the disk has changed. Given a full backup (a backup created from the creation of
the disk to a given point in time), coupled with the creation of a disk
checkpoint at that time, and an incremental backup (a backup created from just
the dirty portion of the disk between the first checkpoint and the second backup
operation), it is possible to do an offline reconstruction of the state of the
disk at the time of the second backup without having to copy as much data as a
second full backup would require. Most disk checkpoints are created in
conjunction with a backup via ``virDomainBackupBegin()``, although a future API
addition of ``virDomainSnapshotCreateXML2()`` will also make this possible when
creating external snapshots; however, libvirt also exposes enough support to
create disk checkpoints independently from a backup operation via
``virDomainCheckpointCreateXML()`` since 5.6.0. Likewise, the creation of
checkpoints when external snapshots exist is currently forbidden, although
future work will make it possible to integrate these two concepts.

Attributes of libvirt checkpoints are stored as child elements of the
``domaincheckpoint`` element. At checkpoint creation time, normally only the
``name``, ``description``, and ``disks`` elements are settable. The rest of the
fields are ignored on creation and will be filled in by libvirt in for
informational purposes by ``virDomainCheckpointGetXMLDesc()``. However, when
redefining a checkpoint, with the ``VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE`` flag
of ``virDomainCheckpointCreateXML()``, all of the XML fields described here are
relevant on input, even the fields that are normally described as readonly for
output.

The top-level ``domaincheckpoint`` element may contain the following elements:

``name``
   The optional name for this checkpoint. If the name is omitted, libvirt will
   create a name based on the time of the creation.

``description``
   An optional human-readable description of the checkpoint. If the description
   is omitted when initially creating the checkpoint, then this field will be
   empty.

``disks``
   On input, this is an optional listing of specific instructions for disk
   checkpoints; it is needed when making a checkpoint on only a subset of the
   disks associated with a domain. In particular, since QEMU checkpoints require
   qcow2 disks, this element may be needed on input for excluding guest disks
   that are not in qcow2 format. If the entire element was omitted on input,
   then all disks participate in the checkpoint, otherwise, only the disks
   explicitly listed which do not also use ``checkpoint='no'`` will participate.
   On output, this is the checkpoint state of each of the domain's disks.

   ``disk``
      This sub-element describes the checkpoint properties of a specific disk
      with the following attributes:

      ``name``
         A mandatory attribute which must match either the
         ``<target dev='name'/>`` or an unambiguous ``<source file='name'/>`` of
         one of the `disk devices <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ specified
         for the domain at the time of the checkpoint.

      ``checkpoint``
         An optional attribute; possible values are ``no`` when the disk does
         not participate in this checkpoint; or ``bitmap`` if the disk will
         track all changes since the creation of this checkpoint via a bitmap.

      ``bitmap``
         The attribute ``bitmap`` is only valid if ``checkpoint='bitmap'``; it
         describes the name of the tracking bitmap (defaulting to the checkpoint
         name).

      ``size``
         The attribute ``size`` is ignored on input; on output, it is only
         present if the ``VIR_DOMAIN_CHECKPOINT_XML_SIZE`` flag was used to
         perform a dynamic query of the estimated size in bytes of the changes
         made since the checkpoint was created.

         Note that updating the backup ``size`` may be expensive and
         the actual required size may increase if the guest OS is actively
         writing to the disk.

``creationTime``
   A readonly representation of the time this checkpoint was created. The time
   is specified in seconds since the Epoch, UTC (i.e. Unix time).

``parent``
   Readonly, present if this checkpoint has a parent. The parent name is given
   by the sub-element ``name``. The parent relationship allows tracking a list
   of related checkpoints.

``domain``
   A readonly representation of the inactive `domain
   configuration <formatdomain.html>`__ at the time the checkpoint was created.
   This element may be omitted for output brevity by supplying the
   ``VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN`` flag. The domain will have
   security-sensitive information omitted unless the flag
   ``VIR_DOMAIN_CHECKPOINT_XML_SECURE`` is provided on a read-write connection.

   ``virDomainCheckpointCreateXML()`` requires that the ``<domain>`` is present
   when used with ``VIR_DOMAIN_CHECKPOINT_CREATE_REDEFINE``.
   :since:`Since 7.0.0` the ``<domain>`` element can be omitted when redefining
   a checkpoint, but hypervisors may not support certain operations if it's
   missing.

Examples
--------

Using this XML to create a checkpoint of just vda on a qemu domain with two
disks and a prior checkpoint:

::

   <domaincheckpoint>
     <description>Completion of updates after OS install</description>
     <disks>
       <disk name='vda' checkpoint='bitmap'/>
       <disk name='vdb' checkpoint='no'/>
     </disks>
   </domaincheckpoint>

will result in XML similar to this from ``virDomainCheckpointGetXMLDesc()``:

::

   <domaincheckpoint>
     <name>1525889631</name>
     <description>Completion of updates after OS install</description>
     <parent>
       <name>1525111885</name>
     </parent>
     <creationTime>1525889631</creationTime>
     <disks>
       <disk name='vda' checkpoint='bitmap' bitmap='1525889631'/>
       <disk name='vdb' checkpoint='no'/>
     </disks>
     <domain type='qemu'>
       <name>fedora</name>
       <uuid>93a5c045-6457-2c09-e56c-927cdf34e178</uuid>
       <memory>1048576</memory>
       ...
       <devices>
         <disk type='file' device='disk'>
           <driver name='qemu' type='qcow2'/>
           <source file='/path/to/file1'/>
           <target dev='vda' bus='virtio'/>
         </disk>
         <disk type='file' device='disk' snapshot='external'>
           <driver name='qemu' type='raw'/>
           <source file='/path/to/file2'/>
           <target dev='vdb' bus='virtio'/>
         </disk>
         ...
       </devices>
     </domain>
   </domaincheckpoint>

With that checkpoint created, the qcow2 image is now tracking all changes that
occur in the image since the checkpoint via the persistent bitmap named
``1525889631``.
