Backup XML format
=================

.. contents::

Backup XML
----------

Creating a backup, whether full or incremental, is done via
``virDomainBackupBegin()``, which takes an XML description of the actions to
perform, as well as an optional second XML document `describing a
checkpoint <formatcheckpoint.html>`__ to create at the same point in time. See
also `a comparison <kbase/domainstatecapture.html>`__ between the various state
capture APIs.

There are two general modes for backups: a push mode (where the hypervisor
writes out the data to the destination file, which may be local or remote), and
a pull mode (where the hypervisor creates an NBD server that a third-party
client can then read as needed, and which requires the use of temporary storage,
typically local, until the backup is complete).

The instructions for beginning a backup job are provided as attributes and
elements of the top-level ``domainbackup`` element. This element includes an
optional attribute ``mode`` which can be either "push" or "pull" (default push).
``virDomainBackupGetXMLDesc()`` can be used to see the actual values selected
for elements omitted during creation (for example, learning which port the NBD
server is using in the pull model or what file names libvirt generated when none
were supplied). The following child elements and attributes are supported:

``incremental``
   An optional element giving the name of an existing checkpoint of the domain,
   which will be used to make this backup an incremental one. In the push model,
   only changes since the named checkpoint are written to the destination. In
   the pull model, the NBD server uses the NBD_OPT_SET_META_CONTEXT extension to
   advertise to the client which portions of the export contain changes since
   the named checkpoint. If omitted, a full backup is performed.

``server``
   Present only for a pull mode backup. Contains the same attributes as the
   ```protocol`` element of a disk <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ attached
   via NBD in the domain (such as transport, socket, name, port, or tls),
   necessary to set up an NBD server that exposes the content of each disk at
   the time the backup is started.

   Note that for the QEMU hypervisor the TLS environment in controlled using
   ``backup_tls_x509_cert_dir``, ``backup_tls_x509_verify``, and
   ``backup_tls_x509_secret_uuid`` properties in ``/etc/libvirt/qemu.conf``.

``disks``
   An optional listing of instructions for disks participating in the backup (if
   omitted, all disks participate and libvirt attempts to generate filenames by
   appending the current timestamp as a suffix). If the entire element was
   omitted on input, then all disks participate in the backup, otherwise, only
   the disks explicitly listed which do not also use ``backup='no'`` will
   participate. On output, this is the state of each of the domain's disk in
   relation to the backup operation.

   ``disk``
      This sub-element describes the backup properties of a specific disk, with
      the following attributes and child elements:

      ``name``
         A mandatory attribute which must match the ``<target dev='name'/>`` of
         one of the `disk devices <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ specified
         for the domain at the time of the checkpoint.

      ``backup``
         Setting this attribute to ``yes``\ (default) specifies that the disk
         should take part in the backup and using ``no`` excludes the disk from
         the backup.

      ``backupmode``
         This attribute overrides the implied backup mode inherited from the
         definition of the backup itself. Value ``full`` forces a full backup
         even if the backup calls for an incremental backup, and ``incremental``
         coupled with the attribute ``incremental='CHECKPOINTNAME`` for the disk
         forces an incremental backup from ``CHECKPOINTNAME``.

       ``incremental``
         An optional attribute giving the name of an existing checkpoint of the
         domain which overrides the one set by the ``<incremental>`` element.

      ``exportname``
         Allows modification of the NBD export name for the given disk. By
         default equal to disk target. Valid only for pull mode backups.

      ``exportbitmap``
         Allows modification of the name of the bitmap describing dirty blocks
         for an incremental backup exported via NBD export name for the given
         disk. Valid only for pull mode backups.

      ``type``
         A mandatory attribute to describe the type of the disk, except when
         ``backup='no'`` is used. Valid values include ``file``, or ``block``.
         Similar to a disk declaration for a domain, the choice of type controls
         what additional sub-elements are needed to describe the destination.

      ``index``
         Output only. The value can be used to refer to the scratch or output
         file of the backup in APIs such as ``virDomainSetBlockThreshold``.

      ``target``
         Valid only for push mode backups, this is the primary sub-element that
         describes the file name of the backup destination, similar to the
         ``source`` sub-element of a domain disk. An optional sub-element
         ``driver`` can also be used, with an attribute ``type`` to specify a
         destination format different from qcow2. See documentation for
         ``scratch`` below for additional configuration.

      ``scratch``
         Valid only for pull mode backups, this is the primary sub-element that
         describes the file name of the local scratch file to be used in
         facilitating the backup, and is similar to the ``source`` sub-element
         of a domain disk. Currently only ``file`` and ``block`` scratch storage
         is supported. The ``file`` scratch file is created and deleted by
         libvirt in the given location. A ``block`` scratch device must exist
         prior to starting the backup and is formatted. The block device must
         have enough space for the corresponding disk data including format
         overhead. If ``VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL`` flag is used
         the file for a scratch of ``file`` type must exist with the correct
         format and size to hold the copy and is used without modification. The
         file is not deleted after the backup but the contents of the file don't
         make sense outside of the backup. The same applies for the block device
         which must be formatted appropriately. Similarly to the domain
         ```disk`` <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ definition ``scratch``
         and ``target`` can contain ``seclabel`` and/or ``encryption``
         subelements to configure the corresponding properties.

Examples
--------

Use ``virDomainBackupBegin()`` to perform a full backup using push mode. The
example lets libvirt pick the destination and format for 'vda', fully specifies
that we want a raw backup of 'vdb', and omits 'vdc' from the operation.

::

   <domainbackup>
     <disks>
       <disk name='vda' backup='yes'/>
       <disk name='vdb' type='file'>
         <target file='/path/to/vdb.backup'/>
         <driver type='raw'/>
       </disk>
       <disk name='vdc' backup='no'/>
     </disks>
   </domainbackup>

If the previous full backup also passed a parameter describing `checkpoint
XML <formatcheckpoint.html>`__ that resulted in a checkpoint named
``1525889631``, we can make another call to ``virDomainBackupBegin()`` to
perform an incremental backup of just the data changed since that checkpoint,
this time using the following XML to start a pull model export of the 'vda' and
'vdb' disks, where a third-party NBD client connecting to '/path/to/server'
completes the backup (omitting 'vdc' from the explicit list has the same effect
as the backup='no' from the previous example):

::

   <domainbackup mode="pull">
     <incremental>1525889631</incremental>
     <server transport="unix" socket="/path/to/server"/>
     <disks>
       <disk name='vda' backup='yes' type='file'>
         <scratch file='/path/to/file1.scratch'/>
       </disk>
     </disks>
   </domainbackup>
