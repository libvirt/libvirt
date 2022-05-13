.. role:: since

===================
Snapshot XML format
===================

.. contents::

Snapshot XML
------------

Snapshots are one form of `domain state
capture <kbase/domainstatecapture.html>`__. There are several types of
snapshots:

disk snapshot
   Contents of disks (whether a subset or all disks associated with the domain)
   are saved at a given point of time, and can be restored back to that state.
   On a running guest, a disk snapshot is likely to be only crash-consistent
   rather than clean (that is, it represents the state of the disk on a sudden
   power outage, and may need fsck or journal replays to be made consistent); on
   an inactive guest, a disk snapshot is clean if the disks were clean when the
   guest was last shut down. Disk snapshots exist in two forms: internal (file
   formats such as qcow2 track both the snapshot and changes since the snapshot
   in a single file) and external (the snapshot is one file, and the changes
   since the snapshot are in another file).
memory state (or VM state)
   Tracks only the state of RAM and all other resources in use by the VM. If the
   disks are unmodified between the time a VM state snapshot is taken and
   restored, then the guest will resume in a consistent state; but if the disks
   are modified externally in the meantime, this is likely to lead to data
   corruption.
full system
   A combination of disk snapshots for all disks as well as VM memory state,
   which can be used to resume the guest from where it left off with symptoms
   similar to hibernation (that is, TCP connections in the guest may have timed
   out, but no files or processes are lost).

Libvirt can manage all three types of snapshots. For now, VM state (memory)
snapshots are created only by the ``virDomainSave()``, ``virDomainSaveFlags``,
``virDomainSaveParams`` and ``virDomainManagedSave()`` functions, and restored
via the ``virDomainRestore()``, ``virDomainRestoreFlags()``,
``virDomainRestoreParams``, ``virDomainCreate()``, and
``virDomainCreateWithFlags()`` functions (as well as via domain autostart). With
managed snapshots, libvirt tracks all information internally; with save images,
the user tracks the snapshot file, but libvirt provides functions such as
``virDomainSaveImageGetXMLDesc()`` to work with those files.

Full system snapshots are created by ``virDomainSnapshotCreateXML()`` with no
flags, while disk snapshots are created by the same function with the
``VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY`` flag. Regardless of the flags provided,
restoration of the snapshot is handled by the ``virDomainRevertToSnapshot()``
function. For these types of snapshots, libvirt tracks each snapshot as a
separate ``virDomainSnapshotPtr`` object, and maintains a tree relationship of
which snapshots descended from an earlier point in time.

Attributes of libvirt snapshots are stored as child elements of the
``domainsnapshot`` element. At snapshot creation time, normally only the
``name``, ``description``, and ``disks`` elements are settable; the rest of the
fields are ignored on creation, and will be filled in by libvirt in for
informational purposes by ``virDomainSnapshotGetXMLDesc()``. However, when
redefining a snapshot ( :since:`since 0.9.5` ), with the
``VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE`` flag of
``virDomainSnapshotCreateXML()``, all of the XML described here is relevant on
input, even the fields that are normally described as readonly for output.

Snapshots are maintained in a hierarchy. A domain can have a current snapshot,
which is the most recent snapshot compared to the current state of the domain
(although a domain might have snapshots without a current snapshot, if snapshots
have been deleted in the meantime). Creating or reverting to a snapshot sets
that snapshot as current, and the prior current snapshot is the parent of the
new snapshot. Branches in the hierarchy can be formed by reverting to a snapshot
with a child, then creating another snapshot. For now, the creation of external
snapshots when checkpoints exist is forbidden, although future work will make it
possible to integrate these two concepts.

The top-level ``domainsnapshot`` element may contain the following elements:

``name``

   The optional name for this snapshot. If the name is omitted, libvirt will
   create a name based on the time of the creation.

``description``

   An optional human-readable description of the snapshot. If the description
   is omitted when initially creating the snapshot, then this field will be
   empty.

``memory``

   On input, this is an optional request for how to handle VM memory state. For
   an offline domain or a disk-only snapshot, attribute ``snapshot`` must be
   ``no``, since there is no VM state saved; otherwise, the attribute can be
   ``internal`` if the memory state is piggy-backed with other internal disk
   state, or ``external`` along with a second attribute ``file`` giving the
   absolute path of the file holding the VM memory state. :since:`Since 1.0.1`

``disks``

   On input, this is an optional listing of specific instructions for disk
   snapshots; it is needed when making a snapshot of only a subset of the disks
   associated with a domain, or when overriding the domain defaults for how to
   snapshot each disk, or for providing specific control over what file name is
   created in an external snapshot. On output, this is fully populated to show
   the state of each disk in the snapshot, including any properties that were
   generated by the hypervisor defaults. For full system snapshots, this field
   is ignored on input and omitted on output (a full system snapshot implies
   that all disks participate in the snapshot process). This element has a list
   of ``disk`` sub-elements, describing anywhere from zero to all of the disks
   associated with the domain. :since:`Since 0.9.5`

   ``disk``

      This sub-element describes the snapshot properties of a specific disk.
      The attribute ``name`` is mandatory, and must match either the ``<target
      dev='name'/>`` (recommended) or an unambiguous ``<source file='name'/>``
      of one of the `disk devices <formatdomain.html#hard-drives-floppy-disks-cdroms>`__
      specified for the domain at the time of the snapshot. The attribute
      ``snapshot`` is optional, and the possible values are the same as the
      ``snapshot`` attribute for `disk devices
      <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ (``no``, ``internal``, or
      ``external``). Some hypervisors like ESX require that if specified, the
      snapshot mode must not override any snapshot mode attached to the
      corresponding domain disk, while others like qemu allow this field to
      override the domain default.

      :since:`Since 8.2.0` the ``snapshot`` attribute supports the ``manual``
      value which instructs the hypervisor to create the snapshot and keep a
      synchronized state by pausing the VM which allows to snapshot disk
      storage from outside of the hypervisor if the storage provider supports
      it.  The caller is responsible for resuming a VM paused by requesting a
      ``manual`` snapshot. When reverting such snapshot, the expectation is that
      the storage is configured in a way where the hypervisor will see the
      correct image state.

      :since:`Since 1.2.2` the ``disk`` element supports an optional attribute
      ``type`` if the ``snapshot`` attribute is set to ``external``. This
      attribute specifies the snapshot target storage type and allows to
      overwrite the default ``file`` type. The ``type`` attribute along with
      the format of the ``source`` sub-element is identical to the ``source``
      element used in domain disk definitions. See the `disk devices
      <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ section documentation for further
      information. Libvirt currently supports the ``type`` element in the qemu
      driver and supported values are ``file``, ``block`` and ``network``
      :since:`(since 1.2.2)`.

      ``source``

         If the snapshot mode is external (whether specified or inherited),
         then there is an optional sub-element ``source``, with an attribute
         ``file`` giving the name of the new file. If ``source`` is not given
         and the disk is backed by a local image file (not a block device or
         remote storage), a file name is generated that consists of the
         existing file name with anything after the trailing dot replaced by
         the snapshot name. Remember that with external snapshots, the original
         file name becomes the read-only snapshot, and the new file name
         contains the read-write delta of all disk changes since the snapshot.

         The ``source`` element also may contain the ``seclabel`` element
         (described in the `domain XML documentation
         <formatdomain.html#security-label>`__) which can be used to override the
         domain security labeling policy for ``source``.

      ``driver``

         An optional sub-element ``driver``, with an attribute ``type`` giving
         the driver type (such as qcow2), of the new file created by the
         external snapshot of the new file. Optionally ``metadata_cache``
         sub-element can be used with same semantics as the identically named
         subelement of the domain definition disk's driver.

``creationTime``

   A readonly representation of the time this snapshot was created. The time is
   specified in seconds since the Epoch, UTC (i.e. Unix time).

``state``

   A readonly representation of the state of the domain at the time this
   snapshot was taken. If a full system snapshot was created, then this is the
   state of the domain at that time. When the domain is reverted to this
   snapshot, the domain's state will default to this state, unless overridden
   by ``virDomainRevertToSnapshot()`` flags to revert to a running or paused
   state.  Additionally, this field can be the value "disk-snapshot" (
   :since:`since 0.9.5`) when it represents only a disk snapshot (no VM memory
   state), and reverting to this snapshot will default to an inactive guest.

``parent``

   Readonly, present only if this snapshot has a parent. The parent name is
   given by the sub-element ``name``. The parent relationship allows tracking a
   tree of related snapshots.

``domain``

   A readonly representation of the domain that this snapshot was taken
   against.  Older versions of libvirt stored only a single child element,
   uuid; reverting to a snapshot like this is risky if the current state of the
   domain differs from the state that the domain was created in, and requires
   the use of the ``VIR_DOMAIN_SNAPSHOT_REVERT_FORCE`` flag in
   ``virDomainRevertToSnapshot()``.  Newer versions of libvirt ( :since:`since
   0.9.5` ) store the entire inactive `domain configuration
   <formatdomain.html>`__ at the time of the snapshot ( :since:`since 0.9.5` ).
   The domain will have security-sensitive information omitted unless the flag
   ``VIR_DOMAIN_SNAPSHOT_XML_SECURE`` is provided on a read-write connection.

``cookie``

   An optional readonly representation of a save image cookie containing
   additional data libvirt may need to properly restore a domain from an active
   snapshot when such data cannot be stored directly in the ``domain`` to
   maintain compatibility with older libvirt or hypervisor.

Examples
--------

Using this XML to create a disk snapshot of just vda on a qemu domain with two
disks:

::

   <domainsnapshot>
     <description>Snapshot of OS install and updates</description>
     <disks>
       <disk name='vda'>
         <source file='/path/to/new'/>
       </disk>
       <disk name='vdb' snapshot='no'/>
       <disk name='vdc'>
         <source file='/path/to/newc'>
           <seclabel model='dac' relabel='no'/>
         </source>
       </disk>
     </disks>
   </domainsnapshot>

will result in XML similar to this from ``virDomainSnapshotGetXMLDesc()``:

::

   <domainsnapshot>
     <name>1270477159</name>
     <description>Snapshot of OS install and updates</description>
     <state>running</state>
     <creationTime>1270477159</creationTime>
     <parent>
       <name>bare-os-install</name>
     </parent>
     <memory snapshot='no'/>
     <disks>
       <disk name='vda' snapshot='external'>
         <driver type='qcow2'/>
         <source file='/path/to/new'/>
       </disk>
       <disk name='vdb' snapshot='no'/>
     </disks>
     <domain>
       <name>fedora</name>
       <uuid>93a5c045-6457-2c09-e56c-927cdf34e178</uuid>
       <memory>1048576</memory>
       ...
       <devices>
         <disk type='file' device='disk'>
           <driver name='qemu' type='raw'/>
           <source file='/path/to/old'/>
           <target dev='vda' bus='virtio'/>
         </disk>
         <disk type='file' device='disk' snapshot='external'>
           <driver name='qemu' type='raw'/>
           <source file='/path/to/old2'/>
           <target dev='vdb' bus='virtio'/>
         </disk>
         ...
       </devices>
     </domain>
   </domainsnapshot>

With that snapshot created, ``/path/to/old`` is the read-only backing file to
the new active file ``/path/to/new``. The ``<domain>`` element within the
snapshot xml records the state of the domain just before the snapshot; a call to
``virDomainGetXMLDesc()`` will show that the domain has been changed to reflect
the snapshot:

::

   <domain>
     <name>fedora</name>
     <uuid>93a5c045-6457-2c09-e56c-927cdf34e178</uuid>
     <memory>1048576</memory>
     ...
     <devices>
       <disk type='file' device='disk'>
         <driver name='qemu' type='qcow2'/>
         <source file='/path/to/new'/>
         <target dev='vda' bus='virtio'/>
       </disk>
       <disk type='file' device='disk' snapshot='external'>
         <driver name='qemu' type='raw'/>
         <source file='/path/to/old2'/>
         <target dev='vdb' bus='virtio'/>
       </disk>
       ...
     </devices>
   </domain>
