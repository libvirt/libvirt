=========
Snapshots
=========

.. contents::

Manual storage snapshotting
===========================

Certain use cases such as block storage on LVM or disks backed via storage
exported through the ``vhost-user-blk`` protocol may require that snapshots are
done in conjunction with the storage provider which is not managed by **libvirt**.

To achieve this such disks can use ``snapshot`` mode ``manual``. When a snapshot
has a disk in manual mode the following happens:

 #. ``libvirt`` takes snapshot of the VM memory if requested

   #. If a live snapshot is requested (``VIR_DOMAIN_SNAPSHOT_CREATE_LIVE``) the
      VM runs until the memory snapshot phase completes and is then paused.
   #. Otherwise the VM is paused right away.

 #. Snapshot of disks which are marked for external snapsot is executed
 #. The API return success, the VM is paused.
 #. The user snapshots the externally managed storage
 #. The user resumes the execution of the VM (``virsh resume $VM``)

Overview of manual snapshots
----------------------------

Manual snapshot of a disk is requested by setting the ``snapshot`` property to
``manual`` in the snapshot XML ::

  <domainsnapshot>
    <memory file='/path/to/memory/img'/>
    <disks>
      <disk name='vda' snapshot='manual'/>
      <disk name='vdb' snapshot='external'/>
      <disk name='vdc' snapshot='no'/>
    </disks>
  </domainsnapshot>

or ``--diskspec vda,snapshot=manual`` when using ``virsh snapshot-create-as``::

  $ virsh snapshot-create-as  --diskspec vda,snapshot=manual \
                              --diskspec vdb,snapshot=external \
                              --diskspec vdc,snapshot=no $VM \
                              --memspec file=/path/to/memory/img
