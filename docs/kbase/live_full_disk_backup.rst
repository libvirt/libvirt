===============================
Efficient live full disk backup
===============================

.. contents::

Overview
========

Live full disk backups are preferred in many scenarios, *despite* their
space requirements.  The following outlines an efficient method to do
that using libvirt's APIs.  This method involves concepts: the notion of
`backing chains <https://libvirt.org/kbase/backing_chains.html>`_,
`QCOW2 overlays
<https://qemu.readthedocs.io/en/latest/interop/live-block-operations.html#disk-image-backing-chain-notation>`_,
and a special operation called "active block-commit", which allows
live-merging an overlay disk image into its backing file.

Two kinds of backup: "push" and "pull"
======================================

QEMU and libvirt combine the concept of `bitmaps
<https://qemu-project.gitlab.io/qemu/interop/bitmaps.html>`_ and network
block device (NBD) to allow copying out modified data blocks.  There are
two approaches to it:  In the first, "push mode", when a user requests
for it, libvirt creates a full backup in an external location (i.e.
libvirt "pushes" the data to the target).

In the other, "pull mode", libvirt (in coordination with QEMU) exposes
the data that needs to be written out and allows a third-party tool to
copy them out reliably (i.e. the data is being "pulled" from libvirt).
The pull-based backup provides more flexibility by letting an external
tool fetch the modified bits as it sees fit, rather than waiting on
libvirt to push out a full backup to a target location.

The push- and pull-mode techniques also apply for differential backups
(it also includes incremental backups), which track what has changed
since *any* given backup.

This document covers only the full backups using the "push" mode.


Full disk backup using "push" mode
==================================

The below approach uses the modern backup API, virDomainBackupBegin().
This requires libvirt-7.2.0 and QEMU-4.2, or higher versions.

#. Start the guest::

    $> virsh start vm1
    Domain 'vm1' started

#. Enumerate the disk(s) in use::

    $> virsh domblklist vm1
     Target   Source
    --------------------------------------
     vda      /var/lib/libvirt/images/vm1.qcow2

#. Begin the backup::

    $> virsh backup-begin vm1
    Backup started

#. Check the job status ("None" means the job has likely completed)::

    $> virsh domjobinfo vm1
    Job type:         None

#. Check the completed job status::

    $> virsh domjobinfo vm1 --completed
    Job type:         Completed
    Operation:        Backup
    Time elapsed:     183          ms
    File processed:   39.250 MiB
    File remaining:   0.000 B
    File total:       39.250 MiB

#. Now we see the copy of the backup::

    $> ls -lash /var/lib/libvirt/images/vm1.qcow2*
    15M -rw-r--r--. 1 qemu qemu 15M May 10 12:22 vm1.qcow2
    21M -rw-------. 1 root root 21M May 10 12:23 vm1.qcow2.1620642185


Full backup with older libvirt versions
=======================================

This is the alternative in case you cannot use libvirt-7.2.0 and
QEMU-4.2 for some reason.  But this assumes you're using *at least* QEMU
2.1 and libvirt-1.2.9.

This backup approach is slightly more involved, and predates the
virDomainBackupBegin() API: Assuming a guest with a single disk image,
create a temporary live QCOW2 overlay (commonly called as "external
snapshot") to track the live guest writes.  Then backup the original
disk image while the guest (live QEMU) keeps writing to the temporary
overlay.  Finally, perform the "active block-commit" operation to
live-merge the temporary overlay disk contents into the original image —
i.e. the backing file — and "pivot" the live QEMU process to point to
it.


#. Start with a guest with a single disk image, ``base.raw``, which is
   where the live QEMU is pointing at, and recording the guest writes::

     base.raw (live QEMU)

#. List the current block device(s) in use::

    $ virsh domblklist vm1
    Target     Source
    ------------------------------------------------
    vda        /var/lib/libvirt/images/base.raw

#. Create the live "external disk snapshot" (or more correctly, "an
   overlay")::

    $ virsh snapshot-create-as --domain vm1 overlay1 \
        --diskspec vda,file=/var/lib/libvirt/images/overlay1.qcow2 \
        --disk-only

   The disk image chain looks as follows::

    base.raw <-- overlay1.qcow2 (live QEMU)

  .. note::
    Above, if you have QEMU guest agent installed in your virtual
    machine, use the ``--quiesce`` option with ``virsh
    snapshot-create-as [...]`` to ensure you have a consistent disk
    state.

    Optionally, you can also supply the ``--no-metadata`` option to
    ``virsh snapshot-create-as`` to tell libvirt not track the snapshot
    metadata.  Otherwise, when you decide to merge snapshot overlays,
    you have to explicitly clean the libvirt metadata using ``virsh
    snapshot-delete vm1 --metadata [name|--current]``.

#. Now, take a backup the original image, ``base.raw``, to a different
   location using ``cp`` or ``rsync``::

    $ cp /var/lib/libvirt/images/base.raw
        /export/backups/copy1_base.raw

    # Or:

    $ rsync -avhW --progress /var/lib/libvirt/images/base.raw \
        /export/backups/copy1_base.raw

#. Enumerate the current block device(s) in use, again.  Notice that the
   current disk image in use is the above-created overlay,
   ``overlay1.qcow2``::

    $ virsh domblklist vm1
    Target     Source
    ------------------------------------------------
    vda        vda,file=/var/lib/libvirt/images/overlay1.qcow2

#. Once the backup of the original image completes, now perform the
   "active block-commit" to live-merge the contents of
   ``overlay1.qcow2`` into ``base.raw`` *and* pivot the live QEMU back
   to the original::

    $ virsh blockcommit vm1 vda --active --verbose --pivot

#. After the above operation completes, again list the current block
   device(s) in use.  And notice that the live QEMU is now writing to
   the original base image::

    $ virsh domblklist vm1
    Target     Source
    ------------------------------------------------
    vda        /var/lib/libvirt/images/base.raw


The final updated disk image "chain" will be a single consolidated
disk::

    [base.raw] (live QEMU)


Now you can safely **discard the overlay image**, ``overlay1.qcow2`` —
it is no longer valid; and its contents are now fully merged into the
base image.
