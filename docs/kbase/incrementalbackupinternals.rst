================================================
Internals of incremental backup handling in qemu
================================================

.. contents::

Libvirt's implementation of incremental backups in the ``qemu`` driver uses
qemu's ``block-dirty-bitmaps`` under the hood to track the guest visible disk
state changes corresponding to the points in time described by a libvirt
checkpoint.

There are some semantica implications with how libvirt creates and manages the
bitmaps which de-facto become API as they are written into the disk images, and
this document will try to summarize them.

Glossary
========

See the knowledge base article on
`domain state capture <https://libvirt.org/kbase/domainstatecapture.html>`_ for
a deeper explanation of some of the concepts.

Checkpoint

    A libvirt object which represents a named point in time of the life of the
    vm where libvirt tracks writes the VM has done, thereby allowing a backup of
    only the blocks which changed. Note that state of the VM memory is _not_
    captured.

    A checkpoint can be created either explicitly via the corresponding API
    (although this isn't very useful on its own), or simultaneously with an
    incremental or full backup of the VM using the ``virDomainBackupBegin`` API
    which allows a next backup to only copy the differences.

Backup

    A copy of either all blocks of selected disks (full backup) or blocks changed
    since a checkpoint (incremental backup) at the time the backup job was
    started. (Blocks modified while the backup job is running are not part of the
    backup!)

Snapshot

    Similarly to a checkpoint it's a point in time in the lifecycle of the VM
    but the state of the VM including memory is captured at that point allowing
    returning to the state later.

Blockjob

    A long running job which modifies the shape and/or location of the disk
    backing chain (images storing the disk contents). Libvirt supports
    ``block pull`` where data is moved up the chain towards the active layer,
    ``block commit`` where data is moved down the chain towards the base/oldest
    image. These blockjobs always remove images from the backing chain. Lastly
    ``block copy`` where image is moved to a different location (and possibly
    collapsed moving all of the data into the new location into the one image).

block-dirty-bitmap (bitmap)

    A data structure in qemu tracking which blocks were written by the guest
    OS since the bitmap was created.

Relationships of bitmaps, checkpoints and VM disks
==================================================

When a checkpoint is created libvirt creates a block-dirty-bitmap for every
configured VM disk named the same way as the chcheckpoint. The bitmap is
actively recording which blocks were changed by the guest OS from that point on.
Other bitmaps are not impacted by any way as they are self-contained:

::

 +----------------+       +----------------+
 | disk: vda      |       | disk: vdb      |
 +--------+-------+       +--------+-------+
          |                        |
 +--------v-------+       +--------v-------+
 | vda-1.qcow2    |       | vdb-1.qcow2    |
 |                |       |                |
 | bitmaps: chk-a |       | bitmaps: chk-a |
 |          chk-b |       |          chk-b |
 |                |       |                |
 +----------------+       +----------------+

Bitmaps are created at the same time to track changes to all disks in sync and
are active and persisted in the QCOW2 image. Other formats currently don't
support this feature.

Modification of bitmaps outside of libvirt is not recommended, but when adhering
to the same semantics which the document will describe it should be safe to do
so, even if we obviously can't guarantee that.


Integration with external snapshots
===================================

External snapshot terminology
-----------------------------

External snapshots on a disk level consist of layered chains of disk images. An
image in the chain can have a ``backing image`` placed below. Any chunk in the
current image which was not written explicitly is transparent and if read the
data from the backing image is passed through. An image placed on top of the
current image is called ``overlay``.

The bottommost backing image at the end of the chain is also usually described
as ``base image``.

The topmost overlay is the image which is being written to by the VM and is also
described as the ``active`` layer or image.

Handling of bitmaps
-------------------

Creating an external snapshot involves adding a new layer to the backing chain
on top of the previous chain. In this step there are no new bitmaps created by
default, which would mean that backups become impossible after this step.

To prevent this from happening we need to re-create the active bitmaps in the
new top/active layer of the backing chain which allows us to continue tracking
the changes with same granularity as before and also allows libvirt to stitch
together all the corresponding bitmaps to do a backup across snapshots.

After taking a snapshot of the ``vda`` disk from the example above placed into
``vda-2.qcow2`` the following topology will be created:

::

   +----------------+
   | disk: vda      |
   +-------+--------+
           |
   +-------v--------+    +----------------+
   | vda-2.qcow2    |    | vda-1.qcow2    |
   |                |    |                |
   | bitmaps: chk-a +----> bitmaps: chk-a |
   |          chk-b |    |          chk-b |
   |                |    |                |
   +----------------+    +----------------+

Checking bitmap health
----------------------

QEMU optimizes disk writes by only updating the bitmaps in certain cases. This
also can cause problems in cases when e.g. QEMU crashes.

For a chain of corresponding bitmaps in a backing chain to be considered valid
and eligible for use with ``virDomainBackupBegin`` it must conform to the
following rules:

1) Top image must contain the bitmap
2) If any of the backing images in the chain contain the bitmap too, all
   contiguous images must have the bitmap (no gaps)
3) all of the above bitmaps must be marked as active
   (``auto`` flag in ``qemu-img`` output, ``recording`` in qemu)
4) none of the above bitmaps can be inconsistent
   (``in-use`` flag in ``qemu-img`` provided that it's not used on image which
   is currently in use by a qemu instance, or ``inconsistent`` in qemu)

::

 # check that image has bitmaps
  $ qemu-img info vda-1.qcow2
   image: vda-1.qcow2
   file format: qcow2
   virtual size: 100 MiB (104857600 bytes)
   disk size: 220 KiB
   cluster_size: 65536
   Format specific information:
       compat: 1.1
       compression type: zlib
       lazy refcounts: false
       bitmaps:
           [0]:
               flags:
                   [0]: in-use
                   [1]: auto
               name: chk-a
               granularity: 65536
           [1]:
               flags:
                   [0]: auto
               name: chk-b
               granularity: 65536
       refcount bits: 16
       corrupt: false

(See also the ``qemuBlockBitmapChainIsValid`` helper method in
``src/qemu/qemu_block.c``)

Creating external snapshots manually
--------------------------------------

To create the same topology outside of libvirt (e.g when doing snapshots offline)
a new ``qemu-img`` which supports the ``bitmap`` subcommand is recommended. The
following algorithm then ensures that the new image after snapshot will work
with backups (note that ``jq`` is a JSON processor):

::

  #!/bin/bash

  # arguments
  SNAP_IMG="vda-2.qcow2"
  BACKING_IMG="vda-1.qcow2"

  # constants - snapshots and bitmaps work only with qcow2
  SNAP_FMT="qcow2"
  BACKING_IMG_FMT="qcow2"

  # create snapshot overlay
  qemu-img create -f "$SNAP_FMT" -F "$BACKING_IMG_FMT" -b "$BACKING_IMG" "$SNAP_IMG"

  BACKING_IMG_INFO=$(qemu-img info --output=json -f "$BACKING_IMG_FMT" "$BACKING_IMG")
  BACKING_BITMAPS=$(jq '."format-specific".data.bitmaps' <<< "$BACKING_IMG_INFO")

  if [ "x$BACKING_BITMAPS" = "xnull" ]; then
      exit 0
  fi

  for BACKING_BITMAP_ in $(jq -c '.[]' <<< "$BACKING_BITMAPS"); do
      BITMAP_FLAGS=$(jq -c -r '.flags[]' <<< "$BACKING_BITMAP_")
      BITMAP_NAME=$(jq -r '.name' <<< "$BACKING_BITMAP_")

      if grep 'in-use' <<< "$BITMAP_FLAGS" ||
         grep -v 'auto' <<< "$BITMAP_FLAGS"; then
         continue
      fi

      qemu-img bitmap -f "$SNAP_FMT" "$SNAP_IMG" --add "$BITMAP_NAME"

  done
