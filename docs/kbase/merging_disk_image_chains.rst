===============================
Merging disk image image chains
===============================

.. contents::

Context
=======

Sometimes a `disk image chain
<https://libvirt.org/kbase/backing_chains.html>`_ can get long and
cumbersome.  For the purpose of illustration, consider this smaller disk
image chain::

    base.raw <-- a.qcow2 <-- b.qcow2 <-- c.qcow2 (live QEMU)

You may want to reduce the backing chain length, or consolidate *all*
the disk images in the chain into a single image.  But you want to
accomplish this *without* incurring guest down time.  Here's how to go
about it.

The same principles used in the `live full disk backup
<https://libvirt.org/kbase/live_full_disk_backup.html>` document are
used here too.

Reducing the disk image chain length
====================================

Starting the earlier image chain::

    base.raw <-- a.qcow2 <-- b.qcow2 <-- c.qcow2 (live QEMU)

Reduce the length of the chain by two images, with the resulting chain
being::

    base.raw <-- c.qcow2 (live QEMU)

Where the ``base.raw`` contains the contents of ``a.qcow2`` and
``b.qcow2``.

#. Start by listing the current active disk image in use::

    $ virsh domblklist vm1
    Target     Source
    ------------------------------------------------
    vda        /var/lib/libvirt/images/base.raw

#. Create the image chain by creating three QCOW2 overlays (or "external
   snapshots") on top of each other, while adding some differentiating
   content in each image::

    $ virsh snapshot-create-as --domain vm1 snap1 \
        --diskspec vda,file=/var/lib/libvirt/images/a.qcow2 \
        --disk-only --no-metadata

    # <Add a file in the guest>

    $ virsh snapshot-create-as --domain vm1 snap2 \
        --diskspec vda,file=/var/lib/libvirt/images/b.qcow2 \
        --disk-only --no-metadata

    # <Add another file in the guest>

    $ virsh snapshot-create-as --domain vm1 snap3 \
        --diskspec vda,file=/var/lib/libvirt/images/c.qcow2 \
        --disk-only --no-metadata

#. Enumerate the backing file chain (here the ``force-share`` option
   simply allows ``qemu-img`` to safely query the disk image status
   while it is active) ::

    $ qemu-img info --force-share --backing-chain /var/lib/libvirt/images/cur.qcow2
    [...]

#. Again, list the current active disk image in use::

    $ virsh domblklist vm1
    Target     Source
    ------------------------------------------------
    vda        /var/lib/libvirt/images/c.qcow2

#. Perform the "block-commit" by specify the "base" and "top" images,
   i.e. merge the contents of ``b.qcow2`` *and* ``a.qcow2`` into
   ``base.raw``, *and* ::

    $ virsh blockcommit vm1 vda \
        --base=/var/lib/libvirt/images/base.raw
        --top=/var/lib/libvirt/images/b.qcow2

A note on accessing 'base' and 'top' images
-------------------------------------------

Specifying file paths, as above, make sense when your disks are in the
local filesystem.  However, when using more complicated setups such as
network block device (NBD) disks, there are no file paths.  Hhere is
where accessing the disk by its index number comes into picture.

As an example, the below  is the ``<disk>`` element of the guest XML for
with the original disk image chain of four images::

    ...
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/c.qcow2' index='4'/>
      <backingStore type='file' index='3'>
        <format type='qcow2'/>
        <source file='/var/lib/libvirt/images/b.qcow2'/>
        <backingStore type='file' index='2'>
          <format type='qcow2'/>
          <source file='/var/lib/libvirt/images/a.qcow2'/>
          <backingStore type='file' index='1'>
            <format type='raw'/>
            <source file='/var/lib/libvirt/images/base.raw'/>
            <backingStore/>
          </backingStore>
        </backingStore>
      </backingStore>
      <target dev='vda' bus='virtio'/>
      <alias name='virtio-disk0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </disk>
    ...

And we can merge the images ``a.qcow2`` and ``b.qcow2`` into
``base.qcow2`` using the index numbers 1 (for ``base.qcow2``) and ::

    $> virsh blockcommit vm1 vda --base='vda[1]' --top='vda[3]'

Note that the shell quoting is necessary here, since unquoted ``[1]``
would do an unexpected shell "globbing" (i.e. file name expansion)  if
you have a file '1' in the current directory

Accessing the disk images via their index numbers is more useful when
you're using blockCommit() API programmatically.


Consolidating an entire disk image chain into a single image
============================================================

Again, starting the original image chain::

    base.raw <-- a.qcow2 <-- b.qcow2 <-- c.qcow2 (live QEMU)

Reduce the length of the chain by two images, with the resulting chain
being::

    base.raw (live QEMU)

Where the ``base.raw`` contains the contents of ``a.qcow2``, ``b.qcow2``
and ``c.qcow2``; *and* the live QEMU is piovoted to point to the
``base.raw``.


#. Use the same procedure discussed earlier to create the disk image
   chain.


#. Now perform the "active block-commit" operation::

    $ virsh blockcommit vm1 vda --verbose --pivot --active
    Block Commit: [100 %]
    Successfully pivoted

  Notes:

  - ``--active``: It performs a two-stage operation: first, the contents
    from top images (``a.qcow2``, ``b.qcow2``, and ``c.qcow2``) are
    committed into the base image; and in the second stage, the
    "block-commit" operation remains awake to synchronize any further
    changes from top images into base.  Here the user can take two
    actions: cancel the job, or pivot the job, i.e. adjust the base
    image as the current active image.

  - ``--pivot``: Once data is committed from sn1, sn2 and current into
    base, it pivots the live QEMU to use base as the active image.

  - ``--verbose``: It shows the progress of block operation.


#. Again, check the current active block device in use::

    $ virsh domblklist vm1
    Target     Source
    ------------------------------------------------
    vda        /var/lib/libvirt/images/base.raw


#. Enumerate the backing file chain::

    $ qemu-img info --backing-chain /var/lib/libvirt/images/base.raw
    [...]

   And the final resulting disk image "chain" will be a single,
   consolidated disk image::

    [base] (live QEMU)

It is worth bearing in mind that once the above pivot completes, *all*
three overlay files — ``a.qcow2``, ``b.qcow2``, and ``c.qcow2`` — are no
longer valid, and can be safely discarded.
