=================
Disk image chains
=================

Modern disk image formats allow users to create an overlay on top of an
existing image which will be the target of the new guest writes. This allows us
to do snapshots of the disk state of a VM efficiently. The following text
describes how libvirt manages such image chains and some problems which can
occur. Note that many of the cases mentioned below are currently only relevant
for the qemu driver.

.. contents::

Domain XML image and chain specification
========================================

Disk image chains can be partially or fully configured in the domain XML. The
basic approach is to use the ``<backingStore>`` elements in the configuration.

The ``<backingStore>`` elements present in the live VM xml represent the actual
topology that libvirt knows of.

Basic disk setup
----------------

Any default configuration or example usually refers only to the top (active)
image of the backing chain.

::

  <disk type='file' device='disk'>
    <driver name='qemu' type='qcow2'/>
    <source file='/tmp/pull4.qcow2'/>
    <target dev='vda' bus='virtio'/>
    <address type='pci' domain='0x0000' bus='0x00' slot='0x0a' function='0x0'/>
  </disk>

This configuration will prompt libvirt to detect the backing image of the source
image and recursively do the same thing until the end of the chain.

Importance of proper backing chain setup
----------------------------------------

The disk image locations are used by libvirt to properly set up the security
system used on the host so that the hypervisor can access the files; it can
also be used to configure the hypervisor to use the appropriate images. Thus
it's important to properly set up the formats and paths of the backing images.

Any externally created image should always use the -F switch of ``qemu-img``
to specify the format of the backing file to avoid probing.

Image detection caveats
-----------------------

Detection of the backing chain requires libvirt to read and understand the
``backing file`` field recorded in the image metadata and also being able to
recurse and read the backing file. Due to security implications libvirt
will refuse to use backing images of any image whose format was not specified
explicitly in the XML or the overlay image itself.

Libvirt also might lack support for a network disk storage technology and thus
may be unable to visit and detect backing chains on such storage. This may
result in the backing chain in the live XML looking incomplete or some
operations not being possible. To prevent this it's possible to specify the
image metadata explicitly in the XML.

Advanced backing chain specifications
-------------------------------------

To specify the topology of disk images explicitly the following XML
specification can be used:

::

 <disk type='file' device='disk'>
   <driver name='qemu' type='qcow2'/>
   <source file='/tmp/pull4.qcow2'/>
   <backingStore type='file'>
     <format type='qcow2'/>
     <source file='/tmp/pull3.qcow2'/>
     <backingStore type='file'>
       <format type='qcow2'/>
       <source file='/tmp/pull2.qcow2'/>
       <backingStore type='file'>
         <format type='qcow2'/>
         <source file='/tmp/pull1.qcow2'/>
         <backingStore type='file'>
           <format type='qcow2'/>
           <source file='/tmp/pull0.qcow2'/>
           <backingStore/>
         </backingStore>
       </backingStore>
     </backingStore>
   </backingStore>
   <target dev='vda' bus='virtio'/>
   <address type='pci' domain='0x0000' bus='0x00' slot='0x0a' function='0x0'/>
 </disk>

This makes libvirt follow the settings as configured in the XML. Note that this
is supported only when the https://libvirt.org/formatdomaincaps.html#backingstoreinput
capability is present.

An empty ``<backingStore/>`` element signals the end of the chain. Using this
will prevent libvirt or qemu from probing the backing chain.

Note that it's also possible to partially specify the chain in the XML but omit
the terminating element. This will result in probing from the last specified
``<backingStore>``

Any image specified explicitly will not be probed for backing file or format.


Manual image creation
=====================

When creating disk images manually outside of libvirt it's important to create
them properly so that they work with libvirt as expected. The created disk
images must contain the format of the backing image in the metadata. This
means that the **-F** parameter of ``qemu-img`` must always be used.

::

  qemu-img create -f qcow2 -F qcow2 -b $BACKING_IMAGE_PATH $IMAGE_PATH

Note that if ``$BACKING_IMAGE_PATH`` is relative the path is considered relative to
the location of ``$IMAGE_PATH``.

Troubleshooting
===============

A few common problems which occur when managing chains of disk images.

VM refuses to start due to misconfigured backing store format
-------------------------------------------------------------

This problem happens on VMs where the backing chain was created manually outside
of libvirt and can have multiple symptoms:

- permission denied error reported on a backing image
- ``format of backing image '%s' of image '%s' was not specified in the image metadata`` error reported
- disk image looking corrupt inside the guest

The cause of the above problem is that the image metadata does not record the
format of the backing image along with the location of the image. When the
format is not specified libvirt or qemu would have to do image format probing
which is insecure to do as a malicious guest could rewrite the header of the
disk leading to access of host files. Libvirt thus does not try to assume
the format of the backing image. The following command can be used to check if
the image has a backing image format specified:

::

 $ qemu-img info /tmp/copy4.qcow2
 image: /tmp/copy4.qcow2
 file format: qcow2
 virtual size: 10 MiB (10485760 bytes)
 disk size: 196 KiB
 cluster_size: 65536
 backing file: copy3.qcow2 (actual path: /tmp/copy3.qcow2)
 backing file format: qcow2
 Format specific information:
     compat: 1.1
     lazy refcounts: false
     refcount bits: 16
     corrupt: false

If the ``backing file format`` field is missing above the format was not
specified properly. The image can be fixed by the following command:

::

 qemu-img rebase -f $IMAGE_FORMAT -F $BACKING_IMAGE_FORMAT -b $BACKING_IMAGE_PATH $IMAGE_PATH

It is important to fill out ``$BACKING_IMAGE_FORMAT`` and ``$IMAGE_FORMAT``
properly. ``$BACKING_IMAGE_PATH`` should be specified as a full absolute path.
If relative referencing of the backing image is desired, the path must be
relative to the location of image described by ``$IMAGE_PATH``.

**Important:** If the ``$BACKING_IMAGE_FORMAT`` is not known it can be queried
using ``qemu-img info $BACKING_IMAGE_PATH`` and looking for the ``file format``
field, but for security reasons the value should be used *only* if at least one
of the following criteria is met:

- ``file format`` is ``raw``
- ``backing file`` is NOT present
- ``backing file`` is present AND is correct/trusted

Note that the last criterion may require manual inspection and thus should not
be scripted unless the trust for the image can be expressed programmatically.

Also note that the above steps may need to be repeated recursively for any
subsequent backing images.

Missing images reported after moving disk images into a different path
----------------------------------------------------------------------

The path to the backing image which is recorded in the image metadata often
contains a full path to the backing image. This is the default libvirt-created
image configuration. When such images are moved to a different location the
top image will no longer point to the correct image.

To fix such issue you can either fully specify the image chain in the domain XML
as pointed out above or the following ``qemu-img`` command can be used:

::

 qemu-img rebase -u -f $IMAGE_FORMAT -F $BACKING_IMAGE_FORMAT -b $BACKING_IMAGE_PATH $IMAGE_PATH

It is important to fill out ``$BACKING_IMAGE_FORMAT`` and ``$IMAGE_FORMAT``
properly. ``$BACKING_IMAGE_PATH`` should be specified as a full absolute path.
If relative referencing of the backing image is desired, the path must be
relative to the location of image described by ``$IMAGE_PATH``.
