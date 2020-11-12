============================
Sharing files with Virtio-FS
============================

.. contents::

Virtio-FS
=========

Virtio-FS is a shared file system that lets virtual machines access
a directory tree on the host. Unlike existing approaches, it
is designed to offer local file system semantics and performance.

See https://virtio-fs.gitlab.io/

Host setup
==========

Almost all virtio devices (all that use virtqueues) require access to
at least certain portions of guest RAM (possibly policed by DMA). In
case of virtiofsd, much like in case of other vhost-user (see
https://www.qemu.org/docs/master/interop/vhost-user.html) virtio
devices that are realized by an userspace process, this in practice
means that QEMU needs to allocate the backing memory for all the guest
RAM as shared memory. As of QEMU 4.2, it is possible to explicitly
specify a memory backend when specifying the NUMA topology. This
method is however only viable for machine types that do support
NUMA. As of QEMU 5.0.0 and libvirt 6.9.0, it is possible to
specify the memory backend without NUMA (using the so called
memobject interface).

Either of the following:

* Use file-backed memory

  Configure the directory where the files backing the memory will be stored
  with the ``memory_backing_dir`` option in ``/etc/libvirt/qemu.conf``

  ::

    # This directory is used for memoryBacking source if configured as file.
    # NOTE: big files will be stored here
    memory_backing_dir = "/dev/shm/"

* Use hugepage-backed memory

  Make sure there are enough huge pages allocated for the requested guest memory.
  For example, for one guest with 2 GiB of RAM backed by 2 MiB hugepages:

  ::

      # virsh allocpages 2M 1024

Guest setup
===========

#. Specify the NUMA topology (this step is only required for the NUMA case)

   in the domain XML of the guest.
   For the simplest one-node topology for a guest with 2GiB of RAM and 8 vCPUs:

   ::

      <domain>
        ...
        <cpu ...>
          <numa>
            <cell id='0' cpus='0-7' memory='2' unit='GiB' memAccess='shared'/>
          </numa>
        </cpu>
       ...
      </domain>

   Note that the CPU element might already be specified and only one is allowed.

#. Specify the memory backend

   Either of the following:

   * File-backed memory

     ::

        <domain>
          ...
          <memoryBacking>
            <access mode='shared'/>
          </memoryBacking>
          ...
        </domain>

     This will create a file in the directory specified in ``qemu.conf``

   * Hugepage-backed memory

     ::

        <domain>
          ...
          <memoryBacking>
            <hugepages>
              <page size='2' unit='M'/>
            </hugepages>
            <access mode='shared'/>
          </memoryBacking>
          ...
        </domain>

#. Add the ``vhost-user-fs`` QEMU device via the ``filesystem`` element

   ::

      <domain>
        ...
        <devices>
          ...
          <filesystem type='mount' accessmode='passthrough'>
            <driver type='virtiofs'/>
            <source dir='/path'/>
            <target dir='mount_tag'/>
          </filesystem>
          ...
        </devices>
      </domain>

   Note that despite its name, the ``target dir`` is actually a mount tag and does
   not have to correspond to the desired mount point in the guest.

   So far, ``passthrough`` is the only supported access mode and it requires
   running the ``virtiofsd`` daemon as root.

#. Boot the guest and mount the filesystem

   ::

      guest# mount -t virtiofs mount_tag /mnt/mount/path

   Note: this requires virtiofs support in the guest kernel (Linux v5.4 or later)

Optional parameters
===================

More optional elements can be specified

::

  <driver type='virtiofs' queue='1024'/>
  <binary path='/usr/libexec/virtiofsd' xattr='on'>
    <cache mode='always'/>
    <lock posix='on' flock='on'/>
  </binary>
