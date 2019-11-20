==============================================
Virtual machine lock manager, virtlockd plugin
==============================================

.. contents::

This page describes use of the ``virtlockd`` service as a `lock
driver <locking.html>`__ plugin for virtual machine disk mutual
exclusion.

virtlockd background
====================

The virtlockd daemon is a single purpose binary which focuses
exclusively on the task of acquiring and holding locks on behalf of
running virtual machines. It is designed to offer a low overhead,
portable locking scheme can be used out of the box on virtualization
hosts with minimal configuration overheads. It makes use of the POSIX
fcntl advisory locking capability to hold locks, which is supported by
the majority of commonly used filesystems.

virtlockd daemon setup
======================

In most OS, the virtlockd daemon itself will not require any upfront
configuration work. It is installed by default when libvirtd is present,
and a systemd socket unit is registered such that the daemon will be
automatically started when first required. With OS that predate systemd
though, it will be necessary to start it at boot time, prior to libvirtd
being started. On RHEL/Fedora distros, this can be achieved as follows

::

   # chkconfig virtlockd on
   # service virtlockd start

The above instructions apply to the instance of virtlockd that runs
privileged, and is used by the libvirtd daemon that runs privileged. If
running libvirtd as an unprivileged user, it will always automatically
spawn an instance of the virtlockd daemon unprivileged too. This
requires no setup at all.

libvirt lockd plugin configuration
==================================

Once the virtlockd daemon is running, or setup to autostart, the next
step is to configure the libvirt lockd plugin. There is a separate
configuration file for each libvirt driver that is using virtlockd. For
QEMU, we will edit ``/etc/libvirt/qemu-lockd.conf``

The default behaviour of the lockd plugin is to acquire locks directly
on the virtual disk images associated with the guest <disk> elements.
This ensures it can run out of the box with no configuration, providing
locking for disk images on shared filesystems such as NFS. It does not
provide any cross host protection for storage that is backed by block
devices, since locks acquired on device nodes in /dev only apply within
the host. It may also be the case that the filesystem holding the disk
images is not capable of supporting fcntl locks.

To address these problems it is possible to tell lockd to acquire locks
on an indirect file. Essentially lockd will calculate the SHA256
checksum of the fully qualified path, and create a zero length file in a
given directory whose filename is the checksum. It will then acquire a
lock on that file. Assuming the block devices assigned to the guest are
using stable paths (eg /dev/disk/by-path/XXXXXXX) then this will allow
for locks to apply across hosts. This feature can be enabled by setting
a configuration setting that specifies the directory in which to create
the lock files. The directory referred to should of course be placed on
a shared filesystem (eg NFS) that is accessible to all hosts which can
see the shared block devices.

::

   $ su - root
   # augtool -s set \
     /files/etc/libvirt/qemu-lockd.conf/file_lockspace_dir \
     "/var/lib/libvirt/lockd/files"

If the guests are using either LVM and SCSI block devices for their
virtual disks, there is a unique identifier associated with each device.
It is possible to tell lockd to use this UUID as the basis for acquiring
locks, rather than the SHA256 sum of the filename. The benefit of this
is that the locking protection will work even if the file paths to the
given block device are different on each host.

::

   $ su - root
   # augtool -s set \
     /files/etc/libvirt/qemu-lockd.conf/scsi_lockspace_dir \
     "/var/lib/libvirt/lockd/scsi"
   # augtool -s set \
     /files/etc/libvirt/qemu-lockd.conf/lvm_lockspace_dir \
     "/var/lib/libvirt/lockd/lvm"

It is important to remember that the changes made to the
``/etc/libvirt/qemu-lockd.conf`` file must be propagated to all hosts
before any virtual machines are launched on them. This ensures that all
hosts are using the same locking mechanism

QEMU/KVM driver configuration
=============================

The QEMU driver is capable of using the virtlockd plugin since the
release 1.0.2. The out of the box configuration, however, currently uses
the **nop** lock manager plugin. To get protection for disks, it is thus
necessary to reconfigure QEMU to activate the **lockd** driver. This is
achieved by editing the QEMU driver configuration file
(``/etc/libvirt/qemu.conf``) and changing the ``lock_manager``
configuration tunable.

::

   $ su - root
   # augtool -s  set /files/etc/libvirt/qemu.conf/lock_manager lockd
   # service libvirtd restart

Every time you start a guest, the virtlockd daemon will acquire locks on
the disk files directly, or in one of the configured lookaside
directories based on SHA256 sum. To check that locks are being acquired
as expected, the ``lslocks`` tool can be run.
