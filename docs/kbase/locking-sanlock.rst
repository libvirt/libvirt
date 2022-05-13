============================================
Virtual machine lock manager, sanlock plugin
============================================

.. contents::

This page describes use of the
`sanlock <https://fedorahosted.org/sanlock/>`__ service as a `lock
driver <locking.html>`__ plugin for virtual machine disk mutual
exclusion.

Sanlock daemon setup
====================

On many operating systems, the **sanlock** plugin is distributed in a
sub-package which needs to be installed separately from the main libvirt
RPM. On a Fedora/RHEL host this can be done with the ``yum`` command

::

   $ su - root
   # yum install libvirt-lock-sanlock

The next step is to start the sanlock daemon. For maximum safety sanlock
prefers to have a connection to a watchdog daemon. This will cause the
entire host to be rebooted in the event that sanlock crashes /
terminates abnormally. To start the watchdog daemon on a Fedora/RHEL
host the following commands can be run:

::

   $ su - root
   # chkconfig wdmd on
   # service wdmd start

Once the watchdog is running, sanlock can be started as follows

::

   # chkconfig sanlock on
   # service sanlock start

*Note:* if you wish to avoid the use of the watchdog, add the following
line to ``/etc/sysconfig/sanlock`` before starting it

::

   SANLOCKOPTS="-w 0"

The sanlock daemon must be started on every single host that will be
running virtual machines. So repeat these steps as necessary.

libvirt sanlock plugin configuration
====================================

Once the sanlock daemon is running, the next step is to configure the
libvirt sanlock plugin. There is a separate configuration file for each
libvirt driver that is using sanlock. For QEMU, we will edit
``/etc/libvirt/qemu-sanlock.conf`` There is one mandatory parameter that
needs to be set, the ``host_id``. This is an integer between 1 and 2000,
which must be set to a **unique** value on each host running virtual
machines.

::

   $ su - root
   # augtool -s set /files/etc/libvirt/qemu-sanlock.conf/host_id 1

Repeat this on every host, changing **1** to a unique value for the
host.

libvirt sanlock storage configuration
=====================================

The sanlock plugin needs to create leases in a directory that is on a
filesystem shared between all hosts running virtual machines. Obvious
choices for this include NFS or GFS2. The libvirt sanlock plugin expects
its lease directory be at ``/var/lib/libvirt/sanlock`` so update the
host's ``/etc/fstab`` to mount a suitable shared/cluster filesystem at
that location

::

   $ su - root
   # echo "some.nfs.server:/export/sanlock /var/lib/libvirt/sanlock nfs hard,nointr 0 0" >> /etc/fstab
   # mount /var/lib/libvirt/sanlock

If your sanlock daemon happen to run under non-root privileges, you need
to tell this to libvirt so it chowns created files correctly. This can
be done by setting ``user`` and/or ``group`` variables in the
configuration file. Accepted values range is specified in description to
the same variables in ``/etc/libvirt/qemu.conf``. For example:

::

   augtool -s set /files/etc/libvirt/qemu-sanlock.conf/user sanlock
   augtool -s set /files/etc/libvirt/qemu-sanlock.conf/group sanlock

But remember, that if this is NFS share, you need a no_root_squash-ed
one for chown (and chmod possibly) to succeed.

In terms of storage requirements, if the filesystem uses 512 byte
sectors, you need to allow for ``1MB`` of storage for each guest disk.
So if you have a network with 20 virtualization hosts, each running 50
virtual machines and an average of 2 disks per guest, you will need
``20*50*2 == 2000 MB`` of storage for sanlock.

On one of the hosts on the network is it wise to setup a cron job which
runs the ``virt-sanlock-cleanup`` script periodically. This scripts
deletes any lease files which are not currently in use by running
virtual machines, freeing up disk space on the shared filesystem. Unless
VM disks are very frequently created + deleted it should be sufficient
to run the cleanup once a week.

QEMU/KVM driver configuration
=============================

The QEMU/KVM driver is fully integrated with the lock manager framework
as of release 0.9.3. The out of the box configuration, however,
currently uses the **nop** lock manager plugin. To get protection for
disks, it is thus necessary to reconfigure QEMU to activate the
**sanlock** driver. This is achieved by editing the QEMU driver
configuration file (``/etc/libvirt/qemu.conf``) and changing the
``lock_manager`` configuration tunable.

::

   $ su - root
   # augtool -s  set /files/etc/libvirt/qemu.conf/lock_manager sanlock
   # service libvirtd restart

If all went well, libvirtd will have talked to sanlock and created the
basic lockspace. This can be checked by looking for existence of the
following file

::

   # ls /var/lib/libvirt/sanlock/
   __LIBVIRT__DISKS__

Every time you start a guest, additional lease files will appear in this
directory, one for each virtual disk. The lease files are named based on
the MD5 checksum of the fully qualified path of the virtual disk backing
file. So if the guest is given a disk backed by
``/var/lib/libvirt/images/demo.img`` expect to see a lease
``/var/lib/libvirt/sanlock/bfa0240911bc17753e0b473688822159``

It should be obvious that for locking to work correctly, every host
running virtual machines should have storage configured in the same way.
The easiest way to do this is to use the libvirt storage pool capability
to configure any NFS volumes, iSCSI targets, or SCSI HBAs used for guest
storage. Simply replicate the same storage pool XML across every host.
It is important that any storage pools exposing block devices are
configured to create volume paths under ``/dev/disks/by-path`` to ensure
stable paths across hosts. An example iSCSI configuration which ensures
this is:

::

   <pool type='iscsi'>
     <name>myiscsipool</name>
     <source>
       <host name='192.168.254.8'/>
       <device path='your-iscsi-target-iqn'/>
     </source>
     <target>
       <path>/dev/disk/by-path</path>
     </target>
   </pool>

Domain configuration
====================

In case sanlock loses access to disk locks for some reason, it will kill
all domains that lost their locks. This default behavior may be changed
using `on_lockfailure element <../formatdomain.html#events-configuration>`__ in
domain XML. When this element is present, sanlock will call
``sanlock_helper`` (provided by libvirt) with the specified action. This
helper binary will connect to libvirtd and thus it may need to
authenticate if libvirtd was configured to require that on the
read-write UNIX socket. To provide the appropriate credentials to
sanlock_helper, a `client authentication
file <../auth.html#client-configuration>`__ needs to contain something like
the following:

::

   [auth-libvirt-localhost]
   credentials=sanlock

   [credentials-sanlock]
   authname=login
   password=password
