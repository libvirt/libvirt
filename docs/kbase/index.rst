==============
Knowledge base
==============

Usage
-----

`Secure usage <secureusage.html>`__
   Secure usage of the libvirt APIs

`Backing chain management <backing_chains.html>`__
   Explanation of how disk backing chain specification impacts libvirt's
   behaviour and basic troubleshooting steps of disk problems.

`Virtiofs <virtiofs.html>`__
   Share a filesystem between the guest and the host

`Security with QEMU passthrough <qemu-passthrough-security.html>`__
   Examination of the security protections used for QEMU and how they need
   configuring to allow use of QEMU passthrough with host files/devices.

`TLS certificates <tlscerts.html>`__
   Generate and deploy x509 certificates for TLS.

`RPM deployment <rpm-deployment.html>`__
   Explanation of the different RPM packages and illustration of which to
   pick for installation

`Domain state capture <domainstatecapture.html>`__
   Comparison between different methods of capturing domain state

`Disk locking <locking.html>`__
   Ensuring exclusive guest access to disks with
   `virtlockd <locking-lockd.html>`__ or
   `Sanlock <locking-sanlock.html>`__

`Protected virtualization on s390 <s390_protected_virt.html>`__
   Running secure s390 guests with IBM Secure Execution

`Launch security <launch_security_sev.html>`__
   Securely launching VMs with AMD SEV

`Live full disk backup <live_full_disk_backup.html>`__
   A walkthrough of how to take effective live full disk backups.

`Merging disk image chains <merging_disk_image_chains.html>`__
   Ways to reduce or consolidate disk image chains.

`KVM real time <kvm-realtime.html>`__
   Run real time workloads in guests on a KVM hypervisor

`PCI hotplug <../pci-hotplug.html>`__
   Effective usage of PCI hotplug

`PCI topology <../pci-addresses.html>`__
   Addressing schemes for PCI devices

`Memory devices <memorydevices.html>`__
   Memory devices and their use

`Snapshots <snapshots.html>`__
    Details about snapshotting a VM

`Secure Boot <secureboot.html>`__
    Enable and disable the Secure Boot feature


Debugging
---------

`Debug logs <debuglogs.html>`__
  Configuration of logging and tips on how to file a good bug report.

`Systemtap <systemtap.html>`__
   Explanation of how to use systemtap for libvirt tracing.

`Capturing core dumps for QEMU <qemu-core-dump.html>`__
   How to configure libvirt to enable capture of core dumps from
   QEMU virtual machines


Internals
---------

`Incremental backup internals <internals/incremental-backup.html>`__
   Incremental backup implementation details relevant for users

`VM migration internals <internals/migration.html>`__
   VM migration implementation details, complementing the info in
   `migration <../migration.html>`__

`API call flow overview <internals/overview.html>`__
   Overview of how an API call is handled by the ``libvirt`` library and passed
   over RPC to the daemon.

`Spawning commands <internals/command.html>`__
   Spawning commands from libvirt driver code

`Event loop and worker pool <internals/eventloop.html>`__
   Libvirt's event loop and worker pool mode

`Lock managers <internals/locking.html>`__
   Use lock managers to protect disk content

`RPC protocol & APIs <internals/rpc.html>`__
   RPC protocol information and API / dispatch guide

`QEMU driver threading <internals/qemu-threads.html>`__
   Basics of locking and threaded access to qemu driver primitives.

`QEMU migration internals <internals/qemu-migration.html>`__
   Description of migration phases in the ``v2`` and ``v3`` migration protocol.

`QEMU monitor event handling <internals/qemu-event-handlers.html>`__
   Brief outline how events emitted by qemu on the monitor are handlded.
