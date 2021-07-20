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

`Virtio-FS <virtiofs.html>`__
   Share a filesystem between the guest and the host

`Security with QEMU passthrough <qemu-passthrough-security.html>`__
   Examination of the security protections used for QEMU and how they need
   configuring to allow use of QEMU passthrough with host files/devices.

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

Internals / Debugging
---------------------

`Debug logs <debuglogs.html>`__
  Configuration of logging and tips on how to file a good bug report.

`Systemtap <systemtap.html>`__
   Explanation of how to use systemtap for libvirt tracing.

`Incremental backup internals <incrementalbackupinternals.html>`__
   Incremental backup implementation details relevant for users

`VM migration internals <migrationinternals.html>`__
   VM migration implementation details, complementing the info in
   `migration <../migration.html>`__

`Capturing core dumps for QEMU <qemu-core-dump.html>`__
   How to configure libvirt to enable capture of core dumps from
   QEMU virtual machines
