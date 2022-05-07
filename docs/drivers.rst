================
Internal drivers
================

-  `Hypervisor drivers`_
-  `Storage drivers <storage.html>`__
-  `Node device driver <drvnodedev.html>`__
-  `Secret driver <drvsecret.html>`__

The libvirt public API delegates its implementation to one or more internal
drivers, depending on the `connection URI <uri.html>`__ passed when initializing
the library. There is always a hypervisor driver active, and if the libvirt
daemon is available there will usually be a network and storage driver active.

Hypervisor drivers
------------------

The hypervisor drivers currently supported by libvirt are:

-  `LXC <drvlxc.html>`__ - Linux Containers
-  `OpenVZ <drvopenvz.html>`__
-  `QEMU/KVM/HVF <drvqemu.html>`__
-  `Test <drvtest.html>`__ - Used for testing
-  `VirtualBox <drvvbox.html>`__
-  `VMware ESX <drvesx.html>`__
-  `VMware Workstation/Player <drvvmware.html>`__
-  `Xen <drvxen.html>`__
-  `Microsoft Hyper-V <drvhyperv.html>`__
-  `Virtuozzo <drvvirtuozzo.html>`__
-  `Bhyve <drvbhyve.html>`__ - The BSD Hypervisor
-  `Cloud Hypervisor <drvch.html>`__
