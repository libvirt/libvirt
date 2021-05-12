=======================
Cloud Hypervisor driver
=======================

.. contents::

Cloud Hypervisor is an open source Virtual Machine Monitor (VMM) that
runs on top of KVM. The project focuses on exclusively running modern,
cloud workloads, on top of a limited set of hardware architectures and
platforms. Cloud workloads refers to those that are usually run by
customers inside a cloud provider. For our purposes this means modern
operating systems with most I/O handled by paravirtualised devices
(i.e. virtio), no requirement for legacy devices, and 64-bit CPUs.

The libvirt Cloud Hypervisor driver is intended to be run as a session
driver without privileges. The cloud-hypervisor binary itself should be
``setcap cap_net_admin+ep`` (in order to create tap interfaces).

Expected connection URI would be

``ch:///session``


Example guest domain XML configurations
=======================================

The Cloud Hypervisor driver in libvirt is in its early stage under active
development only supporting a limited number of Cloud Hypervisor features.

Firmware is from
`hypervisor-fw <https://github.com/cloud-hypervisor/rust-hypervisor-firmware/releases>`__

**Note: Only virtio devices are supported**

::

   <domain type='kvm'>
     <name>cloudhypervisor</name>
     <uuid>4dea22b3-1d52-d8f3-2516-782e98ab3fa0</uuid>
     <os>
       <type>hvm</type>
       <kernel>hypervisor-fw</kernel>
     </os>
     <memory unit='G'>2</memory>
     <devices>
       <disk type='file'>
         <source file='disk.raw'/>
         <target dev='vda' bus='virtio'/>
       </disk>
       <interface type='ethernet'>
         <model type='virtio'/>
       </interface>
     </devices>
     <vcpu>2</vcpu>
   </domain>
