==========================
KVM Real Time Guest Config
==========================

.. contents::

The KVM hypervisor is capable of running real time guest workloads. This page
describes the key pieces of configuration required in the domain XML to achieve
the low latency needs of real time workloads.

For the most part, configuration of the host OS is out of scope of this
documentation. Refer to the operating system vendor's guidance on configuring
the host OS and hardware for real time. Note in particular that the default
kernel used by most Linux distros is not suitable for low latency real time and
must be replaced by a special kernel build.


Host partitioning plan
======================

Running real time workloads requires carefully partitioning up the host OS
resources, such that the KVM / QEMU processes are strictly separated from any
other workload running on the host, both userspace processes and kernel threads.

As such, some subset of host CPUs need to be reserved exclusively for running
KVM guests. This requires that the host kernel be booted using the ``isolcpus``
kernel command line parameter. This parameter removes a set of CPUs from the
scheduler, such that that no kernel threads or userspace processes will ever get
placed on those CPUs automatically. KVM guests are then manually placed onto
these CPUs.

Deciding which host CPUs to reserve for real time requires understanding of the
guest workload needs and balancing with the host OS needs. The trade off will
also vary based on the physical hardware available.

For the sake of illustration, this guide will assume a physical machine with two
NUMA nodes, each with 2 sockets and 4 cores per socket, giving a total of 16
CPUs on the host. Furthermore, it is assumed that hyperthreading is either not
supported or has been disabled in the BIOS, since it is incompatible with real
time. Each NUMA node is assumed to have 32 GB of RAM, giving 64 GB total for
the host.

It is assumed that 2 CPUs in each NUMA node are reserved for the host OS, with
the remaining 6 CPUs available for KVM real time. With this in mind, the host
kernel should have booted with ``isolcpus=2-7,10-15`` to reserve CPUs.

To maximise efficiency of page table lookups for the guest, the host needs to be
configured with most RAM exposed as huge pages, ideally 1 GB sized. 6 GB of RAM
in each NUMA node will be reserved for general host OS usage as normal sized
pages, leaving 26 GB for KVM usage as huge pages.

Once huge pages are reserved on the hypothetical machine, the ``virsh
capabilities`` command output is expected to look approximately like:

::

   <topology>
     <cells num='2'>
       <cell id='0'>
         <memory unit='KiB'>33554432</memory>
         <pages unit='KiB' size='4'>1572864</pages>
         <pages unit='KiB' size='2048'>0</pages>
         <pages unit='KiB' size='1048576'>26</pages>
         <distances>
           <sibling id='0' value='10'/>
           <sibling id='1' value='21'/>
         </distances>
         <cpus num='8'>
           <cpu id='0' socket_id='0' core_id='0' siblings='0'/>
           <cpu id='1' socket_id='0' core_id='1' siblings='1'/>
           <cpu id='2' socket_id='0' core_id='2' siblings='2'/>
           <cpu id='3' socket_id='0' core_id='3' siblings='3'/>
           <cpu id='4' socket_id='1' core_id='0' siblings='4'/>
           <cpu id='5' socket_id='1' core_id='1' siblings='5'/>
           <cpu id='6' socket_id='1' core_id='2' siblings='6'/>
           <cpu id='7' socket_id='1' core_id='3' siblings='7'/>
         </cpus>
       </cell>
       <cell id='1'>
         <memory unit='KiB'>33554432</memory>
         <pages unit='KiB' size='4'>1572864</pages>
         <pages unit='KiB' size='2048'>0</pages>
         <pages unit='KiB' size='1048576'>26</pages>
         <distances>
           <sibling id='0' value='21'/>
           <sibling id='1' value='10'/>
         </distances>
         <cpus num='8'>
           <cpu id='8' socket_id='0' core_id='0' siblings='8'/>
           <cpu id='9' socket_id='0' core_id='1' siblings='9'/>
           <cpu id='10' socket_id='0' core_id='2' siblings='10'/>
           <cpu id='11' socket_id='0' core_id='3' siblings='11'/>
           <cpu id='12' socket_id='1' core_id='0' siblings='12'/>
           <cpu id='13' socket_id='1' core_id='1' siblings='13'/>
           <cpu id='14' socket_id='1' core_id='2' siblings='14'/>
           <cpu id='15' socket_id='1' core_id='3' siblings='15'/>
          </cpus>
       </cell>
     </cells>
   </topology>

Be aware that CPU ID numbers are not always allocated sequentially as shown
here. It is not unusual to see IDs interleaved between sockets on the two NUMA
nodes, such that ``0-3,8-11`` are on the first node and ``4-7,12-15`` are on
the second node.  Carefully check the ``virsh capabilities`` output to determine
the CPU ID numbers when configuring both ``isolcpus`` and the guest ``cpuset``
values.

Guest configuration
===================

What follows is an overview of the key parts of the domain XML that need to be
configured to achieve low latency for real time workflows. The following example
will assume a 4 CPU guest, requiring 16 GB of RAM. It is intended to be placed
on the second host NUMA node.

CPU configuration
-----------------

Real time KVM guests intended to run Linux should have a minimum of 2 CPUs.
One vCPU is for running non-real time processes and performing I/O. The other
vCPUs will run real time applications. Some non-Linux OS may not require a
special non-real time CPU to be available, in which case the 2 CPU minimum would
not apply.

Each guest CPU, even the non-real time one, needs to be pinned to a dedicated
host core that is in the `isolcpus` reserved set. The QEMU emulator threads
need to be pinned to host CPUs that are not in the `isolcpus` reserved set.
The vCPUs need to be given a real time CPU scheduler policy.

When configuring the `guest CPU count <../formatdomain.html#cpu-allocation>`_,
do not include any CPU affinity at this stage:

::

   <vcpu placement='static'>4</vcpu>

The guest CPUs now need to be placed individually. In this case, they will all
be put within the same host socket, such that they can be exposed as core
siblings. This is achieved using the `CPU tuning config <../formatdomain.html#cpu-tuning>`_:

::

   <cputune>
     <emulatorpin cpuset="8-9"/>
     <vcpupin vcpu="0" cpuset="12"/>
     <vcpupin vcpu="1" cpuset="13"/>
     <vcpupin vcpu="2" cpuset="14"/>
     <vcpupin vcpu="3" cpuset="15"/>
     <vcpusched vcpus='0-4' scheduler='fifo' priority='1'/>
   </cputune>

The `guest CPU model <../formatdomain.html#cpu-model-and-topology>`_ now needs to be
configured to pass through the host model unchanged, with topology matching the
placement:

::

   <cpu mode='host-passthrough'>
     <topology sockets='1' dies='1' cores='4' threads='1'/>
     <feature policy='require' name='tsc-deadline'/>
   </cpu>

The performance monitoring unit virtualization needs to be disabled
via the `hypervisor features <../formatdomain.html#hypervisor-features>`_:

::

   <features>
     ...
     <pmu state='off'/>
   </features>


Memory configuration
--------------------

The host memory used for guest RAM needs to be allocated from huge pages on the
second NUMA node, and all other memory allocation needs to be locked into RAM
with memory page sharing disabled.
This is achieved by using the `memory backing config <../formatdomain.html#memory-backing>`_:

::

   <memoryBacking>
     <hugepages>
       <page size="1" unit="G" nodeset="1"/>
     </hugepages>
     <locked/>
     <nosharepages/>
   </memoryBacking>


Device configuration
--------------------

Libvirt adds a few devices by default to maintain historical QEMU configuration
behaviour. It is unlikely these devices are required by real time guests, so it
is wise to disable them. Remove all USB controllers that may exist in the XML
config and replace them with:

::

   <controller type="usb" model="none"/>

Similarly the memory balloon config should be changed to

::

   <memballoon model="none"/>

If the guest had a graphical console at installation time this can also be
disabled, with remote access being over SSH, with a minimal serial console
for emergencies.
