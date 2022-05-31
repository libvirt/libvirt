.. role:: since

==============================
Driver capabilities XML format
==============================

.. contents::

Element and attribute overview
------------------------------

As new virtualization engine support gets added to libvirt, and to handle cases
like QEMU supporting a variety of emulations, a query interface has been added
in 0.2.1 allowing to list the set of supported virtualization capabilities on
the host:

::

   char * virConnectGetCapabilities (virConnectPtr conn);

The value returned is an XML document listing the virtualization capabilities of
the host and virtualization engine to which ```conn`` is connected. One can test
it using ``virsh`` command line tool command '``capabilities``', it dumps the
XML associated to the current connection.

As can be seen in the `Examples`_, the capabilities XML
consists of the ``capabilities`` element which have exactly one ``host`` child
element to report information on host capabilities, and zero or more ``guest``
element to express the set of architectures the host can run at the moment.

Host capabilities
~~~~~~~~~~~~~~~~~

The ``<host/>`` element consists of the following child elements:

``uuid``
   The host UUID.
``cpu``
   The host CPU architecture and features.
``power_management``
   whether host is capable of memory suspend, disk hibernation, or hybrid
   suspend.
``migration_features``
   This element exposes information on the hypervisor's migration capabilities,
   like live migration, supported URI transports, and so on.
``topology``
   This element embodies the host internal topology. Management applications may
   want to learn this information when orchestrating new guests - e.g. due to
   reduce inter-NUMA node transfers. Note that the ``sockets`` value reported
   here is per-NUMA-node; this is in contrast to the value given in domain
   definitions, which is interpreted as a total number of sockets for the
   domain.
``secmodel``
   To find out default security labels for different security models you need to
   parse this element. In contrast with the former elements, this is repeated
   for each security model the libvirt daemon currently supports.

Guest capabilities
~~~~~~~~~~~~~~~~~~

While the previous section (`Host capabilities`_) aims at host capabilities,
this one focuses on capabilities available to a guest using a given hypervisor.
The ``<guest/>`` element will typically wrap up the following elements:

``os_type``
   This expresses what kind of operating system the hypervisor is able to run.
   Possible values are:

   ``xen``
      for XEN PV
   ``linux``
      legacy alias for ``xen``
   ``xenpvh``
      for XEN PVH
   ``hvm``
      Unmodified operating system
   ``exe``
      Container based virtualization
``arch``
   This element brings some information on supported guest architecture.
   Possible subelements are:

   ``wordsize``
      Size of CPU word in bits, for example 64.
   ``emulator``
      Emulator (device model) path, for use in
      `emulator <formatdomain.html#devices>`__ element of domain XML.
   ``loader``
      Loader path, for use in `loader <formatdomain.html#bios-bootloader>`__
      element of domain XML.
   ``machine``
      Machine type, for use in
      `machine <formatdomain.html#operating-system-booting>`__ attribute of
      os/type element in domain XML. For example Xen supports ``xenfv`` for HVM,
      ``xenpv`` for PV, or ``xenpvh`` for PVH.
   ``domain``
      The ``type`` attribute of this element specifies the type of hypervisor
      required to run the domain. Use in
      `type <formatdomain.html#element-and-attribute-overview>`__ attribute of
      the domain root element.
``features``
   This optional element encases possible features that can be used with a guest
   of described type. Possible subelements are:

   ``pae``
      If present, 32-bit guests can use PAE address space extensions,
      :since:`since 0.4.1`
   ``nonpae``
      If present, 32-bit guests can be run without requiring PAE, :since:`since
      0.4.1`
   ``ia64_be``
      If present, IA64 guests can be run in big-endian mode, :since:`since
      0.4.1`
   ``acpi``
      If this element is present, the ``default`` attribute describes whether
      the hypervisor exposes ACPI to the guest by default, and the ``toggle``
      attribute describes whether the user can override this default.
      :since:`Since 0.4.1`
   ``apic``
      If this element is present, the ``default`` attribute describes whether
      the hypervisor exposes APIC to the guest by default, and the ``toggle``
      attribute describes whether the user can override this default.
      :since:`Since 0.4.1`
   ``cpuselection``
      If this element is present, the hypervisor supports the ``<cpu>`` element
      within a domain definition for fine-grained control over the CPU presented
      to the guest. :since:`Since 0.7.5`
   ``deviceboot``
      If this element is present, the ``<boot order='...'/>`` element can be
      used inside devices, rather than the older boot specification by category.
      :since:`Since 0.8.8`
   ``disksnapshot``
      If this element is present, the ``default`` attribute describes whether
      external disk snapshots are supported. If absent, external snapshots may
      still be supported, but it requires attempting the API and checking for an
      error to find out for sure. :since:`Since 1.2.3`

Examples
~~~~~~~~

For example, in the case of a 64-bit machine with hardware virtualization
capabilities enabled in the chip and BIOS you will see:

::

   <capabilities>
     <host>
       <cpu>
         <arch>x86_64</arch>
         <features>
           <vmx/>
         </features>
         <model>core2duo</model>
         <vendor>Intel</vendor>
         <topology sockets="1" dies="1" cores="2" threads="1"/>
         <feature name="lahf_lm"/>
         <feature name='xtpr'/>
         ...
       </cpu>
       <power_management>
         <suspend_mem/>
         <suspend_disk/>
         <suspend_hybrid/>
       </power_management>
     </host>

     <!-- xen-3.0-x86_64 -->
     <guest>
       <os_type>xen</os_type>
       <arch name="x86_64">
         <wordsize>64</wordsize>
         <domain type="xen"></domain>
         <emulator>/usr/lib64/xen/bin/qemu-dm</emulator>
       </arch>
       <features>
       </features>
     </guest>

     <!-- hvm-3.0-x86_32 -->
     <guest>
       <os_type>hvm</os_type>
       <arch name="i686">
         <wordsize>32</wordsize>
         <domain type="xen"></domain>
         <emulator>/usr/lib/xen/bin/qemu-dm</emulator>
         <machine>pc</machine>
         <machine>isapc</machine>
         <loader>/usr/lib/xen/boot/hvmloader</loader>
       </arch>
       <features>
         <cpuselection/>
         <deviceboot/>
       </features>
     </guest>

     ...
   </capabilities>
