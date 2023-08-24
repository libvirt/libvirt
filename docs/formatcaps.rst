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
      creating external disk snapshots is supported. If absent, creating external
      snapshots may still be supported, but it requires attempting the API and
      checking for an error to find out for sure. :since:`Since 1.2.3`
   ``externalSnapshot``
      If this element is present, the hypervisor supports deleting and
      reverting external snapshots including memory state. Support for creation
      of external snapshots is reported via the ``disksnapshot`` feature flag.
      Management applications can now switch from internal snapshots to external
      snapshots. :since:`Since 9.9.0`

Examples
~~~~~~~~

For example, in the case of a 64-bit machine with hardware virtualization
capabilities enabled in the chip and BIOS you will see:

::

  <capabilities>

    <host>
      <uuid>7b55704c-29f4-11b2-a85c-9dc6ff50623f</uuid>
      <cpu>
        <arch>x86_64</arch>
        <model>Skylake-Client-noTSX-IBRS</model>
        <vendor>Intel</vendor>
        <microcode version='236'/>
        <signature family='6' model='142' stepping='12'/>
        <counter name='tsc' frequency='2303997000' scaling='no'/>
        <topology sockets='1' dies='1' cores='4' threads='2'/>
        <maxphysaddr mode='emulate' bits='39'/>
        <feature name='ds'/>
        <feature name='acpi'/>
        <feature name='ss'/>
        <feature name='ht'/>
        <feature name='tm'/>
        <feature name='pbe'/>
        <feature name='dtes64'/>
        <feature name='monitor'/>
        <feature name='ds_cpl'/>
        <feature name='vmx'/>
        <feature name='smx'/>
        <feature name='est'/>
        <feature name='tm2'/>
        <feature name='xtpr'/>
        <feature name='pdcm'/>
        <feature name='osxsave'/>
        <feature name='tsc_adjust'/>
        <feature name='sgx'/>
        <feature name='clflushopt'/>
        <feature name='intel-pt'/>
        <feature name='md-clear'/>
        <feature name='stibp'/>
        <feature name='arch-capabilities'/>
        <feature name='ssbd'/>
        <feature name='xsaves'/>
        <feature name='sgx1'/>
        <feature name='sgx-debug'/>
        <feature name='sgx-mode64'/>
        <feature name='sgx-provisionkey'/>
        <feature name='sgx-tokenkey'/>
        <feature name='pdpe1gb'/>
        <feature name='invtsc'/>
        <feature name='rdctl-no'/>
        <feature name='ibrs-all'/>
        <feature name='skip-l1dfl-vmentry'/>
        <feature name='mds-no'/>
        <feature name='tsx-ctrl'/>
        <pages unit='KiB' size='4'/>
        <pages unit='KiB' size='2048'/>
        <pages unit='KiB' size='1048576'/>
      </cpu>
      <power_management>
        <suspend_mem/>
      </power_management>
      <iommu support='yes'/>
      <migration_features>
        <live/>
        <uri_transports>
          <uri_transport>tcp</uri_transport>
          <uri_transport>rdma</uri_transport>
        </uri_transports>
      </migration_features>
      <topology>
        <cells num='1'>
          <cell id='0'>
            <memory unit='KiB'>32498112</memory>
            <pages unit='KiB' size='4'>6813808</pages>
            <pages unit='KiB' size='2048'>2048</pages>
            <pages unit='KiB' size='1048576'>1</pages>
            <distances>
              <sibling id='0' value='10'/>
            </distances>
            <cpus num='8'>
              <cpu id='0' socket_id='0' die_id='0' core_id='0' siblings='0,4'/>
              <cpu id='1' socket_id='0' die_id='0' core_id='1' siblings='1,5'/>
              <cpu id='2' socket_id='0' die_id='0' core_id='2' siblings='2,6'/>
              <cpu id='3' socket_id='0' die_id='0' core_id='3' siblings='3,7'/>
              <cpu id='4' socket_id='0' die_id='0' core_id='0' siblings='0,4'/>
              <cpu id='5' socket_id='0' die_id='0' core_id='1' siblings='1,5'/>
              <cpu id='6' socket_id='0' die_id='0' core_id='2' siblings='2,6'/>
              <cpu id='7' socket_id='0' die_id='0' core_id='3' siblings='3,7'/>
            </cpus>
          </cell>
        </cells>
      </topology>
      <cache>
        <bank id='0' level='3' type='both' size='8' unit='MiB' cpus='0-7'/>
      </cache>
      <secmodel>
        <model>none</model>
        <doi>0</doi>
      </secmodel>
      <secmodel>
        <model>dac</model>
        <doi>0</doi>
        <baselabel type='kvm'>+77:+77</baselabel>
        <baselabel type='qemu'>+77:+77</baselabel>
      </secmodel>
    </host>

    <guest>
      <os_type>hvm</os_type>
      <arch name='x86_64'>
        <wordsize>64</wordsize>
        <emulator>/usr/bin/qemu-system-x86_64</emulator>
        <machine maxCpus='255'>pc-i440fx-7.1</machine>
        <machine canonical='pc-i440fx-7.1' maxCpus='255'>pc</machine>
        <machine maxCpus='288'>pc-q35-5.2</machine>
        <machine maxCpus='255'>pc-i440fx-2.12</machine>
        <machine maxCpus='255'>pc-i440fx-2.0</machine>
        <machine maxCpus='255'>pc-i440fx-6.2</machine>
        <machine maxCpus='288'>pc-q35-4.2</machine>
        <machine maxCpus='255'>pc-i440fx-2.5</machine>
        <machine maxCpus='255'>pc-i440fx-4.2</machine>
        <machine maxCpus='255'>pc-i440fx-5.2</machine>
        <machine maxCpus='255' deprecated='yes'>pc-i440fx-1.5</machine>
        <machine maxCpus='255'>pc-q35-2.7</machine>
        <machine maxCpus='288'>pc-q35-7.1</machine>
        <machine canonical='pc-q35-7.1' maxCpus='288'>q35</machine>
        <machine maxCpus='255'>pc-i440fx-2.2</machine>
        <machine maxCpus='255'>pc-i440fx-2.7</machine>
        <machine maxCpus='288'>pc-q35-6.1</machine>
        <machine maxCpus='255'>pc-q35-2.4</machine>
        <machine maxCpus='288'>pc-q35-2.10</machine>
        <machine maxCpus='1'>x-remote</machine>
        <machine maxCpus='288'>pc-q35-5.1</machine>
        <machine maxCpus='255' deprecated='yes'>pc-i440fx-1.7</machine>
        <machine maxCpus='288'>pc-q35-2.9</machine>
        <machine maxCpus='255'>pc-i440fx-2.11</machine>
        <machine maxCpus='288'>pc-q35-3.1</machine>
        <machine maxCpus='255'>pc-i440fx-6.1</machine>
        <machine maxCpus='288'>pc-q35-4.1</machine>
        <machine maxCpus='255'>pc-i440fx-2.4</machine>
        <machine maxCpus='255'>pc-i440fx-4.1</machine>
        <machine maxCpus='255'>pc-i440fx-5.1</machine>
        <machine maxCpus='255'>pc-i440fx-2.9</machine>
        <machine maxCpus='1'>isapc</machine>
        <machine maxCpus='255' deprecated='yes'>pc-i440fx-1.4</machine>
        <machine maxCpus='255'>pc-q35-2.6</machine>
        <machine maxCpus='255'>pc-i440fx-3.1</machine>
        <machine maxCpus='288'>pc-q35-2.12</machine>
        <machine maxCpus='288'>pc-q35-7.0</machine>
        <machine maxCpus='255'>pc-i440fx-2.1</machine>
        <machine maxCpus='288'>pc-q35-6.0</machine>
        <machine maxCpus='255'>pc-i440fx-2.6</machine>
        <machine maxCpus='288'>pc-q35-4.0.1</machine>
        <machine maxCpus='255'>pc-i440fx-7.0</machine>
        <machine maxCpus='255' deprecated='yes'>pc-i440fx-1.6</machine>
        <machine maxCpus='288'>pc-q35-5.0</machine>
        <machine maxCpus='288'>pc-q35-2.8</machine>
        <machine maxCpus='255'>pc-i440fx-2.10</machine>
        <machine maxCpus='288'>pc-q35-3.0</machine>
        <machine maxCpus='255'>pc-i440fx-6.0</machine>
        <machine maxCpus='288'>pc-q35-4.0</machine>
        <machine maxCpus='288'>microvm</machine>
        <machine maxCpus='255'>pc-i440fx-2.3</machine>
        <machine maxCpus='255'>pc-i440fx-4.0</machine>
        <machine maxCpus='255'>pc-i440fx-5.0</machine>
        <machine maxCpus='255'>pc-i440fx-2.8</machine>
        <machine maxCpus='288'>pc-q35-6.2</machine>
        <machine maxCpus='255'>pc-q35-2.5</machine>
        <machine maxCpus='255'>pc-i440fx-3.0</machine>
        <machine maxCpus='288'>pc-q35-2.11</machine>
        <domain type='qemu'/>
        <domain type='kvm'/>
      </arch>
      <features>
        <acpi default='on' toggle='yes'/>
        <apic default='on' toggle='no'/>
        <cpuselection/>
        <deviceboot/>
        <disksnapshot default='on' toggle='no'/>
        <externalSnapshot/>
      </features>
    </guest>

  </capabilities>
