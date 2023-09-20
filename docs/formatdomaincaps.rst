.. role:: since

==============================
Domain capabilities XML format
==============================

.. contents::

Overview
--------

Sometimes, when a new domain is to be created it may come handy to know the
capabilities of the hypervisor so the correct combination of devices and drivers
is used. For example, when management application is considering the mode for a
host device's passthrough there are several options depending not only on host,
but on hypervisor in question too. If the hypervisor is qemu then it needs to be
more recent to support VFIO, while legacy KVM is achievable just fine with older
qemus.

The main difference between
`virConnectGetCapabilities <html/libvirt-libvirt-host.html#virConnectGetCapabilities>`__
and the emulator capabilities API is, the former one aims more on the host
capabilities (e.g. NUMA topology, security models in effect, etc.) while the
latter one specializes on the hypervisor capabilities.

While the `Driver Capabilities <formatcaps.html>`__ provides the host
capabilities (e.g NUMA topology, security models in effect, etc.), the Domain
Capabilities provides the hypervisor specific capabilities for Management
Applications to query and make decisions regarding what to utilize.

The Domain Capabilities can provide information such as the correct combination
of devices and drivers that are supported. Knowing which host and hypervisor
specific options are available or supported would allow the management
application to choose an appropriate mode for a pass-through host device as well
as which adapter to utilize.

Some XML elements may be entirely omitted from the domaincapabilities XML,
depending on what the libvirt driver has filled in. Applications should only act
on what is explicitly reported in the domaincapabilities XML. For example, if
<disk supported='yes'/> is present, you can safely assume the driver supports
<disk> devices. If <disk supported='no'/> is present, you can safely assume the
driver does NOT support <disk> devices. If the <disk> block is omitted entirely,
the driver is not indicating one way or the other whether it supports <disk>
devices, and applications should not interpret the missing block to mean any
thing in particular.

Element and attribute overview
------------------------------

A new query interface was added to the virConnect API's to retrieve the XML
listing of the set of domain capabilities ( :since:`Since 1.2.7` ):

   ``virConnectGetDomainCapabilities`` (`API docs <html/libvirt-libvirt-domain.html#virConnectGetDomainCapabilities>`__)

The root element that emulator capability XML document starts with has name
``domainCapabilities``. It contains at least four direct child elements:

::

   <domainCapabilities>
     <path>/usr/bin/qemu-system-x86_64</path>
     <domain>kvm</domain>
     <machine>pc-i440fx-2.1</machine>
     <arch>x86_64</arch>
     ...
   </domainCapabilities>

``path``
   The full path to the emulator binary. Since not every hypervisor has a
   notion of emulator binary this element might be omitted in such drivers.
``domain``
   Describes the `virtualization type <formatdomain.html#element-and-attribute-overview>`__ (or so
   called domain type).
``machine``
   The domain's `machine type <formatdomain.html#bios-bootloader>`__. Since not
   every hypervisor has a sense of machine types this element might be omitted
   in such drivers.
``arch``
   The domain's `architecture <formatdomain.html#bios-bootloader>`__.

CPU Allocation
~~~~~~~~~~~~~~

Before any devices capability occurs, there might be info on domain wide
capabilities, e.g. virtual CPUs:

::

   <domainCapabilities>
     ...
     <vcpu max='255'/>
     ...
   </domainCapabilities>

``vcpu``
   The maximum number of supported virtual CPUs

BIOS bootloader
~~~~~~~~~~~~~~~

Sometimes users might want to tweak some BIOS knobs or use UEFI. For cases like
that, `os <formatdomain.html#bios-bootloader>`__ element exposes what values can
be passed to its children.

::

   <domainCapabilities>
     ...
     <os supported='yes'>
       <enum name='firmware'>
         <value>bios</value>
         <value>efi</value>
       </enum>
       <loader supported='yes'>
         <value>/usr/share/OVMF/OVMF_CODE.fd</value>
         <enum name='type'>
           <value>rom</value>
           <value>pflash</value>
         </enum>
         <enum name='readonly'>
           <value>yes</value>
           <value>no</value>
         </enum>
         <enum name='secure'>
           <value>yes</value>
           <value>no</value>
         </enum>
       </loader>
     </os>
     ...
   <domainCapabilities>

The ``firmware`` enum corresponds to the ``firmware`` attribute of the ``os``
element in the domain XML. The presence of this enum means libvirt is capable of
the so-called firmware auto-selection feature. And the listed firmware values
represent the accepted input in the domain XML. Note that the ``firmware`` enum
reports only those values for which a firmware "descriptor file" exists on the
host. Firmware descriptor file is a small JSON document that describes details
about a given BIOS or UEFI binary on the host, e.g. the firmware binary path,
its architecture, supported machine types, NVRAM template, etc. This ensures
that the reported values won't cause a failure on guest boot.

For the ``loader`` element, the following can occur:

``value``
   List of known firmware binary paths. Currently this is used only to advertise
   the known location of OVMF binaries for QEMU. OVMF binaries will only be
   listed if they actually exist on host.
``type``
   Whether the boot loader is a typical BIOS (``rom``) or a UEFI firmware
   (``pflash``). Each ``value`` sub-element under the ``type`` enum represents a
   possible value for the ``type`` attribute for the <loader/> element in the
   domain XML. E.g. the presence of ``pfalsh`` under the ``type`` enum means
   that a domain XML can use UEFI firmware via: <loader/> type="pflash"
   ...>/path/to/the/firmware/binary/</loader>.
``readonly``
   Options for the ``readonly`` attribute of the <loader/> element in the domain
   XML.
``secure``
   Options for the ``secure`` attribute of the <loader/> element in the domain
   XML. Note that the value ``yes`` is listed only if libvirt detects a firmware
   descriptor file that has path to an OVMF binary that supports Secure boot,
   and lists its architecture and supported machine type.

CPU configuration
~~~~~~~~~~~~~~~~~

The ``cpu`` element exposes options usable for configuring `guest
CPUs <formatdomain.html#cpu-model-and-topology>`__.

::

   <domainCapabilities>
     ...
     <cpu>
       <mode name='host-passthrough' supported='yes'>
         <enum name='hostPassthroughMigratable'>
           <value>on</value>
           <value>off</value>
         </enum>
       </mode>
       <mode name='maximum' supported='yes'>
         <enum name='maximumMigratable'>
           <value>on</value>
           <value>off</value>
         </enum>
       </mode>
       <mode name='host-model' supported='yes'>
         <model fallback='allow'>Broadwell</model>
         <vendor>Intel</vendor>
         <maxphysaddr mode="passthrough" limit="39"/>
         <feature policy='disable' name='aes'/>
         <feature policy='require' name='vmx'/>
       </mode>
       <mode name='custom' supported='yes'>
         <model usable='no' deprecated='no' vendor='Intel'>Broadwell</model>
         <model usable='yes' deprecated='no' vendor='Intel'>Broadwell-noTSX</model>
         <model usable='no' deprecated='yes' vendor='Intel'>Haswell</model>
         <model usable='no' deprecated='no' vendor='AMD'>EPYC-Milan</model>
         ...
       </mode>
     </cpu>
     ...
   <domainCapabilities>

Each CPU mode understood by libvirt is described with a ``mode`` element which
tells whether the particular mode is supported and provides (when applicable)
more details about it:

``host-passthrough``
   The ``hostPassthroughMigratable`` enum shows possible values of the
   ``migratable`` attribute for the <cpu> element with
   ``mode='host-passthrough'`` in the domain XML.
``host-model``
   If ``host-model`` is supported by the hypervisor, the ``mode`` describes the
   guest CPU which will be used when starting a domain with ``host-model`` CPU.
   The hypervisor specifics (such as unsupported CPU models or features, machine
   type, etc.) may be accounted for in this guest CPU specification and thus the
   CPU can be different from the one shown in host capabilities XML. This is
   indicated by the ``fallback`` attribute of the ``model`` sub element:
   ``allow`` means not all specifics were accounted for and thus the CPU a guest
   will see may be different; ``forbid`` indicates that the CPU a guest will see
   should match this CPU definition. The optional ``maxphysaddr`` element
   reports physical address size of the host CPU if this value is available and
   applicable for the requested domain type. This is useful for computing
   baseline CPU definition which should be compatible with several hosts.
``custom``
   The ``mode`` element contains a list of supported CPU models, each described
   by a dedicated ``model`` element. The ``usable`` attribute specifies whether
   the model can be used directly on the host. A special value ``unknown``
   indicates libvirt does not have enough information to provide the usability
   data. When ``usable='no'`` the corresponding model cannot be used without
   disabling some features that the CPU of such model is expected to have. The
   list of features blocking usability of a particular CPU model is returned
   as disabled features in the result of ``virConnectBaselineHypervisorCPU``
   API (or ``virsh hypervisor-cpu-baseline``) when called on a CPU definition
   using the CPU model and no additional feature elements. Models marked as
   usable (``usable='yes'``) can be safely used in domain XMLs with
   ``check='none'`` as the hypervisor guarantees the model can be used on the
   current host and additional checks done by libvirt are redundant. In fact,
   disabling libvirt checks via ``check='none'`` for such models is recommended
   to avoid needless issues with starting domains when libvirt's definition of
   a particular model differs from hypervisor's definition. The
   ``deprecated`` attribute reflects the hypervisor's policy on usage of this
   model :since:`(since 7.1.0)`. The ``vendor`` attribute :since:`(since 8.9.0)`
   contains the vendor of the CPU model for users who want to use CPU models
   with specific vendors only. CPU models with undefined vendor will be listed
   with ``vendor='unkwnown'``.

I/O Threads
~~~~~~~~~~~

The ``iothread`` elements indicates whether or not `I/O
threads <formatdomain.html#iothreads-allocation>`__ are supported.

::

   <domainCapabilities>
     ...
     <iothread supported='yes'/>
     ...
   <domainCapabilities>

Memory Backing
~~~~~~~~~~~~~~

The ``memory backing`` element indicates whether or not `memory
backing <formatdomain.html#memory-backing>`__ is supported.

::

   <domainCapabilities>
     ...
     <memoryBacking supported='yes'>
       <enum name='sourceType'>
         <value>anonymous</value>
         <value>file</value>
         <value>memfd</value>
       </enum>
     </memoryBacking>
     ...
   <domainCapabilities>

``sourceType``
   Options for the ``type`` attribute of the <memoryBacking><source> element.

Devices
~~~~~~~

Another set of XML elements describe the supported devices and their
capabilities. All devices occur as children of the main ``devices`` element.

::

   <domainCapabilities>
     ...
     <devices>
       <disk supported='yes'>
         <enum name='diskDevice'>
           <value>disk</value>
           <value>cdrom</value>
           <value>floppy</value>
           <value>lun</value>
         </enum>
         ...
       </disk>
       <hostdev supported='no'/>
     </devices>
   </domainCapabilities>

Reported capabilities are expressed as an enumerated list of available options
for each of the element or attribute. For example, the <disk/> element has an
attribute ``device`` which can support the values ``disk``, ``cdrom``,
``floppy``, or ``lun``.

Hard drives, floppy disks, CDROMs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disk capabilities are exposed under the ``disk`` element. For instance:

::

   <domainCapabilities>
     ...
     <devices>
       <disk supported='yes'>
         <enum name='diskDevice'>
           <value>disk</value>
           <value>cdrom</value>
           <value>floppy</value>
           <value>lun</value>
         </enum>
         <enum name='bus'>
           <value>ide</value>
           <value>fdc</value>
           <value>scsi</value>
           <value>virtio</value>
           <value>xen</value>
           <value>usb</value>
           <value>sata</value>
           <value>sd</value>
         </enum>
       </disk>
       ...
     </devices>
   </domainCapabilities>

``diskDevice``
   Options for the ``device`` attribute of the <disk/> element.
``bus``
   Options for the ``bus`` attribute of the <target/> element for a <disk/>.

Graphical framebuffers
^^^^^^^^^^^^^^^^^^^^^^

Graphics device capabilities are exposed under the ``graphics`` element. For
instance:

::

   <domainCapabilities>
     ...
     <devices>
       <graphics supported='yes'>
         <enum name='type'>
           <value>sdl</value>
           <value>vnc</value>
           <value>spice</value>
         </enum>
       </graphics>
       ...
     </devices>
   </domainCapabilities>

``type``
   Options for the ``type`` attribute of the <graphics/> element.

Video device
^^^^^^^^^^^^

Video device capabilities are exposed under the ``video`` element. For instance:

::

   <domainCapabilities>
     ...
     <devices>
       <video supported='yes'>
         <enum name='modelType'>
           <value>vga</value>
           <value>cirrus</value>
           <value>vmvga</value>
           <value>qxl</value>
           <value>virtio</value>
         </enum>
       </video>
       ...
     </devices>
   </domainCapabilities>

``modelType``
   Options for the ``type`` attribute of the <video><model> element.

Host device assignment
^^^^^^^^^^^^^^^^^^^^^^

Some host devices can be passed through to a guest (e.g. USB, PCI and SCSI).
Well, only if the following is enabled:

::

   <domainCapabilities>
     ...
     <devices>
       <hostdev supported='yes'>
         <enum name='mode'>
           <value>subsystem</value>
           <value>capabilities</value>
         </enum>
         <enum name='startupPolicy'>
           <value>default</value>
           <value>mandatory</value>
           <value>requisite</value>
           <value>optional</value>
         </enum>
         <enum name='subsysType'>
           <value>usb</value>
           <value>pci</value>
           <value>scsi</value>
         </enum>
         <enum name='capsType'>
           <value>storage</value>
           <value>misc</value>
           <value>net</value>
         </enum>
         <enum name='pciBackend'>
           <value>default</value>
           <value>kvm</value>
           <value>vfio</value>
           <value>xen</value>
         </enum>
       </hostdev>
     </devices>
   </domainCapabilities>

``mode``
   Options for the ``mode`` attribute of the <hostdev/> element.
``startupPolicy``
   Options for the ``startupPolicy`` attribute of the <hostdev/> element.
``subsysType``
   Options for the ``type`` attribute of the <hostdev/> element in case of
   ``mode="subsystem"``.
``capsType``
   Options for the ``type`` attribute of the <hostdev/> element in case of
   ``mode="capabilities"``.
``pciBackend``
   Options for the ``name`` attribute of the <driver/> element.

RNG device
^^^^^^^^^^

RNG device capabilities are exposed under the ``rng`` element. For instance:

::

   <domainCapabilities>
     ...
     <devices>
       <rng supported='yes'>
         <enum name='model'>
           <value>virtio</value>
           <value>virtio-transitional</value>
           <value>virtio-non-transitional</value>
         </enum>
         <enum name='backendModel'>
           <value>random</value>
           <value>egd</value>
           <value>builtin</value>
         </enum>
       </rng>
       ...
     </devices>
   </domainCapabilities>

``model``
   Options for the ``model`` attribute of the <rng> element.
``backendModel``
   Options for the ``model`` attribute of the <rng><backend> element.

Filesystem device
^^^^^^^^^^^^^^^^^

Filesystem device capabilities are exposed under the ``filesystem`` element. For
instance:

::

   <domainCapabilities>
     ...
     <devices>
       <filesystem supported='yes'>
         <enum name='driverType'>
           <value>default</value>
           <value>path</value>
           <value>handle</value>
           <value>virtiofs</value>
         </enum>
       </filesystem>
       ...
     </devices>
   </domainCapabilities>

``driverType``
   Options for the ``type`` attribute of the <filesystem><driver> element.

TPM device
^^^^^^^^^^

TPM device capabilities are exposed under the ``tpm`` element. For instance:

::

  <domainCapabilities>
    ...
    <devices>
      <tpm supported='yes'>
        <enum name='model'>
          <value>tpm-tis</value>
          <value>tpm-crb</value>
        </enum>
        <enum name='backendModel'>
          <value>passthrough</value>
          <value>emulator</value>
        </enum>
        <enum name='backendVersion'>
          <value>1.2</value>
          <value>2.0</value>
        </enum>
      </tpm>
      ...
    </devices>
  </domainCapabilities>

``model``
   Options for the ``model`` attribute of the ``<tpm/>`` element.
``backendModel``
   Options for the ``type`` attribute of the ``<tpm><backend/>`` element.
``backendVersion``
   Options for the ``version`` attribute of the ``<tpm><backend/>`` element.

USB redirect device
^^^^^^^^^^^^^^^^^^^

USB redirdev device capabilities are exposed under the ``redirdev`` element. For instance:

::

  <domainCapabilities>
    ...
    <devices>
      <redirdev supported='yes'>
        <enum name='bus'>
          <value>usb</value>
        </enum>
      </redirdev>
      ...
    </devices>
  </domainCapabilities>

``bus``
   Options for the ``bus`` attribute of the ``<redirdev/>`` element.

Channel device
^^^^^^^^^^^^^^

Channel device capabilities are exposed under the ``channel`` element. For instance:

::

  <domainCapabilities>
    ...
    <devices>
      <channel supported='yes'>
        <enum name='type'>
          <value>pty</value>
          <value>unix</value>
          <value>spicevmc</value>
        </enum>
      </channel
      ...
    </devices>
  </domainCapabilities>

``type``
   Options for the ``type`` attribute of the ``<channel/>`` element.

Crypto device
^^^^^^^^^^^^^^

Crypto device capabilities are exposed under the ``crypto`` element. For instance:

::

  <domainCapabilities>
    ...
    <devices>
      <crypto supported='yes'>
        <enum name='model'>
          <value>virtio</value>
        </enum>
        <enum name='type'>
          <value>qemu</value>
        </enum>
        <enum name='backendModel'>
          <value>builtin</value>
          <value>lkcf</value>
        </enum>
      </crypto>
      ...
    </devices>
  </domainCapabilities>

``model``
   Options for the ``model`` attribute of the ``<crypto/>`` element.
``type``
   Options for the ``type`` attribute of the ``<crypto/>`` element.
``backendModel``
   Options for the ``backendModel`` attribute of the ``<crypto><backend/>`` element.

Features
~~~~~~~~

One more set of XML elements describe the supported features and their
capabilities. All features occur as children of the main ``features`` element.

::

   <domainCapabilities>
     ...
     <features>
       <gic supported='yes'>
         <enum name='version'>
           <value>2</value>
           <value>3</value>
         </enum>
       </gic>
       <vmcoreinfo supported='yes'/>
       <genid supported='yes'/>
       <backingStoreInput supported='yes'/>
       <backup supported='yes'/>
       <async-teardown supported='yes'/>
       <sev>
         <cbitpos>47</cbitpos>
         <reduced-phys-bits>1</reduced-phys-bits>
       </sev>
       <sgx supported='yes'>
         <flc>no</flc>
         <sgx1>yes</sgx1>
         <sgx2>no</sgx2>
         <section_size unit='KiB'>524288</section_size>
         <sections>
           <section node='0' size='262144' unit='KiB'/>
           <section node='1' size='262144' unit='KiB'/>
         </sections>
       </sgx>
       <hyperv supported='yes'>
         <enum name='features'>
           <value>relaxed</value>
           <value>vapic</value>
         </enum>
       </hyperv>
     </features>
   </domainCapabilities>

Reported capabilities are expressed as an enumerated list of possible values for
each of the elements or attributes. For example, the ``gic`` element has an
attribute ``version`` which can support the values ``2`` or ``3``.

For information about the purpose of each feature, see the `relevant
section <formatdomain.html#hypervisor-features>`__ in the domain XML documentation.

GIC capabilities
^^^^^^^^^^^^^^^^

GIC capabilities are exposed under the ``gic`` element.

``version``
   Options for the ``version`` attribute of the ``gic`` element.

vmcoreinfo
^^^^^^^^^^

Reports whether the vmcoreinfo feature can be enabled.

genid
^^^^^

Reports whether the genid feature can be used by the domain.

backingStoreInput
^^^^^^^^^^^^^^^^^

Reports whether the hypervisor will obey the <backingStore> elements configured
for a <disk> when booting the guest, hotplugging the disk to a running guest, or
similar. :since:`(Since 5.10)`

backup
^^^^^^

Reports whether the hypervisor supports the backup, checkpoint, and related
features. (``virDomainBackupBegin``, ``virDomainCheckpointCreateXML`` etc). The
presence of the ``backup`` element even if ``supported='no'`` implies that the
``VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA`` flag for ``virDomainUndefine`` is
supported.

async-teardown
^^^^^^^^^^^^^^

Reports whether the asynchronous teardown feature can be enabled.

s390-pv capability
^^^^^^^^^^^^^^^^^^

Reports whether the hypervisor supports the Protected Virtualization. In order
to use Protected Virtualization with libvirt have a look at the `launchSecurity
element in the domain XML <formatdomain.html#launch-security>`__. For more
details on the Protected Virtualization feature please see `Protected
Virtualization on s390 <kbase/s390_protected_virt.html>`__.

SEV capabilities
^^^^^^^^^^^^^^^^

AMD Secure Encrypted Virtualization (SEV) capabilities are exposed under the
``sev`` element. SEV is an extension to the AMD-V architecture which supports
running virtual machines (VMs) under the control of a hypervisor. When
supported, guest owner can create a VM whose memory contents will be
transparently encrypted with a key unique to that VM.

For more details on the SEV feature, please follow resources in the AMD
developer's document store. In order to use SEV with libvirt have a look at `SEV
in domain XML <formatdomain.html#launch-security>`__

``cbitpos``
   When memory encryption is enabled, one of the physical address bits (aka the
   C-bit) is utilized to mark if a memory page is protected. The C-bit position
   is Hypervisor dependent.
``reducedPhysBits``
   When memory encryption is enabled, we lose certain bits in physical address
   space. The number of bits we lose is hypervisor dependent.
``maxGuests``
   The maximum number of SEV guests that can be launched on the host. This value
   may be configurable in the firmware for some hosts.
``maxESGuests``
   The maximum number of SEV-ES guests that can be launched on the host. This
   value may be configurable in the firmware for some hosts.

SGX capabilities
^^^^^^^^^^^^^^^^

Intel Software Guard Extensions (Intel SGX) capabilities are exposed under the
``sgx`` element.

Intel SGX helps protect data in use via unique application isolation technology.
Protect selected code and data from modification using hardened enclaves with
Intel SGX.

For more details on the SGX feature, please follow resources in the SGX developer's
document store. In order to use SGX with libvirt have a look at `SGX in domain XML
<formatdomain.html#memory-devices>`__

``flc``
   FLC (Flexible Launch Control), not strictly part of SGX2, but was not part of
   original SGX hardware either.

``sgx1``
   the sgx version 1.

``sgx2``
   The sgx version 2.

``section_size``
   The size of the SGX enclave page cache (called EPC).

``sections``
   The sections of the SGX enclave page cache (called EPC).


Hyper-V Enlightenments
^^^^^^^^^^^^^^^^^^^^^^

Report which features improving behavior of guests running Microsoft Windows
are supported. The ``features`` enum corresponds to the ``<hyperv/>`` element
(well, its children) as documented in `Hypervisor features
<formatdomain.html#hypervisor-features>`__.

Please note that depending on the QEMU version some capabilities might be
missing even though QEMU does support them. This is because prior to QEMU-6.1.0
not all features were reported by QEMU.
