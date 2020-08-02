================
libvirt releases
================

This is the list of official releases for libvirt, along with an overview of
the changes introduced by each of them.

For a more fine-grained view, use the `git log`_.


v6.6.0 (2020-08-02)
===================

* **New features**

  * Allow configuring of ACPI NUMA HMAT

    Libvirt allows configuring ACPI Heterogeneous Memory Attribute Table to
    hint software running inside the guest on optimization.

  * esx: Add a ``type`` attribute for mac addresses.

    This attribute allows (when set to ``static``) ignoring VMWare checks of the
    MAC addresses that would generate a new one if they were in its OUI
    (00:0c:29).

  * conf: add control over COW for storage pool directories

    The storage pool code now attempts to disable COW by default on btrfs, but
    management applications may wish to override this behaviour. This is now
    possible via new ``cow`` element.

* **Improvements**

  * esx: Change the NIC limit for recent virtualHW versions

    Specifying a virtualHW version greater or equal to 7 (ESXi 4.0) will allow
    you to use up to 10 NICs instead of 4 as it was previously.

  * qemu: Support encrypted TLS keys for NBD disks

    The secret key used for disks can now be encrypted similarly to TLS keys
    used for migration, chardev and others.

  * qemu: ``VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD`` can now be registered for ``<mirror>``

    The event can now be used also for block copy destinations by using the
    index of the ``<mirror>`` image.

  * qemu: consider available CPUs in ``vcpupin/emulatorpin`` output

    This patch changes the default bitmap of ``vcpupin`` and ``emulatorpin``,
    in the case of domains with static vcpu placement, all available CPUs
    instead of all possible CPUs are returned making these APIs consistent with
    the behavior of ``vcpuinfo``.


* **Bug fixes**

  * virdevmapper: Don't use libdevmapper to obtain dependencies

    When building domain's private ``/dev`` in a namespace, libdevmapper was
    consulted for getting full dependency tree of domain's disks. However, this
    meant that libdevmapper opened ``/dev/mapper/control`` which wasn't closed
    and was leaked to QEMU. CVE-2020-14339

  * qemu: Report correct ``index`` in ``VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD``

    Starting from libvirt 5.10 with QEMU 4.2 the
    ``VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD`` event would report incorrect device
    ``index`` when reported for an image from the backing chain of a disk.

  * qemu: Don't fail active layer block commit or block copy in certain cases

    Starting from libvirt-6.5 an active layer block commit or a block copy could
    fail if the same destination was used more than once.

  * qemu: Don't change ownership of restore file

    When restoring a domain from a file, Libvirt no longer changes its ownership.

  * qemu: Set SPAPR TPM default to 2.0 and prevent 1.2 choice

    The firmware (SLOF) on QEMU for ppc64 does not support TPM 1.2, so prevent
    the choice of TPM 1.2 when the SPAPR device model is chosen and use a
    default of '2.0' (TPM 2) for the backend.

  * qemu: Do not set ``//cpu/@migratable`` for running domains

    Libvirt release of 6.4.0 started to fill the default value for
    ``//cpu/@migratable`` attribute according to QEMU support. However, active
    domains either have the migratable attribute already set or they were
    started with older Libvirt which doesn't support the attribute.


v6.5.0 (2020-07-03)
===================

* **New features**

  * Allow firmware blobs configuration

    QEMU offers a way to tweak how firmware configures itself
    and/or provide new configuration blobs. New ``<sysinfo/>``
    type is introduced that will hold these new blobs.
    It's possible to either specify new value as a string or
    provide a filename which contents then serve as the value.

  * nodedev: Add ability to create mediated devices

    Mediated devices can now be created with ``virNodeDeviceCreateXML()``. This
    functionality requires the ``mdevctl`` utility to be installed. The XML
    schema for node devices was expanded to support attributes for mediated
    devices.

  * QEMU: add TPM Proxy device support

    libvirt can now create guests using a new device type called
    "TPM Proxy". The TPM Proxy connects to a TPM Resource Manager
    present in the host, enabling the guest to run in secure virtual
    machine mode with the help of an Ultravisor. Adding a TPM Proxy to
    a pSeries guest brings no security benefits unless the guest is
    running on a PPC64 host that has Ultravisor and TPM Resource Manager
    support. Only one TPM Proxy is allowed per guest. A guest using
    a TPM Proxy device can instantiate another TPM device at the same
    time. This device is supported only for pSeries guests via the new
    'spapr-tpm-proxy' model of the TPM 'passthrough' backend.

  * virhook: Support hooks placed in several files

    Running all scripts from directory /etc/libvirt/hooks/<driver>.d in
    alphabetical order. Hook script in old place will be executed
    as first for backward compatibility.

  * qemu: Add support for migratable host-passthrough CPU

    QEMU 2.12 made it possible for guests to use a migration-friendly
    version of the host-passthrough CPU. This feature is now exposed by
    libvirt.

* **Improvements**

  * network: Support NAT with IPv6

    It's now possible to use ``<nat ipv6="yes"/>`` in a libvirt network.

  * qemu: Auto-fill NUMA information for incomplete topologies

    If the NUMA topology is not fully described in the guest XML, libvirt
    will complete it by putting all unspecified CPUs in the first NUMA node.
    This is only done in the QEMU binary itself supports disjointed CPU
    ranges for NUMA nodes.

  * qemu: Assign hostdev-backed interfaces to PCIe slots

    All SR-IOV capable devices are PCIe, so when their VFs are assigned to
    guests they should end up in PCIe slots rather than conventional PCI ones.

* **Bug fixes**

  * qemu: fixed crash in ``qemuDomainBlockCommit``

    This release fixes a regression which was introduced in libvirt v6.4.0
    where libvirtd always crashes when a block commit of a disk is requested.

  * qemu: fixed zPCI address auto generation on s390

    Removes the correlation between the zPCI address attributes uid and fid.
    Fixes the validation and autogeneration of zPCI address attributes.

  * qemu: Skip pre-creation of NVMe disks during migration

    libvirt has no way to create NVMe devices on the target host, so it now
    just makes sure they exist and let the migration proceed in that case.


v6.4.0 (2020-06-02)
===================

* **New features**

  * qemu: Add support for pvscsi controllers

    pvscsi is the VMware paravirtualized SCSI controller, which has been
    supported in QEMU for a number of years.

  * cpu: Report model information for ARM CPUs

    ``virsh capabilities`` will now include information about the host CPU when
    run on ARM machines.

* **Improvements**

  * qemu: stricter validation for disk type='lun'

    The 'lun' type is meant for SCSI command passthrough, which can't be
    achieved if qemu's block layer features are used. Disk type='lun' is now
    allowed only when the format is 'raw' and no other block layer features are
    requested.

  * qemu: auto-fill of incomplete NUMA topologies

    Domains with incomplete NUMA topologies, where the sum of vCPUs in all NUMA
    cells is less than the total of vCPUs, will get their first NUMA cell to
    be auto-filled with the remaining vCPUs. This behavior reproduces what QEMU
    already does in these cases. Users are encouraged to provide complete NUMA
    topologies to avoid unexpected changes in the domain XML.

* **Bug fixes**

  * qemu: fixed regression in network device hotplug with new qemu versions

    Starting from QEMU-5.0 it's required to conform to strict schema when
    hotplugging network devices. Libvirt didn't conform to the schema so in
    versions prior to 6.4.0 network device hotplug fails in certain cases. This
    version fixes it and adds stricter testing to prevent further issues.

  * remote: Look up libxl driver correctly

    This makes ``xen://`` connection URIs usable in split daemon mode.

  * systemd: Start libvirtd after firewalld/iptables services

    This solves an issue where iptables rules and chains created by libvirtd
    would get removed by a service started after it.

  * network: Re-create iptables chains on firewalld restart

    firewalld resets all iptables rules and chains on restart, and this
    includes deleting those created by libvirt.

  * qemu: reject readonly attribute for virtiofs

    virtiofs does not yet support read-only shares.


v6.3.0 (2020-05-05)
===================

* **New features**

  * qemu: support network interface downscript

    QEMU has the ability to run a script when a NIC is brought up and down.
    Libvirt only enables use of the up script. Now add support for postscript
    when NIC is down/detached.

  * qemu: support disabling hotplug/unplug of PCIe devices

    libvirt can now set the "hotplug" option for pcie-root-ports and
    pcie-switch-downstream-ports, which can be used to disable hotplug/unplug
    of devices from these ports (default behavior is for these controllers to
    accept all hotplug/unplug attempts, but this is often undesireable).

  * vbox: added support for version 6.0 and 6.1 APIs

    libvirt can now support use of the VirtualBox 6.0 and 6.1 APIs. This is
    compile tested only, so we are looking for feedback from users on how well
    it works in practice.

  * xen: Add support for 'e820_host' hypervisor feature

    ``e820_host`` is a Xen-specific option only available for PV guests. When
    enabled it provides the guest with a virtual e820 memory map based on the
    host one. It must be enabled to allow hotplugging PCI devices to PV guests,
    particularly when memory ballooning is enabled.

  * xen: Add support for 'passthrough' hypervisor feature

    ``passthrough`` is a Xen-specific option new to Xen 4.13 that enables PCI
    passthrough for guests. It must be enabled to allow hotplugging PCI
    devices.

  * qemu: support async IO mode 'io_uring'

    Linux 5.1 introduces a fast and efficient async IO interface io_uring, then
    qemu implements that in version 5.0. It could be used in file, host device
    and host cdrom backend by ``io='io_uring'`` of disk XML.

  * Lease time option included for network DHCP settings

    Users can now configure expiry time for leases for networks where libvirt
    manages DHCP. The time can be specified for whole range and/or fine tuned
    per individual host.

  * qemu: Implement pSeries Spectre mitigation features

    Users can now setup the following capabilities of pSeries guests: CFPC
    (Cache Flush on Privilege Change), SBBC (Speculation Barrier Bounds
    Checking) and IBS (Indirect Branch Speculation).

  * qemu: Add support for virtio packed option

    The ``packed`` attribute controls if QEMU should try to use packed
    virtqueues. Possible values are ``on`` or ``off``.

* **Improvements**

  * qemu: Allow checkpoint redefine for offline VMs

    Skip the liveness and capability checks when redefining checkpoints as we
    don't need QEMU interactions to update the metadata.

  * daemons: Improve timeout handling

    Daemons now support ``--timeout 0`` which suppresses daemon killing after
    given time of inactivity.

  * qemu: Add support for 'multidevs' option

    This option prevents misbehaviours on guest if a QEMU 9pfs export contains
    multiple devices, due to the potential file ID collisions this otherwise
    may cause.

* **Bug fixes**

  * qemu: Various embed driver fixes

    When using shared resources from embed driver (e.g. hugepages, machined,
    etc.) libvirt now generates an unique handler that is not conflicting with
    other embed drivers or system or session daemons.

  * cpu: Distinguish Cascadelake-Server from Skylake-Server

    Libvirt now properly detects Cascadelake-Server and Skylake-Server
    processors which differ only in stepping.

  * qemu: Fix domain restore from a block device

    When using namespaces, libvirt was unable to restore a domain from a block
    device because libvirt tried to relabel the device inside the namespace
    while QEMU was given FD to the block device in the host.

  * node_device_udev: Handle move events

    Libvirt now handles ``move`` event which is emitted on a NIC rename.

  * qemu: Fix capabilities probing with TCG

    Libvirt no long assumes TCG is always available. It now detects whether
    QEMU supports TCG and reports it accordingly.

* **Removed features**

  * vbox: removed support for version 5.0 and 5.1 APIs

    libvirt no longer supports use of VirtualBox 5.0 and 5.1 since these
    versions reached their end of life on 2017/05 and 2018/04 respectively.


v6.2.0 (2020-04-02)
===================

* **New features**

  * qemu: NVDIMM support for pSeries guests

    QEMU 5.0 implements NVDIMM memory support for pSeries guests. This is done
    by adding an 'uuid' element in the memory XML, which can either be provided
    in the XML or, if omitted, generated automatically.

  * qemu: Add virtiofs support

    This feature, introduced in QEMU 4.2, is a more modern alternative to
    virtio-9p, which is exposed through the same ``<filesystem/>`` element.

  * admin: Support reloading TLS certificates

    After renewing TLS certificates, it was usually necessary to restart
    libvirtd for the new ones to be loaded: now the same result can be obtained
    without restarting the daemon by using ``virt-admin server-update-tls`` .

* **Removed features**

  * Removed support for INI style of comments

    With switching of our internal code to GLib, parsing of client
    authentication config files is handed over to GLib which does not support
    ``INI`` style of comments starting with a semicolon ( ``;`` ). Use number
    sign ( ``#`` ) instead.

* **Improvements**

  * qemu: Don't compare local and remote hostnames on migration

    This check was introduced to prevent same-host migration, but did not work
    as expected when multiple libvirtd instances were running on the same host
    but in different containers. With this release, the host UUID (which should
    be unique to the container) is checked instead.

  * qemu: Use per-VM event loops

    Instead of using a single even loop to process communication with the QEMU
    monitor and guest agent, create a separate one for each VM. This helps with
    scalability and prevents scenarios where a single malfunctioning VM could
    affect all those running on the same host.

  * qemu: Support migration with SLIRP helper interface

    With QEMU 5.0, a new D-Bus backend allows migration of external processes.
    When needed, libvirt will start a per-vm D-Bus bus, and migrate the
    slirp-helper along with QEMU.

* **Bug fixes**

  * qemu: Open backing chain late for shallow block copy reusing external
    images

    With introduction of -blockdev for QEMU storage configuration in
    libvirt-5.10 we've started opening the backing chain of the
    destination/mirror of a virDomainBlockcopy started with
    VIR_DOMAIN_BLOCK_COPY_REUSE_EXT | VIR_DOMAIN_BLOCK_COPY_SHALLOW flags when
    starting the job rather than when virDomainBlockJobAbort with
    VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT is issued. For users depending on this
    undocumented quirky pre-blockdev behaviour this caused a regression as the
    backing chain could not be modified while the copy of the top image was
    progressing due to QEMU image locking. Note that this fix also requires
    qemu-5.0 while -blockdev is used starting from QEMU-4.2.

  * Don't generate machine names containing dots

    Even though the guest name containing dots is not a problem for libvirt
    itself, we need to strip them out when registering with machined because of
    the latter's requirements.


v6.1.0 (2020-03-03)
===================

* **New features**

  * qemu: new rng backend type: builtin

    It implements qemu builtin rng backend. That uses getrandom syscall to
    generate random, no external rng source needed. Available since QEMU 4.2.

  * support for virtio+hostdev NIC <teaming>

    QEMU 4.2.0 and later, combined with a sufficiently recent guest virtio-net
    driver (e.g. the driver included in Linux kernel 4.18 and later), supports
    setting up a simple network bond device comprised of one virtio emulated
    NIC and one hostdev NIC (which must be an SRIOV VF). (in QEMU, this is
    known as the "virtio failover" feature). The allure of this setup is that
    the bond will always favor the hostdev device, providing better
    performance, until the guest is migrated - at that time QEMU will
    automatically unplug the hostdev NIC and the bond will send all traffic via
    the virtio NIC until migration is completed, then QEMU on the destination
    side will hotplug a new hostdev NIC and the bond will switch back to using
    the hostdev for network traffic. The result is that guests desiring the
    extra performance of a hostdev NIC are now migratable without network
    downtime (performance is just degraded during migration) and without
    requiring a complicated bonding configuration in the guest OS network
    config and complicated unplug/replug logic in the management application on
    the host - it can instead all be accomplished in libvirt with the interface
    <teaming> subelement "type" and "persistent" attributes.

  * support BR_ISOLATED flag for guest interfaces attached to a Linux host
    bridge

    Since Linux kernel 4.18, the Linux host bridge has had a flag BR_ISOLATED
    that can be applied to individual ports. When this flag is set for a port,
    traffic is blocked between that port and any other port that also has the
    BR_ISOLATED flag set. libvirt domain interface config now supports setting
    this flag via the <port isolated='yes'/> setting. It can also be set for
    all connections to a particular libvirt network by setting the same option
    in the network config - since the port for the host itself does not have
    BR_ISOLATED set, the guests can communicate with the host and the outside
    world, but guests on that network can't communicate with each other. This
    feature works for QEMU and LXC guests with interfaces attached to a Linux
    host bridge.

  * qemu: Introduce the 'armvtimer' timer type

    QEMU 5.0 introduces the ability to control the behavior of the virtual
    timer for KVM ARM/virt guests, and this new timer type exposes the same
    capability to libvirt users.

  * qemu: Storage configuration improvements

    Libvirt now accepts ``<backingStore type='volume'>`` and allows specifying
    the offset and size of the image format container inside the storage source
    via the ``<slices>`` subelement.

  * qemu: Introduce the 'tpm-spapr' TPM model

    This device, available starting from QEMU 5.0, is limited to pSeries
    guests.

  * qemu: support Panic Crashloaded event handling

    The pvpanic device now supports a 'crashloaded' event, which is emitted
    when a guest panic has occurred but has already been handled by the guest
    itself.

  * qemu: Implement virDomainGetHostnameFlags

    The ``--source`` argument to ``virsh domhostname`` can be used to specify
    what data source to use for the domain hostnames. Currently, in addition
    to the 'agent', libvirt can also use 'lease' information from dnsmasq to
    get the hostname.

* **Improvements**

  * qemu: Image format probing is allowed in certain cases

    To resolve regressions when users didn't specify the backing image format
    in the overlay, libvirt now probes the format in certain secure scenarios
    which fixes a few common existing cases. Additionally the knowledge base
    was extended to provide more information on how to rectify the problem.

  * qemu: Support "dies" in CPU topology

    This CPU topology concept, new in QEMU 4.1.0, sits between the existing
    "socket" and "core".

  * libxl: Add support for Credit2 scheduler parameters

  * lxc: Add support LXC 3 network configuration format

* **Bug fixes**

  * conf: Do not generate machine names ending with a dash

    Recent systemd versions do not allow them.

* **Packaging changes**

  * use of gnulib has been completely eliminated

    Historically libvirt has embedded gnulib to provide fixes for various
    platform portability problems. This usage has now been eliminated and
    alternative approaches for platform portability problems adopted where
    required. This has been validated on the set of platforms covered by
    automated CI build testing. Other modern Linux distros using glibc are
    expected to work. Linux distros using non-glibc packages, and other
    non-Linux platforms may encounter regressions when building this release.
    Please report any build problems encountered back to the project
    maintainers for evaluation.


v6.0.0 (2020-01-15)
===================

* **Packaging changes**

  * support for python2 is removed

    Libvirt is no longer able to be built using the Python 2 binary. Python 3
    must be used instead.

  * docs: the python docutils toolset is now required

    The use of rst2html has been introduced for the website build process since
    docs are now being written in the RST as an alternative to HTML.

* **New features**

  * new PCI hostdev address type: unassigned

    A new PCI hostdev address type 'unassigned' is introduced. An unassigned
    PCI hostdev behaves like any regular PCI hostdev inside Libvirt, but it is
    not usable by the guest. This gives the user a new option to manage the
    binding of PCI devices via Libvirt, declaring PCI hostdevs in the domain
    XML but allowing just a subset of them to be assigned to the guest.

  * Provide init scripts for sub-deaemons

    So far libvirt shipped systemd unit files for sub-daemons. With this
    release, init scripts are available too. Package maintainers can choose
    which one to install via ``--with-init-script`` configure option.

  * qemu: Support cold-unplug of sound devices

  * qemu: Implement VIR_MIGRATE_PARAM_TLS_DESTINATION

    This flag, which can be enabled using ``virsh`` 's ``--tls-destination``
    option, allows migration to succeed in situations where there is a mismatch
    between the destination's hostname and the information stored in its TLS
    certificate.

  * qemu: Support reporting memory bandwidth usage stats

    Implement Intel RDT-MBM in libvirt. The stats can be obtained via ``virsh
    domstats --memory`` .

  * qemu: Allow accessing NVMe disks directly

    Before this release there were two ways to configure a NVMe disk for a
    domain. The first was using <disk/> with the <source/> pointing to the
    ``/dev/nvmeXXXX`` . The other was using PCI assignment via <hostdev/>
    element. Both have their disadvantages: the former adds latency of file
    system and block layers of the host kernel, the latter prohibits domain
    migration. In this release the third way of configuring NVMe disk is added
    which combines the advantages and drops disadvantages of the previous two
    ways. It's accessible via <disk type='nvme'/>.

* **Removed features**

  * 'phyp' Power Hypervisor driver removed

    The 'phyp' Power Hypervisor driver has not seen active development since
    2011 and does not seem to have any real world usage. It has now been
    removed.

* **Improvements**

  * qemu: xz save image compression is faster

    When using the xz format to compressed virtual machine saved state images,
    the "-3" compression level preset is now used. This results in slightly
    larger files, but with a massively reduced time to compress. The xz format
    offers the best compression level for saved state images, albeit still with
    the slowest running time. For the fastest possible running time, at cost of
    the larest compressed size, lzop should be used.

  * domain: Improve job stat handling

    It is now possible to retrieve stats for completed and failed jobs.

  * qemu: Don't hold monitor and agent job at the same time

    Before this change, a malicious (or buggy) ``qemu-guest-agent`` running in
    the guest could make other libvirt APIs unavailable for an unbounded amount
    of time.

* **Bug fixes**

  * qemu: Report error if backing image format is not specified explicitly

    For a long time libvirt was assuming that a backing file is RAW when the
    format was not specified. This didn't pose a problem until blockdev support
    was enabled in last release. Libvirt now requires that the format is
    specified in the image metadata or domain XML and the VM will refuse to
    start otherwise. Additionally the error message now links to the knowledge
    base which summarizes how to fix the images.

  * qemu: Fix non-shared storage migration over NBD

  * qemu: Generate a single MAC address for hotplugged network devices

    Since libvirt 4.6.0, when hotplugging a network device that didn't have a
    MAC address already assigned by the user, two separate addresses would be
    generated: one for the live configuration, which would show up immediately,
    and one for the inactive configuration, which would show up after the first
    reboot. This situation was clearly undesirable, so a single MAC address is
    now generated and used both for the live configuration and the inactive
    one.


v5.10.0 (2019-12-02)
====================

* **New features**

  * qemu: Introduce support for ARM CPU features

    The only features supported at the moment are SVE vector lengths, which
    were introduced in QEMU 4.2.0.

  * qemu: Support boot display for GPU mediated devices

    Until now, GPU mediated devices generally did not show any output until the
    guest OS had initialized the vGPU. By specifying the ``ramfb`` attribute,
    QEMU can be configured to use ramfb as a boot display for the device: this
    allows for display of firmware messages, boot loader menu, and other output
    before the guest OS has initialized the vGPU.

  * Add API to change the response timeout for guest agent commands

    By default, when a command is sent to the guest agent, libvirt waits
    forever for a response from the guest agent. If the guest is unresponsive
    for any reason, this can block the calling thread indefinitely. By setting
    a custom timeout using ``virDomainAgentSetResponseTimeout()`` , API users
    can change this behavior.

* **Improvements**

  * Devices CGroup v2 support

    Libvirt supported all controllers of CGroup v2 but the devices controller
    which is implemented in this release.

  * Cold plug of sound device

    The QEMU driver now can handle cold plug of ``<sound/>`` devices.

  * Probe for default CPU types

    With QEMU 4.2.0 we can probe for the default CPU model used by QEMU for a
    particular machine type and store it in the domain XML. This way the chosen
    CPU model is more visible to users and libvirt will make sure the guest
    will see the exact same CPU after migration.

  * Adaptation to qemu's blockdev

    QEMU introduced a new way of specifying disks on the command line which
    enables fine-grained control over the block stack. Libvirt has adapted to
    this.

* **Refactors**

  * More GLib integration

    More patches were merged that replace our internal functions with GLib
    ones. Also some effort was invested in replacing gnulib modules with GLib
    functions.

  * Rewrite of Perl scripts into Python

    Libvirt used Perl scripts to check for coding style, generate some code and
    things like that. To bring the number of languages used down, these scripts
    were rewritten into Python.

* **Bug fixes**

  * Warn verbosely if using old loader:nvram pairs

    Some distributions still use ``--with-loader-nvram`` or ``nvram`` variable
    in qemu.conf. This is now discouraged in favour of FW descriptors. However,
    instead of silently ignoring user's config, libvirt warns if outdated
    config is detected.

  * Drop pconfig from Icelake-Server CPU model

    The pconfig feature was enabled in QEMU by accident in 3.1.0. All other
    newer versions do not support it and it was removed from the Icelake-Server
    CPU model in QEMU.

  * Wait longer for device removal confirmation on PPC64

    After sending device hot unplug request to QEMU, libvirt waits up to 5
    seconds for qemu to confirm the device removal. On some architectures (like
    PPC64) this can take longer time and libvirt now reflects that.

  * Forcibly create nodes in domain's namespace

    The QEMU driver starts a domain in a namepsace with private ``/dev`` and
    creates only those nodes there which the domain is configured to have.
    However, it may have happened that if a node changed its minor number this
    change wasn't propagated to the namespace.

  * Various AppArmor bugfixes

    The AppArmor driver now knows how to handle ``<shmem/>`` devices and also
    snapshotting more disks at once.

  * Improved video model autoselection

    If a graphics device was added to XML that had no video device, libvirt
    automatically added a video device which was always of type 'cirrus' on
    x86_64, even if the underlying qemu didn't support cirrus. Libvirt now
    bases the decision on qemu's capabilities.


v5.9.0 (2019-11-05)
===================

* **Packaging changes**

  * Start linking against GLib and using its features

    Up until now, libvirt has been dealing with platform portability and the
    lack of certain features in libc by using gnulib and implementing its own
    functions and data structures respectively; going forward, it will prefer
    the facilities offered by GLib instead.

  * Stop distributing generated documentation

    Most downstreams already patch the libvirt source to some extent, so this
    change will probably not affect them.

  * Rewrite several Perl scripts in Python

    Phasing out Perl usage is part of the project strategy.

* **New features**

  * qemu: Introduce a new video model of type 'ramfb'

    Introduce a new video model type to the domain XML that supports the
    ``ramfb`` standalone device in qemu.

  * qemu: Implement the ccf-assist pSeries feature

    Users can now decide whether ccf-assist (Count Cache Flush Assist) support
    should be available to pSeries guests.

  * Xen: Support specifying ACPI firmware path

    The libxl driver now supports specifying an ACPI firmware path using the
    ``acpi`` element.

  * qemu: Support specifying resolution for video devices

* **Removed features**

  * logging: Drop support for including stack traces

    This feature was intended to aid debugging, but in practice it resulted in
    logs that were too verbose to be useful and also resulted in a significant
    performance penalty.

* **Improvements**

  * qemu: Implement CPU comparison/baseline on s390x

    This functionality has been historically limited to x86_64, but it's now
    available on s390x too.

* **Bug fixes**

  * lib: autostart objects exactly once

    If libvirtd or any of the sub-daemons is started with socket activation
    then objects might be autostarted more than once. For instance, if a domain
    under ``qemu:///session`` URI is mark as autostarted and the session daemon
    is started then the domain is started with it. If user shuts the domain
    down and the session daemon is started again, the user's wish to keep the
    domain shut off is ignored and the domain is autostarted again. This is now
    fixed.

  * qemu: Properly advertise bochs-display availability

    Support for ``bochs-display`` was introduced in libvirt 5.6.0, but until
    now the model was not listed in the domain capabilities.

  * security: Don't remember labels for TPM devices

    Due to the way they're implemented in the kernel, trying to remember labels
    for TPM devices makes it impossible to use them.

  * security: Properly rollback after failure in a stacked driver

    When multiple security drivers are involved, failure in one of them would
    result in only the corresponding changes being rolled back, leaving the
    ones performed by drivers that had been activated earlier in place. All
    changes are rolled back now.

  * Fix build with musl libc

  * Improve compatibility with non-bash shells


v5.8.0 (2019-10-05)
===================

* **New features**

  * qemu: Support use of precreated tap/macvtap devices by unprivileged
    libvirtd

    It is now possible for an unprivileged libvirtd to make use of tap and
    macvtap devices that were previously created by some other entity. This is
    done by setting ``managed='no'`` along with the device name in the
    ``target`` subelement of ``<interface type='ethernet'>`` .

  * qemu: Support vhost-user-gpu

    Support for running virtio GPUs in separate processes with vhost-user
    backend. It requires QEMU newer than 4.1.

  * Introduce virConnectSetIdentity API

    When split daemons are in use, this API is used to forward uid, gid and
    SELinux info from ``virproxyd`` to other driver daemons such as
    ``virtqemud`` .

* **Improvements**

  * qemu: Support running SLIRP networking in a separate process

    User can configure the slirp-helper path in ``qemu.conf`` . It will start a
    slirp-helper process to provide SLIRP networking when the VM is started
    with network interface "user". That will allow stricter security policies
    for QEMU SLIRP network.

* **Removed features**

  * Remove xenapi driver

    The xenapi driver is removed since it has not received any significant
    development since its initial contribution nine years ago and has no known
    user base.


v5.7.0 (2019-09-03)
===================

* **New features**

  * qemu: Support Direct Mode for Hyper-V Synthetic timers

    The QEMU driver now supports Direct Mode for Hyper-V Synthetic timers for
    Hyper-V guests.

  * lib: Add virDomainGetGuestInfo()

    This API is intended to aggregate several guest agent information queries
    and is inspired by stats API ``virDomainListGetStats()`` . It is
    anticipated that this information will be provided by a guest agent running
    within the domain. It's exposed as ``virsh guestinfo`` .

  * Experimental split of libvirtd into separate daemons

    The big monolithic libvirtd daemon can now be replaced by smaller
    per-driver daemons. The new split daemons are considered experimental at
    this time and distributions are encouraged to continue using the
    traditional libvirtd by default.

  * qemu: Support kvm-hint-dedicated performance hint

    With ``<hint-dedicated state='on'/>`` and ``<cpu
    mode='host-passthrough'/>`` , it allows a guest to enable optimizations
    when running on dedicated vCPUs. QEMU newer than 2.12.0 and kernel newer
    than 4.17 are required.

* **Removed features**

  * Remove KVM assignment support

    The KVM style of PCI device assignment was removed from the kernel in
    version 4.12.0 after being deprecated since 4.2.0. Libvirt defaults to VFIO
    for a long time. Remove support for KVM device assignment from libvirt too.

  * libxml: min required libxml is now 2.9.1

    Support for building with libxml versions older than 2.9.1 has been
    dropped.

* **Improvements**

  * virsh: Support setting bandwidth in migrate subcommand

    In addition to postcopy bandwidth, the ``virsh migrate`` subcommand now
    supports specifying precopy bandwidth with the ``--bandwidth`` parameter.

  * libxl: Implement domain metadata getter/setter

    The libxl driver now supports ``virDomainGetMetadata()`` and
    ``virDomainSetMetadata()`` APIs.

  * test driver: Expand API coverage

    Additional APIs have been implemented in the test driver.

  * Report RNG device in domain capabilities XML

    Libvirt now reports if RNG devices are supported by the underlying
    hypervisor in the domain capabilities XML.

  * Stop linking NSS plugins with libvirt.so

    This reduces the amount of code and 3rd party libraries are that loaded
    into all processes.

  * Split the setuid virt-login-shell binary into two pieces

    The setuid virt-login-shell binary is now a tiny shim that sanitizes the
    process execution environment variables and arguments, before launching the
    trusted virt-login-shell-helper binary.

  * qemu: Allow migration with disk cache on

    When QEMU supports flushing caches at the end of migration, we can safely
    allow migration even if ``disk/driver/@cache`` is neither ``none`` nor
    ``directsync`` .

* **Bug fixes**

  * Various security label remembering fixes

    In the previous release libvirt introduced remembering of original owners
    and SELinux labels on files. However, the feature did not work properly
    with snapshots, on migrations or on network filesystems. This is now fixed.

  * Allow greater PCI domain numbers

    Libvirt used to require PCI domain number to be not greater than 0xFFFF.
    The code was changed to allow 32 bits long numbers.

  * Various D-Bus fixes

    When D-Bus is not available, libvirt was reporting random errors. These are
    now gone.

  * Prefer read-only opening of PCI config files

    When enumerating PCI bus, libvirt opens config files under ``sysfs`` mount
    and parses them to learn various aspects of the device (e.g. its
    capabilities). Only in a very limited number of cases it is actually
    writing into the file. However, it used to open the file also for writing
    even if it was only reading from it.

  * Fix AppArmor profile

    Since the ``5.6.0`` release, libvirt uses ``procfs`` to learn the list of
    opened file descriptors when spawning a command. However, our AppArmor
    profile was not allowing such access.

  * Don't block storage driver when starting or building a pool

    Starting or building a storage pool can take a long time to finish. During
    this time the storage driver was blocked and thus no other API involving
    the storage driver could run. This is now fixed.


v5.6.0 (2019-08-05)
===================

* **New features**

  * qemu: Introduce a new video model of type 'bochs'

    Introduce a new video model type that supports the ``bochs-display`` device
    that was added in qemu version 3.0.

  * api: new virDomainCheckpoint APIs

    Introduce several new APIs for creating and managing checkpoints in the
    test and qemu drivers (the latter requires qcow2 images). Checkpoints serve
    as a way to tell which portions of a disk have changed since a point in
    time.

  * qemu: Add support for overriding max threads per process limit

    systemd-based systems impose a limit on the number of threads a process can
    spawn, which in some cases can be exceeded by QEMU processes running VMs.
    Add a ``max_threads_per_process`` option to qemu.conf to override the
    system default.

  * Remember original owners and SELinux labels of files

    When a domain is starting up libvirt changes DAC and SELinux labels so that
    domain can access it. However, it never remembered the original labels and
    therefore the file was returned back to ``root:root`` . With this release,
    the original labels are remembered and restored properly.

  * network: Allow passing arbitrary options to dnsmasq

    This works similarly to the existing support for passing arbitary options
    to QEMU, and just like that feature it comes with no support guarantees.

* **Removed features**

  * xen: Remove sxpr config support

    Remove the sxpr style config parser and formatter a year after the xend
    driver was removed.

* **Improvements**

  * qemu: Allow XML validation for snapshot creation

    Add flag ``VIR_DOMAIN_SNAPSHOT_CREATE_VALIDATE`` to validate snapshot input
    XML. For virsh, users can use it as ``virsh snapshot-create --validate`` .

  * Support encrypted soft TPM

    A soft TPM backend could be encrypted with passphrase. Now libvirt supports
    using a ``secret`` object to hold the passphrase, and referring to it via
    the ``encryption`` element of the TPM device.

  * test driver: Expand API coverage

    Additional APIs have been implemented in the test driver.

  * Implement per-driver locking

    Drivers now acquire a lock when they're loaded, ensuring that there can
    never be two instances of the same driver active at a time.

  * nss: Report newer addresses first

    In some cases, a guest might be assigned a new IP address by DHCP before
    the previous lease has expired, in which case the NSS plugin will correctly
    report both addresses; many applications, however, ignore all addresses but
    the first, and may thus end up trying to connect using a stale address. To
    prevent that from happening, the NSS plugin will now always report the
    newest address first.

  * util: Optimize mass closing of FDs when spawning child processes

    When the limit on the number of FDs is very high, closing all unwanted FDs
    after calling ``fork()`` can take a lot of time and delay the start of the
    child process. libvirt will now use an optimized algorithm that minimizes
    such delays.

* **Bug fixes**

  * logging: Ensure virtlogd rollover takes priority over logrotate

    virtlogd implements its own rollover mechanism, but until now logrotate
    could end up acting on the logs before virtlogd had a chance to do so
    itself.


v5.5.0 (2019-07-02)
===================

* **Security**

  * api: Prevent access to several APIs over read-only connections

    Certain APIs give root-equivalent access to the host, and as such should be
    limited to privileged users. CVE-2019-10161, CVE-2019-10166,
    CVE-2019-10167, CVE-2019-10168.

* **New features**

  * qemu: Support SMMUv3 IOMMU

    SMMUv3 is an IOMMU implementation for ARM virt guests.

  * network: Introduce the network port API

    This new public API can be used by virtualization drivers to manage network
    resources associated with guests, and is a further step towards splitting
    libvirtd into multiple daemons.

* **Removed features**

  * qemu: Remove support for virDomainQemuAttach and
    virConnectDomainXMLFromNative APIs

    The qemu implementations for the APIs mentioned above were removed and the
    APIs now return an error. The implementation was stale for a long time and
    did not work with modern QEMU command lines, generated from libvirt or
    otherwise.

  * Stop supporting migration of config files from pre-XDG layout

    The new layout was introduced with libvirt 0.9.13 (Jul 2012).

  * Remove Avahi mDNS support

    This feature was never used outside of virt-manager, which has itself
    stopped using it a while ago.

* **Improvements**

  * sysinfo: Report SMBIOS information on aarch64

    While SMBIOS support has historically been limited to x86_64, modern
    aarch64 machines often offer access to the same information as well, and
    libvirt now exposes it to the user when that's the case.

  * test driver: Expand API coverage

    Even more APIs that were missing from the test driver have now been
    implemented.

  * virt-xml-validate: Allow input to be read from stdin

  * qemu: Validate spapr-vio addresses as 32-bit

    libvirt has always considered these addresses (used for pSeries guests) as
    64-bit, but the sPAPR specification says that they're 32-bit instead.

* **Bug fixes**

  * qemu: Set process affinity correctly when using <numatune>

    libvirt would mistakenly interpret the ``nodeset`` attribute as a list of
    CPUs instead of as a list of NUMA node, and the process affinity would be
    set incorrectly as a result; this has now been fixed.


v5.4.0 (2019-06-03)
===================

* **Security**

  * cpu: Introduce support for the md-clear CPUID bit

    This bit is set when microcode provides the mechanism to invoke a flush of
    various exploitable CPU buffers by invoking the x86 ``VERW`` instruction.
    CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091.

  * Restrict user access to virt-admin, virtlogd and virtlockd

    The intended users for these facilities are the ``root`` user and the
    ``libvirtd`` service respectively, but these restrictions were not enforced
    correctly. CVE-2019-10132.

* **Improvements**

  * test driver: Expand API coverage

    Several APIs that were missing from the test driver have now been
    implemented.

  * Avoid unnecessary static linking

    Most binaries shipped as part of libvirt, for example ``virtlogd`` and
    ``libvirt_iohelper`` , were embedding parts of the library even though they
    also linked against the ``libvirt.so`` dynamic library. This is no longer
    the case, which results in both the disk and memory footprint being
    reduced.

  * qemu: Report stat-htlb-pgalloc and stat-htlb-pgfail balloon stats

    These stats have been introduced in QEMU 3.0.

* **Bug fixes**

  * qemu: Fix emulator scheduler support

    Setting the scheduler for QEMU's main thread before QEMU had a chance to
    start up other threads was misleading as it would affect other threads
    (vCPU and I/O) as well. In some particular situations this could also lead
    to an error when the thread for vCPU #0 was being moved to its cpu,cpuacct
    cgroup. This was fixed so that the scheduler for the main thread is set
    after QEMU starts.

  * apparmor: Allow hotplug of vhost-scsi devices


v5.3.0 (2019-05-04)
===================

* **New features**

  * qemu: Add support for setting the emulator scheduler parameters

    I/O threads and vCPU threads already support setting schedulers, but until
    now it was impossible to do so for the main QEMU thread (emulator thread in
    the libvirt naming). This is, however, requested for some very specific
    scenarios, for example when vCPU threads are running at such priority that
    could starve the main thread.

* **Removed features**

  * vbox: Drop support for VirtualBox 4.x releases

    Support for all the 4.x releases was ended by VirtualBox maintainers in
    December 2015. Therefore, libvirt support for these releases is dropped.

* **Improvements**

  * qemu: Use PCI by default for RISC-V guests

    PCI support for RISC-V guests was already available in libvirt 5.1.0, but
    it required the user to opt-in by manually assigning PCI addresses: with
    this release, RISC-V guests will use PCI automatically when running against
    a recent enough (4.0.0+) QEMU release.

  * qemu: Advertise firmware autoselection in domain capabilities

    The firmware autoselection feature is now exposed in domain capabilities
    and management applications can query for accepted values, i.e. values that
    are accepted and for which libvirt found firmware descriptor files.
    Firmware Secure Boot support is also advertised.

  * Drop YAJL 1 support

    YAJL 2 is widely adopted and maintaining side by side support for two
    versions is unnecessary.

* **Bug fixes**

  * rpc: cleanup in virNetTLSContextNew

    Failed new gnutls context allocations in virNetTLSContextNew function
    results in double free and segfault. Occasional memory leaks may also
    occur.

  * virsh: various completers fixes

    There were some possible crashers, memory leaks, etc. which are now fixed.

  * qemu: Make hugepages work with memfd backend

    Due to a bug in command line generation libvirt did not honor hugepages
    setting with memfd backend.

  * Enforce ACL write permission for getting guest time & hostname

    Getting the guest time and hostname both require use of guest agent
    commands. These must not be allowed for read-only users, so the permissions
    check must validate "write" permission not "read".


v5.2.0 (2019-04-03)
===================

* **New features**

  * Add Storage Pool Capabilities output

    Add support to list an enumerated list of supported Storage Pools via the
    virConnectGetCapabilities API when connected via a Storage Driver. Add
    support to get a more detailed list XML output Storage Pool Capabilities
    vis the virConnectGetStoragePoolCapabilites API.

  * qemu: Support virtio-{non-}transitional device models

    ``virtio-transitional`` and ``virtio-non-transitional`` ``model`` values
    were added to the QEMU driver for the following devices: ``disk`` ,
    ``interface`` , ``filesystem`` , ``rng`` , ``vsock`` , ``memballoon`` ,
    ``controller`` type ``scsi`` , ``controller`` type ``virtio-serial`` ,
    ``input`` bus ``virtio`` type ``passthrough`` , ``hostdev`` type
    ``scsi_host`` . These new models can be used to give fine grained control
    over what virtio device version is presented to the guest.

  * qemu: Enable firmware autoselection

    Libvirt allows users to provide loader path for some time now. However,
    this puts some burden on users because they need to know what firmware
    meets their requirements. Now that QEMU ships firmware description files
    this burden can be moved onto libvirt. It is as easy as setting the
    ``firmware`` attribute in the ``os`` element (accepted values are ``bios``
    and ``efi`` ). Moreover, libvirt automatically enables domain features
    needed for firmware it chooses.

  * snapshots: Add support for topological listings

    A new flag VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL is available for the
    various snapshot listing APIs such as virDomainListAllSnapshots(). For
    drivers that support the flag, the listed snapshots are guaranteed to be
    sorted such that parents occur before children.

  * Xen: Add support for max grant frames setting

    Add support for Xen's max_grant_frames setting by adding a new xenbus
    controller type with a maxGrantFrames attribute. E.g. ``<controller
    type='xenbus' maxGrantFrames='64'/>``

  * qemu: Add support for parallel migration

    With QEMU 4.0.0 libvirt can enable parallel migration which causes the
    memory pages to be processed in parallel by several threads and sent to the
    destination host using several connections at the same time. This may
    increase migration speed in case a single thread is unable to saturate the
    network link.

* **Removed features**

  * Drop support for Upstart and "Red Hat" init scripts

    Not a single one of the platforms we target still uses Upstart, and the
    Upstart project itself has been abandoned for several years now; the same
    is true for the "Red Hat" (really System V) init scripts, since RHEL 7 and
    later releases use systemd.

* **Improvements**

  * Report class information for PCI node device capability.

  * Split setup of IPv4 and IPv6 top level chain

    The requirement resulting from private chains improvement done in
    ``v5.1.0`` was refined so that only tables from corresponding IP version
    are required. This means that if a network doesn't have ``IPv6`` enabled
    then those tables are not required.

  * Don't default to building the QEMU driver

    Historically, the QEMU driver has been special in that it was enabled by
    default, with the option to explicitly opt-out of it; starting now, we're
    enabling it opportunistically if we detect that all requirements are
    available, just like we do with other drivers.

* **Bug fixes**

  * virt-host-validate: Fix IOMMU check on s390x

  * qemu: Allow creating pSeries guests with graphics and no USB mouse

    It's now possible to prevent libvirt from automatically adding a USB mouse
    to pSeries guests by including a USB tablet in the input XML: doing so is
    desiderable as using a tablet results in a much better user experience when
    working with GUIs.

  * qemu: Set $HOME and XGD variables for qemu:///system guests

    This avoids files being accidentally created under ``/`` or the guests not
    being able to start because they lack the necessary permissions to write to
    that location.


v5.1.0 (2019-03-04)
===================

* **New features**

  * bhyve: Add support for additional command-line arguments

    The bhyve driver now supports passing additional command-line arguments to
    the bhyve process using the new ``<bhyve:commandline>`` element in domain
    configuration.

  * network: Support setting a firewalld "zone" for virtual network bridges

    All libvirt virtual networks with bridges managed by libvirt (i.e. those
    with forward mode of "nat", "route", "open", or no forward mode) will now
    be placed in a special firewalld zone called "libvirt" by default. The zone
    of any network bridge can be changed using the ``zone`` attribute of the
    network's ``bridge`` element.

  * bhyve: Support for ignoring unknown MSRs reads and writes

    A new <features> element <msrs unknown='ignore'/> was introduced and the
    bhyve driver supports it to control unknown Model Specific Registers (MSRs)
    reads and writes.

  * qemu: Add support for encrypted VNC TLS keys

    Use the password stored in the secret driver under the uuid specified by
    the ``vnc_tls_x509_secret_uuid`` option in qemu.conf.

  * Add storage pool namespace options

    Allow for adjustment of RBD configuration options via Storage Pool XML
    Namespace adjustments.

  * qemu: Add support for setting post-copy migration bandwidth

    Users can now limit the bandwidth of post-copy migration, e.g. via ``virsh
    migrate --postcopy-bandwidth`` .

* **Improvements**

  * Create private chains for virtual network firewall rules

    Historically firewall rules for virtual networks were added straight into
    the base chains. This works but has a number of bugs and design
    limitations. To address them, libvirt now puts firewall rules into its own
    chains. Note that with this change the ``filter`` , ``nat`` and ``mangle``
    tables are required for both ``IPv4`` and ``IPv6`` .

  * Detect CEPH and GPFS as shared FS

    When starting a migration libvirt performs some sanity checks to make sure
    domain will be able to run on the destination. One of the requirements is
    that the disk has to either be migrated too or be accessible from a network
    filesystem. CEPH and GPFS weren't detected as a network filesystem.

  * Advertise network MTU via DHCP when specified

    If network MTU is set and the network has DHCP enabled, advertise the MTU
    in DHCP transaction too so that clients can adjust their link accordingly.

  * qemu: Allocate memory at the configured NUMA nodes from start

    Libvirt used to just start QEMU, let it allocate memory for the guest, and
    then use CGroups to move the memory to configured NUMA nodes. This is
    suboptimal as huge chunks of memory have to be moved. Moreover, this relies
    on ability to move memory later which is not always true. A change was made
    to set process affinity correctly from the start so that memory is
    allocated on the configured nodes from the beginning.

  * Support for newer Wireshark

    Adapt libvirt to use the more recent release requiring a source build
    configuration of libvirt ``--with-wireshark`` to upgrade to the more recent
    version.

  * Batch mode virsh and virt-admin parsing improvements

    When parsing a single-argument command_string in batch mode, virsh and
    virt-admin now permit newlines in addition to semicolons for splitting
    commands, and backslash-newline for splitting long lines, to be more like
    shell parsing.

* **Bug fixes**

  * qemu: Use CAP_DAC_OVERRIDE during QEMU capabilities probing

    By default, libvirt runs the QEMU process as ``qemu:qemu`` which could
    cause issues during probing as some features like AMD SEV might be
    inaccessible to QEMU because of file system permissions. Therefore,
    ``CAP_DAC_OVERRIDE`` is granted to overcome these for the purposes of
    probing.

  * storage: Add default mount options for fs/netfs storage pools

    Altered the command line generation for fs/netfs storage pools to add some
    default options. For Linux based systems, the options added are "nodev,
    nosuid, noexec". For FreeBSD based systems, the options added are "nosuid,
    noexec".

  * qemu: Allow use of PCI for RISC-V guests

    This works with QEMU 4.0.0+ only and is opt-in at the moment, since it
    requires users to manually assign PCI addresses, but is otherwise fully
    functional.

  * network: Fix virtual networks on systems using firewalld+nftables

    Because of the transitional state of firewalld's new support for nftables,
    not all iptables features required by libvirt are yet available, so libvirt
    must continue to use iptables for its own packet filtering rules even when
    the firewalld backend is set to use nftables. However, due to the way
    iptables support is implemented in kernels using nftables (iptables rules
    are converted to nftables rules and processed in a separate hook from the
    native nftables rules), guest networking was broken on hosts with firewalld
    configured to use nftables as the backend. This has been fixed by putting
    libvirt-managed bridges in their own firewalld zone, so that guest traffic
    can be forwarded beyond the host and host services can be exposed to guests
    on the virtual network without opening up those same services to the rest
    of the physical network. This means that host access from virtual machines
    is no longer controlled by the firewalld default zone (usually "public"),
    but rather by the new firewalld zone called "libvirt" (unless configured
    otherwise using the new zone attribute of the network bridge element).

  * qemu: Fix i6300esb watchdog hotplug on Q35

    Ensure that libvirt allocates a PCI address for the device so that QEMU did
    not default to an address that would not allow for device hotplug.

  * lxc: Don't reboot host on virDomainReboot

    If the container is really a simple one (init is just bash and the whole
    root is passed through) then virDomainReboot and virDomainShutdown would
    reboot or shutdown the host. The solution is to use different method to
    reboot or shutdown the container in that case (e.g. signal).

  * rpc: Various stream fixes

    One particular race was fixed, one locking problem and error reporting from
    streams was made better.

  * qemu: Fix guestfwd hotplug/hotunplug

    Fixed the generation of the guestfwd hotplug/unplug command sent to QEMU to
    match the syntax used when creating the initial command line.

  * qemu: Forbid CDROMs on virtio bus

    Attempting to create an empty virtio-blk drive or attempting to eject it
    results into an error. Forbid configurations where users would attempt to
    use CDROMs in virtio bus.

  * qemu: Use 'raw' for 'volume' disks without format

    Storage pools might want to specify format of the image when translating
    the volume thus libvirt can't add any default format when parsing the XML.
    Add an explicit format when starting the VM and format is not present
    neither by user specifying it nor by the storage pool translation function.

  * qemu: Assume 'raw' default storage format also for network storage

    Post parse callback adds the 'raw' type only for local files. Remote files
    can also have backing store (even local) so we should do this also for
    network backed storage.

  * qemu: Fix block job progress reporting and advocate for READY event

    In some cases QEMU can get to 100% and still not reach the synchronised
    phase. Initiating a pivot in that case will fail. Therefore it is strongly
    advised to wait for ``VIR_DOMAIN_BLOCK_JOB_READY`` event which does not
    suffer from this problem.

  * qemu: Don't format image properties for empty drive

    If a ``-drive`` has no image, then formatting attributes such as cache,
    readonly, etc. would cause errors to be reported from QEMU. This was fixed
    by not supplying the attributes for devices without an image.

  * External snapshot metadata redefinition is fixed

    Attempting to use VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE to reinstate the
    metadata describing an external snapshot created earlier for an offline
    domain no longer fails.


v5.0.0 (2019-01-15)
===================

* **New features**

  * Xen: Add support for openvswitch

    The libxl driver now supports virtual interfaces that connect to an
    openvswitch bridge, including interfaces with VLAN tagging and trunking
    configuration.

  * qemu: Report whether KVM nesting is available

    Running nested KVM guests requires specific configuration steps to be
    performed on the host; libvirt will now report in the host capabilities
    whether KVM nesting support is available.

* **Removed features**

  * Drop UML driver

    The UML driver was unmaintained and not tested for quite some time now.
    Worse, there is a bug that causes it to deadlock on some very basic
    operations (e.g. dumping domain XML). These facts make us believe no one
    uses it.

* **Improvements**

  * qemu: Add support for ARMv6l guests

  * Support more NVDIMM configuration options

    Introduce more configuration options. For the source element, add the
    'alignsize' and 'pmem' subelements. For the target element, add the
    'readonly' subelement.

  * cpu: Add support for "stibp" x86_64 feature

    Add cpu flag stibp (Single Thread Indirect Branch Predictors) to prevent
    indirect branch predictions from being controlled by the sibling
    Hyperthread.

  * libxl: Handle external domain destroy

    Historically, if a domain was destroyed using ``xl`` rather than through
    libvirt APIs, libvirt would not be aware of the fact and keep considering
    it as running. This is no longer the case.

  * Start selecting the first available DRI device for OpenGL operations

    If OpenGL support is needed (either with SPICE gl enabled or with
    egl-headless), libvirt is now able to pick the first available DRI device
    for the job. At the same time, this improvement is also a bugfix as it
    prevents permission-related issues with regards to our mount namespaces and
    the default DRI render node's permissions which would normally prevent QEMU
    from accessing such a device.

  * qemu: Add support for postcopy-requests migration statistics

    The ``virDomainJobInfo`` can get number page requests received from the
    destination host during post-copy migration.

* **Bug fixes**

  * lxc: Don't forbid interfaces with type=direct

    Such interfaces are supported by lxc and should be allowed.

  * qemu: Fully clean up RNG devices on detach

    Some RNG device types, such as those using EGD, might need extra clean up
    on the host in addition to removing the guest-side device.


v4.10.0 (2018-12-03)
====================

* **New features**

  * qemu: Add Hyper-V PV IPI and Enlightened VMCS support

    The QEMU driver now has support for Hyper-V PV IPI and Enlightened VMCS for
    Windows and Hyper-V guests.

  * qemu: Added support for PCI devices on S390

    PCI addresses can now include the new zpci element which contains uid
    (user-defined identifier) and fid (PCI function identifier) attributes and
    makes the corresponding devices usable by S390 guests.

  * Support changing IOThread polling parameters for a live guest

    Introduced virDomainSetIOThreadParams which allows dynamically setting the
    IOThread polling parameters used by QEMU to manage the thread polling
    interval and the algorithm for growth or shrink of the polling time. The
    values only affect a running guest with IOThreads. The guest's IOThread
    polling values can be viewed via the domain statistics.

  * Xen: Add support for PVH

    The libxl driver now supports Xen's PVH virtual machine type. PVH machines
    are enabled with the new "xenpvh" OS type, e.g.
    ``<os><type>xenpvh</type></os>``

  * qemu: Added support for CMT (Cache Monitoring Technology)

    Introduced cache monitoring using the ``monitor`` element in ``cachetune``
    for vCPU threads. Added interfaces to get and display the cache utilization
    statistics through the command 'virsh domstats' via the
    virConnectGetAllDomainStats API.

  * qemu: Add support for nested HV for pSeries guests

    Nested HV support makes it possible to run nested (L2) guests with minimal
    performance penalty when compared to regular (L1) guests on ppc64 hardware.

* **Bug fixes**

  * Xen: Handle soft reset shutdown event

    The pvops Linux kernel uses soft reset to handle the crash machine
    operation. The libxl driver now supports the soft reset shutdown event,
    allowing proper crash handling of pvops-based HVM domains.


v4.9.0 (2018-11-04)
===================

* **New features**

  * util: Add cgroup v2 support

    cgroup v2 support has been implemented in libvirt, with both "unified" (v2
    only) and "hybrid" (v2 + v1) setups being usable; existing "legacy" (v1
    only) setups will keep working.

  * qemu: Add vfio AP support

    The QEMU driver now has support to passthrough adjunct processors into QEMU
    guests on S390.

* **Improvements**

  * rpc: Make 'genprotocol' output reproducible

    This is another step towards making libvirt builds fully reproducible.

* **Bug fixes**

  * security: Fix permissions for UNIX sockets

    Since 4.5.0, libvirt is using FD passing to hand sockets over to QEMU,
    which in theory removes the need for them to be accessible by the user
    under which the QEMU process is running; however, other processes such as
    vdsm need to access the sockets as well, which means adjusting permissions
    is still necessary.

  * cpu_map: Add Icelake model definitions

    These CPU models will be available in the upcoming 3.1.0 QEMU release.

  * util: Properly parse URIs with missing trailing slash

    Some storage URIs were not parsed correctly, in which case libvirt ended up
    emitting XML that it would then refuse to parse back.


v4.8.0 (2018-10-01)
===================

* **New features**

  * Xen: Support PM Suspend and Wakeup

    The libxl driver now supports the virDomainPMSuspendForDuration and
    virDomainPMWakeup APIs.

* **Removed features**

  * Xen: Drop support for Xen 4.4 and 4.5

    Xen 4.4 and 4.5 are no longer supported by the Xen community. Drop support
    for these older versions and require Xen >= 4.6.

  * nwfilter: Disallow binding creation in session mode

    Ensure that a filter binding creation is not attempted in session mode and
    generates a proper error message.

* **Improvements**

  * qemu: Retrieve guest hostname through QEMU Guest Agent command

    QEMU is now able to retrieve the guest hostname using a new QEMU-GA command
    called 'guest-get-host-name'. Virsh users can execute 'domhostname' for
    QEMU driver for domains configured to use the Guest Agent.

  * virsh: Implement vsh-table in virsh and virsh-admin

    The new API fixes problems with table-alignment, making the tables more
    readable and deals with unicode.

* **Bug fixes**

  * storage: Allow inputvol to be encrypted

    When creating a storage volume based on another volume, the base input
    volume is allowed to be encrypted.

  * virsh: Require explicit --domain for domxml-to-native

    The --domain option for domxml-to-native virsh command has always been
    documented as required, but commit v4.3.0-127-gd86531daf2 accidentally made
    it optional.

  * lxc_monitor: Avoid AB / BA lock race

    A deadlock situation could occur when autostarting a LXC domain 'guest' due
    to two threads attempting to take opposing locks while holding opposing
    locks (AB BA problem).


v4.7.0 (2018-09-03)
===================

* **New features**

  * storage: add storage pool iscsi-direct

    Introduce a new storage pool backend that uses libiscsi instead of
    iscsiadm. It support basic pool operations: checkPool and refreshPool.

  * Add support for MBA (Memory Bandwidth Allocation technology)

    Domain vCPU threads can now have allocated some parts of host memory
    bandwidth by using the ``memorytune`` element in ``cputune`` .

  * qemu: Add support for RISC-V guests

    riscv32 and riscv64 guest architectures are now supported.

* **Improvements**

  * qemu: Add ccw support for vhost-vsock

    Support the vhost-vsock-ccw device on S390.

  * qemu: Make default machine type independent of QEMU

    We can't control whether or not QEMU will change its default machine type
    in the future, or whether downstream distributions will decide to compile
    out some machine types, so our only option to provide a predictable
    behavior is taking care of the default ourselves; management applications
    and users are encouraged to explicitly pick a machine type when creating
    new guests.

  * apparmor: Various improvements

    Rules have been added to deal with a number of scenarios that didn't work
    correctly.

* **Bug fixes**

  * esx: Truncate CPU model name

    Some CPU model names are too long to be stored into the corresponding
    property, and should be explicitly truncated to avoid unexpected behavior
    in users of the ``virNodeGetInfo()`` API such as ``virsh nodeinfo`` .

  * utils: Remove arbitrary limit on socket_id/core_id

    Both values were assumed to be smaller than 4096, but in fact they are
    entirely hardware-dependent and there have been reports of machines
    presenting much bigger values, preventing libvirt from working correctly;
    all such limits have now been removed.


v4.6.0 (2018-08-06)
===================

* **New features**

  * qemu: Implement the HTM pSeries feature

    Users can now decide whether HTM (Hardware Transactional Memory) support
    should be available to the guest.

  * qemu: Enable VNC console for mediated devices

    Host devices now support a new atribute 'display' which can be used to turn
    on frame buffer rendering on a vgpu mediated device instead of on an
    emulated GPU, like QXL.

* **Improvements**

  * qemu: Introduce a new video model of type 'none'

    Introduce a new video model type that disables the automatic addition of a
    video device to domains with 'graphics' specified in their XML. This can be
    useful with GPU mediated devices which can serve as the only rendering
    devices within the guest.

  * virsh: Add --alias to attach-disk and attach-interface commands

    Add option --alias to set customized device alias name when using
    attach-disk or attach-interface commands.

  * virsh: Support usb and sata address to attach-disk

    Usb or sata address could be used when attach-disk with --address. For
    example, use usb address as usb:<bus>.<port>, use sata address as
    <controller>.<bus>.<unit>.


v4.5.0 (2018-07-02)
===================

* **New features**

  * qemu: Provide TPM emulator support

    Support QEMU's TPM emulator based on swtpm. Each QEMU guest gets its own
    virtual TPM.

  * bhyve: Support specifying guest CPU topology

    Bhyve's guest CPU topology could be specified using the ``<cpu><topology
    ../></cpu>`` element.

  * qemu: Add support for extended TSEG size

    Support specifying extended TSEG size for SMM in QEMU.

  * qemu: Add support for SEV guests

    SEV (Secure Encrypted Virtualization) is a feature available on AMD CPUs
    that encrypts the guest memory and makes it inaccessible even to the host
    OS.

* **Removed features**

  * Remove support for qcow/default encrypted volumes

    Disallow using a qcow encrypted volume for the guest and disallow creation
    of the qcow or default encrypted volume from the storage driver. Support
    for qcow encrypted volumes has been phasing out since QEMU 2.3 and by QEMU
    2.9 creation of a qcow encrypted volume via qemu-img required usage of
    secret objects, but that support was never added to libvirt.

  * Make GnuTLS mandatory

    Building without GnuTLS is no longer possible.

  * qemu: Remove allow_disk_format_probing configuration option

    The option represented a security risk when used with malicious disk
    images, so users were recommended against enabling it; with this release,
    it's been removed altogether.

* **Improvements**

  * capabilities: Provide info about host IOMMU support

    Capabilities XML now provide information about host IOMMU support.

  * virsh: Add --all to domblkinfo command

    Alter the ``domblkinfo`` command to add the option --all in order to
    display the size details of each domain block device from one command in a
    output table.

  * qemu: Allow concurrent access to monitor and guest agent

    Historically libvirt prevented concurrent accesses to the qemu monitor and
    the guest agent. Therefore two independent calls (one querying the monitor
    and the other querying guest agent) would serialize which hurts
    performance. The code was reworked to allow two independent calls run at
    the same time.

  * qemu: Allow configuring the page size for HPT pSeries guests

    For HPT pSeries guests, the size of the host pages used to back guest
    memory and the usable guest page sizes are connected; the new setting can
    be used to request that a certain page size is available in the guest.

  * Add support to use an raw input volume for encryption

    It is now possible to provide a raw input volume as input for to generate a
    luks encrypted volume via either virsh vol-create-from or
    virStorageVolCreateXMLFrom.

  * qemu: Add support for vsock hot (un)plug and cold (un)plug

  * qemu: Add support for NBD over TLS

    NBD volumes can now be accessed securely.

  * qemu: Implement FD passing for Unix sockets

    Instead of having QEMU open the socket and then connecting to it, which is
    inherently racy, starting with QEMU 2.12 we can open the socket ourselves
    and pass it to QEMU, avoiding race conditions.

  * virsh: Introduce --nowait option for domstat command

    When this option is specified, virsh will try to fetch the guest stats but
    abort instead of stalling if they can't be retrieved right away.

* **Bug fixes**

  * qemu: Fix a potential libvirtd crash on VM reconnect

    Initialization of the driver worker pool needs to come before libvirtd
    trying to reconnect to all machines, since one of the QEMU processes migh
    have already emitted events which need to be handled prior to us getting to
    the worker pool initialization.

  * qemu: Fix domain resume after failed migration

    Recent versions of QEMU activate block devices before the guest CPU has
    been started, which makes it impossible to roll back a failed migration.
    Use the ``late-block-activate`` migration capability if supported to avoid
    the issue.

  * vmx: Permit guests to have an odd number of vCPUs

    An odd number of vCPUs greater than 1 was forbidden in the past, but
    current versions of ESXi have lifted that restriction.


v4.4.0 (2018-06-04)
===================

* **New features**

  * bhyve: Support locking guest memory

    Bhyve's guest memory may be wired using the
    ``<memoryBacking><locked/></memoryBacking>`` element.

  * qemu: Provide VFIO channel I/O passthrough support

    Support passthrough devices that use channel I/O based mechanism in a QEMU
    virtual machine.

  * qemu: Add support for migration of VMs with non-shared storage over TLS

    It's now possible to use the VIR_MIGRATE_TLS flag together with
    VIR_MIGRATE_NON_SHARED_DISK. The connection is then secured using the TLS
    environment which is setup for the migration connection.

  * Add support for VM Generation ID

    The VM Generatation ID exposes a 128-bit, cryptographically random, integer
    value identifier, referred to as a Globally Unique Identifier (GUID) to the
    guest in order to notify the guest operating system when the virtual
    machine is executed with a different configuration. Add a new domain XML
    processing and a domain capabilities feature.

  * Introduce virDomainDetachDeviceAlias

    This new API enables users to detach device using only its alias.

  * Introduce new virConnectCompareHypervisorCPU and
    virConnectBaselineHypervisorCPU APIs

    Unlike the old virConnectCompareCPU and virConnectBaselineCPU APIs, both
    new APIs consider capabilities of a specific hypervisor.

  * Introduce SCSI persistent reservations support

    The QEMU driver gained support for qemu-pr-helper which enables guests to
    issue SCSI commands for persistent reservation.

  * qemu: Implement multiple screen support for virDomainScreenshot

    While the virDomainScreenshot API supported multihead video cards, the
    implementation was missing. But now that QEMU implemented it libvirt has
    done as well.

  * qemu: add support for vhost-vsock-device

    A new vsock device was introduced, allowing communication between the guest
    and the host via the AF_VSOCK family.

* **Improvements**

  * qemu: Add suport for OpenGL rendering with SDL

    Domains using SDL as a graphics backend will now be able to use OpenGL
    accelerated rendering.

  * qemu: Add support for 'output' audio codec

    Support QEMU's 'hda-output' codec advertising only a line-out for ich6 and
    ich9 sound devices.

  * virsh: Enhance event name completion

    Implement event name completion for some commands (e.g. event,
    secret-event, pool-event and nodedev-event)


v4.3.0 (2018-05-02)
===================

* **New features**

  * qemu: Add support for the pcie-to-pci-bridge controller

    Pure PCIe guests such as x86_64/q35 and aarch64/virt will now add this
    controller when traditional PCI devices are in use.

  * Xen: Support setting CPU features for host-passthrough model

    The CPU model presented to Xen HVM domains is equivalent to libvirt's
    host-passthrough model, although individual features can be enabled and
    disabled via the cpuid setting. The libvirt libxl driver now supports
    enabling and disabling individual features of the host-passthrough CPU
    model.

* **Removed features**

  * Xen: Drop the legacy xend-based driver

    The xm/xend toolstack was deprecated in Xen 4.2 and removed from the Xen
    sources in the 4.5 development cycle. The libvirt driver based on xend is
    now removed from the libvirt sources.

* **Improvements**

  * qemu: Support hot plug and hot unplug of mediated devices

    Libvirt now allows mediated devices to be hot plugged and hot unplugged
    from a guest rather than reporting an error that this isn't supported. In
    fact, kernel has been supporting this since 4.10.

* **Bug fixes**

  * Improve handling of device mapper targets

    When starting a domain with a disk backed by a device mapper volume libvirt
    also needs to allow the storage backing the device mapper in CGroups. In
    the past kernel did not care, but starting from 4.16 CGroups are consulted
    on each access to the device mapper target.


v4.2.0 (2018-04-01)
===================

* **New features**

  * Support building with Python 3

    Python is required to build libvirt, and up until now only Python 2 could
    be used as an interpreter. All scripts used during build have now been made
    compatible with Python 3, which means both major releases of the language
    are fully supported.

  * qemu: Provide ccw address support for graphics and input devices

    Support the virtio-gpu-ccw device as a video device and virtio-{keyboard,
    mouse, tablet}-ccw devices as input devices on S390.

* **Improvements**

  * qemu: Add logging of guest crash information on S390

    On S390, when the guest crashes and QEMU exposes the guest crash
    information, log the relevant data to the domain log file.

  * qemu: use arp table of host to get the IP address of guests

    Find IP address of a VM by arp table on hosts. If someone customizing IP
    address inside VM, it will be helpful.

  * Xen: Remove hard-coded scheduler weight

    The libxl driver was accidentally hard-coding the per-domain scheduler
    weight to 1000, silently ignoring any user-provided ``<shares>`` in
    ``<cputune>`` . The driver now honors ``<shares>`` , and defers setting a
    default value to Xen. Note that the Xen default is 256, so any domains
    started after this improvement will have one fourth the shares of
    previously started domains. If all domains must have equal CPU shares,
    administrators must manually set the weight of previously started domains
    to 256, or restart them.

* **Bug fixes**

  * qemu: TLS migration now enforces use of TLS for the NBD connection

    When the VIR_MIGRATE_TLS flag was used with the migration API libvirt did
    not ensure that the NBD connection was using TLS as well. The code now
    rejects such migration as the TLS transport for NBD is not ready yet, but
    prevents a false sense of security that TLS would be used. The support TLS
    for NBD will be added soon.


v4.1.0 (2018-03-05)
===================

* **New features**

  * Added support for CAT (Cache allocation Technology)

    Domain vCPU threads can now have allocated some parts of host cache using
    the ``cachetune`` element in ``cputune`` .

  * Allow opening secondary drivers

    Up until now it was possible to connect to only hypervisor drivers (e.g.
    qemu:///system, lxc:///, vbox:///system, and so on). The internal drivers
    (like network driver, node device driver, etc.) were hidden from users and
    users could use them only indirectly. Starting with this release new
    connection URIs are accepted. For instance network:///system,
    storage:///system and so on.

  * virtlogd, virtlockd: Add support for admin protocol

    These two daemons now support admin protocol through which some admin info
    can be gathered or some configuration tweaked on the fly.

* **Improvements**

  * virsh: Enhance bash completion

    Implement more bash completions so that basic libvirt objects can be
    auto-completed (e.g. networks, interfaces, NWFilters, and so on).

  * qemu: Use VIR_ERR_DEVICE_MISSING for various hotplug/detach messages

  * qemu: Allow showing the dump progress for memory only dump

    Alter the QEMU dump-guest-memory command processing to check for and allow
    asynchronous completion which then allows for the virsh dump --memory-only
    --verbose command to display percent completion data.

  * conf: add support for setting Chassis SMBIOS data fields

  * libxl: add support for setting clock offset and adjustment

  * Make port allocator global

    Up until now each driver had their own port allocator module. This meant
    that info on port usage was not shared. Starting with this release, the
    port allocator module is made global and therefore drivers allocate ports
    from global pool.

  * Fixed some compiler warnings that appear with GCC 8

* **Bug fixes**

  * qemu: Check for unsafe migration more thoroughly

    If a domain disk is stored on local filesystem (e.g. ext4) but is not being
    migrated it is very likely that domain is not able to run on destination.
    Regardless of share/cache mode.

  * qemu: Fix updating device with boot order

    Starting with 3.7.0 release updating any device with boot order would fail
    with 'boot order X is already used by another device' while in fact it was
    the very same device.

  * virlog: determine the hostname on startup CVE-2018-6764

    At later point it might not be possible or even safe to use getaddrinfo().
    It can in turn result in a load of NSS module which can even be loaded from
    unsage guest filesystem and thus escape the confinment of its container.

  * qemu: Rework vCPU statistics fetching

    Fetching vCPU statistics was very expensive because it lead to waking up
    vCPU threads in QEMU and thus it degraded performance. The code was
    reworked so that fetching statistics does not wake up halted vCPUs.

  * qemu: unlink memory backing file on domain shutdown

    Depending on the filesystem where domain memory is stored, some files might
    have been left behind. This is not a problem on hugetlbfs, but it is a
    problem on regular filesystems like ext4.

  * qemu: Fix shutting down domains in parallel

    If multiple domains were being shut down in parallel, libvirtd might have
    deadlocked.

  * nodedev: Update PCI mdev capabilities dynamically

    PCI devices may have other nested capabilities, like SRIOV and mdev which
    depend on the device being plugged into the native vendor driver. However,
    in case such a device is directly assigned to a guest using VFIO driver,
    the device will naturally lose these capabilities and libvirt needs to
    reflect that.


v4.0.0 (2018-01-19)
===================

* **New features**

  * tools: Provide bash completion support

    Both ``virsh`` and ``virt-admin`` now implement basic bash completion
    support.

  * qemu: Refresh capabilities on host microcode update

    A microcode update can cause the CPUID bits to change; therefore, the
    capabilities cache should be rebuilt when such an update is detected on the
    host.

  * lxc: Set hostname based on container name

* **Improvements**

  * CPU frequency reporting improvements

    The CPU frequency will now be reported by ``virsh nodeinfo`` and other
    tools for s390 hosts; at the same time; CPU frequency has been disabled on
    aarch64 hosts because there's no way to detect it reliably.

  * libxl: Mark domain0 as persistent

  * Xen: Add support for multiple IP addresses on interface devices

  * qemu: Add support for hot unplugging redirdev device

* **Bug fixes**

  * qemu: Enforce vCPU hotplug granularity constraints

    QEMU 2.7 and newer don't allow guests to start unless the initial vCPUs
    count is a multiple of the vCPU hotplug granularity, so validate it and
    report an error if needed.


v3.10.0 (2017-12-04)
====================

* **New features**

  * conf: Support defining distances between virtual NUMA cells

    A NUMA hardware architecture supports the notion of distances between NUMA
    cells. This can now be specified using the ``<distances>`` element within
    the NUMA cell configuration. Drivers which support this include Xen and
    QEMU.

  * Xen: Support defining vNUMA topology

    Xen now supports defining a virtual NUMA topology for VMs, including
    specifying distances between NUMA cells.

  * qemu: Add the ability to configure HPT resizing for pSeries guests

    The user can now decide whether HPT (Hash Page Table) resizing should be
    enabled, disabled or required instead of leaving it up to hypervisor
    defaults and negotiation between the guest and the host.

  * qemu: Add vmcoreinfo feature

    Starting with QEMU 2.11, the guest can save kernel debug details when this
    feature is enabled and the kernel supports it. It is useful to process
    kernel dump with KASLR enabled, and also provides various kernel details to
    crash tools.

  * conf: Move the auth and encryption definitions to disk source

    Allow parsing and formatting of the ``auth`` and ``encryption``
    sub-elements to be a child of the ``source`` element. This will allow
    adding an ``auth`` sub-element to a ``backingStore`` or ``mirror`` elements
    as a means to track specific authentication and/or encryption needs.

* **Improvements**

  * vbox: Add VirtualBox 5.2 support

  * vbox: Add support for configuring storage controllers

    The VirtualBox driver now supports the ``<controller>`` element in the
    domain XML for configuring storage controllers in VBOX VMs. Additionally,
    libvirt's domain XML schema was updated to allow optional ``model``
    attribute for ``<controller type='ide'>`` which is used by the VBOX driver
    to set the IDE controller model to be one of 'piix4', 'piix4' (default), or
    'ich6'. Finally, with this change ``dumpxml`` generates ``<controller>``
    elements that correspond to current VBOX VM storage controller
    configuration.

  * vbox: Add support for attaching empty removable disks

    The VirutalBox driver now supports adding CD-ROM and floppy disk devices
    that do not have the disk source specified. Previously such devices were
    silently ignored.

  * vbox: Add support for attaching SAS storage controllers

    In VirtualBox, SCSI and SAS are distinct controller types whereas libvirt
    does not make such distinction. Therefore, the VBOX driver was updated to
    allow attaching SAS controllers via ``<controller type='scsi'
    model='lsisas1068'>`` element. If there are both SCSI and SAS controllers
    present in the VBOX VM, the domain XML can associate the disk device using
    the ``<address>`` element with the ``controller`` attribute, and
    optionally, set the port via ``unit`` attribute.

  * qemu: Generate predictable paths for qemu memory backends

    In some cases management applications need to know paths passed to
    memory-backend-file objects upfront. Libvirt now generates predictable
    paths so applications can prepare the files if they need to do so.

  * Shareable disks work properly with recent qemu

    Recent qemu versions added image locking to avoid potential corruption of
    disk images. This broke shareable disks with libvirt since the feature was
    turned on by default in qemu. Libvirt now enables sharing of those disks in
    qemu so that the image locking is not applied in that case. Additionally
    libvirt now checks that shareable disks have supported format (raw) to
    avoid metadata corruption.

  * Improve serial console behavior on non-x86 architectures

    ppc64, aarch64 and s390x guests were treating the <serial> and <console>
    elements differently from x86, in some cases presenting misleading
    information to the user. The behavior is now consistent across all
    architectures and the information reported is always accurate.

* **Bug fixes**

  * vbox: Do not ignore failures to attach disk devices when defining

    The ``define`` now fails and reports an error if any of the ``controller``
    or ``disk`` devices specified in the domain XML fail to attach to the
    VirtualBox VM.

  * vbox: Fix dumpxml to always output disk devices

    The VirtualBox driver was ignoring any disk devices in ``dumpxml`` output
    if there was a SAS storage controller attached to the VM.

  * vbox: Fix dumpxml to always generate valid domain XML

    When a VirtualBox VM has multiple disks attached, each to a different
    storage controller that uses 'sd' prefix for block device names e.g. one
    disk attached to SATA and one to SCSI controller, it no longer generates
    XML where both would have 'sda' device name assigned. Instead it properly
    assigns 'sda' and 'sdb' to those disks in the order of appearance.

  * Securely pass iSCSI authentication data

    Rather than supplying the authentication data as part of the iSCSI URL for
    a disk or host device, utilize the encrypted secret object to securely pass
    the authentication data.


v3.9.0 (2017-11-02)
===================

* **New features**

  * Add capability to allow hot (un)plug of a domain watchdog device

  * Allow users to set device aliases

    Users can set aliases to domain devices and thus identify them easily.

  * qemu: Support multiqueue for virtio-blk

    Multiqueue support for ``virtio-blk`` has been available in QEMU ever since
    2.7.0, and now libvirt guests can enable it.

  * Add virDomainSetLifecycleAction API

    Provided a new API to allow dynamic guest lifecycle control for guest
    reactions to poweroff, restart, or crash type events related to the domain
    XML ``on_poweroff`` , ``on_reboot`` , and ``on_crash`` elements. The
    ``virsh set-lifecycle-action`` command was created to control the actions.

  * qemu: Allow cold(un)plugging and hot(un)plugging input devices

  * net: Implement QoS for vhostuser

* **Improvements**

  * Allow a logical volume to be create using LUKS

    A logical volume may be created using an ``encryption`` element using
    "luks" format. This does require a previously created ``secret`` to store
    the passphrase used to encrypt the volume Adding the volume to a domain can
    then either provide the secret or allow the consumer in the guest to
    provide the passphrase in order to decrypt the volume.

  * net: Ignore auto-generated MAC address when detaching an interface

    If the MAC address has not been specified by the user, libvirt will try and
    fill in the gaps by generating one; however, for some error paths that led
    to some confusing error messages, so when an auto-generated MAC address is
    specified the error message will not include the auto-generated MAC.

  * net: Enable MAC address lookup for virDomainInterfaceStats

  * apparmor: Several improvements

    Changes include permitting access to data about USB devices and ``dnsmasq``
    instances, allowing spaces in guest names and many more.

  * cpu: Use CPU information obtained from QEMU when possible

    Recent QEMU versions can expose information about which CPU models are
    available and usable on the host; libvirt will now make use of such
    information whenever possible.

  * hyperv: Various improvements

    The error reported when clients can't connect to Hyper-V has been made more
    descriptive, and memory limits for guests are now mapped to more
    appropriate libvirt equivalents.

  * qemu: Report QEMU error on failed migration

    Instead of reporting a generic error, ask QEMU for a more detailed and thus
    hopefully more helpful one.

  * vbox: Implement autoport for RDP

    libvirt will now obtain the (dynamically allocated) RDP port number from
    VirtualBox itself, avoiding conflicts between multiple guests wanting to
    use RDP at the same time.

  * qemu: Allow rotation of small logs

    On a host where numerous unique instances are executed per day, it's quite
    possible that, even though each of the single log files are fairly small,
    collectively the quantity and volume may add tens of thousands of log files
    to the ``/var/log/libvirt/qemu/`` directory. Removing the constraints that
    log have to be bigger than 100 KiB before they can be rotated solves the
    issue.

* **Bug fixes**

  * Fix swapped interface statistics and QoS

    Due to internal implementation, reported statistics for some types of
    interfaces were swapped (RX appeared in TX and vice versa). Similarly, QoS
    was set in reversed way.

  * Properly resize local LUKS encrypted volume

    Resizing of a local LUKS encrypted volume will now use qemu-img to resize
    the volume. This will require configuring a secret for the LUKS encrypted
    volume.

  * qemu: Reserve PCI addresses for implicit i440fx devices

    Failing to do so causes the addresses to be considered usable by libvirt,
    which means they could be assigned to more than one device resulting in the
    guest failing to start.

  * spec: Restart libvirtd only at the end of the upgrade process

    Use ``%posttrans`` to make sure ``libvirtd`` is not restarted before all
    other components, such as the library itself and storage / hypervisor
    drivers, have already been upgraded.

* **Security**

  * qemu: Ensure TLS clients always verify the server certificate

    While it's reasonable to turn off client certificate validation, as setting
    it up can be non-trivial, clients should always verify the server
    certificate to avoid MITM attacks. However, libvirt was using the same knob
    to control both checks, leading to CVE-2017-1000256 / LSN-2017-0002.


v3.8.0 (2017-10-04)
===================

* **New features**

  * qemu: Added support for cold-(un)plug of watchdog devices

  * qemu: Added support for setting IP address os usernet interfaces

  * qemu: Added support for Veritas Hyperscale (VxHS) block devices

  * storage: Added new events for pool-build and pool-delete

* **Improvements**

  * qemu: Set DAC permissions properly for spice rendernode

    When a ``rendernode`` path is set for SPICE GL on ``qemu:///system`` , we
    now correctly set DAC permissions on the device at VM startup. This is the
    last remaining hurdle to let SPICE GL work for ``qemu:///system`` without
    any external host changes.

  * nodedev: Add switchdev offload query to NIC capabilities

    Allow querying the NIC interface capabilities for the availability of
    switchdev offloading (also known as kernel-forward-plane-offload).

  * New CPU models for AMD and Intel

    AMD EPYC and Intel Skylake-Server CPU models were added together with their
    features

  * Improve long waiting when saving a domain

    While waiting for a write to disk to be finished, e.g. during save, even
    simple operations like ``virsh list`` would be blocking due to domain lock.
    This is now resolved by unlocking the domain in places where it is not
    needed.

* **Bug fixes**

  * Proper units are now used in virsh manpage for dom(mem)stats

    Previously the documentation used multiples of 1000, but now it is fixed to
    use multiples of 1024.

  * qemu: Fix error reporting when disk attachment fails

    There was a possibility for the actual error to be overridden or cleared
    during the rollback.

  * qemu: Fix assignment of graphics ports after daemon restart

    This could be seen with newer kernels that have bug regarding SO_REUSEADDR.
    After libvirtd was restarted it could assign already used address to new
    guests which would make them fail to start. This is fixed by marking used
    ports unavailable when reconnecting to running QEMU domains.

  * Fix message decoding which was causing a very strange bug

    When parsing an RPC message with file descriptors was interrupted and had
    to restart, the offset of the payload was calculated badly causing strange
    issues like not being able to find a domain that was not requested.


v3.7.0 (2017-09-04)
===================

* **New features**

  * qemu: Add managedsave-edit commands

    Using managedsave-dumpxml, managedsave-define and managedsave-edit
    commands, now we can dump and edit the XML configuration of domain which
    has managedsave image.

  * qemu: Add migrate-getmaxdowntime command

    Currently, the maximum tolerable downtime for a domain being migrated is
    write-only from libvirt, via migrate-setmaxdowntime. This implements a
    complementary migrate-getmaxdowntime command

  * bhyve: Support autoport for VNC ports

    It's no longer necessary to explicitly specify VNC port for the bhyve
    guests. With the autoport feature it will be allocated automatically.
    Please refer to the bhyve driver documentation for examples.

  * qemu: Added support for setting heads of virtio GPU

  * qemu: Added support to configure reconnect timeout for chardev devices

    When you have a TCP or UNIX chardev device and it's connected somewhere you
    can configure reconnect timeout if the connection is closed.

* **Improvements**

  * qemu: Report a clear error when dropping a VM during startup

    "Failed to load config for domain 'DOMNAME'" is now reported if a VM config
    can't be parsed for some reason, and thus provides a clear indication for
    users (and devs).

  * apparmor: Update for QEMU 2.10 compatibility

    Starting with QEMU 2.10, disk images and NVRAM files get automatically
    locked to prevent them from being corrupted; however, file locking needs to
    be explicitly allowed through ``virt-aa-helper`` or AppArmor will reject
    the requests and the guest will not be able to run.

  * virsh: List Unix sockets in 'domdisplay' output

    VNC and SPICE graphics can use Unix sockets instead of TCP/IP sockets as
    connection endpoints, but such a configuration was not handled correctly by
    ``virsh domdisplay`` , causing the respective endpoints to be missing from
    the output.

  * qemu: Don't check whether offline migration is safe

    Since offline migration only copies the guest definition to the destination
    host, data corruption is not a concern and the operation can always be
    performed safely.

  * virt-host-validate: Fix IOMMU detection on ppc64

* **Bug fixes**

  * qemu: Better support for international domain names (with wide characters)

    There were some issues with multi-byte domains getting lost on daemon
    restart due to truncation, so the code now handles multi-byte names a bit
    better.

  * qemu: Support long domain names with namespaces

    Domains with extremely long names would fail to start due to temporary
    namespace paths being created with the whole name. The path is now
    generated with shortened name instead.

  * qemu: Tolerate missing emulator binary during libvirtd restart

    For some time libvirt required qemu capabilities being present when parsing
    VM configs during startup. As a side effect VM configs would fail to parse
    and thus vanish, if the emulator binary would be uninstalled or broken.
    Libvirt now tolerates when capabilities are missing during startup.

  * qemu: Prevent pSeries guests from disappearing in some situations

    pSeries guest would disappear if any of the host devices they were
    configured to use was not available during libvirtd startup, which could
    easily happen for SR-IOV Virtual Functions. This scenario is now handled
    correctly.

  * qemu: Honor <on_reboot/> setting

    The setting was accepted by the parser, but not actually implemented.

  * Fix --verbose option for all daemons

    Since v3.0.0, the option had been ignored by all libvirt daemons (
    ``libvirtd`` , ``virtlogd`` and ``virtlockd`` ); it's now working as
    intended once again.


v3.6.0 (2017-08-02)
===================

* **New features**

  * hyperv: Implement virDomainSetMemory and virDomainSendKey APIs

  * qemu: Support multiple PHBs for pSeries guests

    pSeries guests can now have multiple PHBs (PCI Host Bridges), which show up
    as separate PCI domains in the guest. To create additional PHBs, simply add
    PCI controllers with model ``pci-root`` to the guest configuration.

  * qemu: Isolate hostdevs on pSeries guests

    To enable better error reporting and recovery, unrelated hostdevs will now
    be automatically isolated on pSeries guests by placing them on separate
    PHBs (PCI Host Bridges).

* **Improvements**

  * qemu: platform serial devices can now use chardev features

    QEMU VMs that depend on platform serial devices can now use QEMU's
    ``-chardev`` option, which enables access to advanced features like log
    file configuration. This applies to the default serial devices for arm,
    aarch64, and some ppc configurations.

  * Require use of GCC 4.4 or Clang compilers

    We only ever test libvirt with GCC or Clang (which provides a GCC
    compatible compilation environment). Between them, these compilers cover
    every supported operating system platform, including Windows.

  * qemu: shared disks with directsync cache should be safe for migration

    At present shared disks can be migrated with either readonly or
    ``cache=none`` . But ``cache=directsync`` should be safe for migration,
    because both ``cache=directsync`` and ``cache=none`` don't use the host
    page cache, and ``cache=direct`` write through qemu block layer cache.

  * Handle hotplug change on VLAN configuration using OVS

    Libvirt was taught to handle VLAN change for running OVS interface.

* **Bug fixes**

  * qemu: Use vCPU 'node-id' property and pass it back to qemu

    vCPU properties gathered from query-hotpluggable-cpus need to be passed
    back to QEMU. As QEMU did not use the node-id property until now and
    libvirt forgot to pass it back properly (it was parsed but not passed
    around) we did not honor this.

  * Miscellaneous stream fixes

    After introducing sparse stream features there were still some known bugs
    left. Those are fixed in this release.

  * qemu: Miscellaneous domain NS fixes

    Libvirt starts qemu domains in separate Linux namespaces for a while now.
    However, there were still some bugs lingering. For instance libvirt did not
    know how to handle file based bind mounts.

  * Various CPU driver improvements

    There were some minor bugs when using 'host-model' CPU.


v3.5.0 (2017-07-04)
===================

* **New features**

  * qemu: Add support for loadparm for a boot device

    Add an optional boot parameter 'loadparm' for a boot device. Loadparm is an
    8 byte parameter that, when present, is queried by S390 guests via sclp or
    diag 308. Linux guests on S390 use it to select a boot entry.

  * Support controlling how video devices are exposed to the bhyve guests

    The ``vgaconf`` attribute was added to ``video`` 's ``driver`` element.
    Possible values are: ``on`` , ``off`` , and ``io`` . It controls the way
    how bhyve exposes video devices to its guests; various guest OSes might
    require different settings to boot properly.

  * qemu: Add support for live updates of coalesce settings

    Users can now use ``virsh update-device`` to change the coalesce settings
    of an interfaces while the domain is running.

  * qemu: Allow VirtIO devices to use vIOMMU

    It is now possible to turn on IOTBL for the vIOMMU and have VirtIO devices
    use it, provided they have been configured appropriately.

* **Improvements**

  * qemu: block copy job can be used with persistent domains

    Until now it was not possible to use block copy with persistent VMs. In use
    cases where it's not required to recover the job after VM shutdown, it's
    possible to specify VIR_DOMAIN_BLOCK_COPY_TRANSIENT_JOB flag to start the
    copy job.

  * JSON pseudo-protocol backing store parser supports new format of qemu 2.9

    QEMU 2.9 modified a few structures corresponding to the JSON format of
    specifying a backing store for a disk image. Libvirt now implements the new
    format.

  * Capabilities now include info about host's CAT settings

    Various information about resource control from the host is gathered and
    presented in capabilities if available.

  * apparmor: Several improvements

    Allow access to Ceph config, EFI firmware on both x86_64 and aarch64,
    device tree on ppc64 and more.

  * qemu: Support host-model on POWER9 machines

* **Bug fixes**

  * qemu: snapshot: retrieve image metadata from user provided files

    Disk images of an external snapshot created with
    VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT flag specified would not be scanned
    for metadata after recent changes. The metadata is necessary to allow
    keeping relative paths between images when doing a block-commit.

  * Parse decimal numbers in a locale-independent way

    Some locales, such as ``de_DE`` and ``pt_BR`` , use comma rather than dot
    to separate the integer part from the fractional part of a decimal number;
    however, several data sources such as the kernel use a locale-independent
    representation and need to be treated accordingly.

  * Support compilation with newer compiler and libc versions

    Several fixes have been included to make compilation with Clang 4.0.0, GCC
    7.1 and glibc >= 2.25.90 possible.

  * qemu: Query name for vhost-user interfaces at runtime

    This makes it possible to use ``virsh`` subcommands such as ``domiflist``
    and ``domifstat`` on vhost-user interfaces.

  * qemu: Set MTU for hotplugged interfaces correctly

    When hotplugging a network interface, the MTU was only set on the guest
    side. Set it on the host side as well.

  * qemu: Forbid updating MTU for interfaces of running guests

    The MTU setting can't be modified while the guest is running, so any
    attempt to alter it at runtime will now result in an error rather than
    being silently ignored.

  * qemu: Fix specifying QXL heads with older QEMU releases

    Specifying the number of QXL heads was not working correctly for QEMU
    releases older than 1.6.

  * qemu: Fix migration to older libvirt/QEMU versions

    When the guest is started, libvirt updates the CPU definition to reflect
    the actual CPU features to enforce ABI. We need to send original and
    updated CPU definition in order to support migration to older libvirt/QEMU
    versions. Only the updated CPU definition was sent to destination.


v3.4.0 (2017-06-02)
===================

* **New features**

  * Improved streams to efficiently transfer sparseness

    New extension to virStream was implemented so that virStorageVolDownload
    and virStorageVolUpload can preserve file sparseness.

  * I/O APIC type can be specified for QEMU/KVM domains

    The ``ioapic`` tag was added to domain ``features`` , so the type of the
    I/O APIC can now be specified (e.g. putting it in userspace for KVM
    domains).

  * The reason for VM shutdown is reported, if known

    QEMU 2.10 will be able to report the reason for shutting down (whether that
    was caused by the guest or not), and libvirt is prepared for that and
    reports that information in its shutdown event as well, if it is known.

* **Improvements**

  * Repository now has new README.md file

    The new file uses markdown syntax, so it looks better on github and
    possibly other web pages, but it has also more useful information. The old
    README is now symlink to the new file.

  * qemu: Use GICv2 by default for aarch64/virt TCG guests

    The emulated GICv3 has some limitations that make it unusable as a default;
    use GICv2 until they're sorted out. This change makes it once again
    possible to run aarch64/virt guests on a x86_64 host without having to
    tweak their configuration.

  * Additional capabilities for the node_device module

    Introduce two new capabilities to the node_device module. The first is for
    CCW devices, most common on the S390 architecture. The second is for fibre
    channel-backed SCSI devices and exposes the fc_remote_port sub-capability
    to SCSI target devices.

  * Node devices now report Mediated device capabilities

    Endpoint devices support new ``mdev`` capability and their parents now
    report the supported types in new ``mdev_types`` capability.

  * Capabilities now report information about host caches

    If supported in the kernel, host capabilities will now list L3 caches. The
    code for other levels was added as well, but only L3 caches are reported
    currently.

  * POWER9 CPU model was added

    It is now properly reported in host capabilities.

  * libxl: NUMA sibling distances are now reported in host capabilities

  * VMDK version 3 files are now properly detected

  * Interrupt remapping and Extended interrupt mode for IOMMU devices

    These two new features can now be controlled with new ``<driver
    intremap='on/off' eim='on/off'/>`` tag for ``iommu`` devices.

  * Graphics in libxl domains now have default addresses

    Even though there were default addresses before this change, they were not
    saved in the XML. It is now possible to see and control the listen
    addresses properly.

  * Default USB controllers are now added for devices in libxl domains

    Even though they were added automatically when USB device was attached,
    they could've been missing in some other cases. The logic is now fixed so
    there are always USB controllers, even if there was none of them in the
    specified XML.

  * Limits for RPC messages were increased

    Hitting the RPC limits we have is easier every day, so they were increased
    once again and some guessing logic was improved as well. It is now possible
    to get more stats than ever using the ``virConnectGetAllDomainStats()``
    call and push through even bigger requests and replies for all APIs.

* **Bug fixes**

  * qemu: Create memory_backing_dir on startup

    Libvirt's policy is that directories are created on startup if they don't
    exist. We've missed this one.

  * PCIe 4.0 cards now report proper link speeds

    It could happen that the link speed for PCIe devices was not properly
    reported or the nodedev-dumpxml just failed. That was due to mistake in the
    field width, but should now work properly.

  * qemu: Do not report errors on shutdown

    For some users, in some rare cases, it could happen that there was an error
    message "internal error: End of file from qemu monitor" in the logs even
    though no problem happened. The detection of these false positives was
    improved and such errors should not show any more.

  * User-specified UNIX socket paths for virtio channels should not be reset

    It could happen, in some cases, that libvirt would mistake a user-specified
    path for its own generated one and thus remove it from the XML. The
    detection of such addresses was improved now.

  * Fix address reservation during RNG hot-plug

    When error occurred in a specific point in time during the hot-plug of an
    RNG device, it could happen that an address was released even though
    another device was already using it, making it possible to hot-plug another
    device with that address, effectively having duplicated addresses in the
    XML.


v3.3.0 (2017-05-05)
===================

* **New features**

  * net: Add support for coalesce settings

    Enabling data batching through these settings can improve network
    performance for guests.

  * qemu: Add support for guest CPU cache specification

    This features allows fine-grained control of the cache behavior of the
    guest CPU.

  * qemu: Add support for the qemu-xhci USB controller

* **Improvements**

  * hyperv: Support Hyper-V 2012 and newer

    Starting with Hyper-V 2012 the API has changed causing the existing driver
    to be unable to send and process requests properly. This has been resolved
    by adding abstractions to handle the differences and ease handling such
    breaks if they happen in the future.

  * libxl: Add support for nested HVM domains

    Xen has supported nested HVM domains since version 4.4. The libvirt libxl
    driver now supports nested HVM domains by specifying the host-passthrough
    CPU mode when defining a domain.

  * qemu: Implement ACPI support for aarch64 guests

    Up until this point, ACPI support was only advertised for x86_64 guests and
    disabling it for aarch64 guests was not possible at all.

  * vz: Add support for changing the number of vCPUs

  * qemu: Automatically choose the best USB controller for guests

    The recently introduced qemu-xhci USB controller is the best choice for
    both ppc64 and aarch64 guests, so use it by default on those architectures
    if available.

  * daemon: Increase default task limit for libvirtd

    The default number of tasks for the pids cgroup controller is 512, which
    libvirtd can quickly bump into when starting lots of guests. Raise the
    limit to a more reasonable 32768.

  * docs: Include man pages describing key code names and values

  * virsh: Report initialization errors

    Sometimes virsh might be unable to start: when that happens, report useful
    diagnostics instead of failing silently.

* **Bug fixes**

  * nss: Don't require a network restart for libvirt_guest

    Previously, the libvirt_guest NSS module would only work properly after the
    corresponding network had been restarted; now newly started guests will be
    reported correctly right away.

  * storage: Remove unavailable transient pools after restart

    Solve an issue where transient storage pools would be stuck in an
    unmanageable state if the source disappeared and libvirtd was subsequently
    restarted.

  * storage: Fix capacity value for LUKS encrypted volumes

    The 'capacity' value (e.g. guest logical size) for a LUKS volume is smaller
    than the 'physical' value of the file in the file system, so we need to
    account for that.

  * qemu: Fix regression when hyperv/vendor_id feature is used

    Guests using the feature would not be started at all; it is now possible to
    start them as expected.

  * qemu: Do not crash on USB address with no port and invalid bus

  * crypto: Always pad data before encrypting it

    If this step is not performed, when the data length matches the chunk size
    the decryption routines will misinterpret the last byte of data as the
    padding length and fail to decode it correctly.


v3.2.0 (2017-04-02)
===================

* **New features**

  * The virt-host-validate tool now supports bhyve hypervisor

  * Introduce NVDIMM memory model

    NVDIMM is new type of memory introduced into QEMU 2.6. The idea is that we
    have a non-volatile memory module that keeps the data persistent across
    domain reboots and offers much faster data accesses. However, due to a bug
    in QEMU, this feature is not enabled for QEMUs older than 2.9.0.

  * qemu: Introduce support for generic PCIe Root Ports

    For new controllers, a generic device (pcie-root-port) will be used by
    default instead of the Intel-specific device (ioh3420), provided the QEMU
    binary supports it.

  * qemu: Add support for checking guest CPU ABI compatibility

    When migrating a domain to a different host, restoring a domain from a file
    or reverting a snapshot libvirt will make sure the guest CPU QEMU presents
    to the guest OS exactly matches the one provided on the source host (or
    before the domain's state was saved). This enhanced check may also be
    requested when starting a new domain to ensure the virtual CPU exactly
    matches the one specified in the XML.

  * qemu: Add support to migrate using TLS

    Add the ability to migrate QEMU guests using TLS via a new flag
    VIR_MIGRATE_TLS or virsh migrate '--tls' option. Requires using at least
    QEMU 2.9.0 in order to work properly.

  * qemu: add mediated devices framework support

    Recent kernel version introduced new mediated device framework, so provide
    an initial support of this framework for libvirt, mainly by introducing a
    new host device type in the XML.

  * qemu: Add support for setting TSC frequency

    Setting TSC frequency is required to enable migration for domains with
    'invtsc' CPU feature turned on.

  * Add support for block device threshold event

    When using thin provisioning, management tools need to resize the disk in
    certain cases. To avoid having them to poll disk usage this version
    introduces an event which will be fired when a given offset of the storage
    is written by the hypervisor. Together with the API it allows registering
    thresholds for given storage backing volumes and this event will then
    notify management if the threshold is exceeded. Currently only the qemu
    driver supports this.

  * bhyve: Add support for UEFI boot ROM, VNC, and USB tablet

    The bhyve driver now supports booting using the UEFI boot ROM, so
    non-FreeBSD guests that support UEFI could be booted without using an
    external boot loader like grub-bhyve. Video is also supported now, allowing
    to connect to guests via VNC and use an USB tablet as an input device.
    Please refer to the driver page for domain XML examples.

* **Improvements**

  * qemu: Detect host CPU model by asking QEMU on x86_64

    Previously, libvirt detected the host CPU model using CPUID instruction,
    which caused libvirt to detect a lot of CPU features that are not supported
    by QEMU/KVM. Asking QEMU makes sure we don't start it with unsupported
    features.

  * perf: Add more perf statistics

    Add support to get the count of cpu clock time, task clock time, page
    faults, context switches, cpu migrations, minor page faults, major page
    faults, alignment faults, emulation faults by applications running on the
    platform.

  * Write hyperv crash information into vm log

    qemu's implementation of the hyperv panic notifier now reports information
    about the crash from the guest os. Starting with this version, libvirt logs
    the information to the vm log file for possible debugging.

* **Bug fixes**

  * QEMU: Use adaptive timeout for connecting to monitor

    When starting qemu, libvirt waits for qemu to create the monitor socket
    which libvirt connects to. Historically, there was sharp 30 second timeout
    after which the qemu process was killed. This approach is suboptimal as in
    some scenarios with huge amounts of guest RAM it can take a minute or more
    for kernel to allocate and zero out pages for qemu. The timeout is now
    flexible and computed by libvirt at domain startup.

  * Overwrite (clear) 2 KB instead of just 512 bytes when initializing logical
    device

  * Describe the logical backend requirements better for pool-create-as


v3.1.0 (2017-03-03)
===================

* **New features**

  * storage: Add Virtuozzo storage backend storage pool

    Add new storage backend to support pool and volume management within the
    Virtuozzo Storage environment. Virtuozzo Storage is a highly available
    distributed software defined storage with built-in replication and disaster
    recovery.

  * qemu: Add support for memory backing with file source

    Add support in numa topology for file source inside memory backing
    (hugepages are not needed) Three new elements <source/>,<access/> and
    <allocation/> were added to <memoryBacking/> element. Also new
    configuration parameter ``memory_backing_dir`` was added to qemu.conf.

  * network: make openvswitch call timeout configurable

    Adding the ability to specify the timeout value in seconds for openvswitch
    calls in the libvirtd configuration file.

  * bhyve: add e1000 NIC support

    Add support for e1000 NIC. Previously, the only available option was
    ``virtio-net`` .

  * libxl: add tunneled migration support

    Add tunneled migration to libxl driver, which is always capable of strong
    encryption and doesn't require any extra network connection other than
    what's required for remote access of libvirtd.

  * qemu: add rendernode argument

    Add a new attribute 'rendernode' to <gl> spice element.

  * nodedev: add drm capability

    Add a new 'drm' capability for Direct Rendering Manager (DRM) devices,
    providing device type information.

  * Add API for individual/specific vCPU hotplug

    The new API allows selecting specific vCPUs to be added/removed from the
    VM. The existing APIs allowed only adding/removing from the end which did
    not play well with NUMA.

* **Improvements**

  * virsh: pool-list: allow both --uuid and --name in one command

    Adjust the virsh-pool command to support the --uuid and/or --name options
    in order to print just the --name and/or --uuid of pools.

  * Introduce MTU to domain <interface/> and <network>

    Allow setting MTU size for some types of domain interface and network.

  * libxl: improve support for <timer> configurations

    Add support for multiple timers. Extend the tsc timer to support the
    emulate mode. Improve conversion of timer XML to/from xl.cfg.

  * storage: modularize the storage driver

    Split up the storage driver backends into loadable modules so that binary
    distributions don't have to compromise on shipping the storage driver with
    all backends which may pull in too many dependencies.

* **Bug fixes**

  * nodedev: Fabric name must not be required for fc_host capability

    fabric_name is one of many fc_host attributes in Linux that is optional and
    left to the low-level driver to decide if it is implemented. For example
    the zfcp device driver does not provide a fabric name for an fcp host. The
    requirement for the existence of a fabric name has been removed by making
    it optional.

  * bhyve: change address allocation schema for SATA disks

    Previously, the bhyve driver assigned PCI addresses to SATA disks directly
    rather than assigning that to a controller and using SATA addresses for
    disks. It was implemented this way because bhyve has no notion of an
    explicit SATA controller. However, as this doesn't match libvirt's
    understanding of disk addresses, the bhyve driver was changed to follow the
    common schema and have PCI addresses for SATA controllers and SATA
    addresses for disks. If you're having issues because of this, it's
    recommended to edit the domain's XML and remove <address type='pci'> from
    the <disk> elements with <target bus='sata'/> and let libvirt regenerate it
    properly.

  * libxl: maximum memory fixes

    Fix reporting of domain maximum memory. Fix setting dom0 maximum memory.

  * libxl: fix disk detach when <driver> not specified

  * libxl: fix dom0 autoballooning with Xen 4.8

  * qemu: Allow empty script path to <interface/>

    Historically, this was always allowed. Unfortunately, due to some rework
    done for 1.3.2 release a bug was dragged in which suddenly stop allowing
    domain with such configuration to start.


v3.0.0 (2017-01-17)
===================

* **New features**

  * Domain events for metadata content changes

    The domain events framework has a new event ID that can be used to get
    notifications when domain metadata content changes.

  * Event notifications for the secret object

    The secret object now supports event notifications, covering lifcycle
    changes and secret value changes.

  * New localPtr attribute for "ip" element in network XML

  * qemu: Support QEMU group I/O throttling

    Add the capability to allow group I/O throttling via a new domain <disk>
    <iotune> subelement "group_name" to allow sharing I/O throttling quota
    between multiple drives.

  * nss: Introduce libvirt_guest

    New ``libvirt_guest`` nss module that translates libvirt guest names into
    IP addresses.

  * daemon: Add support for runtime logging settings adjustment

    Logging-related settings like log outputs and filters can now be adjusted
    during runtime using the admin interface without the necessity of the
    daemon's restart.

  * storage: Add virStorageVolInfoFlags API

    Add the API to support using the VIR_STORAGE_VOL_GET_PHYSICAL flag in order
    to return the host physical size in bytes of the image container in the
    allocation field of the _virStorageVolInfo structure. The --physical flag
    has been added to the virsh vol-info command to access the data.

  * libxl: Implement virDomainGetMaxVcpus API

  * storage: Add overwrite flag checking for logical pool

    Add support for the OVERWRITE flags for the logical storage backend
    including checking for existing data on the target volumes when building a
    new logical pool on target volume(s).

  * qemu: Add support for guest CPU configuration on s390(x)

* **Improvements**

  * perf: Add more perf statistics

    Add support to get the count of branch instructions executed, branch
    misses, bus cycles, stalled frontend cpu cycles, stalled backend cpu
    cycles, and ref cpu cycles by applications running on the platform.

  * conf: Display <physical> for volume xml

    Add a display of the <physical> size of a disk volume in the output of the
    volume XML.

  * qemu: Use virtio-pci by default for aarch64 mach-virt guests

    virtio-pci provides several advantages over virtio-mmio, such as the
    ability to hotplug devices and improved performance. While opting in to
    virtio-pci has been possible for a while, newly-defined guests will now use
    it automatically.

  * vbox: remove support for VirtualBox 3.x and older

    Those old VirtualBox versions have been unsupported by upstream for a long
    time and the API of 4.0 and newer has diverged enough to require code
    abstractions to handle differences. Removing support for those old versions
    drops lots of code from the driver and simplifies the logic to ease
    implementation of new features going forward.

  * virsh: pool-info: introduce option --bytes

    Add option --bytes to virsh pool-info in order ti allow display of units in
    bytes rather than default of human readable output.

  * scsi: Add parent wwnn/wwpn or fabric capability for createVport

    Improve the algorithm searching for the parent scsi_host device for
    vHBA/NPIV scsi_host creation. Rather than supplying the "parent" by name,
    it's now possible to define the parent by it's wwnn/wwpn or fabric_wwn in
    the node device create XML or the storage pool XML.

  * qemu: aggregate pcie-root-ports onto multiple functions of a slot

    When pcie-root-ports are added to pcie-root in order to provide a place to
    connect PCI Express endpoint devices, libvirt now aggregates multiple root
    ports together onto the same slot (up to 8 per slot) in order to conserve
    slots. Using this method, it's possible to connect more than 200 endpoint
    devices to a guest that uses PCIe without requiring setup of any PCIe
    switches.

* **Bug fixes**

  * lxc: fix accidental killing of containers during libvirtd restart

    The libvirt_lxc process was previously not moved into the container scope.
    As a result, if systemd reloads its config after a container is started,
    when libvirtd is later restarted it will accidentally kill the containers.

  * qemu: Correct GetBlockInfo values

    For an active domain, correct the physical value provided for a raw sparse
    file backed storage and the allocation value provided for a qcow2 file
    backed storage that hasn't yet been opened on the domain.

  * qemu: Make virtio console usable on ppc64 guests

    The chardev detection code has been improved and can now handle this
    configuration properly.

  * qemu: Enable mount namespace

    To avoid funny races with udev relabelling devices under our hands and to
    enhance security, libvirt now spawns each qemu process with its own
    ``/dev`` .

  * storage: Fix implementation of no-overwrite for file system backend

    Fix file system storage backend implementation of the OVERWRITE flags to be
    consistent between code and documentation. Add checks to ensure that when
    building a new file system on a target volume that there is not something
    already on the disk in a format that libvirt can recognize.

  * qemu: Create hugepage path on per domain basis

    Historically, all hugepage enabled domains shared the same path under
    hugetlbfs. This left libvirt unable to correctly set security labels on it.
    With this release, however, each domain is put into a separate path which
    is also correctly labeled.

  * conf: Reject domains with duplicate drive addresses

    Reject duplicate drive addresses for disks and hostdevs at domain
    definition.

  * libxl: reverse defaults on HVM net device attach

    Fixes network interface attach for HVM domains when no model is specified.
    Emulated hotplug isn't yet supported and hence we should default to the
    general working scenario.

  * libxl: always enable pae for x86_64 HVM

    By default pae is disabled in libxl. Without an explicit <pae/> setting in
    the domain <features> configuration, an x86_64 HVM domain would be get an
    i686 environment. pae should always be enabled for x86_64 HVM domains.

  * qemu: Fix XML dump of autogenerated websocket

    As a result autogenerated websocket port is regenerated on domain restore,
    migration and such as it should be.


v2.5.0 (2016-12-04)
===================

* **New features**

  * shmem: Add support for additional models

    The shmem device can now utilize QEMU's ivshmem-plain and ivshmem-doorbell,
    more modern versions of ivshmem.

  * vbox: Add VirtualBox 5.1 support

  * libssh: New transport

    The new libssh transport allows one to connect to a running libvirtd via
    SSH, using the libssh library; for example: ``qemu+libssh://server/system``
    .

  * vhost-scsi: Add support scsi_host hostdev passthrough

    Add the capability to pass through a scsi_host HBA and the associated LUNs
    to the guest.

  * Allow debugging of gluster volumes in qemu

    Users can now enable debug logging for native gluster volumes in qemu using
    the "gluster_debug_level" option in qemu.conf

  * Pre-allocate memory slots for memory hotplug

    Slot numbers for memory devices are now automatically allocated and thus
    persistent. In addition slot numbers can be specified without providing a
    base address, which simplifies user configuration

  * qemu: Express devices will be placed on PCIe bus by default

    For machine types that use a PCI Express root bus (e.g. x86_64/Q35 and
    aarch64/virt), any unaddressed PCI device that is an Express device (all
    virtio-1.0 devices, e1000e, nec-xhci, vfio assigned devices) will be placed
    on an Express controller (i.e. a pcie-root-port) instead of a legacy PCI
    controller (i.e. pci-bridge) with the root ports added as needed.

* **Improvements**

  * docs: Better documentation for migration APIs and flags

  * vbox: Address thread safety issues

  * virsh: Add support for passing an alternative persistent XML to migrate
    command

  * vhostuser: Allow hotplug of multiqueue devices

  * NEWS: Switch to an improved format

    List user-visible changes instead of single commits for a better high-level
    overview of differences between libvirt releases.

  * website: Modernize layout and branding

    The libvirt website looked very cluttered and outdated; it has now been
    completely overhauled, resulting in a design that's better organized and
    more pleasant to look at.

* **Bug fixes**

  * vz: Fix migration in P2P mode

  * Forbid newline character in names of some libvirt objects

  * Fix compilation on macOS


v2.4.0 (2016-11-01)
===================

No release notes.


v2.3.0 (2016-10-04)
===================

No release notes.


v2.2.0 (2016-09-02)
===================

No release notes.


v2.1.0 (2016-08-02)
===================

No release notes.


v2.0.0 (2016-07-01)
===================

No release notes.


v1.3.5 (2016-06-04)
===================

No release notes.


v1.3.4 (2016-05-01)
===================

No release notes.


v1.3.3 (2016-04-06)
===================

No release notes.


v1.3.2 (2016-03-01)
===================

No release notes.


v1.3.1 (2016-01-17)
===================

No release notes.


v1.3.0 (2015-12-09)
===================

No release notes.


v1.2.21 (2015-11-04)
====================

No release notes.


v1.2.20 (2015-10-02)
====================

No release notes.


v1.2.19 (2015-09-02)
====================

No release notes.


v1.2.18 (2015-08-03)
====================

No release notes.


v1.2.17 (2015-07-02)
====================

No release notes.


v1.2.16 (2015-06-01)
====================

No release notes.


v1.2.15 (2015-05-04)
====================

No release notes.


v1.2.14 (2015-04-02)
====================

No release notes.


v1.2.13 (2015-03-02)
====================

No release notes.


v1.2.12 (2015-01-27)
====================

No release notes.


v1.2.11 (2014-12-13)
====================

No release notes.


v1.2.10 (2014-11-03)
====================

No release notes.


v1.2.9 (2014-10-01)
===================

No release notes.


v1.2.8 (2014-09-02)
===================

No release notes.


v1.2.7 (2014-08-02)
===================

No release notes.


v1.2.6 (2014-07-02)
===================

No release notes.


v1.2.5 (2014-06-02)
===================

No release notes.


v1.2.4 (2014-05-04)
===================

No release notes.


v1.2.3 (2014-04-01)
===================

No release notes.


v1.2.2 (2014-03-02)
===================

No release notes.


v1.2.1 (2014-01-16)
===================

No release notes.


v1.2.0 (2013-12-02)
===================

No release notes.


v1.1.4 (2013-11-04)
===================

No release notes.


v1.1.3 (2013-10-01)
===================

No release notes.


v1.1.2 (2013-09-02)
===================

No release notes.


v1.1.1 (2013-07-30)
===================

No release notes.


v1.1.0 (2013-07-01)
===================

No release notes.


v1.0.6 (2013-06-03)
===================

No release notes.


v1.0.5 (2013-05-02)
===================

No release notes.


v1.0.4 (2013-04-01)
===================

No release notes.


v1.0.3 (2013-03-05)
===================

No release notes.


v1.0.2 (2013-01-30)
===================

No release notes.


v1.0.1 (2012-12-17)
===================

No release notes.


v1.0.0 (2012-11-02)
===================

No release notes.


v0.10.2 (2012-09-24)
====================

No release notes.


v0.10.1 (2012-08-31)
====================

No release notes.


v0.10.0 (2012-08-29)
====================

No release notes.


v0.9.13 (2012-08-02)
====================

No release notes.


v0.9.12 (2012-05-14)
====================

No release notes.


v0.9.11 (2012-04-03)
====================

No release notes.


v0.9.10 (2012-02-13)
====================

No release notes.


v0.9.9 (2012-01-07)
===================

No release notes.


v0.9.8 (2011-12-08)
===================

No release notes.


v0.9.7 (2011-11-08)
===================

No release notes.


v0.9.6 (2011-09-22)
===================

No release notes.


v0.9.5 (2011-09-20)
===================

No release notes.


v0.9.4 (2011-08-03)
===================

No release notes.


v0.9.3 (2011-07-04)
===================

No release notes.


v0.9.2 (2011-06-06)
===================

No release notes.


v0.9.1 (2011-05-05)
===================

No release notes.


v0.9.0 (2011-04-04)
===================

No release notes.


v0.8.8 (2011-02-17)
===================

No release notes.


v0.8.7 (2011-01-04)
===================

No release notes.


v0.8.6 (2010-11-30)
===================

No release notes.


v0.8.5 (2010-10-29)
===================

No release notes.


v0.8.4 (2010-09-10)
===================

No release notes.


v0.8.3 (2010-08-04)
===================

No release notes.


v0.8.2 (2010-07-05)
===================

No release notes.


v0.8.1 (2010-04-30)
===================

No release notes.


v0.8.0 (2010-04-12)
===================

No release notes.


v0.7.7 (2010-03-05)
===================

No release notes.


v0.7.6 (2010-02-03)
===================

No release notes.


v0.7.5 (2009-12-23)
===================

No release notes.


v0.7.4 (2009-11-20)
===================

No release notes.


v0.7.3 (2009-11-20)
===================

No release notes.


v0.7.2 (2009-10-14)
===================

No release notes.


v0.7.1 (2009-09-15)
===================

No release notes.


v0.7.0 (2009-08-05)
===================

No release notes.


v0.6.5 (2009-07-03)
===================

No release notes.


v0.6.4 (2009-05-29)
===================

No release notes.


v0.6.3 (2009-04-24)
===================

No release notes.


v0.6.2 (2009-04-03)
===================

No release notes.


v0.6.1 (2009-03-03)
===================

No release notes.


v0.6.0 (2009-01-31)
===================

No release notes.


v0.5.1 (2008-12-04)
===================

No release notes.


v0.5.0 (2008-11-25)
===================

No release notes.


v0.4.6 (2008-09-23)
===================

No release notes.


v0.4.5 (2008-09-08)
===================

No release notes.


v0.4.4 (2008-06-25)
===================

No release notes.


v0.4.3 (2008-06-12)
===================

No release notes.


v0.4.2 (2008-04-08)
===================

No release notes.


v0.4.1 (2008-03-03)
===================

No release notes.


v0.4.0 (2007-12-18)
===================

No release notes.


v0.3.3 (2007-09-30)
===================

No release notes.


v0.3.2 (2007-08-21)
===================

No release notes.


v0.3.1 (2007-07-24)
===================

No release notes.


v0.3.0 (2007-07-09)
===================

No release notes.


v0.2.3 (2007-06-08)
===================

No release notes.


v0.2.2 (2007-04-17)
===================

No release notes.


v0.2.1 (2007-03-16)
===================

No release notes.


v0.2.0 (2007-02-14)
===================

No release notes.


v0.1.11 (2007-01-22)
====================

No release notes.


v0.1.10 (2006-12-20)
====================

No release notes.


v0.1.9 (2006-11-29)
===================

No release notes.


v0.1.8 (2006-10-16)
===================

No release notes.


v0.1.7 (2006-09-29)
===================

No release notes.


v0.1.6 (2006-09-22)
===================

No release notes.


v0.1.5 (2006-09-05)
===================

No release notes.


v0.1.4 (2006-08-16)
===================

No release notes.


v0.1.3 (2006-07-11)
===================

No release notes.


v0.1.2 (2006-07-03)
===================

No release notes.


v0.1.1 (2006-06-21)
===================

No release notes.


v0.1.0 (2006-04-10)
===================

No release notes.


v0.0.6 (2006-02-28)
===================

No release notes.


v0.0.5 (2006-02-23)
===================

No release notes.


v0.0.4 (2006-02-10)
===================

No release notes.


v0.0.3 (2006-02-09)
===================

No release notes.


v0.0.2 (2006-01-29)
===================

No release notes.


v0.0.1 (2005-12-19)
===================

No release notes.


.. _git log: https://gitlab.com/libvirt/libvirt/-/commits/master
