============================
Launch security with AMD SEV
============================

.. contents::

Storage encryption in modern public cloud computing is a common
practice. However, from the point of view of a user of these cloud
workloads, a significant amount of trust needs to be put in the cloud
platform security as well as integrity (was the hypervisor tampered?).
For this reason there's ever rising demand for securing data in use,
i.e. memory encryption. One of the solutions addressing this matter is
AMD SEV.

AMD Secure Encrypted Virtualization (SEV)
=========================================

SEV (Secure Encrypted Virtualization) is a feature extension of AMD's
SME (Secure Memory Encryption) intended for KVM virtual machines which
is supported primarily on AMD's EPYC CPU line. In contrast to SME, SEV
uses a unique memory encryption key for each VM. The whole encryption of
memory pages is completely transparent to the hypervisor and happens
inside dedicated hardware in the on-die memory controller. Each
controller includes a high-performance Advanced Encryption Standard
(AES) engine that encrypts data when it is written to DRAM and decrypts
it when read. For more details about the technology itself, you can
visit `AMD's developer portal <https://developer.amd.com/sev/>`__.

Enabling SEV on the host
========================

Before VMs can make use of the SEV feature you need to make sure your
AMD CPU does support SEV. You can run ``virt-host-validate``
(libvirt >= 6.5.0) to check if your host supports secure guests or you
can follow the manual checks below.

You can manually check whether SEV is among the CPU flags with:

::

   $ grep -w sev /proc/cpuinfo
   ...
   sme ssbd sev ibpb

Next step is to enable SEV in the kernel, because it is disabled by
default. This is done by putting the following onto the kernel command
line:

::

   mem_encrypt=on kvm_amd.sev=1

To make the changes persistent, append the above to the variable holding
parameters of the kernel command line in ``/etc/default/grub`` to
preserve SEV settings across reboots

::

   $ cat /etc/default/grub
   ...
   GRUB_CMDLINE_LINUX="... mem_encrypt=on kvm_amd.sev=1"
   $ grub2-mkconfig -o /boot/efi/EFI/<distro>/grub.cfg

``mem_encrypt=on`` turns on the SME memory encryption feature on the
host which protects against the physical attack on the hypervisor
memory. The ``kvm_amd.sev`` parameter actually enables SEV in the kvm
module. It can be set on the command line alongside ``mem_encrypt`` like
shown above, or it can be put into a module config under
``/etc/modprobe.d/``

::

   $ cat /etc/modprobe.d/sev.conf
   options kvm_amd sev=1

After rebooting the host, you should see SEV being enabled in the
kernel:

::

   $ cat /sys/module/kvm_amd/parameters/sev
   1


Checking SEV support in the virt stack
======================================

**Note: All of the commands below need to be run with root
privileges.**

First make sure you have the following packages in the specified
versions:

-  libvirt >= 4.5.0 (>5.1.0 recommended due to additional SEV bugfixes)
-  QEMU >= 2.12.0

To confirm that the virtualization stack supports SEV, run the
following:

::

   # virsh domcapabilities
   <domainCapabilities>
   ...
     <features>
       ...
       <sev supported='yes'>
         <cbitpos>47</cbitpos>
         <reducedPhysBits>1</reducedPhysBits>
       </sev>
       ...
     </features>
   </domainCapabilities>

Note that if libvirt (<6.5.0) was already installed and libvirtd running before
enabling SEV in the kernel followed by the host reboot you need to force
libvirtd to re-probe both the host and QEMU capabilities. First stop
libvirtd:

::

   # systemctl stop libvirtd.service

Now you need to clean the capabilities cache:

::

   # rm -f /var/cache/libvirt/qemu/capabilities/*

If you now restart libvirtd, it will re-probe the capabilities and if
you now run:

::

   # virsh domcapabilities

SEV should be listed as supported. If you still see:

::

   <sev supported='no'/>

it means one of two things:

#. libvirt does support SEV, but either QEMU or the host does not
#. you have libvirt <=5.1.0 which suffered from getting a
   ``'Permission denied'`` on ``/dev/sev`` because of the default
   permissions on the character device which prevented QEMU from opening
   it during capabilities probing - you can either manually tweak the
   permissions so that QEMU has access to it or preferably install
   libvirt 5.1.0 or higher

VM Configuration
================

SEV is enabled in the XML by specifying the
`<launchSecurity> <https://libvirt.org/formatdomain.html#launch-security>`__
element. However, specifying ``launchSecurity`` isn't enough to boot an
SEV VM. Further configuration requirements are discussed below.

Machine type
------------

Even though both Q35 and legacy PC machine types (for PC see also
"virtio") can be used with SEV, usage of the legacy PC machine type is
strongly discouraged, since depending on how your OVMF package was built
(e.g. including features like SecureBoot or SMM) Q35 may even be
required.

Q35
~~~

::

   ...
   <os>
     <type arch='x86_64' machine='pc-q35-3.0'>hvm</type>
     ...
   </os>
   ...

i440fx (discouraged)
~~~~~~~~~~~~~~~~~~~~

::

   ...
   <os>
     <type arch='x86_64' machine='pc-i440fx-3.0'>hvm</type>
     ...
   </os>
   ...

Boot loader
-----------

SEV is only going to work with OVMF (UEFI), so you'll need to point
libvirt to the correct OVMF binary.

::

   ...
   <os>
     <type arch='x86_64' machine='pc-q35-3.0'>hvm</type>
     <loader readonly='yes' type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE.fd</loader>
   </os>
   ...

If intending to attest the boot measurement, it is required to use a
firmware binary that is stateless, as persistent NVRAM can undermine
the trust of the secure guest. This is achieved by telling libvirt
that a stateless binary is required

::

   ...
   <os type='efi'>
     <type arch='x86_64' machine='q35'>hvm</type>
     <loader stateless='yes'/>
   </os>
   ...

Memory
------

Internally, SEV expects that the encrypted memory pages won't be swapped
out or move around so the VM memory needs to be pinned in physical RAM
which will be handled by QEMU. Apart from that, certain memory regions
allocated by QEMU itself (UEFI pflash, device ROMs, video RAM, etc.)
have to be encrypted as well. This causes a conflict in how libvirt
tries to protect the host. By default, libvirt enforces a memory hard
limit on each VM's cgroup in order to protect the host from malicious
QEMU to allocate and lock all the available memory. This limit
corresponds to the total memory allocation for the VM given by
``<currentMemory>`` element. However, trying to account for the
additional memory regions QEMU allocates when calculating the limit in
an automated manner is non-deterministic. One way to resolve this is to
set the hard limit manually.

Note: Figuring out the right number so that your guest boots and isn't
killed is challenging, but 256MiB extra memory over the total guest RAM
should suffice for most workloads and may serve as a good starting
point. For example, a domain with 4GB memory with a 256MiB extra hard
limit would look like this:

::

   # virsh edit <domain>
   <domain>
     ...
     <currentMemory unit='KiB'>4194304</currentMemory>
     <memtune>
       <hard_limit unit='KiB'>4456448</hard_limit>
     </memtune>
     ...
   </domain>

There's another, preferred method of taking care of the limits by using
the\ ``<memoryBacking>`` element along with the ``<locked/>``
subelement:

::

   <domain>
     ...
     <memoryBacking>
       <locked/>
     </memoryBacking>
     ...
   </domain>

What that does is that it tells libvirt not to force any hard limit
(well, unlimited) upon the VM cgroup. The obvious advantage is that one
doesn't need to determine the hard limit for every single SEV-enabled
VM. However, there is a significant security-related drawback to this
approach. Since no hard limit is applied, a malicious QEMU could perform
a DoS attack by locking all of the host's available memory. The way to
avoid this issue and to protect the host is to enforce a bigger hard
limit on the master cgroup containing all of the VMs - on systemd this
is ``machine.slice``.

::

   # systemctl set-property machine.slice MemoryHigh=<value>

To put even stricter measures in place which would involve the OOM
killer, use

::

   # systemctl set-property machine.slice MemoryMax=<value>

instead. Alternatively, you can create a systemd config (don't forget to
reload systemd configuration in this case):

::

   # cat << EOF > /etc/systemd/system.control/machine.slice.d/90-MemoryMax.conf
   MemoryMax=<value>
   EOF

The trade-off to keep in mind with the second approach is that the VMs
can still perform DoS on each other.

Virtio
------

In order to make virtio devices work, we need to use
``<driver iommu='on'/>`` inside the given device XML element in order
to enable DMA API in the virtio driver.

Starting with QEMU 6.0.0 QEMU will set this for us by default. For earlier
versions though, you will need to explicitly enable this in the device XML as
follows::

   # virsh edit <domain>
   <domain>
     ...
     <controller type='virtio-serial' index='0'>
       <driver iommu='on'/>
     </controller>
     <controller type='scsi' index='0' model='virtio-scsi'>
       <driver iommu='on'/>
     </controller>
     ...
     <memballoon model='virtio'>
       <driver iommu='on'/>
     </memballoon>
     <rng model='virtio'>
       <backend model='random'>/dev/urandom</backend>
       <driver iommu='on'/>
     </rng>
     ...
   <domain>

If you for some reason want to use the legacy PC machine type, further
changes to the virtio configuration is required, because SEV will not
work with Virtio <1.0. In libvirt, this is handled by using the
virtio-non-transitional device model (libvirt >= 5.2.0 required).

Note: some devices like video devices don't support non-transitional
model, which means that virtio GPU cannot be used.

::

   <domain>
     ...
     <devices>
       ...
       <memballoon model='virtio-non-transitional'>
         <driver iommu='on'/>
       </memballoon>
     </devices>
     ...
   </domain>

Virtio-net
~~~~~~~~~~
With virtio-net it's also necessary to disable the iPXE option ROM as
iPXE is not aware of SEV (at the time of this writing). This translates to the
following XML:

::

   <domain>
     ...
     <interface type='network'>
        ...
       <model type='virtio'/>
       <driver iommu='on'/>
       <rom enabled='no'/>
     </interface>
     ...
   <domain>


Checking SEV from within the guest
==================================

After making the necessary adjustments discussed in
`VM Configuration`_, the VM should now boot successfully
with SEV enabled. You can then verify that the guest has SEV enabled by
running:

::

   # dmesg | grep -i sev
   AMD Secure Encrypted Virtualization (SEV) active

Guest attestation for SEV/SEV-ES from a trusted host
====================================================

Before a confidential guest is used, it may be desirable to attest the boot
measurement. To be trustworthy the attestation process needs to be performed
from a machine that is already trusted. This would typically be a physical
machine that the guest owner controls, or could be a previously launched
confidential guest that has already itself been attested. Most notably, it is
**not** possible to securely attest a guest from the hypervisor host itself,
as the goal of the attestation process is to detect whether the hypervisor is
malicious.

Performing an attestation requires that the ``<launchSecurity>`` element is
configured with a guest owner Diffie-Hellman (DH) certificate, and a session
data blob. These must be unique for every guest launch attempt. Any reuse will
open avenues of attack for the hypervisor to fake the measurement. Unique data
can be generated using the `sevctl <https://github.com/virtee/sevctl>`_ tool.

First of all the Platform Diffie-Hellman key (PDH) for the hypervisor host
needs to be obtained. The PDH is used to negotiate a master secret between
the SEV firmware and external entities.

The admin of the hypervisor can extract the PDH using::

  $ sevctl export --full ${hostname}.pdh

Upon receiving the PDH associated with the hypervisor, the guest owner should
validate its integrity::

  $ sevctl verify --sev ${hostname}.pdh
  PDH EP384 D256 008cec87d6bd9df67a35e7d6057a933463cd8a02440f60c5df150821b5662ee0
   ⬑ PEK EP384 E256 431ba88424378200d58b6fb5db9657268c599b1be25f8047ac2e2981eff667e6
     •⬑ OCA EP384 E256 b4f1d0a2144186d1aa9c63f19039834e729f508000aa05a76ba044f8e1419765
      ⬑ CEK EP384 E256 22c27ee3c1c33287db24d3c06869a5ae933eb44148fdb70838019e267077c6b8
         ⬑ ASK R4096 R384 d8cd9d1798c311c96e009a91552f17b4ddc4886a064ec933697734965b9ab29db803c79604e2725658f0861bfaf09ad4
           •⬑ ARK R4096 R384 3d2c1157c29ef7bd4207fc0c8b08db080e579ceba267f8c93bec8dce73f5a5e2e60d959ac37ea82176c1a0c61ae203ed

   • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs

Assuming this is successful, it is now possible to generate a unique launch
data for the guest boot attempt::

  $ sevctl session --name ${myvmname} ${hostname}.pdh ${policy}

This will generate four files

 * ``${myvmname}_tik.bin``
 * ``${myvmname}_tek.bin``
 * ``${myvmname}_godh.bin``
 * ``${myvmname}_session.bin``

The ``tik.bin`` and ``tek.bin`` files will be needed to perform the boot
attestation, and must be kept somewhere secure, away from the hypervisor
host.

The ``godh.bin`` file contents should be copied into the ``<dhCert>`` field
in the ``<launchSecurity>`` configuration, while the ``session.bin`` file
contents should be copied into the ``<session>`` field.

When launching the guest, it should be set to remain in the paused state with
no vCPUs running::

  $ virsh start --paused ${myvmname}

With it launched, it is possible to query the launch measurement::

  $ virsh domlaunchsecinfo ${myvmname}
  sev-measurement: LMnv8i8N2QejezMPkscShF0cyPYCslgUoCxGWRqQuyt0Q0aUjVkH/T6NcmkwZkWp
  sev-api-major  : 0
  sev-api-minor  : 24
  sev-build-id   : 15
  sev-policy     : 3

The techniques required to validate the measurement reported are beyond the
scope of this document. Fortunately, libvirt provides a tool that can be used
to perform this validation::

  $ virt-qemu-sev-validate \
      --measurement LMnv8i8N2QejezMPkscShF0cyPYCslgUoCxGWRqQuyt0Q0aUjVkH/T6NcmkwZkWp \
      --api-major 0 \
      --api-minor 24 \
      --build-id 15 \
      --policy 3 \
      --firmware /path/to/OVMF.sev.fd \
      --tik ${myvmname}_tik.bin \
      --tek ${myvmname}_tek.bin
  OK: Looks good to me

The `man page <../manpages/virt-qemu-sev-validate.html>`__ for
``virt-qemu-sev-validate`` outlines a great many other ways to invoke this
tool.

Limitations
===========

With older kernels (kernel <5.1) the boot disk cannot not be of type
virtio-blk, instead, virtio-scsi needs to be used if virtio is desired.

If you still cannot start an SEV VM, it could be because of wrong SELinux label
on the ``/dev/sev`` device with selinux-policy <3.14.2.40 which prevents QEMU
from touching the device. This can be resolved by upgrading the package, tuning
the selinux policy rules manually to allow svirt_t to access the device (see
``audit2allow`` on how to do that) or putting SELinux into permissive mode
(discouraged).

Full domain XML examples
========================

Q35 machine
-----------

::

   <domain type='kvm'>
     <name>sev-dummy</name>
     <memory unit='KiB'>4194304</memory>
     <currentMemory unit='KiB'>4194304</currentMemory>
     <memoryBacking>
       <locked/>
     </memoryBacking>
     <vcpu placement='static'>4</vcpu>
     <os>
       <type arch='x86_64' machine='pc-q35-3.0'>hvm</type>
       <loader readonly='yes' type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE.fd</loader>
       <nvram>/var/lib/libvirt/qemu/nvram/sev-dummy_VARS.fd</nvram>
     </os>
     <features>
       <acpi/>
       <apic/>
       <vmport state='off'/>
     </features>
     <cpu mode='host-model' check='partial'>
       <model fallback='allow'/>
     </cpu>
     <clock offset='utc'>
       <timer name='rtc' tickpolicy='catchup'/>
       <timer name='pit' tickpolicy='delay'/>
       <timer name='hpet' present='no'/>
     </clock>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>destroy</on_crash>
     <pm>
       <suspend-to-mem enabled='no'/>
       <suspend-to-disk enabled='no'/>
     </pm>
     <devices>
       <emulator>/usr/bin/qemu-kvm</emulator>
       <disk type='file' device='disk'>
         <driver name='qemu' type='qcow2'/>
         <source file='/var/lib/libvirt/images/sev-dummy.qcow2'/>
         <target dev='sda' bus='scsi'/>
         <boot order='1'/>
       </disk>
       <controller type='virtio-serial' index='0'>
         <driver iommu='on'/>
       </controller>
       <controller type='scsi' index='0' model='virtio-scsi'>
         <driver iommu='on'/>
       </controller>
       <interface type='network'>
         <mac address='52:54:00:cc:56:90'/>
         <source network='default'/>
         <model type='virtio'/>
         <driver iommu='on'/>
         <rom enabled='no'/>
       </interface>
       <graphics type='spice' autoport='yes'>
         <listen type='address'/>
         <gl enable='no'/>
       </graphics>
       <video>
         <model type='qxl'/>
       </video>
       <memballoon model='virtio'>
         <driver iommu='on'/>
       </memballoon>
       <rng model='virtio'>
         <driver iommu='on'/>
       </rng>
     </devices>
     <launchSecurity type='sev'>
       <cbitpos>47</cbitpos>
       <reducedPhysBits>1</reducedPhysBits>
       <policy>0x0003</policy>
     </launchSecurity>
   </domain>

PC-i440fx machine
-----------------

::

   <domain type='kvm'>
     <name>sev-dummy-legacy</name>
     <memory unit='KiB'>4194304</memory>
     <currentMemory unit='KiB'>4194304</currentMemory>
     <memtune>
       <hard_limit unit='KiB'>5242880</hard_limit>
     </memtune>
     <vcpu placement='static'>4</vcpu>
     <os>
       <type arch='x86_64' machine='pc-i440fx-3.0'>hvm</type>
       <loader readonly='yes' type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE.fd</loader>
       <nvram>/var/lib/libvirt/qemu/nvram/sev-dummy_VARS.fd</nvram>
       <boot dev='hd'/>
     </os>
     <features>
     <acpi/>
     <apic/>
     <vmport state='off'/>
     </features>
     <cpu mode='host-model' check='partial'>
       <model fallback='allow'/>
     </cpu>
     <clock offset='utc'>
       <timer name='rtc' tickpolicy='catchup'/>
       <timer name='pit' tickpolicy='delay'/>
       <timer name='hpet' present='no'/>
     </clock>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>destroy</on_crash>
     <pm>
       <suspend-to-mem enabled='no'/>
       <suspend-to-disk enabled='no'/>
     </pm>
     <devices>
       <emulator>/usr/bin/qemu-kvm</emulator>
       <disk type='file' device='disk'>
         <driver name='qemu' type='qcow2'/>
         <source file='/var/lib/libvirt/images/sev-dummy-seabios.qcow2'/>
         <target dev='sda' bus='sata'/>
       </disk>
       <interface type='network'>
         <mac address='52:54:00:d8:96:c8'/>
         <source network='default'/>
         <model type='virtio-non-transitional'/>
         <driver iommu='on'/>
         <rom enabled='no'/>
       </interface>
       <serial type='pty'>
         <target type='isa-serial' port='0'>
           <model name='isa-serial'/>
         </target>
       </serial>
       <console type='pty'>
         <target type='serial' port='0'/>
       </console>
       <input type='tablet' bus='usb'>
         <address type='usb' bus='0' port='1'/>
       </input>
       <input type='mouse' bus='ps2'/>
       <input type='keyboard' bus='ps2'/>
       <graphics type='spice' autoport='yes'>
         <listen type='address'/>
         <gl enable='no'/>
       </graphics>
       <video>
         <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
       </video>
       <memballoon model='virtio-non-transitional'>
         <driver iommu='on'/>
       </memballoon>
         <rng model='virtio-non-transitional'>
       <driver iommu='on'/>
       </rng>
     </devices>
     <launchSecurity type='sev'>
       <cbitpos>47</cbitpos>
       <reducedPhysBits>1</reducedPhysBits>
       <policy>0x0003</policy>
     </launchSecurity>
   </domain>
