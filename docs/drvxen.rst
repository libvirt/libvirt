.. role:: since

===============================
libxl hypervisor driver for Xen
===============================

.. contents::

The libvirt libxl driver provides the ability to manage virtual machines on any
Xen release from 4.6.0 onwards.

Project Links
-------------

-  The `Xen <https://www.xenproject.org>`__ hypervisor on Linux and Solaris
   hosts

Deployment pre-requisites
-------------------------

The libvirt libxl driver uses Xen's libxl API, also known as libxenlight, to
implement libvirt's hypervisor driver functionality. libxl provides a
consolidated interface for managing a Xen host and its virtual machines, unlike
old versions of Xen where applications often had to communicate with xend,
xenstored, and the hypervisor itself via hypercalls. With libxl the only
pre-requisit is a properly installed Xen host with the libxl toolstack running
in a service domain (often Domain-0).

Connections to libxl driver
---------------------------

The libvirt libxl driver is a single-instance privileged driver, with a driver
name of 'xen'. Some example connection URIs for the libxl driver are:

::

   xen:///system                     (local access, direct)
   xen+unix:///system                (local access, via daemon)
   xen://example.com/system          (remote access, TLS/x509)
   xen+tcp://example.com/system      (remote access, SASl/Kerberos)
   xen+ssh://root@example.com/system (remote access, SSH tunnelled)

Location of configuration files
-------------------------------

The libxl driver comes with sane default values. However, during its
initialization it reads a configuration file which offers system administrator
to override some of that default. The file is located under
``/etc/libvirt/libxl.conf``

Import and export of libvirt domain XML configs
-----------------------------------------------

The libxl driver currently supports three native config formats. The first,
known as ``xen-xm``, is the original Xen virtual machine config format used by
the legacy xm/xend toolstack. The second, known as ``xen-sxpr``, is also one of
the original formats that was used by xend's legacy HTTP RPC service (
:since:`removed in 5.6.0` )

The third format is ``xen-xl``, which is the virtual machine config format
supported by modern Xen. The ``xen-xl`` format is described in the xl.cfg(5) man
page.

Converting from XM config files to domain XML
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh domxml-from-native`` provides a way to convert an existing set of
xl, xm, or sxpr config files to libvirt Domain XML, which can then be used by
libvirt.

::

   $ virsh -c xen:///system domxml-from-native xen-xm rhel5.cfg
   <domain type='xen'>
     <name>rhel5pv</name>
     <uuid>8f07fe28-753f-2729-d76d-bdbd892f949a</uuid>
     <memory>2560000</memory>
     <currentMemory>307200</currentMemory>
     <vcpu>4</vcpu>
     <bootloader>/usr/bin/pygrub</bootloader>
     <os>
       <type arch='x86_64' machine='xenpv'>linux</type>
     </os>
     <clock offset='utc'/>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>restart</on_crash>
     <devices>
       <disk type='file' device='disk'>
         <driver name='tap' type='aio'/>
         <source file='/var/lib/xen/images/rhel5pv.img'/>
         <target dev='xvda' bus='xen'/>
       </disk>
       <disk type='file' device='disk'>
         <driver name='tap' type='qcow'/>
         <source file='/root/qcow1-xen.img'/>
         <target dev='xvdd' bus='xen'/>
       </disk>
       <interface type='bridge'>
         <mac address='00:16:3e:60:36:ba'/>
         <source bridge='xenbr0'/>
       </interface>
       <console type='pty'>
         <target port='0'/>
       </console>
       <input type='mouse' bus='xen'/>
       <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'/>
     </devices>
   </domain>

Converting from domain XML to XM config files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh domxml-to-native`` provides a way to convert a guest description
using libvirt Domain XML into xl, xm, or sxpr config format.

::

   $ virsh -c xen:///system domxml-to-native xen-xm rhel5pv.xml
   name = "rhel5pv"
   uuid = "8f07fe28-753f-2729-d76d-bdbd892f949a"
   maxmem = 2500
   memory = 300
   vcpus = 4
   bootloader = "/usr/bin/pygrub"
   kernel = "/var/lib/xen/boot_kernel.0YK-cS"
   ramdisk = "/var/lib/xen/boot_ramdisk.vWgrxK"
   extra = "ro root=/dev/VolGroup00/LogVol00 rhgb quiet"
   on_poweroff = "destroy"
   on_reboot = "restart"
   on_crash = "restart"
   sdl = 0
   vnc = 1
   vncunused = 1
   vnclisten = "0.0.0.0"
   disk = [ "tap:aio:/var/lib/xen/images/rhel5pv.img,xvda,w", "tap:qcow:/root/qcow1-xen.img,xvdd,w" ]
   vif = [ "mac=00:16:3e:60:36:ba,bridge=virbr0,script=vif-bridge,vifname=vif5.0" ]

Pass-through of arbitrary command-line arguments to the qemu device model
-------------------------------------------------------------------------

:since:`Since 6.7.0` , the Xen driver supports passing arbitrary command-line
arguments to the qemu device model used by Xen with the ``<xen:commandline>``
element under ``domain``. In order to use command-line pass-through, an XML
namespace request must be issued that pulls in
``http://libvirt.org/schemas/domain/xen/1.0``. With the namespace in place, it
is then possible to add ``<xen:arg>``\ sub-elements to ``<xen:commandline>``
describing each argument passed to the device model when starting the domain.

The following example illustrates passing arguments to the QEMU device model
that define a floppy drive, which Xen does not support through its public APIs:

::

   <domain type="xen" xmlns:xen="http://libvirt.org/schemas/domain/xen/1.0">
     ...
     <xen:commandline>
       <xen:arg value='-drive'/>
       <xen:arg value='file=/path/to/image,format=raw,if=none,id=drive-fdc0-0-0'/>
       <xen:arg value='-global'/>
       <xen:arg value='isa-fdc.driveA=drive-fdc0-0-0'/>
     </xen:commandline>
   </domain>

Example domain XML config
-------------------------

Below are some example XML configurations for Xen guest domains. For full
details of the available options, consult the `domain XML
format <formatdomain.html>`__ guide.

Paravirtualized guest bootloader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using a bootloader allows a paravirtualized guest to be booted using a kernel
stored inside its virtual disk image

::

   <domain type='xen' >
     <name>fc8</name>
     <bootloader>/usr/bin/pygrub</bootloader>
     <os>
       <type>linux</type>
     </os>
     <memory>131072</memory>
     <vcpu>1</vcpu>
     <devices>
       <disk type='file'>
         <source file='/var/lib/xen/images/fc4.img'/>
         <target dev='sda1'/>
       </disk>
       <interface type='bridge'>
         <source bridge='xenbr0'/>
         <mac address='aa:00:00:00:00:11'/>
         <script path='/etc/xen/scripts/vif-bridge'/>
       </interface>
       <console tty='/dev/pts/5'/>
     </devices>
   </domain>

Paravirtualized guest direct kernel boot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For installation of paravirtualized guests it is typical to boot the domain
using a kernel and initrd stored in the host OS

::

   <domain type='xen' >
     <name>fc8</name>
     <os>
       <type>linux</type>
       <kernel>/var/lib/xen/install/vmlinuz-fedora8-x86_64</kernel>
       <initrd>/var/lib/xen/install/initrd-vmlinuz-fedora8-x86_64</initrd>
       <cmdline> kickstart=http://example.com/myguest.ks </cmdline>
     </os>
     <memory>131072</memory>
     <vcpu>1</vcpu>
     <devices>
       <disk type='file'>
         <source file='/var/lib/xen/images/fc4.img'/>
         <target dev='sda1'/>
       </disk>
       <interface type='bridge'>
         <source bridge='xenbr0'/>
         <mac address='aa:00:00:00:00:11'/>
         <script path='/etc/xen/scripts/vif-bridge'/>
       </interface>
       <graphics type='vnc' port='-1'/>
       <console tty='/dev/pts/5'/>
     </devices>
   </domain>

Fullyvirtualized guest BIOS boot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fullyvirtualized guests use the emulated BIOS to boot off the primary harddisk,
CDROM or Network PXE ROM.

::

   <domain type='xen' id='3'>
     <name>fv0</name>
     <uuid>4dea22b31d52d8f32516782e98ab3fa0</uuid>
     <os>
       <type>hvm</type>
       <loader>/usr/lib/xen/boot/hvmloader</loader>
       <boot dev='hd'/>
     </os>
     <memory>524288</memory>
     <vcpu>1</vcpu>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>restart</on_crash>
     <features>
       <pae/>
       <acpi/>
       <apic/>
     </features>
     <clock sync="localtime"/>
     <devices>
       <emulator>/usr/lib/xen/bin/qemu-dm</emulator>
       <interface type='bridge'>
         <source bridge='xenbr0'/>
         <mac address='00:16:3e:5d:c7:9e'/>
         <script path='vif-bridge'/>
       </interface>
       <disk type='file'>
         <source file='/var/lib/xen/images/fv0'/>
         <target dev='hda'/>
       </disk>
       <disk type='file' device='cdrom'>
         <source file='/var/lib/xen/images/fc5-x86_64-boot.iso'/>
         <target dev='hdc'/>
         <readonly/>
       </disk>
       <disk type='file' device='floppy'>
         <source file='/root/fd.img'/>
         <target dev='fda'/>
       </disk>
       <graphics type='vnc' port='5904'/>
     </devices>
   </domain>

Fullyvirtualized guest direct kernel boot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With Xen 3.2.0 or later it is possible to bypass the BIOS and directly boot a
Linux kernel and initrd as a fullyvirtualized domain. This allows for complete
automation of OS installation, for example using the Anaconda kickstart support.

::

   <domain type='xen' id='3'>
     <name>fv0</name>
     <uuid>4dea22b31d52d8f32516782e98ab3fa0</uuid>
     <os>
       <type>hvm</type>
       <loader>/usr/lib/xen/boot/hvmloader</loader>
       <kernel>/var/lib/xen/install/vmlinuz-fedora8-x86_64</kernel>
       <initrd>/var/lib/xen/install/initrd-vmlinuz-fedora8-x86_64</initrd>
       <cmdline> kickstart=http://example.com/myguest.ks </cmdline>
     </os>
     <memory>524288</memory>
     <vcpu>1</vcpu>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>restart</on_crash>
     <features>
       <pae/>
       <acpi/>
       <apic/>
     </features>
     <clock sync="localtime"/>
     <devices>
       <emulator>/usr/lib/xen/bin/qemu-dm</emulator>
       <interface type='bridge'>
         <source bridge='xenbr0'/>
         <mac address='00:16:3e:5d:c7:9e'/>
         <script path='vif-bridge'/>
       </interface>
       <disk type='file'>
         <source file='/var/lib/xen/images/fv0'/>
         <target dev='hda'/>
       </disk>
       <disk type='file' device='cdrom'>
         <source file='/var/lib/xen/images/fc5-x86_64-boot.iso'/>
         <target dev='hdc'/>
         <readonly/>
       </disk>
       <disk type='file' device='floppy'>
         <source file='/root/fd.img'/>
         <target dev='fda'/>
       </disk>
       <graphics type='vnc' port='5904'/>
     </devices>
   </domain>
