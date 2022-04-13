.. role:: since

============
Bhyve driver
============

.. contents::

Bhyve is a FreeBSD hypervisor. It first appeared in FreeBSD 10.0. However, it's
recommended to keep tracking FreeBSD 10-STABLE to make sure all new features of
bhyve are supported. In order to enable bhyve on your FreeBSD host, you'll need
to load the ``vmm`` kernel module. Additionally, ``if_tap`` and ``if_bridge``
modules should be loaded for networking support. Also, :since:`since 3.2.0` the
``virt-host-validate(1)`` supports the bhyve host validation and could be used
like this:

::

   $ virt-host-validate bhyve
    BHYVE: Checking for vmm module                                              : PASS
    BHYVE: Checking for if_tap module                                           : PASS
    BHYVE: Checking for if_bridge module                                        : PASS
    BHYVE: Checking for nmdm module                                             : PASS
   $

Additional information on bhyve could be obtained on
`bhyve.org <https://bhyve.org/>`__.

Connections to the Bhyve driver
-------------------------------

The libvirt bhyve driver is a single-instance privileged driver. Some sample
connection URIs are:

::

   bhyve:///system                     (local access)
   bhyve+unix:///system                (local access)
   bhyve+ssh://root@example.com/system (remote access, SSH tunnelled)

Example guest domain XML configurations
---------------------------------------

Example config
~~~~~~~~~~~~~~

The bhyve driver in libvirt is in its early stage and under active development.
So it supports only limited number of features bhyve provides.

Note: in older libvirt versions, only a single network device and a single disk
device were supported per-domain. However, :since:`since 1.2.6` the libvirt
bhyve driver supports up to 31 PCI devices.

Note: the Bhyve driver in libvirt will boot whichever device is first. If you
want to install from CD, put the CD device first. If not, put the root HDD
first.

Note: Only the SATA bus is supported. Only ``cdrom``- and ``disk``-type disks
are supported.

::

   <domain type='bhyve'>
       <name>bhyve</name>
       <uuid>df3be7e7-a104-11e3-aeb0-50e5492bd3dc</uuid>
       <memory>219136</memory>
       <currentMemory>219136</currentMemory>
       <vcpu>1</vcpu>
       <os>
          <type>hvm</type>
       </os>
       <features>
         <apic/>
         <acpi/>
       </features>
       <clock offset='utc'/>
       <on_poweroff>destroy</on_poweroff>
       <on_reboot>restart</on_reboot>
       <on_crash>destroy</on_crash>
       <devices>
         <disk type='file'>
           <driver name='file' type='raw'/>
           <source file='/path/to/bhyve_freebsd.img'/>
           <target dev='hda' bus='sata'/>
         </disk>
         <disk type='file' device='cdrom'>
           <driver name='file' type='raw'/>
           <source file='/path/to/cdrom.iso'/>
           <target dev='hdc' bus='sata'/>
           <readonly/>
         </disk>
         <interface type='bridge'>
           <model type='virtio'/>
           <source bridge="virbr0"/>
         </interface>
       </devices>
   </domain>

(The <disk> sections may be swapped in order to install from *cdrom.iso*.)

Example config (Linux guest)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note the addition of <bootloader>.

::

   <domain type='bhyve'>
       <name>linux_guest</name>
       <uuid>df3be7e7-a104-11e3-aeb0-50e5492bd3dc</uuid>
       <memory>131072</memory>
       <currentMemory>131072</currentMemory>
       <vcpu>1</vcpu>
       <bootloader>/usr/local/sbin/grub-bhyve</bootloader>
       <os>
          <type>hvm</type>
       </os>
       <features>
         <apic/>
         <acpi/>
       </features>
       <clock offset='utc'/>
       <on_poweroff>destroy</on_poweroff>
       <on_reboot>restart</on_reboot>
       <on_crash>destroy</on_crash>
       <devices>
         <disk type='file' device='disk'>
           <driver name='file' type='raw'/>
           <source file='/path/to/guest_hdd.img'/>
           <target dev='hda' bus='sata'/>
         </disk>
         <disk type='file' device='cdrom'>
           <driver name='file' type='raw'/>
           <source file='/path/to/cdrom.iso'/>
           <target dev='hdc' bus='sata'/>
           <readonly/>
         </disk>
         <interface type='bridge'>
           <model type='virtio'/>
           <source bridge="virbr0"/>
         </interface>
       </devices>
   </domain>

Example config (Linux UEFI guest, VNC, tablet)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is an example to boot into Fedora 25 installation:

::

   <domain type='bhyve'>
       <name>fedora_uefi_vnc_tablet</name>
       <memory unit='G'>4</memory>
       <vcpu>2</vcpu>
       <os>
          <type>hvm</type>
          <loader readonly="yes" type="pflash">/usr/local/share/uefi-firmware/BHYVE_UEFI.fd</loader>
       </os>
       <features>
         <apic/>
         <acpi/>
       </features>
       <clock offset='utc'/>
       <on_poweroff>destroy</on_poweroff>
       <on_reboot>restart</on_reboot>
       <on_crash>destroy</on_crash>
       <devices>
         <disk type='file' device='cdrom'>
           <driver name='file' type='raw'/>
             <source file='/path/to/Fedora-Workstation-Live-x86_64-25-1.3.iso'/>
           <target dev='hdc' bus='sata'/>
           <readonly/>
         </disk>
         <disk type='file' device='disk'>
           <driver name='file' type='raw'/>
           <source file='/path/to/linux_uefi.img'/>
           <target dev='hda' bus='sata'/>
           </disk>
         <interface type='bridge'>
           <model type='virtio'/>
           <source bridge="virbr0"/>
         </interface>
         <serial type="nmdm">
           <source master="/dev/nmdm0A" slave="/dev/nmdm0B"/>
         </serial>
         <graphics type='vnc' port='5904'>
           <listen type='address' address='127.0.0.1'/>
         </graphics>
         <controller type='usb' model='nec-xhci'/>
         <input type='tablet' bus='usb'/>
       </devices>
   </domain>

Please refer to the `Using UEFI bootrom, VNC, and USB tablet`_ section for a
more detailed explanation.

Guest usage / management
------------------------

Connecting to a guest console
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Guest console connection is supported through the ``nmdm`` device. It could be
enabled by adding the following to the domain XML ( :since:`Since 1.2.4` ):

::

   ...
   <devices>
     <serial type="nmdm">
       <source master="/dev/nmdm0A" slave="/dev/nmdm0B"/>
     </serial>
   </devices>
   ...

Make sure to load the ``nmdm`` kernel module if you plan to use that.

Then ``virsh console`` command can be used to connect to the text console of a
guest.

**NB:** Some versions of bhyve have a bug that prevents guests from booting
until the console is opened by a client. This bug was fixed in `FreeBSD
changeset r262884 <https://svnweb.freebsd.org/changeset/base/262884>`__. If an
older version is used, one either has to open a console manually with
``virsh console`` to let a guest boot or start a guest using:

::

   start --console domname

**NB:** A bootloader configured to require user interaction will prevent the
domain from starting (and thus ``virsh console`` or ``start --console`` from
functioning) until the user interacts with it manually on the VM host. Because
users typically do not have access to the VM host, interactive bootloaders are
unsupported by libvirt. *However,* if you happen to run into this scenario and
also happen to have access to the Bhyve host machine, you may select a boot
option and allow the domain to finish starting by using an alternative terminal
client on the VM host to connect to the domain-configured null modem device. One
example (assuming ``/dev/nmdm0B`` is configured as the slave end of the domain
serial device) is:

::

   cu -l /dev/nmdm0B

Converting from domain XML to Bhyve args
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh domxml-to-native`` command can preview the actual ``bhyve`` commands
that will be executed for a given domain. It outputs two lines, the first line
is a ``bhyveload`` command and the second is a ``bhyve`` command.

Please note that the ``virsh domxml-to-native`` doesn't do any real actions
other than printing the command, for example, it doesn't try to find a proper
TAP interface and create it, like what is done when starting a domain; and
always returns ``tap0`` for the network interface. So if you're going to run
these commands manually, most likely you might want to tweak them.

::

   # virsh -c "bhyve:///system"  domxml-to-native --format bhyve-argv --xml /path/to/bhyve.xml
   /usr/sbin/bhyveload -m 214 -d /home/user/vm1.img vm1
   /usr/sbin/bhyve -c 2 -m 214 -A -I -H -P -s 0:0,hostbridge \
       -s 3:0,virtio-net,tap0,mac=52:54:00:5d:74:e3 -s 2:0,virtio-blk,/home/user/vm1.img \
       -s 1,lpc -l com1,/dev/nmdm0A vm1

Using ZFS volumes
~~~~~~~~~~~~~~~~~

It's possible to use ZFS volumes as disk devices :since:`since 1.2.8` . An
example of domain XML device entry for that will look like:

::

   ...
   <disk type='volume' device='disk'>
     <source pool='zfspool' volume='vol1'/>
     <target dev='vdb' bus='virtio'/>
   </disk>
   ...

Please refer to the `Storage documentation <storage.html>`__ for more details on
storage management.

Using grub2-bhyve or Alternative Bootloaders
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's possible to boot non-FreeBSD guests by specifying an explicit bootloader,
e.g. ``grub-bhyve(1)``. Arguments to the bootloader may be specified as well. If
the bootloader is ``grub-bhyve`` and arguments are omitted, libvirt will try and
infer boot ordering from user-supplied <boot order='N'> configuration in the
domain. Failing that, it will boot the first disk in the domain (either
``cdrom``- or ``disk``-type devices). If the disk type is ``disk``, it will
attempt to boot from the first partition in the disk image.

::

   ...
   <bootloader>/usr/local/sbin/grub-bhyve</bootloader>
   <bootloader_args>...</bootloader_args>
   ...

Caveat: ``bootloader_args`` does not support any quoting. Filenames, etc, must
not have spaces or they will be tokenized incorrectly.

Using UEFI bootrom, VNC, and USB tablet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:since:`Since 3.2.0` , in addition to
`Using grub2-bhyve or Alternative Bootloaders`_, non-FreeBSD
guests could be also booted using an UEFI boot ROM, provided both guest OS and
installed ``bhyve(1)`` version support UEFI. To use that, ``loader`` should be
specified in the ``os`` section:

::

   <domain type='bhyve'>
       ...
       <os>
          <type>hvm</type>
          <loader readonly="yes" type="pflash">/usr/local/share/uefi-firmware/BHYVE_UEFI.fd</loader>
       </os>
       ...

This uses the UEFI firmware provided by the
`sysutils/bhyve-firmware <https://www.freshports.org/sysutils/bhyve-firmware/>`__
FreeBSD port.

VNC and the tablet input device could be configured this way:

::

   <domain type='bhyve'>
       <devices>
         ...
         <graphics type='vnc' port='5904'>
           <listen type='address' address='127.0.0.1'/>
         </graphics>
         <controller type='usb' model='nec-xhci'/>
         <input type='tablet' bus='usb'/>
       </devices>
       ...
   </domain>

This way, VNC will be accessible on ``127.0.0.1:5904``.

Please note that the tablet device requires to have a USB controller of the
``nec-xhci`` model. Currently, only a single controller of this type and a
single tablet are supported per domain.

:since:`Since 3.5.0` , it's possible to configure how the video device is
exposed to the guest using the ``vgaconf`` attribute:

::

   <domain type='bhyve'>
       <devices>
       ...
         <graphics type='vnc' port='5904'>
           <listen type='address' address='127.0.0.1'/>
         </graphics>
         <video>
           <driver vgaconf='on'/>
           <model type='gop' heads='1' primary='yes'/>
         </video>
         ...
       </devices>
       ...
   </domain>

If not specified, bhyve's default mode for ``vgaconf`` will be used. Please
refer to the
`bhyve(8) <https://www.freebsd.org/cgi/man.cgi?query=bhyve&sektion=8&manpath=FreeBSD+12-current>`__
manual page and the `bhyve wiki <https://wiki.freebsd.org/bhyve>`__ for more
details on using the ``vgaconf`` option.

:since:`Since 3.7.0` , it's possible to use ``autoport`` to let libvirt allocate
VNC port automatically (instead of explicitly specifying it with the ``port``
attribute):

::

       <graphics type='vnc' autoport='yes'>

:since:`Since 6.8.0` , it's possible to set framebuffer resolution using the
``resolution`` sub-element:

::

      <video>
        <model type='gop' heads='1' primary='yes'>
          <resolution x='800' y='600'/>
        </model>
      </video>

:since:`Since 6.8.0` , VNC server can be configured to use password based
authentication:

::

     <graphics type='vnc' port='5904' passwd='foobar'>
       <listen type='address' address='127.0.0.1'/>
     </graphics>

Note: VNC password authentication is known to be cryptographically weak.
Additionally, the password is passed as a command line argument in clear text.
Make sure you understand the risks associated with this feature before using it.

Clock configuration
~~~~~~~~~~~~~~~~~~~

Originally bhyve supported only localtime for RTC. Support for UTC time was
introduced in `FreeBSD changeset
r284894 <https://svnweb.freebsd.org/changeset/base/284894>`__ for *10-STABLE*
and in `changeset r279225 <https://svnweb.freebsd.org/changeset/base/279225>`__
for *-CURRENT*. It's possible to use this in libvirt :since:`since 1.2.18` ,
just place the following to domain XML:

::

   <domain type="bhyve">
       ...
       <clock offset='utc'/>
       ...
   </domain>

Please note that if you run the older bhyve version that doesn't support UTC
time, you'll fail to start a domain. As UTC is used as a default when you do not
specify clock settings, you'll need to explicitly specify 'localtime' in this
case:

::

   <domain type="bhyve">
       ...
       <clock offset='localtime'/>
       ...
   </domain>

e1000 NIC
~~~~~~~~~

As of `FreeBSD changeset
r302504 <https://svnweb.freebsd.org/changeset/base/302504>`__ bhyve supports
Intel e1000 network adapter emulation. It's supported in libvirt :since:`since
3.1.0` and could be used as follows:

::

   ...
       <interface type='bridge'>
         <source bridge='virbr0'/>
         <model type='e1000'/>
       </interface>
   ...

Sound device
~~~~~~~~~~~~

As of `FreeBSD changeset
r349355 <https://svnweb.freebsd.org/changeset/base/349355>`__ bhyve supports
sound device emulation. It's supported in libvirt :since:`since 6.7.0` .

::

   ...
     <sound model='ich7'>
       <audio id='1'/>
     </sound>
     <audio id='1' type='oss'>
       <input dev='/dev/dsp0'/>
       <output dev='/dev/dsp0'/>
     </audio>
   ...

Here, the ``sound`` element specifies the sound device as it's exposed to the
guest, with ``ich7`` being the only supported model now, and the ``audio``
element specifies how the guest device is mapped to the host sound device.

Virtio-9p filesystem
~~~~~~~~~~~~~~~~~~~~

As of `FreeBSD changeset
r366413 <https://svnweb.freebsd.org/changeset/base/366413>`__ bhyve supports
sharing arbitrary directory tree between the guest and the host. It's supported
in libvirt :since:`since 6.9.0` .

::

   ...
     <filesystem>
       <source dir='/shared/dir'/>
       <target dir='shared_dir'/>
     </filesystem>
   ...

This share could be made read only by adding the ``<readonly/>`` sub-element.

In the Linux guest, this could be mounted using:

::

   mount -t 9p shared_dir /mnt/shared_dir

Wiring guest memory
~~~~~~~~~~~~~~~~~~~

:since:`Since 4.4.0` , it's possible to specify that guest memory should be
wired and cannot be swapped out as follows:

::

   <domain type="bhyve">
       ...
       <memoryBacking>
         <locked/>
       </memoryBacking>
       ...
   </domain>

CPU topology
~~~~~~~~~~~~

:since:`Since 4.5.0` , it's possible to specify guest CPU topology, if bhyve
supports that. Support for specifying guest CPU topology was added to bhyve in
`FreeBSD changeset r332298 <https://svnweb.freebsd.org/changeset/base/332298>`__
for *-CURRENT*. Example:

::

   <domain type="bhyve">
       ...
       <cpu>
         <topology sockets='1' cores='2' threads='1'/>
       </cpu>
       ...
   </domain>

Ignoring unknown MSRs reads and writes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:since:`Since 5.1.0` , it's possible to make bhyve ignore accesses to
unimplemented Model Specific Registers (MSRs). Example:

::

   <domain type="bhyve">
       ...
       <features>
         ...
         <msrs unknown='ignore'/>
         ...
       </features>
       ...
   </domain>

Pass-through of arbitrary bhyve commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:since:`Since 5.1.0` , it's possible to pass additional command-line arguments
to the bhyve process when starting the domain using the ``<bhyve:commandline>``
element under ``domain``. To supply an argument, use the element ``<bhyve:arg>``
with the attribute ``value`` set to additional argument to be added. The arg
element may be repeated multiple times. To use this XML addition, it is
necessary to issue an XML namespace request (the special ``xmlns:name``
attribute) that pulls in ``http://libvirt.org/schemas/domain/bhyve/1.0``;
typically, the namespace is given the name of ``bhyve``.

Example:

::

   <domain type="bhyve" xmlns:bhyve="http://libvirt.org/schemas/domain/bhyve/1.0">
     ...
     <bhyve:commandline>
       <bhyve:arg value='-somebhyvearg'/>
     </bhyve:commandline>
   </domain>

Note that these extensions are for testing and development purposes only. They
are **unsupported**, using them may result in inconsistent state, and upgrading
either bhyve or libvirtd maybe break behavior of a domain that was relying on a
specific commands pass-through.
