.. role:: since

============================
VirtualBox hypervisor driver
============================

The libvirt VirtualBox driver can manage any VirtualBox version from version 6.1
onwards ( :since:`since libvirt 3.0.0` ).

Project Links
-------------

-  The `VirtualBox <https://www.virtualbox.org/>`__ hypervisor

Connections to VirtualBox driver
--------------------------------

The libvirt VirtualBox driver provides per-user drivers (the "session"
instance). The uri of the driver protocol is "vbox". Some example connection
URIs for the driver are:

::

   vbox:///session                      (local access to per-user instance)
   vbox+unix:///session                 (local access to per-user instance)
   vbox+tcp://user@example.com/session  (remote access, SASl/Kerberos)
   vbox+ssh://user@example.com/session  (remote access, SSH tunnelled)

**NOTE: as of libvirt 1.0.6, the VirtualBox driver will always run inside the
libvirtd daemon, instead of being built-in to the libvirt.so library directly.
This change was required due to the fact that VirtualBox code is LGPLv2-only
licensed, which is not compatible with the libvirt.so license of
LGPLv2-or-later. The daemon will be auto-started when the first connection to
VirtualBox is requested. This change also means that it will not be possible to
use VirtualBox URIs on the Windows platform, until additional work is completed
to get the libvirtd daemon working there.**

Example domain XML config
-------------------------

::

   <domain type='vbox'>
     <name>vbox</name>
     <uuid>4dab22b31d52d8f32516782e98ab3fa0</uuid>

     <os>
       <type>hvm</type>
       <boot dev='cdrom'/>
       <boot dev='hd'/>
       <boot dev='fd'/>
       <boot dev='network'/>
     </os>

     <memory>654321</memory>
     <vcpu>1</vcpu>

     <features>
       <pae/>
       <acpi/>
       <apic/>
     </features>

     <devices>
       <!--Set IDE controller model to PIIX4 (default PIIX3)-->
       <controller type='ide' model='piix4'/>

       <controller type='scsi' index='0'/>

       <!--VirtualBox SAS Controller-->
       <controller type='scsi' index='1' model='lsisas1068'/>

       <disk type='file' device='cdrom'>
         <source file='/home/user/Downloads/slax-6.0.9.iso'/>
         <target dev='hdc'/>
         <readonly/>
       </disk>

       <disk type='file' device='disk'>
         <source file='/home/user/tmp/vbox.vdi'/>
         <target dev='hdd'/>
       </disk>

       <!--Attach to the SCSI controller (index=0, default)-->
       <disk type='file' device='disk'>
         <source file='/home/user/tmp/vbox2.vdi'/>
         <target dev='sda' bus='scsi'/>
       </disk>

       <!--Attach to the SAS controller (index=1)-->
       <disk type='file' device='disk'>
         <source file='/home/user/tmp/vbox3.vdi'/>
         <target dev='sda' bus='scsi'/>
         <address type='drive' controller='1' bus='0' target='0' unit='0'/>
       </disk>

       <disk type='file' device='floppy'>
         <source file='/home/user/tmp/WIN98C.IMG'/>
         <target dev='fda'/>
       </disk>

       <filesystem type='mount'>
         <source dir='/home/user/stuff'/>
         <target dir='my-shared-folder'/>
       </filesystem>

       <!--BRIDGE-->
       <interface type='bridge'>
         <source bridge='eth0'/>
         <mac address='00:16:3e:5d:c7:9e'/>
         <model type='am79c973'/>
       </interface>

       <!--NAT-->
       <interface type='user'>
         <mac address='56:16:3e:5d:c7:9e'/>
         <model type='82540eM'/>
       </interface>

       <graphics type='desktop'/>

       <!--Activate the VRDE server with a port in 3389-3689 range-->
       <graphics type='rdp' autoport='yes' multiUser='yes'/>

       <sound model='sb16'/>

       <parallel type='dev'>
         <source path='/dev/pts/1'/>
         <target port='0'/>
       </parallel>

       <parallel type='dev'>
         <source path='/dev/pts/2'/>
         <target port='1'/>
       </parallel>

       <serial type="dev">
         <source path="/dev/ttyS0"/>
         <target port="0"/>
       </serial>

       <serial type="pipe">
         <source path="/tmp/serial.txt"/>
         <target port="1"/>
       </serial>

       <hostdev mode='subsystem' type='usb'>
         <source>
           <vendor id='0x1234'/>
           <product id='0xbeef'/>
         </source>
       </hostdev>

       <hostdev mode='subsystem' type='usb'>
         <source>
           <vendor id='0x4321'/>
           <product id='0xfeeb'/>
         </source>
       </hostdev>
     </devices>
   </domain>
