================
Virtuozzo driver
================

The libvirt vz driver can manage Virtuozzo starting from version 6.0.

Project Links
-------------

-  The `Virtuozzo <https://www.virtuozzo.com/>`__ Solution.

Connections to the Virtuozzo driver
-----------------------------------

The libvirt Virtuozzo driver is a single-instance privileged driver, with a
driver name of 'virtuozzo'. Some example connection URIs for the libvirt driver
are:

::

   vz:///system                     (local access)
   vz+unix:///system                (local access)
   vz://example.com/system          (remote access, TLS/x509)
   vz+tcp://example.com/system      (remote access, SASl/Kerberos)
   vz+ssh://root@example.com/system (remote access, SSH tunnelled)

Example guest domain XML configuration
--------------------------------------

Virtuozzo driver require at least one hard disk for new domains at this time. It
is used for defining directory, where VM should be created.

::

   <domain type='vz'>
     <name>demo</name>
     <uuid>54cdecad-4492-4e31-a209-33cc21d64057</uuid>
     <description>some description</description>
     <memory unit='KiB'>1048576</memory>
     <currentMemory unit='KiB'>1048576</currentMemory>
     <vcpu placement='static'>2</vcpu>
     <os>
       <type arch='x86_64'>hvm</type>
     </os>
     <clock offset='utc'/>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>destroy</on_reboot>
     <on_crash>destroy</on_crash>
     <devices>
       <disk type='file' device='disk'>
         <source file='/storage/vol1'/>
         <target dev='hda'/>
       </disk>
       <video>
         <model type='vga' vram='33554432' heads='1'>
           <acceleration accel3d='no' accel2d='no'/>
         </model>
       </video>
     </devices>
   </domain>
