=======================================================
VMware Workstation / Player / Fusion hypervisors driver
=======================================================

The libvirt VMware driver should be able to manage any Workstation, Player,
Fusion version supported by the VMware VIX API. See the compatibility list
`here <https://www.vmware.com/support/developer/vix-api/vix110_reference/>`__.

This driver uses the "vmrun" utility which is distributed with the VMware VIX
API. You can download the VIX API from
`here <https://www.vmware.com/support/developer/vix-api/>`__.

Project Links
-------------

-  The `VMware Workstation and Player <https://www.vmware.com/>`__ hypervisors
-  The `VMware Fusion <https://www.vmware.com/fusion>`__ hypervisor

Connections to VMware driver
----------------------------

The libvirt VMware driver provides per-user drivers (the "session" instance).
Three uris are available:

-  "vmwareplayer" for VMware Player
-  "vmwarews" for VMware Workstation
-  "vmwarefusion" for VMware Fusion

Some example connection URIs for the driver are:

::

   vmwareplayer:///session                  (local access to VMware Player per-user instance)
   vmwarews:///session                      (local access to VMware Workstation per-user instance)
   vmwarefusion:///session                  (local access to VMware Fusion per-user instance)
   vmwarews+tcp://user@example.com/session  (remote access to VMware Workstation, SASl/Kerberos)
   vmwarews+ssh://user@example.com/session  (remote access to VMware Workstation, SSH tunnelled)

Example domain XML config
-------------------------

::

   <domain type='vmware'>
     <name>vmware</name>
     <uuid>bea92244-8885-4562-828b-3b086731c5b1</uuid>

     <os>
       <type>hvm</type>
     </os>

     <memory>524288</memory>
     <vcpu>1</vcpu>

     <features>
       <pae/>
       <acpi/>
     </features>

     <devices>
       <disk type='file' device='disk'>
         <source file='/home/user/tmp/disk.vmdk'/>
         <target bus='ide' dev='hda'/>
       </disk>

       <interface type='bridge'>
         <target dev='/dev/vmnet1'/>
         <source bridge=''/>
         <mac address='00:16:3e:5d:c7:9e'/>
       </interface>
     </devices>
   </domain>
