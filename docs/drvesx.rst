.. role:: since

============================
VMware ESX hypervisor driver
============================

.. contents::

The libvirt VMware ESX driver can manage VMware ESX/ESXi 3.5/4.x/5.x and VMware
GSX 2.0, also called VMware Server 2.0, and possibly later versions.
:since:`Since 0.8.3` the driver can also connect to a VMware vCenter 2.5/4.x/5.x
(VPX).

Project Links
-------------

-  The `VMware ESX and GSX <https://www.vmware.com/>`__ hypervisors

Deployment pre-requisites
-------------------------

None. Any out-of-the-box installation of VPX/ESX(i)/GSX should work. No
preparations are required on the server side, no libvirtd must be installed on
the ESX server. The driver uses version 2.5 of the remote, SOAP based `VMware
Virtual Infrastructure
API <https://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/>`__
(VI API) to communicate with the ESX server, like the VMware Virtual
Infrastructure Client (VI client) does. Since version 4.0 this API is called
`VMware vSphere
API <https://www.vmware.com/support/developer/vc-sdk/visdk400pubs/ReferenceGuide/>`__.

Connections to the VMware ESX driver
------------------------------------

Some example remote connection URIs for the driver are:

::

   vpx://example-vcenter.com/dc1/srv1     (VPX over HTTPS, select ESX server 'srv1' in datacenter 'dc1')
   esx://example-esx.com                  (ESX over HTTPS)
   gsx://example-gsx.com                  (GSX over HTTPS)
   esx://example-esx.com/?transport=http  (ESX over HTTP)
   esx://example-esx.com/?no_verify=1     (ESX over HTTPS, but doesn't verify the server's SSL certificate)

**Note**: In contrast to other drivers, the ESX driver is a client-side-only
driver. It connects to the ESX server using HTTP(S). Therefore, the `remote
transport mechanism <remote.html>`__ provided by the remote driver and libvirtd
will not work, and you cannot use URIs like ``esx+ssh://example.com``.

URI Format
~~~~~~~~~~

URIs have this general form (``[...]`` marks an optional part).

::

   type://[username@]hostname[:port]/[[folder/...]datacenter/[folder/...][cluster/]server][?extraparameters]

The ``type://`` is either ``esx://`` or ``gsx://`` or ``vpx://`` :since:`since
0.8.3` . The driver selects the default port depending on the ``type://``. For
``esx://`` and ``vpx://`` the default HTTPS port is 443, for ``gsx://`` it is
8333. If the port parameter is given, it overrides the default port.

A ``vpx://`` connection is currently restricted to a single ESX server. This
might be relaxed in the future. The path part of the URI is used to specify the
datacenter and the ESX server in it. If the ESX server is part of a cluster then
the cluster has to be specified too.

An example: ESX server ``example-esx.com`` is managed by vCenter
``example-vcenter.com`` and part of cluster ``cluster1``. This cluster is part
of datacenter ``dc1``.

::

   vpx://example-vcenter.com/dc1/cluster1/example-esx.com

Datacenters and clusters can be organized in folders, those have to be specified
as well. The driver can handle folders :since:`since 0.9.7` .

::

   vpx://example-vcenter.com/folder1/dc1/folder2/example-esx.com

Extra parameters
^^^^^^^^^^^^^^^^

Extra parameters can be added to a URI as part of the query string (the part
following ``?``). A single parameter is formed by a ``name=value`` pair.
Multiple parameters are separated by ``&``.

::

   ?no_verify=1&auto_answer=1&proxy=socks://example-proxy.com:23456

The driver understands the extra parameters shown below.

+-----------------+-----------------------------+-----------------------------+
| Name            | Values                      | Meaning                     |
+=================+=============================+=============================+
| ``transport``   | ``http`` or ``https``       | Overrides the default HTTPS |
|                 |                             | transport. For ``esx://``   |
|                 |                             | and ``vpx://`` the default  |
|                 |                             | HTTP port is 80, for        |
|                 |                             | ``gsx://`` it is 8222.      |
+-----------------+-----------------------------+-----------------------------+
| ``vcenter``     | Hostname of a VMware        | In order to perform a       |
|                 | vCenter or ``*``            | migration the driver needs  |
|                 |                             | to know the VMware vCenter  |
|                 |                             | for the ESX server. If set  |
|                 |                             | to ``*``, the driver        |
|                 |                             | connects to the vCenter     |
|                 |                             | known to the ESX server.    |
|                 |                             | This parameter in useful    |
|                 |                             | when connecting to an ESX   |
|                 |                             | server only.                |
+-----------------+-----------------------------+-----------------------------+
| ``no_verify``   | ``0`` or ``1``              | If set to 1, this disables  |
|                 |                             | libcurl client checks of    |
|                 |                             | the server's SSL            |
|                 |                             | certificate. The default    |
|                 |                             | value is 0. See the         |
|                 |                             | `Certificates for HTTPS`_   |
|                 |                             | section for details.        |
+-----------------+-----------------------------+-----------------------------+
| ``auto_answer`` | ``0`` or ``1``              | If set to 1, the driver     |
|                 |                             | answers all                 |
|                 |                             | `Questions blocking tasks`_ |
|                 |                             | with the default answer. If |
|                 |                             | set to 0, questions are     |
|                 |                             | reported as errors. The     |
|                 |                             | default value is 0.         |
|                 |                             | :since:`Since 0.7.5` .      |
+-----------------+-----------------------------+-----------------------------+
| ``proxy``       | ``[type://]host[:port]``    | Allows to specify a proxy   |
|                 |                             | for HTTP and HTTPS          |
|                 |                             | communication.              |
|                 |                             | :since:`Since 0.8.2` . The  |
|                 |                             | optional ``type`` part may  |
|                 |                             | be one of: ``http``,        |
|                 |                             | ``socks``, ``socks4``,      |
|                 |                             | ``socks4a`` or ``socks5``.  |
|                 |                             | The default is ``http`` and |
|                 |                             | ``socks`` is synonymous for |
|                 |                             | ``socks5``. The optional    |
|                 |                             | ``port`` allows to override |
|                 |                             | the default port 1080.      |
+-----------------+-----------------------------+-----------------------------+

Authentication
~~~~~~~~~~~~~~

In order to perform any useful operation the driver needs to log into the ESX
server. Therefore, only ``virConnectOpenAuth`` can be used to connect to an ESX
server, ``virConnectOpen`` and ``virConnectOpenReadOnly`` don't work. To log
into an ESX server or vCenter the driver will request credentials using the
callback passed to the ``virConnectOpenAuth`` function. The driver passes the
hostname as challenge parameter to the callback. This enables the callback to
distinguish between requests for ESX server and vCenter.

**Note**: During the ongoing driver development, testing is done using an
unrestricted ``root`` account. Problems may occur if you use a restricted
account. Detailed testing with restricted accounts has not been done yet.

Certificates for HTTPS
~~~~~~~~~~~~~~~~~~~~~~

By default the ESX driver uses HTTPS to communicate with an ESX server. Proper
HTTPS communication requires correctly configured SSL certificates. This
certificates are different from the ones libvirt uses for `secure communication
over TLS <remote.html>`__ to a libvirtd one a remote server.

By default the driver tries to verify the server's SSL certificate using the CA
certificate pool installed on your client computer. With an out-of-the-box
installed ESX server this won't work, because a newly installed ESX server uses
auto-generated self-signed certificates. Those are signed by a CA certificate
that is typically not known to your client computer and libvirt will report an
error like this one:

::

   error: internal error curl_easy_perform() returned an error: Peer certificate cannot be authenticated with known CA certificates (60)

Where are two ways to solve this problem:

-  Use the ``no_verify=1`` `Extra parameters`_ to disable server
   certificate verification.
-  Generate new SSL certificates signed by a CA known to your client computer
   and replace the original ones on your ESX server. See the section *Replace a
   Default Certificate with a CA-Signed Certificate* in the `ESX Configuration
   Guide <https://www.vmware.com/pdf/vsphere4/r40/vsp_40_esx_server_config.pdf>`__

Connection problems
~~~~~~~~~~~~~~~~~~~

There are also other causes for connection problems than those related to
`Certificates for HTTPS`_ .

-  As stated before the ESX driver doesn't need the `remote transport
   mechanism <remote.html>`__ provided by the remote driver and libvirtd, nor
   does the ESX driver support it. Therefore, using an URI including a transport
   in the scheme won't work. Only URIs as described in `URI Format`_ are
   supported by the ESX driver. Here's a collection of possible error messages:

   ::

      $ virsh -c esx+tcp://example.com/
      error: unable to connect to libvirtd at 'example.com': Connection refused

   ::

      $ virsh -c esx+tls://example.com/
      error: Cannot access CA certificate '/etc/pki/CA/cacert.pem': No such file or directory

   ::

      $ virsh -c esx+ssh://example.com/
      error: cannot recv data: ssh: connect to host example.com port 22: Connection refused

   ::

      $ virsh -c esx+ssh://example.com/
      error: cannot recv data: Resource temporarily unavailable

-  :since:`Since 0.7.0` libvirt contains the ESX driver. Earlier versions of
   libvirt will report a misleading error about missing certificates when you
   try to connect to an ESX server.

   ::

      $ virsh -c esx://example.com/
      error: Cannot access CA certificate '/etc/pki/CA/cacert.pem': No such file or directory

   Don't let this error message confuse you. Setting up certificates as
   described on the `tls certificates <kbase/tlscerts.html>`__ page does not
   help, as this is not a certificate related problem.

   To fix this problem you need to update your libvirt to 0.7.0 or newer. You
   may also see this error when you use a libvirt version that contains the ESX
   driver but you or your distro disabled the ESX driver during compilation.
   :since:`Since 0.8.3` the error message has been improved in this case:

   ::

      $ virsh -c esx://example.com/
      error: invalid argument in libvirt was built without the 'esx' driver

Questions blocking tasks
------------------------

Some methods of the VI API start tasks, for example ``PowerOnVM_Task()``. Such
tasks may be blocked by questions if the ESX server detects an issue with the
domain that requires user interaction. The ESX driver cannot prompt the user to
answer a question, libvirt doesn't have an API for something like this.

The VI API provides the ``AnswerVM()`` method to programmatically answer a
questions. So the driver has two options how to handle such a situation: either
answer the questions with the default answer or report the question as an error
and cancel the blocked task if possible. The ``auto_answer`` query
parameter (see `URI Format`_) controls the answering behavior.

Specialities in the domain XML config
-------------------------------------

There are several specialities in the domain XML config for ESX domains.

Restrictions
~~~~~~~~~~~~

There are some restrictions for some values of the domain XML config. The driver
will complain if this restrictions are violated.

-  Memory size has to be a multiple of 4096
-  Number of virtual CPU has to be 1 or a multiple of 2. :since:`Since 4.10.0`
   any number of vCPUs is supported.
-  Valid MAC address prefixes are ``00:0c:29`` and ``00:50:56``. :since:`Since
   0.7.6` arbitrary `MAC addresses`_ are supported.

Datastore references
~~~~~~~~~~~~~~~~~~~~

Storage is managed in datastores. VMware uses a special path format to reference
files in a datastore. Basically, the datastore name is put into squared braces
in front of the path.

::

   [datastore] directory/filename

To define a new domain the driver converts the domain XML into a VMware VMX file
and uploads it to a datastore known to the ESX server. Because multiple
datastores may be known to an ESX server the driver needs to decide to which
datastore the VMX file should be uploaded. The driver deduces this information
from the path of the source of the first file-based harddisk listed in the
domain XML.

MAC addresses
~~~~~~~~~~~~~

VMware has registered two MAC address prefixes for domains: ``00:0c:29`` and
``00:50:56``. These prefixes are split into ranges for different purposes.

+--------------------------------------+--------------------------------------+
| Range                                | Purpose                              |
+======================================+======================================+
| ``00:0c:29:00:00:00`` -              | An ESX server autogenerates MAC      |
| ``00:0c:29:ff:ff:ff``                | addresses from this range if the VMX |
|                                      | file doesn't contain a MAC address   |
|                                      | when trying to start a domain.       |
+--------------------------------------+--------------------------------------+
| ``00:50:56:00:00:00`` -              | MAC addresses from this range can by |
| ``00:50:56:3f:ff:ff``                | manually assigned by the user in the |
|                                      | VI client.                           |
+--------------------------------------+--------------------------------------+
| ``00:50:56:80:00:00`` -              | A VI client autogenerates MAC        |
| ``00:50:56:bf:ff:ff``                | addresses from this range for newly  |
|                                      | defined domains.                     |
+--------------------------------------+--------------------------------------+

The VMX files generated by the ESX driver always contain a MAC address, because
libvirt generates a random one if an interface element in the domain XML file
lacks a MAC address. :since:`Since 0.7.6` the ESX driver sets the prefix for
generated MAC addresses to ``00:0c:29``. Before 0.7.6 the ``00:50:56`` prefix
was used. Sometimes this resulted in the generation of out-of-range MAC address
that were rejected by the ESX server.

Also :since:`since 0.7.6` every MAC address outside this ranges can be used. For
such MAC addresses the ESX server-side check is disabled in the VMX file to stop
the ESX server from rejecting out-of-predefined-range MAC addresses.

::

   ethernet0.checkMACAddress = "false"

:since:`Since 6.6.0` , one can force libvirt to keep the provided MAC address
when it's in the reserved VMware range by adding a ``type="static"`` attribute
to the ``<mac/>`` element. Note that this attribute is useless if the provided
MAC address is outside of the reserved VMWare ranges.

Available hardware
~~~~~~~~~~~~~~~~~~

VMware ESX supports different models of SCSI controllers and network cards.

SCSI controller models
^^^^^^^^^^^^^^^^^^^^^^

``auto``
   This isn't an actual controller model. If specified the ESX driver tries to
   detect the SCSI controller model referenced in the ``.vmdk`` file and use it.
   Autodetection fails when a SCSI controller has multiple disks attached and
   the SCSI controller models referenced in the ``.vmdk`` files are
   inconsistent. :since:`Since 0.8.3`
``buslogic``
   BusLogic SCSI controller for older guests.
``lsilogic``
   LSI Logic SCSI controller for recent guests.
``lsisas1068``
   LSI Logic SAS 1068 controller. :since:`Since 0.8.0`
``vmpvscsi``
   Special VMware Paravirtual SCSI controller, requires VMware tools inside the
   guest. See `VMware KB1010398 <https://kb.vmware.com/kb/1010398>`__ for
   details. :since:`Since 0.8.3`

Here a domain XML snippet:

::

   ...
   <disk type='file' device='disk'>
     <source file='[local-storage] Fedora11/Fedora11.vmdk'/>
     <target dev='sda' bus='scsi'/>
     <address type='drive' controller='0' bus='0' unit='0'/>
   </disk>
   <controller type='scsi' index='0' model='lsilogic'/>
   ...

The controller element is supported :since:`since 0.8.2` . Prior to this
``<driver name='lsilogic'/>`` was abused to specify the SCSI controller model.
This attribute usage is deprecated now.

::

   ...
   <disk type='file' device='disk'>
     <driver name='lsilogic'/>
     <source file='[local-storage] Fedora11/Fedora11.vmdk'/>
     <target dev='sda' bus='scsi'/>
   </disk>
   ...

Network card models
^^^^^^^^^^^^^^^^^^^

``vlance``
   AMD PCnet32 network card for older guests.
``vmxnet``, ``vmxnet2``, ``vmxnet3``
   Special VMware VMXnet network card, requires VMware tools inside the guest.
   See `VMware KB1001805 <https://kb.vmware.com/kb/1001805>`__ for details.
``e1000``
   Intel E1000 network card for recent guests.

Here a domain XML snippet:

::

   ...
   <interface type='bridge'>
     <mac address='00:50:56:25:48:c7'/>
     <source bridge='VM Network'/>
     <model type='e1000'/>
   </interface>
   ...

Import and export of domain XML configs
---------------------------------------

The ESX driver currently supports a native config format known as ``vmware-vmx``
to handle VMware VMX configs.

Converting from VMware VMX config to domain XML config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh domxml-from-native`` provides a way to convert an existing VMware
VMX config into a domain XML config that can then be used by libvirt.

::

   $ cat > demo.vmx << EOF
   #!/usr/bin/vmware
   config.version = "8"
   virtualHW.version = "4"
   floppy0.present = "false"
   nvram = "Fedora11.nvram"
   deploymentPlatform = "windows"
   virtualHW.productCompatibility = "hosted"
   tools.upgrade.policy = "useGlobal"
   powerType.powerOff = "default"
   powerType.powerOn = "default"
   powerType.suspend = "default"
   powerType.reset = "default"
   displayName = "Fedora11"
   extendedConfigFile = "Fedora11.vmxf"
   scsi0.present = "true"
   scsi0.sharedBus = "none"
   scsi0.virtualDev = "lsilogic"
   memsize = "1024"
   scsi0:0.present = "true"
   scsi0:0.fileName = "/vmfs/volumes/498076b2-02796c1a-ef5b-000ae484a6a3/Fedora11/Fedora11.vmdk"
   scsi0:0.deviceType = "scsi-hardDisk"
   ide0:0.present = "true"
   ide0:0.clientDevice = "true"
   ide0:0.deviceType = "cdrom-raw"
   ide0:0.startConnected = "false"
   ethernet0.present = "true"
   ethernet0.networkName = "VM Network"
   ethernet0.addressType = "vpx"
   ethernet0.generatedAddress = "00:50:56:91:48:c7"
   chipset.onlineStandby = "false"
   guestOSAltName = "Red Hat Enterprise Linux 5 (32-Bit)"
   guestOS = "rhel5"
   uuid.bios = "50 11 5e 16 9b dc 49 d7-f1 71 53 c4 d7 f9 17 10"
   snapshot.action = "keep"
   sched.cpu.min = "0"
   sched.cpu.units = "mhz"
   sched.cpu.shares = "normal"
   sched.mem.minsize = "0"
   sched.mem.shares = "normal"
   toolScripts.afterPowerOn = "true"
   toolScripts.afterResume = "true"
   toolScripts.beforeSuspend = "true"
   toolScripts.beforePowerOff = "true"
   scsi0:0.redo = ""
   tools.syncTime = "false"
   uuid.location = "56 4d b5 06 a2 bd fb eb-ae 86 f7 d8 49 27 d0 c4"
   sched.cpu.max = "unlimited"
   sched.swap.derivedName = "/vmfs/volumes/498076b2-02796c1a-ef5b-000ae484a6a3/Fedora11/Fedora11-7de040d8.vswp"
   tools.remindInstall = "TRUE"
   EOF

   $ virsh -c esx://example.com domxml-from-native vmware-vmx demo.vmx
   Enter username for example.com [root]:
   Enter root password for example.com:
   <domain type='vmware'>
     <name>Fedora11</name>
     <uuid>50115e16-9bdc-49d7-f171-53c4d7f91710</uuid>
     <memory>1048576</memory>
     <currentMemory>1048576</currentMemory>
     <vcpu>1</vcpu>
     <os>
       <type arch='i686'>hvm</type>
     </os>
     <clock offset='utc'/>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>destroy</on_crash>
     <devices>
       <disk type='file' device='disk'>
         <source file='[local-storage] Fedora11/Fedora11.vmdk'/>
         <target dev='sda' bus='scsi'/>
         <address type='drive' controller='0' bus='0' unit='0'/>
       </disk>
       <controller type='scsi' index='0' model='lsilogic'/>
       <interface type='bridge'>
         <mac address='00:50:56:91:48:c7'/>
         <source bridge='VM Network'/>
       </interface>
     </devices>
   </domain>

Converting from domain XML config to VMware VMX config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh domxml-to-native`` provides a way to convert a domain XML config
into a VMware VMX config.

::

   $ cat > demo.xml << EOF
   <domain type='vmware'>
     <name>Fedora11</name>
     <uuid>50115e16-9bdc-49d7-f171-53c4d7f91710</uuid>
     <memory>1048576</memory>
     <currentMemory>1048576</currentMemory>
     <vcpu>1</vcpu>
     <os>
       <type arch='x86_64'>hvm</type>
     </os>
     <devices>
       <disk type='file' device='disk'>
         <source file='[local-storage] Fedora11/Fedora11.vmdk'/>
         <target dev='sda' bus='scsi'/>
         <address type='drive' controller='0' bus='0' unit='0'/>
       </disk>
       <controller type='scsi' index='0' model='lsilogic'/>
       <interface type='bridge'>
         <mac address='00:50:56:25:48:c7'/>
         <source bridge='VM Network'/>
       </interface>
     </devices>
   </domain>
   EOF

   $ virsh -c esx://example.com domxml-to-native vmware-vmx demo.xml
   Enter username for example.com [root]:
   Enter root password for example.com:
   config.version = "8"
   virtualHW.version = "4"
   guestOS = "other-64"
   uuid.bios = "50 11 5e 16 9b dc 49 d7-f1 71 53 c4 d7 f9 17 10"
   displayName = "Fedora11"
   memsize = "1024"
   numvcpus = "1"
   scsi0.present = "true"
   scsi0.virtualDev = "lsilogic"
   scsi0:0.present = "true"
   scsi0:0.deviceType = "scsi-hardDisk"
   scsi0:0.fileName = "/vmfs/volumes/local-storage/Fedora11/Fedora11.vmdk"
   ethernet0.present = "true"
   ethernet0.networkName = "VM Network"
   ethernet0.connectionType = "bridged"
   ethernet0.addressType = "static"
   ethernet0.address = "00:50:56:25:48:C7"

Example domain XML configs
--------------------------

Fedora11 on x86_64
~~~~~~~~~~~~~~~~~~

::

   <domain type='vmware'>
     <name>Fedora11</name>
     <uuid>50115e16-9bdc-49d7-f171-53c4d7f91710</uuid>
     <memory>1048576</memory>
     <currentMemory>1048576</currentMemory>
     <vcpu>1</vcpu>
     <os>
       <type arch='x86_64'>hvm</type>
     </os>
     <devices>
       <disk type='file' device='disk'>
         <source file='[local-storage] Fedora11/Fedora11.vmdk'/>
         <target dev='sda' bus='scsi'/>
         <address type='drive' controller='0' bus='0' unit='0'/>
       </disk>
       <controller type='scsi' index='0'/>
       <interface type='bridge'>
         <mac address='00:50:56:25:48:c7'/>
         <source bridge='VM Network'/>
       </interface>
     </devices>
   </domain>

Migration
---------

A migration cannot be initiated on an ESX server directly, a VMware vCenter is
necessary for this. The ``vcenter`` query parameter must be set either to the
hostname or IP address of the vCenter managing the ESX server or to ``*``.
Setting it to ``*`` causes the driver to connect to the vCenter known to the ESX
server. If the ESX server is not managed by a vCenter an error is reported.

::

   esx://example.com/?vcenter=example-vcenter.com

Here's an example how to migrate the domain ``Fedora11`` from ESX server
``example-src.com`` to ESX server ``example-dst.com`` implicitly involving
vCenter ``example-vcenter.com`` using ``virsh``.

::

   $ virsh -c esx://example-src.com/?vcenter=* migrate Fedora11 esx://example-dst.com/?vcenter=*
   Enter username for example-src.com [root]:
   Enter root password for example-src.com:
   Enter username for example-vcenter.com [administrator]:
   Enter administrator password for example-vcenter.com:
   Enter username for example-dst.com [root]:
   Enter root password for example-dst.com:
   Enter username for example-vcenter.com [administrator]:
   Enter administrator password for example-vcenter.com:

:since:`Since 0.8.3` you can directly connect to a vCenter. This simplifies
migration a bit. Here's the same migration as above but using ``vpx://``
connections and assuming both ESX server are in datacenter ``dc1`` and aren't
part of a cluster.

::

   $ virsh -c vpx://example-vcenter.com/dc1/example-src.com migrate Fedora11 vpx://example-vcenter.com/dc1/example-dst.com
   Enter username for example-vcenter.com [administrator]:
   Enter administrator password for example-vcenter.com:
   Enter username for example-vcenter.com [administrator]:
   Enter administrator password for example-vcenter.com:

Scheduler configuration
-----------------------

The driver exposes the ESX CPU scheduler. The parameters listed below are
available to control the scheduler.

``reservation``
   The amount of CPU resource in MHz that is guaranteed to be available to the
   domain. Valid values are 0 and greater.
``limit``
   The CPU utilization of the domain will be limited to this value in MHz, even
   if more CPU resources are available. If the limit is set to -1, the CPU
   utilization of the domain is unlimited. If the limit is not set to -1, it
   must be greater than or equal to the reservation.
``shares``
   Shares are used to determine relative CPU allocation between domains. In
   general, a domain with more shares gets proportionally more of the CPU
   resource. Valid values are 0 and greater. The special values -1, -2 and -3
   represent the predefined shares level ``low``, ``normal`` and ``high``.

VMware tools
------------

Some actions require installed VMware tools. If the VMware tools are not
installed in the guest and one of the actions below is to be performed the ESX
server raises an error and the driver reports it.

-  ``virDomainGetHostname``
-  ``virDomainInterfaceAddresses`` (only for the
   ``VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT`` source)
-  ``virDomainReboot``
-  ``virDomainShutdown``

Links
-----

-  `VMware vSphere Web Services SDK
   Documentation <https://www.vmware.com/support/developer/vc-sdk/>`__
-  `The Role of Memory in VMware ESX Server
   3 <https://www.vmware.com/pdf/esx3_memory.pdf>`__
-  `VMware VMX config parameters <https://www.sanbarrow.com/vmx.html>`__
-  `VMware ESX 4.0 PVSCSI Storage
   Performance <https://www.vmware.com/pdf/vsp_4_pvscsi_perf.pdf>`__
