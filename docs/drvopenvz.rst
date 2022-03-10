=======================
OpenVZ container driver
=======================

.. contents::

The OpenVZ driver for libvirt allows use and management of container based
virtualization on a Linux host OS. Prior to using the OpenVZ driver, the OpenVZ
enabled kernel must be installed & booted, and the OpenVZ userspace tools
installed. The libvirt driver has been tested with OpenVZ 3.0.22, but other
3.0.x versions should also work without undue trouble.

Project Links
-------------

-  The `OpenVZ <https://openvz.org/>`__ Linux container system

Connections to OpenVZ driver
----------------------------

The libvirt OpenVZ driver is a single-instance privileged driver, with a driver
name of 'openvz'. Some example connection URIs for the libvirt driver are:

::

   openvz:///system                     (local access)
   openvz+unix:///system                (local access)
   openvz://example.com/system          (remote access, TLS/x509)
   openvz+tcp://example.com/system      (remote access, SASl/Kerberos)
   openvz+ssh://root@example.com/system (remote access, SSH tunnelled)

Notes on bridged networking
---------------------------

Bridged networking enables a guest domain (ie container) to have its network
interface connected directly to the host's physical LAN. Before this can be used
there are a couple of configuration pre-requisites for the host OS.

Host network devices
~~~~~~~~~~~~~~~~~~~~

One or more of the physical devices must be attached to a bridge. The process
for this varies according to the operating system in use, so for up to date
notes consult the `Wiki <https://wiki.libvirt.org>`__ or your operating system's
networking documentation. The basic idea is that the host OS should end up with
a bridge device "br0" containing a physical device "eth0", or a bonding device
"bond0".

OpenVZ tools configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenVZ releases later than 3.0.23 ship with a standard network device setup
script that is able to setup bridging, named ``/usr/sbin/vznetaddbr``. For
releases prior to 3.0.23, this script must be created manually by the host OS
administrator. The simplest way is to just download the latest version of this
script from a newer OpenVZ release, or upstream source repository. Then a
generic configuration file ``/etc/vz/vznet.conf`` must be created containing

::

   #!/bin/bash
   EXTERNAL_SCRIPT="/usr/sbin/vznetaddbr"

The host OS is now ready to allow bridging of guest containers, which will work
whether the container is started with libvirt, or OpenVZ tools.

Example guest domain XML configuration
--------------------------------------

The current libvirt OpenVZ driver has a restriction that the domain names must
match the OpenVZ container VEID, which by convention start at 100, and are
incremented from there. The choice of OS template to use inside the container is
determined by the ``filesystem`` tag, and the template source name matches the
templates known to OpenVZ tools.

::

   <domain type='openvz' id='104'>
     <name>104</name>
     <uuid>86c12009-e591-a159-6e9f-91d18b85ef78</uuid>
     <vcpu>3</vcpu>
     <os>
       <type>exe</type>
       <init>/sbin/init</init>
     </os>
     <devices>
       <filesystem type='template'>
         <source name='fedora-9-i386-minimal'/>
         <target dir='/'/>
       </filesystem>
       <interface type='bridge'>
         <mac address='00:18:51:5b:ea:bf'/>
         <source bridge='br0'/>
         <target dev='veth101.0'/>
       </interface>
     </devices>
   </domain>
