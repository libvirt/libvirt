.. role:: since

=======================
Network port XML format
=======================

.. contents::

This page provides an introduction to the network port XML format. This stores
information about the connection between a virtual interface of a virtual
domain, and the virtual network it is attached to.

Element and attribute overview
------------------------------

The root element required for all virtual network ports is named ``networkport``
and has no configurable attributes The network port XML format is available
:since:`since 5.5.0`

General metadata
~~~~~~~~~~~~~~~~

The first elements provide basic metadata about the virtual network port.

::

   <networkport>
     <uuid>7ae63b5f-fe96-4af0-a7c3-da04ba1b3f54</uuid>
     <owner>
       <uuid>06578fc1-c686-46fa-bc2c-220893b466a6</uuid>
       <name>myguest</name>
     </owner>
     <group>webfront</group>
     <mac address='52:54:0:7b:35:93'/>
     ...

``uuid``
   The content of the ``uuid`` element provides a globally unique identifier for
   the virtual network port. The format must be RFC 4122 compliant, eg
   ``3e3fce45-4f53-4fa7-bb32-11f34168b82b``. If omitted when defining/creating a
   new network port, a random UUID is generated.
   The ``owner`` node records the domain object that is the owner of the network
   port. It contains two child nodes:

   ``uuid``
      The content of the ``uuid`` element provides a globally unique identifier
      for the virtual domain.
   ``name``
      The unique name of the virtual domain
``group``
   The port group in the virtual network to which the port belongs. Can be
   omitted if no port groups are defined on the network.
``mac``
   The ``address`` attribute provides the MAC address of the virtual port that
   will be see by the guest. The MAC address must not start with 0xFE as this
   byte is reserved for use on the host side of the port.

Common elements
~~~~~~~~~~~~~~~

The following elements are common to one or more of the plug types listed later

::

     ...
     <bandwidth>
       <inbound average='1000' peak='5000' floor='200' burst='1024'/>
       <outbound average='128' peak='256' burst='256'/>
     </bandwidth>
     <rxfilters trustGuest='yes'/>
     <port isolated='yes'/>
     <virtualport type='802.1Qbg'>
       <parameters managerid='11' typeid='1193047' typeidversion='2'/>
     </virtualport>
     ...

``bandwidth``
   This part of the network port XML provides setting quality of service.
   Incoming and outgoing traffic can be shaped independently. The ``bandwidth``
   element and its child elements are described in the
   `QoS <formatnetwork.html#quality-of-service>`__ section of the Network XML. In
   addition the ``classID`` attribute may exist to provide the ID of the traffic
   shaping class that is active.
``rxfilters``
   The ``rxfilters`` element property ``trustGuest`` provides the capability for
   the host to detect and trust reports from the guest regarding changes to the
   interface mac address and receive filters by setting the attribute to
   ``yes``. The default setting for the attribute is ``no`` for security reasons
   and support depends on the guest network device model as well as the type of
   connection on the host - currently it is only supported for the virtio device
   model and for macvtap connections on the host.
``port``
   :since:`Since 6.1.0.` The ``port`` element property ``isolated``, when set to
   ``yes`` (default setting is ``no``) is used to isolate this port's network
   traffic from other ports on the same network that also have
   ``<port isolated='yes'/>``. This setting is only supported for emulated
   network devices connected to a Linux host bridge via a standard tap device.
``virtualport``
   The ``virtualport`` element describes metadata that needs to be provided to
   the underlying network subsystem. It is described in the domain XML
   `interface documentation <formatdomain.html#network-interfaces>`__.

Plugs
~~~~~

The ``plug`` element has varying content depending on the value of the ``type``
attribute.

Network
^^^^^^^

The ``network`` plug type refers to a managed virtual network plug that is based
on a traditional software bridge device privately managed by libvirt.

::

     ...
     <plug type='network' bridge='virbr0'/>
     ...

The ``bridge`` attribute provides the name of the privately managed bridge
device associated with the virtual network.

Bridge
^^^^^^

The ``bridge`` plug type refers to an externally managed traditional software
bridge.

::

     ...
     <plug type='bridge' bridge='br2'/>
     ...

The ``bridge`` attribute provides the name of the externally managed bridge
device associated with the virtual network.

Direct
^^^^^^

The ``direct`` plug type refers to a connection directly to a physical network
interface.

::

     ...
     <plug type='direct' dev='ens3' mode='vepa'/>
     ...

The ``dev`` attribute provides the name of the physical network interface to
which the port will be connected. The ``mode`` attribute describes how the
connection will be setup and takes the same values described in the `domain
XML <formatdomain.html#direct-attachment-to-physical-interface>`__.

Host PCI
^^^^^^^^

The ``hostdev-pci`` plug type refers to the passthrough of a physical PCI device
rather than emulation.

::

     ...
     <plug type='hostdev-pci' managed='yes'>
       <driver name='vfio'/>
       <address domain='0x0001' bus='0x02' slot='0x03' function='0x4'/>
     </plug>
     ...

The ``managed`` attribute indicates who is responsible for managing the PCI
device in the host. When set to the value ``yes`` libvirt is responsible for
automatically detaching the device from host drivers and resetting it if needed.
If the value is ``no``, some other party must ensure the device is not attached
to any host drivers.
