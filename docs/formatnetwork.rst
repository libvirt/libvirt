.. role:: since

==================
Network XML format
==================

.. contents::

This page provides an introduction to the network XML format. For background
information on the concepts referred to here, consult the `relevant wiki
page <https://wiki.libvirt.org/page/Networking>`__.

Element and attribute overview
------------------------------

The root element required for all virtual networks is named ``network`` and has
no configurable attributes (although :since:`since 0.10.0` there is one optional
read-only attribute - when examining the live configuration of a network, the
attribute ``connections``, if present, specifies the number of guest interfaces
currently connected via this network). The network XML format is available
:since:`since 0.3.0`

General metadata
~~~~~~~~~~~~~~~~

The first elements provide basic metadata about the virtual network.

::

   <network ipv6='yes' trustGuestRxFilters='no'>
     <name>default</name>
     <uuid>3e3fce45-4f53-4fa7-bb32-11f34168b82b</uuid>
     <title>A short description - title - of the network</title>
     <description>Some human readable description</description>
     <metadata>
       <app1:foo xmlns:app1="http://app1.org/app1/">..</app1:foo>
       <app2:bar xmlns:app2="http://app1.org/app2/">..</app2:bar>
     </metadata>
     ...

``name``
   The content of the ``name`` element provides a short name for the virtual
   network. This name should consist only of alphanumeric characters and is
   required to be unique within the scope of a single host. It is used to form
   the filename for storing the persistent configuration file. :since:`Since
   0.3.0`
``uuid``
   The content of the ``uuid`` element provides a globally unique identifier for
   the virtual network. The format must be RFC 4122 compliant, eg
   ``3e3fce45-4f53-4fa7-bb32-11f34168b82b``. If omitted when defining/creating a
   new network, a random UUID is generated. :since:`Since 0.3.0`
``metadata``
   The ``metadata`` node can be used by applications to store custom metadata in
   the form of XML nodes/trees. Applications must use custom namespaces on their
   XML nodes/trees, with only one top-level element per namespace (if the
   application needs structure, they should have sub-elements to their namespace
   element). :since:`Since 2.1.0`
``ipv6``
   When set to ``yes``, the optional parameter ``ipv6`` enables a network
   definition with no IPv6 gateway addresses specified to have guest-to-guest
   communications. For further information, see the example below for the
   example with no gateway addresses. :since:`Since 1.0.1`
``trustGuestRxFilters``
   The optional parameter ``trustGuestRxFilters`` can be used to set that
   attribute of the same name for each domain interface connected to this
   network ( :since:`since 1.2.10` ). See the `Network
   interfaces <formatdomain.html#network-interfaces>`__ section of the domain XML
   documentation for more details. Note that an explicit setting of this
   attribute in a portgroup or the individual domain interface will override the
   setting in the network.
``title``
   The optional element ``title`` provides space for a short description of the
   network. The title should not contain any newlines. :since:`Since 9.7.0` .
``description``
   The content of the ``description`` element provides a human readable
   description of the network. This data is not used by libvirt in any
   way, it can contain any information the user wants. :since:`Since 9.7.0`


Connectivity
~~~~~~~~~~~~

The next set of elements control how a virtual network is provided connectivity
to the physical LAN (if at all).

::

   ...
   <bridge name="virbr0" stp="on" delay="5" macTableManager="libvirt"/>
   <mtu size="9000"/>
   <domain name="example.com" localOnly="no"/>
   <forward mode="nat" dev="eth0"/>
   ...

``bridge``
   The ``name`` attribute on the ``bridge`` element defines the name of a bridge
   device which will be used to construct the virtual network. The virtual
   machines will be connected to this bridge device allowing them to talk to
   each other. The bridge device may also be connected to the LAN. When defining
   a new network with a ``<forward>`` mode of "nat", "route", or "open" (or an
   isolated network with no ``<forward>`` element), libvirt will automatically
   generate a unique name for the bridge device if none is given, and this name
   will be permanently stored in the network configuration so that that the same
   name will be used every time the network is started. For these types of
   networks (nat, route, open, and isolated), a bridge name beginning with the
   prefix "virbr" is recommended (and that is what is auto-generated), but not
   enforced. Attribute ``stp`` specifies if Spanning Tree Protocol is 'on' or
   'off' (default is 'on'). Attribute ``delay`` sets the bridge's forward delay
   value in seconds (default is 0). :since:`Since 0.3.0`

   The ``macTableManager`` attribute of the bridge element is used to tell
   libvirt how the bridge's MAC address table (used to determine the correct
   egress port for packets based on destination MAC address) will be managed. In
   the default ``kernel`` setting, the kernel automatically adds and removes
   entries, typically using learning, flooding, and promiscuous mode on the
   bridge's ports in order to determine the proper egress port for packets. When
   ``macTableManager`` is set to ``libvirt``, libvirt disables kernel management
   of the MAC table (in the case of the Linux host bridge, this means enabling
   vlan_filtering on the bridge, and disabling learning and unicast_filter for
   all bridge ports), and explicitly adds/removes entries to the table according
   to the MAC addresses in the domain interface configurations. Allowing libvirt
   to manage the MAC table can improve performance - with a Linux host bridge,
   for example, turning off learning and unicast_flood on ports has its own
   performance advantage, and can also lead to an additional boost by permitting
   the kernel to automatically turn off promiscuous mode on some ports of the
   bridge (in particular, the port attaching the bridge to the physical
   network). However, it can also cause some networking setups to stop working
   (e.g. vlan tagging, multicast, guest-initiated changes to MAC address) and is
   not supported by older kernels. :since:`Since 1.2.11, requires kernel 3.17 or
   newer`

   The optional ``zone`` attribute of the ``bridge`` element is used to specify
   the `firewalld <https://firewalld.org>`__ zone for the bridge of a network
   with ``forward`` mode of "nat", "route", "open", or one with no ``forward``
   specified. By default, the bridges of all virtual networks with these forward
   modes are placed in the firewalld zone named "libvirt", which permits
   incoming DNS, DHCP, TFTP, and SSH to the host from guests on the network.
   This behavior can be changed either by modifying the libvirt zone (using
   firewalld management tools), or by placing the network in a different zone
   (which will also be managed using firewalld tools). :since:`Since 5.1.0`

``mtu``
   The ``size`` attribute of the ``mtu>`` element specifies the Maximum
   Transmission Unit (MTU) for the network. :since:`Since 3.1.0` . In the case
   of a libvirt-managed network (one with forward mode of ``nat``, ``route``,
   ``open``, or no ``forward`` element (i.e. an isolated network), this will be
   the MTU assigned to the bridge device when libvirt creates it, and thereafter
   also assigned to all tap devices created to connect guest interfaces. Network
   types not specifically mentioned here don't support having an MTU set in the
   libvirt network config. If mtu size is unspecified, the default setting for
   the type of device being used is assumed (usually 1500).
``domain``
   The ``name`` attribute on the ``domain`` element defines the DNS domain of
   the DHCP server. This element is optional, and is only used for those
   networks with a ``<forward>`` mode of "nat" or "route" (or an isolated
   network with no ``<forward>`` element). :since:`Since 0.4.5`

   If the optional ``localOnly`` attribute on the ``domain`` element is "yes",
   then DNS requests under this domain will only be resolved by the virtual
   network's own DNS server - they will not be forwarded to the host's upstream
   DNS server. If ``localOnly`` is "no", and by default, unresolved requests
   **will** be forwarded. :since:`Since 1.2.12`

``forward``
   Inclusion of the ``forward`` element indicates that the virtual network is to
   be connected to the physical LAN. :since:`Since 0.3.0.` The ``mode``
   attribute determines the method of forwarding. If there is no ``forward``
   element, the network will be isolated from any other network (unless a guest
   connected to that network is acting as a router, of course). The following
   are valid settings for ``mode`` (if there is a ``forward`` element but mode
   is not specified, ``mode='nat'`` is assumed):

   ``nat``
      All traffic between guests connected to this network and the physical
      network will be forwarded to the physical network via the host's IP
      routing stack, after the guest's IP address is translated to appear as the
      host machine's public IP address (a.k.a. Network Address Translation, or
      "NAT"). This allows multiple guests, all having access to the physical
      network, on a host that is only allowed a single public IP address. If a
      network has any IPv6 addresses defined, the IPv6 traffic will be forwarded
      using plain routing, since IPv6 has no concept of NAT. Firewall rules will
      allow outbound connections to any other network device whether ethernet,
      wireless, dialup, or VPN. If the ``dev`` attribute is set, the firewall
      rules will restrict forwarding to the named device only. Inbound
      connections from other networks are all prohibited; all connections
      between guests on the same network, and to/from the host to the guests,
      are unrestricted and not NATed. :since:`Since 0.4.2`

      :since:`Since 1.0.3` it is possible to specify a public IPv4 address and
      port range to be used for the NAT by using the ``<nat>`` subelement. Note
      that all addresses from the range are used, not just those that are in use
      on the host. The address range is set with the ``<address>`` subelements
      and ``start`` and ``stop`` attributes:

      ::

         ...
           <forward mode='nat'>
             <nat>
               <address start='1.2.3.4' end='1.2.3.10'/>
             </nat>
           </forward>
         ...

      A single IPv4 address can be set by setting ``start`` and ``end``
      attributes to the same value.

      The port range to be used for the ``<nat>`` can be set via the subelement
      ``<port>``:

      ::

         ...
           <forward mode='nat'>
             <nat>
               <port start='500' end='1000'/>
             </nat>
           </forward>
         ...

      :since:`Since 6.5.0` it is possible to enable NAT with IPv6 networking. As
      noted above, IPv6 has historically done plain forwarding and thus to avoid
      breaking historical compatibility, IPv6 NAT must be explicitly requested.

      ::

         ...
           <forward mode='nat'>
             <nat ipv6='yes'/>
           </forward>
         ...

   ``route``
      Guest network traffic will be forwarded to the physical network via the
      host's IP routing stack, but without having NAT applied. Again, if the
      ``dev`` attribute is set, firewall rules will restrict forwarding to the
      named device only. This presumes that the local LAN router has suitable
      routing table entries to return traffic to this host. All incoming and
      outgoing sessions to guest on these networks are unrestricted. (To
      restrict incoming traffic to a guest on a routed network, you can
      configure `nwfilter rules <formatnwfilter.html>`__ on the guest's
      interfaces.) :since:`Since 0.4.2`
   ``open``
      As with mode='route', guest network traffic will be forwarded to the
      physical network via the host's IP routing stack, but there will be no
      firewall rules added to either enable or prevent any of this traffic. When
      forward='open' is set, the ``dev`` attribute cannot be set (because the
      forward dev is enforced with firewall rules, and the purpose of
      forward='open' is to have a forwarding mode where libvirt doesn't add any
      firewall rules). This mode presumes that the local LAN router has suitable
      routing table entries to return traffic to this host, and that some other
      management system has been used to put in place any necessary firewall
      rules. Although no firewall rules will be added for the network, it is of
      course still possible to add restrictions for specific guests using
      `nwfilter rules <formatnwfilter.html>`__ on the guests' interfaces.)
      :since:`Since 2.2.0`
   ``bridge``
      This network describes either 1) an existing host bridge that was
      configured outside of libvirt (if a ``<bridge name='xyz'/>`` element has
      been specified, :since:`Since 0.9.4` ), 2) an existing Open vSwitch bridge
      that was configured outside of libvirt (if both a ``<bridge name='xyz'/>``
      element **and** a ``<virtualport             type='openvswitch'/>`` have
      been specified :since:`Since 0.10.0` ) 3) an interface or group of
      interfaces to be used for a "direct" connection via macvtap using
      macvtap's "bridge" mode (if the forward element has one or more
      ``<interface>`` subelements, :since:`Since 0.9.4` ) (see `Direct
      attachment to physical interface <formatdomain.html#direct-attachment-to-physical-interface>`__
      for descriptions of the various macvtap modes). libvirt doesn't attempt to
      manage the bridge interface at all, thus the ``<bridge>`` element's
      ``stp`` and ``delay`` attributes are not allowed; no iptables rules, IP
      addresses, or DHCP/DNS services are added; at the IP level, the guest
      interface appears to be directly connected to the physical interface.
      :since:`Since 0.9.4`
   ``private``
      This network uses a macvtap "direct" connection in "private" mode to
      connect each guest to the network. The physical interface to be used will
      be picked from among those listed in ``<interface>`` subelements of the
      ``<forward>`` element; when using 802.1Qbh mode (as indicated by the
      ``<virtualport>`` type attribute - note that this requires an
      802.1Qbh-capable hardware switch), each physical interface can only be in
      use by a single guest interface at a time; in modes other than 802.1Qbh,
      multiple guest interfaces can share each physical interface (libvirt will
      attempt to balance usage between all available interfaces). :since:`Since
      0.9.4`
   ``vepa``
      This network uses a macvtap "direct" connection in "vepa" mode to connect
      each guest to the network (this requires that the physical interfaces used
      be connected to a vepa-capable hardware switch. The physical interface to
      be used will be picked from among those listed in ``<interface>``
      subelements of the ``<forward>`` element; multiple guest interfaces can
      share each physical interface (libvirt will attempt to balance usage
      between all available interfaces). :since:`Since 0.9.4`
   ``passthrough``
      This network uses a macvtap "direct" connection in "passthrough" mode to
      connect each guest to the network (note that this is *not* the same thing
      as "PCI passthrough"). The physical interface to be used will be picked
      from among those listed in ``<interface>`` subelements of the
      ``<forward>`` element. Each physical interface can only be in use by a
      single guest interface at a time, so libvirt will keep track of which
      interfaces are currently in use, and only assign unused interfaces (if
      there are no available physical interfaces when a domain interface is
      being attached, an error will be logged, and the operation causing the
      attach will fail (usually either a domain start, or a hotplug interface
      attach to a domain). :since:`Since 0.9.4`
   ``hostdev``
      This network facilitates PCI Passthrough of a network device. A network
      device is chosen from the interface pool and directly assigned to the
      guest using generic device passthrough, after first optionally setting the
      device's MAC address and vlan tag to the configured value, and optionally
      associating the device with an 802.1Qbh capable switch using a
      ``<virtualport>`` element. Note that - due to limitations in standard
      single-port PCI ethernet card driver design - only SR-IOV (Single Root I/O
      Virtualization) virtual function (VF) devices can be assigned in this
      manner; to assign a standard single-port PCI or PCIe ethernet card to a
      guest, use the traditional ``<hostdev>`` device definition. :since:` Since
      0.10.0`

      To force use of a particular type of device assignment, a <forward
      type='hostdev'> interface can have an optional ``driver`` sub-element with
      a ``name`` attribute set to either "vfio" (VFIO is a new method of device
      assignment that is compatible with UEFI Secure Boot) or "kvm" (the legacy
      device assignment handled directly by the KVM kernel module) :since:`Since
      1.0.5 (QEMU and KVM only, requires kernel 3.6 or newer)` . When specified,
      device assignment will fail if the requested method of device assignment
      isn't available on the host. When not specified, the default is "vfio" on
      systems where the VFIO driver is available and loaded, and "kvm" on older
      systems, or those where the VFIO driver hasn't been loaded :since:`Since
      1.1.3` (prior to that the default was always "kvm").

      Note that this "intelligent passthrough" of network devices is very
      similar to the functionality of a standard ``<hostdev>`` device, the
      difference being that this method allows specifying a MAC address, vlan
      tag, and ``<virtualport>`` for the passed-through device. If these
      capabilities are not required, if you have a standard single-port PCI,
      PCIe, or USB network card that doesn't support SR-IOV (and hence would
      anyway lose the configured MAC address during reset after being assigned
      to the guest domain), or if you are using a version of libvirt older than
      0.10.0, you should use a standard ``<hostdev>`` device definition in the
      domain's configuration to assign the device to the guest instead of
      defining an ``<interface             type='network'>`` pointing to a
      network with ``<forward mode='hostdev'/>``.

   As mentioned above, a ``<forward>`` element can have multiple ``<interface>``
   subelements, each one giving the name of a physical interface that can be
   used for this network :since:`Since 0.9.4` :

   ::

      ...
        <forward mode='passthrough'>
          <interface dev='eth10'/>
          <interface dev='eth11'/>
          <interface dev='eth12'/>
          <interface dev='eth13'/>
          <interface dev='eth14'/>
        </forward>
      ...

   :since:`since 0.10.0` , ``<interface>`` also has an optional read-only
   attribute - when examining the live configuration of a network, the attribute
   ``connections``, if present, specifies the number of guest interfaces
   currently connected via this physical interface.

   Additionally, :since:`since 0.9.10` , libvirt allows a shorthand for
   specifying all virtual interfaces associated with a single physical function,
   by using the ``<pf>`` subelement to call out the corresponding physical
   interface associated with multiple virtual interfaces:

   ::

      ...
        <forward mode='passthrough'>
          <pf dev='eth0'/>
        </forward>
      ...

   When a guest interface is being constructed, libvirt will pick an interface
   from this list to use for the connection. In modes where physical interfaces
   can be shared by multiple guest interfaces, libvirt will choose the interface
   that currently has the least number of connections. For those modes that do
   not allow sharing of the physical device (in particular, 'passthrough' mode,
   and 'private' mode when using 802.1Qbh), libvirt will choose an unused
   physical interface or, if it can't find an unused interface, fail the
   operation.

   :since:`since 0.10.0` When using forward mode 'hostdev', the interface pool
   is specified with a list of ``<address>`` elements, each of which has
   ``<type>`` (must always be ``'pci'``), ``<domain>``, ``<bus>``,
   ``<slot>``\ and ``<function>`` attributes.

   ::

      ...
        <forward mode='hostdev' managed='yes'>
          <driver name='vfio'/>
          <address type='pci' domain='0' bus='4' slot='0' function='1'/>
          <address type='pci' domain='0' bus='4' slot='0' function='2'/>
          <address type='pci' domain='0' bus='4' slot='0' function='3'/>
        </forward>
      ...

   Alternatively the interface pool can also be defined using a single physical
   function ``<pf>`` subelement to call out the corresponding physical interface
   associated with multiple virtual interfaces (similar to passthrough mode):

   ::

      ...
        <forward mode='hostdev' managed='yes'>
          <pf dev='eth0'/>
        </forward>
      ...

Quality of service
^^^^^^^^^^^^^^^^^^

::

   ...
     <forward mode='nat' dev='eth0'/>
     <bandwidth>
       <inbound average='1000' peak='5000' burst='5120'/>
       <outbound average='128' peak='256' burst='256'/>
     </bandwidth>
   ...

The ``<bandwidth>`` element allows setting quality of service for a particular
network ( :since:`since 0.9.4` ). Setting ``bandwidth`` for a network is
supported only for networks with a ``<forward>`` mode of ``route``, ``nat``,
``bridge``, or no mode at all (i.e. an "isolated" network). Setting
``bandwidth`` is **not** supported for forward modes ``passthrough``,
``private``, or ``hostdev``. Attempts to do this will lead to a failure to
define the network or to create a transient network.

The ``<bandwidth>`` element can only be a subelement of a domain's
``<interface>``, a subelement of a ``<network>``, or a subelement of a
``<portgroup>`` in a ``<network>``.

As a subelement of a domain's ``<interface>``, the bandwidth only applies to
that one interface of the domain. As a subelement of a ``<network>``, the
bandwidth is a total aggregate bandwidth to/from all guest interfaces attached
to that network, **not** to each guest interface individually. If a domain's
``<interface>`` has ``<bandwidth>`` element values higher than the aggregate for
the entire network, then the aggregate bandwidth for the ``<network>`` takes
precedence. This is because the two choke points are independent of each other
where the domain's ``<interface>`` bandwidth control is applied on the
interface's tap device, while the ``<network>`` bandwidth control is applied on
the interface part of the bridge device created for that network.

As a subelement of a ``<portgroup>`` in a ``<network>``, if a domain's
``<interface>`` has a ``portgroup`` attribute in its ``<source>`` element
**and** if the ``<interface>`` itself has no ``<bandwidth>`` element, then the
``<bandwidth>`` element of the portgroup will be applied individually to each
guest interface defined to be a member of that portgroup. Any ``<bandwidth>``
element in the domain's ``<interface>`` definition will override the setting in
the portgroup ( :since:`since 1.0.1` ).

Incoming and outgoing traffic can be shaped independently. The ``bandwidth``
element can have at most one ``inbound`` and at most one ``outbound`` child
element. Leaving either of these children elements out results in no QoS applied
for that traffic direction. So, when you want to shape only incoming traffic,
use ``inbound`` only, and vice versa. Each of these elements have one mandatory
attribute - ``average`` (or ``floor`` as described below). The attributes are as
follows, where accepted values for each attribute is an integer number.

``average``
   Specifies the desired average bit rate for the interface being shaped (in
   kilobytes/second).
``peak``
   Optional attribute which specifies the maximum rate at which the bridge can
   send data (in kilobytes/second). Note the limitation of implementation: this
   attribute in the ``outbound`` element is ignored (as Linux ingress filters
   don't know it yet).
``burst``
   Optional attribute which specifies the amount of kibibytes that can be
   transmitted in a single burst at ``peak`` speed.
``floor``
   Optional attribute available only for the ``inbound`` element. This attribute
   guarantees minimal throughput for shaped interfaces. This, however, requires
   that all traffic goes through one point where QoS decisions can take place,
   hence why this attribute works only for virtual networks for now (that is
   ``<interface type='network'/>`` with a forward type of route, nat, open or no
   forward at all). Moreover, the virtual network the interface is connected to
   is required to have at least inbound QoS set (``average`` at least). If using
   the ``floor`` attribute users don't need to specify ``average``. However,
   ``peak`` and ``burst`` attributes still require ``average``. Currently, the
   Linux kernel doesn't allow ingress qdiscs to have any classes therefore
   ``floor`` can be applied only on ``inbound`` and not ``outbound``.

Attributes ``average``, ``peak``, and ``burst`` are available :since:`since
0.9.4` , while the ``floor`` attribute is available :since:`since 1.0.1` .

Setting VLAN tag (on supported network types only)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   <network>
     <name>ovs-net</name>
     <forward mode='bridge'/>
     <bridge name='ovsbr0'/>
     <virtualport type='openvswitch'>
       <parameters interfaceid='09b11c53-8b5c-4eeb-8f00-d84eaa0aaa4f'/>
     </virtualport>
     <vlan trunk='yes'>
       <tag id='42' nativeMode='untagged'/>
       <tag id='47'/>
     </vlan>
     <portgroup name='dontpanic'>
       <vlan>
         <tag id='42'/>
       </vlan>
     </portgroup>
   </network>

If (and only if) the network connection used by the guest supports VLAN tagging
transparent to the guest, an optional ``<vlan>`` element can specify one or more
VLAN tags to apply to the guest's network traffic :since:`Since 0.10.0` .
Network connections that support guest-transparent VLAN tagging include 1)
type='bridge' interfaces connected to an Open vSwitch bridge :since:`Since
0.10.0` , 2) SRIOV Virtual Functions (VF) used via type='hostdev' (direct device
assignment) :since:`Since 0.10.0` , and 3) SRIOV VFs used via type='direct' with
mode='passthrough' (macvtap "passthru" mode) :since:`Since 1.3.5` . All other
connection types, including standard linux bridges and libvirt's own virtual
networks, **do not** support it. 802.1Qbh (vn-link) and 802.1Qbg (VEPA) switches
provide their own way (outside of libvirt) to tag guest traffic onto a specific
VLAN. Each tag is given in a separate ``<tag>`` subelement of ``<vlan>`` (for
example: ``<tag       id='42'/>``). For VLAN trunking of multiple tags (which is
supported only on Open vSwitch connections), multiple ``<tag>`` subelements can
be specified, which implies that the user wants to do VLAN trunking on the
interface for all the specified tags. In the case that VLAN trunking of a single
tag is desired, the optional attribute ``trunk='yes'`` can be added to the
toplevel ``<vlan>`` element to differentiate trunking of a single tag from
normal tagging.

For network connections using Open vSwitch it is also possible to configure
'native-tagged' and 'native-untagged' VLAN modes :since:`Since 1.1.0.` This is
done with the optional ``nativeMode`` attribute on the ``<tag>`` subelement:
``nativeMode`` may be set to 'tagged' or 'untagged'. The ``id`` attribute of the
``<tag>`` subelement containing ``nativeMode`` sets which VLAN is considered to
be the "native" VLAN for this interface, and the ``nativeMode`` attribute
determines whether or not traffic for that VLAN will be tagged.

``<vlan>`` elements can also be specified in a ``<portgroup>`` element, as well
as directly in a domain's ``<interface>`` element. In the case that a vlan tag
is specified in multiple locations, the setting in ``<interface>`` takes
precedence, followed by the setting in the ``<portgroup>`` selected by the
interface config. The ``<vlan>`` in ``<network>`` will be selected only if none
is given in ``<portgroup>`` or ``<interface>``.

Isolating ports from one another
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   <network>
     <name>isolated-ports</name>
     <forward mode='bridge'/>
     <bridge name='br0'/>
     <port isolated='yes'/>
   </network>

:since:`Since 6.1.0.` The ``port`` element property ``isolated``, when set to
``yes`` (default setting is ``no``) is used to isolate the network traffic of
each guest on the network from all other guests connected to the network; it
does not have an effect on communication between the guests and the host, or
between the guests and destinations beyond this network. This setting is only
supported for networks that use a Linux host bridge to connect guest interfaces
via a standard tap device (i.e. those with a forward mode of nat, route, open,
bridge, or no forward mode).

Portgroups
^^^^^^^^^^

::

   ...
     <forward mode='private'/>
       <interface dev="eth20"/>
       <interface dev="eth21"/>
       <interface dev="eth22"/>
       <interface dev="eth23"/>
       <interface dev="eth24"/>
     </forward>
     <portgroup name='engineering' default='yes'>
       <virtualport type='802.1Qbh'>
         <parameters profileid='test'/>
       </virtualport>
       <bandwidth>
         <inbound average='1000' peak='5000' burst='5120'/>
         <outbound average='1000' peak='5000' burst='5120'/>
       </bandwidth>
     </portgroup>
     <portgroup name='sales' trustGuestRxFilters='no'>
       <virtualport type='802.1Qbh'>
         <parameters profileid='salestest'/>
       </virtualport>
       <bandwidth>
         <inbound average='500' peak='2000' burst='2560'/>
         <outbound average='128' peak='256' burst='256'/>
       </bandwidth>
     </portgroup>
   ...

:since:`Since 0.9.4` A portgroup provides a method of easily putting guest
connections to the network into different classes, with each class potentially
having a different level/type of service. :since:`Since 0.9.4` Each network can
have multiple portgroup elements (and one of those can optionally be designated
as the 'default' portgroup for the network), and each portgroup has a name, as
well as various attributes and subelements associated with it. The currently
supported subelements are ``<bandwidth>`` (described in `Quality of service`_)
and ``<virtualport>`` (documented
`here <formatdomain.html#direct-attachment-to-physical-interface>`__). If a domain interface
definition specifies a portgroup (by adding a ``portgroup`` attribute to the
``<source>`` subelement), that portgroup's info will be merged into the
interface's configuration. If no portgroup is given in the interface definition,
and one of the network's portgroups has ``default='yes'``, that default
portgroup will be used. If no portgroup is given in the interface definition,
and there is no default portgroup, then none will be used. Any ``<bandwidth>``
specified directly in the domain XML will take precedence over any setting in
the chosen portgroup. if a ``<virtualport>`` is specified in the portgroup
(and/or directly in the network definition), the multiple virtualports will be
merged, and any parameter that is specified in more than one virtualport, and is
not identical, will be considered an error, and will prevent the interface from
starting.

portgroups also support the optional parameter ``trustGuestRxFilters`` which can
be used to set that attribute of the same name for each domain interface using
this portgroup ( :since:`since 1.2.10` ). See the `Network
interfaces <formatdomain.html#network-interfaces>`__ section of the domain XML
documentation for more details. Note that an explicit setting of this attribute
in the portgroup overrides the network-wide setting, and an explicit setting in
the individual domain interface will override the setting in the portgroup.

Static Routes
^^^^^^^^^^^^^

Static route definitions are used to provide routing information to the
virtualization host for networks which are not directly reachable from the
virtualization host, but \*are\* reachable from a guest domain that is itself
reachable from the host :since:`since 1.0.6` .

As shown in `Network config with no gateway addresses`_ example, it is
possible to define a virtual network interface with no IPv4 or IPv6 addresses.
Such networks are useful to provide host connectivity to networks which are only
reachable via a guest. A guest with connectivity both to the guest-only network
and to another network that is directly reachable from the host can act as a
gateway between the networks. A static route added to the "host-visible" network
definition provides the routing information so that IP packets can be sent from
the virtualization host to guests on the hidden network.

Here is a fragment of a definition which shows the static route specification as
well as the IPv4 and IPv6 definitions for network addresses which are referred
to in the ``gateway`` gateway address specifications. Note that the third static
route specification includes the ``metric`` attribute specification with a value
of 2. This particular route would \*not\* be preferred if there was another
existing rout on the system with the same address and prefix but with a lower
value for the metric. If there is a route in the host system configuration that
should be overridden by a route in a virtual network whenever the virtual
network is running, the configuration for the system-defined route should be
modified to have a higher metric, and the route on the virtual network given a
lower metric (for example, the default metric of "1").

::

   ...
     <ip address="192.168.122.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.122.128" end="192.168.122.254"/>
       </dhcp>
     </ip>
     <route address="192.168.222.0" prefix="24" gateway="192.168.122.2"/>
     <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64"/>
     <route family="ipv6" address="2001:db8:ca2:3::" prefix="64" gateway="2001:db8:ca2:2::2"/>
     <route family="ipv6" address="2001:db9:4:1::" prefix="64" gateway="2001:db8:ca2:2::3" metric='2'/>
   ...

Addressing
~~~~~~~~~~

The final set of elements define the addresses (IPv4 and/or IPv6, as well as
MAC) to be assigned to the bridge device associated with the virtual network,
and optionally enable DHCP services. These elements are only valid for isolated
networks (no ``forward`` element specified), and for those with a forward mode
of 'route' or 'nat'.

::

   ...
   <mac address='00:16:3E:5D:C7:9E'/>
   <domain name="example.com"/>
   <dns>
     <txt name="example" value="example value"/>
     <forwarder addr="8.8.8.8"/>
     <forwarder domain='example.com' addr="8.8.4.4"/>
     <forwarder domain='www.example.com'/>
     <srv service='name' protocol='tcp' domain='test-domain-name' target='.'
       port='1024' priority='10' weight='10'/>
     <host ip='192.168.122.2'>
       <hostname>myhost</hostname>
       <hostname>myhostalias</hostname>
     </host>
   </dns>
   <ip address="192.168.122.1" netmask="255.255.255.0" localPtr="yes">
     <dhcp>
       <range start="192.168.122.100" end="192.168.122.254">
         <lease expiry='1' unit='hours'/>
       </range>
       <host mac="00:16:3e:77:e2:ed" name="foo.example.com" ip="192.168.122.10">
         <lease expiry='30' unit='minutes'/>
       </host>
       <host mac="00:16:3e:3e:a9:1a" name="bar.example.com" ip="192.168.122.11"/>
     </dhcp>
   </ip>
   <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64" localPtr="yes"/>
   <route family="ipv6" address="2001:db9:ca1:1::" prefix="64" gateway="2001:db8:ca2:2::2"/>

``mac``
   The ``address`` attribute defines a MAC (hardware) address formatted as 6
   groups of 2-digit hexadecimal numbers, the groups separated by colons (eg,
   ``"52:54:00:1C:DA:2F"``). This MAC address is assigned to the bridge device
   when it is created. Generally it is best to not specify a MAC address when
   creating a network - in this case, if a defined MAC address is needed for
   proper operation, libvirt will automatically generate a random MAC address
   and save it in the config. Allowing libvirt to generate the MAC address will
   assure that it is compatible with the idiosyncrasies of the platform where
   libvirt is running. :since:`Since 0.8.8`
``dns``
   The dns element of a network contains configuration information for the
   virtual network's DNS server :since:`Since 0.9.3` .

   The dns element can have an optional ``enable`` attribute :since:`Since
   2.2.0` . If ``enable`` is "no", then no DNS server will be setup by libvirt
   for this network (and any other configuration in ``<dns>`` will be ignored).
   If ``enable`` is "yes" or unspecified (including the complete absence of any
   ``<dns>`` element) then a DNS server will be setup by libvirt to listen on
   all IP addresses specified in the network's configuration.

   The dns element can have an optional ``forwardPlainNames`` attribute
   :since:`Since 1.1.2` . If ``forwardPlainNames`` is "no", then DNS resolution
   requests for names that are not qualified with a domain (i.e. names with no
   "." character) will not be forwarded to the host's upstream DNS server - they
   will only be resolved if they are known locally within the virtual network's
   own DNS server. If ``forwardPlainNames`` is "yes", unqualified names **will**
   be forwarded to the upstream DNS server if they can't be resolved by the
   virtual network's own DNS server.

   Currently supported sub-elements of ``<dns>`` are:

   ``forwarder``
      The dns element can have 0 or more ``<forwarder>`` elements. Each
      forwarder element defines an alternate DNS server to use for some, or all,
      DNS requests sent to this network's DNS server. There are two attributes -
      ``domain``, and ``addr``; at least one of these must be specified in any
      ``<forwarder>`` element. If both ``domain`` and ``addr`` are specified,
      then all requests that match the given domain will be forwarded to the DNS
      server at addr. If only ``domain`` is specified, then all matching domains
      will be resolved locally (or via the host's standard DNS forwarding if
      they can't be resolved locally). If an ``addr`` is specified by itself,
      then all DNS requests to the network's DNS server will be forwarded to the
      DNS server at that address with no exceptions. ``addr`` :since:`Since
      1.1.3` , ``domain`` :since:`Since 2.2.0` .
   ``txt``
      A ``dns`` element can have 0 or more ``txt`` elements. Each txt element
      defines a DNS TXT record and has two attributes, both required: a name
      that can be queried via dns, and a value that will be returned when that
      name is queried. names cannot contain embedded spaces or commas. value is
      a single string that can contain multiple values separated by commas.
      :since:`Since 0.9.3`
   ``host``
      The ``host`` element within ``dns`` is the definition of DNS hosts to be
      passed to the DNS service. The IP address is identified by the ``ip``
      attribute and the names for that IP address are identified in the
      ``hostname`` sub-elements of the ``host`` element. :since:`Since 0.9.3`

   ``srv``
      The ``dns`` element can have also 0 or more ``srv`` record elements. Each
      ``srv`` record element defines a DNS SRV record and has 2 mandatory and 5
      optional attributes. The mandatory attributes are ``service`` and
      ``protocol`` (tcp, udp) and the optional attributes are ``target``,
      ``port``, ``priority``, ``weight`` and ``domain`` as defined in DNS server
      SRV RFC (RFC 2782). :since:`Since 0.9.9`

``ip``
   The ``address`` attribute defines an IPv4 address in dotted-decimal format,
   or an IPv6 address in standard colon-separated hexadecimal format, that will
   be configured on the bridge device associated with the virtual network. To
   the guests this IPv4 address will be their IPv4 default route. For IPv6, the
   default route is established via Router Advertisement. For IPv4 addresses,
   the ``netmask`` attribute defines the significant bits of the network
   address, again specified in dotted-decimal format. For IPv6 addresses, and as
   an alternate method for IPv4 addresses, the significant bits of the network
   address can be specified with the ``prefix`` attribute, which is an integer
   (for example, ``netmask='255.255.255.0'`` could also be given as
   ``prefix='24'``). The ``family`` attribute is used to specify the type of
   address - ``ipv4`` or ``ipv6``; if no ``family`` is given, ``ipv4`` is
   assumed. More than one address of each family can be defined for a network.
   The optional ``localPtr`` attribute ( :since:`since 3.0.0` ) configures the
   DNS server to not forward any reverse DNS requests for IP addresses from the
   network configured by the ``address`` and ``netmask``/``prefix`` attributes.
   For some unusual network prefixes (not divisible by 8 for IPv4 or not
   divisible by 4 for IPv6) libvirt may be unable to compute the PTR domain
   automatically. The ``ip`` element is supported :since:`since 0.3.0` . IPv6,
   multiple addresses on a single network, ``family``, and ``prefix`` are
   supported :since:`since 0.8.7` . The ``ip`` element may contain the following
   elements:

   ``tftp``
      The optional ``tftp`` element and its mandatory ``root`` attribute enable
      TFTP services. The attribute specifies the path to the root directory
      served via TFTP. The ``tftp`` element is not supported for IPv6 addresses,
      and can only be specified on a single IPv4 address per network.
      :since:`Since 0.7.1`
   ``dhcp``
      The presence of this element enables DHCP services on the virtual network.
      The ``dhcp`` element is supported for both IPv4 ( :since:`since 0.3.0` )
      and IPv6 ( :since:`since 1.0.1` ), but only for one IP address of each
      type per network. The following sub-elements are supported:

      ``range``
         The ``start`` and ``end`` attributes on the ``range`` element specify
         the boundaries of a pool of addresses to be provided to DHCP clients.
         These two addresses must lie within the scope of the network defined on
         the parent ``ip`` element. There may be zero or more ``range`` elements
         specified. :since:`Since 0.3.0`
      ``host``
         Within the ``dhcp`` element there may be zero or more ``host``
         elements. These specify hosts which will be given names and predefined
         IP addresses by the built-in DHCP server. Any IPv4 ``host`` element
         must specify the MAC address of the host to be assigned a given name
         (via the ``mac`` attribute), the IP to be assigned to that host (via
         the ``ip`` attribute), and the name itself (the ``name`` attribute).
         The IPv6 ``host`` element differs slightly from that for IPv4: there is
         no ``mac`` attribute since a MAC address has no defined meaning in
         IPv6. Instead, the ``name`` attribute is used to identify the host to
         be assigned the IPv6 address. For DHCPv6, the name is the plain name of
         the client host sent by the client to the server. Note that this method
         of assigning a specific IP address can also be used for IPv4 instead of
         the ``mac`` attribute. :since:`Since 0.4.5`
      ``bootp``
         The optional ``bootp`` element specifies BOOTP options to be provided
         by the DHCP server for IPv4 only. Two attributes are supported:
         ``file`` is mandatory and gives the file to be used for the boot image;
         ``server`` is optional and gives the address of the TFTP server from
         which the boot image will be fetched. ``server`` defaults to the same
         host that runs the DHCP server, as is the case when the ``tftp``
         element is used. The BOOTP options currently have to be the same for
         all address ranges and statically assigned addresses. :since:`Since
         0.7.1` (``server`` :since:`since 0.7.3` )

      Optionally, ``range`` and ``host`` elements can have ``lease`` child
      element which specifies the lease time through it's attributes ``expiry``
      and ``unit`` (which accepts ``seconds``, ``minutes`` and ``hours`` and
      defaults to ``minutes`` if omitted). The minimal lease time is 2 minutes,
      except when setting an infinite lease time (``expiry='0'``). :since:`Since
      6.3.0`

Network namespaces
~~~~~~~~~~~~~~~~~~

A special XML namespace is available for passing options directly to the
underlying dnsmasq configuration file :since:`since 5.6.0` . Usage of XML
namespaces comes with no support guarantees, so use at your own risk.

This example XML will pass the option strings ``foo=bar`` and
``cname=*.foo.example.com,master.example.com`` directly to the underlying
dnsmasq instance.

::

   <network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
     ...
     <dnsmasq:options>
       <dnsmasq:option value="foo=bar"/>
       <dnsmasq:option value="cname=*.foo.example.com,master.example.com"/>
     </dnsmasq:options>
   </network>

Example configuration
---------------------

NAT based network
~~~~~~~~~~~~~~~~~

This example is the so called "default" virtual network. It is provided and
enabled out-of-the-box for all libvirt installations. This is a configuration
that allows guest OS to get outbound connectivity regardless of whether the host
uses ethernet, wireless, dialup, or VPN networking without requiring any
specific admin configuration. In the absence of host networking, it at least
allows guests to talk directly to each other.

::

   <network>
     <name>default</name>
     <bridge name="virbr0"/>
     <forward mode="nat"/>
     <ip address="192.168.122.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.122.2" end="192.168.122.254"/>
       </dhcp>
     </ip>
     <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64"/>
   </network>

Below is a variation of the above example which adds an IPv6 dhcp range
definition.

::

   <network>
     <name>default6</name>
     <bridge name="virbr0"/>
     <forward mode="nat"/>
     <ip address="192.168.122.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.122.2" end="192.168.122.254"/>
       </dhcp>
     </ip>
     <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64">
       <dhcp>
         <range start="2001:db8:ca2:2:1::10" end="2001:db8:ca2:2:1::ff"/>
       </dhcp>
     </ip>
   </network>

IPv6 NAT based network
~~~~~~~~~~~~~~~~~~~~~~

Below is a variation for also providing IPv6 NAT. This can be especially useful
when using multiple interfaces where some, such as WiFi cards, can not be
bridged (usually on a laptop), making it difficult to provide end-to-end IPv6
routing.

::

   <network>
     <name>default6</name>
     <bridge name="virbr0"/>
     <forward mode="nat">
       <nat ipv6='yes'>
         <port start='1024' end='65535'/>
       </nat>
     </forward>
     <ip address="192.168.122.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.122.2" end="192.168.122.254"/>
       </dhcp>
     </ip>
     <ip family="ipv6" address="fdXX:XXXX:XXXX:NNNN::" prefix="64"/>
   </network>

IPv6 NAT addressing has some caveats over the more straight forward IPv4 case.
`RFC 4193 <https://tools.ietf.org/html/rfc4193>`__ defines the address range
fd00::/8 for /48 IPv6 private networks. It should be concatenated with a random
40-bit string (i.e. 10 random hexadecimal digits replacing the X values above,
RFC 4193 provides an
`algorithm <https://tools.ietf.org/html/rfc4193#section-3.2.2>`__ if you do not
have a source of sufficient randomness). This leaves 0 through ffff for subnets
(N above) which you can use at will.

Many operating systems will not consider these addresses as preferential to
IPv4, due to some practical history of these addresses being present but
unroutable and causing networking issues. On many Linux distributions, you may
need to override /etc/gai.conf with values from `RFC
3484 <https://www.ietf.org/rfc/rfc3484.txt>`__ to have your IPv6 NAT network
correctly preferenced over IPv4.

Routed network config
~~~~~~~~~~~~~~~~~~~~~

This is a variant on the default network which routes traffic from the virtual
network to the LAN without applying any NAT. It requires that the IP address
range be pre-configured in the routing tables of the router on the host network.
This example further specifies that guest traffic may only go out via the
``eth1`` host network device.

::

   <network>
     <name>local</name>
     <bridge name="virbr1"/>
     <forward mode="route" dev="eth1"/>
     <ip address="192.168.122.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.122.2" end="192.168.122.254"/>
       </dhcp>
     </ip>
     <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64"/>
   </network>

Below is another IPv6 variation. Instead of a dhcp range being specified, this
example has a couple of IPv6 host definitions. Note that most of the dhcp host
definitions use an "id" (client id or DUID) since this has proven to be a more
reliable way of specifying the interface and its association with an IPv6
address. The first is a DUID-LLT, the second a DUID-LL, and the third a
DUID-UUID. :since:`Since 1.0.3`

::

   <network>
     <name>local6</name>
     <bridge name="virbr1"/>
     <forward mode="route" dev="eth1"/>
     <ip address="192.168.122.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.122.2" end="192.168.122.254"/>
       </dhcp>
     </ip>
     <ip family="ipv6" address="2001:db8:ca2:2::1" prefix="64">
       <dhcp>
         <host name="paul" ip="2001:db8:ca2:2:3::1"/>
         <host id="0:1:0:1:18:aa:62:fe:0:16:3e:44:55:66" ip="2001:db8:ca2:2:3::2"/>
         <host id="0:3:0:1:0:16:3e:11:22:33" name="ralph" ip="2001:db8:ca2:2:3::3"/>
         <host id="0:4:7e:7d:f0:7d:a8:bc:c5:d2:13:32:11:ed:16:ea:84:63"
           name="badbob" ip="2001:db8:ca2:2:3::4"/>
       </dhcp>
     </ip>
   </network>

Below is yet another IPv6 variation. This variation has only IPv6 defined with
DHCPv6 on the primary IPv6 network. A static link if defined for a second IPv6
network which will not be directly visible on the bridge interface but there
will be a static route defined for this network via the specified gateway. Note
that the gateway address must be directly reachable via (on the same subnet as)
one of the <ip> addresses defined for this <network>. :since:`Since 1.0.6`

::

   <network>
     <name>net7</name>
     <bridge name="virbr7"/>
     <forward mode="route"/>
     <ip family="ipv6" address="2001:db8:ca2:7::1" prefix="64">
       <dhcp>
         <range start="2001:db8:ca2:7::100" end="2001:db8:ca2::1ff"/>
         <host id="0:4:7e:7d:f0:7d:a8:bc:c5:d2:13:32:11:ed:16:ea:84:63"
           name="lucas" ip="2001:db8:ca2:2:3::4"/>
       </dhcp>
     </ip>
     <route family="ipv6" address="2001:db8:ca2:8::" prefix="64" gateway="2001:db8:ca2:7::4"/>
   </network>

Isolated network config
~~~~~~~~~~~~~~~~~~~~~~~

This variant provides a completely isolated private network for guests. The
guests can talk to each other, and the host OS, but cannot reach any other
machines on the LAN, due to the omission of the ``forward`` element in the XML
description.

::

   <network>
     <name>private</name>
     <bridge name="virbr2"/>
     <ip address="192.168.152.1" netmask="255.255.255.0">
       <dhcp>
         <range start="192.168.152.2" end="192.168.152.254"/>
       </dhcp>
     </ip>
     <ip family="ipv6" address="2001:db8:ca2:3::1" prefix="64"/>
   </network>

Isolated IPv6 network config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This variation of an isolated network defines only IPv6. Note that most of the
dhcp host definitions use an "id" (client id or DUID) since this has proven to
be a more reliable way of specifying the interface and its association with an
IPv6 address. The first is a DUID-LLT, the second a DUID-LL, and the third a
DUID-UUID. :since:`Since 1.0.3`

::

   <network>
     <name>sixnet</name>
     <bridge name="virbr6"/>
     <ip family="ipv6" address="2001:db8:ca2:6::1" prefix="64">
       <dhcp>
         <host name="peter" ip="2001:db8:ca2:6:6::1"/>
         <host id="0:1:0:1:18:aa:62:fe:0:16:3e:44:55:66" ip="2001:db8:ca2:6:6::2"/>
         <host id="0:3:0:1:0:16:3e:11:22:33" name="dariusz" ip="2001:db8:ca2:6:6::3"/>
         <host id="0:4:7e:7d:f0:7d:a8:bc:c5:d2:13:32:11:ed:16:ea:84:63"
           name="anita" ip="2001:db8:ca2:6:6::4"/>
       </dhcp>
     </ip>
   </network>

Using an existing host bridge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:since:`Since 0.9.4` This shows how to use a pre-existing host bridge "br0". The
guests will effectively be directly connected to the physical network (i.e.
their IP addresses will all be on the subnet of the physical network, and there
will be no restrictions on inbound or outbound connections).

::

   <network>
     <name>host-bridge</name>
     <forward mode="bridge"/>
     <bridge name="br0"/>
   </network>

Using a macvtap "direct" connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:since:`Since 0.9.4, QEMU and KVM only, requires Linux kernel 2.6.34 or newer`
This shows how to use macvtap to connect to the physical network directly
through one of a group of physical devices (without using a host bridge device).
As with the host bridge network, the guests will effectively be directly
connected to the physical network so their IP addresses will all be on the
subnet of the physical network, and there will be no restrictions on inbound or
outbound connections. Note that, due to a limitation in the implementation of
macvtap, these connections do not allow communication directly between the host
and the guests - if you require this you will either need the attached physical
switch to be operating in a mirroring mode (so that all traffic coming to the
switch is reflected back to the host's interface), or provide alternate means
for this communication (e.g. a second interface on each guest that is connected
to an isolated network). The other forward modes that use macvtap (private,
vepa, and passthrough) would be used in a similar fashion.

::

   <network>
     <name>direct-macvtap</name>
     <forward mode="bridge">
       <interface dev="eth20"/>
       <interface dev="eth21"/>
       <interface dev="eth22"/>
       <interface dev="eth23"/>
       <interface dev="eth24"/>
     </forward>
   </network>

Network config with no gateway addresses
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A valid network definition can contain no IPv4 or IPv6 addresses. Such a
definition can be used for a "very private" or "very isolated" network since it
will not be possible to communicate with the virtualization host via this
network. However, this virtual network interface can be used for communication
between virtual guest systems. This works for IPv4 and :since:`(Since 1.0.1)`
IPv6. However, the new ipv6='yes' must be added for guest-to-guest IPv6
communication.

::

   <network ipv6='yes'>
     <name>nogw</name>
     <uuid>7a3b7497-1ec7-8aef-6d5c-38dff9109e93</uuid>
     <bridge name="virbr2" stp="on" delay="0"/>
     <mac address='00:16:3E:5D:C7:9E'/>
   </network>
