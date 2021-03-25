.. role:: since

===============
Network Filters
===============

.. contents::

This page provides an introduction to libvirt's network filters, their goals,
concepts and XML format.

Goals and background
--------------------

The goal of the network filtering XML is to enable administrators of a
virtualized system to configure and enforce network traffic filtering rules on
virtual machines and manage the parameters of network traffic that virtual
machines are allowed to send or receive. The network traffic filtering rules are
applied on the host when a virtual machine is started. Since the filtering rules
cannot be circumvented from within the virtual machine, it makes them mandatory
from the point of view of a virtual machine user.

The network filter subsystem allows each virtual machine's network traffic
filtering rules to be configured individually on a per interface basis. The
rules are applied on the host when the virtual machine is started and can be
modified while the virtual machine is running. The latter can be achieved by
modifying the XML description of a network filter.

Multiple virtual machines can make use of the same generic network filter. When
such a filter is modified, the network traffic filtering rules of all running
virtual machines that reference this filter are updated.

Network filtering support is available :since:`since 0.8.1 (QEMU, KVM)`

Concepts
--------

The network traffic filtering subsystem enables configuration of network traffic
filtering rules on individual network interfaces that are configured for certain
types of network configurations. Supported network types are

-  ``network``

-  ``ethernet`` -- must be used in bridging mode

-  ``bridge``

The interface XML is used to reference a top-level filter. In the following
example, the interface description references the filter ``clean-traffic``.

::

   ...
   <devices>
     <interface type='bridge'>
       <mac address='00:16:3e:5d:c7:9e'/>
       <filterref filter='clean-traffic'/>
     </interface>
   </devices>
   ...

Network filters are written in XML and may either contain references to other
filters, contain rules for traffic filtering, or hold a combination of both. The
above referenced filter ``clean-traffic`` is a filter that only contains
references to other filters and no actual filtering rules. Since references to
other filters can be used, a *tree* of filters can be built. The
``clean-traffic`` filter can be viewed using the command
``virsh nwfilter-dumpxml clean-traffic``.

As previously mentioned, a single network filter can be referenced by multiple
virtual machines. Since interfaces will typically have individual parameters
associated with their respective traffic filtering rules, the rules described in
a filter XML can be parameterized with variables. In this case, the variable
name is used in the filter XML and the name and value are provided at the place
where the filter is referenced. In the following example, the interface
description has been extended with the parameter ``IP`` and a dotted IP address
as value.

::

   ...
   <devices>
     <interface type='bridge'>
       <mac address='00:16:3e:5d:c7:9e'/>
       <filterref filter='clean-traffic'>
         <parameter name='IP' value='10.0.0.1'/>
       </filterref>
     </interface>
   </devices>
   ...

In this particular example, the ``clean-traffic`` network traffic filter will be
instantiated with the IP address parameter 10.0.0.1 and enforce that the traffic
from this interface will always be using 10.0.0.1 as the source IP address,
which is one of the purposes of this particular filter.

Filtering chains
~~~~~~~~~~~~~~~~

Filtering rules are organized in filter chains. These chains can be thought of
as having a tree structure with packet filtering rules as entries in individual
chains (branches).

Packets start their filter evaluation in the ``root`` chain and can then
continue their evaluation in other chains, return from those chains back into
the ``root`` chain or be dropped or accepted by a filtering rule in one of the
traversed chains.

Libvirt's network filtering system automatically creates individual ``root``
chains for every virtual machine's network interface on which the user chooses
to activate traffic filtering. The user may write filtering rules that are
either directly instantiated in the ``root`` chain or may create
protocol-specific filtering chains for efficient evaluation of protocol-specific
rules. The following chains exist:

-  root

-  mac :since:`(since 0.9.8)`

-  stp (spanning tree protocol) :since:`(since 0.9.8)`

-  vlan (802.1Q) :since:`(since 0.9.8)`

-  arp, rarp

-  ipv4

-  ipv6

:since:`Since 0.9.8` multiple chains evaluating the ``mac``, ``stp``, ``vlan``,
``arp``, ``rarp``, ``ipv4``, or ``ipv6`` protocol can be created using the
protocol name only as a prefix in the chain's name. This for examples allows
chains with names ``arp-xyz`` or ``arp-test`` to be specified and have ARP
protocol packets evaluated in those chains.

The following filter shows an example of filtering ARP traffic in the ``arp``
chain.

::

   <filter name='no-arp-spoofing' chain='arp' priority='-500'>
     <uuid>f88f1932-debf-4aa1-9fbe-f10d3aa4bc95</uuid>
     <rule action='drop' direction='out' priority='300'>
       <mac match='no' srcmacaddr='$MAC'/>
     </rule>
     <rule action='drop' direction='out' priority='350'>
       <arp match='no' arpsrcmacaddr='$MAC'/>
     </rule>
     <rule action='drop' direction='out' priority='400'>
       <arp match='no' arpsrcipaddr='$IP'/>
     </rule>
     <rule action='drop' direction='in' priority='450'>
       <arp opcode='Reply'/>
       <arp match='no' arpdstmacaddr='$MAC'/>
     </rule>
     <rule action='drop' direction='in' priority='500'>
       <arp match='no' arpdstipaddr='$IP'/>
     </rule>
     <rule action='accept' direction='inout' priority='600'>
       <arp opcode='Request'/>
     </rule>
     <rule action='accept' direction='inout' priority='650'>
       <arp opcode='Reply'/>
     </rule>
     <rule action='drop' direction='inout' priority='1000'/>
   </filter>

The consequence of putting ARP-specific rules in the ``arp`` chain, rather than
for example in the ``root`` chain, is that packets for any other protocol than
ARP do not need to be evaluated by ARP protocol-specific rules. This improves
the efficiency of the traffic filtering. However, one must then pay attention to
only put filtering rules for the given protocol into the chain since any other
rules will not be evaluated, i.e., an IPv4 rule will not be evaluated in the ARP
chain since no IPv4 protocol packets will traverse the ARP chain.

Filtering chain priorities
~~~~~~~~~~~~~~~~~~~~~~~~~~

All chains are connected to the ``root`` chain. The order in which those chains
are accessed is influenced by the priority of the chain. The following table
shows the chains that can be assigned a priority and their default priorities.

============== ================
Chain (prefix) Default priority
============== ================
stp            -810
mac            -800
vlan           -750
ipv4           -700
ipv6           -600
arp            -500
rarp           -400
============== ================

A chain with a lower priority value is accessed before one with a higher value.

:since:`Since 0.9.8` the above listed chains can be assigned custom priorities
by writing a value in the range [-1000, 1000] into the priority (XML) attribute
in the filter node. The above example filter shows the default priority of -500
for ``arp`` chains.

Usage of variables in filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two variables names have so far been reserved for usage by the network traffic
filtering subsystem: ``MAC`` and ``IP``.

``MAC`` is the MAC address of the network interface. A filtering rule that
references this variable will automatically be instantiated with the MAC address
of the interface. This works without the user having to explicitly provide the
MAC parameter. Even though it is possible to specify the MAC parameter similar
to the IP parameter above, it is discouraged since libvirt knows what MAC
address an interface will be using.

The parameter ``IP`` represents the IP address that the operating system inside
the virtual machine is expected to use on the given interface. The ``IP``
parameter is special in so far as the libvirt daemon will try to determine the
IP address (and thus the IP parameter's value) that is being used on an
interface if the parameter is not explicitly provided but referenced. For
current limitations on IP address detection, consult the section on
`Limitations`_ on how to use this feature and what to expect when using it.

The above-shown network filer ``no-arp-spoofing`` is an example of a network
filter XML referencing the ``MAC`` and ``IP`` variables.

Note that referenced variables are always prefixed with the $ (dollar) sign. The
format of the value of a variable must be of the type expected by the filter
attribute in the XML. In the above example, the ``IP`` parameter must hold a
dotted IP address in decimal numbers format. Failure to provide the correct
value type will result in the filter not being instantiatable and will prevent a
virtual machine from starting or the interface from attaching when hotplugging
is used. The types that are expected for each XML attribute are shown below.

:since:`Since 0.9.8` variables can contain lists of elements, e.g., the variable
``IP`` can contain multiple IP addresses that are valid on a particular
interface. The notation for providing multiple elements for the IP variable is:

::

   ...
   <devices>
     <interface type='bridge'>
       <mac address='00:16:3e:5d:c7:9e'/>
       <filterref filter='clean-traffic'>
         <parameter name='IP' value='10.0.0.1'/>
         <parameter name='IP' value='10.0.0.2'/>
         <parameter name='IP' value='10.0.0.3'/>
       </filterref>
     </interface>
   </devices>
   ...

This then allows filters to enable multiple IP addresses per interface.
Therefore, with the list of IP address shown above, the following rule will
create 3 individual filtering rules, one for each IP address.

::

   ...
   <rule action='accept' direction='in' priority='500'>
     <tcp srpipaddr='$IP'/>
   </rule>
   ...

:since:`Since 0.9.10` it is possible to access individual elements of a variable
holding a list of elements. A filtering rule like the following accesses the 2nd
element of the variable DSTPORTS.

::

   ...
   <rule action='accept' direction='in' priority='500'>
     <udp dstportstart='$DSTPORTS[1]'/>
   </rule>
   ...

:since:`Since 0.9.10` it is possible to create filtering rules that instantiate
all combinations of rules from different lists using the notation of
``$VARIABLE[@<iterator ID>]``. The following rule allows a virtual machine to
receive traffic on a set of ports, which are specified in DSTPORTS, from the set
of source IP address specified in SRCIPADDRESSES. The rule generates all
combinations of elements of the variable DSTPORT with those of SRCIPADDRESSES by
using two independent iterators to access their elements.

::

   ...
   <rule action='accept' direction='in' priority='500'>
     <ip srcipaddr='$SRCIPADDRESSES[@1]' dstportstart='$DSTPORTS[@2]'/>
   </rule>
   ...

In an example we assign concrete values to SRCIPADDRESSES and DSTPORTS

::

   SRCIPADDRESSES = [ 10.0.0.1, 11.1.2.3 ]
   DSTPORTS = [ 80, 8080 ]

Accessing the variables using $SRCIPADDRESSES[@1] and $DSTPORTS[@2] would then
result in all combinations of addresses and ports being created:

::

   10.0.0.1, 80
   10.0.0.1, 8080
   11.1.2.3, 80
   11.1.2.3, 8080

Accessing the same variables using a single iterator, for example by using the
notation $SRCIPADDRESSES[@1] and $DSTPORTS[@1], would result in parallel access
to both lists and result in the following combinations:

::

   10.0.0.1, 80
   11.1.2.3, 8080

Further, the notation of $VARIABLE is short-hand for $VARIABLE[@0]. The former
notation always assumes the iterator with Id '0'.

Automatic IP address detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The detection of IP addresses used on a virtual machine's interface is
automatically activated if the variable ``IP`` is referenced but no value has
been assigned to it. :since:`Since 0.9.13` the variable ``CTRL_IP_LEARNING`` can
be used to specify the IP address learning method to use. Valid values are
``any``, ``dhcp``, or ``none``.

The value ``any`` means that libvirt may use any packet to determine the address
in use by a virtual machine, which is the default behavior if the variable
``CTRL_IP_LEARNING`` is not set. This method will only detect a single IP
address on an interface. Once a VM's IP address has been detected, its IP
network traffic will be locked to that address, if for example IP address
spoofing is prevented by one of its filters. In that case the user of the VM
will not be able to change the IP address on the interface inside the VM, which
would be considered IP address spoofing. When a VM is migrated to another host
or resumed after a suspend operation, the first packet sent by the VM will again
determine the IP address it can use on a particular interface.

A value of ``dhcp`` specifies that libvirt should only honor DHCP
server-assigned addresses with valid leases. This method supports the detection
and usage of multiple IP address per interface. When a VM is resumed after a
suspend operation, still valid IP address leases are applied to its filters.
Otherwise the VM is expected to again use DHCP to obtain new IP addresses. The
migration of a VM to another physical host requires that the VM again runs the
DHCP protocol.

Use of ``CTRL_IP_LEARNING=dhcp`` (DHCP snooping) provides additional
anti-spoofing security, especially when combined with a filter allowing only
trusted DHCP servers to assign addresses. To enable this, set the variable
``DHCPSERVER`` to the IP address of a valid DHCP server and provide filters that
use this variable to filter incoming DHCP responses.

When DHCP snooping is enabled and the DHCP lease expires, the VM will no longer
be able to use the IP address until it acquires a new, valid lease from a DHCP
server. If the VM is migrated, it must get a new valid DHCP lease to use an IP
address (e.g., by bringing the VM interface down and up again).

Note that automatic DHCP detection listens to the DHCP traffic the VM exchanges
with the DHCP server of the infrastructure. To avoid denial-of-service attacks
on libvirt, the evaluation of those packets is rate-limited, meaning that a VM
sending an excessive number of DHCP packets per second on an interface will not
have all of those packets evaluated and thus filters may not get adapted. Normal
DHCP client behavior is assumed to send a low number of DHCP packets per second.
Further, it is important to setup appropriate filters on all VMs in the
infrastructure to avoid them being able to send DHCP packets. Therefore VMs must
either be prevented from sending UDP and TCP traffic from port 67 to port 68 or
the ``DHCPSERVER`` variable should be used on all VMs to restrict DHCP server
messages to only be allowed to originate from trusted DHCP servers. At the same
time anti-spoofing prevention must be enabled on all VMs in the subnet.

If ``CTRL_IP_LEARNING`` is set to ``none``, libvirt does not do IP address
learning and referencing ``IP`` without assigning it an explicit value is an
error.

The following XML provides an example for the activation of IP address learning
using the DHCP snooping method:

::

   <interface type='bridge'>
     <source bridge='virbr0'/>
     <filterref filter='clean-traffic'>
       <parameter name='CTRL_IP_LEARNING' value='dhcp'/>
     </filterref>
   </interface>

Reserved Variables
~~~~~~~~~~~~~~~~~~

The following table lists reserved variables in use by libvirt.

+------------------+----------------------------------------------------------+
| Variable Name    | Semantics                                                |
+==================+==========================================================+
| MAC              | The MAC address of the interface                         |
+------------------+----------------------------------------------------------+
| IP               | The list of IP addresses in use by an interface          |
+------------------+----------------------------------------------------------+
| IPV6             | The list of IPV6 addresses in use by an interface        |
+------------------+----------------------------------------------------------+
| DHCPSERVER       | The list of IP addresses of trusted DHCP servers         |
+------------------+----------------------------------------------------------+
| DHCPSERVERV6     | Not currently implemented: The list of IPv6 addresses of |
|                  | trusted DHCP servers                                     |
+------------------+----------------------------------------------------------+
| CTRL_IP_LEARNING | The choice of the IP address detection mode              |
+------------------+----------------------------------------------------------+

Element and attribute overview
------------------------------

The root element required for all network filters is named ``filter`` with two
possible attributes. The ``name`` attribute provides a unique name of the given
filter. The ``chain`` attribute is optional but allows certain filters to be
better organized for more efficient processing by the firewall subsystem of the
underlying host. Currently the system only supports the chains
``root,       ipv4, ipv6, arp and rarp``.

References to other filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Any filter may hold references to other filters. Individual filters may be
referenced multiple times in a filter tree but references between filters must
not introduce loops (directed acyclic graph).

The following shows the XML of the ``clean-traffic`` network filter referencing
several other filters.

::

   <filter name='clean-traffic'>
     <uuid>6ef53069-ba34-94a0-d33d-17751b9b8cb1</uuid>
     <filterref filter='no-mac-spoofing'/>
     <filterref filter='no-ip-spoofing'/>
     <filterref filter='allow-incoming-ipv4'/>
     <filterref filter='no-arp-spoofing'/>
     <filterref filter='no-other-l2-traffic'/>
     <filterref filter='qemu-announce-self'/>
   </filter>

To reference another filter, the XML node ``filterref`` needs to be provided
inside a ``filter`` node. This node must have the attribute ``filter`` whose
value contains the name of the filter to be referenced.

New network filters can be defined at any time and may contain references to
network filters that are not known to libvirt, yet. However, once a virtual
machine is started or a network interface referencing a filter is to be
hotplugged, all network filters in the filter tree must be available. Otherwise
the virtual machine will not start or the network interface cannot be attached.

Filter rules
~~~~~~~~~~~~

The following XML shows a simple example of a network traffic filter
implementing a rule to drop traffic if the IP address (provided through the
value of the variable IP) in an outgoing IP packet is not the expected one, thus
preventing IP address spoofing by the VM.

::

   <filter name='no-ip-spoofing' chain='ipv4'>
     <uuid>fce8ae33-e69e-83bf-262e-30786c1f8072</uuid>
     <rule action='drop' direction='out' priority='500'>
       <ip match='no' srcipaddr='$IP'/>
     </rule>
   </filter>

A traffic filtering rule starts with the ``rule`` node. This node may contain up
to three attributes

-  action -- mandatory; must either be ``drop`` (matching the rule silently
   discards the packet with no further analysis), ``reject`` (matching the rule
   generates an ICMP reject message with no further analysis) :since:`(since
   0.9.0)` , ``accept`` (matching the rule accepts the packet with no further
   analysis), ``return`` (matching the rule passes this filter, but returns
   control to the calling filter for further analysis) :since:`(since 0.9.7)` ,
   or ``continue`` (matching the rule goes on to the next rule for further
   analysis) :since:`(since 0.9.7)` .

-  direction -- mandatory; must either be ``in``, ``out`` or ``inout`` if the
   rule is for incoming, outgoing or incoming-and-outgoing traffic

-  priority -- optional; the priority of the rule controls the order in which
   the rule will be instantiated relative to other rules. Rules with lower value
   will be instantiated before rules with higher values. Valid values are in the
   range of 0 to 1000. :since:`Since 0.9.8` this has been extended to cover the
   range of -1000 to 1000. If this attribute is not provided, priority 500 will
   automatically be assigned.

   Note that filtering rules in the ``root`` chain are sorted with filters
   connected to the ``root`` chain following their priorities. This allows to
   interleave filtering rules with access to filter chains. (See also section on
   `Filtering chain priorities`_ .)

-  statematch -- optional; possible values are '0' or 'false' to turn the
   underlying connection state matching off; default is 'true'

   Also read the section on `Advanced Filter Configuration Topics`_.

The above example indicates that the traffic of type ``ip`` will be associated
with the chain 'ipv4' and the rule will have priority 500. If for example
another filter is referenced whose traffic of type ``ip`` is also associated
with the chain 'ipv4' then that filter's rules will be ordered relative to the
priority 500 of the shown rule.

A rule may contain a single rule for filtering of traffic. The above example
shows that traffic of type ``ip`` is to be filtered.

Supported protocols
^^^^^^^^^^^^^^^^^^^

The following sections enumerate the list of protocols that are supported by the
network filtering subsystem. The type of traffic a rule is supposed to filter on
is provided in the ``rule`` node as a nested node. Depending on the traffic type
a rule is filtering, the attributes are different. The above example showed the
single attribute ``srcipaddr`` that is valid inside the ``ip`` traffic filtering
node. The following sections show what attributes are valid and what type of
data they are expecting. The following datatypes are available:

-  UINT8 : 8 bit integer; range 0-255

-  UINT16: 16 bit integer; range 0-65535

-  MAC_ADDR: MAC address in dotted decimal format, i.e., 00:11:22:33:44:55

-  MAC_MASK: MAC address mask in MAC address format, i.e., FF:FF:FF:FC:00:00

-  IP_ADDR: IP address in dotted decimal format, i.e., 10.1.2.3

-  IP_MASK: IP address mask in either dotted decimal format (255.255.248.0) or
   CIDR mask (0-32)

-  IPV6_ADDR: IPv6 address in numbers format, i.e., FFFF::1

-  IPV6_MASK: IPv6 mask in numbers format (FFFF:FFFF:FC00::) or CIDR mask
   (0-128)

-  STRING: A string

-  BOOLEAN: 'true', 'yes', '1' or 'false', 'no', '0'

-  IPSETFLAGS: The source and destination flags of the ipset described by up to
   6 'src' or 'dst' elements selecting features from either the source or
   destination part of the packet header; example: src,src,dst. The number of
   'selectors' to provide here depends on the type of ipset that is referenced.

Every attribute except for those of type IP_MASK or IPV6_MASK can be negated
using the ``match`` attribute with value ``no``. Multiple negated attributes may
be grouped together. The following XML fragment shows such an example using
abstract attributes.

::

   [...]
   <rule action='drop' direction='in'>
     <protocol match='no' attribute1='value1' attribute2='value2'/>
     <protocol attribute3='value3'/>
   </rule>
   [...]

Rules perform a logical AND evaluation on all values of the given protocol
attributes. Thus, if a single attribute's value does not match the one given in
the rule, the whole rule will be skipped during evaluation. Therefore, in the
above example incoming traffic will only be dropped if the protocol property
attribute1 does not match value1 AND the protocol property attribute2 does not
match value2 AND the protocol property attribute3 matches value3.

MAC (Ethernet)
''''''''''''''

Protocol ID: ``mac``

Note: Rules of this type should go into the ``root`` chain.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of sender       |
+-------------------------+-------------------------+-------------------------+
| dstmacaddr              | MAC_ADDR                | MAC address of          |
|                         |                         | destination             |
+-------------------------+-------------------------+-------------------------+
| dstmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of destination  |
+-------------------------+-------------------------+-------------------------+
| protocolid              | UINT16 (0x600-0xffff),  | Layer 3 protocol ID     |
|                         | STRING                  |                         |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+

Valid Strings for ``protocolid`` are: arp, rarp, ipv4, ipv6

::

   [...]
   <mac match='no' srcmacaddr='$MAC'/>
   [...]

VLAN (802.1Q) :since:`(Since 0.9.8)`
''''''''''''''''''''''''''''''''''''

Protocol ID: ``vlan``

Note: Rules of this type should go either into the ``root`` or ``vlan`` chain.

+----------------+-----------------------------+-----------------------------+
| Attribute      | Datatype                    | Semantics                   |
+================+=============================+=============================+
| srcmacaddr     | MAC_ADDR                    | MAC address of sender       |
+----------------+-----------------------------+-----------------------------+
| srcmacmask     | MAC_MASK                    | Mask applied to MAC address |
|                |                             | of sender                   |
+----------------+-----------------------------+-----------------------------+
| dstmacaddr     | MAC_ADDR                    | MAC address of destination  |
+----------------+-----------------------------+-----------------------------+
| dstmacmask     | MAC_MASK                    | Mask applied to MAC address |
|                |                             | of destination              |
+----------------+-----------------------------+-----------------------------+
| vlanid         | UINT16 (0x0-0xfff, 0 -      | VLAN ID                     |
|                | 4095)                       |                             |
+----------------+-----------------------------+-----------------------------+
| encap-protocol | UINT16 (0x03c-0xfff),       | Encapsulated layer 3        |
|                | String                      | protocol ID                 |
+----------------+-----------------------------+-----------------------------+
| comment        | STRING                      | text with max. 256          |
|                |                             | characters                  |
+----------------+-----------------------------+-----------------------------+

Valid Strings for ``encap-protocol`` are: arp, ipv4, ipv6

STP (Spanning Tree Protocol) (Since 0.9.8)
''''''''''''''''''''''''''''''''''''''''''

Protocol ID: ``stp``

Note: Rules of this type should go either into the ``root`` or ``stp`` chain.

=================== =========== =====================================
Attribute           Datatype    Semantics
=================== =========== =====================================
srcmacaddr          MAC_ADDR    MAC address of sender
srcmacmask          MAC_MASK    Mask applied to MAC address of sender
type                UINT8       Bridge Protocol Data Unit (BPDU) type
flags               UINT8       BPDU flag
root-priority       UINT16      Root priority (range start)
root-priority-hi    UINT16      Root priority range end
root-address        MAC_ADDRESS Root MAC address
root-address-mask   MAC_MASK    Root MAC address mask
root-cost           UINT32      Root path cost (range start)
root-cost-hi        UINT32      Root path cost range end
sender-priority     UINT16      Sender priority (range start)
sender-priority-hi  UINT16      Sender priority range end
sender-address      MAC_ADDRESS BPDU sender MAC address
sender-address-mask MAC_MASK    BPDU sender MAC address mask
port                UINT16      Port identifier (range start)
port_hi             UINT16      Port identifier range end
msg-age             UINT16      Message age timer (range start)
msg-age-hi          UINT16      Message age timer range end
max-age             UINT16      Maximum age timer (range start)
max-age-hi          UINT16      Maximum age timer range end
hello-time          UINT16      Hello time timer (range start)
hello-time-hi       UINT16      Hello time timer range end
forward-delay       UINT16      Forward delay (range start)
forward-delay-hi    UINT16      Forward delay range end
comment             STRING      text with max. 256 characters
=================== =========== =====================================

ARP/RARP
''''''''

Protocol ID: ``arp`` or ``rarp``

Note: Rules of this type should either go into the ``root`` or ``arp/rarp``
chain.

+-----------------------------+----------------+-----------------------------+
| Attribute                   | Datatype       | Semantics                   |
+=============================+================+=============================+
| srcmacaddr                  | MAC_ADDR       | MAC address of sender       |
+-----------------------------+----------------+-----------------------------+
| srcmacmask                  | MAC_MASK       | Mask applied to MAC address |
|                             |                | of sender                   |
+-----------------------------+----------------+-----------------------------+
| dstmacaddr                  | MAC_ADDR       | MAC address of destination  |
+-----------------------------+----------------+-----------------------------+
| dstmacmask                  | MAC_MASK       | Mask applied to MAC address |
|                             |                | of destination              |
+-----------------------------+----------------+-----------------------------+
| hwtype                      | UINT16         | Hardware type               |
+-----------------------------+----------------+-----------------------------+
| protocoltype                | UINT16         | Protocol type               |
+-----------------------------+----------------+-----------------------------+
| opcode                      | UINT16, STRING | Opcode                      |
+-----------------------------+----------------+-----------------------------+
| arpsrcmacaddr               | MAC_ADDR       | Source MAC address in       |
|                             |                | ARP/RARP packet             |
+-----------------------------+----------------+-----------------------------+
| arpdstmacaddr               | MAC_ADDR       | Destination MAC address in  |
|                             |                | ARP/RARP packet             |
+-----------------------------+----------------+-----------------------------+
| arpsrcipaddr                | IP_ADDR        | Source IP address in        |
|                             |                | ARP/RARP packet             |
+-----------------------------+----------------+-----------------------------+
| arpsrcipmask :since:`(Since | IP_MASK        | Source IP mask              |
| 1.2.3)`                     |                |                             |
+-----------------------------+----------------+-----------------------------+
| arpdstipaddr                | IP_ADDR        | Destination IP address in   |
|                             |                | ARP/RARP packet             |
+-----------------------------+----------------+-----------------------------+
| arpdstipmask :since:`(Since | IP_MASK        | Destination IP mask         |
| 1.2.3)`                     |                |                             |
+-----------------------------+----------------+-----------------------------+
| comment :since:`(Since      | STRING         | text with max. 256          |
| 0.8.5)`                     |                | characters                  |
+-----------------------------+----------------+-----------------------------+
| gratuitous :since:`(Since   | BOOLEAN        | boolean indicating whether  |
| 0.9.2)`                     |                | to check for gratuitous ARP |
|                             |                | packet                      |
+-----------------------------+----------------+-----------------------------+

Valid strings for the ``Opcode`` field are: Request, Reply, Request_Reverse,
Reply_Reverse, DRARP_Request, DRARP_Reply, DRARP_Error, InARP_Request, ARP_NAK

IPv4
''''

Protocol ID: ``ip``

Note: Rules of this type should either go into the ``root`` or ``ipv4`` chain.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of sender       |
+-------------------------+-------------------------+-------------------------+
| dstmacaddr              | MAC_ADDR                | MAC address of          |
|                         |                         | destination             |
+-------------------------+-------------------------+-------------------------+
| dstmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of destination  |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IP_ADDR                 | Source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IP_MASK                 | Mask applied to source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IP_ADDR                 | Destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IP_MASK                 | Mask applied to         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| protocol                | UINT8, STRING           | Layer 4 protocol        |
|                         |                         | identifier              |
+-------------------------+-------------------------+-------------------------+
| srcportstart            | UINT16                  | Start of range of valid |
|                         |                         | source ports; requires  |
|                         |                         | ``protocol``            |
+-------------------------+-------------------------+-------------------------+
| srcportend              | UINT16                  | End of range of valid   |
|                         |                         | source ports; requires  |
|                         |                         | ``protocol``            |
+-------------------------+-------------------------+-------------------------+
| dstportstart            | UINT16                  | Start of range of valid |
|                         |                         | destination ports;      |
|                         |                         | requires ``protocol``   |
+-------------------------+-------------------------+-------------------------+
| dstportend              | UINT16                  | End of range of valid   |
|                         |                         | destination ports;      |
|                         |                         | requires ``protocol``   |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+

Valid strings for ``protocol`` are: tcp, udp, udplite, esp, ah, icmp, igmp, sctp

IPv6
''''

Protocol ID: ``ipv6``

Note: Rules of this type should either go into the ``root`` or ``ipv6`` chain.

+--------------------------------+-----------+--------------------------------+
| Attribute                      | Datatype  | Semantics                      |
+================================+===========+================================+
| srcmacaddr                     | MAC_ADDR  | MAC address of sender          |
+--------------------------------+-----------+--------------------------------+
| srcmacmask                     | MAC_MASK  | Mask applied to MAC address of |
|                                |           | sender                         |
+--------------------------------+-----------+--------------------------------+
| dstmacaddr                     | MAC_ADDR  | MAC address of destination     |
+--------------------------------+-----------+--------------------------------+
| dstmacmask                     | MAC_MASK  | Mask applied to MAC address of |
|                                |           | destination                    |
+--------------------------------+-----------+--------------------------------+
| srcipaddr                      | IPV6_ADDR | Source IPv6 address            |
+--------------------------------+-----------+--------------------------------+
| srcipmask                      | IPV6_MASK | Mask applied to source IPv6    |
|                                |           | address                        |
+--------------------------------+-----------+--------------------------------+
| dstipaddr                      | IPV6_ADDR | Destination IPv6 address       |
+--------------------------------+-----------+--------------------------------+
| dstipmask                      | IPV6_MASK | Mask applied to destination    |
|                                |           | IPv6 address                   |
+--------------------------------+-----------+--------------------------------+
| protocol                       | UINT8     | Layer 4 protocol identifier    |
+--------------------------------+-----------+--------------------------------+
| srcportstart                   | UINT16    | Start of range of valid source |
|                                |           | ports; requires ``protocol``   |
+--------------------------------+-----------+--------------------------------+
| srcportend                     | UINT16    | End of range of valid source   |
|                                |           | ports; requires ``protocol``   |
+--------------------------------+-----------+--------------------------------+
| dstportstart                   | UINT16    | Start of range of valid        |
|                                |           | destination ports; requires    |
|                                |           | ``protocol``                   |
+--------------------------------+-----------+--------------------------------+
| dstportend                     | UINT16    | End of range of valid          |
|                                |           | destination ports; requires    |
|                                |           | ``protocol``                   |
+--------------------------------+-----------+--------------------------------+
| type :since:`(Since 1.2.12)`   | UINT8     | ICMPv6 type; requires          |
|                                |           | ``protocol`` to be set to      |
|                                |           | ``icmpv6``                     |
+--------------------------------+-----------+--------------------------------+
| typeend :since:`(Since         | UINT8     | ICMPv6 type end of range;      |
| 1.2.12)`                       |           | requires ``protocol`` to be    |
|                                |           | set to ``icmpv6``              |
+--------------------------------+-----------+--------------------------------+
| code :since:`(Since 1.2.12)`   | UINT8     | ICMPv6 code; requires          |
|                                |           | ``protocol`` to be set to      |
|                                |           | ``icmpv6``                     |
+--------------------------------+-----------+--------------------------------+
| code :since:`(Since 1.2.12)`   | UINT8     | ICMPv6 code end of range;      |
|                                |           | requires ``protocol`` to be    |
|                                |           | set to ``icmpv6``              |
+--------------------------------+-----------+--------------------------------+
| comment :since:`(Since 0.8.5)` | STRING    | text with max. 256 characters  |
+--------------------------------+-----------+--------------------------------+

Valid strings for ``protocol`` are: tcp, udp, udplite, esp, ah, icmpv6, sctp

TCP/UDP/SCTP
''''''''''''

Protocol ID: ``tcp``, ``udp``, ``sctp``

Note: The chain parameter is ignored for this type of traffic and should either
be omitted or set to ``root``.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IP_ADDR                 | Source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IP_MASK                 | Mask applied to source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IP_ADDR                 | Destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IP_MASK                 | Mask applied to         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| srcipfrom               | IP_ADDR                 | Start of range of       |
|                         |                         | source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipto                 | IP_ADDR                 | End of range of source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipfrom               | IP_ADDR                 | Start of range of       |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipto                 | IP_ADDR                 | End of range of         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| srcportstart            | UINT16                  | Start of range of valid |
|                         |                         | source ports            |
+-------------------------+-------------------------+-------------------------+
| srcportend              | UINT16                  | End of range of valid   |
|                         |                         | source ports            |
+-------------------------+-------------------------+-------------------------+
| dstportstart            | UINT16                  | Start of range of valid |
|                         |                         | destination ports       |
+-------------------------+-------------------------+-------------------------+
| dstportend              | UINT16                  | End of range of valid   |
|                         |                         | destination ports       |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+
| state :since:`(Since    | STRING                  | comma separated list of |
| 0.8.5)`                 |                         | NEW,ESTA                |
|                         |                         | BLISHED,RELATED,INVALID |
|                         |                         | or NONE                 |
+-------------------------+-------------------------+-------------------------+
| flags :since:`(Since    | STRING                  | TCP-only: format of     |
| 0.9.1)`                 |                         | mask/flags with mask    |
|                         |                         | and flags each being a  |
|                         |                         | comma separated list of |
|                         |                         | SYN,ACK,URG,PSH,FIN,RST |
|                         |                         | or NONE or ALL          |
+-------------------------+-------------------------+-------------------------+
| ipset :since:`(Since    | STRING                  | The name of an IPSet    |
| 0.9.13)`                |                         | managed outside of      |
|                         |                         | libvirt                 |
+-------------------------+-------------------------+-------------------------+
| ipsetflags              | IPSETFLAGS              | flags for the IPSet;    |
| :since:`(Since 0.9.13)` |                         | requires ipset          |
|                         |                         | attribute               |
+-------------------------+-------------------------+-------------------------+

ICMP
''''

Protocol ID: ``icmp``

Note: The chain parameter is ignored for this type of traffic and should either
be omitted or set to ``root``.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of sender       |
+-------------------------+-------------------------+-------------------------+
| dstmacaddr              | MAC_ADDR                | MAC address of          |
|                         |                         | destination             |
+-------------------------+-------------------------+-------------------------+
| dstmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of destination  |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IP_ADDR                 | Source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IP_MASK                 | Mask applied to source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IP_ADDR                 | Destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IP_MASK                 | Mask applied to         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| srcipfrom               | IP_ADDR                 | Start of range of       |
|                         |                         | source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipto                 | IP_ADDR                 | End of range of source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipfrom               | IP_ADDR                 | Start of range of       |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipto                 | IP_ADDR                 | End of range of         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| type                    | UINT16                  | ICMP type               |
+-------------------------+-------------------------+-------------------------+
| code                    | UINT16                  | ICMP code               |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+
| state :since:`(Since    | STRING                  | comma separated list of |
| 0.8.5)`                 |                         | NEW,ESTA                |
|                         |                         | BLISHED,RELATED,INVALID |
|                         |                         | or NONE                 |
+-------------------------+-------------------------+-------------------------+
| ipset :since:`(Since    | STRING                  | The name of an IPSet    |
| 0.9.13)`                |                         | managed outside of      |
|                         |                         | libvirt                 |
+-------------------------+-------------------------+-------------------------+
| ipsetflags              | IPSETFLAGS              | flags for the IPSet;    |
| :since:`(Since 0.9.13)` |                         | requires ipset          |
|                         |                         | attribute               |
+-------------------------+-------------------------+-------------------------+

IGMP, ESP, AH, UDPLITE, 'ALL'
'''''''''''''''''''''''''''''

Protocol ID: ``igmp``, ``esp``, ``ah``, ``udplite``, ``all``

Note: The chain parameter is ignored for this type of traffic and should either
be omitted or set to ``root``.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of sender       |
+-------------------------+-------------------------+-------------------------+
| dstmacaddr              | MAC_ADDR                | MAC address of          |
|                         |                         | destination             |
+-------------------------+-------------------------+-------------------------+
| dstmacmask              | MAC_MASK                | Mask applied to MAC     |
|                         |                         | address of destination  |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IP_ADDR                 | Source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IP_MASK                 | Mask applied to source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IP_ADDR                 | Destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IP_MASK                 | Mask applied to         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| srcipfrom               | IP_ADDR                 | Start of range of       |
|                         |                         | source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipto                 | IP_ADDR                 | End of range of source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipfrom               | IP_ADDR                 | Start of range of       |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipto                 | IP_ADDR                 | End of range of         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+
| state :since:`(Since    | STRING                  | comma separated list of |
| 0.8.5)`                 |                         | NEW,ESTA                |
|                         |                         | BLISHED,RELATED,INVALID |
|                         |                         | or NONE                 |
+-------------------------+-------------------------+-------------------------+
| ipset :since:`(Since    | STRING                  | The name of an IPSet    |
| 0.9.13)`                |                         | managed outside of      |
|                         |                         | libvirt                 |
+-------------------------+-------------------------+-------------------------+
| ipsetflags              | IPSETFLAGS              | flags for the IPSet;    |
| :since:`(Since 0.9.13)` |                         | requires ipset          |
|                         |                         | attribute               |
+-------------------------+-------------------------+-------------------------+

TCP/UDP/SCTP over IPV6
''''''''''''''''''''''

Protocol ID: ``tcp-ipv6``, ``udp-ipv6``, ``sctp-ipv6``

Note: The chain parameter is ignored for this type of traffic and should either
be omitted or set to ``root``.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IPV6_ADDR               | Source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IPV6_MASK               | Mask applied to source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IPV6_ADDR               | Destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IPV6_MASK               | Mask applied to         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| srcipfrom               | IPV6_ADDR               | Start of range of       |
|                         |                         | source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipto                 | IPV6_ADDR               | End of range of source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipfrom               | IPV6_ADDR               | Start of range of       |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipto                 | IPV6_ADDR               | End of range of         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| srcportstart            | UINT16                  | Start of range of valid |
|                         |                         | source ports            |
+-------------------------+-------------------------+-------------------------+
| srcportend              | UINT16                  | End of range of valid   |
|                         |                         | source ports            |
+-------------------------+-------------------------+-------------------------+
| dstportstart            | UINT16                  | Start of range of valid |
|                         |                         | destination ports       |
+-------------------------+-------------------------+-------------------------+
| dstportend              | UINT16                  | End of range of valid   |
|                         |                         | destination ports       |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+
| state :since:`(Since    | STRING                  | comma separated list of |
| 0.8.5)`                 |                         | NEW,ESTA                |
|                         |                         | BLISHED,RELATED,INVALID |
|                         |                         | or NONE                 |
+-------------------------+-------------------------+-------------------------+
| flags :since:`(Since    | STRING                  | TCP-only: format of     |
| 0.9.1)`                 |                         | mask/flags with mask    |
|                         |                         | and flags each being a  |
|                         |                         | comma separated list of |
|                         |                         | SYN,ACK,URG,PSH,FIN,RST |
|                         |                         | or NONE or ALL          |
+-------------------------+-------------------------+-------------------------+
| ipset :since:`(Since    | STRING                  | The name of an IPSet    |
| 0.9.13)`                |                         | managed outside of      |
|                         |                         | libvirt                 |
+-------------------------+-------------------------+-------------------------+
| ipsetflags              | IPSETFLAGS              | flags for the IPSet;    |
| :since:`(Since 0.9.13)` |                         | requires ipset          |
|                         |                         | attribute               |
+-------------------------+-------------------------+-------------------------+

ICMPv6
''''''

Protocol ID: ``icmpv6``

Note: The chain parameter is ignored for this type of traffic and should either
be omitted or set to ``root``.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IPV6_ADDR               | Source IPv6 address     |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IPV6_MASK               | Mask applied to source  |
|                         |                         | IPv6 address            |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IPV6_ADDR               | Destination IPv6        |
|                         |                         | address                 |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IPV6_MASK               | Mask applied to         |
|                         |                         | destination IPv6        |
|                         |                         | address                 |
+-------------------------+-------------------------+-------------------------+
| srcipfrom               | IPV6_ADDR               | Start of range of       |
|                         |                         | source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipto                 | IPV6_ADDR               | End of range of source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipfrom               | IPV6_ADDR               | Start of range of       |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipto                 | IPV6_ADDR               | End of range of         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| type                    | UINT16                  | ICMPv6 type             |
+-------------------------+-------------------------+-------------------------+
| code                    | UINT16                  | ICMPv6 code             |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+
| state :since:`(Since    | STRING                  | comma separated list of |
| 0.8.5)`                 |                         | NEW,ESTA                |
|                         |                         | BLISHED,RELATED,INVALID |
|                         |                         | or NONE                 |
+-------------------------+-------------------------+-------------------------+
| ipset :since:`(Since    | STRING                  | The name of an IPSet    |
| 0.9.13)`                |                         | managed outside of      |
|                         |                         | libvirt                 |
+-------------------------+-------------------------+-------------------------+
| ipsetflags              | IPSETFLAGS              | flags for the IPSet;    |
| :since:`(Since 0.9.13)` |                         | requires ipset          |
|                         |                         | attribute               |
+-------------------------+-------------------------+-------------------------+

ESP, AH, UDPLITE, 'ALL' over IPv6
'''''''''''''''''''''''''''''''''

Protocol ID: ``esp-ipv6``, ``ah-ipv6``, ``udplite-ipv6``, ``all-ipv6``

Note: The chain parameter is ignored for this type of traffic and should either
be omitted or set to ``root``.

+-------------------------+-------------------------+-------------------------+
| Attribute               | Datatype                | Semantics               |
+=========================+=========================+=========================+
| srcmacaddr              | MAC_ADDR                | MAC address of sender   |
+-------------------------+-------------------------+-------------------------+
| srcipaddr               | IPV6_ADDR               | Source IPv6 address     |
+-------------------------+-------------------------+-------------------------+
| srcipmask               | IPV6_MASK               | Mask applied to source  |
|                         |                         | IPv6 address            |
+-------------------------+-------------------------+-------------------------+
| dstipaddr               | IPV6_ADDR               | Destination IPv6        |
|                         |                         | address                 |
+-------------------------+-------------------------+-------------------------+
| dstipmask               | IPV6_MASK               | Mask applied to         |
|                         |                         | destination IPv6        |
|                         |                         | address                 |
+-------------------------+-------------------------+-------------------------+
| srcipfrom               | IPV6_ADDR               | Start of range of       |
|                         |                         | source IP address       |
+-------------------------+-------------------------+-------------------------+
| srcipto                 | IPV6_ADDR               | End of range of source  |
|                         |                         | IP address              |
+-------------------------+-------------------------+-------------------------+
| dstipfrom               | IPV6_ADDR               | Start of range of       |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dstipto                 | IPV6_ADDR               | End of range of         |
|                         |                         | destination IP address  |
+-------------------------+-------------------------+-------------------------+
| dscp                    | UINT8 (0x0-0x3f, 0 -    | Differentiated Services |
|                         | 63)                     | Code Point              |
+-------------------------+-------------------------+-------------------------+
| comment :since:`(Since  | STRING                  | text with max. 256      |
| 0.8.5)`                 |                         | characters              |
+-------------------------+-------------------------+-------------------------+
| state :since:`(Since    | STRING                  | comma separated list of |
| 0.8.5)`                 |                         | NEW,ESTA                |
|                         |                         | BLISHED,RELATED,INVALID |
|                         |                         | or NONE                 |
+-------------------------+-------------------------+-------------------------+
| ipset :since:`(Since    | STRING                  | The name of an IPSet    |
| 0.9.13)`                |                         | managed outside of      |
|                         |                         | libvirt                 |
+-------------------------+-------------------------+-------------------------+
| ipsetflags              | IPSETFLAGS              | flags for the IPSet;    |
| :since:`(Since 0.9.13)` |                         | requires ipset          |
|                         |                         | attribute               |
+-------------------------+-------------------------+-------------------------+

Advanced Filter Configuration Topics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following sections discuss advanced filter configuration topics.

Connection tracking
^^^^^^^^^^^^^^^^^^^

The network filtering subsystem (on Linux) makes use of the connection tracking
support of iptables. This helps in enforcing the directionality of network
traffic (state match) as well as counting and limiting the number of
simultaneous connections towards a VM. As an example, if a VM has TCP port 8080
open as a server, clients may connect to the VM on port 8080. Connection
tracking and enforcement of directionality then prevents the VM from initiating
a connection from (TCP client) port 8080 to the host back to a remote host. More
importantly, tracking helps to prevent remote attackers from establishing a
connection back to a VM. For example, if the user inside the VM established a
connection to port 80 on an attacker site, then the attacker will not be able to
initiate a connection from TCP port 80 back towards the VM. By default the
connection state match that enables connection tracking and then enforcement of
directionality of traffic is turned on.

The following shows an example XML fragment where this feature has been turned
off for incoming connections to TCP port 12345.

::

   [...]
   <rule direction='in' action='accept' statematch='false'>
     <tcp dstportstart='12345'/>
   </rule>
   [...]

This now allows incoming traffic to TCP port 12345, but would also enable the
initiation from (client) TCP port 12345 within the VM, which may or may not be
desirable.

Limiting Number of Connections
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To limit the number of connections a VM may establish, a rule must be provided
that sets a limit of connections for a given type of traffic. If for example a
VM is supposed to be allowed to only ping one other IP address at a time and is
supposed to have only one active incoming ssh connection at a time, the
following XML fragment can be used to achieve this.

::

   [...]
   <rule action='drop' direction='in' priority='400'>
     <tcp connlimit-above='1'/>
   </rule>
   <rule action='accept' direction='in' priority='500'>
     <tcp dstportstart='22'/>
   </rule>
   <rule action='drop' direction='out' priority='400'>
     <icmp connlimit-above='1'/>
   </rule>
   <rule action='accept' direction='out' priority='500'>
     <icmp/>
   </rule>
   <rule action='accept' direction='out' priority='500'>
     <udp dstportstart='53'/>
   </rule>
   <rule action='drop' direction='inout' priority='1000'>
     <all/>
   </rule>
   [...]

Note that the rule for the limit has to logically appear before the rule for
accepting the traffic.

An additional rule for letting DNS traffic to port 22 go out the VM has been
added to avoid ssh sessions not getting established for reasons related to DNS
lookup failures by the ssh daemon. Leaving this rule out may otherwise lead to
fun-filled debugging joy (symptom: ssh client seems to hang while trying to
connect).

Lot of care must be taken with timeouts related to tracking of traffic. An ICMP
ping that the user may have terminated inside the VM may have a long timeout in
the host's connection tracking system and therefore not allow another ICMP ping
to go through for a while. Therefore, the timeouts have to be tuned in the
host's sysfs, i.e.,

::

   echo 3 > /proc/sys/net/netfilter/nf_conntrack_icmp_timeout

sets the ICMP connection tracking timeout to 3 seconds. The effect of this is
that once one ping is terminated, another one can start after 3 seconds.

Further, we want to point out that a client that for whatever reason has not
properly closed a TCP connection may cause a connection to be held open for a
longer period of time, depending to what timeout the ``TCP established`` state
timeout has been set to on the host. Also, idle connections may time out in the
connection tracking system but can be reactivated once packets are exchanged.
However, a newly initiated connection may force an idle connection into TCP
backoff if the number of allowed connections is set to a too low limit, the new
connection is established and hits (not exceeds) the limit of allowed
connections and for example a key is pressed on the old ssh session, which now
has become unresponsive due to its traffic being dropped. Therefore, the limit
of connections should be rather high so that fluctuations in new TCP connections
don't cause odd traffic behavior in relation to idle connections.

Command line tools
------------------

The libvirt command line tool ``virsh`` has been extended with life-cycle
support for network filters. All commands related to the network filtering
subsystem start with the prefix ``nwfilter``. The following commands are
available:

-  nwfilter-list : list UUIDs and names of all network filters

-  nwfilter-define : define a new network filter or update an existing one

-  nwfilter-undefine : delete a network filter given its name; it must not be
   currently in use

-  nwfilter-dumpxml : display a network filter given its name

-  nwfilter-edit : edit a network filter given its name

Pre-existing network filters
----------------------------

The following is a list of example network filters that are automatically
installed with libvirt.

+---------------------+-------------------------------------------------------+
| Name                | Description                                           |
+=====================+=======================================================+
| no-arp-spoofing     | Prevent a VM from spoofing ARP traffic; this filter   |
|                     | only allows ARP request and reply messages and        |
|                     | enforces that those packets contain the MAC and IP    |
|                     | addresses of the VM.                                  |
+---------------------+-------------------------------------------------------+
| allow-arp           | Allow ARP traffic in both directions                  |
+---------------------+-------------------------------------------------------+
| allow-ipv4          | Allow IPv4 traffic in both directions                 |
+---------------------+-------------------------------------------------------+
| allow-ipv6          | Allow IPv6 traffic in both directions                 |
+---------------------+-------------------------------------------------------+
| allow-incoming-ipv4 | Allow incoming IPv4 traffic                           |
+---------------------+-------------------------------------------------------+
| allow-incoming-ipv6 | Allow incoming IPv6 traffic                           |
+---------------------+-------------------------------------------------------+
| allow-dhcp          | Allow a VM to request an IP address via DHCP (from    |
|                     | any DHCP server)                                      |
+---------------------+-------------------------------------------------------+
| allow-dhcpv6        | Similar to allow-dhcp, but for DHCPv6                 |
+---------------------+-------------------------------------------------------+
| allow-dhcp-server   | Allow a VM to request an IP address from a specified  |
|                     | DHCP server. The dotted decimal IP address of the     |
|                     | DHCP server must be provided in a reference to this   |
|                     | filter. The name of the variable must be              |
|                     | *DHCPSERVER*.                                         |
+---------------------+-------------------------------------------------------+
| allow-dhcpv6-server | Similar to allow-dhcp-server, but for DHCPv6          |
+---------------------+-------------------------------------------------------+
| no-ip-spoofing      | Prevent a VM from sending of IPv4 packets with a      |
|                     | source IP address different from the one in the       |
|                     | packet.                                               |
+---------------------+-------------------------------------------------------+
| no-ipv6-spoofing    | Similar to no-ip-spoofing, but for IPv6               |
+---------------------+-------------------------------------------------------+
| no-ip-multicast     | Prevent a VM from sending IP multicast packets.       |
+---------------------+-------------------------------------------------------+
| no-ipv6-multicast   | Similar to no-ip-multicast, but for IPv6              |
+---------------------+-------------------------------------------------------+
| clean-traffic       | Prevent MAC, IP and ARP spoofing. This filter         |
|                     | references several other filters as building blocks.  |
+---------------------+-------------------------------------------------------+

Note that most of the above filters are only building blocks and require a
combination with other filters to provide useful network traffic filtering. The
most useful one in the above list is the *clean-traffic* filter. This filter
itself can for example be combined with the *no-ip-multicast* filter to prevent
virtual machines from sending IP multicast traffic on top of the prevention of
packet spoofing.

Writing your own filters
------------------------

Since libvirt only provides a couple of example networking filters, you may
consider writing your own. When planning on doing so there are a couple of
things you may need to know regarding the network filtering subsystem and how it
works internally. Certainly you also have to know and understand the protocols
very well that you want to be filtering on so that no further traffic than what
you want can pass and that in fact the traffic you want to allow does pass.

The network filtering subsystem is currently only available on Linux hosts and
only works for QEMU and KVM type of virtual machines. On Linux it builds upon
the support for ``ebtables``, ``iptables`` and ``ip6tables`` and makes use of
their features. From the above list of supported protocols the following ones
are implemented using ``ebtables``:

-  mac

-  stp (spanning tree protocol)

-  vlan (802.1Q)

-  arp, rarp

-  ipv4

-  ipv6

All other protocols over IPv4 are supported using iptables, those over IPv6 are
implemented using ip6tables.

On a Linux host, all traffic filtering instantiated by libvirt's network filter
subsystem first passes through the filtering support implemented by ebtables and
only then through iptables or ip6tables filters. If a filter tree has rules with
the protocols ``mac``, ``stp``, ``vlan`` ``arp``, ``rarp``, ``ipv4``, or
``ipv6`` ebtables rules will automatically be instantiated.

The role of the ``chain`` attribute in the network filter XML is that internally
a new user-defined ebtables table is created that then for example receives all
``arp`` traffic coming from or going to a virtual machine if the chain ``arp``
has been specified. Further, a rule is generated in an interface's ``root``
chain that directs all ipv4 traffic into the user-defined chain. Therefore, all
ARP traffic rules should then be placed into filters specifying this chain. This
type of branching into user-defined tables is only supported with filtering on
the ebtables layer.

:since:`Since 0.9.8` multiple chains for the same protocol can be created. For
this the name of the chain must have a prefix of one of the previously
enumerated protocols. To create an additional chain for handling of ARP traffic,
a chain with name ``arp-test`` can be specified.

As an example, it is possible to filter on UDP traffic by source and destination
ports using the ``ip`` protocol filter and specifying attributes for the
protocol, source and destination IP addresses and ports of UDP packets that are
to be accepted. This allows early filtering of UDP traffic with ebtables.
However, once an IP or IPv6 packet, such as a UDP packet, has passed the
ebtables layer and there is at least one rule in a filter tree that instantiates
iptables or ip6tables rules, a rule to let the UDP packet pass will also be
necessary to be provided for those filtering layers. This can be achieved with a
rule containing an appropriate ``udp`` or ``udp-ipv6`` traffic filtering node.

Example custom filter
~~~~~~~~~~~~~~~~~~~~~

As an example we want to now build a filter that fulfills the following list of
requirements:

-  prevents a VM's interface from MAC, IP and ARP spoofing

-  opens only TCP ports 22 and 80 of a VM's interface

-  allows the VM to send ping traffic from an interface but not let the VM be
   pinged on the interface

-  allows the VM to do DNS lookups (UDP towards port 53)

The requirement to prevent spoofing is fulfilled by the existing
``clean-traffic`` network filter, thus we will reference this filter from our
custom filter.

To enable traffic for TCP ports 22 and 80 we will add 2 rules to enable this
type of traffic. To allow the VM to send ping traffic we will add a rule for
ICMP traffic. For simplicity reasons we allow general ICMP traffic to be
initiated from the VM, not just ICMP echo request and response messages. To then
disallow all other traffic to reach or be initiated by the VM we will then need
to add a rule that drops all other traffic. Assuming our VM is called *test* and
the interface we want to associate our filter with is called *eth0*, we name our
filter *test-eth0*. The result of these considerations is the following network
filter XML:

::

   <filter name='test-eth0'>
     <!-- reference the clean traffic filter to prevent
          MAC, IP and ARP spoofing. By not providing
          and IP address parameter, libvirt will detect the
          IP address the VM is using. -->
     <filterref filter='clean-traffic'/>

     <!-- enable TCP ports 22 (ssh) and 80 (http) to be reachable -->
     <rule action='accept' direction='in'>
       <tcp dstportstart='22'/>
     </rule>

     <rule action='accept' direction='in'>
       <tcp dstportstart='80'/>
     </rule>

     <!-- enable general ICMP traffic to be initiated by the VM;
          this includes ping traffic -->
     <rule action='accept' direction='out'>
       <icmp/>
     </rule>

     <!-- enable outgoing DNS lookups using UDP -->
     <rule action='accept' direction='out'>
       <udp dstportstart='53'/>
     </rule>

     <!-- drop all other traffic -->
     <rule action='drop' direction='inout'>
       <all/>
     </rule>

   </filter>

Note that none of the rules in the above XML contain the IP address of the VM as
either source or destination address, yet the filtering of the traffic works
correctly. The reason is that the evaluation of the rules internally happens on
a per-interface basis and the rules are evaluated based on the knowledge about
which (tap) interface has sent or will receive the packet rather than what their
source or destination IP address may be.

An XML fragment for a possible network interface description inside the domain
XML of the ``test`` VM could then look like this:

::

   [...]
   <interface type='bridge'>
     <source bridge='mybridge'/>
     <filterref filter='test-eth0'/>
   </interface>
   [...]

To more strictly control the ICMP traffic and enforce that only ICMP echo
requests can be sent from the VM and only ICMP echo responses be received by the
VM, the above ``ICMP`` rule can be replaced with the following two rules:

::

   <!-- enable outgoing ICMP echo requests-->
   <rule action='accept' direction='out'>
     <icmp type='8'/>
   </rule>

   <!-- enable incoming ICMP echo replies-->
   <rule action='accept' direction='in'>
     <icmp type='0'/>
   </rule>

Second example custom filter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this example we now want to build a similar filter as in the example above,
but extend the list of requirements with an ftp server located inside the VM.
Further, we will be using features that have been added in :since:`version
0.8.5` . The requirements for this filter are:

-  prevents a VM's interface from MAC, IP and ARP spoofing

-  opens only TCP ports 22 and 80 of a VM's interface

-  allows the VM to send ping traffic from an interface but not let the VM be
   pinged on the interface

-  allows the VM to do DNS lookups (UDP towards port 53)

-  enable an ftp server (in active mode) to be run inside the VM

The additional requirement of allowing an ftp server to be run inside the VM
maps into the requirement of allowing port 21 to be reachable for ftp control
traffic as well as enabling the VM to establish an outgoing tcp connection
originating from the VM's TCP port 20 back to the ftp client (ftp active mode).
There are several ways of how this filter can be written and we present 2
solutions.

The 1st solution makes use of the ``state`` attribute of the TCP protocol that
gives us a hook into the connection tracking framework of the Linux host. For
the VM-initiated ftp data connection (ftp active mode) we use the ``RELATED``
state that allows us to detect that the VM-initiated ftp data connection is a
consequence of ( or 'has a relationship with' ) an existing ftp control
connection, thus we want to allow it to let packets pass the firewall. The
``RELATED`` state, however, is only valid for the very first packet of the
outgoing TCP connection for the ftp data path. Afterwards, the state to compare
against is ``ESTABLISHED``, which then applies equally to the incoming and
outgoing direction. All this is related to the ftp data traffic originating from
TCP port 20 of the VM. This then leads to the following solution :since:`(since
0.8.5 (QEMU, KVM))` :

::

   <filter name='test-eth0'>
     <!-- reference the clean traffic filter to prevent
          MAC, IP and ARP spoofing. By not providing
          and IP address parameter, libvirt will detect the
          IP address the VM is using. -->
     <filterref filter='clean-traffic'/>

     <!-- enable TCP port 21 (ftp-control) to be reachable -->
     <rule action='accept' direction='in'>
       <tcp dstportstart='21'/>
     </rule>

     <!-- enable TCP port 20 for VM-initiated ftp data connection
          related to an existing ftp control connection -->
     <rule action='accept' direction='out'>
       <tcp srcportstart='20' state='RELATED,ESTABLISHED'/>
     </rule>

     <!-- accept all packets from client on the ftp data connection -->
     <rule action='accept' direction='in'>
       <tcp dstportstart='20' state='ESTABLISHED'/>
     </rule>

     <!-- enable TCP ports 22 (ssh) and 80 (http) to be reachable -->
     <rule action='accept' direction='in'>
       <tcp dstportstart='22'/>
     </rule>

     <rule action='accept' direction='in'>
       <tcp dstportstart='80'/>
     </rule>

     <!-- enable general ICMP traffic to be initiated by the VM;
          this includes ping traffic -->
     <rule action='accept' direction='out'>
       <icmp/>
     </rule>

     <!-- enable outgoing DNS lookups using UDP -->
     <rule action='accept' direction='out'>
       <udp dstportstart='53'/>
     </rule>

     <!-- drop all other traffic -->
     <rule action='drop' direction='inout'>
       <all/>
     </rule>

   </filter>

Before trying out a filter using the ``RELATED`` state, you have to make sure
that the appropriate connection tracking module has been loaded into the host's
kernel. Depending on the version of the kernel, you must run either one of the
following two commands before the ftp connection with the VM is established.

::

   modprobe nf_conntrack_ftp   # where available  or

   modprobe ip_conntrack_ftp   # if above is not available

If other protocols than ftp are to be used in conjunction with the ``RELATED``
state, their corresponding module must be loaded. Modules exist at least for the
protocols ftp, tftp, irc, sip, sctp, and amanda.

The 2nd solution makes uses the state flags of connections more than the
previous solution did. In this solution we take advantage of the fact that the
``NEW`` state of a connection is valid when the very first packet of a traffic
flow is seen. Subsequently, if the very first packet of a flow is accepted, the
flow becomes a connection and enters the ``ESTABLISHED`` state. This allows us
to write a general rule for allowing packets of ``ESTABLISHED`` connections to
reach the VM or be sent by the VM. We write specific rules for the very first
packets identified by the ``NEW`` state and for which ports they are acceptable.
All packets for ports that are not explicitly accepted will be dropped and
therefore the connection will not go into the ``ESTABLISHED`` state and any
subsequent packets be dropped.

::

   <filter name='test-eth0'>
     <!-- reference the clean traffic filter to prevent
          MAC, IP and ARP spoofing. By not providing
          and IP address parameter, libvirt will detect the
          IP address the VM is using. -->
     <filterref filter='clean-traffic'/>

     <!-- let the packets of all previously accepted connections reach the VM -->
     <rule action='accept' direction='in'>
       <all state='ESTABLISHED'/>
     </rule>

     <!-- let the packets of all previously accepted and related connections be sent from the VM -->
     <rule action='accept' direction='out'>
       <all state='ESTABLISHED,RELATED'/>
     </rule>

     <!-- enable traffic towards port 21 (ftp), 22 (ssh) and 80 (http) -->
     <rule action='accept' direction='in'>
       <tcp dstportstart='21' dstportend='22' state='NEW'/>
     </rule>

     <rule action='accept' direction='in'>
       <tcp dstportstart='80' state='NEW'/>
     </rule>

     <!-- enable general ICMP traffic to be initiated by the VM;
          this includes ping traffic -->
     <rule action='accept' direction='out'>
       <icmp state='NEW'/>
     </rule>

     <!-- enable outgoing DNS lookups using UDP -->
     <rule action='accept' direction='out'>
       <udp dstportstart='53' state='NEW'/>
     </rule>

     <!-- drop all other traffic -->
     <rule action='drop' direction='inout'>
       <all/>
     </rule>

   </filter>

Limitations
-----------

The following sections list (current) limitations of the network filtering
subsystem.

VM Migration
~~~~~~~~~~~~

VM migration is only supported if the whole filter tree that is referenced by a
virtual machine's top level filter is also available on the target host. The
network filter *clean-traffic* for example should be available on all libvirt
installations of version 0.8.1 or later and thus enable migration of VMs that
for example reference this filter. All other custom filters must be migrated
using higher layer software. It is outside the scope of libvirt to ensure that
referenced filters on the source system are equivalent to those on the target
system and vice versa.

Migration must occur between libvirt installations of version 0.8.1 or later in
order not to lose the network traffic filters associated with an interface.

VLAN filtering on Linux
~~~~~~~~~~~~~~~~~~~~~~~

VLAN (802.1Q) packets, if sent by a virtual machine, cannot be filtered with
rules for protocol IDs ``arp``, ``rarp``, ``ipv4`` and ``ipv6`` but only with
protocol IDs ``mac`` and ``vlan``. Therefore, the example filter
``clean-traffic`` will not work as expected.
