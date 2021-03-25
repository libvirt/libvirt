=========================================
Firewall and network filtering in libvirt
=========================================

.. contents::

There are three pieces of libvirt functionality which do network filtering of
some type.  At a high level they are:

- The virtual network driver

    This provides an isolated bridge device (ie no physical NICs attached).
    Guest TAP devices are attached to this bridge. Guests can talk to each
    other and the host, and optionally the wider world.

- The QEMU driver MAC filtering

    This provides a generic filtering of MAC addresses to prevent the guest
    spoofing its MAC address. This is mostly obsoleted by the next item, so
    won't be discussed further.

- The network filter driver

    This provides fully configurable, arbitrary network filtering of traffic on
    guest NICs. Generic rulesets are defined at the host level to control
    traffic in some manner. Rules sets are then associated with individual NICs
    of a guest. While not as expressive as directly using iptables/ebtables,
    this can still do nearly everything you would want to on a guest NIC
    filter.

The virtual network driver
--------------------------

The typical configuration for guests is to use bridging of the physical NIC on
the host to connect the guest directly to the LAN. In RHEL6 there is also the
possibility of using macvtap/sr-iov and VEPA connectivity. None of this stuff
plays nicely with wireless NICs, since they will typically silently drop any
traffic with a MAC address that doesn't match that of the physical NIC.

Thus the virtual network driver in libvirt was invented. This takes the form of
an isolated bridge device (ie one with no physical NICs attached). The TAP
devices associated with the guest NICs are attached to the bridge device. This
immediately allows guests on a single host to talk to each other and to the host
OS (modulo host IPtables rules).

libvirt then uses iptables to control what further connectivity is available.
There are three configurations possible for a virtual network at time of
writing:

-  isolated: all off-node traffic is completely blocked
-  nat: outbound traffic to the LAN is allowed, but MASQUERADED
-  forward: outbound traffic to the LAN is allowed

The latter 'forward' case requires the virtual network be on a separate sub-net
from the main LAN, and that the LAN admin has configured routing for this
subnet. In the future we intend to add support for IP subnetting and/or
proxy-arp. This allows for the virtual network to use the same subnet as the
main LAN and should avoid need for the LAN admin to configure special routing.

Libvirt will optionally also provide DHCP services to the virtual network using
DNSMASQ. In all cases, we need to allow DNS/DHCP queries to the host OS. Since
we can't predict whether the host firewall setup is already allowing this, we
insert 4 rules into the head of the INPUT chain

::

   target     prot opt in     out     source               destination
   ACCEPT     udp  --  virbr0 *       0.0.0.0/0            0.0.0.0/0           udp dpt:53
   ACCEPT     tcp  --  virbr0 *       0.0.0.0/0            0.0.0.0/0           tcp dpt:53
   ACCEPT     udp  --  virbr0 *       0.0.0.0/0            0.0.0.0/0           udp dpt:67
   ACCEPT     tcp  --  virbr0 *       0.0.0.0/0            0.0.0.0/0           tcp dpt:67

Note we have restricted our rules to just the bridge associated with the virtual
network, to avoid opening undesirable holes in the host firewall wrt the
LAN/WAN.

The next rules depend on the type of connectivity allowed, and go in the main
FORWARD chain:

-  | type=isolated
   | Allow traffic between guests. Deny inbound. Deny outbound.

   ::

      target     prot opt in     out     source               destination
      ACCEPT     all  --  virbr1 virbr1  0.0.0.0/0            0.0.0.0/0
      REJECT     all  --  *      virbr1  0.0.0.0/0            0.0.0.0/0           reject-with icmp-port-unreachable
      REJECT     all  --  virbr1 *       0.0.0.0/0            0.0.0.0/0           reject-with icmp-port-unreachable

-  | type=nat
   | Allow inbound related to an established connection. Allow outbound, but
     only from our expected subnet. Allow traffic between guests. Deny all other
     inbound. Deny all other outbound.

   ::

      target     prot opt in     out     source               destination
      ACCEPT     all  --  *      virbr0  0.0.0.0/0            192.168.122.0/24    state RELATED,ESTABLISHED
      ACCEPT     all  --  virbr0 *       192.168.122.0/24     0.0.0.0/0
      ACCEPT     all  --  virbr0 virbr0  0.0.0.0/0            0.0.0.0/0
      REJECT     all  --  *      virbr0  0.0.0.0/0            0.0.0.0/0           reject-with icmp-port-unreachable
      REJECT     all  --  virbr0 *       0.0.0.0/0            0.0.0.0/0           reject-with icmp-port-unreachable

-  | type=routed
   | Allow inbound, but only to our expected subnet. Allow outbound, but only
     from our expected subnet. Allow traffic between guests. Deny all other
     inbound. Deny all other outbound.

   ::

      target     prot opt in     out     source               destination
      ACCEPT     all  --  *      virbr2  0.0.0.0/0            192.168.124.0/24
      ACCEPT     all  --  virbr2 *       192.168.124.0/24     0.0.0.0/0
      ACCEPT     all  --  virbr2 virbr2  0.0.0.0/0            0.0.0.0/0
      REJECT     all  --  *      virbr2  0.0.0.0/0            0.0.0.0/0           reject-with icmp-port-unreachable
      REJECT     all  --  virbr2 *       0.0.0.0/0            0.0.0.0/0           reject-with icmp-port-unreachable

-  Finally, with type=nat, there is also an entry in the POSTROUTING chain to
   apply masquerading:

   ::

      target     prot opt in     out     source               destination
      MASQUERADE all  --  *      *       192.168.122.0/24    !192.168.122.0/24

firewalld and the virtual network driver
----------------------------------------

If `firewalld <https://firewalld.org>`__ is active on the host, libvirt will
attempt to place the bridge interface of a libvirt virtual network into the
firewalld zone named "libvirt" (thus making all guest->host traffic on that
network subject to the rules of the "libvirt" zone). This is done because, if
firewalld is using its nftables backend (available since firewalld 0.6.0) the
default firewalld zone (which would be used if libvirt didn't explicitly set the
zone) prevents forwarding traffic from guests through the bridge, as well as
preventing DHCP, DNS, and most other traffic from guests to host. The zone named
"libvirt" is installed into the firewalld configuration by libvirt (not by
firewalld), and allows forwarded traffic through the bridge as well as DHCP,
DNS, TFTP, and SSH traffic to the host - depending on firewalld's backend this
will be implemented via either iptables or nftables rules. libvirt's own rules
outlined above will \*always\* be iptables rules regardless of which backend is
in use by firewalld.

NB: It is possible to manually set the firewalld zone for a network's interface
with the "zone" attribute of the network's "bridge" element.

NB: Prior to libvirt 5.1.0, the firewalld "libvirt" zone did not exist, and
prior to firewalld 0.7.0 a feature crucial to making the "libvirt" zone operate
properly (rich rule priority settings) was not implemented in firewalld. In
cases where one or the other of the two packages is missing the necessary
functionality, it's still possible to have functional guest networking by
setting the firewalld backend to "iptables" (in firewalld prior to 0.6.0, this
was the only backend available).

The network filter driver
-------------------------

This driver provides a fully configurable network filtering capability that
leverages ebtables, iptables and ip6tables. This was written by the libvirt guys
at IBM and although its XML schema is defined by libvirt, the conceptual model
is closely aligned with the DMTF CIM schema for network filtering:

https://www.dmtf.org/standards/cim/cim_schema_v2230/CIM_Network.pdf

The filters are managed in libvirt as a top level, standalone object. This
allows the filters to then be referenced by any libvirt object that requires
their functionality, instead tying them only to use by guest NICs. In the
current implementation, filters can be associated with individual guest NICs via
the libvirt domain XML format. In the future we might allow filters to be
associated with the virtual network objects. Further we're expecting to define a
new 'virtual switch' object to remove the complexity of configuring
bridge/sriov/vepa networking modes. This make also end up making use of network
filters.

There are a new set of virsh commands for managing network filters:

- ``virsh nwfilter-define``
    define or update a network filter from an XML file
- ``virsh nwfilter-undefine``
    undefine a network filter
- ``virsh nwfilter-dumpxml``
    network filter information in XML
- ``virsh nwfilter-list``
    list network filters
- ``virsh nwfilter-edit``
    edit XML configuration for a network filter

There are equivalently named C APIs for each of these commands.

As with all objects libvirt manages, network filters are configured using an XML
format. At a high level the format looks like this:

::

   <filter name='no-spamming' chain='XXXX'>
     <uuid>d217f2d7-5a04-0e01-8b98-ec2743436b74</uuid>

     <rule ...>
       ....
     </rule>

     <filterref filter='XXXX'/>
   </filter>

Every filter has a name and UUID which serve as unique identifiers. A filter can
have zero-or-more ``<rule>`` elements which are used to actually define network
controls. Filters can be arranged into a DAG, so zero-or-more ``<filterref/>``
elements are also allowed. Cycles in the graph are not allowed.

The ``<rule>`` element is where all the interesting stuff happens. It has three
attributes, an action, a traffic direction and an optional priority. E.g.:

::

   <rule action='drop' direction='out' priority='500'>

Within the rule there are a wide variety of elements allowed, which do protocol
specific matching. Supported protocols currently include ``mac``, ``arp``,
``rarp``, ``ip``, ``ipv6``, ``tcp/ip``, ``icmp/ip``, ``igmp/ip``, ``udp/ip``,
``udplite/ip``, ``esp/ip``, ``ah/ip``, ``sctp/ip``, ``tcp/ipv6``, ``icmp/ipv6``,
``igmp/ipv6``, ``udp/ipv6``, ``udplite/ipv6``, ``esp/ipv6``, ``ah/ipv6``,
``sctp/ipv6``. Each protocol defines what is valid inside the <rule> element.
The general pattern though is:

::

   <protocol match='yes|no' attribute1='value1' attribute2='value2'/>

So, eg a TCP protocol, matching ports 0-1023 would be expressed as:

::

   <tcp match='yes' srcportstart='0' srcportend='1023'/>

Attributes can included references to variables defined by the object using the
rule. So the guest XML format allows each NIC to have a MAC address and IP
address defined. These are made available to filters via the variables ``$IP``
and ``$MAC``.

So to define a filter that prevents IP address spoofing we can simply match on
source IP address ``!= $IP`` like this:

::

   <filter name='no-ip-spoofing' chain='ipv4'>
     <rule action='drop' direction='out'>
       <ip match='no' srcipaddr='$IP' />
     </rule>
   </filter>

I'm not going to go into details on all the other protocol matches you can do,
because it'll take far too much space. You can read about the options
`here <formatnwfilter.html#supported-protocols>`__.

Out of the box in RHEL6/Fedora rawhide, libvirt ships with a set of default
useful rules:

::

   # virsh nwfilter-list
   UUID                                  Name
   ----------------------------------------------------------------
   15b1ab2b-b1ac-1be2-ed49-2042caba4abb  allow-arp
   6c51a466-8d14-6d11-46b0-68b1a883d00f  allow-dhcp
   7517ad6c-bd90-37c8-26c9-4eabcb69848d  allow-dhcp-server
   7680776c-77aa-496f-90d6-13097664b925  allow-dhcpv6
   9cdaad60-7631-4172-8ccb-ef774be7485b  allow-dhcpv6-server
   3d38b406-7cf0-8335-f5ff-4b9add35f288  allow-incoming-ipv4
   908543c1-902e-45f6-a6ca-1a0ad35e7599  allow-incoming-ipv6
   5ff06320-9228-2899-3db0-e32554933415  allow-ipv4
   ce8904cc-ad3a-4454-896c-53452882f817  allow-ipv6
   db0b1767-d62b-269b-ea96-0cc8b451144e  clean-traffic
   6d6ddcc8-1242-4c43-ac63-63af80493132  clean-traffic-gateway
   4cf38077-c7d5-4e25-99bb-6c4c9efad294  no-arp-ip-spoofing
   0b11a636-ce58-497f-be90-17f63c92487a  no-arp-mac-spoofing
   f88f1932-debf-4aa1-9fbe-f10d3aa4bc95  no-arp-spoofing
   772f112d-52e4-700c-0250-e178a3d91a7a  no-ip-multicast
   7ee20370-8106-765d-f7ff-8a60d5aaf30b  no-ip-spoofing
   f8a51c43-a08f-49b3-b9e2-393d54522dc0  no-ipv6-multicast
   a7f0afe9-a428-44b8-8566-c8ee2a669271  no-ipv6-spoofing
   d5d3c490-c2eb-68b1-24fc-3ee362fc8af3  no-mac-broadcast
   fb57c546-76dc-a372-513f-e8179011b48a  no-mac-spoofing
   dba10ea7-446d-76de-346f-335bd99c1d05  no-other-l2-traffic
   f5c78134-9da4-0c60-a9f0-fb37bc21ac1f  no-other-rarp-traffic
   7637e405-4ccf-42ac-5b41-14f8d03d8cf3  qemu-announce-self
   9aed52e7-f0f3-343e-fe5c-7dcb27b594e5  qemu-announce-self-rarp

Most of these are just building blocks. The interesting one here is
'clean-traffic'. This pulls together all the building blocks into one filter
that you can then associate with a guest NIC. This stops the most common bad
things a guest might try, IP spoofing, arp spoofing and MAC spoofing. To look at
the rules for any of these just do:

::

   virsh nwfilter-dumpxml FILTERNAME|UUID

They are all stored in ``/etc/libvirt/nwfilter``, but don't edit the files there
directly. Use ``virsh nwfilter-define`` to update them. This ensures the guests
have their iptables/ebtables rules recreated.

To associate the clean-traffic filter with a guest, edit the guest XML config
and change the ``<interface>`` element to include a ``<filterref>`` and also
specify the ``<ip address/>`` that the guest is allowed to use:

::

   <interface type='bridge'>
     <mac address='52:54:00:56:44:32'/>
     <source bridge='br1'/>
     <ip address='10.33.8.131'/>
     <target dev='vnet0'/>
     <model type='virtio'/>
     <filterref filter='clean-traffic'/>
   </interface>

If no ``<ip address>`` is included, the network filter driver will activate its
'learning mode'. This uses libpcap to snoop on network traffic the guest sends
and attempts to identify the first IP address it uses. It then locks traffic to
this address. Obviously this isn't entirely secure, but it does offer some
protection against the guest being trojaned once up and running. In the future
we intend to enhance the learning mode so that it looks for DHCPOFFERS from a
trusted DHCP server and only allows the offered IP address to be used.

Now, how is all this implemented...?

The network filter driver uses a combination of ebtables, iptables and
ip6tables, depending on which protocols are referenced in a filter. The out of
the box 'clean-traffic' filter rules only require use of ebtables. If you want
to do matching at tcp/udp/etc protocols (eg to add a new filter
'no-email-spamming' to block port 25), then iptables will also be used.

The driver attempts to keep its rules separate from those that the host admin
might already have configured. So the first thing it does with ebtables, is to
add two hooks in POSTROUTING and PREROUTING chains, to redirect traffic to
custom chains. These hooks match on the TAP device name of the guest NIC, so
they should not interact badly with any administrator defined rules:

::

   Bridge chain: PREROUTING, entries: 1, policy: ACCEPT
   -i vnet0 -j libvirt-I-vnet0

   Bridge chain: POSTROUTING, entries: 1, policy: ACCEPT
   -o vnet0 -j libvirt-O-vnet0

To keep things manageable and easy to follow, the driver will then create
further sub-chains for each protocol then it needs to match against:

::

   Bridge chain: libvirt-I-vnet0, entries: 5, policy: ACCEPT
   -p IPv4 -j I-vnet0-ipv4
   -p ARP -j I-vnet0-arp
   -p 0x8035 -j I-vnet0-rarp
   -p 0x835 -j ACCEPT
   -j DROP

   Bridge chain: libvirt-O-vnet0, entries: 4, policy: ACCEPT
   -p IPv4 -j O-vnet0-ipv4
   -p ARP -j O-vnet0-arp
   -p 0x8035 -j O-vnet0-rarp
   -j DROP

Finally, here comes the actual implementation of the filters. This example shows
the 'clean-traffic' filter implementation. I'm not going to explain what this is
doing now. :-)

::

   Bridge chain: I-vnet0-ipv4, entries: 2, policy: ACCEPT
   -s ! 52:54:0:56:44:32 -j DROP
   -p IPv4 --ip-src ! 10.33.8.131 -j DROP

   Bridge chain: O-vnet0-ipv4, entries: 1, policy: ACCEPT
   -j ACCEPT

   Bridge chain: I-vnet0-arp, entries: 6, policy: ACCEPT
   -s ! 52:54:0:56:44:32 -j DROP
   -p ARP --arp-mac-src ! 52:54:0:56:44:32 -j DROP
   -p ARP --arp-ip-src ! 10.33.8.131 -j DROP
   -p ARP --arp-op Request -j ACCEPT
   -p ARP --arp-op Reply -j ACCEPT
   -j DROP

   Bridge chain: O-vnet0-arp, entries: 5, policy: ACCEPT
   -p ARP --arp-op Reply --arp-mac-dst ! 52:54:0:56:44:32 -j DROP
   -p ARP --arp-ip-dst ! 10.33.8.131 -j DROP
   -p ARP --arp-op Request -j ACCEPT
   -p ARP --arp-op Reply -j ACCEPT
   -j DROP

   Bridge chain: I-vnet0-rarp, entries: 2, policy: ACCEPT
   -p 0x8035 -s 52:54:0:56:44:32 -d Broadcast --arp-op Request_Reverse --arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 --arp-mac-src 52:54:0:56:44:32 --arp-mac-dst 52:54:0:56:44:32 -j ACCEPT
   -j DROP

   Bridge chain: O-vnet0-rarp, entries: 2, policy: ACCEPT
   -p 0x8035 -d Broadcast --arp-op Request_Reverse --arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 --arp-mac-src 52:54:0:56:44:32 --arp-mac-dst 52:54:0:56:44:32 -j ACCEPT
   -j DROP

NB, we would have liked to include the prefix 'libvirt-' in all of our chain
names, but unfortunately the kernel limits names to a very short maximum length.
So only the first two custom chains can include that prefix. The others just
include the TAP device name + protocol name.

If I define a new filter 'no-spamming' and then add this to the 'clean-traffic'
filter, I can illustrate how iptables usage works:

::

   # cat > /root/spamming.xml <<EOF
   <filter name='no-spamming' chain='root'>
     <uuid>d217f2d7-5a04-0e01-8b98-ec2743436b74</uuid>
     <rule action='drop' direction='out' priority='500'>
       <tcp dstportstart='25' dstportend='25'/>
     </rule>
   </filter>
   EOF
   # virsh nwfilter-define /root/spamming.xml
   # virsh nwfilter-edit clean-traffic

...add ``<filterref filter='no-spamming'/>``

All active guests immediately have their iptables/ebtables rules rebuilt.

The network filter driver deals with iptables in a very similar way. First it
separates out its rules from those the admin may have defined, by adding a
couple of hooks into the INPUT/FORWARD chains:

::

   Chain INPUT (policy ACCEPT 13M packets, 21G bytes)
   target           prot opt in     out     source               destination
   libvirt-host-in  all  --  *      *       0.0.0.0/0            0.0.0.0/0

   Chain FORWARD (policy ACCEPT 5532K packets, 3010M bytes)
   target           prot opt in     out     source               destination
   libvirt-in       all  --  *      *       0.0.0.0/0            0.0.0.0/0
   libvirt-out      all  --  *      *       0.0.0.0/0            0.0.0.0/0
   libvirt-in-post  all  --  *      *       0.0.0.0/0            0.0.0.0/0

These custom chains then do matching based on the TAP device name, so they won't
open holes in the admin defined matches for the LAN/WAN (if any).

::

   Chain libvirt-host-in (1 references)
     target     prot opt in     out     source               destination
     HI-vnet0   all  --  *      *       0.0.0.0/0            0.0.0.0/0           [goto] PHYSDEV match --physdev-in vnet0

   Chain libvirt-in (1 references)
     target     prot opt in     out     source               destination
     FI-vnet0   all  --  *      *       0.0.0.0/0            0.0.0.0/0           [goto] PHYSDEV match --physdev-in vnet0

   Chain libvirt-in-post (1 references)
     target     prot opt in     out     source               destination
     ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           PHYSDEV match --physdev-in vnet0

   Chain libvirt-out (1 references)
     target     prot opt in     out     source               destination
     FO-vnet0   all  --  *      *       0.0.0.0/0            0.0.0.0/0           [goto] PHYSDEV match --physdev-out vnet0

Finally, we can see the interesting bit which is the actual implementation of my
filter to block port 25 access:

::

   Chain FI-vnet0 (1 references)
     target     prot opt in     out     source               destination
     DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp dpt:25

   Chain FO-vnet0 (1 references)
     target     prot opt in     out     source               destination
     DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp spt:25

   Chain HI-vnet0 (1 references)
     target     prot opt in     out     source               destination
     DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp dpt:25

One thing in looking at this you may notice is that if there are many guests all
using the same filters, we will be duplicating the iptables rules over and over
for each guest. This is merely a limitation of the current rules engine
implementation. At the libvirt object modelling level you can clearly see we've
designed the model so filter rules are defined in one place, and indirectly
referenced by guests. Thus it should be possible to change the implementation in
the future so we can share the actual iptables/ebtables rules for each guest to
create a more scalable system. The stuff in current libvirt is more or less the
very first working implementation we've had of this, so there's not been much
optimization work done yet.

Also notice that at the XML level we don't expose the fact we are using iptables
or ebtables at all. The rule definition is done in terms of network protocols.
Thus if we ever find a need, we could plug in an alternative implementation that
calls out to a different firewall implementation instead of ebtables/iptables
(providing that implementation was suitably expressive of course)

Finally, in terms of problems we have in deployment. The biggest problem is that
if the admin does ``service iptables restart`` all our work gets blown away.
We've experimented with using lokkit to record our custom rules in a persistent
config file, but that caused different problem. Admins who were not using lokkit
for their config found that all their own rules got blown away. So we threw away
our lokkit code. Instead we document that if you run
``service iptables restart``, you need to send SIGHUP to libvirt to make it
recreate its rules.

More in depth documentation on this is `here <formatnwfilter.html>`__.
