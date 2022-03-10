==================
Libvirt NSS module
==================

.. contents::

When it comes to managing guests and executing commands inside them, logging
into guest operating system and doing the job is convenient. Users are used to
ssh in this case. Ideally:

``ssh user@virtualMachine``

would be nice. But depending on virtual network configuration it might not be
always possible. For instance, when using libvirt NATed network it's dnsmasq
(spawned by libvirt) who assigns IP addresses to domains. But by default, the
dnsmasq process is then not consulted when it comes to host name translation.
Users work around this problem by configuring their libvirt network to assign
static IP addresses and maintaining ``/etc/hosts`` file in sync. But this puts
needless burden onto users. This is where NSS module comes handy.

Installation
------------

Installing the module is really easy:

::

   # yum install libvirt-nss

Configuration
-------------

Enabling the module is really easy. Just add **libvirt** into
``/etc/nsswitch.conf`` file. For instance:

::

   $ cat /etc/nsswitch.conf
   # /etc/nsswitch.conf:
   passwd:      compat
   shadow:      compat
   group:       compat
   hosts:       files libvirt dns
   # ...

So, in this specific case, whenever ssh program is looking up the host user is
trying to connect to, **files** module is consulted first (which boils down to
looking up the host name in ``/etc/hosts`` file), if not found **libvirt**
module is consulted then. The DNS is the last effort then, if none of the
previous modules matched the host in question. Therefore users should consider
the order in which they want the modules to lookup given host name.

Sources of information
----------------------

As of ``v3.0.0`` release, libvirt offers two NSS modules implementing two
different methods of hostname translation. The first and older method is
implemented by ``libvirt`` plugin and basically looks up the hostname to IP
address translation in DHCP server records. Therefore this is dependent on
hostname provided by guests. Thing is, not all the guests out there provide one
in DHCP transactions, or not every sysadmin out there believes all the guests.
Hence libvirt implements second method in ``libvirt_guest`` module which does
libvirt guest name to IP address translation (regardless of hostname set in the
guest).

To enable either of the modules put their name into the ``nsswitch.conf`` file.
For instance, to enable ``libvirt_guest`` module:

::

   $ cat /etc/nsswitch.conf
   # /etc/nsswitch.conf:
   hosts:       files libvirt_guest dns
   # ...

Or users can enable both at the same time:

::

   $ cat /etc/nsswitch.conf
   # /etc/nsswitch.conf:
   hosts:       files libvirt libvirt_guest dns
   # ...

This configuration will mean that if hostname is not found by the ``libvirt``
module (e.g. because a guest did not sent hostname during DHCP transaction), the
``libvirt_guest`` module is consulted (and if the hostname matches libvirt guest
name it will be resolved).

How does it work?
-----------------

Whenever an Unix process wants to do a host name translation
`gethostbyname() <https://linux.die.net/man/3/gethostbyname>`__ or some variant
of it is called. This is a glibc function that takes a string containing the
host name, crunch it and produces a list of IP addresses assigned to that host.
Now, glibc developers made a really good decision when implementing the
internals of the function when they decided to make the function pluggable.
Since there can be several sources for the records (e.g. ``/etc/hosts`` file,
DNS, LDAP, etc.) it would not make much sense to create one big implementation
containing all possible cases. What they have done instead is this pluggable
mechanism. Small plugins implementing nothing but specific technology for lookup
process are provided and the function then calls those plugins. There is just
one configuration file that instructs the lookup function in which order should
the plugins be called and which plugins should be loaded. For more info reading
`wiki page <https://en.wikipedia.org/wiki/Name_Service_Switch>`__ is
recommended.

And this is point where libvirt comes in. Libvirt provides plugin for the NSS
ecosystem. For some time now libvirt keeps a list of assigned IP addresses for
libvirt networks. The NSS plugin does no more than search the list trying to
find matching record for given host name. When found, matching IP address is
returned to the caller. If not found, translation process continues with the
next plugin configured. At this point it is important to stress the order in
which plugins are called. Users should be aware that a hostname might match in
multiple plugins and right after first match, translation process is terminated
and no other plugin is consulted. Therefore, if there are two different records
for the same host name users should carefully chose the lookup order.

Limitations
-----------

#. The ``libvirt`` NSS module matches only hostnames provided by guest. If the
   libvirt name and one advertised by guest differs, the latter is matched.
   However, as of ``v3.0.0`` there are two libvirt NSS modules translating both
   hostnames provided by guest and libvirt guest names.
#. The module works only in that cases where IP addresses are assigned by
   dnsmasq spawned by libvirt. Libvirt NATed networks are typical example.

*The following paragraph describes implementation limitation of the ``libvirt``
NSS module.* These limitation are result of libvirt's internal implementation.
While libvirt can report IP addresses regardless of their origin, a public API
must be used to obtain those. However, for the API a connection object is
required. Doing that for every name translation request would be too costly.
Fortunately, libvirt spawns dnsmasq for NATed networks. Not only that, it
provides small executable that on each IP address space change updates an
internal list of addresses thus keeping it in sync. The NSS module then merely
consults the list trying to find the match. Users can view the list themselves:

::

   virsh net-dhcp-leases $network

where ``$network`` iterates through all running networks. So the module does
merely the same as

::

   virsh domifaddr --source lease $domain

If there's no record for either of the aforementioned commands, it's very likely
that NSS module won't find anything and vice versa. As of ``v3.0.0`` libvirt
provides ``libvirt_guest`` NSS module that doesn't have this limitation.
However, the statement is still true for the ``libvirt`` NSS module.
