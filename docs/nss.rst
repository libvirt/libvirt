.. role:: since

==================
Libvirt NSS module
==================

.. contents::

Effectively managing guests often requires connecting to them via SSH, same as
you would for any remote machine. Ideally

::

   $ ssh user@mydomain

would work out of the box, but depending on the network configuration that
might not be the case. Setting up the libvirt NSS module is a one-time
operation that makes the process of connecting from the host to the guests
running on it much more convenient.

Note that this feature only works in certain scenarios. See the
`limitations`_ section for more information.

Installation
------------

Installing the module on Fedora or RHEL is really easy:

::

   # dnf install libvirt-nss

The package might have a different name on other distributions, but the process
of installing it will be similar.

Configuration
-------------

To enable the module, modify ``/etc/nsswitch.conf`` so that the ``hosts`` line
looks similar to

::

   hosts: files libvirt libvirt_guest dns

With this configuration, whenever SSH (or any other application)
tries to contact a guest, the ``files`` module will be consulted first (this
boils down to searching for a matching line in ``/etc/hosts``); if no IP
address could be found that way, the ``libvirt`` and ``libvirt_guest`` modules
(see `below <variants_>`__ for differences between the two) will be used
instead. Finally, if no previous attempt at resolving the hostname was
successful, a DNS query will be performed.

Variants
--------

There are two different variants of the module:

* ``libvirt`` (:since:`since 1.3.3`) resolves hostnames based on the
  information that the guest OS itself has reported to the DHCP server when
  asking for an IP address, so it won't work if the guest OS hasn't been fully
  configured yet;

* ``libvirt_guest`` (:since:`since 3.0.0`) resolves hostnames by mapping them
  directly to libvirt domain names, so it will work regardless of how the guest
  OS is configured and will have more predictable results.

The recommended configuration seen above enables both of them and gives
priority to the former but it's also possible to enable only a single one, or
to alter the precedence by simply changing the order in which they are listed.

Implementation details
----------------------

Whenever a Unix process needs to convert a hostname into an IP address, it will
call the `gethostbyname() <https://linux.die.net/man/3/gethostbyname>`__ libc
function or one of its variants.

Since multiple sources for this information are possible (for example the
contents of ``/etc/hosts``, DNS, LDAP, etc.) a mechanism called
`NSS <https://en.wikipedia.org/wiki/Name_Service_Switch>`__ has been created to
make the name resolution process extensible. This allows each source to be
implemented as a separate plugin that can be enabled or disabled based on the
administrator's preferences.

In the case of libvirt, the lookup is performed by inspecting the DHCP leases
handed out by ``dnsmasq``, the software used to implement NATed networks. The
results will be the same that would be reported by

::

   $ virsh domifaddr --source lease mydomain

except that things will work transparently for any application that uses the
libc resolver, without it needing to link against libvirt or even be aware of
its existence.

Limitations
-----------

Since the libvirt NSS module works by looking at ``dnsmasq``, it can only work
for guests that are connected to a NATed libvirt network. Guests that obtain
their IP addresses in any other way (usermode networking, assigned network
devices and so on) will not be able to have their hostnames resolved through
it.

Alternatives
------------

:since:`Since 10.3.0`, libvirt implements an `SSH proxy <ssh-proxy.html>`__.
This allows the use of SSH even for guests that have no network connectivity,
by communicating over VSOCK.
