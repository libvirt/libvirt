=============
Documentation
=============

Deployment / operation
----------------------

`Applications <apps.html>`__
   Applications known to use libvirt

`Manual pages <manpages/index.html>`__
   Manual pages for libvirt tools / daemons

`Windows <windows.html>`__
   Downloads for Windows

`macOS <macos.html>`__
   Working with libvirt on macOS

`Migration <migration.html>`__
   Migrating guests between machines

`Daemons <daemons.html>`__
   Overview of the daemons provided by libvirt

`Remote access <remote.html>`__
   Enable remote access over TCP

`TLS certs <tlscerts.html>`__
   Generate and deploy x509 certificates for TLS

`Authentication <auth.html>`__
   Configure authentication for the libvirt daemon

`Access control <acl.html>`__
   Configure access control libvirt APIs with `polkit <aclpolkit.html>`__

`Logging <logging.html>`__
   The library and the daemon logging support

`Audit log <auditlog.html>`__
   Audit trail logs for host operations

`Firewall <firewall.html>`__
   Firewall and network filter configuration

`Hooks <hooks.html>`__
   Hooks for system specific management

`NSS module <nss.html>`__
   Enable domain host name translation to IP addresses

`FAQ <https://wiki.libvirt.org/page/FAQ>`__
   Frequently asked questions

Application development
-----------------------

`API reference <html/index.html>`__
   Reference manual for the C public API, split in
   `common <html/libvirt-libvirt-common.html>`__,
   `domain <html/libvirt-libvirt-domain.html>`__,
   `domain checkpoint <html/libvirt-libvirt-domain-checkpoint.html>`__,
   `domain snapshot <html/libvirt-libvirt-domain-snapshot.html>`__,
   `error <html/libvirt-virterror.html>`__,
   `event <html/libvirt-libvirt-event.html>`__,
   `host <html/libvirt-libvirt-host.html>`__,
   `interface <html/libvirt-libvirt-interface.html>`__,
   `network <html/libvirt-libvirt-network.html>`__,
   `node device <html/libvirt-libvirt-nodedev.html>`__,
   `network filter <html/libvirt-libvirt-nwfilter.html>`__,
   `secret <html/libvirt-libvirt-secret.html>`__,
   `storage <html/libvirt-libvirt-storage.html>`__,
   `stream <html/libvirt-libvirt-stream.html>`__ and
   `admin <html/index-admin.html>`__,
   `QEMU <html/index-qemu.html>`__,
   `LXC <html/index-lxc.html>`__ libs

`Language bindings and API modules <bindings.html>`__
   Bindings of the libvirt API for
   `c# <csharp.html>`__,
   `go <https://pkg.go.dev/libvirt.org/go/libvirt>`__,
   `java <java.html>`__,
   `ocaml <https://libvirt.org/ocaml/>`__,
   `perl <https://search.cpan.org/dist/Sys-Virt/>`__,
   `python <python.html>`__,
   `php <php.html>`__,
   `ruby <https://libvirt.org/ruby/>`__
   and integration API modules for
   `D-Bus <dbus.html>`__

`XML schemas <format.html>`__
   Description of the XML schemas for
   `domains <formatdomain.html>`__,
   `networks <formatnetwork.html>`__,
   `network ports <formatnetworkport.html>`__,
   `network filtering <formatnwfilter.html>`__,
   `storage <formatstorage.html>`__,
   `storage encryption <formatstorageencryption.html>`__,
   `capabilities <formatcaps.html>`__,
   `domain capabilities <formatdomaincaps.html>`__,
   `storage pool capabilities <formatstoragecaps.html>`__,
   `node devices <formatnode.html>`__,
   `secrets <formatsecret.html>`__,
   `snapshots <formatsnapshot.html>`__,
   `checkpoints <formatcheckpoint.html>`__,
   `backup jobs <formatbackup.html>`__

`URI format <uri.html>`__
   The URI formats used for connecting to libvirt

`CGroups <cgroups.html>`__
   Control groups integration

`Drivers <drivers.html>`__
   Hypervisor specific driver information

`Support guarantees <support.html>`__
   Details of support status for various interfaces

`Driver support <hvsupport.html>`__
   matrix of API support per hypervisor per release

`Knowledge Base <kbase/index.html>`__
   Task oriented guides to key features

Project development
-------------------

`Contributor guidelines <hacking.html>`__
   General hacking guidelines for contributors

`Docs style guide <styleguide.html>`__
   Style guidelines for reStructuredText docs

`Project strategy <strategy.html>`__
   Sets a vision for future direction & technical choices

`CI Testing <ci.html>`__
   Details of the Continuous Integration testing strategy

`Bug reports <bugs.html>`__
   How and where to report bugs and request features

`Compiling <compiling.html>`__
   How to compile libvirt

`Goals <goals.html>`__
   Terminology and goals of libvirt API

`API concepts <api.html>`__
   The libvirt API concepts

`API extensions <api_extension.html>`__
   Adding new public libvirt APIs

`Functional testing <testsuites.html>`__
   Testing libvirt with
   `TCK test suite <testtck.html>`__ and
   `Libvirt-test-API <testapi.html>`__

`New repo setup <newreposetup.html>`__
   Procedure for configuring new git repositories for libvirt
