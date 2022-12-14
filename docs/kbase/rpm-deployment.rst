.. role:: removed

=======================
RPM Deployment Guidance
=======================

.. contents::

A complete libvirt build includes a wide range of features, many of which are
dynamically loadable at runtime. Applications using libvirt typically only
need to use a subset of these features, and so do not require a full install
of all libvirt RPM packages.

This document provides some guidance on the RPM packages available with libvirt
on Fedora and related distributions, to enable applications and administrators
to pick the optimal set for their needs.

The RHEL and CentOS distributions use the same RPM packaging split, but many
of the drivers will be disabled at build time, so not all of the packages
listed on this page will exist.


Deployment choices
==================

Full features for one virt driver
---------------------------------

This is a common default installation profile when there is no need to minimise
the on-disk footprint.

This is achieved by installing the `libvirt-daemon-XXXX` package for the
virtualization driver that is desired. This will also pull in the default
set of hypervisor packages too.

Since this installs every possible libvirt feature for the virtualization
driver in question, the on-disk footprint is quite large. The in-memory
footprint of the daemons is also relatively large since a lot of code is
loaded.


Client only install
-------------------

If an application is capable of using multiple different virtualization drivers
it is undesirable to force the installation of a specific set of drivers. In
this case the application will merely wish to request a client only install

Alternatively if an application is intended to communicate with a hypervisor on
a remote host there is no need to install drivers locally, only a client is
needed

The only required package is the `libvirt-libs`, however, it is useful to
also install `libvirt-client`.


Minimal features for one virt driver
------------------------------------

This is the best installation profile when it is desired to minimize the
on-disk footprint.

This is achieved by installing the individual `libvirt-daemon-driver-XXX`
packages needed for the features that will be used.  This will not pull in the
hypervisor packages, allowing a fine grained set of hypervisor features to be
chosen separately.

Since this allows fine grained installation of individual libvirt drivers,
this results in the lowest on-disk footprint. The in-memory footprint of
the daemons is also minimized by reducing the code loaded.

As an example, the smallest possible installation for running KVM guests can
be achieved by installing `libvirt-daemon-driver-qemu` and `qemu-kvm-core`.
This will exclude all the secondary libvirt drivers for storage, networking
and host devices, leaving only the bare minimum functionality for managing
KVM guests.


Every possible virt driver
--------------------------

There is rarely a need to install every virt driver at once on a given host.
In the unlikely event that this is needed, however, the `libvirt` package
should be installed.

Note that this doesn't actually pull in the hypervisors, only the libvirt
code to talk to the hypervisors.


RPM packages
============

* libvirt

  This is an empty package that exists solely as a convenient way to install
  every other libvirt RPM package. Almost every deployment scenario would be
  better served by picking one of the other RPMs listed below.

* libvirt-client

  The virsh tool, used for interacting with any libvirt driver, both primary
  virt drivers and secondary drivers for storage, networking, etc. All libvirt
  installs should have this installed as it provides a useful way to view and
  debug what is being done by other applications using libvirt.

* libvirt-daemon

  The monolithic libvirtd daemon, traditionally used for running all the
  stateful drivers. This package does not contain any drivers, so further
  packages need to be installed to provide the desired drivers.

  New installations should not use this package, instead opting for one of
  the modular daemon deployment options.

* libvirt-daemon-common
  This package contains libvirt-guests, virt-host-validate, virt-ssh-helper
  and other utilities and configuration files necessary to create and
  administer a virtualization host.

  The virt-admin tool, used for administrative operations on any of the libvirt
  daemons, is also included in this package. It is most useful for reconfiguring
  logging filters and outputs on a running daemon without the need for a restart.

* libvirt-daemon-config-network

  The sample configuration file providing the 'default' virtual network that
  enables outbound NAT based connectivity for virtual machines. This is useful
  on desktop installations, but is not typically desired on server
  installations where VMs will use full bridged connectivity.

* libvirt-daemon-config-nwfilter

  The sample configuration files providing the network filters for protecting
  against common malicious guest traffic. This includes protection against ARP,
  MAC and IP spoofing. This is typically desired on server installations, if
  the mgmt app is using libvirt's network filtering features.

* libvirt-daemon-driver-interface

  The dynamically loadable driver providing an implementation of the host
  network interface management APIs, as well as the virtinterfaced daemon
  binary.

* libvirt-daemon-driver-libxl

  The dynamically loadable driver providing an implementation of the hypervisor
  APIs for Xen using the libxl library, as well as the virtxend daemon
  binary.

  Note that this is a minimal package so does not actually pull in the full
  Xen hypervisor package set. This be must requested separately.

* libvirt-daemon-driver-lxc

  The dynamically loadable driver providing an implementation of the hypervisor
  APIs for Linux containers, as well as the virtlxcd daemon binary.

* libvirt-daemon-driver-network

  The dynamically loadable driver providing an implementation of the virtual
  network interface management APIs, as well as the virtinterfaced daemon
  binary. Typically the libvirt-daemon-config-network RPM will also be desired
  when this is installed.

* libvirt-daemon-driver-nodedev

  The dynamically loadable driver providing an implementation of the host
  device management APIs, as well as the virtnodedevd daemon binary.

* libvirt-daemon-driver-nwfilter

  The dynamically loadable driver providing an implementation of the host
  network firewall management APIs, as well as the virtnwfilterd daemon
  binary.

* libvirt-daemon-driver-qemu

  The dynamically loadable driver providing an implementation of the hypervisor
  network interface management APIs, as well as the virtqemud daemon
  binary.

  Note that this is a minimal package so does not actually pull in the full
  QEMU or KVM package set. This be must requested separately.

* libvirt-daemon-driver-secret

  The dynamically loadable driver providing an implementation of the secret
  data management APIs, as well as the virtsecretd daemon binary.

* libvirt-daemon-driver-storage

  This is an empty package that exists only as a convenient way to request
  installation of all the storage pool drivers.

  If the application only supports a subset of storage pool types, then
  a smaller install footprint can be obtained by requesting the individual
  drivers.

* libvirt-daemon-driver-storage-core

  The dynamically loadable driver providing an implementation of the host
  storage pool/volume management APIs, as well as the virtstoraged daemon
  binary.

  Note that this is a minimal package so does not actually pull in any pool
  implementations.

* libvirt-daemon-driver-storage-disk

  The dynamically loadable driver providing an implementation of the disk
  partition storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-gluster

  The dynamically loadable driver providing an implementation of the GlusterFS
  file storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-iscsi

  The dynamically loadable driver providing an implementation of the ISCSI
  disk storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-iscsi-direct

  The dynamically loadable driver providing an implementation of the ISCSI
  network storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-logical

  The dynamically loadable driver providing an implementation of the LVM
  storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-mpath

  The dynamically loadable driver providing an implementation of the multipath
  disk storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-rbd

  The dynamically loadable driver providing an implementation of the RBD
  network storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-scsi

  The dynamically loadable driver providing an implementation of the SCSI
  disk storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-storage-sheepdog

  The dynamically loadable driver providing an implementation of the SheepDog
  network storage pool type, for the storage pool management APIs. This
  sub-package was :removed:`removed in libvirt-8.8` as the sheepdog backend
  driver was dropped from upstream.

* libvirt-daemon-driver-storage-zfs

  The dynamically loadable driver providing an implementation of the ZFS
  file storage pool type, for the storage pool management APIs.

* libvirt-daemon-driver-vbox

  The dynamically loadable driver providing an implementation of the host
  network interface management APIs, as well as the virtinterfaced daemon
  binary.

* libvirt-daemon-kvm

  This is an empty package that exists only as a convenient way to request
  installation of all the libvirt features that are relevant to the management
  of KVM guests. This includes the QEMU driver, and the secondary drivers for
  secrets, storage pools, virtual networks, host interfaces, host devices
  and network filtering.

  It will also pull in the full set of QEMU features that can be utilized with
  native architecture KVM guests.

  This is a good default for an installation to use KVM if the specific set of
  required features is not known. To have finer grained control over the
  features, the subset of libvirt-daemon-driver-XXX packages should be used
  instead.

* libvirt-daemon-lock
  This package provides virtlockd, a server side daemon used to manage locks
  held against virtual machine resources.

* libvirt-daemon-log
  This package provides virtlogd, a server side daemon used to manage logs
  from virtual machine consoles.

* libvirt-daemon-lxc

  This is an empty package that exists only as a convenient way to request
  installation of all the libvirt features that are relevant to the management
  of Linux containers. This includes the LXC driver, and the secondary drivers
  for secrets, storage pools, virtual networks, host interfaces, host devices
  and network filtering.

  This is a good default for an installation to use LXC if the specific set of
  required features is not known. To have finer grained control over the
  features, the subset of libvirt-daemon-driver-XXX packages should be used
  instead.

* libvirt-daemon-plugin-lockd
  This package provides the lockd.so module, a daemon plugin that implements
  disk locking using POSIX fcntl advisory locks via communication with the
  virtlockd daemon.

* libvirt-daemon-plugin-sanlock

  This package provides the sanlock.so module, a daemon plugin that implements
  disk locking via communication with the sanlock daemon. It is optional and
  only relevant to hosts with the QEMU driver and oVirt management application.

* libvirt-daemon-proxy
  This package provides virtproxyd, a server side daemon providing remote
  network access to libvirt daemons, as well as backwards compatibility
  for older libvirt clients expecting to communicate with the traditional,
  monolithic libvirtd.

* libvirt-daemon-qemu

  This is an empty package that exists only as a convenient way to request
  installation of all the libvirt features that are relevant to the management
  of QEMU guests. This includes the QEMU driver, and the secondary drivers for
  secrets, storage pools, virtual networks, host interfaces, host devices
  and network filtering.

  It will also pull in the full set of QEMU features that can be utilized to
  emulate any guests architecture supported by QEMU.

  This is a good default for an installation to use QEMU if the specific set of
  required features is not known. To have finer grained control over the
  features, the subset of libvirt-daemon-driver-XXX packages should be used
  instead.

* libvirt-daemon-vbox

  This is an empty package that exists only as a convenient way to request
  installation of all the libvirt features that are relevant to the management
  of KVM guests. This includes the QEMU driver, and the secondary drivers for
  secrets, storage pools, virtual networks, host interfaces, host devices
  and network filtering.

  This is a good default for an installation to use VirtualBox if the specific
  set of required features is not known. To have finer grained control over the
  features, the subset of libvirt-daemon-driver-XXX packages should be used
  instead.

* libvirt-daemon-xen

  This is an empty package that exists only as a convenient way to request
  installation of all the libvirt features that are relevant to the management
  of KVM guests. This includes the QEMU driver, and the secondary drivers for
  secrets, storage pools, virtual networks, host interfaces, host devices
  and network filtering.

  It will also pull in the full set of Xen features that can be utilized with
  Xen guests.

  This is a good default for an installation to use Xen if the specific set of
  required features is not known. To have finer grained control over the
  features, the subset of libvirt-daemon-driver-XXX packages should be used
  instead.

* libvirt-devel

  The header files required to build applications, or language bindings against
  the libvirt C library. This should never be required on a production host,
  only development hosts.

* libvirt-docs

  A local copy of the `libvirt website <https://libvirt.org>`_ website content
  that matches the deployed version of libvirt.

* libvirt-libs

  The ELF libraries providing the main application interface to libvirt. These
  have stateless drivers (VMWare ESX, HyperV, etc) built-in, and are able to
  take to the libvirt daemons to utilize stateful drivers (QEMU, Xen, BHyve,
  LXC, VZ, etc). This is needed on all libvirt hosts, both client and server.

* libvirt-login-shell

  A simple login shell that automatically spawns an LXC container for the user
  logging in and places them in a shell inside that container.

* libvirt-nss

  A NSS plugin that provides hostname resolution for guests attached to a
  libvirt virtual network. It is recommended to be installed on any host with
  guests using the libvirt virtual network connectivity.

* libvirt-wireshark

  A wireshark plugin that allows for dissecting the XDR based RPC protocol used
  between libvirt and its daemons. Since production deployments should all be
  using a TLS encrypted, this only useful for development hosts with a libvirt
  daemon configured without encryption.
