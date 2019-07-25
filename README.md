[![Build Status](https://travis-ci.org/libvirt/libvirt.svg)](https://travis-ci.org/libvirt/libvirt)
 [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/355/badge)](https://bestpractices.coreinfrastructure.org/projects/355)

Libvirt API for virtualization
==============================

Libvirt provides a portable, long term stable C API for managing the
virtualization technologies provided by many operating systems. It
includes support for QEMU, KVM, Xen, LXC, bhyve, Virtuozzo, VMware
vCenter and ESX, VMware Desktop, Hyper-V, VirtualBox and the POWER
Hypervisor.

For some of these hypervisors, it provides a stateful management
daemon which runs on the virtualization host allowing access to the
API both by non-privileged local users and remote users.

Layered packages provide bindings of the libvirt C API into other
languages including Python, Perl, PHP, Go, Java, OCaml, as well as
mappings into object systems such as GObject, CIM and SNMP.

Further information about the libvirt project can be found on the
website:

[https://libvirt.org](https://libvirt.org)


License
-------

The libvirt C API is distributed under the terms of GNU Lesser General
Public License, version 2.1 (or later). Some parts of the code that are
not part of the C library may have the more restrictive GNU General
Public License, version 2.0 (or later). See the files `COPYING.LESSER`
and `COPYING` for full license terms & conditions.


Installation
------------

Libvirt uses the GNU Autotools build system, so in general can be built
and installed with the usual commands. For example, to build in a manner
that is suitable for installing as root, use:

```
$ ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
$ make
$ sudo make install
```

While to build & install as an unprivileged user

```
$ ./configure --prefix=$HOME/usr
$ make
$ make install
```

The libvirt code relies on a large number of 3rd party libraries. These will
be detected during execution of the `configure` script and a summary printed
which lists any missing (optional) dependencies.


Contributing
------------

The libvirt project welcomes contributions in many ways. For most components
the best way to contribute is to send patches to the primary development
mailing list. Further guidance on this can be found on the website:

[https://libvirt.org/contribute.html](https://libvirt.org/contribute.html)


Contact
-------

The libvirt project has two primary mailing lists:

  * libvirt-users@redhat.com (**for user discussions**)
  * libvir-list@redhat.com (**for development only**)

Further details on contacting the project are available on the website:

[https://libvirt.org/contact.html](https://libvirt.org/contact.html)
