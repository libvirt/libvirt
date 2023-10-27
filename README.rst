.. image:: https://gitlab.com/libvirt/libvirt/badges/master/pipeline.svg
     :target: https://gitlab.com/libvirt/libvirt/pipelines
     :alt: GitLab CI Build Status
.. image:: https://bestpractices.coreinfrastructure.org/projects/355/badge
     :target: https://bestpractices.coreinfrastructure.org/projects/355
     :alt: CII Best Practices
.. image:: https://translate.fedoraproject.org/widgets/libvirt/-/libvirt/svg-badge.svg
     :target: https://translate.fedoraproject.org/engage/libvirt/
     :alt: Translation status

==============================
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

https://libvirt.org


License
=======

The libvirt C API is distributed under the terms of GNU Lesser General
Public License, version 2.1 (or later). Some parts of the code that are
not part of the C library may have the more restrictive GNU General
Public License, version 2.0 (or later). See the files ``COPYING.LESSER``
and ``COPYING`` for full license terms & conditions.


Installation
============

Instructions on building and installing libvirt can be found on the website:

https://libvirt.org/compiling.html

Contributing
============

The libvirt project welcomes contributions in many ways. For most components
the best way to contribute is to send patches to the primary development
mailing list. Further guidance on this can be found on the website:

https://libvirt.org/contribute.html


Contact
=======

The libvirt project has two primary mailing lists:

* users@lists.libvirt.org (**for user discussions**)
* devel@lists.libvirt.org (**for development only**)

Further details on contacting the project are available on the website:

https://libvirt.org/contact.html
