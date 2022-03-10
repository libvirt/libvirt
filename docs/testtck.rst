==========================================
libvirt TCK : Technology Compatibility Kit
==========================================

The libvirt TCK provides a framework for performing testing of the integration
between libvirt drivers, the underlying virt hypervisor technology, related
operating system services and system configuration. The idea (and name) is
motivated by the Java TCK.

In particular the libvirt TCK is intended to address the following scenarios:

-  Validate that a new libvirt driver is in compliance with the (possibly
   undocumented!) driver API semantics
-  Validate that an update to an existing driver does not change the API
   semantics in a non-compliant manner
-  Validate that a new hypervisor release is still providing compatibility with
   the corresponding libvirt driver usage
-  Validate that an OS distro deployment consisting of a hypervisor and libvirt
   release is configured correctly

Thus the libvirt TCK will allow developers, administrators and users to
determine the level of compatibility of their platform, and evaluate whether it
will meet their needs, and get awareness of any regressions that may have
occurred since a previous test run.

For more details you can look at:

-  The initial `mail from Daniel
   Berrange <https://www.redhat.com/archives/libvir-list/2009-April/msg00176.html>`__
   presenting the project.
-  The `page describing
   VirtTCK <https://fedoraproject.org/wiki/Features/VirtTCK>`__ the inclusion of
   libvirt-TCK as a Fedora Feature.

Libvirt-TCK is maintained using `a GIT
repository <https://gitlab.com/libvirt/libvirt-tck>`__, and comment, patches and
reviews are carried on the `libvir-list <contact.html>`__ development list.
