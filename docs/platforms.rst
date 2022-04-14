========================
Supported host platforms
========================

.. contents::

Libvirt aims to support building and executing on multiple host OS platforms,
as well as working with multiple hypervisors. This document outlines which
platforms are targeted for each of these areas.


Build targets
=============

These platforms are used as the basis for deciding upon the minimum required
versions of 3rd party software libvirt depends on. If a platform is not listed
here, it does not imply that libvirt won't work. If an unlisted platform has
comparable software versions to a listed platform, there is every expectation
that it will work.  Bug reports are welcome for problems encountered on
unlisted platforms unless they are clearly older vintage than what is described
here.

Note that when considering software versions shipped in distros as support
targets, libvirt considers only the version number, and assumes the features in
that distro match the upstream release with the same version. In other words,
if a distro backports extra features to the software in their distro, libvirt
upstream code will not add explicit support for those backports, unless the
feature is auto-detectable in a manner that works for the upstream releases
too.

The `Repology`_ site is a useful resource to identify currently shipped
versions of software in various operating systems, though it does not cover all
distros listed below.

* `libvirt on Repology`_
* `qemu on Repology`_

Linux, FreeBSD and macOS
------------------------

The project aims to support the most recent major version at all times. Support
for the previous major version will be dropped 2 years after the new major
version is released or when the vendor itself drops support, whichever comes
first. In this context, third-party efforts to extend the lifetime of a distro
are not considered, even when they are endorsed by the vendor (e.g. Debian
LTS); the same is true of repositories that contain packages backported from
later releases (e.g. Debian backports). Within each major release, only the
most recent minor release is considered.

For the purposes of identifying supported software versions available on Linux,
the project will look at CentOS, Debian, Fedora, openSUSE, RHEL, SLES and
Ubuntu LTS. Other distros will be assumed to ship similar software versions.

For FreeBSD, decisions will be made based on the contents of the ports tree;
for macOS, `Homebrew`_ will be used, although `MacPorts`_ is expected to carry
similar versions.

Windows
-------

The project supports building with current versions of the MinGW toolchain,
hosted on Linux.

The version of the Windows API that's currently targeted is Vista / Server
2008.


Virtualization platforms
========================

For `hypervisor drivers`_ which execute locally (QEMU, LXC, VZ, libxl, etc),
the set of supported operating system platforms listed above will inform
choices as to the minimum required versions of 3rd party libraries and
hypervisor management APIs.

If a hypervisor is not commonly shipped directly by any distro listed above,
(VMware ESX, HyperV, VZ), the project aims to support versions up to 5 years,
or until the vendor discontinues support, whichever comes first.


.. _Homebrew: https://brew.sh/
.. _MacPorts: https://www.macports.org/
.. _Repology: https://repology.org/
.. _hypervisor drivers: drivers.html
.. _libvirt on Repology: https://repology.org/metapackage/libvirt/versions
.. _qemu on Repology: https://repology.org/metapackage/qemu/versions
