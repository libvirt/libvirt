===============
Windows support
===============

.. contents::

Libvirt is known to work as a client (not server) on Windows XP (32-bit), and
Windows 7 (64-bit). Other Windows variants likely work as well but we either
haven't tested or received reports for them.

Installation packages
---------------------

Users who need pre-built Windows DLLs of libvirt are advised to use the `Virt
Viewer <https://virt-manager.org>`__ pre-compiled `Windows MSI
packages <https://virt-manager.org/download/>`__

These installers include the libvirt, gtk-vnc and spice-gtk DLLs along with any
of their pre-requisite supporting DLLs, the virsh command line tool and the
virt-viewer & remote-viewer graphical tools. The development headers are not
currently provided in this installer, so this cannot be used for compiling new
applications against libvirt.

Connection types
----------------

These connection types are known to work:

-  QEMU with TLS (qemu+tls://)

-  QEMU with direct TCP (qemu+tcp://)

-  VMware ESX (esx://)

-  VMware VPX (vpx://)

These connection types are known not to work:

-  QEMU with SSH (qemu+ssh://)

All other connection types may or may not work, and haven't been tested.

Please let us know either the results (either way) if you do.

**Special note** - Support for VirtualBox \*on windows\* was added in libvirt
0.8.7, so reports on success and failure if you're using that would be really
helpful and appreciated.

**WARNING - The qemu+tcp:// connection type passes all traffic without
encryption. This is a security hazard, and should not be used in security
sensitive environments.**

Connecting to VMware ESX/vSphere
--------------------------------

Details on the capabilities, certificates, and connection string syntax used for
connecting to VMware ESX and vSphere can be found online here:

https://libvirt.org/drvesx.html

TLS Certificates
----------------

TLS certificates need to have been created and placed in the correct locations,
before you will be able to connect to QEMU servers over TLS.

Information on generating TLS certificates can be found here:

https://wiki.libvirt.org/page/TLSSetup

These instructions are for \*nix, and have not yet been adapted for Windows.
You'll need to figure out the Windows equivalents until that's done (sorry). If
you can help us out with this, that would be really welcome.

The locations of the TLS certificates and key file on Windows are hard coded,
rather than being configurable.

The Certificate Authority (CA) certificate file must be placed in:

-  %APPDATA%\libvirt\pki\CA\cacert.pem

The Client certificate file must be placed in:

-  %APPDATA%\libvirt\pki\libvirt\clientcert.pem

The Client key file must be placed in:

-  %APPDATA%\libvirt\pki\libvirt\private\clientkey.pem

On an example Windows 7 x64 system here, this resolves to these paths:

-  C:\Users\someuser\AppData\Roaming\libvirt\pki\CA\cacert.pem

-  C:\Users\someuser\AppData\Roaming\libvirt\pki\libvirt\clientcert.pem

-  C:\Users\someuser\AppData\Roaming\libvirt\pki\libvirt\private\clientkey.pem

Feedback
--------

Feedback and suggestions on changes to make and what else to include `are
desired <contact.html>`__.

Compiling yourself
------------------

Libvirt can be compiled on Windows using the free `MinGW-w64
compiler <https://www.mingw-w64.org/>`__.

MSYS Build script
~~~~~~~~~~~~~~~~~

The easiest way is to use the **msys_setup** script, developed by Matthias
Bolte. This is actively developed and kept current with libvirt releases:

https://github.com/photron/msys_setup

Cross compiling
~~~~~~~~~~~~~~~

You can also cross-compile to a Windows target from a Fedora machine using the
packages available in the Fedora repos.

By hand
~~~~~~~

Use these options when following the instructions on the
`Compiling <compiling.html>`__ page.

::

   meson build \
     -Dsasl=disabled \
     -Dpolkit=disabled \
     -Ddriver_libxl=disabled \
     -Ddriver_qemu=disabled \
     -Ddriver_lxc=disabled \
     -Ddriver_openvz=disabled \
     -Ddriver_libvirtd=disabled
