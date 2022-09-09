====================
libvirt Installation
====================

.. contents::

Installing from distribution repositories
-----------------------------------------

This is the recommended option to install libvirt. Libvirt is present in the
package repositories of all major distributions. Installing a package from the
package manager ensures that it's properly compiled, installed, and updated
during the lifecycle of the distribution.

For users who wish to use the most recent version, certain distributions also
allow installing the most recent versions of virtualization packages:

  **Fedora**

    Refer to https://fedoraproject.org/wiki/Virtualization_Preview_Repository

  **Gentoo**

   The ``app-emulation/libvirt`` is regularly updated, but newest versions are
   usually marked as testing by the ``~*`` keyword.

Compiling a release tarball
---------------------------

libvirt uses the standard setup/build/install steps and mandates that
the build directory is different from the source directory:

::

   $ xz -dc libvirt-x.x.x.tar.xz | tar xvf -
   $ cd libvirt-x.x.x
   $ meson build

The *meson* script can be given options to change its default behaviour.

**Note:** Please ensure that you have the appropriate minimal ``meson`` version
installed in your build environment. The minimal version for a specific package
can be checked in the top level ``meson.build`` file in the ``meson_version``
field.

To get the complete list of the options run the following command:

::

   $ meson configure

When you have determined which options you want to use (if any),
continue the process.

::

   $ meson build [possible options]
   $ ninja -C build

The ``build`` directory now contains the built binaries.

Building from a GIT checkout
----------------------------

The libvirt build process uses Meson build system. By default when the
``meson`` is run from within a GIT checkout, it will turn on -Werror for
builds. This can be disabled with --werror=false, but this is not
recommended.

To build & install libvirt to your home directory the following commands
can be run:

::

   $ meson build --prefix=$HOME/usr
   $ ninja -C build

Be aware though, that binaries built with a custom prefix will not
interoperate with OS vendor provided binaries, since the UNIX socket
paths will all be different. To produce a build that is compatible with
normal OS vendor prefixes, use

::

   $ meson build -Dsystem=true
   $ ninja -C build

The ``build`` directory now contains the built binaries.

Running compiled binaries from build directory
----------------------------------------------

For testing or development purposes it's usually not necessary to install the
built binaries into your system. Instead simply run libvirt directly from the
source tree. For example to run a privileged libvirtd instance

::

   $ su -
   # service libvirtd stop  (or systemctl stop libvirtd.service)
   # /home/to/your/checkout/build/src/libvirtd


It is also possible to run virsh directly from the build tree using the
./run script (which sets some environment variables):

::

   $ pwd
   /home/to/your/checkout/build
   $ ./run ./tools/virsh ....

Installing compiled binaries
----------------------------

**Important:** Manual installation of libvirt is generally not recommended and
you should prefer installation from your operating system's package repository
or from manually built packages which are then installed using the package
manager. Overwriting an installation of libvirt from the package manager by a
manually compiled installation may not work properly.

Installing the compiled binaries into the appropriate location (based on
how the build was configured) is done by the following command:

::

   $ sudo ninja -C build install

Note the use of **sudo** with the *ninja install* command. Using
sudo is only required when installing to a location your user does not
have write access to. Installing to a system location is a good example
of this.

If you are installing to a location that your user *does* have write
access to, then you can instead run the *ninja install* command without
putting **sudo** before it.

After installation you you **may** have to run ``ldconfig`` or a similar
utility to update your list of installed shared libs, or adjust the paths where
the system looks for binaries and shared libraries.
