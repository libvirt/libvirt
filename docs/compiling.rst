====================
libvirt Installation
====================

.. contents::

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

Note the use of **sudo** with the *ninja install* command below. Using
sudo is only required when installing to a location your user does not
have write access to. Installing to a system location is a good example
of this.

If you are installing to a location that your user *does* have write
access to, then you can instead run the *ninja install* command without
putting **sudo** before it.

::

   $ meson build [possible options]
   $ ninja -C build
   $ sudo ninja -C build install

At this point you **may** have to run ldconfig or a similar utility to
update your list of installed shared libs.

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
   $ sudo ninja -C build install

Be aware though, that binaries built with a custom prefix will not
interoperate with OS vendor provided binaries, since the UNIX socket
paths will all be different. To produce a build that is compatible with
normal OS vendor prefixes, use

::

   $ meson build -Dsystem=true
   $ ninja -C build


When doing this for day-to-day development purposes, it is recommended
not to install over the OS vendor provided binaries. Instead simply run
libvirt directly from the source tree. For example to run a privileged
libvirtd instance

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
