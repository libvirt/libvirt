=======================
Contributing to libvirt
=======================

Full, up to date information on how to contribute to libvirt can be
found on the libvirt website:

https://libvirt.org/contribute.html

To build the same document locally, from the top level directory of
your git clone run:

::

   $ meson build
   $ ninja -C build

You'll find the freshly-built document in ``docs/contribute.html``.

If ``meson setup`` fails because of missing dependencies, you can set
up your system by calling

::

   $ sudo dnf builddep libvirt

if you're on a RHEL-based distribution or

::

   $ sudo apt-get build-dep libvirt

if you're on a Debian-based one.

Note that, for the RHEL-based case, if you're on a machine where you
haven't done any C development before, you will probably also need
to run

::

   $ sudo dnf install gcc make ninja-build rpm-build

You might still be missing some dependencies if your distribution is
shipping an old libvirt version, but that will get you much closer to
where you need to be to build successfully from source.
