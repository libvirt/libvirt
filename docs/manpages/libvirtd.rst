========
libvirtd
========

-------------------------
libvirt management daemon
-------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``libvirtd`` [*OPTION*]...


DESCRIPTION
===========

The ``libvirtd`` program is the server side daemon component of the libvirt
virtualization management system.

This daemon runs on host servers and performs required management tasks for
virtualized guests.  This includes activities such as starting, stopping
and migrating guests between host servers, configuring and manipulating
networking, and managing storage for use by guests.

The libvirt client libraries and utilities connect to this daemon to issue
tasks and collect information about the configuration and resources of the host
system and guests.

By default, the ``libvirtd`` daemon listens for requests on a local Unix domain
socket.  Using the ``-l`` | ``--listen`` command line option, the ``libvirtd``
daemon can be instructed to additionally listen on a TCP/IP socket.  The TCP/IP
socket to use is defined in the ``libvirtd`` configuration file.

Restarting ``libvirtd`` does not impact running guests.  Guests continue to
operate and will be picked up automatically if their XML configuration has been
defined.  Any guests whose XML configuration has not been defined will be lost
from the configuration.


SYSTEM SOCKET ACTIVATION
========================

The ``libvirtd`` daemon is capable of starting in two modes.

In the traditional mode, it will create and listen on UNIX sockets itself.
If the ``--listen`` parameter is given, it will also listen on TCP/IP socket(s),
according to the ``listen_tcp`` and ``listen_tls`` options in
``/etc/libvirt/libvirtd.conf``

In socket activation mode, it will rely on systemd to create and listen
on the UNIX, and optionally TCP/IP, sockets and pass them as pre-opened
file descriptors. In this mode, it is not permitted to pass the ``--listen``
parameter, and most of the socket related config options in
``/etc/libvirt/libvirtd.conf`` will no longer have any effect. To enable
TCP or TLS sockets use either

::

   $ systemctl start libvirtd-tls.socket

Or

::

   $ systemctl start libvirtd-tcp.socket

Socket activation mode is generally the default when running on a host
OS that uses systemd. To revert to the traditional mode, all the socket
unit files must be masked:

::

   $ systemctl mask libvirtd.socket libvirtd-ro.socket \
      libvirtd-admin.socket libvirtd-tls.socket libvirtd-tcp.socket

On top of that make sure that the --timeout argument is not used for the daemon
since it would not be started upon any later connection.

If using libvirt-guests service then the ordering for that service needs to be
adapted so that it is ordered after the service unit instead of the socket unit.
Since dependencies and ordering cannot be changed with drop-in overrides, the
whole libvirt-guests unit file needs to be changed.  In order to preserve such
change copy the installed ``/usr/lib/systemd/system/libvirt-guests.service`` to
``/etc/systemd/system/libvirt-guests.service`` and make the change there,
specifically make sure the ``After=`` ordering mentions ``libvirtd.service`` and
not ``libvirtd.socket``:

::

   [Unit]
   After=libvirtd.service


OPTIONS
=======

``-h``, ``--help``

Display command line help usage then exit.

``-d``, ``--daemon``

Run as a daemon & write PID file.

``-f``, ``--config *FILE*``

Use this configuration file, overriding the default value.

``-l``, ``--listen``

Listen for TCP/IP connections. This should not be set if using systemd
socket activation. Instead activate the ``libvirtd-tls.socket`` or
``libvirtd-tcp.socket`` unit files.

``-p``, ``--pid-file *FILE*``

Use this name for the PID file, overriding the default value.

``-t``, ``--timeout *SECONDS*``

Exit after timeout period (in seconds), provided there are neither any client
connections nor any running domains.

``-v``, ``--verbose``

Enable output of verbose messages.

``--version``

Display version information then exit.


SIGNALS
=======

On receipt of ``SIGHUP`` ``libvirtd`` will reload its configuration.


FILES
=====

When run as *root*
------------------

* ``@SYSCONFDIR@/libvirt/libvirtd.conf``

The default configuration file used by ``libvirtd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

Depending on what driver is installed, then the following files are also read:

* ``@SYSCONFDIR@/libvirt/qemu.conf`` for the QEMU driver
* ``@SYSCONFDIR@/libvirt/lxc.conf`` for the LXC driver
* ``@SYSCONFDIR@/libvirt/libxl.conf`` for the libxl driver

These files contain various knobs and default values for virtual machines
created within their respective drivers, and offer a way to override the built
in defaults, for instance (but not limited to): paths to various supplementary
binaries, TLS certificates location, graphical consoles configuration and
others. Location of neither of these files can be overridden by any command
line switch.

* ``@RUNSTATEDIR@/libvirt/libvirt-sock``
* ``@RUNSTATEDIR@/libvirt/libvirt-sock-ro``

The sockets ``libvirtd`` will use.

* ``@SYSCONFDIR@/pki/CA/cacert.pem``

The TLS **Certificate Authority** certificate ``libvirtd`` will use.

* ``@SYSCONFDIR@/pki/libvirt/servercert.pem``

The TLS **Server** certificate ``libvirtd`` will use.

* ``@SYSCONFDIR@/pki/libvirt/private/serverkey.pem``

The TLS **Server** private key ``libvirtd`` will use.

* ``@RUNSTATEDIR@/libvirtd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.


When run as *non-root*
----------------------

* ``$XDG_CONFIG_HOME/libvirt/libvirtd.conf``

The default configuration file used by ``libvirtd``, unless overridden on the
command line using the ``-f``|``--config`` option.

If QEMU driver is installed, then the following file is also read:

* ``$XDG_CONFIG_HOME/libvirt/qemu.conf``

If the file exists, it can contain various knobs and default values for virtual
machines created within QEMU driver, and offers a way to override the built in
defaults, for instance (but not limited to): paths to various supplementary
binaries, TLS certificates location, graphical consoles configuration and
others. Location of this file can't be overridden by any command line switch.

* ``$XDG_RUNTIME_DIR/libvirt/libvirt-sock``

The socket ``libvirtd`` will use.

* ``$HOME/.pki/libvirt/cacert.pem``

The TLS **Certificate Authority** certificate ``libvirtd`` will use.

* ``$HOME/.pki/libvirt/servercert.pem``

The TLS **Server** certificate ``libvirtd`` will use.

* ``$HOME/.pki/libvirt/serverkey.pem``

The TLS **Server** private key ``libvirtd`` will use.

* ``$XDG_RUNTIME_DIR/libvirt/libvirtd.pid``

The PID file to use, unless overridden by the ``-p``|``--pid-file`` option.


If ``$XDG_CONFIG_HOME`` is not set in your environment, ``libvirtd`` will use
``$HOME/.config``

If ``$XDG_RUNTIME_DIR`` is not set in your environment, ``libvirtd`` will use
``$HOME/.cache``


EXAMPLES
========

To retrieve the version of ``libvirtd``:

::

  # libvirtd --version
  libvirtd (libvirt) @VERSION@


To start ``libvirtd``, instructing it to daemonize and create a PID file:

::

  # libvirtd -d
  # ls -la @RUNSTATEDIR@/libvirtd.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/libvirtd.pid


BUGS
====

Please report all bugs you discover.  This should be done via either:

#. the mailing list

   `https://libvirt.org/contact.html <https://libvirt.org/contact.html>`_

#. the bug tracker

   `https://libvirt.org/bugs.html <https://libvirt.org/bugs.html>`_

Alternatively, you may report bugs to your software distributor / vendor.


AUTHORS
=======

Please refer to the AUTHORS file distributed with libvirt.


COPYRIGHT
=========

Copyright (C) 2006-2012 Red Hat, Inc., and the authors listed in the
libvirt AUTHORS file.


LICENSE
=======

``libvirtd`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), virt-install(1), virt-xml-validate(1), virt-top(1),
virt-df(1), `https://libvirt.org/ <https://libvirt.org/>`_
