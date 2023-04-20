==========
virtproxyd
==========

--------------------
libvirt proxy daemon
--------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virtproxyd`` [*OPTION*]...


DESCRIPTION
===========

The ``virtproxyd`` program is a server side daemon component of the libvirt
virtualization management system.

It is one of a collection of modular daemons that replace functionality
previously provided by the monolithic ``libvirtd`` daemon.

This daemon runs on virtualization hosts and

 * Listens on a UNIX socket to provide backwards compatibility for clients
   that previously connected to the ``libvirtd`` socket.

 * Optionally listens on TCP ports for connections from off-node clients

Upon receiving RPC messages from a client ``virtproxyd`` will transparently
forward them on to the appropriate modular daemon, and similarly relay back
any asynchronous events.

By default, the ``virtproxyd`` daemon listens for requests on a local Unix
domain socket with the same path previously used by ``libvirtd``.  The
configuration file can be used to instruct it to also listen on TCP socket(s).
Systemd socket activation is also supported to allow it to receive pre-opened
listener sockets on startup.

Since ``virtproxyd`` merely forwards RPC messages, it has no important state,
and can be restarted at any time. Clients should expect to reconnect after
the restart.


DAEMON STARTUP MODES
====================

The ``virtproxyd`` daemon is capable of starting in two modes.


Socket activation mode
----------------------

On hosts with systemd it is started in socket activation mode and it will rely
on systemd to create and listen on the UNIX, and optionally TCP/IP, sockets and
pass them as pre-opened file descriptors. In this mode most of the socket
related config options in ``/etc/libvirt/virtproxyd.conf`` will no longer have
any effect. To enable TCP or TLS sockets use either

::

   $ systemctl start virtproxyd-tls.socket

Or

::

   $ systemctl start virtproxyd-tcp.socket

**Note**: The TCP socket uses plain unencrypted TCP connection and thus is
insecure and should not be used.


Traditional service mode
------------------------

On hosts without systemd, it will create and listen on UNIX sockets itself.
It will also listen on TCP/IP socket(s), according to the ``listen_tcp``
and ``listen_tls`` options in ``/etc/libvirt/virtproxyd.conf``


OPTIONS
=======

``-h``, ``--help``

Display command line help usage then exit.

``-d``, ``--daemon``

Run as a daemon & write PID file.

``-f``, ``--config *FILE*``

Use this configuration file, overriding the default value.

``-p``, ``--pid-file *FILE*``

Use this name for the PID file, overriding the default value.

``-t``, ``--timeout *SECONDS*``

Exit after timeout period (in seconds), provided there are no client
connections.

``-v``, ``--verbose``

Enable output of verbose messages.

``--version``

Display version information then exit.


SIGNALS
=======

On receipt of ``SIGHUP`` ``virtproxyd`` will reload its configuration.


FILES
=====

When run as *root*
------------------

* ``@SYSCONFDIR@/libvirt/virtproxyd.conf``

The default configuration file used by ``virtproxyd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

* ``@RUNSTATEDIR@/libvirt/libvirt-sock``
* ``@RUNSTATEDIR@/libvirt/libvirt-sock-ro``

The sockets ``virtproxyd`` will use.

* ``@SYSCONFDIR@/pki/CA/cacert.pem``

The TLS **Certificate Authority** certificate ``virtproxyd`` will use.

* ``@SYSCONFDIR@/pki/libvirt/servercert.pem``

The TLS **Server** certificate ``virtproxyd`` will use.

* ``@SYSCONFDIR@/pki/libvirt/private/serverkey.pem``

The TLS **Server** private key ``virtproxyd`` will use.

* ``@RUNSTATEDIR@/virtproxyd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.


When run as *non-root*
----------------------

* ``$XDG_CONFIG_HOME/libvirt/virtproxyd.conf``

The default configuration file used by ``virtproxyd``, unless overridden on the
command line using the ``-f``|``--config`` option.

* ``$XDG_RUNTIME_DIR/libvirt/libvirt-sock``

The socket ``virtproxyd`` will use.

* ``$HOME/.pki/libvirt/cacert.pem``

The TLS **Certificate Authority** certificate ``virtproxyd`` will use.

* ``$HOME/.pki/libvirt/servercert.pem``

The TLS **Server** certificate ``virtproxyd`` will use.

* ``$HOME/.pki/libvirt/serverkey.pem``

The TLS **Server** private key ``virtproxyd`` will use.

* ``$XDG_RUNTIME_DIR/libvirt/virtproxyd.pid``

The PID file to use, unless overridden by the ``-p``|``--pid-file`` option.


If ``$XDG_CONFIG_HOME`` is not set in your environment, ``virtproxyd`` will use
``$HOME/.config``

If ``$XDG_RUNTIME_DIR`` is not set in your environment, ``virtproxyd`` will use
``$HOME/.cache``


EXAMPLES
========

To retrieve the version of ``virtproxyd``:

::

  # virtproxyd --version
  virtproxyd (libvirt) @VERSION@


To start ``virtproxyd``, instructing it to daemonize and create a PID file:

::

  # virtproxyd -d
  # ls -la @RUNSTATEDIR@/virtproxyd.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/virtproxyd.pid


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

Copyright (C) 2006-2020 Red Hat, Inc., and the authors listed in the
libvirt AUTHORS file.


LICENSE
=======

``virtproxyd`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), libvirtd(8),
`https://libvirt.org/daemons.html <https://libvirt.org/daemons.html>`_,
