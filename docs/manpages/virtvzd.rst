=======
virtvzd
=======

-----------------------------------
libvirt Virtuozzo management daemon
-----------------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virtvzd`` [*OPTION*]...


DESCRIPTION
===========

The ``virtvzd`` program is a server side daemon component of the libvirt
virtualization management system.

It is one of a collection of modular daemons that replace functionality
previously provided by the monolithic ``libvirtd`` daemon.

This daemon runs on virtualization hosts to provide management for Virtuozzo
virtual machines.

The ``virtvzd`` daemon only listens for requests on a local Unix domain
socket. Remote access via TLS/TCP and backwards compatibility with legacy
clients expecting ``libvirtd`` is provided by the ``virtproxyd`` daemon.

Restarting ``virtvzd`` does not interrupt running guests. Guests continue to
operate and changes in their state will generally be picked up automatically
during startup. None the less it is recommended to avoid restarting with
running guests whenever practical.


DAEMON STARTUP MODES
====================

The ``virtvzd`` daemon is capable of starting in two modes.


Socket activation mode
----------------------

On hosts with systemd it is started in socket activation mode and it will rely
on systemd to create and listen on the UNIX sockets and pass them as pre-opened
file descriptors. In this mode most of the socket related config options in
``/etc/libvirt/virtvzd.conf`` will no longer have any effect.


Traditional service mode
------------------------

On hosts without systemd, it will create and listen on UNIX sockets itself.


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

On receipt of ``SIGHUP`` ``virtvzd`` will reload its configuration.


FILES
=====

When run as *root*
------------------

* ``@SYSCONFDIR@/libvirt/virtvzd.conf``

The default configuration file used by ``virtvzd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

* ``@RUNSTATEDIR@/libvirt/virtvzd-sock``
* ``@RUNSTATEDIR@/libvirt/virtvzd-sock-ro``
* ``@RUNSTATEDIR@/libvirt/virtvzd-admin-sock``

The sockets ``virtvzd`` will use.

The TLS **Server** private key ``virtvzd`` will use.

* ``@RUNSTATEDIR@/virtvzd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.


When run as *non-root*
----------------------

* ``$XDG_CONFIG_HOME/libvirt/virtvzd.conf``

The default configuration file used by ``virtvzd``, unless overridden on the
command line using the ``-f``|``--config`` option.

* ``$XDG_RUNTIME_DIR/libvirt/virtvzd-sock``
* ``$XDG_RUNTIME_DIR/libvirt/virtvzd-admin-sock``

The sockets ``virtvzd`` will use.

* ``$XDG_RUNTIME_DIR/libvirt/virtvzd.pid``

The PID file to use, unless overridden by the ``-p``|``--pid-file`` option.


If ``$XDG_CONFIG_HOME`` is not set in your environment, ``virtvzd`` will use
``$HOME/.config``

If ``$XDG_RUNTIME_DIR`` is not set in your environment, ``virtvzd`` will use
``$HOME/.cache``


EXAMPLES
========

To retrieve the version of ``virtvzd``:

::

  # virtvzd --version
  virtvzd (libvirt) @VERSION@


To start ``virtvzd``, instructing it to daemonize and create a PID file:

::

  # virtvzd -d
  # ls -la @RUNSTATEDIR@/virtvzd.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/virtvzd.pid


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

``virtvzd`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), libvirtd(8),
`https://libvirt.org/daemons.html <https://libvirt.org/daemons.html>`_,
`https://libvirt.org/drvvz.html <https://libvirt.org/drvvz.html>`_
