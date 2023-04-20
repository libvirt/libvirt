============
virtstoraged
============

--------------------------------------
libvirt storage pool management daemon
--------------------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virtstoraged`` [*OPTION*]...


DESCRIPTION
===========

The ``virtstoraged`` program is a server side daemon component of the libvirt
virtualization management system.

It is one of a collection of modular daemons that replace functionality
previously provided by the monolithic ``libvirtd`` daemon.

This daemon runs on virtualization hosts to provide management for storage
pools.

The ``virtstoraged`` daemon only listens for requests on a local Unix domain
socket. Remote access via TLS/TCP and backwards compatibility with legacy
clients expecting ``libvirtd`` is provided by the ``virtproxyd`` daemon.

Restarting ``virtstoraged`` does not interrupt running guests. Guests continue to
operate and changes in their state will generally be picked up automatically
during startup. None the less it is recommended to avoid restarting with
running guests whenever practical.


DAEMON STARTUP MODES
====================

The ``virtstoraged`` daemon is capable of starting in two modes.


Socket activation mode
----------------------

On hosts with systemd it is started in socket activation mode and it will rely
on systemd to create and listen on the UNIX sockets and pass them as pre-opened
file descriptors. In this mode most of the socket related config options in
``/etc/libvirt/virtstoraged.conf`` will no longer have any effect.


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

On receipt of ``SIGHUP`` ``virtstoraged`` will reload its configuration.


FILES
=====

When run as *root*
------------------

* ``@SYSCONFDIR@/libvirt/virtstoraged.conf``

The default configuration file used by ``virtstoraged``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

* ``@RUNSTATEDIR@/libvirt/virtstoraged-sock``
* ``@RUNSTATEDIR@/libvirt/virtstoraged-sock-ro``
* ``@RUNSTATEDIR@/libvirt/virtstoraged-admin-sock``

The sockets ``virtstoraged`` will use.

The TLS **Server** private key ``virtstoraged`` will use.

* ``@RUNSTATEDIR@/virtstoraged.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.


When run as *non-root*
----------------------

* ``$XDG_CONFIG_HOME/libvirt/virtstoraged.conf``

The default configuration file used by ``virtstoraged``, unless overridden on the
command line using the ``-f``|``--config`` option.

* ``$XDG_RUNTIME_DIR/libvirt/virtstoraged-sock``
* ``$XDG_RUNTIME_DIR/libvirt/virtstoraged-admin-sock``

The sockets ``virtstoraged`` will use.

* ``$XDG_RUNTIME_DIR/libvirt/virtstoraged.pid``

The PID file to use, unless overridden by the ``-p``|``--pid-file`` option.


If ``$XDG_CONFIG_HOME`` is not set in your environment, ``virtstoraged`` will use
``$HOME/.config``

If ``$XDG_RUNTIME_DIR`` is not set in your environment, ``virtstoraged`` will use
``$HOME/.cache``


EXAMPLES
========

To retrieve the version of ``virtstoraged``:

::

  # virtstoraged --version
  virtstoraged (libvirt) @VERSION@


To start ``virtstoraged``, instructing it to daemonize and create a PID file:

::

  # virtstoraged -d
  # ls -la @RUNSTATEDIR@/virtstoraged.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/virtstoraged.pid


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

``virtstoraged`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), libvirtd(8),
`https://libvirt.org/daemons.html <https://libvirt.org/daemons.html>`_,
`https://libvirt.org/drvstorage.html <https://libvirt.org/drvstorage.html>`_
