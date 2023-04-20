========
virtlxcd
========

------------------------------
libvirt LXC management daemon
------------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virtlxcd`` [*OPTION*]...


DESCRIPTION
===========

The ``virtlxcd`` program is a server side daemon component of the libvirt
virtualization management system.

It is one of a collection of modular daemons that replace functionality
previously provided by the monolithic ``libvirtd`` daemon.

This daemon runs on virtualization hosts to provide management for LXC
containers.

The ``virtlxcd`` daemon only listens for requests on a local Unix domain
socket. Remote access via TLS/TCP and backwards compatibility with legacy
clients expecting ``libvirtd`` is provided by the ``virtproxyd`` daemon.

Restarting ``virtlxcd`` does not interrupt running guests. Guests continue to
operate and changes in their state will generally be picked up automatically
during startup. None the less it is recommended to avoid restarting with
running guests whenever practical.


DAEMON STARTUP MODES
====================

The ``virtlxcd`` daemon is capable of starting in two modes.


Socket activation mode
----------------------

On hosts with systemd it is started in socket activation mode and it will rely
on systemd to create and listen on the UNIX sockets and pass them as pre-opened
file descriptors. In this mode most of the socket related config options in
``/etc/libvirt/virtlxcd.conf`` will no longer have any effect.


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

Exit after timeout period (in seconds), provided there are neither any client
connections nor any running domains.

``-v``, ``--verbose``

Enable output of verbose messages.

``--version``

Display version information then exit.


SIGNALS
=======

On receipt of ``SIGHUP`` ``virtlxcd`` will reload its configuration.


FILES
=====

The ``virtlxcd`` program must be ran as root. Trying to start the program under
a different user results in error.

* ``@SYSCONFDIR@/libvirt/virtlxcd.conf``

The default configuration file used by ``virtlxcd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

In addition to the default configuration file, ``virtlxcd`` reads
configuration for the LXC driver from:

* ``@SYSCONFDIR@/libvirt/lxc.conf``

This file contains various knobs and default values for virtual machines
created within LXC driver, and offers a way to override the built in defaults,
Location of this file can't be overridden by any command line switch.

* ``@RUNSTATEDIR@/libvirt/virtlxcd-sock``
* ``@RUNSTATEDIR@/libvirt/virtlxcd-sock-ro``
* ``@RUNSTATEDIR@/libvirt/virtlxcd-admin-sock``

The sockets ``virtlxcd`` will use.

The TLS **Server** private key ``virtlxcd`` will use.

* ``@RUNSTATEDIR@/virtlxcd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.


EXAMPLES
========

To retrieve the version of ``virtlxcd``:

::

  # virtlxcd --version
  virtlxcd (libvirt) @VERSION@


To start ``virtlxcd``, instructing it to daemonize and create a PID file:

::

  # virtlxcd -d
  # ls -la @RUNSTATEDIR@/virtlxcd.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/virtlxcd.pid


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

``virtlxcd`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

virsh(1), libvirtd(8),
`https://libvirt.org/daemons.html <https://libvirt.org/daemons.html>`_,
`https://libvirt.org/drvlxc.html <https://libvirt.org/drvlxc.html>`_
