========
virtlogd
========

-----------------------------
libvirt log management daemon
-----------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virtlogd`` [*OPTION*]...


DESCRIPTION
===========

The ``virtlogd`` program is a server side daemon component of the libvirt
virtualization management system that is used to manage logs from virtual
machine consoles.

This daemon is not used directly by libvirt client applications, rather it
is called on their behalf by ``libvirtd``. By maintaining the logs in a
standalone daemon, the main libvirtd daemon can be restarted without risk
of losing logs. The ``virtlogd`` daemon has the ability to re-exec()
itself upon receiving SIGUSR1, to allow live upgrades without downtime.

The ``virtlogd`` daemon listens for requests on a local Unix domain socket.


OPTIONS
=======

``-h``, ``--help``

Display command line help usage then exit.

``-d``, ``--daemon``

Run as a daemon and write PID file.

``-f``, ``--config`` *FILE*

Use this configuration file, overriding the default value.

``-t``, ``--timeout`` *SECONDS*

Automatically shutdown after *SECONDS* have elapsed with
no active console log.

``-p``, ``--pid-file`` *FILE*

Use this name for the PID file, overriding the default value.

``-v``, ``--verbose``

Enable output of verbose messages.

``-V``, ``--version``

Display version information then exit.


SIGNALS
=======

On receipt of ``SIGUSR1``, ``virtlogd`` will re-exec() its binary, while
maintaining all current logs and clients. This allows for live
upgrades of the ``virtlogd`` service.


FILES
=====

When run as *root*
------------------

* ``@SYSCONFDIR@/libvirt/virtlogd.conf``

The default configuration file used by ``virtlogd``, unless overridden on the
command line using the ``-f``  | ``--config`` option.

* ``@RUNSTATEDIR@/libvirt/virtlogd-sock``

The sockets ``virtlogd`` will use.

* ``@RUNSTATEDIR@/virtlogd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.

When run as *non-root*
----------------------

* ``$XDG_CONFIG_HOME/libvirt/virtlogd.conf``

The default configuration file used by ``virtlogd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

* ``$XDG_RUNTIME_DIR/libvirt/virtlogd-sock``

The socket ``virtlogd`` will use.

* ``$XDG_RUNTIME_DIR/libvirt/virtlogd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.

If ``$XDG_CONFIG_HOME`` is not set in your environment, ``virtlogd`` will use
``$HOME/.config``

If ``$XDG_RUNTIME_DIR`` is not set in your environment, ``virtlogd`` will use
``$HOME/.cache``


EXAMPLES
========

To retrieve the version of ``virtlogd``:

::

  # virtlogd --version
  virtlogd (libvirt) @VERSION@

To start ``virtlogd``, instructing it to daemonize and create a PID file:

::

  # virtlogd -d
  # ls -la @RUNSTATEDIR@/virtlogd.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/virtlogd.pid


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

Copyright (C) 2006-2015 Red Hat, Inc., and the authors listed in the
libvirt AUTHORS file.


LICENSE
=======

``virtlogd`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

libvirtd(8),  `https://libvirt.org/ <https://libvirt.org/>`_
