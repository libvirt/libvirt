=========
virtlockd
=========

------------------------------
libvirt lock management daemon
------------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``virtlockd``  [*OPTION*]...


DESCRIPTION
===========

The ``virtlockd`` program is a server side daemon component of the libvirt
virtualization management system that is used to manage locks held against
virtual machine resources, such as their disks.

This daemon is not used directly by libvirt client applications, rather it
is called on their behalf by ``libvirtd``. By maintaining the locks in a
standalone daemon, the main libvirtd daemon can be restarted without risk
of losing locks.  The ``virtlockd`` daemon has the ability to re-exec()
itself upon receiving SIGUSR1, to allow live upgrades without downtime.

The ``virtlockd`` daemon listens for requests on a local Unix domain socket.


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
no active client or lock.

``-p``, ``--pid-file`` *FILE*

Use this name for the PID file, overriding the default value.

``-v``, ``--verbose``

Enable output of verbose messages.

``-V``, ``--version``

Display version information then exit.

SIGNALS
=======

On receipt of ``SIGUSR1``, ``virtlockd`` will re-exec() its binary, while
maintaining all current locks and clients. This allows for live
upgrades of the ``virtlockd`` service.


FILES
=====

When run as *root*
------------------

* ``@SYSCONFDIR@/libvirt/virtlockd.conf``

The default configuration file used by ``virtlockd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

* ``@RUNSTATEDIR@/libvirt/virtlockd-sock``

The sockets ``virtlockd`` will use.

* ``@RUNSTATEDIR@/virtlockd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.


When run as *non-root*
----------------------

* ``$XDG_CONFIG_HOME/libvirt/virtlockd.conf``

The default configuration file used by ``virtlockd``, unless overridden on the
command line using the ``-f`` | ``--config`` option.

* ``$XDG_RUNTIME_DIR/libvirt/virtlockd-sock``

The socket ``virtlockd`` will use.

* ``$XDG_RUNTIME_DIR/libvirt/virtlockd.pid``

The PID file to use, unless overridden by the ``-p`` | ``--pid-file`` option.

If ``$XDG_CONFIG_HOME`` is not set in your environment, ``virtlockd`` will use
``$HOME/.config``

If ``$XDG_RUNTIME_DIR`` is not set in your environment, ``virtlockd`` will use
``$HOME/.cache``

EXAMPLES
========

To retrieve the version of ``virtlockd``:

::

  # virtlockd --version
  virtlockd (libvirt) @VERSION@

To start ``virtlockd``, instructing it to daemonize and create a PID file:

::

  # virtlockd -d
  # ls -la @RUNSTATEDIR@/virtlockd.pid
  -rw-r--r-- 1 root root 6 Jul  9 02:40 @RUNSTATEDIR@/virtlockd.pid

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

Copyright (C) 2006-2013 Red Hat, Inc., and the authors listed in the
libvirt AUTHORS file.


LICENSE
=======

``virtlockd`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

libvirtd(8),  `https://libvirt.org/ <https://libvirt.org/>`_
