==============
libvirt-guests
==============

-------------------------------------
suspend/resume running libvirt guests
-------------------------------------

:Manual section: 8
:Manual group: Virtualization Support

.. contents::

SYNOPSIS
========

``libvirt-guests`` *COMMAND*


DESCRIPTION
===========

``libvirt-guests`` is a service that can be used to coordinate guest and host
lifecycle actions. By default, ``libvirt-guests`` will suspend running guests
when the host shuts down, and restore them to their pre-shutdown state when
the host reboots.

``libvirt-guests`` is typically under control of systemd. When
``libvirt-guests.service`` is enabled, systemd will call ``libvirt-guests``
with the ``start`` *COMMAND* when the host boots. Conversely, systemd will call
``libvirt-guests`` with the ``stop`` *COMMAND* when the host shuts down.

``libvirt-guests`` can be used directly. In addition to the ``start`` and
``stop`` *COMMAND*\s, it also supports ``status``, ``restart``, ``condrestart``,
``try-restart``, ``reload``, ``force-reload``, ``gueststatus``, and
``shutdown`` *COMMAND*\s.


FILES
=====

``libvirt-guests`` defines several variables to control service behavior.
The default value of these variables can be overridden in:

* ``@INITCONFDIR@/libvirt-guests``

The following variables are supported:

- URIS=default

  URIs to check for running guests. Example:
  ``URIS='default xen:///system xen+tcp://host/system lxc:///system'``

- ON_BOOT=start

  Action taken on host boot

  * start

    All guests which were running on shutdown are started on boot regardless
    of their autostart settings

  * ignore

    ``libvirt-guests`` won't start any guest on boot, however, guests marked
    as autostart will still be automatically started by libvirtd

- START_DELAY=0

  Number of seconds to wait between each guest start. Set to 0 to allow parallel
  startup.

- ON_SHUTDOWN=suspend

  Action taken on host shutdown

  * suspend

    All running guests are suspended using virsh managedsave

  * shutdown

    All running guests are asked to shutdown. Please be careful with this
    settings since there is no way to distinguish between a guest which is
    stuck or ignores shutdown requests and a guest which just needs a long
    time to shutdown. When setting ON_SHUTDOWN=shutdown, you must also set
    SHUTDOWN_TIMEOUT to a value suitable for your guests.

- PARALLEL_SHUTDOWN=0

  Number of guests will be shutdown concurrently, taking effect when
  "ON_SHUTDOWN" is set to "shutdown". If Set to 0, guests will be shutdown one
  after another. Number of guests on shutdown at any time will not exceed number
  set in this variable.

- SHUTDOWN_TIMEOUT=300

  Number of seconds we're willing to wait for a guest to shut down. If parallel
  shutdown is enabled, this timeout applies as a timeout for shutting down all
  guests on a single URI defined in the variable URIS. If this is 0, then there
  is no time out (use with caution, as guests might not respond to a shutdown
  request). The default value is 300 seconds (5 minutes).

- BYPASS_CACHE=0

  If non-zero, try to bypass the file system cache when saving and
  restoring guests, even though this may give slower operation for
  some file systems.

- SYNC_TIME=0

  If non-zero, try to sync guest time on domain resume. Be aware, that
  this requires guest agent with support for time synchronization
  running in the guest. By default, this functionality is turned off.


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


LICENSE
=======

``libvirt-guests`` is distributed under the terms of the GNU LGPL v2.1+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE


SEE ALSO
========

libvirtd(8), `https://libvirt.org/ <https://libvirt.org/>`_
