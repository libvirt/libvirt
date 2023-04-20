==========
Debug Logs
==========

.. contents::

Turning on debug logs
=====================

If you `report a bug <https://gitlab.com/libvirt/libvirt/-/issues/new>`__
against libvirt, in most cases you will be asked to attach debug logs. These
are bare text files which tracks transition between different states of
libvirtd, what it has tried to achieve, etc. Because of client -- server schema
used in libvirt, the logs can be either client or server too. Usually, it's
server side that matters as nearly all interesting work takes place there.
Moreover, libvirt catches stderr of all running domains. These can be useful as
well.

TL;DR - Enable debug logs for most common scenario
===================================================

This applies to the most common scenario of ``system`` instance of
``virtqemud``. Log setting is not persisted, so a restart of ``virtqemud`` or
the system clears this setting::

   # virt-admin -c virtqemud:///system daemon-log-outputs "3:journald 1:file:/var/log/libvirt/libvirtd.log"
   # virt-admin -c virtqemud:///system daemon-log-filters "3:remote 4:event 3:util.json 3:util.object 3:util.dbus 3:util.netlink 3:node_device 3:rpc 3:access 1:*"
   # virt-admin -c virtqemud:///system daemon-timeout 0

The last command disabling timeout of the daemon is available since
``libvirt-8.6.0``. With older versions make sure to reproduce the issue within
120 seconds or have a VM running which prevents the daemon from timing out.

For any other configuration please read the rest of the document. If you want
to persist the log level and log outputs settings edit
``/etc/libvirt/virtqemud.conf`` and look for ``log-filters`` and ``log-outputs``

Logging settings in libvirt
===========================

Log levels
----------

Libvirt log messages are classified into 4 priority levels; the higher the
priority level, the less is the volume of produced messages.

The log level setting is controlled by the ``log_filters`` and ``log_outputs``
settings explained in the `Log outputs`_ and `Log filters`_ sections
respectively.

  * ``1: DEBUG``
  * ``2: INFO``
  * ``3: WARNING``
  * ``4: ERROR``

For debugging it's necessary to capture the ``DEBUG`` level entries as the name
implies.

Log outputs
-----------

Log outputs describe where the log messages are being recorded. The outputs
are described by a space-separated list of tuples in the following format:

::

  level:output

``level`` refers to the minimum priority level of entries recorded in the output.

``output`` is one of the following:

  ``file:FILENAME``
    Logging messages are appended to FILENAME.

  ``journald``
    Logging goes to the ``journald`` logging daemon.

  ``stderr``
    Logging goes to the standard error output stream of the libvirt daemon.

  ``syslog:name``
    Logging goes to syslogd. ``name`` is used to identify the entries.

The default output on systems running ``journald`` is ``3:journald``. Note that
``journald`` can throttle the amount of logs per process so in order to capture
debug logs of a libvirt daemon should go to a file instead (in addition to
theoriginal logging daemon), e.g.:

::

  "1:file:/var/log/libvirt/libvirtd.log 3:journald"


Log filters
-----------

Log filters, as the name suggest, help filtering out messages which are
irrelevant to the cause.  The log filters is a space-separated list of tuples
list of tuples using the ``level:identifier`` format. Each filter defined this
way will then limit messages coming from a module matching the ``identifier``
pattern (accepts globs too) to the given ``level``."

As ``identifier`` is based on internal naming of modules, preferred way of
configuring your filters is to start with the `Example filter settings`_.

The rule of thumb here is to have more logs rather than less and miss something
important.

Libvirt daemons logging configuration
=====================================

Libvirt daemons can be configured either via a config file or via the
administration API. The configuration location depends on multiple factors.

Session vs system daemons
-------------------------

Libvirt daemons run either in the ``system`` mode or on ``session`` (user)
mode, depending on the configuration of the host and available permission
levels.

The `connection URI <https://libvirt.org/uri.html>`__ influences which daemon
the client will communicate with.

System daemon mode
~~~~~~~~~~~~~~~~~~
  * all connection URIs end in ``/system`` e.g. ``qemu:///system``

  * config files are usually placed in ``/etc/libvirt``

Session daemon mode
~~~~~~~~~~~~~~~~~~~

  * connection URIs end in ``/session``

  * config files are usually placed in ``$XDG_CONFIG_HOME/libvirt/`` directory

Modular vs. monolithic daemons
------------------------------

While there is only a single 'libvirtd.conf' configuration file in case of the
monolithic daemon setup, each of the modular daemons has their own
configuration file giving you a lot of possibilities how to configure them
individually including logging. Realistically though, logging will have to be
configured only for a single or a couple of daemons in case debug logs are
requested.


Refer to `documentation about daemons <../daemons.html#checking-whether-modular-monolithic-mode-is-in-use>`__
to figure out which is in use by your system.

Modular daemons
~~~~~~~~~~~~~~~

The configuration of modular daemons is in file named after the daemon. E.g.
for ``qemu:///system`` connection this is the ``virtqemud`` daemon and
correspondingly:

  * ``virtqemud.conf`` config file is used

  * ``virtqemud:///system`` or ``virtqemud:///session`` admin URI is used

Monolithic daemon
~~~~~~~~~~~~~~~~~

   * ``libvirtd.conf`` config file is used

   * ``libvirtd:///system`` or ``libvirtd:///session`` admin URI is used
     when the modular qemu hypervisor driver ``virtqemud``

Persistent setting
------------------

In order to setup libvirt logging persistently, follow the steps below:

-  open the appropriate daemon config file in your favourite editor ::

     /etc/libvirt/virtqemud.conf
     /etc/libvirt/libvirtd.conf
     $XDG_CONFIG_HOME/libvirt/libvirtd.conf
     $XDG_CONFIG_HOME/libvirt/virtqemud.conf

-  find & replace, or set the appropriate `Log outputs`_ and `Log filters`_, e.g ::

     log_filters="3:remote 4:event 3:util.json 3:rpc 1:*"
     log_outputs="1:file:/var/log/libvirt/libvirtd.log"

-  save and exit
-  restart the corresponding service/daemon e.g. ::

    systemctl restart virtqemud.socket
    systemctl restart libvirtd.socket
    systemctl restart libvirtd.service


*Note:* Libvirt prior to the ``libvirt-4.4.0`` release didn't support globbing
patterns and thus requires more configuration. See
`Legacy (pre-4.4.0) libvirt daemon logging configuration`_.

Runtime setting
---------------

Debugging anomalies can be very painful, especially when trying to reproduce it
after the daemon restarts, since the new session can make the anomaly
"disappear". Therefore, it's possible to enable the debug logs during runtime
using libvirt administration API. To use it conveniently, there's the
``virt-admin`` client provided by the ``libvirt-admin`` package. Use the
package manager provided by your distribution to install this package.

**Important**: Substitute ``virt-admin -c $ADMIN_URI`` according to the
guideline in the sections above in place of ``virt-admin`` in the examples
below if needed.


Timeout of the configured daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Common deployments of libvirt start the libvirt daemons via socket activation
and with automatic shutdown timeout of 120 seconds when no client or object is
handled by the daemon. When a timeout is reached the daemon stops and all
settings done during runtime via ``virt-admin`` are discarded. The daemon then
is re-started with another command.

To prevent auto-shutdown of the daemon you can use the following command::

  virt-admin daemon-timeout 0

The above is introduced in libvirt-8.6.0.


Adding filters and outputs
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following command allows to query the list of currently active log filters:

::

   # virt-admin daemon-log-filters
    Logging filters: 3:remote 4:util.json 4:rpc

In order to change this set, run the same command as root, this time with your
own set of filters:

::

   # virt-admin daemon-log-filters "3:remote 4:util.json 4:rpc 1:*"

Analogically, the same procedure can be performed with log outputs:

::

   # virt-admin daemon-log-outputs
    Logging outputs: 3:syslog:libvirtd
   # virt-admin daemon-log-outputs "1:file:/var/log/libvirt/libvirtd.log"

NOTE: It's always good practice to return the settings to the original state
once you're finished debugging, just remember to save the original sets of
filters and outputs and restore them at the end the same way as described above.

Removing filters and outputs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's also possible to remove all the filters and produce an enormous log file,
but it is not recommended since some of libvirt's modules can produce a large
amount of noise. However, should you really want to do this, you can specify an
empty set of filters:

::

   # virt-admin daemon-log-filters ""
    Logging filters:

The situation is a bit different with outputs, since libvirt always has to log
somewhere and resetting the outputs to an empty set will restore the default
setting which depends on the host configuration, *journald* in our case:

::

   # virt-admin daemon-log-outputs
    Logging outputs: 1:file:/var/log/libvirt/libvirtd.log
   # virt-admin daemon-log-outputs ""
    Logging outputs: 2:journald

Legacy (pre-4.4.0) libvirt daemon logging configuration
-------------------------------------------------------

Old libvirt versions didn't support globbing (e.g. ``1:*``) to configure
logging, thus it's required to explicitly set logging level to 1 (debug level)
with the ``log_level`` setting and then filter out the noise with a tailored log
``log_filters`` string.

::

   # LEGACY SETTINGS PRIOR LIBVIRT 4.4.0
   log_level = 1
   log_filters="1:qemu 3:remote 4:event 3:util.json 3:rpc"
   log_outputs="1:file:/var/log/libvirt/libvirtd.log"


Or using ``virt-admin``:

::

   ## LEGACY APPROACH ENUMERATING ALL THE DESIRED MODULES ##
   # virt-admin daemon-log-filters "1:util 1:libvirt 1:storage 1:network 1:nodedev 1:qemu"

Client library logging
======================

By default the client library doesn't produce any logs and usually usually it's
not very interesting on its own anyway.

In case you want to get the client logs, logging is controlled via the
``LIBVIRT_LOG_OUTPUTS`` and ``LIBVIRT_LOG_FILTERS`` environment variables.
Generally when client logs are needed make sure you don't filter them:

::

   export LIBVIRT_LOG_OUTPUTS="1:file:/tmp/libvirt_client.log"

What to attach?
===============

Now you should go and reproduce the bug. Once you're finished, attach:

-  ``/var/log/libvirt/libvirtd.log`` or whatever path you set for the daemon
   logs.
-  If the problem is related to a domain named ``$dom`` attach:

   -  ``/var/log/libvirt/qemu/$dom.log`` (Or substitute ``qemu`` with whatever
      hypervisor you are using.)
   -  The XML configuration of the vm/domain obtained by ``virsh dumpxml $dom``

-  If the problem involves a crash of ``libvirtd`` or any other component, also
   attach the backtrace from the core dump if possible (e.g. using
   ``coredumpctl``).
-  If you are asked for client logs, ``/tmp/libvirt_client.log``.
-  Ideally don't tear down the environment in case additional information is
   required.
-  Consider whether you view any of the information in the debug logs
   sensitive: `Sensitive information in debug logs`_.

Example filter settings
=======================

Some filter setting suggestions for debugging more specific things. Unless it's
explicitly stated, these work on libvirt 4.4.0 and later. Please note that some
of the filters below may not log enough information for filing a proper libvirt
bug. Usually it's better to log more than less.

Targeted logging for debugging QEMU VMs
---------------------------------------

Specifying only some sections allows for a targeted filter configuration which
works on all versions and is sufficient for most cases.

::

    1:libvirt 1:qemu 1:conf 1:security 3:event 3:json 3:file 3:object 1:util

Less verbose logging for QEMU VMs
---------------------------------

Some subsystems are very noisy and usually not the culprit of the problems. They
can be silenced individually for a less verbose log while still logging
everything else. Usual suspects are the JSON code, RPC, authentication and such.
A permissive filter is good for development use cases.

::

    3:remote 4:event 3:util.json 3:util.object 3:util.dbus 3:util.netlink 3:node_device 3:rpc 3:access 1:*

Minimalistic QEMU QMP monitor logging
-------------------------------------

This filter logs only QMP traffic and skips most of libvirt's messages.

::

    2:qemu.qemu_monitor 3:*

Sensitive information in debug logs
===================================

Debug logs may contain information that certain users may consider sensitive
although generally it's okay to share debuglogs publicly.

Information which could be deemed sensitive:

 - hostname of the host
 - names of VMs and other objects
 - paths to disk images
 - IP addresses of guests and the host
 - hostnames/IP addresses of disks accessed via network


Libvirt's debug logs only ever have passwords and disk encryption secrets in
encrypted form without the key being part of the log. There's one notable
exception, that ``VNC/SPICE`` passwords can be found in the logs.

In case you decide to mask information you consider sensitive from the posted
debug logs, make sure that the masking doesn't introduce ambiguity.
