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

How to turn on debug logs for libvirt
=====================================

Persistent setting
------------------

The daemon configuration files location is dependent on `connection
URI <https://libvirt.org/uri.html>`__. For ``qemu:///system``:



-  open ``/etc/libvirt/libvirtd.conf`` in your favourite editor
-  find & replace, or set these variables:

::

   log_filters="3:remote 4:event 3:util.json 3:rpc 1:*"
   log_outputs="1:file:/var/log/libvirt/libvirtd.log"

-  save and exit
-  restart libvirtd service

::

   systemctl restart libvirtd.service


*Note:* Libvirt prior to the ``libvirt-4.4.0`` release didn't support globbing
patterns and thus requires more configuration. See
`Legacy (pre-4.4.0) libvirt daemon logging configuration`_.

In case you want to get the client logs, you need to set this environment
variable:

::

   export LIBVIRT_LOG_OUTPUTS="1:file:/tmp/libvirt_client.log"


However, when you are using the session mode ``qemu:///session`` or you run the
``libvirtd`` as unprivileged user you will find configuration file under
``$XDG_CONFIG_HOME/libvirt/libvirtd.conf``.

Runtime setting
---------------

Debugging anomalies can be very painful, especially when trying to reproduce it
after the daemon restarts, since the new session can make the anomaly
"disappear". Therefore, it's possible to enable the debug logs during runtime
using libvirt administration API. To use it conveniently, there's a virt-admin
client provided by the libvirt-admin package. Use the package manager provided
by your distribution to install this package. Once you have it installed, run
the following as root to see the set of log filters currently being active:

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
