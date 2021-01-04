==========
Debug Logs
==========

.. contents::

Turning on debug logs
---------------------

If you `report a bug <https://gitlab.com/libvirt/libvirt/-/issues/new>`__
against libvirt, in most cases you will be asked to attach debug logs. These
are bare text files which tracks transition between different states of
libvirtd, what it has tried to achieve, etc. Because of client -- server schema
used in libvirt, the logs can be either client or server too. Usually, it's
server side that matters as nearly all interesting work takes place there.
Moreover, libvirt catches stderr of all running domains. These can be useful as
well.


How to turn on debug logs for libvirt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Persistent setting
^^^^^^^^^^^^^^^^^^

The daemon configuration files location is dependent on `connection
URI <https://libvirt.org/uri.html>`__. For ``qemu:///system``:



-  open ``/etc/libvirt/libvirtd.conf`` in your favourite editor
-  find & replace, or set these variables:

::

   # LEGACY SETTINGS PRIOR LIBVIRT 4.4.0 SEE BELOW! #
   log_level = 1
   log_filters="1:qemu 3:remote 4:event 3:util.json 3:rpc"
   log_outputs="1:file:/var/log/libvirt/libvirtd.log"

::

   # PREFERRED SETTINGS AFTER LIBVIRT 4.4.0 #
   log_filters="3:remote 4:event 3:util.json 3:rpc 1:*"
   log_outputs="1:file:/var/log/libvirt/libvirtd.log"

-  save and exit
-  restart libvirtd service

::

   systemctl restart libvirtd.service

In the config variables above, we have set logging level to 1 (debug level), set
some filters (to filter out noise), e.g. from rpc only warnings (=level 3) and
above will be reported. The logs are saved into
``/var/log/libvirt/libvirtd.log``. Since libvirt **4.4.0** log filters support
shell globbing, therefore the usage of ``log_level`` is considered deprecated in
favour of pure usage of ``log_filters``.

In case you want to get the client logs, you need to set this environment
variable:

::

   export LIBVIRT_LOG_OUTPUTS="1:file:/tmp/libvirt_client.log"


However, when you are using the session mode ``qemu:///session`` or you run the
``libvirtd`` as unprivileged user you will find configuration file under
``$XDG_CONFIG_HOME/libvirt/libvirtd.conf``.

Runtime setting
^^^^^^^^^^^^^^^

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

   ## LEGACY APPROACH ENUMERATING ALL THE DESIRED MODULES ##
   # virt-admin daemon-log-filters "1:util 1:libvirt 1:storage 1:network 1:nodedev 1:qemu"

::

   ## CURRENT APPROACH USING SHELL GLOBBING ##
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
''''''''''''''''''''''''''''

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

What to attach?
---------------

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
-----------------------

Some filter setting suggestions for debugging more specific things. Unless it's
explicitly stated, these work on libvirt 4.4.0 and later. Please note that some
of the filters below may not log enough information for filing a proper libvirt
bug. Usually it's better to log more than less.

Targeted logging for debugging QEMU VMs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Specifying only some sections allows for a targeted filter configuration which
works on all versions and is sufficient for most cases.

::

    1:libvirt 1:qemu 1:conf 1:security 3:event 3:json 3:file 3:object 1:util

Less verbose logging for QEMU VMs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some subsystems are very noisy and usually not the culprit of the problems. They
can be silenced individually for a less verbose log while still logging
everything else. Usual suspects are the JSON code, RPC, authentication and such.
A permissive filter is good for development use cases.

::

    3:remote 4:event 3:util.json 3:util.object 3:util.dbus 3:util.netlink 3:node_device 3:rpc 3:access 1:*

Minimalistic QEMU QMP monitor logging
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This filter logs only QMP traffic and skips most of libvirt's messages.

::

    2:qemu.qemu_monitor 3:*
