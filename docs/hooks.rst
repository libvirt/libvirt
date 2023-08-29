.. role:: since

====================================
Hooks for specific system management
====================================

.. contents::

Custom event scripts
--------------------

Beginning with libvirt 0.8.0, specific events on a host system will trigger
custom scripts.

These custom **hook** scripts are executed when any of the following actions
occur:

-  The libvirt daemon starts, stops, or reloads its configuration (
   :since:`since 0.8.0` )
-  A QEMU guest is started or stopped ( :since:`since 0.8.0` )
-  An LXC guest is started or stopped ( :since:`since 0.8.0` )
-  A libxl-handled Xen guest is started or stopped ( :since:`since 2.1.0` )
-  An bhyve guest is started or stopped ( :since:`since 6.1.0` )
-  A network is started or stopped or an interface is plugged/unplugged to/from
   the network ( :since:`since 1.2.2` )

Script location
---------------

The libvirt hook scripts are located in the directory
``$SYSCONFDIR/libvirt/hooks/``.

-  In Linux distributions such as Fedora and RHEL, this is
   ``/etc/libvirt/hooks/``. Other Linux distributions may do this differently.
-  If your installation of libvirt has instead been compiled from source, it is
   likely to be ``/usr/local/etc/libvirt/hooks/``.
-  :since:`Since 6.5.0` , you can also place several hook scripts in the
   directories ``/etc/libvirt/hooks/<driver>.d/``.

To use hook scripts, you will need to create this ``hooks`` directory manually,
place the desired hook scripts inside, then make them executable.

Script names
------------

At present, there are five hook scripts that can be called:

-  ``/etc/libvirt/hooks/daemon``
   Executed when the libvirt daemon is started, stopped, or reloads its
   configuration
-  ``/etc/libvirt/hooks/qemu``
   Executed when a QEMU guest is started, stopped, or migrated
-  ``/etc/libvirt/hooks/lxc``
   Executed when an LXC guest is started or stopped
-  ``/etc/libvirt/hooks/libxl``
   Executed when a libxl-handled Xen guest is started, stopped, or migrated
-  ``/etc/libvirt/hooks/bhyve``
   Executed when an bhyve guest is started or stopped
-  ``/etc/libvirt/hooks/network``
   Executed when a network is started or stopped or an interface is
   plugged/unplugged to/from the network

:since:`Since 6.5.0` , you can also have several scripts with any name in the
directories ``/etc/libvirt/hooks/<driver>.d/``. They are executed in
alphabetical order after main script.

Script structure
----------------

The hook scripts are executed using standard Linux process creation functions.
Therefore, they must begin with the declaration of the command interpreter to
use.

For example:

::

   #!/bin/bash

or:

::

   #!/usr/bin/env python3

Other command interpreters are equally valid, as is any executable binary, so
you are welcome to use your favourite languages.

Script arguments
----------------

The hook scripts are called with specific command line arguments, depending upon
the script, and the operation being performed.

The guest hook scripts, qemu, lxc, libxl and bhyve are also given the **full**
XML description for the domain on their stdin. This includes items such the UUID
of the domain and its storage information, and is intended to provide all the
libvirt information the script needs.

For all cases, stdin of the network hook script is provided with the full XML
description of the network status in the following form:

::

   <hookData>
     <network>
        <name>$network_name</name>
        <uuid>afca425a-2c3a-420c-b2fb-dd7b4950d722</uuid>
        ...
     </network>
   </hookData>

In the case of an network port being created / deleted, the network XML will be
followed with the full XML description of the port:

::

   <hookData>
     <network>
        <name>$network_name</name>
        <uuid>afca425a-2c3a-420c-b2fb-dd7b4950d722</uuid>
        ...
     </network>
     <networkport>
       <uuid>5d744f21-ba4a-4d6e-bdb2-30a35ff3207d</uuid>
       ...
       <plug type='direct' dev='ens3' mode='vepa'/>
     </networkport>
   </hookData>

Please note that this approach is different from other cases such as ``daemon``,
``qemu``, ``lxc``, ``libxl`` or ``bhyve`` hook scripts, because two XMLs may be
passed here, while in the other cases only a single XML is passed.

The command line arguments take this approach:

#. The first argument is the name of the **object** involved in the operation,
   or '-' if there is none.
   For example, the name of a guest being started.
#. The second argument is the name of the **operation** being performed.
   For example, "start" if a guest is being started.
#. The third argument is a **sub-operation** indication, or '-' if there is
   none.
#. The last argument is an **extra argument** string, or '-' if there is none.

Specifics
~~~~~~~~~

This translates to the following specifics for each hook script:

/etc/libvirt/hooks/daemon
^^^^^^^^^^^^^^^^^^^^^^^^^

-  | When the libvirt daemon is started, this script is called as:

   ::

      /etc/libvirt/hooks/daemon - start - start

-  | When the libvirt daemon is shut down, this script is called as:

   ::

      /etc/libvirt/hooks/daemon - shutdown - shutdown

-  | When the libvirt daemon receives the SIGHUP signal, it reloads its
     configuration and triggers the hook script as:

   ::

      /etc/libvirt/hooks/daemon - reload begin SIGHUP

Please note that when the libvirt daemon is restarted, the *daemon* hook script
is called once with the "shutdown" operation, and then once with the "start"
operation. There is no specific operation to indicate a "restart" is occurring.

/etc/libvirt/hooks/qemu
^^^^^^^^^^^^^^^^^^^^^^^

-  | Before a QEMU guest is started, the qemu hook script is called in three
     locations; if any location fails, the guest is not started. The first
     location, :since:`since 0.9.0` , is before libvirt performs any resource
     labeling, and the hook can allocate resources not managed by libvirt such
     as DRBD or missing bridges. This is called as:

   ::

      /etc/libvirt/hooks/qemu guest_name prepare begin -

   | The second location, available :since:`Since 0.8.0` , occurs after libvirt
     has finished labeling all resources, but has not yet started the guest,
     called as:

   ::

      /etc/libvirt/hooks/qemu guest_name start begin -

   | The third location, :since:`0.9.13` , occurs after the QEMU process has
     successfully started up:

   ::

      /etc/libvirt/hooks/qemu guest_name started begin -

-  | When a QEMU guest is stopped, the qemu hook script is called in two
     locations, to match the startup. First, :since:`since 0.8.0` , the hook is
     called before libvirt restores any labels:

   ::

      /etc/libvirt/hooks/qemu guest_name stopped end -

   | Then, after libvirt has released all resources, the hook is called again,
     :since:`since 0.9.0` , to allow any additional resource cleanup:

   ::

      /etc/libvirt/hooks/qemu guest_name release end -

-  :since:`Since 0.9.11` , the qemu hook script is also called at the beginning
   of incoming migration. It is called as:

   ::

      /etc/libvirt/hooks/qemu guest_name migrate begin -

   with domain XML sent to standard input of the script. In this case, the
   script acts as a filter and is supposed to modify the domain XML and print it
   out on its standard output. Empty output is identical to copying the input
   XML without changing it. In case the script returns failure or the output XML
   is not valid, incoming migration will be canceled. This hook may be used,
   e.g., to change location of disk images for incoming domains.

-  :since:`Since 1.2.9` , the qemu hook script is also called when restoring a
   saved image either via the API or automatically when restoring a managed save
   machine. It is called as:

   ::

      /etc/libvirt/hooks/qemu guest_name restore begin -

   with domain XML sent to standard input of the script. In this case, the
   script acts as a filter and is supposed to modify the domain XML and print it
   out on its standard output. Empty output is identical to copying the input
   XML without changing it. In case the script returns failure or the output XML
   is not valid, restore of the image will be aborted. This hook may be used,
   e.g., to change location of disk images for restored domains.

-  :since:`Since 6.5.0` , you can also place several hook scripts in the
   directory ``/etc/libvirt/hooks/qemu.d/``. They are executed in alphabetical
   order after main script. In this case each script also acts as filter and can
   modify the domain XML and print it out on its standard output. This script
   output is passed to standard input next script in order. Empty output from
   any script is also identical to copying the input XML without changing it. In
   case any script returns failure common process will be aborted, but all
   scripts from the directory will are executed.

-  :since:`Since 0.9.13` , the qemu hook script is also called when the libvirtd
   daemon restarts and reconnects to previously running QEMU processes. If the
   script fails, the existing QEMU process will be killed off. It is called as:

   ::

      /etc/libvirt/hooks/qemu guest_name reconnect begin -

-  :since:`Since 0.9.13` , the qemu hook script is also called when the QEMU
   driver is told to attach to an externally launched QEMU process. It is called
   as:

   ::

      /etc/libvirt/hooks/qemu guest_name attach begin -

/etc/libvirt/hooks/lxc
^^^^^^^^^^^^^^^^^^^^^^

-  | Before a LXC guest is started, the lxc hook script is called in three
     locations; if any location fails, the guest is not started. The first
     location, :since:`since 0.9.13` , is before libvirt performs any resource
     labeling, and the hook can allocate resources not managed by libvirt such
     as DRBD or missing bridges. This is called as:

   ::

      /etc/libvirt/hooks/lxc guest_name prepare begin -

   | The second location, available :since:`Since 0.8.0` , occurs after libvirt
     has finished labeling all resources, but has not yet started the guest,
     called as:

   ::

      /etc/libvirt/hooks/lxc guest_name start begin -

   | The third location, :since:`0.9.13` , occurs after the LXC process has
     successfully started up:

   ::

      /etc/libvirt/hooks/lxc guest_name started begin -

-  | When a LXC guest is stopped, the lxc hook script is called in two
     locations, to match the startup. First, :since:`since 0.8.0` , the hook is
     called before libvirt restores any labels:

   ::

      /etc/libvirt/hooks/lxc guest_name stopped end -

   | Then, after libvirt has released all resources, the hook is called again,
     :since:`since 0.9.0` , to allow any additional resource cleanup:

   ::

      /etc/libvirt/hooks/lxc guest_name release end -

-  :since:`Since 0.9.13` , the lxc hook script is also called when the libvirtd
   daemon restarts and reconnects to previously running LXC processes. If the
   script fails, the existing LXC process will be killed off. It is called as:

   ::

      /etc/libvirt/hooks/lxc guest_name reconnect begin -

/etc/libvirt/hooks/libxl
^^^^^^^^^^^^^^^^^^^^^^^^

-  | Before a Xen guest is started using libxl driver, the libxl hook script is
     called in three locations; if any location fails, the guest is not started.
     The first location, :since:`since 2.1.0` , is before libvirt performs any
     resource labeling, and the hook can allocate resources not managed by
     libvirt. This is called as:

   ::

      /etc/libvirt/hooks/libxl guest_name prepare begin -

   | The second location, available :since:`Since 2.1.0` , occurs after libvirt
     has finished labeling all resources, but has not yet started the guest,
     called as:

   ::

      /etc/libvirt/hooks/libxl guest_name start begin -

   | The third location, :since:`2.1.0` , occurs after the domain has
     successfully started up:

   ::

      /etc/libvirt/hooks/libxl guest_name started begin -

-  | When a libxl-handled Xen guest is stopped, the libxl hook script is called
     in two locations, to match the startup. First, :since:`since 2.1.0` , the
     hook is called before libvirt restores any labels:

   ::

      /etc/libvirt/hooks/libxl guest_name stopped end -

   | Then, after libvirt has released all resources, the hook is called again,
     :since:`since 2.1.0` , to allow any additional resource cleanup:

   ::

      /etc/libvirt/hooks/libxl guest_name release end -

-  :since:`Since 2.1.0` , the libxl hook script is also called at the beginning
   of incoming migration. It is called as:

   ::

      /etc/libvirt/hooks/libxl guest_name migrate begin -

   with domain XML sent to standard input of the script. In this case, the
   script acts as a filter and is supposed to modify the domain XML and print it
   out on its standard output. Empty output is identical to copying the input
   XML without changing it. In case the script returns failure or the output XML
   is not valid, incoming migration will be canceled. This hook may be used,
   e.g., to change location of disk images for incoming domains.

-  :since:`Since 6.5.0` , you can also place several hook scripts in the
   directory ``/etc/libvirt/hooks/libxl.d/``. They are executed in alphabetical
   order after main script. In this case each script also acts as filter and can
   modify the domain XML and print it out on its standard output. This script
   output is passed to standard input next script in order. Empty output from
   any script is also identical to copying the input XML without changing it. In
   case any script returns failure common process will be aborted, but all
   scripts from the directory will are executed.

-  :since:`Since 2.1.0` , the libxl hook script is also called when the libvirtd
   daemon restarts and reconnects to previously running Xen domains. If the
   script fails, the existing Xen domains will be killed off. It is called as:

   ::

      /etc/libvirt/hooks/libxl guest_name reconnect begin -

/etc/libvirt/hooks/bhyve
^^^^^^^^^^^^^^^^^^^^^^^^

-  | Before an bhyve guest is started, the bhyve hook script is called in three
     locations; if any location fails, the guest is not started. The first
     location, :since:`since 6.1.0` , is before libvirt performs any resource
     labeling, and the hook can allocate resources not managed by libvirt. This is
     called as:

   ::

      /etc/libvirt/hooks/bhyve guest_name prepare begin -

   | The second location, available :since:`Since 6.1.0` , occurs after libvirt
     has finished labeling all resources, but has not yet started the guest,
     called as:

   ::

      /etc/libvirt/hooks/bhyve guest_name start begin -

   | The third location, :since:`6.1.0` , occurs after the bhyve process has
     successfully started up:

   ::

      /etc/libvirt/hooks/bhyve guest_name started begin -

-  | When an bhyve guest is stopped, the bhyve hook script is called in two
     locations, to match the startup. First, :since:`since 6.1.0` , the hook is
     called before libvirt restores any labels:

   ::

      /etc/libvirt/hooks/bhyve guest_name stopped end -

   | Then, after libvirt has released all resources, the hook is called again,
     :since:`since 6.1.0` , to allow any additional resource cleanup:

   ::

      /etc/libvirt/hooks/bhyve guest_name release end -

/etc/libvirt/hooks/network
^^^^^^^^^^^^^^^^^^^^^^^^^^

-  | :since:`Since 1.2.2` , before a network is started, this script is called
     as:

   ::

      /etc/libvirt/hooks/network network_name start begin -

-  | After the network is started, up & running, the script is called as:

   ::

      /etc/libvirt/hooks/network network_name started begin -

-  | When a network is shut down, this script is called as:

   ::

      /etc/libvirt/hooks/network network_name stopped end -

-  | Later, when network is started and there's an interface from a domain to be
     plugged into the network, the hook script is called as:

   ::

      /etc/libvirt/hooks/network network_name port-created begin -

   Please note, that in this case, the script is passed both network and port
   XMLs on its stdin.

-  | When network is updated, the hook script is called as:

   ::

      /etc/libvirt/hooks/network network_name updated begin -

-  | When the domain from previous case is shutting down, the interface is
     unplugged. This leads to another script invocation:

   ::

      /etc/libvirt/hooks/network network_name port-deleted begin -

   And again, as in previous case, both network and port XMLs are passed onto
   script's stdin.

Script execution
----------------

-  The "start" operation for the guest and network hook scripts, executes
   **prior** to the object (guest or network) being created. This allows the
   object start operation to be aborted if the script returns indicating
   failure.
-  The "stopped" operation for the guest and network hook scripts, executes
   **after** the object (guest or network) has stopped. If the hook script
   indicates failure in its return, the shut down of the object cannot be
   aborted because it has already been performed.
-  Hook scripts execute in a synchronous fashion. Libvirt waits for them to
   return before continuing the given operation.
   This is most noticeable with the guest or network start operation, as a
   lengthy operation in the hook script can mean an extended wait for the guest
   or network to be available to end users.
-  For a hook script to be utilised, it must have its execute bit set (e.g.
   chmod o+rx *qemu*), and must be present when the libvirt daemon is started.
-  If a hook script is added to a host after the libvirt daemon is already
   running, it won't be used until the libvirt daemon next starts.

QEMU guest migration
--------------------

Migration of a QEMU guest involves running hook scripts on both the source and
destination hosts:

#. At the beginning of the migration, the *qemu* hook script on the
   **destination** host is executed with the "migrate" operation.
#. Before QEMU process is spawned, the two operations ("prepare" and "start")
   called for domain start are executed on **destination** host.
#. If both of these hook script executions exit successfully (exit status 0),
   the migration continues. Any other exit code indicates failure, and the
   migration is aborted.
#. The QEMU guest is then migrated to the destination host.
#. Unless an error occurs during the migration process, the *qemu* hook script
   on the **source** host is then executed with the "stopped" and "release"
   operations to indicate it is no longer running on this host. Regardless of
   the return codes, the migration is not aborted as it has already been
   performed.

Calling libvirt functions from within a hook script
---------------------------------------------------

**DO NOT DO THIS!**

A hook script must not call back into libvirt, as the libvirt daemon is already
waiting for the script to exit.

A deadlock is likely to occur.

Return codes and logging
------------------------

If a hook script returns with an exit code of 0, the libvirt daemon regards this
as successful and performs no logging of it.

However, if a hook script returns with a non zero exit code, the libvirt daemon
regards this as a failure, logs its return code, and additionally logs anything
on stderr the hook script returns.

For example, a hook script might use this code to indicate failure, and send a
text string to stderr:

::

   echo "Could not find required XYZZY" >&2
   exit 1

The resulting entry in the libvirt log will appear as:

::

   20:02:40.297: error : virHookCall:285 : Hook script execution failed: internal error Child process (LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
                          HOME=/root USER=root LOGNAME=root /etc/libvirt/hooks/qemu qemu prepare begin -) unexpected exit status 1: Could not find required XYZZY
