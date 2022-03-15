=====================================
Logging in the library and the daemon
=====================================

.. contents::

Libvirt includes logging facilities starting from version 0.6.0, this
complements the `error handling <errors.html>`__ mechanism and APIs to allow
tracing through the execution of the library as well as in the libvirtd daemon.

Logging in the library
----------------------

The logging functionalities in libvirt are based on 3 key concepts, similar to
the one present in other generic logging facilities like log4j:

-  **log messages**: they are information generated at runtime by the libvirt
   code. Each message includes a priority level (DEBUG = 1, INFO = 2, WARNING =
   3, ERROR = 4), a category, function name and line number, indicating where it
   originated from, and finally a formatted message. In addition the library
   adds a timestamp at the beginning of the message
-  **log filters**: a set of patterns and priorities to accept or reject a log
   message. If the message category matches a filter, the message priority is
   compared to the filter priority, if lower the message is discarded, if higher
   the message is output. If no filter matches, then a general priority level is
   applied to all remaining messages. This allows, for example, capturing all
   debug messages for the QEMU driver, but otherwise only allowing errors to
   show up from other parts.
-  **log outputs**: once a message has gone through filtering a set of output
   defines where to send the message, they can also filter based on the
   priority, for example it may be useful to output all messages to a debugging
   file but only allow errors to be logged through syslog.

Configuring logging in the library
----------------------------------

The library configuration of logging is through 3 environment variables allowing
to control the logging behaviour:

-  LIBVIRT_DEBUG: it can take the four following values:

   -  1 or "debug": asking the library to log every message emitted, though the
      filters can be used to avoid filling up the output
   -  2 or "info": log all non-debugging information
   -  3 or "warn": log warnings and errors, that's the default value
   -  4 or "error": log only error messages

-  LIBVIRT_LOG_FILTERS: defines logging filters
-  LIBVIRT_LOG_OUTPUTS: defines logging outputs

Note that, for example, setting LIBVIRT_DEBUG= is the same as unset. If you
specify an invalid value, it will be ignored with a warning. If you have an
error in a filter or output string, some of the settings may be applied up to
the point at which libvirt encountered the error.

Logging in the daemon
---------------------

Similarly the daemon logging behaviour can be tuned using 3 config variables,
stored in the configuration file:

-  log_level: accepts the following values:

   -  4: only errors
   -  3: warnings and errors
   -  2: information, warnings and errors
   -  1: debug and everything

-  log_filters: defines logging filters
-  log_outputs: defines logging outputs

When starting the libvirt daemon, any logging environment variable settings will
override settings in the config file. Command line options take precedence over
all. If no outputs are defined for libvirtd, it will try to use

-  0.10.0 or later: systemd journal, if ``/run/systemd/journal/socket`` exists
-  0.9.0 or later: file ``/var/log/libvirt/libvirtd.log`` if running as a daemon
-  before 0.9.0: syslog if running as a daemon
-  all versions: to stderr stream if running in the foreground

Libvirtd does not reload its logging configuration when issued a SIGHUP. If you
want to reload the configuration, you must do a
``service        libvirtd restart`` or manually stop and restart the daemon
yourself.

Starting from 0.9.0, the daemon can save all the content of the debug buffer to
the defined error channels (or /var/log/libvirt/libvirtd.log by default) in case
of crash, this can also be activated explicitly for debugging purposes by
sending the daemon a USR2 signal:

::

   killall -USR2 libvirtd

Syntax for filters and output values
------------------------------------

The syntax for filters and outputs is the same for both types of variables.

The format for a filter is:

::

   x:name

where ``name`` is a string which is matched against the category given in the
VIR_LOG_INIT() at the top of each libvirt source file, e.g., ``remote``,
``qemu``, or ``util.json`` (the name in the filter can be a substring of the
full category name, in order to match multiple similar categories), and ``x`` is
the minimal level where matching messages should be logged:

-  1: DEBUG
-  2: INFO
-  3: WARNING
-  4: ERROR

Multiple filters can be defined in a single string, they just need to be
separated by spaces, e.g: ``"3:remote 4:event"`` to only get warning or errors
from the remote layer and only errors from the event layer.

If you specify a log priority in a filter that is below the default log priority
level, messages that match that filter will still be logged, while others will
not. In order to see those messages, you must also have an output defined that
includes the priority level of your filter.

The format for an output can be one of the following forms:

-  ``x:stderr`` output goes to stderr
-  ``x:syslog:name`` use syslog for the output and use the given ``name`` as the
   ident
-  ``x:file:file_path`` output to a file, with the given filepath
-  ``x:journald`` output goes to systemd journal

In all cases the x prefix is the minimal level, acting as a filter:

-  1: DEBUG
-  2: INFO
-  3: WARNING
-  4: ERROR

Multiple output can be defined, they just need to be separated by spaces, e.g.:
``"3:syslog:libvirtd 1:file:/tmp/libvirt.log"`` will log all warnings and errors
to syslog under the libvirtd ident but also log all debug and information
included in the file ``/tmp/libvirt.log``

Systemd journal fields
----------------------

When logging to the systemd journal, the following fields are defined, in
addition to any automatically recorded `standard
fields <https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html>`__:

``MESSAGE``
   The log message string
``PRIORITY``
   The log priority value
``LIBVIRT_SOURCE``
   The source type, one of "file", "error", "audit", "trace", "library"
``CODE_FILE``
   The name of the file emitting the log record
``CODE_LINE``
   The line number of the file emitting the log record
``CODE_FUNC``
   The name of the function emitting the log record
``LIBVIRT_DOMAIN``
   The libvirt error domain (values from virErrorDomain enum), if
   LIBVIRT_SOURCE="error"
``LIBVIRT_CODE``
   The libvirt error code (values from virErrorCode enum), if
   LIBVIRT_SOURCE="error"

Well known message ID values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certain areas of the code will emit log records tagged with well known unique id
values, which are guaranteed never to change in the future. This allows
applications to identify critical log events without doing string matching on
the ``MESSAGE`` field.

``MESSAGE_ID=8ae2f3fb-2dbe-498e-8fbd-012d40afa361``
   Generated by the QEMU driver when it identifies a QEMU system emulator
   binary, but is unable to extract information about its capabilities. This is
   usually an indicator of a broken QEMU build or installation. When this is
   emitted, the ``LIBVIRT_QEMU_BINARY`` message field will provide the full path
   of the QEMU binary that failed.

The ``journalctl`` command can be used to search the journal matching on
specific message ID values

::

   $ journalctl MESSAGE_ID=8ae2f3fb-2dbe-498e-8fbd-012d40afa361 --output=json
   { ...snip...
     "LIBVIRT_SOURCE" : "file",
     "PRIORITY" : "3",
     "CODE_FILE" : "qemu/qemu_capabilities.c",
     "CODE_LINE" : "2770",
     "CODE_FUNC" : "virQEMUCapsLogProbeFailure",
     "MESSAGE_ID" : "8ae2f3fb-2dbe-498e-8fbd-012d40afa361",
     "LIBVIRT_QEMU_BINARY" : "/bin/qemu-system-xtensa",
     "MESSAGE" : "Failed to probe capabilities for /bin/qemu-system-xtensa:" \
                 "internal error: Child process (LC_ALL=C LD_LIBRARY_PATH=/home/berrange" \
                 "/src/virt/libvirt/src/.libs PATH=/usr/lib64/ccache:/usr/local/sbin:" \
                 "/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin HOME=/root " \
                 "USER=root LOGNAME=root /bin/qemu-system-xtensa -help) unexpected " \
                 "exit status 127: /bin/qemu-system-xtensa: error while loading shared " \
                 "libraries: libglapi.so.0: cannot open shared object file: No such " \
                 "file or directory\n" }

Examples
--------

Examples with useful log settings along with more information on how to properly
configure logging for various situations can be found in the
`logging knowledge base article <kbase/debuglogs.html>`__.
