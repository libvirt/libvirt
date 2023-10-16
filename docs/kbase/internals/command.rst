==================================================
Spawning processes / commands from libvirt drivers
==================================================

.. contents::

This page describes the usage of libvirt APIs for spawning processes / commands
from libvirt drivers. All code is required to use these APIs

Problems with standard POSIX APIs
---------------------------------

The POSIX specification includes a number of APIs for spawning processes /
commands, but they suffer from a number of flaws

-  ``fork+exec``: The lowest & most flexible level, but very hard to use
   correctly / safely. It is easy to leak file descriptors, have unexpected
   signal handler behaviour and not handle edge cases. Furthermore, it is not
   portable to mingw.
-  ``system``: Convenient if you don't care about capturing command output, but
   has the serious downside that the command string is interpreted by the shell.
   This makes it very dangerous to use, because improperly validated user input
   can lead to exploits via shell meta characters.
-  ``popen``: Inherits the flaws of ``system``, and has no option for
   bi-directional communication.
-  ``posix_spawn``: A half-way house between simplicity of system() and the
   flexibility of fork+exec. It does not allow for a couple of important
   features though, such as running a hook between the fork+exec stage, or
   closing all open file descriptors.

Due to the problems mentioned with each of these, libvirt driver code **must not
use** any of the above APIs. Historically libvirt provided a higher level API
known as virExec. This was wrapper around fork+exec, in a similar style to
posix_spawn, but with a few more features.

This wrapper still suffered from a number of problems. Handling command cleanup
via waitpid() is overly complex & error prone for most usage. Building up the
argv[] + env[] string arrays is quite cumbersome and error prone, particularly
wrt memory leak / OOM handling.

The libvirt command execution API
---------------------------------

There is now a high level API that provides a safe and flexible way to spawn
commands, which prevents the most common errors & is easy to code against. This
code is provided in the ``src/util/vircommand.h`` header which can be imported
using ``#include "vircommand.h"``

Defining commands in libvirt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first step is to declare what command is to be executed. The command name
can be either a fully qualified path, or a bare command name. In the latter case
it will be resolved wrt the ``$PATH`` environment variable.

::

   virCommand *cmd = virCommandNew("/usr/bin/dnsmasq");

There is no need to check for allocation failure after ``virCommandNew``. This
will be detected and reported at a later time.

Adding arguments to the command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are a number of APIs for adding arguments to a command. To add a direct
string arg

::

   virCommandAddArg(cmd, "-strict-order");

If an argument takes an attached value of the form ``-arg=val``, then this can
be done using

::

   virCommandAddArgPair(cmd, "--conf-file", "/etc/dnsmasq.conf");

If an argument needs to be formatted as if by ``printf``:

::

   virCommandAddArgFormat(cmd, "%d", count);

To add an entire NULL terminated array of arguments in one go, there are two
options.

::

   const char *const args[] = {
       "--strict-order", "--except-interface", "lo", NULL
   };
   virCommandAddArgSet(cmd, args);
   virCommandAddArgList(cmd, "--domain", "localdomain", NULL);

This can also be done at the time of initial construction of the
``virCommand *`` object:

::

   const char *const args[] = {
       "/usr/bin/dnsmasq",
       "--strict-order", "--except-interface",
       "lo", "--domain", "localdomain", NULL
   };
   virCommand *cmd1 = virCommandNewArgs(cmd, args);
   virCommand *cmd2 = virCommandNewArgList("/usr/bin/dnsmasq",
                                             "--domain", "localdomain", NULL);

Setting up the environment
~~~~~~~~~~~~~~~~~~~~~~~~~~

By default a command will inherit all environment variables from the current
process. Generally this is not desirable and a customized environment will be
more suitable. Any customization done via the following APIs will prevent
inheritance of any existing environment variables unless explicitly allowed. The
first step is usually to pass through a small number of variables from the
current process.

::

   virCommandAddEnvPassCommon(cmd);

This has now set up a clean environment for the child, passing through ``PATH``,
``LD_PRELOAD``, ``LD_LIBRARY_PATH``, ``HOME``, ``USER``, ``LOGNAME`` and
``TMPDIR``. Furthermore it will explicitly set ``LC_ALL=C`` to avoid unexpected
localization of command output. Further variables can be passed through from
parent explicitly:

::

   virCommandAddEnvPass(cmd, "DISPLAY");
   virCommandAddEnvPass(cmd, "XAUTHORITY");

To define an environment variable in the child with an separate key / value:

::

   virCommandAddEnvPair(cmd, "TERM", "xterm");

If the key/value pair is pre-formatted in the right format, it can be set
directly

::

   virCommandAddEnvString(cmd, "TERM=xterm");

Miscellaneous other options
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Normally the spawned command will retain the current process and process group
as its parent. If the current process dies, the child will then (usually) be
terminated too. If this cleanup is not desired, then the command should be
marked as daemonized:

::

   virCommandDaemonize(cmd);

When daemonizing a command, the PID visible from the caller will be that of the
intermediate process, not the actual damonized command. If the PID of the real
command is required then a pidfile can be requested

::

   virCommandSetPidFile(cmd, "/var/run/dnsmasq.pid");

This PID file is guaranteed to be written before the intermediate process exits.
Moreover, the daemonized process will inherit the FD of the opened and locked
PID file.

Reducing command privileges
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Normally a command will inherit all privileges of the current process. To
restrict what a command can do, it is possible to request that all its
capabilities are cleared. With this done it will only be able to access
resources for which it has explicit DAC permissions

::

   virCommandClearCaps(cmd);

Managing file handles
~~~~~~~~~~~~~~~~~~~~~

To prevent unintended resource leaks to child processes, the child defaults to
closing all open file handles, and setting stdin/out/err to ``/dev/null``. It is
possible to allow an open file handle to be passed into the child, while
controlling whether that handle remains open in the parent or guaranteeing that
the handle will be closed in the parent after virCommandRun, virCommandRunAsync,
or virCommandFree.

::

   int sharedfd = open("cmd.log", "w+");
   int childfd = open("conf.txt", "r");
   virCommandPassFD(cmd, sharedfd, 0);
   virCommandPassFD(cmd, childfd,
                    VIR_COMMAND_PASS_FD_CLOSE_PARENT);
   if (VIR_CLOSE(sharedfd) < 0)
       goto cleanup;

With this, both file descriptors sharedfd and childfd in the current process
remain open as the same file descriptors in the child. Meanwhile, after the
child is spawned, sharedfd remains open in the parent, while childfd is closed.

For stdin/out/err it is sometimes necessary to map a file handle. If a mapped
file handle is a pipe fed or consumed by the caller, then the caller should use
virCommandDaemonize or virCommandRunAsync rather than virCommandRun to avoid
deadlock (mapping a regular file is okay with virCommandRun). To attach file
descriptor 7 in the current process to stdin in the child:

::

   virCommandSetInputFD(cmd, 7);

Equivalently to redirect stdout or stderr in the child, pass in a pointer to the
desired handle

::

   int outfd = open("out.log", "w+");
   int errfd = open("err.log", "w+");
   virCommandSetOutputFD(cmd, &outfd);
   virCommandSetErrorFD(cmd, &errfd);

Alternatively it is possible to request that a pipe be created to fetch
stdout/err in the parent, by initializing the FD to -1.

::

   int outfd = -1;
   int errfd = -1
   virCommandSetOutputFD(cmd, &outfd);
   virCommandSetErrorFD(cmd, &errfd);

Once the command is running, ``outfd`` and ``errfd`` will be initialized with
valid file handles that can be read from. It is permissible to pass the same
pointer for both outfd and errfd, in which case both standard streams in the
child will share the same fd in the parent.

Normally, file descriptors opened to collect output from a child process perform
blocking I/O, but the parent process can request non-blocking mode:

::

   virCommandNonblockingFDs(cmd);

Feeding & capturing strings to/from the child
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Often dealing with file handles for stdin/out/err is unnecessarily complex; an
alternative is to let virCommandRun perform the I/O and interact via string
buffers. Use of a buffer only works with virCommandRun, and cannot be mixed with
pipe file descriptors. That is, the choice is generally between managing all I/O
in the caller (any fds not specified are tied to /dev/null), or letting
virCommandRun manage all I/O via strings (unspecified stdin is tied to
/dev/null, and unspecified output streams get logged but are otherwise
discarded).

It is possible to specify a string buffer to act as the data source for the
child's stdin, if there are no embedded NUL bytes, and if the command will be
run with virCommandRun:

::

   const char *input = "Hello World\n";
   virCommandSetInputBuffer(cmd, input);

Similarly it is possible to request that the child's stdout/err be redirected
into a string buffer, if the output is not expected to contain NUL bytes, and if
the command will be run with virCommandRun:

::

   char *output = NULL, *errors = NULL;
   virCommandSetOutputBuffer(cmd, &output);
   virCommandSetErrorBuffer(cmd, &errors);

Once the command has finished executing, these buffers will contain the output.
Allocation is guaranteed if virCommandRun or virCommandWait succeed (if there
was no output, then the buffer will contain an allocated empty string); if the
command failed, then the buffers usually contain a best-effort allocation of
collected information (however, on an out-of-memory condition, the buffer may
still be NULL). The caller is responsible for freeing registered buffers, since
the buffers are designed to persist beyond virCommandFree. It is possible to
pass the same pointer to both virCommandSetOutputBuffer and
virCommandSetErrorBuffer, in which case the child process interleaves output
into a single string.

Setting working directory
~~~~~~~~~~~~~~~~~~~~~~~~~

Daemonized commands are always run with "/" as the current working directory.
All other commands default to running in the same working directory as the
parent process, but an alternate directory can be specified:

::

   virCommandSetWorkingDirectory(cmd, LOCALSTATEDIR);

Any additional hooks
~~~~~~~~~~~~~~~~~~~~

If anything else is needed, it is possible to request a hook function that is
called in the child after the fork, as the last thing before changing
directories, dropping capabilities, and executing the new process. If
hook(opaque) returns non-zero, then the child process will not be run.

::

   virCommandSetPreExecHook(cmd, hook, opaque);

Logging commands
~~~~~~~~~~~~~~~~

Sometimes, it is desirable to log what command will be run, or even to use
virCommand solely for creation of a single consolidated string without running
anything.

::

   int logfd = ...;
   char *timestamp = virTimestamp();
   char *string = NULL;

   dprintf(logfd, "%s: ", timestamp);
   VIR_FREE(timestamp);
   virCommandWriteArgLog(cmd, logfd);

   string = virCommandToString(cmd, false);
   if (string)
       VIR_DEBUG("about to run %s", string);
   VIR_FREE(string);
   if (virCommandRun(cmd, NULL) < 0)
       return -1;

Running commands synchronously
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For most commands, the desired behaviour is to spawn the command, wait for it to
complete & exit and then check that its exit status is zero

::

   if (virCommandRun(cmd, NULL) < 0)
      return -1;

**Note:** if the command has been daemonized this will only block & wait for the
intermediate process, not the real command. ``virCommandRun`` will report on any
errors that have occurred upon this point with all previous API calls. If the
command fails to run, or exits with non-zero status an error will be reported
via normal libvirt error infrastructure. If a non-zero exit status can represent
a success condition, it is possible to request the exit status and perform that
check manually instead of letting ``virCommandRun`` raise the error. By default,
the captured status is only for a normal exit (death from a signal is treated as
an error), but a caller can use ``virCommandRawStatus`` to get encoded status
that includes any terminating signals.

::

   int status;
   if (virCommandRun(cmd, &status) < 0)
       return -1;
   if (status == 1) {
     ...do stuff...
   }

   virCommandRawStatus(cmd2);
   if (virCommandRun(cmd2, &status) < 0)
       return -1;
   if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
     ...do stuff...
   }

Running commands asynchronously
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In certain complex scenarios, particularly special I/O handling is required for
the child's stdin/err/out it will be necessary to run the command asynchronously
and wait for completion separately.

::

   pid_t pid;
   if (virCommandRunAsync(cmd, &pid) < 0)
      return -1;

   ... do something while pid is running ...

   int status;
   if (virCommandWait(cmd, &status) < 0)
      return -1;

   if (WEXITSTATUS(status)...) {
      ..do stuff..
   }

As with ``virCommandRun``, the ``status`` arg for ``virCommandWait`` can be
omitted, in which case it will validate that exit status is zero and raise an
error if not.

There are two approaches to child process cleanup, determined by how long you
want to keep the virCommand object in scope.

1. If the virCommand object will outlast the child process, then pass NULL for
the pid argument, and the child process will automatically be reaped at
virCommandFree, unless you reap it sooner via virCommandWait or virCommandAbort.

2. If the child process must exist on at least one code path after
virCommandFree, then pass a pointer for the pid argument. Later, to clean up the
child, call virPidWait or virPidAbort. Before virCommandFree, you can still use
virCommandWait or virCommandAbort to reap the process.

Releasing resources
~~~~~~~~~~~~~~~~~~~

Once the command has been executed, or if execution has been abandoned, it is
necessary to release resources associated with the ``virCommand *`` object. This
is done with:

::

   virCommandFree(cmd);

There is no need to check if ``cmd`` is NULL before calling ``virCommandFree``.
This scenario is handled automatically. If the command is still running, it will
be forcibly killed and cleaned up (via waitpid).

Complete examples
-----------------

This shows a complete example usage of the APIs roughly using the libvirt source
src/util/hooks.c

::

   int runhook(const char *drvstr, const char *id,
               const char *opstr, const char *subopstr,
               const char *extra)
   {
     g_autofree char *path = NULL;
     g_autoptr(virCommand) cmd = NULL;

     path = g_build_filename(LIBVIRT_HOOK_DIR, drvstr, NULL);

     cmd = virCommandNew(path);

     virCommandAddEnvPassCommon(cmd);

     virCommandAddArgList(cmd, id, opstr, subopstr, extra, NULL);

     virCommandSetInputBuffer(cmd, input);

     return virCommandRun(cmd, NULL);
   }

In this example, the command is being run synchronously. A pre-formatted string
is being fed to the command as its stdin. The command takes four arguments, and
has a minimal set of environment variables passed down. In this example, the
code does not require any error checking. All errors are reported by the
``virCommandRun`` method, and the exit status from this is returned to the
caller to handle as desired.
