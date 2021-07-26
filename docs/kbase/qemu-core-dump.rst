=============================
Capturing core dumps for QEMU
=============================

The default behaviour for a QEMU virtual machine launched by libvirt is to
have core dumps disabled. There can be times, however, when it is beneficial
to collect a core dump to enable debugging.

QEMU driver configuration
=========================

There is a global setting in the QEMU driver configuration file that controls
whether core dumps are permitted, and their maximum size. Enabling core dumps
is simply a matter of setting the maximum size to a non-zero value by editing
the ``/etc/libvirt/qemu.conf`` file:

::

   max_core = "unlimited"

For an adhoc debugging session, setting the core dump size to "unlimited" is
viable, on the assumption that core dumps will be disabled again once the
requisite information is collected. If the intention is to leave core dumps
permanently enabled, more careful consideration of limits is required

Note that by default, a core dump will **NOT** include the guest RAM
region, only memory regions used by QEMU for emulation and backend purposes.
This is expected to be sufficient for the vast majority of debugging needs.

When there is a need to examine guest RAM though, a further setting is
available:

::

   dump_guest_core = 1

This will of course result in core dumps that are as large as the biggest
virtual machine on the host - potentially 10's or even 100's of GB in size.

After changing either of the settings in ``/etc/libvirt/qemu.conf`` the daemon
hosting the QEMU driver must be restarted. For deployments using the monolithic
daemons, this means ``libvirtd``, while for those using modular daemons this
means ``virtqemud``:

::

   systemctl restart libvirtd    (for a monolithic deployment)
   systemctl restart virtqemud   (for a modular deployment)

While libvirt attempts to make it possible to restart the daemons without
negatively impacting running guests, there are some management operations
that may get interrupted. In particular long running jobs like live
migration or block device copy jobs may abort. It is thus wise to check
that the host is mostly idle before restarting the daemons.

Guest core dump configuration
=============================

The ``dump_guest_core`` setting mentioned above will allow guest RAM to be
included in core dumps for all virtual machines on the host. This may not
be desirable, so it is also possible to control this on a per-virtual
machine basis in the XML configuration:

::

   <memory dumpCore="on">...</memory>

Note, it is still necessary to at least set ``max_core`` to a non-zero
value in the global configuration file.

Some management applications may not offer the ability to customimze the
XML configuration for a guest. In such situations, using the global
``dump_guest_core`` setting is the only option.

Host OS core dump storage
=========================

The Linux kernel default behaviour is to write core dumps to a file in the
current working directory of the process. This will not work with QEMU
processes launched by libvirt, because their working directory is ``/``
which will not be writable.

Most modern OS distros, however, now include systemd which configures a
custom core dump handler out of the box. When this is in effect, core dumps
from QEMU can be seen using the ``coredumpctl`` commands:

::

   $ coredumpctl list -r
   TIME                        PID     UID  GID SIG     COREFILE EXE                          SIZE
   Tue 2021-07-20 12:12:52 BST 2649303 107  107 SIGABRT present  /usr/bin/qemu-system-x86_64  1.8M
   ...snip...

   $ coredumpctl info 2649303
             PID: 2649303 (qemu-system-x86)
             UID: 107 (qemu)
             GID: 107 (qemu)
          Signal: 6 (ABRT)
       Timestamp: Tue 2021-07-20 12:12:52 BST (48min ago)
    Command Line: /usr/bin/qemu-system-x86_64 -name guest=f30,debug-threads=on ..snip... -msg timestamp=on
      Executable: /usr/bin/qemu-system-x86_64
   Control Group: /machine.slice/machine-qemu\x2d1\x2df30.scope/libvirt/emulator
            Unit: machine-qemu\x2d1\x2df30.scope
           Slice: machine.slice
         Boot ID: 6b9015d0c05f4e7fbfe4197a2c7824a2
      Machine ID: c78c8286d6d74b22ac0dd275975f9ced
        Hostname: localhost.localdomain
         Storage: /var/lib/systemd/coredump/core.qemu-system-x86.107.6b9015d0c05f4e7fbfe4197a2c7824a2.2649303.1626779572000000.zst (present)
       Disk Size: 1.8M
         Message: Process 2649303 (qemu-system-x86) of user 107 dumped core.

                  Stack trace of thread 2649303:
                  #0  0x00007ff3c32436be n/a (libc.so.6 + 0xf56be)
                  #1  0x000055a949c0ed05 qemu_poll_ns (qemu-system-x86_64 + 0x7b0d05)
                  #2  0x000055a949c0e476 main_loop_wait (qemu-system-x86_64 + 0x7b0476)
                  #3  0x000055a949a36d27 qemu_main_loop (qemu-system-x86_64 + 0x5d8d27)
                  #4  0x000055a94979e4d2 main (qemu-system-x86_64 + 0x3404d2)
                  #5  0x00007ff3c3175b75 n/a (libc.so.6 + 0x27b75)
                  #6  0x000055a9497a1f5e _start (qemu-system-x86_64 + 0x343f5e)

                  Stack trace of thread 2649368:
                  #0  0x00007ff3c32435bf n/a (libc.so.6 + 0xf55bf)
                  #1  0x00007ff3c3af547c g_main_context_iterate.constprop.0 (libglib-2.0.so.0 + 0xa947c)
                  #2  0x00007ff3c3aa0a93 g_main_loop_run (libglib-2.0.so.0 + 0x54a93)
                  #3  0x00007ff3c17a727a red_worker_main.lto_priv.0 (libspice-server.so.1 + 0x5227a)
                  #4  0x00007ff3c3326299 start_thread (libpthread.so.0 + 0x9299)
                  #5  0x00007ff3c324e353 n/a (libc.so.6 + 0x100353)

		  ...snip...
