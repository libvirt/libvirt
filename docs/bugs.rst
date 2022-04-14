=============
Bug reporting
=============

.. contents::

Security Issues
---------------

If you think that an issue with libvirt may have security implications, **please
do not** publicly report it in the bug tracker, mailing lists, or irc. Libvirt
has `a dedicated process for handling (potential) security
issues <securityprocess.html>`__ that should be used instead. So if your issue
has security implications, ignore the rest of this page and follow the `security
process <securityprocess.html>`__ instead.

Bug Tracking
------------

If you are using libvirt binaries from a Linux distribution check below for
distribution specific bug reporting policies first.

General libvirt bug reports
---------------------------

Bugs in upstream libvirt code should be reported as issues in the appropriate
`project on GitLab. <https://gitlab.com/libvirt>`__ Before submitting a ticket,
check the existing tickets to see if the bug/feature is already tracked.

It's always a good idea to file bug reports, as the process of filing the report
always makes it easier to describe the problem, and the bug number provides a
quick way of referring to the problem. However, not everybody in the community
pays frequent attention to issues, so after you file a bug, asking questions and
submitting patches on `the libvirt mailing lists <contact.html>`__ will increase
your bug's visibility and encourage people to think about your problem. Don't
hesitate to ask questions on the list, as others may know of existing solutions
or be interested in collaborating with you on finding a solution. Patches are
always appreciated, and it's likely that someone else has the same problem you
do!

If you decide to write code, though, before you begin please read the
`contributor guidelines <hacking.html>`__, especially the first point: "Discuss
any large changes on the mailing list first. Post patches early and listen to
feedback." Few development experiences are more discouraging than spending a
bunch of time writing a patch only to have someone point out a better approach
on list.

-  `View libvirt.git tickets <https://gitlab.com/libvirt/libvirt/-/issues>`__
-  `New libvirt.git ticket <https://gitlab.com/libvirt/libvirt/-/issues/new>`__

Note bugs in language bindings and other sub-projects should be reported to
their corresponding git repository rather than the main libvirt.git linked
above.

Linux Distribution specific bug reports
---------------------------------------

-  If you are using binaries from **Fedora**, enter tickets against the
   ``Fedora`` product and the ``libvirt`` component.

   -  `View Fedora libvirt
      tickets <https://bugzilla.redhat.com/buglist.cgi?component=libvirt&product=Fedora>`__
   -  `New Fedora libvirt
      ticket <https://bugzilla.redhat.com/bugzilla/enter_bug.cgi?product=Fedora&component=libvirt>`__

-  If you are using binaries from **Red Hat Enterprise Linux**, enter tickets
   against the Red Hat Enterprise Linux product that you're using (e.g., Red Hat
   Enterprise Linux 6) and the ``libvirt`` component. Red Hat bugzilla has
   `additional guidance <https://bugzilla.redhat.com>`__ about getting support
   if you are a Red Hat customer.

-  If you are using binaries from another Linux distribution first follow their
   own bug reporting guidelines.

-  Finally, if you are a contributor to another Linux distribution and would
   like to have your procedure for filing bugs mentioned here, please mail the
   libvirt development list.

How to file high quality bug reports
------------------------------------

To increase the likelihood of your bug report being addressed it is important to
provide as much information as possible. When filing libvirt bugs use this
checklist to see if you are providing enough information:

-  The version number of the libvirt build, or SHA1 of the GIT commit
-  The hardware architecture being used
-  The name of the hypervisor (Xen, QEMU, KVM)
-  The XML config of the guest domain if relevant
-  For Xen hypervisor, the domain logfiles from /var/log/xen and
   /var/log/libvirt/libxl
-  For QEMU/KVM, the domain logfile from /var/log/libvirt/qemu

If the bug leads to a tool linked to libvirt crash, then the best is to provide
a backtrace along with the scenario used to get the crash, the simplest is to
run the program under gdb, reproduce the steps leading to the crash and then
issue a gdb "bt -a" command to get the stack trace, attach it to the bug. Note
that for the data to be really useful libvirt debug information must be present
for example by installing libvirt debuginfo package on Fedora or Red Hat
Enterprise Linux (with debuginfo-install libvirt) prior to running gdb.

| It may also happen that the libvirt daemon itself crashes or gets stuck, in
  the first case run it (as root) under gdb, and reproduce the sequence leading
  to the crash, similarly to a normal program provide the "bt" backtrace
  information to where gdb will have stopped.
| But if libvirtd gets stuck, for example seems to stop processing commands, try
  to attach to the faulty daemon and issue a gdb command "thread apply all bt"
  to show all the threads backtraces, as in:

::

    #  ps -o etime,pid `pgrep libvirt`
   ... note the process id from the output
   # gdb /usr/sbin/libvirtd
   .... some information about gdb and loading debug data
   (gdb) attach $the_daemon_process_id
   ....
   (gdb) thread apply all bt
   .... information to attach to the bug
   (gdb)
