============================
Virtual machine lock manager
============================

Libvirt includes a framework for ensuring mutual exclusion between
virtual machines using host resources. Typically this is used to prevent
two VM processes from having concurrent write access to the same disk
image, as this would result in data corruption if the guest was not
using a cluster aware filesystem.

Lock manager plugins
====================

The lock manager framework has a pluggable architecture, to allow
different locking technologies to be used.

nop
   This is a "no op" implementation which does absolutely nothing. This
   can be used if mutual exclusion between virtual machines is not
   required, or if it is being solved at another level in the management
   stack.
`lockd <locking-lockd.html>`__
   This is the current preferred implementation shipped with libvirt. It
   uses the ``virtlockd`` daemon to manage locks using the POSIX fcntl()
   advisory locking capability. As such it requires a shared filesystem
   of some kind be accessible to all hosts which share the same image
   storage.
`sanlock <locking-sanlock.html>`__
   This is an alternative implementation preferred by the oVirt project.
   It uses a disk paxos algorithm for maintaining continuously renewed
   leases. In the default setup it requires some shared filesystem, but
   it is possible to use it in a manual mode where the management
   application creates leases in SAN storage volumes.
