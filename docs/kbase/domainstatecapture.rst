==================================
Domain state capture using Libvirt
==================================

.. contents::

In order to aid application developers to choose which operations best
suit their needs, this page compares the different means for capturing
state related to a domain managed by libvirt.

The information here is primarily geared towards capturing the state of
an active domain. Capturing the state of an inactive domain essentially
amounts to copying the contents of guest disks, followed by a fresh boot
of the same domain configuration with disks restored back to that saved
state.

State capture trade-offs
========================

One of the features made possible with virtual machines is live
migration -- transferring all state related to the guest from one host
to another with minimal interruption to the guest's activity. In this
case, state includes domain memory (including register and device
contents), and domain storage (whether the guest's view of the disks are
backed by local storage on the host, or by the hypervisor accessing
shared storage over a network). A clever observer will then note that if
all state is available for live migration, then there is nothing
stopping a user from saving some or all of that state at a given point
of time in order to be able to later rewind guest execution back to the
state it previously had. The astute reader will also realize that state
capture at any level requires that the data must be stored and managed
by some mechanism. This processing might fit in a single file, or more
likely require a chain of related files, and may require synchronization
with third-party tools built around managing the amount of data
resulting from capturing the state of multiple guests that each use
multiple disks.

There are several libvirt APIs associated with capturing the state of a
guest, which can later be used to rewind that guest to the conditions it
was in earlier. The following is a list of trade-offs and differences
between the various facets that affect capturing domain state for active
domains:

Duration
   Capturing state can be a lengthy process, so while the captured state
   ideally represents an atomic point in time corresponding to something
   the guest was actually executing, capturing state tends to focus on
   minimizing guest downtime while performing the rest of the state
   capture in parallel with guest execution. Some interfaces require
   up-front preparation (the state captured is not complete until the
   API ends, which may be some time after the command was first
   started), while other interfaces track the state when the command was
   first issued, regardless of the time spent in capturing the rest of
   the state. Also, time spent in state capture may be longer than the
   time required for live migration, when state must be duplicated
   rather than shared.
Amount of state
   For an online guest, there is a choice between capturing the guest's
   memory (all that is needed during live migration when the storage is
   already shared between source and destination), the guest's disk
   state (all that is needed if there are no pending guest I/O
   transactions that would be lost without the corresponding memory
   state), or both together. Reverting to partial state may still be
   viable, but typically, booting from captured disk state without
   corresponding memory is comparable to rebooting a machine that had
   power cut before I/O could be flushed. Guests may need to use proper
   journaling methods to avoid problems when booting from partial state.
Quiescing of data
   Even if a guest has no pending I/O, capturing disk state may catch
   the guest at a time when the contents of the disk are inconsistent.
   Cooperating with the guest to perform data quiescing is an optional
   step to ensure that captured disk state is fully consistent without
   requiring additional memory state, rather than just crash-consistent.
   But guest cooperation may also have time constraints, where the guest
   can rightfully panic if there is too much downtime while I/O is
   frozen.
Quantity of files
   When capturing state, some approaches store all state within the same
   file (internal), while others expand a chain of related files that
   must be used together (external), for more files that a management
   application must track.
Impact to guest definition
   Capturing state may require temporary changes to the guest
   definition, such as associating new files into the domain definition.
   While state capture should never impact the running guest, a change
   to the domain's active XML may have impact on other host operations
   being performed on the domain.
Third-party integration
   When capturing state, there are tradeoffs to how much of the process
   must be done directly by the hypervisor, and how much can be
   off-loaded to third-party software. Since capturing state is not
   instantaneous, it is essential that any third-party integration see
   consistent data even if the running guest continues to modify that
   data after the point in time of the capture.
Full vs. incremental
   When periodically repeating the action of state capture, it is useful
   to minimize the amount of state that must be captured by exploiting
   the relation to a previous capture, such as focusing only on the
   portions of the disk that the guest has modified in the meantime.
   Some approaches are able to take advantage of checkpoints to provide
   an incremental backup, while others are only capable of a full backup
   even if that means re-capturing unchanged portions of the disk.
Local vs. remote
   Domains that completely use remote storage may only need some
   mechanism to keep track of guest memory state while using external
   means to manage storage. Still, hypervisor and guest cooperation to
   ensure points in time when no I/O is in flight across the network can
   be important for properly capturing disk state.
Network latency
   Whether it's domain storage or saving domain state into remote
   storage, network latency has an impact on snapshot data. Having
   dedicated network capacity, bandwidth, or quality of service levels
   may play a role, as well as planning for how much of the backup
   process needs to be local.

An example of the various facets in action is migration of a running
guest. In order for the guest to be able to resume on the destination at
the same place it left off at the source, the hypervisor has to get to a
point where execution on the source is stopped, the last remaining
changes occurring since the migration started are then transferred, and
the guest is started on the target. The management software thus must
keep track of the starting point and any changes since the starting
point. These last changes are often referred to as dirty page tracking
or dirty disk block bitmaps. At some point in time during the migration,
the management software must freeze the source guest, transfer the dirty
data, and then start the guest on the target. This period of time must
be minimal. To minimize overall migration time, one is advised to use a
dedicated network connection with a high quality of service.
Alternatively saving the current state of the running guest can just be
a point in time type operation which doesn't require updating the "last
vestiges" of state prior to writing out the saved state file. The state
file is the point in time of whatever is current and may contain
incomplete data which if used to restart the guest could cause confusion
or problems because some operation wasn't completed depending upon where
in time the operation was commenced.

State capture APIs
==================

With those definitions, the following libvirt APIs related to state
capture have these properties:

`virDomainManagedSave <../html/libvirt-libvirt-domain.html#virDomainManagedSave>`__
   This API saves guest memory, with libvirt managing all of the saved
   state, then stops the guest. While stopped, the disks can be copied
   by a third party. However, since any subsequent restart of the guest
   by libvirt API will restore the memory state (which typically only
   works if the disk state is unchanged in the meantime), and since it
   is not possible to get at the memory state that libvirt is managing,
   this is not viable as a means for rolling back to earlier saved
   states, but is rather more suited to situations such as suspending a
   guest prior to rebooting the host in order to resume the guest when
   the host is back up. This API also has a drawback of potentially long
   guest downtime, and therefore does not lend itself well to live
   backups.
`virDomainSave <../html/libvirt-libvirt-domain.html#virDomainSave>`__
   This API is similar to virDomainManagedSave(), but moves the burden
   on managing the stored memory state to the user. As such, the user
   can now couple saved state with copies of the disks to perform a
   revert to an arbitrary earlier saved state. However, changing who
   manages the memory state does not change the drawback of potentially
   long guest downtime when capturing state.
`virDomainSnapshotCreateXML <../html/libvirt-libvirt-domain-snapshot.html#virDomainSnapshotCreateXML>`__
   This API wraps several approaches for capturing guest state, with a
   general premise of creating a snapshot (where the current guest
   resources are frozen in time and a new wrapper layer is opened for
   tracking subsequent guest changes). It can operate on both offline
   and running guests, can choose whether to capture the state of
   memory, disk, or both when used on a running guest, and can choose
   between internal and external storage for captured state. However, it
   is geared towards post-event captures (when capturing both memory and
   disk state, the disk state is not captured until all memory state has
   been collected first). Using QEMU as the hypervisor, internal
   snapshots currently have lengthy downtime that is incompatible with
   freezing guest I/O, but external snapshots are quick when memory
   contents are not also saved. Since creating an external snapshot
   changes which disk image resource is in use by the guest, this API
   can be coupled with
   `virDomainBlockCommit() <../html/libvirt-libvirt-domain.html#virDomainBlockCommit>`__
   to restore things back to the guest using its original disk image,
   where a third-party tool can read the backing file prior to the live
   commit. See also the `XML details <../formatsnapshot.html>`__ used with
   this command.
`virDomainFSFreeze <../html/libvirt-libvirt-domain.html#virDomainFSFreeze>`__, `virDomainFSThaw <../html/libvirt-libvirt-domain.html#virDomainFSThaw>`__
   This pair of APIs does not directly capture guest state, but can be
   used to coordinate with a trusted live guest that state capture is
   about to happen, and therefore guest I/O should be quiesced so that
   the state capture is fully consistent, rather than merely crash
   consistent. Some APIs are able to automatically perform a freeze and
   thaw via a flags parameter, rather than having to make separate calls
   to these functions. Also, note that freezing guest I/O is only
   possible with trusted guests running a guest agent, and that some
   guests place maximum time limits on how long I/O can be frozen.
`virDomainCheckpointCreateXML <../html/libvirt-libvirt-domain-checkpoint.html#virDomainCheckpointCreateXML>`__
   This API does not actually capture guest state, rather it makes it
   possible to track which portions of guest disks have changed between
   a checkpoint and the current live execution of the guest. However,
   while it is possible use this API to create checkpoints in isolation,
   it is more typical to create a checkpoint as a side-effect of
   starting a new incremental backup with ``virDomainBackupBegin()`` or
   at the creation of an external snapshot with
   ``virDomainSnapshotCreateXML2()``, since a second incremental backup
   is most useful when using the checkpoint created during the first.
   See also the `XML details <../formatcheckpoint.html>`__ used with this
   command.
`virDomainBackupBegin <../html/libvirt-libvirt-domain.html#virDomainBackupBegin>`__
   This API wraps approaches for capturing the state of disks of a
   running guest, but does not track accompanying guest memory state.
   The capture is consistent to the start of the operation, where the
   captured state is stored independently from the disk image in use
   with the guest and where it can be easily integrated with a
   third-party for capturing the disk state. Since the backup operation
   is stored externally from the guest resources, there is no need to
   commit data back in at the completion of the operation. When coupled
   with checkpoints, this can be used to capture incremental backups
   instead of full.

Examples
========

The following two sequences both accomplish the task of capturing the
disk state of a running guest, then wrapping things up so that the guest
is still running with the same file as its disk image as before the
sequence of operations began. The difference between the two sequences
boils down to the impact of an unexpected interruption made at any point
in the middle of the sequence: with such an interruption, the first
example leaves the guest tied to a temporary wrapper file rather than
the original disk, and requires manual clean up of the domain
definition; while the second example has no impact to the domain
definition.

Backup via temporary snapshot
-----------------------------

::

   virDomainFSFreeze()
   virDomainSnapshotCreateXML(VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY)
   virDomainFSThaw()
   third-party copy the backing file to backup storage # most time spent here
   virDomainBlockCommit(VIR_DOMAIN_BLOCK_COMMIT_ACTIVE) per disk
   wait for commit ready event per disk
   virDomainBlockJobAbort() per disk


Direct backup
-------------

::

   virDomainFSFreeze()
   virDomainBackupBegin()
   virDomainFSThaw()
   wait for push mode event, or pull data over NBD # most time spent here
   virDomainBackupEnd()
