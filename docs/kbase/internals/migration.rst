===========================
Libvirt migration internals
===========================

.. contents::

Migration is a multi-step operation with at least two distinct actors,
the source and the destination libvirtd daemons, and a lot of failure
points. This document describes the basic migration workflow in the
code level, as a way to complement `the base migration docs <../../migration.html>`_
and help developers to get up to speed quicker with the code.

In this document, unless stated otherwise, these conventions are followed:

* 'user' refers to any entity that initiates a migration, regardless of being
  an human using 'virsh' or a program consuming the Libvirt API;

* 'source' refers to the source host of the migration, where the guest currently
  exists;

* 'destination' refers to the destination host of the migration;

* 'libvirt client' refers to the Libvirt client process that controls the
  migration flow, e.g. virsh. Note that this client process can reside in
  any host;

* 'regular migration' refers to any migration operation where the libvirt
  client coordinates the communication between the libvirtd instances in
  the source and destination hosts.

Migration protocol
==================

Libvirt works with three migrations protocols. Preference is given to
protocol version 3, falling back to older versions if source and destination
can't handle version 3. Version 3 has been around since at least 2014, when
virDomainMigrate3 was moved to libvirt-domain.c by commit 67c08fccdcad,
meaning that it's safe to assume that users today are capable of always running
this protocol.

Version 3 protocol sequence
---------------------------

The sequence of events in the migration protocol version 3, considering a
regular migration, is:

1) in the source, generate the domain XML to pass to the destination. This
step is called "Begin";

2) in the destination, prepare the host to accept the incoming VM from the
source. This step is called "Prepare";

3) the source then starts the migration of the guest and waits for completion.
This is called "Perform";

4) destination waits for the migration to be completed, checking if it was successful
or not. The guest is killed in case of failure. This step is called "Finish";

5) the source checks the results of the migration process, killing the guest
if successful or resuming it if it failed. This is called "Confirm".

In steps 1, 2, 3 and 4, an optional migration cookie can be generated and passed
to source or destination. This cookie contains extra information that informs
about extra settings or configuration required during the process.

The name of each step and the version of the protocol is used to name the driver
interfaces that implements the logic. The steps above are implemented by the
following interfaces:

1) Begin version 3:  ``domainMigrateBegin3()`` and ``domainMigrateBegin3Params()``
2) Prepare version 3: ``domainMigratePrepare3()`` and ``domainMigratePrepare3Params()``
3) Perform version 3: ``domainMigratePerform3()`` and ``domainMigratePerform3Params()``
4) Finish version 3: ``domainMigrateFinish3()`` and ``domainMigrateFinish3Params()``
5) Confirm version 3: ``domainMigrateConfirm3()`` and ``domainMigrateConfirm3Params()``


"virsh migrate" entry point
=============================

When an user executes a "virsh migrate" command, virsh-domain.c calls ``cmdMigrate()``.
A virThread is created with the ``doMigrate`` worker. After validation of flags and
parameters, one of these functions will be executed:

* if ``VIR_MIGRATE_PEER2PEER`` is set (i.e. --p2p was passed to virsh migrate), or
  --direct was passed as parameter, ``virDomainMigrateToURI3()`` is called;

* for all other cases, regular migration is assumed and execution goes
  to ``virDomainMigrate3()``.

virDomainMigrate3 function
--------------------------

``virDomainMigrate3()`` overall logic is:

* if VIR_MIGRATE_PEER2PEER is set, error out and tell the user that this case must
  be handled via ``virDomainMigrateToURI3()``

* if VIR_MIGRATE_OFFLINE is set, check if both source and destination supports it;

* VIR_MIGRATE_CHANGE_PROTECTION is set, check if the source host supports it;

* check if the source and the destination driver supports VIR_DRV_FEATURE_MIGRATION_PARAMS.
  In this case, forward execution to ``virDomainMigrateVersion3Params()``;

* proceed to check for a suitable migration protocol in both source and destination
  drivers. The preference is to use migration protocol v3, via
  ``virDomainMigrateVersion3()``, falling back to older versions if needed.

Both ``virDomainMigrateVersion3()`` and ``virDomainMigrateVersion3Params()``
are wrappers of ``virDomainMigrateVersion3Full()``, where the logic of the
regular migration is executed from step 1 (Begin) to 5 (Confirm).

virDomainMigrateToURI3 function
-------------------------------

While ``virDomainMigrate3()`` handles regular migration cases, ``virDomainMigrateToURI3()``
takes care of peer-2-peer and direct migration scenarios. The function does flags
validation and then calls ``virDomainMigrateUnmanagedParams()``. At this point,
more checkings are made and then:

* if VIR_MIGRATE_PEER2PEER is set and the source supports extensible parameters
  (tested via VIR_DRV_FEATURE_MIGRATION_PARAMS support), ``domainMigratePerform3Params()``
  API of the hypervisor driver is called;

* for all other cases, ``virDomainMigrateUnmanagedProto3()`` is called. This function does
  additional checkings and then calls ``domainMigratePerform3()`` API of the hypervisor
  driver.

For both cases, the execution ends in the same API that handles the third step (Perform)
of the regular migration sequence. It's up for each hypervisor driver implementation to
differ when the API is being called from a regular or a peer-2-peer/direct migration.

QEMU driver specifics
=====================

The QEMU driver supports migration protocol version 2 and 3. Here's a list of
version 3 APIs that were discussed in this document that QEMU implements,
which can be found in src/qemu/qemu_driver.c:

::

  .domainMigrateBegin3 = qemuDomainMigrateBegin3, /* 0.9.2 */
  .domainMigratePrepare3 = qemuDomainMigratePrepare3, /* 0.9.2 */
  .domainMigratePerform3 = qemuDomainMigratePerform3, /* 0.9.2 */
  .domainMigrateFinish3 = qemuDomainMigrateFinish3, /* 0.9.2 */
  .domainMigrateConfirm3 = qemuDomainMigrateConfirm3, /* 0.9.2 */

  .domainMigrateBegin3Params = qemuDomainMigrateBegin3Params, /* 1.1.0 */
  .domainMigratePrepare3Params = qemuDomainMigratePrepare3Params, /* 1.1.0 */
  .domainMigratePerform3Params = qemuDomainMigratePerform3Params, /* 1.1.0 */
  .domainMigrateFinish3Params = qemuDomainMigrateFinish3Params, /* 1.1.0 */
  .domainMigrateConfirm3Params = qemuDomainMigrateConfirm3Params, /* 1.1.0 */

All implementations have a 'Params' variation that handles the case where the
source and destationation can handle the extensible parameters API
(VIR_DRV_FEATURE_MIGRATION_PARAMS), but both versions calls out the same
inner function:

* ``qemuDomainMigrateBegin3()`` and ``qemuDomainMigrateBegin3Params()`` use
  ``qemuMigrationSrcBegin()``;

* ``qemuDomainMigratePrepare3()`` and ``qemuDomainMigratePrepare3Params()`` use
  ``qemuMigrationDstPrepareDirect()``;

* ``qemuDomainMigratePerform3()`` and ``qemuDomainMigratePerform3Params()`` use
  ``qemuMigrationSrcPerform()``

* ``qemuDomainMigrateFinish3()`` and ``qemuDomainMigrateFinish3Params()`` use
  ``qemuMigrationDstFinish()``

* ``qemuDomainMigrateConfirm3()`` and ``qemuDomainMigrateConfirm3Params()`` use
  ``qemuMigrationSrcConfirm()``
