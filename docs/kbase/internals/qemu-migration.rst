QEMU Migration Phases
=====================

.. contents::

QEMU supports only migration protocols 2 and 3 (1 was lacking too many
steps).  Repeating the protocol sequences from libvirt.c:

Migration protocol v2 API Sequence
----------------------------------

  **Src**: ``DumpXML``
    - Generate XML to pass to dst

  **Dst**: ``Prepare``
    - Get ready to accept incoming VM
    - Generate optional cookie to pass to src

  **Src**: ``Perform``
    - Start migration and wait for send completion
    - Kill off VM if successful, resume if failed

  **Dst**: ``Finish``
    - Wait for recv completion and check status
    - Kill off VM if unsuccessful

Migration protocol v3 API Sequence
----------------------------------

  **Src**: ``Begin``
    - Generate XML to pass to dst
    - Generate optional cookie to pass to dst

  **Dst**: ``Prepare``
    - Get ready to accept incoming VM
    - Generate optional cookie to pass to src

  **Src**: ``Perform``
    - Start migration and wait for send completion
    - Generate optional cookie to pass to dst

  **Dst**: ``Finish``
    - Wait for recv completion and check status
    - Kill off VM if failed, resume if success
    - Generate optional cookie to pass to src

  **Src**: ``Confirm``
    - Kill off VM if success, resume if failed

QEMU Migration Locking Rules
============================

Migration is a complicated beast which may span across several APIs on both
source and destination side and we need to keep the domain we are migrating in
a consistent state during the whole process.

To avoid anyone from changing the domain in the middle of migration we need to
keep ``MIGRATION_OUT`` job active during migration from ``Begin`` to
``Confirm`` on the source side and ``MIGRATION_IN`` job has to be active from
``Prepare`` to ``Finish`` on the destination side.

For this purpose we introduce several helper methods to deal with locking
primitives (described in `qemu-threads <qemu-threads.html>`__) in the right way:

* ``qemuMigrationJobStart``

* ``qemuMigrationJobContinue``

* ``qemuMigrationJobStartPhase``

* ``qemuMigrationJobSetPhase``

* ``qemuMigrationJobFinish``

The sequence of calling ``qemuMigrationJob*`` helper methods is as follows:

- The first API of a migration protocol (``Prepare`` or ``Perform/Begin``
  depending on migration type and version) has to start migration job and keep
  it active::

      qemuMigrationJobStart(driver, vm, VIR_JOB_MIGRATION_{IN,OUT});
      qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_*);
      ...do work...
      qemuMigrationJobContinue(vm);

- All consequent phases except for the last one have to keep the job active::

      if (!qemuMigrationJobIsActive(vm, VIR_JOB_MIGRATION_{IN,OUT}))
          return;
      qemuMigrationJobStartPhase(driver, vm, QEMU_MIGRATION_PHASE_*);
      ...do work...
      qemuMigrationJobContinue(vm);

- The last migration phase finally finishes the migration job::

      if (!qemuMigrationJobIsActive(vm, VIR_JOB_MIGRATION_{IN,OUT}))
          return;
      qemuMigrationJobStartPhase(driver, vm, QEMU_MIGRATION_PHASE_*);
      ...do work...
      qemuMigrationJobFinish(vm);

While migration job is running (i.e., after ``qemuMigrationJobStart*`` but before
``qemuMigrationJob{Continue,Finish}``), migration phase can be advanced using::

      qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_*);
