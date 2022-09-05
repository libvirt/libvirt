QEMU Driver Threading: The Rules
================================

.. contents::

This document describes how thread safety is ensured throughout
the QEMU driver. The criteria for this model are:

 - Objects must never be exclusively locked for any prolonged time
 - Code which sleeps must be able to time out after suitable period
 - Must be safe against dispatch of asynchronous events from monitor

Basic locking primitives
------------------------

There are a number of locks on various objects

  ``virQEMUDriver``

    The ``qemu_conf.h`` file has inline comments describing the locking
    needs for each field. Any field marked immutable, self-locking
    can be accessed without the driver lock. For other fields there
    are typically helper APIs in ``qemu_conf.c`` that provide serialized
    access to the data. No code outside ``qemu_conf.c`` should ever
    acquire this lock

  ``virDomainObj``

    Will be locked and the reference counter will be increased after calling
    any of the ``virDomainObjListFindBy{ID,Name,UUID}`` methods. The preferred way
    of decrementing the reference counter and unlocking the domain is using the
    ``virDomainObjEndAPI()`` function.

    Lock must be held when changing/reading any variable in the ``virDomainObj``

    This lock must not be held for anything which sleeps/waits (i.e. monitor
    commands).


  ``qemuMonitorPrivatePtr`` job conditions

    Since ``virDomainObj`` lock must not be held during sleeps, the job
    conditions provide additional protection for code making updates.

    QEMU driver uses three kinds of job conditions: asynchronous, agent
    and normal.

    Asynchronous job condition is used for long running jobs (such as
    migration) that consist of several monitor commands and it is
    desirable to allow calling a limited set of other monitor commands
    while such job is running.  This allows clients to, e.g., query
    statistical data, cancel the job, or change parameters of the job.

    Normal job condition is used by all other jobs to get exclusive
    access to the monitor and also by every monitor command issued by an
    asynchronous job.  When acquiring normal job condition, the job must
    specify what kind of action it is about to take and this is checked
    against the allowed set of jobs in case an asynchronous job is
    running.  If the job is incompatible with current asynchronous job,
    it needs to wait until the asynchronous job ends and try to acquire
    the job again.

    Agent job condition is then used when thread wishes to talk to qemu
    agent monitor. It is possible to acquire just agent job
    (``virDomainObjBeginAgentJob``), or only normal job (``virDomainObjBeginJob``)
    but not both at the same time. Holding an agent job and a normal job would
    allow an unresponsive or malicious agent to block normal libvirt API and
    potentially result in a denial of service. Which type of job to grab
    depends whether caller wishes to communicate only with agent socket, or
    only with qemu monitor socket.

    Immediately after acquiring the ``virDomainObj`` lock, any method
    which intends to update state must acquire asynchronous, normal or
    agent job . The ``virDomainObj`` lock is released while blocking on
    these condition variables.  Once the job condition is acquired, a
    method can safely release the ``virDomainObj`` lock whenever it hits
    a piece of code which may sleep/wait, and re-acquire it after the
    sleep/wait.  Whenever an asynchronous job wants to talk to the
    monitor, it needs to acquire nested job (a special kind of normal
    job) to obtain exclusive access to the monitor.

    Since the ``virDomainObj`` lock was dropped while waiting for the
    job condition, it is possible that the domain is no longer active
    when the condition is finally obtained.  The monitor lock is only
    safe to grab after verifying that the domain is still active.


  ``qemuMonitor`` mutex

    Lock to be used when invoking any monitor command to ensure safety
    wrt any asynchronous events that may be dispatched from the monitor.
    It should be acquired before running a command.

    The job condition *MUST* be held before acquiring the monitor lock

    The ``virDomainObj`` lock *MUST* be held before acquiring the monitor
    lock.

    The ``virDomainObj`` lock *MUST* then be released when invoking the
    monitor command.


Helper methods
--------------

To lock the ``virDomainObj``

  ``virObjectLock()``
    - Acquires the ``virDomainObj`` lock

  ``virObjectUnlock()``
    - Releases the ``virDomainObj`` lock


To acquire the normal job condition

  ``virDomainObjBeginJob()``
    - Waits until the job is compatible with current async job or no
      async job is running
    - Waits for ``job.cond`` condition ``job.active != 0`` using ``virDomainObj``
      mutex
    - Rechecks if the job is still compatible and repeats waiting if it
      isn't
    - Sets ``job.active`` to the job type

  ``virDomainObjEndJob()``
    - Sets job.active to 0
    - Signals on job.cond condition


To acquire the agent job condition

  ``virDomainObjBeginAgentJob()``
    - Waits until there is no other agent job set
    - Sets ``job.agentActive`` to the job type

  ``virDomainObjEndAgentJob()``
    - Sets ``job.agentActive`` to 0
    - Signals on ``job.cond`` condition


To acquire the asynchronous job condition

  ``virDomainObjBeginAsyncJob()``
    - Waits until no async job is running
    - Waits for ``job.cond`` condition ``job.active != 0`` using ``virDomainObj``
      mutex
    - Rechecks if any async job was started while waiting on ``job.cond``
      and repeats waiting in that case
    - Sets ``job.asyncJob`` to the asynchronous job type

  ``virDomainObjEndAsyncJob()``
    - Sets ``job.asyncJob`` to 0
    - Broadcasts on ``job.asyncCond`` condition


To acquire the QEMU monitor lock

  ``qemuDomainObjEnterMonitor()``
    - Acquires the ``qemuMonitorObj`` lock
    - Releases the ``virDomainObj`` lock

  ``qemuDomainObjExitMonitor()``
    - Releases the ``qemuMonitorObj`` lock
    - Acquires the ``virDomainObj`` lock

  These functions must not be used by an asynchronous job.


To acquire the QEMU monitor lock as part of an asynchronous job

  ``qemuDomainObjEnterMonitorAsync()``
    - Validates that the right async job is still running
    - Acquires the ``qemuMonitorObj`` lock
    - Releases the ``virDomainObj`` lock
    - Validates that the VM is still active

  qemuDomainObjExitMonitor()
    - Releases the ``qemuMonitorObj`` lock
    - Acquires the ``virDomainObj`` lock

  These functions are for use inside an asynchronous job; the caller
  must check for a return of -1 (VM not running, so nothing to exit).
  Helper functions may also call this with ``VIR_ASYNC_JOB_NONE`` when
  used from a sync job (such as when first starting a domain).


To keep a domain alive while waiting on a remote command

  ``qemuDomainObjEnterRemote()``
    - Releases the ``virDomainObj`` lock

  ``qemuDomainObjExitRemote()``
    - Acquires the ``virDomainObj`` lock


Design patterns
---------------

 * Accessing something directly to do with a ``virDomainObj``::

     virDomainObj *obj;

     obj = qemuDomObjFromDomain(dom);

     ...do work...

     virDomainObjEndAPI(&obj);


 * Updating something directly to do with a ``virDomainObj``::

     virDomainObj *obj;

     obj = qemuDomObjFromDomain(dom);

     virDomainObjBeginJob(obj, VIR_JOB_TYPE);

     ...do work...

     virDomainObjEndJob(obj);

     virDomainObjEndAPI(&obj);


 * Invoking a monitor command on a ``virDomainObj``::

     virDomainObj *obj;
     qemuDomainObjPrivate *priv;

     obj = qemuDomObjFromDomain(dom);

     virDomainObjBeginJob(obj, VIR_JOB_TYPE);

     ...do prep work...

     if (virDomainObjIsActive(vm)) {
         qemuDomainObjEnterMonitor(obj);
         qemuMonitorXXXX(priv->mon);
         qemuDomainObjExitMonitor(obj);
     }

     ...do final work...

     virDomainObjEndJob(obj);
     virDomainObjEndAPI(&obj);


 * Invoking an agent command on a ``virDomainObj``::

     virDomainObj *obj;
     qemuAgent *agent;

     obj = qemuDomObjFromDomain(dom);

     virDomainObjBeginAgentJob(obj, VIR_AGENT_JOB_TYPE);

     ...do prep work...

     if (!qemuDomainAgentAvailable(obj, true))
         goto cleanup;

     agent = qemuDomainObjEnterAgent(obj);
     qemuAgentXXXX(agent, ..);
     qemuDomainObjExitAgent(obj, agent);

     ...do final work...

     virDomainObjEndAgentJob(obj);
     virDomainObjEndAPI(&obj);


 * Running asynchronous job::

     virDomainObj *obj;
     qemuDomainObjPrivate *priv;

     obj = qemuDomObjFromDomain(dom);

     virDomainObjBeginAsyncJob(obj, VIR_ASYNC_JOB_TYPE);
     qemuDomainObjSetAsyncJobMask(obj, allowedJobs);

     ...do prep work...

     if (qemuDomainObjEnterMonitorAsync(driver, obj,
                                        VIR_ASYNC_JOB_TYPE) < 0) {
         /* domain died in the meantime */
         goto error;
     }
     ...start qemu job...
     qemuDomainObjExitMonitor(obj);

     while (!finished) {
         if (qemuDomainObjEnterMonitorAsync(driver, obj,
                                            VIR_ASYNC_JOB_TYPE) < 0) {
             /* domain died in the meantime */
             goto error;
         }
         ...monitor job progress...
         qemuDomainObjExitMonitor(obj);

         virObjectUnlock(obj);
         sleep(aWhile);
         virObjectLock(obj);
     }

     ...do final work...

     virDomainObjEndAsyncJob(obj);
     virDomainObjEndAPI(&obj);


 * Coordinating with a remote server for migration::

     virDomainObj *obj;
     qemuDomainObjPrivate *priv;

     obj = qemuDomObjFromDomain(dom);

     virDomainObjBeginAsyncJob(obj, VIR_ASYNC_JOB_TYPE);

     ...do prep work...

     if (virDomainObjIsActive(vm)) {
         qemuDomainObjEnterRemote(obj);
         ...communicate with remote...
         qemuDomainObjExitRemote(obj);
         /* domain may have been stopped while we were talking to remote */
         if (!virDomainObjIsActive(vm)) {
             qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("guest unexpectedly quit"));
         }
     }

     ...do final work...

     virDomainObjEndAsyncJob(obj);
     virDomainObjEndAPI(&obj);
