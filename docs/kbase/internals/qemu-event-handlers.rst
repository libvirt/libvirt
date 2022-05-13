===================
QEMU event handlers
===================

This is a short description of how an example qemu event can be used
to trigger handler code that is called from the context of a worker
thread, rather than directly from the event thread (which should
itself never block, and can't do things like send qemu monitor
commands, etc).

In this case (the ``NIC_RX_FILTER_CHANGED`` event) the event is handled by
calling a qemu monitor command to get the current RX filter state,
then executing ioctls/sending netlink messages on the host in response
to changes in that filter state. This event is *not* propagated to the
libvirt API (but if someone wants to add details of how to handle that
to the end of this document, please do!).

Hopefully this narration will be helpful when adding handlers for
other qemu events in the future.

QEMU monitor events
-------------------

Any event emitted by qemu is received by
``qemu_monitor_json.c:qemuMonitorJSONIOProcessEvent()``. It looks up the
event by name in the table ``eventHandlers`` (in the same file), which
should have an entry like this for each event that libvirt
understands::

    { "NIC_RX_FILTER_CHANGED", qemuMonitorJSONHandleNicRxFilterChanged, },

NB: This table is searched with bsearch, so it *must* be alphabetically sorted.

``qemuMonitorJSONIOProcessEvent`` calls the function listed in
``eventHandlers``, e.g.::

   qemu_monitor_json.c:qemuMonitorJSONHandleNicRxFilterChanged()

which extracts any required data from the JSON ("name" in this case),
and calls::

   qemu_monitor.c:qemuMonitorEmitNicRxFilterChanged()

which uses ``QEMU_MONITOR_CALLBACK()`` to call
``mon->cb->domainNicRxFilterChanged()``. ``domainNicRxFilterChanged`` is one
in a list of function pointers in ``qemu_process.c:monitorCallbacks``. For
our example, it has been set to::

   qemuProcessHandleNicRxFilterChanged()

This function allocates a ``qemuProcessEvent`` object, and queues an event
named ``QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED`` (you'll want to add an
enum to ``qemu_domain.h:qemuProcessEventType`` for your event) for a
worker thread to handle.

(Everything up to this point has happened in the context of the thread
that is reading events from qemu, so it should do as little as
possible, never block, and never call back into the qemu
monitor. Everything after this is handled in the context of a worker
thread, so it has more freedom to make qemu monitor calls and blocking
system calls on the host.)

When the worker thread gets the event, it calls::

   qemuProcessEventHandler()

which switches on the eventType (in our example,
``QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED``) and decides to call::

   processNicRxFilterChangedEvent()

and *that* is where the actual work will be done (and any
event-specific memory allocated during ``qemuProcessHandleXXX()`` will be
freed). Note that this function must do proper refcounting of the
domain object, and assure that the domain is still active prior to
performing any operations - it is possible that the domain could have
been destroyed between the time the event was received and the time
that it is processed, and it is also possible that the domain could be
destroyed *during* the event processing if it doesn't get properly
referenced by the handler.
