=========================
libvirt API call overview
=========================

The following diagram depicts code flow from a client application, in this case
the libvirt provided ``virsh`` command through the various layers to elicit a
response from some chosen hypervisor.

**Note:** Some aspects of this document may be outdated.

.. image:: ../../images/libvirt-virConnect-example.png
   :alt: virConnectOpen calling sequence

-  ``virsh -c qemu:///system list --all``

   After the virsh code processes the input arguments, it eventually will make a
   call to open the connection using a default set of authentication credentials
   (``virConnectAuthDefault``).

-  ``virConnectOpenAuth()``

   Each of the ``virConnectOpen`` APIs will first call ``virInitialize()`` and
   then revector through the local "``do_open()``" call.

   -  ``virInitialize()``

      Calls the registration API for each of the drivers with client-side only
      capabilities and then call the ``remoteRegister()`` API last. This
      ensures the ``virDriverTab[]`` tries local drivers first before using the
      remote driver.

   -  Loop through ``virDriverTab[]`` entries trying to call their respective
      "open" entry point (in our case ``remoteOpen()``)

   -  After successful return from the ``virDriverTab[]`` ``open()`` API,
      attempt to find and open other drivers (network, interface, storage, etc.)

-  ``remoteOpen()``

   After a couple of URI checks, a call to ``doRemoteOpen()`` is made

   -  Determine network transport and host/port to use from URI

      The transport will be either ``tls``, ``unix``, ``ssh``, ``libssh2``,
      ``ext``, or ``tcp`` with the default of ``tls``. Decode the host/port if
      provided or default to ``localhost``.

   -  ``virNetClientRegisterAsyncIO()``

      Register an I/O callback mechanism to get returned data via
      ``virNetClientIncomingEvent()``

   -  ``call(...REMOTE_PROC_OPEN...)``

      Eventually routes into ``virNetClientProgramCall()`` which will call
      ``virNetClientSendWithReply()`` and eventually uses ``virNetClientIO()``
      to send the message to libvirtd and then waits for a response using
      ``virNetClientIOEventLoop()``

   -  ``virNetClientIncomingEvent()``

      Receives the returned packet and processes through
      ``virNetClientIOUpdateCallback()``

-  libvirtd Daemon

   -  Daemon Startup

      The daemon initialization processing will declare itself as a daemon via a
      ``virNetDaemonNew()`` call, then creates new server using
      ``virNetServerNew()`` and adds that server to the main daemon struct with
      ``virNetDaemonAddServer()`` call. It will then use
      ``virDriverLoadModule()`` to find/load all known drivers, set up an RPC
      server program using the ``remoteProcs[]`` table via a
      ``virNetServerProgramNew()`` call. The table is the corollary to the
      ``remote_procedure`` enum list in the client. It lists all the functions
      to be called in the same order. Once RPC is set up, networking server
      sockets are opened, the various driver state initialization routines are
      run from the ``virStateDriverTab[]``, the network links are enabled, and
      the daemon waits for work.

   -  RPC

      When a message is received, the ``remoteProcs[]`` table is referenced for
      the ``REMOTE_PROC_OPEN`` call entry. This results in
      ``remoteDispatchOpen()`` being called via the
      ``virNetServerProgramDispatchCall()``.

   -  ``remoteDispatchOpen()``

      The API will read the argument passed picking out the ``name`` of the
      driver to be opened. The code will then call ``virConnectOpen()`` or
      ``virConnectOpenReadOnly()`` depending on the argument ``flags``.

   -  ``virConnectOpen()`` or ``virConnectOpenReadOnly()``

      Just like the client except that upon entry the URI is what was passed
      from the client and will be found and opened to process the data.

      The returned structure data is returned via the ``virNetServer``
      interfaces to the remote driver which then returns it to the client
      application.
