=================================
Implementing a new API in Libvirt
=================================

.. contents::

This document walks you through the process of implementing a new API in
libvirt. Remember that new API consists of any new public functions, as
well as the addition of flags or extensions of XML used by existing
functions.

Before you begin coding, it is critical that you propose your changes on
the libvirt mailing list and get feedback on your ideas to make sure
what you're proposing fits with the general direction of the project.
Even before doing a proof of concept implementation, send an email
giving an overview of the functionality you think should be added to
libvirt. Someone may already be working on the feature you want. Also,
recognize that everything you write is likely to undergo significant
rework as you discuss it with the other developers, so don't wait too
long before getting feedback.

Adding a new API to libvirt is not difficult, but there are quite a few
steps. This document assumes that you are familiar with C programming
and have checked out the libvirt code from the source code repository
and successfully built the existing tree. Instructions on how to check
out and build the code can be found at:

https://libvirt.org/downloads.html

Once you have a working development environment, the steps to create a
new API are:

#. define the public API
#. define the internal driver API
#. implement the public API
#. implement the remote protocol:

   #. define the wire protocol format
   #. implement the RPC client
   #. implement the server side dispatcher

#. use new API where appropriate in drivers
#. add virsh support
#. add common handling for new API
#. for each driver that can support the new API:

   #. add prerequisite support
   #. fully implement new API

It is, of course, possible to implement the pieces in any order, but if
the development tasks are completed in the order listed, the code will
compile after each step. Given the number of changes required,
verification after each step is highly recommended.

Submit new code in the form of one patch per step. That's not to say
submit patches before you have working functionality--get the whole
thing working and make sure you're happy with it. Then use git to break
the changes into pieces so you don't drop a big blob of code on the
mailing list in one go. Also, you should follow the upstream tree, and
rebase your series to adapt your patches to work with any other changes
that were accepted upstream during your development.

Don't mix anything else into the patches you submit. The patches should
be the minimal changes required to implement the functionality you're
adding. If you notice a bug in unrelated code (i.e., code you don't have
to touch to implement your API change) during development, create a
patch that just addresses that bug and submit it separately.

Defining the public API
-----------------------

The first task is to define the public API. If the new API involves an
XML extension, you have to enhance the RelaxNG schema and document the
new elements or attributes:

``src/conf/schemas/domaincommon.rng         docs/formatdomain.rst``

If the API extension involves a new function, you have to add a
declaration in the public header, and arrange to export the function
name (symbol) so other programs can link against the libvirt library and
call the new function:

``include/libvirt/libvirt-$MODULE.h.in         src/libvirt_public.syms``

Please consult our `coding
style <coding-style.html#xml-element-and-attribute-naming>`__ guide on
elements and attribute names.

This task is in many ways the most important to get right, since once
the API has been committed to the repository, it's libvirt's policy
never to change it. Mistakes in the implementation are bugs that you can
fix. Make a mistake in the API definition and you're stuck with it, so
think carefully about the interface and don't be afraid to rework it as
you go through the process of implementing it.

Defining the internal API
-------------------------

Each public API call is associated with a driver, such as a host
virtualization driver, a network virtualization driver, a storage
virtualization driver, a state driver, or a device monitor. Adding the
internal API is ordinarily a matter of adding a new member to the struct
representing one of these drivers.

Of course, it's possible that the new API will involve the creation of
an entirely new driver type, in which case the changes will include the
creation of a new struct type to represent the new driver type.

The driver structs are defined in:

``src/driver-$MODULE.h``

To define the internal API, first typedef the driver function prototype
and then add a new field for it to the relevant driver struct. Then,
update all existing instances of the driver to provide a ``NULL`` stub
for the new function.

Implementing the public API
---------------------------

Implementing the public API is largely a formality in which we wire up
public API to the internal driver API. The public API implementation
takes care of some basic validity checks before passing control to the
driver implementation. In RFC 2119 vocabulary, this function:

#. SHOULD log a message with VIR_DEBUG() indicating that it is being
   called and its parameters;
#. MUST call virResetLastError();
#. SHOULD confirm that the connection is valid with
   virCheckConnectReturn() or virCheckConnectGoto();
#. **SECURITY: If the API requires a connection with write privileges,
   MUST confirm that the connection flags do not indicate that the
   connection is read-only with virCheckReadOnlyGoto();**
#. SHOULD do basic validation of the parameters that are being passed
   in, using helpers like virCheckNonNullArgGoto();
#. MUST confirm that the driver for this connection exists and that it
   implements this function;
#. MUST call the internal API;
#. SHOULD log a message with VIR_DEBUG() indicating that it is
   returning, its return value, and status.
#. MUST return status to the caller.

The public API calls are implemented in:

``src/libvirt-$MODULE.c``

Implementing the remote protocol
--------------------------------

Implementing the remote protocol is essentially a straightforward
exercise which is probably most easily understood by referring to the
existing code.

Defining the wire protocol format
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Defining the wire protocol involves making additions to:

``src/remote/remote_protocol.x``

First, create two new structs for each new function that you're adding
to the API. One struct describes the parameters to be passed to the
remote function, and a second struct describes the value returned by the
remote function. The one exception to this rule is that functions that
return only 0 or -1 for status do not require a struct for returned
data.

Second, add values to the remote_procedure enum for each new function
added to the API.

Once these changes are in place, it's necessary to run 'make rpcgen' in
the src directory to create the .c and .h files required by the remote
protocol code. This must be done on a Linux host using the GLibC rpcgen
program. Other rpcgen versions may generate code which results in bogus
compile time warnings. This regenerates the following files:

``src/remote/remote_daemon_dispatch_stubs.h         src/remote/remote_daemon_dispatch.h         src/remote/remote_daemon_dispatch.c         src/remote/remote_protocol.c         src/remote/remote_protocol.h``

Implement the RPC client
~~~~~~~~~~~~~~~~~~~~~~~~

Implementing the RPC client uses the rpcgen generated .h files. The
remote method calls go in:

``src/remote/remote_driver.c``

Each remote method invocation does the following:

#. locks the remote driver;
#. sets up the method arguments;
#. invokes the remote function;
#. checks the return value, if necessary;
#. extracts any returned data;
#. frees any returned data;
#. unlocks the remote driver.

Implement the server side dispatcher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementing the server side of the remote function call is simply a
matter of deserializing the parameters passed in from the remote caller
and passing them to the corresponding internal API function. The server
side dispatchers are implemented in:

``src/remote/remote_daemon_dispatch.c``

Again, this step uses the .h files generated by make rpcgen.

After all three pieces of the remote protocol are complete, and the
generated files have been updated, it will be necessary to update the
file:

``src/remote_protocol-structs``

This file should only have new lines added; modifications to existing
lines probably imply a backwards-incompatible API change.

Use the new API internally
--------------------------

Sometimes, a new API serves as a superset of existing API, by adding
more granularity in what can be managed. When this is the case, it makes
sense to share a common implementation by making the older API become a
trivial wrapper around the new API, rather than duplicating the common
code. This step should not introduce any semantic differences for the
old API, and is not necessary if the new API has no relation to existing
API.

Expose the new API in virsh
---------------------------

All new API should be manageable from the virsh command line shell. This
proves that the API is sufficient for the intended purpose, and helps to
identify whether the proposed API needs slight changes for easier usage.
However, remember that virsh is used to connect to hosts running older
versions of libvirtd, so new commands should have fallbacks to an older
API if possible; implementing the virsh hooks at this point makes it
very easy to test these fallbacks. Also remember to document virsh
additions.

A virsh command is composed of a few pieces of code. You need to define
an array of vshCmdInfo structs for each new command that contain the
help text and the command description text. You also need an array of
vshCmdOptDef structs to describe the command options. Once you have
those pieces in place you can write the function implementing the virsh
command. Finally, you need to add the new command to the commands[]
array. The following files need changes:

``tools/virsh-$MODULE.c         tools/virsh.pod``

Implement the driver methods
----------------------------

So, after all that, we get to the fun part. All functionality in libvirt
is implemented inside a driver. Thus, here is where you implement
whatever functionality you're adding to libvirt. You'll either need to
add additional files to the src directory or extend files that are
already there, depending on what functionality you're adding.

Implement common handling
~~~~~~~~~~~~~~~~~~~~~~~~~

If the new API is applicable to more than one driver, it may make sense
to provide some utility routines, or to factor some of the work into the
dispatcher, to avoid reimplementing the same code in every driver. In
the example code, this involved adding a member to the virDomainDef
struct for mapping between the XML API addition and the in-memory
representation of a domain, along with updating all clients to use the
new member. Up to this point, there have been no changes to existing
semantics, and the new APIs will fail unless they are used in the same
way as the older API wrappers.

Implement driver handling
~~~~~~~~~~~~~~~~~~~~~~~~~

The remaining patches should only touch one driver at a time. It is
possible to implement all changes for a driver in one patch, but for
review purposes it may still make sense to break things into simpler
steps. Here is where the new APIs finally start working.

It is always a good idea to patch the test driver in addition to the
target driver, to prove that the API can be used for more than one
driver.

Any cleanups resulting from the changes should be added as separate
patches at the end of the series.

Once you have working functionality, run ninja test on each patch of the
series before submitting patches. It may also be worth writing tests for
the libvirt-TCK testsuite to exercise your new API, although those
patches are not kept in the libvirt repository.
