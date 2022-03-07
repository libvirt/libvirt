==================
Support guarantees
==================

.. contents::

This document will outline the support status / guarantees around the very
interfaces that libvirt exposes to applications and/or system administrators.
The intent is to help users understand what features they can rely upon in
particular scenarios, and whether they are likely to suffer disruption during
upgrades.

Primary public API
------------------

The main public API provided by ``libvirt.so`` and described in
``libvirt/libvirt.h`` exposes the primary hypervisor agnostic management
interface of libvirt. This API has the strongest guarantee of any part of
libvirt with a promise to keep backwards compatibility forever. Specific details
are as follows:

Functions
   Functions will never be removed from the public API, and will never have
   parameters added, removed or changed in their signature. IOW they will be ABI
   compatible forever. The semantics implied by a specific set of parameters
   passed to the function will remain unchanged. Where a parameter accepts a
   bitset of feature flags, or an enumerated value, further flags / enum values
   may be supported in the future. Where a parameter accepts one of a set of
   related constants, further constants may be supported in the future.
Struct types
   Once defined in a release, struct definitions will never have any fields add,
   removed or changed in any way. Their size and layout is fixed forever. If a
   struct name starts with an underscore, it is considered acceptable to rename
   it. Applications should thus always use the corresponding typedef in
   preference to the struct name.
Union types
   Once defined in a release, union definitions will never have any existing
   fields removed or changed. New union choices may be added, provided that they
   don't change the size of the existing union definition. If a struct name
   starts with an underscore, it is considered acceptable to rename it.
   Applications should thus always use the corresponding typedef in preference
   to the struct name.
Type definitions
   Most custom data types used in the APIs have corresponding typedefs provided
   for their stable names. The typedefs should always be used in preference to
   the underlying data type name, as the latter are not guaranteed to be stable.
Enumerations
   Once defined in a release, existing enumeration values will never be removed
   or renamed. New enumeration values may be introduced at any time. Every
   enumeration will have a '_LAST' value which indicates the current highest
   enumeration value, which may increase with new releases. If an enumeration
   name starts with an underscore, it is considered acceptable to rename it.
   Applications should thus always use the corresponding typedef in preference
   to the enum name.
Constants
   Once defined in a release, existing constants will never be removed or have
   their value changed. Most constants are grouped into related sets, and within
   each set, new constants may be introduced. APIs which use the constants may
   thus accept or return new constant values over time.
Symbol versions
   Where the platform library format permits, APIs defined in libvirt.so library
   will have version information associated. Each API will be tagged with the
   version in which it was introduced, and this won't be changed thereafter.

Hypervisor specific APIs
------------------------

A number of hypervisor drivers provide additional libraries with hypervisor
specific APIs, extending the core libvirt API. These add-on libraries follow the
same general principles described above, however, they are **not** guaranteed to
be preserved forever. The project reserves the right to remove hypervisor
specific APIs in any new release, or to change their semantics. That said the
project will endeavour to maintain API compatibility for as long as is
practical.

Use of some hypervisor specific APIs may result in the running guest being
marked as "tainted" if the API is at risk of having unexpected interactions with
normal libvirt operations. An application which chooses to make use of
hypervisor specific APIs should validate their operation with each new release
of libvirt and each new release of the underlying hypervisor. The semantics may
change in unexpected ways, or have unforeseen interactions with libvirt's
operation.

Error reporting
---------------

Most API calls are subject to failure and so will report error codes and
messages. Libvirt defines error codes for a wide variety of scenarios, some
represent very specific problems, while others are general purpose for broad
classes of problem. Over time the error codes reported are liable to change,
usually changing from a generic error to a more specific error. Thus
applications should be careful about checking for & taking action upon specific
error codes, as their behaviour may change across releases.

XML schemas
-----------

The main objects exposed via the primary libvirt public API are usually
configured via XML documents following specific schemas. The XML schemas are
considered to be stable formats, whose compatibility will be maintained forever.
Specific details are as follows:

Attributes
   Attributes defined on an XML element will never be removed or renamed. New
   attributes may be defined. If the set of valid values for an attribute are
   determined by an enumeration, the permitted values will never be removed or
   renamed, only new values defined. None the less, specific hypervisors may
   reject usage of certain values according to their feature set.
Elements
   Elements defined will never be removed or renamed. New child elements may be
   defined at any time. In places where only a single instance of a named XML
   element is used, future versions may be extended to permit multiple instances
   of the named XML element to be used. An element which currently has no
   content may later gain child elements.

Some hypervisor drivers may choose to allow use of hypervisor specific
extensions to the XML documents. These extensions will always be contained
within a hypervisor specific XML namespace. There is generally no guarantee of
long term support for the hypervisor specific extensions across releases, though
the project will endeavour to preserve them as long as is possible. Applications
choosing to use hypervisor specific extensions should validate their operation
against new libvirt or hypervisor releases.

Configuration files
-------------------

A number of programs / daemons provided libvirt rely on host filesystem
configuration files. These configuration files are accompanied by augeas lens
for easy manipulation by applications. There is in general no guarantee that
parameters available in the configuration file will be preserved across
releases, though the project will endeavour to preserve them as long as is
possible. If a configuration option is dropped from the file, the augeas lens
will retain the ability to read that configuration parameter, so that it is able
to read & update historically modified files. The default configuration files
ship with all parameters commented out such that a deployment relies on the
built-in defaults of the application in question. There is no guarantee that the
defaults will remain the same across releases. A deployment that expects a
particular value for a configuration parameter should consider defining it
explicitly, instead of relying on the defaults.

Hypervisor drivers
------------------

The libvirt project provides support for a wide variety of hypervisor drivers.
These drivers target certain versions of the hypervisor's underlying management
APIs. In general libvirt aims to work with any hypervisor version that is still
broadly supported by its vendor. When a vendor discontinues support for a
particular hypervisor version it will be dropped by libvirt. Libvirt may choose
to drop support for a particular hypervisor version prior to the vendor ending
support, if it deems that the likely usage is too small to justify the ongoing
maintenance cost.

Each hypervisor release will implement a distinct subset of features that can be
expressed in the libvirt APIs and XML formats. While the XML schema syntax will
be stable across releases, libvirt is unable to promise that it will always be
able to support usage of the same features across hypervisor releases. Where a
hypervisor changes the way a feature is implemented, the project will endeavour
to adapt to the new implementation to provide the same semantics. In cases where
the feature is discontinued by the hypervisor, libvirt will return an error
indicating it is not supported. Likewise libvirt will make reasonable efforts to
keep API calls working across hypervisor releases even if the underlying
implementation changes. In cases where this is impossible, a suitable error will
be reported. The list of APIs which have implementations `is detailed
separately <hvsupport.html>`__.

RPC protocol
------------

For some hypervisor drivers, the libvirt.so library communicates with separate
libvirt daemons to perform work. This communication takes place over a binary
RPC protocol defined by libvirt. The protocol uses the XDR format for data
encoding, and the message packet format is defined in libvirt source code.

Applications are encouraged to use the primary libvirt.so library which
transparently talks to the daemons, so that they are not exposed to the
hypervisor driver specific details. None the less, the RPC protocol associated
with the libvirtd is considered to be a long term stable ABI. It will only ever
have new messages added to it, existing messages will not be removed, nor have
their contents changed. Thus if an application does wish to provide its own
client side implementation of the RPC protocol this is supported, with the
caveat that the application will loose the ability to work with certain
hypervisors libvirt supports. The project reserves the right to define new
authentication and encryption options for the protocol, and the defaults used in
this area may change over time. This is particularly true of the TLS ciphers
permitted. Thus applications choosing to implement the RPC protocol must be
prepared to track support for new security options. If defaults are changed,
however, it will generally be possible to reconfigure the daemon to use the old
defaults, albeit with possible implications for system security.

Other daemons besides, libvirtd, also use the same RPC protocol, but with
different message types defined. These RPC protocols are all considered to be
private implementations that are liable to change at any time. Applications must
not attempt to talk to these other daemons directly.

virsh client
------------

The virsh program provides a simple client to interact with an arbitrary libvirt
hypervisor connection. Since it uses the primary public API of libvirt, it
should generally inherit the guarantees associated with that API, and with the
hypervisor driver. The commands that virsh exposes, and the arguments they
accept are all considered to be long term stable. Existing commands and
arguments will not be removed or renamed. New commands and arguments may be
added in new releases. The text output format produced by virsh commands is not
generally guaranteed to be stable if it contains compound data (eg formatted
tables or lists). Commands which output single data items (ie an object name, or
an XML document), can be treated as having stable format.
