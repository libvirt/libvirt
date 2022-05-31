==========================
libvirt RPC infrastructure
==========================

.. contents::

libvirt includes a basic protocol and code to implement an extensible, secure
client/server RPC service. This was originally designed for communication
between the libvirt client library and the libvirtd daemon, but the code is now
isolated to allow reuse in other areas of libvirt code. This document provides
an overview of the protocol and structure / operation of the internal RPC
library APIs.

RPC protocol
------------

libvirt uses a simple, variable length, packet based RPC protocol. All
structured data within packets is encoded using the `XDR
standard <https://en.wikipedia.org/wiki/External_Data_Representation>`__ as
currently defined by `RFC 4506 <https://tools.ietf.org/html/rfc4506>`__. On any
connection running the RPC protocol, there can be multiple programs active, each
supporting one or more versions. A program defines a set of procedures that it
supports. The procedures can support call+reply method invocation, asynchronous
events, and generic data streams. Method invocations can be overlapped, so
waiting for a reply to one will not block the receipt of the reply to another
outstanding method. The protocol was loosely inspired by the design of SunRPC.
The definition of the RPC protocol is in the file ``src/rpc/virnetprotocol.x``
in the libvirt source tree.

Packet framing
~~~~~~~~~~~~~~

On the wire, there is no explicit packet framing marker. Instead each packet is
preceded by an unsigned 32-bit integer giving the total length of the packet in
bytes. This length includes the 4-bytes of the length word itself. Conceptually
the framing looks like this:

::

   |~~~   Packet 1   ~~~|~~~   Packet 2   ~~~|~~~  Packet 3    ~~~|~~~

   +-------+------------+-------+------------+-------+------------+...
   | n=U32 | (n-4) * U8 | n=U32 | (n-4) * U8 | n=U32 | (n-4) * U8 |
   +-------+------------+-------+------------+-------+------------+...

   |~ Len ~|~   Data   ~|~ Len ~|~   Data   ~|~ Len ~|~   Data   ~|~

Packet data
~~~~~~~~~~~

The data in each packet is split into two parts, a short fixed length header,
followed by a variable length payload. So a packet from the illustration above
is more correctly shown as

::


   +-------+-------------+---------------....---+
   | n=U32 | 6*U32       | (n-(7*4))*U8         |
   +-------+-------------+---------------....---+

   |~ Len ~|~  Header   ~|~  Payload     ....  ~|

Packet header
~~~~~~~~~~~~~

The header contains 6 fields, encoded as signed/unsigned 32-bit integers.

::

   +---------------+
   | program=U32   |
   +---------------+
   | version=U32   |
   +---------------+
   | procedure=S32 |
   +---------------+
   | type=S32      |
   +---------------+
   | serial=U32    |
   +---------------+
   | status=S32    |
   +---------------+

``program``
   This is an arbitrarily chosen number that will uniquely identify the
   "service" running over the stream.
``version``
   This is the version number of the program, by convention starting from '1'.
   When an incompatible change is made to a program, the version number is
   incremented. Ideally both versions will then be supported on the wire in
   parallel for backwards compatibility.
``procedure``
   This is an arbitrarily chosen number that will uniquely identify the method
   call, or event associated with the packet. By convention, procedure numbers
   start from 1 and are assigned monotonically thereafter.
``type``
   This can be one of the following enumeration values

   #. call: invocation of a method call
   #. reply: completion of a method call
   #. event: an asynchronous event
   #. stream: control info or data from a stream

``serial``
   This is a number that starts from 1 and increases each time a method call
   packet is sent. A reply or stream packet will have a serial number matching
   the original method call packet serial. Events always have the serial number
   set to 0.
``status``
   This can one of the following enumeration values

   #. ok: a normal packet. this is always set for method calls or events. For
      replies it indicates successful completion of the method. For streams it
      indicates confirmation of the end of file on the stream.
   #. error: for replies this indicates that the method call failed and error
      information is being returned. For streams this indicates that not all
      data was sent and the stream has aborted
   #. continue: for streams this indicates that further data packets will be
      following

Packet payload
~~~~~~~~~~~~~~

The payload of a packet will vary depending on the ``type`` and ``status``
fields from the header.

-  type=call: the in parameters for the method call, XDR encoded
-  type=call-with-fds: number of file handles, then the in parameters for the
   method call, XDR encoded, followed by the file handles
-  type=reply+status=ok: the return value and/or out parameters for the method
   call, XDR encoded
-  type=reply+status=error: the error information for the method, a virErrorPtr
   XDR encoded
-  type=reply-with-fds+status=ok: number of file handles, the return value
   and/or out parameters for the method call, XDR encoded, followed by the file
   handles
-  type=reply-with-fds+status=error: number of file handles, the error
   information for the method, a virErrorPtr XDR encoded, followed by the file
   handles
-  type=event: the parameters for the event, XDR encoded
-  type=stream+status=ok: no payload
-  type=stream+status=error: the error information for the method, a virErrorPtr
   XDR encoded
-  type=stream+status=continue: the raw bytes of data for the stream. No XDR
   encoding

With the two packet types that support passing file descriptors, in between the
header and the payload there will be a 4-byte integer specifying the number of
file descriptors which are being sent. The actual file handles are sent after
the payload has been sent. Each file handle has a single dummy byte transmitted
as a carrier for the out of band file descriptor. While the sender should always
send '\0' as the dummy byte value, the receiver ought to ignore the value for
the sake of robustness.

For the exact payload information for each procedure, consult the XDR protocol
definition for the program+version in question

Wire examples
~~~~~~~~~~~~~

The following diagrams illustrate some example packet exchanges between a client
and server

Method call
^^^^^^^^^^^

A single method call and successful reply, for a program=8, version=1,
procedure=3, which 10 bytes worth of input args, and 4 bytes worth of return
values. The overall input packet length is 4 + 24 + 10 == 38, and output packet
length 32

::

          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 1 | 0 | .o.oOo.o. |  --> S  (call)
          +--+-----------------------+-----------+

          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 1 | 0 | .o.oOo |  <-- S  (reply)
          +--+-----------------------+--------+

Method call with error
^^^^^^^^^^^^^^^^^^^^^^

An unsuccessful method call will instead return an error object

::

          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 1 | 0 | .o.oOo.o. |  --> S   (call)
          +--+-----------------------+-----------+

          +--+-----------------------+--------------------------+
   C <--  |48| 8 | 1 | 3 | 2 | 1 | 0 | .o.oOo.o.oOo.o.oOo.o.oOo |  <-- S  (error)
          +--+-----------------------+--------------------------+

Method call with upload stream
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A method call which also involves uploading some data over a stream will result
in

::

          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 1 | 0 | .o.oOo.o. |  --> S  (call)
          +--+-----------------------+-----------+

          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 1 | 0 | .o.oOo |  <-- S  (reply)
          +--+-----------------------+--------+

          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          ...
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+
   C -->  |24| 8 | 1 | 3 | 3 | 1 | 0 | --> S  (stream finish)
          +--+-----------------------+
          +--+-----------------------+
   C <--  |24| 8 | 1 | 3 | 3 | 1 | 0 | <-- S  (stream finish)
          +--+-----------------------+

Method call bidirectional stream
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A method call which also involves a bi-directional stream will result in

::

          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 1 | 0 | .o.oOo.o. |  --> S  (call)
          +--+-----------------------+-----------+

          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 1 | 0 | .o.oOo |  <-- S  (reply)
          +--+-----------------------+--------+

          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C <--  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  <-- S  (stream data down)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C <--  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  <-- S  (stream data down)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C <--  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  <-- S  (stream data down)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C <--  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  <-- S  (stream data down)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          ..
          +--+-----------------------+-------------....-------+
   C -->  |38| 8 | 1 | 3 | 3 | 1 | 2 | .o.oOo.o.oOo....o.oOo. |  --> S  (stream data up)
          +--+-----------------------+-------------....-------+
          +--+-----------------------+
   C -->  |24| 8 | 1 | 3 | 3 | 1 | 0 | --> S  (stream finish)
          +--+-----------------------+
          +--+-----------------------+
   C <--  |24| 8 | 1 | 3 | 3 | 1 | 0 | <-- S  (stream finish)
          +--+-----------------------+

Method calls overlapping
^^^^^^^^^^^^^^^^^^^^^^^^

::

          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 1 | 0 | .o.oOo.o. |  --> S  (call 1)
          +--+-----------------------+-----------+
          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 2 | 0 | .o.oOo.o. |  --> S  (call 2)
          +--+-----------------------+-----------+
          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 2 | 0 | .o.oOo |  <-- S  (reply 2)
          +--+-----------------------+--------+
          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 3 | 0 | .o.oOo.o. |  --> S  (call 3)
          +--+-----------------------+-----------+
          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 3 | 0 | .o.oOo |  <-- S  (reply 3)
          +--+-----------------------+--------+
          +--+-----------------------+-----------+
   C -->  |38| 8 | 1 | 3 | 0 | 4 | 0 | .o.oOo.o. |  --> S  (call 4)
          +--+-----------------------+-----------+
          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 1 | 0 | .o.oOo |  <-- S  (reply 1)
          +--+-----------------------+--------+
          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 4 | 0 | .o.oOo |  <-- S  (reply 4)
          +--+-----------------------+--------+

Method call with passed FD
^^^^^^^^^^^^^^^^^^^^^^^^^^

A single method call with 2 passed file descriptors and successful reply, for a
program=8, version=1, procedure=3, which 10 bytes worth of input args, and 4
bytes worth of return values. The number of file descriptors is encoded as a
32-bit int. Each file descriptor then has a 1 byte dummy payload. The overall
input packet length is 4 + 24 + 4 + 2 + 10 == 44, and output packet length 32.

::

          +--+-----------------------+---------------+-------+
   C -->  |44| 8 | 1 | 3 | 0 | 1 | 0 | 2 | .o.oOo.o. | 0 | 0 |  --> S  (call)
          +--+-----------------------+---------------+-------+

          +--+-----------------------+--------+
   C <--  |32| 8 | 1 | 3 | 1 | 1 | 0 | .o.oOo |  <-- S  (reply)
          +--+-----------------------+--------+

RPC security
------------

There are various things to consider to ensure an implementation of the RPC
protocol can be satisfactorily secured

Authentication/encryption
~~~~~~~~~~~~~~~~~~~~~~~~~

The basic RPC protocol does not define or require any specific
authentication/encryption capabilities. A generic solution to providing
encryption for the protocol is to run the protocol over a TLS encrypted data
stream. x509 certificate checks can be done to form a crude authentication
mechanism. It is also possible for an RPC program to negotiate an encryption /
authentication capability, such as SASL, which may then also provide per-packet
data encryption. Finally the protocol data stream can of course be tunnelled
over transports such as SSH.

Data limits
~~~~~~~~~~~

Although the protocol itself defines many arbitrary sized data values in the
payloads, to avoid denial of service attack there are a number of size limit
checks prior to encoding or decoding data. There is a limit on the maximum size
of a single RPC message, limit on the maximum string length, and limits on any
other parameter which uses a variable length array. These limits can be raised,
subject to agreement between client/server, without otherwise breaking
compatibility of the RPC data on the wire.

Data validation
~~~~~~~~~~~~~~~

It is important that all data be fully validated before performing any actions
based on the data. When reading an RPC packet, the first four bytes must be read
and the max packet size limit validated, before any attempt is made to read the
variable length packet data. After a complete packet has been read, the header
must be decoded and all 6 fields fully validated, before attempting to dispatch
the payload. Once dispatched, the payload can be decoded and passed on to the
appropriate API for execution. The RPC code must not take any action based on
the payload, since it has no way to validate the semantics of the payload data.
It must delegate this to the execution API (e.g. corresponding libvirt public
API).

RPC internal APIs
-----------------

The generic internal RPC library code lives in the ``src/rpc/`` directory of the
libvirt source tree. Unless otherwise noted, the objects are all threadsafe. The
core object types and their purposes are:

Overview of RPC objects
~~~~~~~~~~~~~~~~~~~~~~~

The following is a high level overview of the role of each of the main RPC
objects

``virNetSASLContext *`` (virnetsaslcontext.h)
   The virNetSASLContext APIs maintain SASL state for a network service (server
   or client). This is primarily used on the server to provide an access control
   list of SASL usernames permitted as clients.
``virNetSASLSession *`` (virnetsaslcontext.h)
   The virNetSASLSession APIs maintain SASL state for a single network
   connection (socket). This is used to perform the multi-step SASL handshake
   and perform encryption/decryption of data once authenticated, via integration
   with virNetSocket.
``virNetTLSContext *`` (virnettlscontext.h)
   The virNetTLSContext APIs maintain TLS state for a network service (server or
   client). This is primarily used on the server to provide an access control
   list of x509 distinguished names, as well as diffie-hellman keys. It can also
   do validation of x509 certificates prior to initiating a connection, in order
   to improve detection of configuration errors.
``virNetTLSSession *`` (virnettlscontext.h)
   The virNetTLSSession APIs maintain TLS state for a single network connection
   (socket). This is used to perform the multi-step TLS handshake and perform
   encryption/decryption of data once authenticated, via integration with
   virNetSocket.
``virNetSocket *`` (virnetsocket.h)
   The virNetSocket APIs provide a higher level wrapper around the raw BSD
   sockets and getaddrinfo APIs. They allow for creation of both server and
   client sockets. Data transports supported are TCP, UNIX, SSH tunnel or
   external command tunnel. Internally the TCP socket impl uses the getaddrinfo
   info APIs to ensure correct protocol-independent behaviour, thus supporting
   both IPv4 and IPv6. The socket APIs can be associated with a
   virNetSASLSession \*or virNetTLSSession \*object to allow seamless
   encryption/decryption of all writes and reads. For UNIX sockets it is
   possible to obtain the remote client user ID and process ID. Integration with
   the libvirt event loop also allows use of callbacks for notification of
   various I/O conditions
``virNetMessage *`` (virnetmessage.h)
   The virNetMessage APIs provide a wrapper around the libxdr API calls, to
   facilitate processing and creation of RPC packets. There are convenience APIs
   for encoding/encoding the packet headers, encoding/decoding the payload using
   an XDR filter, encoding/decoding a raw payload (for streams), and encoding a
   virErrorPtr object. There is also a means to add to/serve from a linked-list
   queue of messages.
``virNetClient *`` (virnetclient.h)
   The virNetClient APIs provide a way to connect to a remote server and run one
   or more RPC protocols over the connection. Connections can be made over TCP,
   UNIX sockets, SSH tunnels, or external command tunnels. There is support for
   both TLS and SASL session encryption. The client also supports management of
   multiple data streams over each connection. Each client object can be used
   from multiple threads concurrently, with method calls/replies being
   interleaved on the wire as required.
``virNetClientProgram *`` (virnetclientprogram.h)
   The virNetClientProgram APIs are used to register a program+version with the
   connection. This then enables invocation of method calls, receipt of
   asynchronous events and use of data streams, within that program+version.
   When created a set of callbacks must be supplied to take care of dispatching
   any incoming asynchronous events.
``virNetClientStream *`` (virnetclientstream.h)
   The virNetClientStream APIs are used to control transmission and receipt of
   data over a stream active on a client. Streams provide a low latency,
   unlimited length, bi-directional raw data exchange mechanism layered over the
   RPC connection
``virNetServer *`` (virnetserver.h)
   The virNetServer APIs are used to manage a network server. A server exposed
   one or more programs, over one or more services. It manages multiple client
   connections invoking multiple RPC calls in parallel, with dispatch across
   multiple worker threads.
``virNetDaemon *`` (virnetdaemon.h)
   The virNetDaemon APIs are used to manage a daemon process. A daemon is a
   process that might expose one or more servers. It handles most
   process-related details, network-related should be part of the underlying
   server.
``virNetServerClient *`` (virnetserverclient.h)
   The virNetServerClient APIs are used to manage I/O related to a single client
   network connection. It handles initial validation and routing of incoming RPC
   packets, and transmission of outgoing packets.
``virNetServerProgram *`` (virnetserverprogram.h)
   The virNetServerProgram APIs are used to provide the implementation of a
   single program/version set. Primarily this includes a set of callbacks used
   to actually invoke the APIs corresponding to program procedure numbers. It is
   responsible for all the serialization of payloads to/from XDR.
``virNetServerService *`` (virnetserverservice.h)
   The virNetServerService APIs are used to connect the server to one or more
   network protocols. A single service may involve multiple sockets (ie both
   IPv4 and IPv6). A service also has an associated authentication policy for
   incoming clients.

Client RPC dispatch
~~~~~~~~~~~~~~~~~~~

The client RPC code must allow for multiple overlapping RPC method calls to be
invoked, transmission and receipt of data for multiple streams and receipt of
asynchronous events. Understandably this involves coordination of multiple
threads.

The core requirement in the client dispatch code is that only one thread is
allowed to be performing I/O on the socket at any time. This thread is said to
be "holding the buck". When any other thread comes along and needs to do I/O it
must place its packets on a queue and delegate processing of them to the thread
that has the buck. This thread will send out the method call, and if it sees a
reply will pass it back to the waiting thread. If the other thread's reply
hasn't arrived, by the time the main thread has got its own reply, then it will
transfer responsibility for I/O to the thread that has been waiting the longest.
It is said to be "passing the buck" for I/O.

When no thread is performing any RPC method call, or sending stream data there
is still a need to monitor the socket for incoming I/O related to asynchronous
events, or stream data receipt. For this task, a watch is registered with the
event loop which triggers whenever the socket is readable. This watch is
automatically disabled whenever any other thread grabs the buck, and re-enabled
when the buck is released.

Example with buck passing
^^^^^^^^^^^^^^^^^^^^^^^^^

In the first example, a second thread issues an API call while the first thread
holds the buck. The reply to the first call arrives first, so the buck is passed
to the second thread.

::

           Thread-1
              |
              V
          Call API1()
              |
              V
          Grab Buck
              |           Thread-2
              V              |
          Send method1       V
              |          Call API2()
              V              |
           Wait I/O          V
              |<--------Queue method2
              V              |
          Send method2       V
              |          Wait for buck
              V              |
           Wait I/O          |
              |              |
              V              |
          Recv reply1        |
              |              |
              V              |
          Pass the buck----->|
              |              V
              V           Wait I/O
          Return API1()      |
                             V
                         Recv reply2
                             |
                             V
                        Release the buck
                             |
                             V
                         Return API2()

Example without buck passing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this second example, a second thread issues an API call which is sent and
replied to, before the first thread's API call has completed. The first thread
thus notifies the second that its reply is ready, and there is no need to pass
the buck

::

           Thread-1
              |
              V
          Call API1()
              |
              V
          Grab Buck
              |           Thread-2
              V              |
          Send method1       V
              |          Call API2()
              V              |
           Wait I/O          V
              |<--------Queue method2
              V              |
          Send method2       V
              |          Wait for buck
              V              |
           Wait I/O          |
              |              |
              V              |
          Recv reply2        |
              |              |
              V              |
         Notify reply2------>|
              |              V
              V          Return API2()
           Wait I/O
              |
              V
          Recv reply1
              |
              V
        Release the buck
              |
              V
          Return API1()

Example with async events
^^^^^^^^^^^^^^^^^^^^^^^^^

In this example, only one thread is present and it has to deal with some async
events arriving. The events are actually dispatched to the application from the
event loop thread

::

           Thread-1
              |
              V
          Call API1()
              |
              V
          Grab Buck
              |
              V
          Send method1
              |
              V
           Wait I/O
              |          Event thread
              V              ...
          Recv event1         |
              |               V
              V          Wait for timer/fd
          Queue event1        |
              |               V
              V           Timer fires
           Wait I/O           |
              |               V
              V           Emit event1
          Recv reply1         |
              |               V
              V          Wait for timer/fd
          Return API1()       |
                             ...

Server RPC dispatch
~~~~~~~~~~~~~~~~~~~

The RPC server code must support receipt of incoming RPC requests from multiple
client connections, and parallel processing of all RPC requests, even many from
a single client. This goal is achieved through a combination of event driven
I/O, and multiple processing threads.

The main libvirt event loop thread is responsible for performing all socket I/O.
It will read incoming packets from clients and will transmit outgoing packets to
clients. It will handle the I/O to/from streams associated with client API
calls. When doing client I/O it will also pass the data through any applicable
encryption layer (through use of the virNetSocket / virNetTLSSession and
virNetSASLSession integration). What is paramount is that the event loop thread
never do any task that can take a non-trivial amount of time.

When reading packets, the event loop will first read the 4 byte length word.
This is validated to make sure it does not exceed the maximum permissible packet
size, and the client is set to allow receipt of the rest of the packet data.
Once a complete packet has been received, the next step is to decode the RPC
header. The header is validated to ensure the request is sensible, ie the server
should not receive a method reply from a client. If the client has not yet
authenticated, an access control list check is also performed to make sure the
procedure is one of those allowed prior to auth. If the packet is a method call,
it will be placed on a global processing queue. The event loop thread is now
done with the packet for the time being.

The server has a pool of worker threads, which wait for method call packets to
be queued. One of them will grab the new method call off the queue for
processing. The first step is to decode the payload of the packet to extract the
method call arguments. The worker does not attempt to do any semantic validation
of the arguments, except to make sure the size of any variable length fields is
below defined limits.

The worker now invokes the libvirt API call that corresponds to the procedure
number in the packet header. The worker is thus kept busy until the API call
completes. The implementation of the API call is responsible for doing semantic
validation of parameters and any MAC security checks on the objects affected.

Once the API call has completed, the worker thread will take the return value
and output parameters, or error object and encode them into a reply packet.
Again it does not attempt to do any semantic validation of output data, aside
from variable length field limit checks. The worker thread puts the reply packet
on the transmission queue for the client. The worker is now finished and goes
back to wait for another incoming method call.

The main event loop is back in charge and when the client socket becomes
writable, it will start sending the method reply packet back to the client.

At any time the libvirt connection object can emit asynchronous events. These
are handled by callbacks in the main event thread. The callback will simply
encode the event parameters into a new data packet and place the packet on the
client transmission queue.

Incoming and outgoing stream packets are also directly handled by the main event
thread. When an incoming stream packet is received, instead of placing it in the
global dispatch queue for the worker threads, it is sidetracked into a
per-stream processing queue. When the stream becomes writable, queued incoming
stream packets will be processed, passing their data payload on the stream.
Conversely when the stream becomes readable, chunks of data will be read from
it, encoded into new outgoing packets, and placed on the client's transmit
queue.

Example with overlapping methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example illustrates processing of two incoming methods with overlapping
execution

::

      Event thread    Worker 1       Worker 2
          |               |              |
          V               V              V
       Wait I/O       Wait Job       Wait Job
          |               |              |
          V               |              |
      Recv method1        |              |
          |               |              |
          V               |              |
      Queue method1       V              |
          |          Serve method1       |
          V               |              |
       Wait I/O           V              |
          |           Call API1()        |
          V               |              |
      Recv method2        |              |
          |               |              |
          V               |              |
      Queue method2       |              V
          |               |         Serve method2
          V               V              |
       Wait I/O      Return API1()       V
          |               |          Call API2()
          |               V              |
          V         Queue reply1         |
      Send reply1         |              |
          |               V              V
          V           Wait Job       Return API2()
       Wait I/O           |              |
          |              ...             V
          V                          Queue reply2
      Send reply2                        |
          |                              V
          V                          Wait Job
       Wait I/O                          |
          |                             ...
         ...

Example with stream data
^^^^^^^^^^^^^^^^^^^^^^^^

This example illustrates processing of stream data

::

      Event thread
          |
          V
       Wait I/O
          |
          V
      Recv stream1
          |
          V
      Queue stream1
          |
          V
       Wait I/O
          |
          V
      Recv stream2
          |
          V
      Queue stream2
          |
          V
       Wait I/O
          |
          V
      Write stream1
          |
          V
      Write stream2
          |
          V
       Wait I/O
          |
         ...
