==============
Remote support
==============

Libvirt allows you to access hypervisors running on remote machines through
authenticated and encrypted connections.

.. contents::

Basic usage
-----------

On the remote machine, ``libvirtd`` should be running in general. See
`libvirtd configuration file`_ section on how to configure ``libvirtd``.

Not all hypervisors supported by libvirt require a running ``libvirtd``. If you
want to connect to a VMware ESX/ESXi or GSX server then ``libvirtd`` is not
necessary. See the `VMware ESX page <drvesx.html>`__ for details.

To tell libvirt that you want to access a remote resource, you should supply a
hostname in the normal `URI <uri.html>`__ that is passed to ``virConnectOpen``
(or ``virsh -c ...``). For example, if you normally use ``qemu:///system`` to
access the system-wide QEMU daemon, then to access the system-wide QEMU daemon
on a remote machine called ``compute1.libvirt.org`` you would use
``qemu://compute1.libvirt.org/system``.

The `section on remote URIs <uri.html#remote-uris>`__ describes in more detail
these remote URIs.

From an API point of view, apart from the change in URI, the API should behave
the same. For example, ordinary calls are routed over the remote connection
transparently, and values or errors from the remote side are returned to you as
if they happened locally. Some differences you may notice:

-  Additional errors can be generated, specifically ones relating to failures in
   the remote transport itself.
-  Remote calls are handled synchronously, so they will be much slower than,
   say, direct hypervisor calls.

Transports
----------

Remote libvirt supports a range of transports:

``tls``
   `TLS <https://en.wikipedia.org/wiki/Transport_Layer_Security>`__ 1.0 (SSL
   3.1) authenticated and encrypted TCP/IP socket, usually listening on a public
   port number. To use this you will need to `generate client and server
   certificates <kbase/tlscerts.html>`__. The standard port is 16514.
``unix``
   Unix domain socket. Since this is only accessible on the local machine, it is
   not encrypted, and uses Unix permissions or SELinux for authentication. The
   standard socket names are ``/var/run/libvirt/libvirt-sock`` and
   ``/var/run/libvirt/libvirt-sock-ro`` (the latter for read-only connections).
``ssh``
   Transported over an ordinary `ssh (secure
   shell) <https://www.openssh.com/>`__ connection. Requires `Netcat
   (nc) <https://en.wikipedia.org/wiki/Netcat>`__ installed and libvirtd should be
   running on the remote machine. You should use some sort of ssh key management
   (eg. `ssh-agent <http://mah.everybody.org/docs/ssh>`__) otherwise programs
   which use this transport will stop to ask for a password.
``ext``
   Any external program which can make a connection to the remote machine by
   means outside the scope of libvirt.
``tcp``
   Unencrypted TCP/IP socket. Not recommended for production use, this is
   normally disabled, but an administrator can enable it for testing or use over
   a trusted network. The standard port is 16509.
``libssh2``
   Transport over the SSH protocol using `libssh2 <https://libssh2.org/>`__
   instead of the OpenSSH binary. This transport uses the libvirt authentication
   callback for all ssh authentication calls and therefore supports
   keyboard-interactive authentication even with graphical management
   applications. As with the classic ssh transport netcat is required on the
   remote side.
``libssh``
   Transport over the SSH protocol using `libssh <https://libssh.org/>`__
   instead of the OpenSSH binary. This transport uses the libvirt authentication
   callback for all ssh authentication calls and therefore supports
   keyboard-interactive authentication even with graphical management
   applications. As with the classic ssh transport netcat is required on the
   remote side.

The choice of transport is determined by the `URI
scheme <uri.html#remote-uris>`__, with ``tls`` as the default if no explicit
transport is requested.

libvirtd configuration file
---------------------------

Libvirtd (the remote daemon) is configured from a file called
``/etc/libvirt/libvirtd.conf``, or specified on the command line using
``-f filename`` or ``--config filename``.

This file should contain lines of the form below. Blank lines and comments
beginning with ``#`` are ignored.

::

   setting = value

The following settings, values and default are:

.. list-table::
   :header-rows: 1

   * - Line
     - Default
     - Meaning

   * - listen_tls *[0|1]*
     - 1 (on)
     - Listen for secure TLS connections on the public TCP/IP port.
       Note: it is also necessary to start the server in listening mode
       by running it with --listen or adding a LIBVIRTD_ARGS="--listen" line to
       /etc/sysconfig/libvirtd.

   * - listen_tcp *[0|1]*
     - 0 (off)
     - Listen for unencrypted TCP connections on the public TCP/IP port. Note:
       it is also necessary to start the server in listening mode.

   * - tls_port *"service"*
     - "16514"
     - The port number or service name to listen on for secure TLS connections.

   * - tcp_port *"service"*
     - "16509"
     - The port number or service name to listen on for unencrypted TCP
       connections.

   * - unix_sock_group *"groupname"*
     - "root"
     - The UNIX group to own the UNIX domain socket. If the socket permissions
       allow group access, then applications running under matching group can
       access the socket. Only valid if running as root

   * - unix_sock_ro_perms *"octal-perms"*
     - "0777"
     - The permissions for the UNIX domain socket for read-only client
       connections. The default allows any user to monitor domains.

   * - unix_sock_rw_perms *"octal-perms"*
     - "0700"
     - The permissions for the UNIX domain socket for read-write client
       connections. The default allows only root to manage domains.

   * - tls_no_verify_certificate *[0|1]*
     - 0 (certificates are verified)
     - If set to 1 then if a client certificate check fails, it is not an
       error.

   * - tls_no_verify_address *[0|1]*
     - 0 (addresses are verified)
     - If set to 1 then if a client IP address check fails, it is not an
       error.

   * - key_file *"filename"*
     - "/etc/pki/libvirt/private/serverkey.pem"
     - Change the path used to find the server's private key. If you set this
       to an empty string, then no private key is loaded.

   * - cert_file *"filename"*
     - "/etc/pki/libvirt/servercert.pem"
     - Change the path used to find the server's certificate. If you set this
       to an empty string, then no certificate is loaded.

   * - ca_file *"filename"*
     - "/etc/pki/CA/cacert.pem"
     - Change the path used to find the trusted CA certificate. If you set this
       to an empty string, then no trusted CA certificate is loaded.

   * - crl_file *"filename"*
     - (no CRL file is used)
     - Change the path used to find the CA certificate revocation list (CRL)
       file. If you set this to an empty string, then no CRL is loaded.

   * - tls_allowed_dn_list ["DN1", "DN2"]
     - (none - DNs are not checked)
     - Enable an access control list of client certificate Distinguished Names
       (DNs) which can connect to the TLS port on this server.

       The default is that DNs are not checked.

       This list may contain wildcards such as
       ``"C=GB,ST=London,L=London,O=Libvirt Project,CN=*"``
       Any * matches in the string matches any number of consecutive characters,
       like a simplified ``glob(7)``.

       Note that if this is an empty list, *no client can connect*.

       Note also that GnuTLS returns DNs without spaces after commas between
       the fields (and this is what we check against), but the ``openssl x509``
       tool shows spaces.

       To make it easy to see the order of the fields in the DN a helper
       executable ``virt-pki-query-dn`` is provided for this particular use
       case.

IPv6 support
------------

The libvirtd service and libvirt remote client driver both use the
``getaddrinfo()`` functions for name resolution and are thus fully IPv6 enabled.
ie, if a server has IPv6 address configured the daemon will listen for incoming
connections on both IPv4 and IPv6 protocols. If a client has an IPv6 address
configured and the DNS address resolved for a service is reachable over IPv6,
then an IPv6 connection will be made, otherwise IPv4 will be used. In summary it
should just 'do the right thing(tm)'.
