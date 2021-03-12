=========================
Connection authentication
=========================

.. contents::

When connecting to libvirt, some connections may require client
authentication before allowing use of the APIs. The set of possible
authentication mechanisms is administrator controlled, independent
of applications using libvirt. Once authenticated, libvirt can apply
fine grained `access control <acl.html>`_ to the operations
performed by a client.

Client configuration
====================

When connecting to a remote hypervisor which requires authentication,
most libvirt applications will prompt the user for the credentials. It is
also possible to provide a client configuration file containing all the
authentication credentials, avoiding any interaction. Libvirt will look
for the authentication file using the following sequence:

* The file path specified by the ``$LIBVIRT_AUTH_FILE`` environment
  variable.
* The file path specified by the ``authfile=/some/file`` URI
  query parameter
* The file ``$XDG_CONFIG_HOME/libvirt/auth.conf``
* The file ``/etc/libvirt/auth.conf``

The auth configuration file uses the traditional ``.ini``
style syntax. There are two types of groups that can be present in
the config. First there are one or more ``credential``
sets, which provide the actual authentication credentials. The keys
within the group may be:

* ``username``: the user login name to act as. This
  is relevant for ESX, Xen, HyperV and SSH, but probably not
  the one you want for libvirtd with SASL.
* ``authname``: the name to authorize as. This is
  what is commonly required for libvirtd with SASL.
* ``password``: the secret password.
* ``realm``: the domain realm for SASL, mostly unused.

Each set of credentials has a name, which is part of the group
entry name. Overall the syntax is

::

   [credentials-$NAME]
   credname1=value1
   credname2=value2


For example, to define two sets of credentials used for production
and test machines, using libvirtd, and a further ESX server for
development:

::

   [credentials-test]
   authname=fred
   password=123456

   [credentials-prod]
   authname=bar
   password=letmein

   [credentials-dev]
   username=joe
   password=hello

   [credentials-defgrp]
   username=defuser
   password=defpw

The second set of groups provide mappings of credentials to
specific machine services. The config file group names compromise
the service type and host:

::

   [auth-$SERVICE-$HOSTNAME]
   credentials=$CREDENTIALS

For example, following the previous example, here is how to
map some machines. For convenience libvirt supports a default
mapping of credentials to machines:

::

   [auth-libvirt-test1.example.com]
   credentials=test

   [auth-libvirt-test2.example.com]
   credentials=test

   [auth-libvirt-demo3.example.com]
   credentials=test

   [auth-libvirt-prod1.example.com]
   credentials=prod

   [auth-libvirt-default]
   credentials=defgrp

   [auth-esx-dev1.example.com]
   credentials=dev

   [auth-esx-default]
   credentials=defgrp

The following service types are known to libvirt:

* ``esx`` - used for connections to an ESX or VirtualCenter server
* ``hyperv`` - used for connections to an HyperV server
* ``libvirt`` - used for connections to a libvirtd
  server, which is configured with SASL auth
* ``ssh`` - used for connections to a remote QEMU driver over SSH


Applications using libvirt are free to use this same configuration
file for storing other credentials. For example, it can be used
to storage VNC or SPICE login credentials

Server configuration
====================

The libvirt daemon allows the administrator to choose the authentication
mechanisms used for client connections on each network socket independently.
This is primarily controlled via the libvirt daemon master config file in
``/etc/libvirt/libvirtd.conf``. Each of the libvirt sockets can
have its authentication mechanism configured independently. There is
currently a choice of ``none``, ``polkit``, and ``sasl``.
The SASL scheme can be further configured to choose between a large
number of different mechanisms.

UNIX socket permissions/group
-----------------------------

If libvirt does not contain support for PolicyKit, then access control for
the UNIX domain socket is done using traditional file user/group ownership
and permissions. There are 2 sockets, one for full read-write access, the
other for read-only access. The RW socket will be restricted (mode 0700) to
only allow the ``root`` user to connect. The read-only socket will
be open access (mode 0777) to allow any user to connect.

To allow non-root users greater access, the ``libvirtd.conf`` file
can be edited to change the permissions via the ``unix_sock_rw_perms``,
config parameter and to set a user group via the ``unix_sock_group``
parameter. For example, setting the former to mode ``0770`` and the
latter ``wheel`` would let any user in the wheel group connect to
the libvirt daemon.

UNIX socket PolicyKit auth
--------------------------

If libvirt contains support for PolicyKit, then access control options are
more advanced. The ``auth_unix_rw`` parameter will default to
``polkit``, and the file permissions will default to ``0777``
even on the RW socket. Upon connecting to the socket, the client application
will be required to identify itself with PolicyKit. The default policy for the
RW daemon socket will require any application running in the current desktop
session to authenticate using the user's password. This is akin to ``sudo``
auth, but does not require that the client application ultimately run as root.
Default policy will still allow any application to connect to the RO socket.

The default policy can be overridden by creating a new policy file in the
``/etc/polkit-1/rules.d`` directory. Information on the options
available can be found by reading the ``polkit(8)`` man page. The
two libvirt actions are named ``org.libvirt.unix.manage`` for full
management access, and ``org.libvirt.unix.monitor`` for read-only
access.

As an example, creating ``/etc/polkit-1/rules.d/80-libvirt-manage.rules``
with the following gives the user ``fred`` full management access
when accessing from an active local session:

::

   polkit.addRule(function(action, subject) {
     if (action.id == "org.libvirt.unix.manage" &&
         subject.local && subject.active && subject.user == "fred") {
       return polkit.Result.YES;
     }
   });

Older versions of PolicyKit used policy files ending with .pkla in the
local override directory ``/etc/polkit-1/localauthority/50-local.d/``.
Compatibility with this older format is provided by
`polkit-pkla-compat <https://pagure.io/polkit-pkla-compat>`_. As an
example, this gives the user ``fred`` full management access:

::

   [Allow fred libvirt management permissions]
   Identity=unix-user:fred
   Action=org.libvirt.unix.manage
   ResultAny=yes
   ResultInactive=yes
   ResultActive=yes

SASL pluggable authentication
-----------------------------

Libvirt integrates with the ``cyrus-sasl`` library to provide a pluggable
authentication system using the SASL protocol. SASL can be used in combination
with libvirtd's TLS or TCP socket listeners. When used with the TCP listener,
the SASL mechanism is required to provide session encryption in addition to
authentication. Only a very few SASL mechanisms are able to do this, and of
those that can do it, only the ``GSSAPI`` plugin is considered acceptably secure
by modern standards. ``GSSAPI`` is the default mechanism enabled in the libvirt
SASL configuration. It uses the Kerberos v5 authentication protocol underneath,
and assuming the Kerberos client/server are configured with modern ciphers
(AES), it provides strong session encryption capabilities. All other SASL
mechanisms should only be used with the libvirtd TLS or UNIX socket listeners.

Username/password auth
~~~~~~~~~~~~~~~~~~~~~~

To provide a simple username/password auth scheme on the libvirt UNIX socket
or TLS listeners, however, it is possible to use the ``SCRAM`` mechanism, in its
``SCRAM-SHA-256`` variant. The ``auth_unix_ro``, ``auth_unix_rw``, ``auth_tls``
config params in ``libvirtd.conf`` can be used to turn on SASL auth in these
listeners.

Since the libvirt SASL config file defaults to using ``GSSAPI`` (Kerberos), a
config change is required to enable plain password auth. This is done by
editing ``/etc/sasl2/libvirt.conf`` to set the ``mech_list``
parameter to ``scram-sha-256``.

**Note:** previous versions of libvirt suggested ``DIGEST-MD5`` and
``SCRAM-SHA-1`` mechanisms. **Use of these is strongly discouraged as they are
not considered secure by modern standards.** It is possible to replace them with
use of ``SCRAM-SHA-256``, while still using the same password database.

Out of the box, no user accounts are defined, so no clients will be able to
authenticate on the TCP socket. Adding users and setting their passwords is
done with the ``saslpasswd2`` command. When running this command it is
important to tell it that the appname is ``libvirt``. As an example, to add
a user ``fred``, run

::

   # saslpasswd2 -a libvirt fred
   Password: xxxxxx
   Again (for verification): xxxxxx

To see a list of all accounts the ``sasldblistusers2`` command can be used.
This command expects to be given the path to the libvirt user database, which
is kept in ``/etc/libvirt/passwd.db``

::

   # sasldblistusers2 -f /etc/libvirt/passwd.db
   fred@t60wlan.home.berrange.com: userPassword

Finally, to disable a user's access, the ``saslpasswd2`` command can be used
again:

::

   # saslpasswd2 -a libvirt -d fred

**Note: the SASL ``passwd.db`` file stores passwords in clear text, so
care should be taken not to let its contents be disclosed to unauthorized
users.**

GSSAPI/Kerberos auth
~~~~~~~~~~~~~~~~~~~~

The plain TCP listener of the libvirt daemon defaults to using SASL for
authentication. The libvirt SASL config also defaults to ``GSSAPI``, so there
is no need to edit the SASL config when using ``GSSAPI``. If the libvirtd TLS
or UNIX listeners are used, then the Kerberos session encryption will be
disabled since it is not required in these scenarios - only the plain TCP
listener needs encryption.

Some operating systems do not install the SASL kerberos plugin by default. It
may be necessary to install a sub-package such as ``cyrus-sasl-gssapi``.
To check whether the Kerberos plugin is installed run the ``pluginviewer``
program and verify that ``gssapi`` is listed, e.g.:

::

   # pluginviewer
   ...snip...
   Plugin "gssapiv2" [loaded],     API version: 4
   SASL mechanism: GSSAPI, best SSF: 56
   security flags: NO_ANONYMOUS|NO_PLAINTEXT|NO_ACTIVE|PASS_CREDENTIALS|MUTUAL_AUTH
   features: WANT_CLIENT_FIRST|PROXY_AUTHENTICATION|NEED_SERVER_FQDN

Next it is necessary for the administrator of the Kerberos realm to
issue a principal for the libvirt server. There needs to be one
principal per host running the libvirt daemon. The principal should be
named ``libvirt/full.hostname@KERBEROS.REALM``.  This is
typically done by running the ``kadmin.local`` command on the
Kerberos server, though some Kerberos servers have alternate ways of
setting up service principals.  Once created, the principal should be
exported to a keytab, copied to the host running the libvirt daemon
and placed in ``/etc/libvirt/krb5.tab``

::

   # kadmin.local
   kadmin.local: add_principal libvirt/foo.example.com
   Enter password for principal "libvirt/foo.example.com@EXAMPLE.COM":
   Re-enter password for principal "libvirt/foo.example.com@EXAMPLE.COM":
   Principal "libvirt/foo.example.com@EXAMPLE.COM" created.

   kadmin.local:  ktadd -k /root/libvirt-foo-example.tab libvirt/foo.example.com@EXAMPLE.COM
   Entry for principal libvirt/foo.example.com@EXAMPLE.COM with kvno 4, encryption type Triple DES cbc mode with HMAC/sha1 added to keytab WRFILE:/root/libvirt-foo-example.tab.
   Entry for principal libvirt/foo.example.com@EXAMPLE.COM with kvno 4, encryption type ArcFour with HMAC/md5 added to keytab WRFILE:/root/libvirt-foo-example.tab.
   Entry for principal libvirt/foo.example.com@EXAMPLE.COM with kvno 4, encryption type DES with HMAC/sha1 added to keytab WRFILE:/root/libvirt-foo-example.tab.
   Entry for principal libvirt/foo.example.com@EXAMPLE.COM with kvno 4, encryption type DES cbc mode with RSA-MD5 added to keytab WRFILE:/root/libvirt-foo-example.tab.

   kadmin.local: quit

   # scp /root/libvirt-foo-example.tab root@foo.example.com:/etc/libvirt/krb5.tab
   # rm /root/libvirt-foo-example.tab

Any client application wishing to connect to a Kerberos enabled libvirt server
merely needs to run ``kinit`` to gain a user principal. This may well
be done automatically when a user logs into a desktop session, if PAM is set up
to authenticate against Kerberos.
