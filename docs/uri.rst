===============
Connection URIs
===============

.. contents::

Since libvirt supports many different kinds of virtualization (often referred to
as "drivers" or "hypervisors"), we need a way to be able to specify which driver
a connection refers to. Additionally we may want to refer to a driver on a
remote machine over the network.

To this end, libvirt uses URIs as used on the Web and as defined in `RFC
2396 <https://www.ietf.org/rfc/rfc2396.txt>`__. This page documents libvirt
URIs.

Specifying URIs to libvirt
--------------------------

The URI is passed as the ``name`` parameter to
`virConnectOpen <html/libvirt-libvirt-host.html#virConnectOpen>`__ or
`virConnectOpenReadOnly <html/libvirt-libvirt-host.html#virConnectOpenReadOnly>`__
. For example:

::

   virConnectPtr conn = virConnectOpenReadOnly ("test:///default");

Configuring URI aliases
-----------------------

To simplify life for administrators, it is possible to setup URI aliases in a
libvirt client configuration file. The configuration file is
``/etc/libvirt/libvirt.conf`` for the root user, or
``$XDG_CONFIG_HOME/libvirt/libvirt.conf`` for any unprivileged user. In this
file, the following syntax can be used to setup aliases

::

   uri_aliases = [
     "hail=qemu+ssh://root@hail.cloud.example.com/system",
     "sleet=qemu+ssh://root@sleet.cloud.example.com/system",
   ]

A URI alias should be a string made up from the characters ``a-Z, 0-9, _, -``.
Following the ``=`` can be any libvirt URI string, including arbitrary URI
parameters. URI aliases will apply to any application opening a libvirt
connection, unless it has explicitly passed the ``VIR_CONNECT_NO_ALIASES``
parameter to ``virConnectOpenAuth``. If the passed in URI contains characters
outside the allowed alias character set, no alias lookup will be attempted.

Default URI choice
------------------

If the URI passed to ``virConnectOpen*`` is NULL or empty string, then libvirt
will use the following logic to determine what URI to use.

#. The environment variable ``LIBVIRT_DEFAULT_URI``
#. The client configuration file ``uri_default`` parameter
#. Probe each hypervisor in turn until one that works is found

Historically an empty URI was equivalent to ``xen:///system``.

Specifying URIs to virsh, virt-manager and virt-install
-------------------------------------------------------

In virsh use the ``-c`` or ``--connect`` option:

::

   virsh -c test:///default list

If virsh finds the environment variable ``VIRSH_DEFAULT_CONNECT_URI`` set, it
will try this URI by default. Use of this environment variable is, however,
deprecated now that libvirt supports ``LIBVIRT_DEFAULT_URI`` itself.

When using the interactive virsh shell, you can also use the ``connect`` *URI*
command to reconnect to another hypervisor.

In virt-manager use the ``-c`` or ``--connect=``\ *URI* option:

::

   virt-manager -c test:///default

In virt-install use the ``--connect=``\ *URI* option:

::

   virt-install --connect=test:///default [other options]

Local hypervisor URIs
---------------------

xen:///system URI
~~~~~~~~~~~~~~~~~

To access a Xen hypervisor running on the local machine use the URI
``xen:///system``.

Historically libvirt 0.2.2 and previous versions required to use the name
``"xen"`` to refer to the Xen hypervisor.

qemu:///... QEMU and KVM URIs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use QEMU support in libvirt you must be running the ``libvirtd`` daemon
(named ``libvirt_qemud`` in releases prior to 0.3.0). The purpose of this daemon
is to manage qemu instances.

The ``libvirtd`` daemon should be started by the init scripts when the machine
boots. It should appear as a process ``libvirtd --daemon`` running as root in
the background and will handle qemu instances on behalf of all users of the
machine (among other things).

So to connect to the daemon, one of two different URIs is used:

-  ``qemu:///system`` connects to a system mode daemon.
-  ``qemu:///session`` connects to a session mode daemon.

(If you do ``libvirtd --help``, the daemon will print out the paths of the Unix
domain socket(s) that it listens on in the various different modes).

KVM URIs are identical. You select between qemu, qemu accelerated and KVM guests
in the `guest XML as described here <drvqemu.html#example-domain-xml-config>`__.

test:///... Test URIs
~~~~~~~~~~~~~~~~~~~~~

The test driver is a dummy hypervisor for test purposes. The URIs supported are:

-  ``test:///default`` connects to a default set of host definitions built into
   the driver.
-  ``test:///path/to/host/definitions`` connects to a set of host definitions
   held in the named file.

Remote URIs
-----------

Remote URIs have the general form ("[...]" meaning an optional part):

::

  driver[+transport]://[username@][hostname][:port]/[path][?extraparameters]

Either the transport or the hostname must be given in order to distinguish this
from a local URI.

Some examples:

-  ``xen+ssh://rjones@towada/system``
   — Connect to a remote Xen hypervisor on host ``towada`` using ssh transport
   and ssh username ``rjones``.
-  ``xen://towada/system``
   — Connect to a remote Xen hypervisor on host ``towada`` using TLS.
-  ``xen://towada/system?no_verify=1``
   — Connect to a remote Xen hypervisor on host ``towada`` using TLS. Do not
   verify the server's certificate.
-  ``qemu+unix:///system?socket=/opt/libvirt/run/libvirt/libvirt-sock``
   — Connect to the local qemu instances over a non-standard Unix socket (the
   full path to the Unix socket is supplied explicitly in this case).
-  ``test+tcp://localhost:5000/default``
   — Connect to a libvirtd daemon offering unencrypted TCP/IP connections on
   localhost port 5000 and use the test driver with default settings.
-  ``qemu+libssh2://user@host/system?known_hosts=/home/user/.ssh/known_hosts``
   — Connect to a remote host using a ssh connection with the libssh2 driver and
   use a different known_hosts file.
-  ``qemu+libssh://user@host/system?known_hosts=/home/user/.ssh/known_hosts``
   — Connect to a remote host using a ssh connection with the libssh driver and
   use a different known_hosts file.

Transport configuration
~~~~~~~~~~~~~~~~~~~~~~~

The remote driver supports multiple transport protocols and approaches which are
configurable via the URI.

Extra parameters can be added to remote URIs as part of the query string (the
part following ``?``). Remote URIs understand the extra parameters shown
below. Any others are passed unmodified through to the back end. Note that
parameter values must be
`URI-escaped <https://gnome.pages.gitlab.gnome.org/libxml2/devhelp/libxml2-uri.html#xmlURIEscapeStr>`__.

All transports support the following parameters:

  ``name``

    The name passed to the remote ``virConnectOpen`` function. The name is
    normally formed by removing transport, hostname, port number, username and
    extra parameters from the remote URI, but in certain very complex cases it
    may be better to supply the name explicitly.

    **Example:** ``name=qemu:///system``

``ssh`` transport
^^^^^^^^^^^^^^^^^

The ``ssh`` transport uses the standard SSH protocol via the system installed
binary.

Supported extra parameters:

  ``mode``
    See the info on the `mode parameter`_.
  ``proxy``
    See the info on the `proxy parameter`_.
  ``command``
    Path to the ``ssh`` binary to use.

    **Example:** ``command=/opt/openssh/bin/ssh``
  ``socket``
    See the info on the `socket parameter`_.
  ``netcat``
    See the info on the `netcat parameter`_.
  ``keyfile``
    See the info on the `keyfile parameter`_.
  ``no_verify``
    If set to a non-zero value, this disables client's strict host key checking
    making it auto-accept new host keys. Existing host keys will still be
    validated.

    **Example:** ``no_verify=1``
  ``no_tty``
    If set to a non-zero value, this stops ssh from asking for a password if it
    cannot log in to the remote machine automatically (eg. using ssh-agent
    etc.). Use this when you don't have access to a terminal - for example in
    graphical programs which use libvirt.

    **Example:** ``no_tty=1``

``libssh`` and ``libssh2`` transport
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Same as the ``ssh`` transport but the SSH client is handled directly by using
either ``libssh`` or ``libssh2`` to handle the SSH protocol without spawning an
extra process.

Supported extra parameters:

  ``mode``
    See the info on the `mode parameter`_.
  ``proxy``
    See the info on the `proxy parameter`_.
  ``socket``
    See the info on the `socket parameter`_.
  ``netcat``
    See the info on the `netcat parameter`_.
  ``keyfile``
    See the info on the `keyfile parameter`_.
  ``known_hosts``
    Path to the known_hosts file to verify the host key against. LibSSH2 and
    libssh support OpenSSH-style known_hosts files, although LibSSH2 does not
    support all key types, so using files created by the OpenSSH binary may
    result into truncating the known_hosts file. Thus, with LibSSH2 it's
    recommended to use the default known_hosts file is located in libvirt's
    client local configuration directory e.g.: ~/.conf ig/libvirt/known_hosts.

    *Note:* Use absolute paths.

    **Example:** ``known_hosts=/root/.ssh/known_hosts``

  ``known_hosts_verify``
    If set to ``normal`` (default), then the user will be asked to accept new
    host keys.  If set to ``auto``, new host keys will be auto-accepted, but
    existing host keys will still be validated. If set to ``ignore``, this
    disables client's strict host key checking.

    **Example:** ``known_hosts_verify=ignore``

  ``sshauth``
    A comma separated list of authentication methods to use. Default (is
    "agent,privkey,password ,keyboard-interactive".  The order of the methods
    is preserved.  Some methods may require additional parameters.

    **Example:** ``sshauth=privkey,agent``

``tls`` transport
^^^^^^^^^^^^^^^^^

This transport uses a TCP connection to the socket. The data is encrypted using
TLS to ensure security. Note that TLS certificates must be setup for this to
work.

Supported extra parameters:

  ``tls_priority``
    A valid GNUTLS priority string.

    **Example:** ``tls_priority=NORMAL:-VERS-SSL3.0``

  ``no_verify``
    If set to a non-zero value, this disables client checks of the server's
    certificate. Note that to disable server checks of the client's certificate
    or IP address you must `change the libvirtd configuration
    <remote.html#libvirtd-configuration-file>`__

    **Example:** ``no_verify=1``

  ``pkipath``

    Specifies x509 certificates path for the client. If any of the CA
    certificate, client certificate, or client key is missing, the connection
    will fail with a fatal error.

    **Example:** ``pkipath=/tmp/pki/client``

``unix`` transport
^^^^^^^^^^^^^^^^^^

This transport uses an unix domain socket is used to connect to the daemon.
This is the most common case. In most cases no extra parameters are needed.

Supported extra parameters:

  ``mode``
    See the info on the `mode parameter`_.
  ``socket``
    See the info on the `socket parameter`_.

``ext`` transport
^^^^^^^^^^^^^^^^^

The ``ext`` transport invokes the user specified command to transport the
libvirt RPC protocol to the destination. The command must be able to handle
the proper connection. Standard input/output is used for the communication.

Supported extra parameters:

  ``command``
    The external command launched to tunnel the data to the destination.

``tcp`` transport
^^^^^^^^^^^^^^^^^

The ``tcp`` transport uses plain unencrypted TCP connection to libvirt. This
is insecure and should not be used. This transport has no additional arguments.

Common extra parameters
~~~~~~~~~~~~~~~~~~~~~~~

Certain extra parameters are shared between multiple protocols. See the list of
transport protocols above for specific usage.

``mode`` parameter
^^^^^^^^^^^^^^^^^^

Controls whether to connect to per-driver daemons or libvirtd.

Supported values:

  ``auto``
    automatically determine the daemon
  ``direct``
    connect to per-driver daemons
  ``legacy``
    connect to libvirtd

Default is ``auto``. Can also be set in ``libvirt.conf`` as ``remote_mode``.

**Example:** ``mode=direct``

``proxy`` parameter
^^^^^^^^^^^^^^^^^^^

Controls which proxy binary is used on the remote side of connection to connect
to the daemon.

Supported values:

  ``auto``
    try native, fallback to netcat
  ``netcat``
    only use netcat
  ``native``
    use the libvirt native proxy binary

Default is ``auto``. Can also be set in ``libvirt.conf`` as ``remote_proxy``.

**Example:** ``proxy=native``

``socket`` parameter
^^^^^^^^^^^^^^^^^^^^

The path to the Unix domain socket, which overrides the compiled-in default.
This may be passed to the remote proxy command (See. `proxy parameter`).

**Example:** ``socket=/opt/libvirt/run/libvirt/libvirt-sock``

``netcat`` parameter
^^^^^^^^^^^^^^^^^^^^
The name of the netcat command on the remote machine. The default is ``nc``.
This is not permitted when using the ``native`` proxy mode.

The command used here is used on the remote side of the connection as:

  ``netcat -U socket``

**Example:** ``netcat=/opt/netcat/bin/nc``

``keyfile`` parameter
^^^^^^^^^^^^^^^^^^^^^

The name of the private key file to use to authentication to the remote
machine. If this option is not used the default keys are used.

**Example:** ``keyfile=/root/.ssh/example_key``
