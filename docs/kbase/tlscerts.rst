==========================
TLS x509 certificate setup
==========================

.. contents::

Public Key Infrastructure set up
--------------------------------

If you are unsure how to create TLS certificates, skip to the next section.

.. list-table::
   :header-rows: 1

   * - Location
     - Machine
     - Description
     - Required fields

   * - ``/etc/pki/CA/cacert.pem``
     - Installed on the client and server
     - CA's certificate
     - n/a

   * - ``$HOME/.pki/cacert.pem``
     - Installed on the client
     - CA's certificate
     - n/a

   * - ``/etc/pki/libvirt/private/serverkey.pem``
     - Installed on the server
     - Server's private key
     - n/a

   * - ``/etc/pki/libvirt/servercert.pem``
     - Installed on the server
     - Server's certificate signed by the CA
     - CommonName (CN) must be the hostname of the server as it is seen by
       clients. All hostname and IP address variants that might be used to
       reach the server should be listed in Subject Alt Name fields.

   * - ``/etc/pki/libvirt/private/clientkey.pem``
     - Installed on the client
     - Client's private key
     - n/a

   * - ``/etc/pki/libvirt/clientcert.pem``
     - Installed on the client
     - Client's certificate signed by the CA
     - Distinguished Name (DN) can be checked against an access control list
       (``tls_allowed_dn_list``).

   * - ``$HOME/.pki/libvirt/clientkey.pem``
     - Installed on the client
     - Client's private key
     - n/a

   * - ``$HOME/.pki/libvirt/clientcert.pem``
     - Installed on the client
     - Client's certificate signed by the CA
       (see `Issuing client certificates`_)
     - Distinguished Name (DN) can be checked against an access control list
       (``tls_allowed_dn_list``).

If 'pkipath' is specified in URI, then all the client certificates must be found
in the path specified, otherwise the connection will fail with a fatal error. If
'pkipath' is not specified:

-  For a non-root user, libvirt tries to find the certificates in
   $HOME/.pki/libvirt first. If the required CA certificate cannot be found,
   then the global default location (/etc/pki/CA/cacert.pem) will be used.
   Likewise, if either the client certificate or the client key cannot be found,
   then the global default locations (/etc/pki/libvirt/clientcert.pem,
   /etc/pki/libvirt/private/clientkey.pem) will be used.

-  For the root user, the global default locations will always be used.

Multiple parallel certificate identities
----------------------------------------

Any scenario that requires a certificate identify (``servercert.pem`` /
``serverkey.pem`` and ``clientcert.pem`` / ``clientkey.pem``) can optionally
provide multiple parallel identities via a new indexed file naming
scheme. The new filenames are ``servercertNN.pem`` / ``serverkeyNN.pem``
and ``clientcertNN.pem`` / ``clientkeyNN.pem``, for values of ``NN`` between
0 and 3 inclusive.

The new naming can be used instead of the old naming, or concurrently
with the old naming. The old file names will be loaded first (if
present), followed by the indexed file names. Loading will stop at
the first missing index value. ie if ``servercert1.pem`` is not present,
then no attempt will be made to load ``servercert2.pem`` or ``servercert3.pem``.

If multiple CA certificates are required they must all be concatenated
into the single ``cacert.pem`` file.

Background to TLS certificates
------------------------------

Libvirt supports TLS certificates for verifying the identity of the server and
clients. There are two distinct checks involved:

-  The client should know that it is connecting to the right server. Checking
   done by client by matching the certificate that the server sends to the
   server's hostname. May be disabled by adding ``?no_verify=1`` to the `remote
   URI <../uri.html#tls-transport>`__.

-  The server should know that only permitted clients are connecting. This can
   be done based on client's IP address, or on client's IP address and client's
   certificate. Checking done by the server. May be enabled and disabled in the
   `libvirtd.conf file <../remote.html#libvirtd-configuration-file>`__.

For full certificate checking you will need to have certificates issued by a
recognised `Certificate Authority
(CA) <https://en.wikipedia.org/wiki/Certificate_authority>`__ for your server(s)
and all clients. To avoid the expense of getting certificates from a commercial
CA, you can set up your own CA and tell your server(s) and clients to trust
certificates issues by your own CA. Follow the instructions in the next section.

Be aware that the `default configuration for
libvirtd <../remote.html#libvirtd-configuration-file>`__ allows any client to
connect provided they have a valid certificate issued by the CA for their own IP
address. You may want to change this to make it less (or more) permissive,
depending on your needs.

The following sections will describe how to created the data needed for the TLS
setup. They use templates to create Certificate Authority, server and client
certificates.

Important: versions of libvirt before 11.6.0 also required the ``encryption_key``
flag in the server and client template. This is no longer mandated since it is
not applicable for use with many modern cryptographic algorithms, but it is
harmless if present as it will be ignored. If compatibility with both old and
new libvirt versions is required, then this extra flag must be added when
creating the certificate.


Setting up a Certificate Authority (CA)
---------------------------------------

You will need the `GnuTLS certtool program documented
here <https://www.gnutls.org/manual/html_node/certtool-Invocation.html>`__. In
Fedora, it is in the ``gnutls-utils`` package.

Create a private key for your CA:

::

   certtool --generate-privkey > cakey.pem

and self-sign it by creating a file with the signature details called
``ca.info`` containing:

::

   cn = Name of your organization
   ca
   cert_signing_key

::

   certtool --generate-self-signed --load-privkey cakey.pem \
     --template ca.info --outfile cacert.pem

(You can delete ``ca.info`` file now if you want).

Now you have two files which matter:

-  ``cakey.pem`` - Your CA's private key (keep this very secret!)

-  ``cacert.pem`` - Your CA's certificate (this is public).

``cacert.pem`` has to be installed on clients and server(s) to let them know
that they can trust certificates issued by your CA.

The normal installation directory for ``cacert.pem`` is
``/etc/pki/CA/cacert.pem`` on all clients and servers.

To see the contents of this file, do:

::

   certtool -i --infile cacert.pem

   X.509 certificate info:

   Version: 3
   Serial Number (hex): 00
   Subject: CN=Libvirt Project
   Issuer: CN=Libvirt Project
   Signature Algorithm: RSA-SHA
   Validity:
           Not Before: Mon Jun 18 16:22:18 2007
           Not After: Tue Jun 17 16:22:18 2008
   [etc]

This is all that is required to set up your CA. Keep the CA's private key
carefully as you will need it when you come to issue certificates for your
clients and servers.

Issuing server certificates
---------------------------

For each server (libvirtd) you need to issue a certificate containing one or
more hostnames and/or IP addresses. Historically the CommonName (CN) field would
contain the hostname of the server and would match the hostname used in the URI
that clients pass to libvirt. In most TLS implementations the CN field is
considered legacy data. The preferential mechanism is to use Subject Alt Name
(SAN) extension fields to validate against. In the future use of the CN field
for validation may be discontinued entirely, so it is strongly recommended to
include the SAN fields.

In the example below, clients will be connecting to the server using a
`URI <../uri.html#remote-uris>`__ of ``qemu://compute1.libvirt.org/system``, so the
CN must be "``compute1.libvirt.org``".

Make a private key for the server:

::

   certtool --generate-privkey > serverkey.pem

and sign that key with the CA's private key by first creating a template file
called ``server.info``. The template file will contain a number of fields to
define the server as follows:

::

   organization = Name of your organization
   cn = compute1.libvirt.org
   dns_name = compute1
   dns_name = compute1.libvirt.org
   ip_address = 10.0.0.74
   ip_address = 192.168.1.24
   ip_address = 2001:cafe::74
   ip_address = fe20::24
   tls_www_server
   signing_key

The 'cn' field should refer to the fully qualified public hostname of the
server. For the SAN extension data, there must also be one or more 'dns_name'
fields that contain all possible hostnames that can be reasonably used by
clients to reach the server, both with and without domain name qualifiers. If
clients are likely to connect to the server by IP address, then one or more
'ip_address' fields should also be added.

Use the template file as input to a ``certtool`` command to sign the server
certificate:

::

   certtool --generate-certificate --load-privkey serverkey.pem \
     --load-ca-certificate cacert.pem --load-ca-privkey cakey.pem \
     --template server.info --outfile servercert.pem

This gives two files:

-  ``serverkey.pem`` - The server's private key.

-  ``servercert.pem`` - The server's public key.

We can examine this certificate and its signature:

::

   certtool -i --infile servercert.pem
   X.509 certificate info:

   Version: 3
   Serial Number (hex): 00
   Subject: O=Libvirt Project,CN=compute1.libvirt.org
   Issuer: CN=Libvirt Project
   Signature Algorithm: RSA-SHA
   Validity:
           Not Before: Wed Oct 04 09:09:44 UTC 2017
           Not After: Thu Oct 04 09:09:44 UTC 2018
   Extensions:
           Basic Constraints (critical):
                   Certificate Authority (CA): FALSE
           Subject Alternative Name (not critical):
                   DNSname: compute1
                   DNSname: compute1.libvirt.org
                   IPAddress: 10.0.0.74
                   IPAddress: 192.168.1.24
                   IPAddress: 2001:cafe::74
                   IPAddress: fe20::24

Note the "Issuer" CN is "Libvirt Project" (the CA) and the "Subject" CN is
"compute1.libvirt.org" (the server). Notice that the hostname listed in the CN
must also be duplicated as a DNSname entry

Finally we have two files to install:

-  ``serverkey.pem`` is the server's private key which should be copied to the
   server *only* as ``/etc/pki/libvirt/private/serverkey.pem``.

-  ``servercert.pem`` is the server's certificate which can be installed on the
   server as ``/etc/pki/libvirt/servercert.pem``.

Issuing client certificates
---------------------------

For each client (ie. any program linked with libvirt, such as
`virt-manager <https://virt-manager.org/>`__) you need to issue a certificate
with the X.509 Distinguished Name (DN) set to a suitable name. You can decide
this on a company / organisation policy. For example:

::

   C=GB,ST=London,L=London,O=Libvirt Project,CN=name_of_client

The process is the same as for `Issuing server certificates`_ so here we just
briefly cover the steps.

#. Make a private key:

   ::

      certtool --generate-privkey > clientkey.pem

#. Act as CA and sign the certificate. Create client.info containing:

   ::

      country = GB
      state = London
      locality = London
      organization = Libvirt Project
      cn = client1
      tls_www_client
      signing_key

   and sign by doing:

   ::

      certtool --generate-certificate --load-privkey clientkey.pem \
        --load-ca-certificate cacert.pem --load-ca-privkey cakey.pem \
        --template client.info --outfile clientcert.pem

#. Install the certificates on the client machine:

   ::

      cp clientkey.pem /etc/pki/libvirt/private/clientkey.pem
      cp clientcert.pem /etc/pki/libvirt/clientcert.pem

Configuring for Post-Quantum Cryptography
-----------------------------------------

Given a new enough gnutls release, suitably integrated & configured with the
operating system crypto policies, libvirt is able to support post-quantum
crytography on TLS enabled services, either exclusively or in a hybrid mode.

In exclusive mode, only a single set of certificates need to be configured
for libvirt, with PQC compliant algorithms. Such a libvirt configuration will
only be able to interoperate with other libvirt daemons that also have PQC
enabled. This can result in compatibility concerns during the period of
transition over to PQC compliant algorithms.

In hybrid mode, multiple sets of certificates need to be configured for libvirt,
at least one set with traditional (non-PQC compliant) algorithms, and at least
one other set with modern (PQC compliant) algorithms. At time of the TLS
handshake, the GNUTLS algorithm priorities should ensure that PQC compliant
algorithms are negotiated if both sides of the connection support PQC. If one
side lacks PQC, the TLS handshake should fallback to the non-PQC algorithms.
This can assist with interoperability during the transition to PQC, but has a
potential weakness wrt downgrade attacks forcing use of non-PQC algorithms.
Exclusive PQC mode should be preferred where both peers in the TLS connections
are known to support PQC.

Key generation parameters
^^^^^^^^^^^^^^^^^^^^^^^^^

To create certificates with PQC compliant algorithms, the ``--key-type``
argument must be passed to ``certtool`` when creating private keys. No
extra arguments are required for the other ``certtool`` commands, as
their behaviour will be determined by the private key type.

The typical PQC compliant algorithms to use are ``ML-DSA-44``, ``ML-DSA-65``
and ``ML-DSA-87``, with ``ML-DSA-65`` being a suitable default choice in
the absence of explicit requirements.

Taking the example earlier, for creating a key for a client certificate,
to use ``ML-DSA-65`` the command line would be modified to look like::

   # certtool --generate-privkey --key-type=mldsa65 > clientkey.pem

The equivalent modification applies to the creation of the private keys
used for server certs, or root/intermediate CA certs.

For hybrid mode, the additional indexed certificate naming must be used.
If multiple configured certificates are compatible with the mutually
supported crypto algorithms between the client and server, then the
first matching certificate will be used.

IOW, to ensure that PQC certificates are preferred, they must use a
non-index based filename, or use an index that is smaller than any
non-PQC certificates. ie, ``servercert.pem`` for PQC and ``servercert0.pem``
for non-PQC, or ``servercert0.pem`` for PQC and ``servercert1.pem`` for
non-PQC.

Force disabling PQC via crypto priority
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the OS configuration for system crypto algorithm priorities has
enabled PQC, this can (optionally) be overriden in libvirt server
configuration. To disable use of PQC set the ``tls_priority``
parameter in the ``libvirtd.conf`` / ``virtproxyd.conf`` files:

  tls_priority = "@SYSTEM:-SIGN-ML-DSA-65:-SIGN-ML-DSA-44:-SIGN-ML-DSA-87:-GROUP-X25519-MLKEM768:-GROUP-SECP256R1-MLKEM768:-GROUP-SECP384R1-MLKEM1024"

On the client side this can be overriden using the ``tls_priority``
URI parameter in the libvirt connection address.


Troubleshooting TLS certificate problems
----------------------------------------

* TLS socket

  After setting up your sever certificates you'll have to start libvirt's
  tls socket and restart the corresponding daemon if it was already running,
  i.e.

 * for modular daemon setup run

   ::

       systemctl start virtproxyd-tls.socket
       systemctl try-start virtproxyd.service

 * for monolithic daemon setup run

   ::

       systemctl start libvirtd-tls.socket
       systemctl try-start libvirtd.service


* failed to verify client's certificate

  On the server side, run the libvirtd server with the '--listen' and
  '--verbose' options while the client is connecting. The verbose log messages
  should tell you enough to diagnose the problem.

You can use the virt-pki-validate shell script to analyze the setup on the
client or server machines, preferably as root. It will try to point out the
possible problems and provide solutions to fix the set up up to a point where
you have secure remote access.
