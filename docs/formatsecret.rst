.. role:: since

=================
Secret XML format
=================

.. contents::

Secret XML
----------

Secrets stored by libvirt may have attributes associated with them, using the
``secret`` element. The ``secret`` element has two optional attributes, each
with values '``yes``' and '``no``', and defaulting to '``no``':

``ephemeral``
   This secret must only be kept in memory, never stored persistently.
``private``
   The value of the secret must not be revealed to any caller of libvirt, nor to
   any other node.

The top-level ``secret`` element may contain the following elements:

``uuid``
   An unique identifier for this secret (not necessarily in the UUID format). If
   omitted when defining a new secret, a random UUID is generated.
``description``
   A human-readable description of the purpose of the secret.
``usage``
   Specifies what this secret is used for. A mandatory ``type`` attribute
   specifies the usage category, currently only ``volume``, ``ceph``, ``iscsi``,
   ``tls``, and ``vtpm`` are defined. Specific usage categories are described
   below.

Usage type "volume"
~~~~~~~~~~~~~~~~~~~

This secret is associated with a volume, whether the format is either for a
"luks" encrypted volume. Each volume will have a unique secret associated with
it and it is safe to delete the secret after the volume is deleted. The
``<usage type='volume'>`` element must contain a single ``volume`` element that
specifies the path of the volume this secret is associated with. For example,
create a volume-secret.xml file as follows:

::

   <secret ephemeral='no' private='yes'>
      <description>Super secret name of my first puppy</description>
      <uuid>0a81f5b2-8403-7b23-c8d6-21ccc2f80d6f</uuid>
      <usage type='volume'>
         <volume>/var/lib/libvirt/images/puppyname.img</volume>
      </usage>
   </secret>

Define the secret and set the passphrase as follows:

::

   # virsh secret-define volume-secret.xml
   Secret 0a81f5b2-8403-7b23-c8d6-21ccc2f80d6f created

See `Setting secret values in virsh`_ on how to set the value of the secret
using ``virsh secret-set-value``.

The volume type secret can be supplied either in volume XML during creation of a
`storage volume <formatstorage.html#storage-volume-xml>`__ in order to provide
the passphrase to encrypt the volume or in domain XML
`disk device <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ in order to provide the
passphrase to decrypt the volume, :since:`since 2.1.0` . An example follows:

::

   # cat luks-secret.xml
   <secret ephemeral='no' private='yes'>
      <description>LUKS Sample Secret</description>
      <uuid>f52a81b2-424e-490c-823d-6bd4235bc57</uuid>
      <usage type='volume'>
         <volume>/var/lib/libvirt/images/luks-sample.img</volume>
      </usage>
   </secret>

   # virsh secret-define luks-secret.xml
   Secret f52a81b2-424e-490c-823d-6bd4235bc57 created

See `Setting secret values in virsh`_ on how to set the value of the secret
using ``virsh secret-set-value``.

The volume type secret can be supplied in domain XML for a luks storage volume
`encryption <formatstorageencryption.html>`__ as follows:

::

   <encryption format='luks'>
     <secret type='passphrase' uuid='f52a81b2-424e-490c-823d-6bd4235bc57'/>
   </encryption>

Usage type "ceph"
~~~~~~~~~~~~~~~~~

This secret is associated with a Ceph RBD (rados block device). The
``<usage type='ceph'>`` element must contain a single ``name`` element that
specifies a usage name for the secret. The Ceph secret can then be used by UUID
or by this usage name via the ``<auth>`` element of a `disk
device <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ or a `storage pool
(rbd) <formatstorage.html>`__. :since:`Since 0.9.7` . The following is an
example of the steps to be taken. First create a ceph-secret.xml file:

::

   <secret ephemeral='no' private='yes'>
      <description>CEPH passphrase example</description>
      <usage type='ceph'>
         <name>ceph_example</name>
      </usage>
   </secret>

Next, use ``virsh secret-define ceph-secret.xml`` to define the secret and
``virsh secret-set-value`` using the generated UUID value and a base64 generated
secret value in order to define the chosen secret pass phrase.

::

   # virsh secret-define ceph-secret.xml
   Secret 1b40a534-8301-45d5-b1aa-11894ebb1735 created
   #
   # virsh secret-list
    UUID                                 Usage
   -----------------------------------------------------------
    1b40a534-8301-45d5-b1aa-11894ebb1735 cephx ceph_example

See `Setting secret values in virsh`_ on how to set the value of the secret
using ``virsh secret-set-value``.

The ceph secret can then be used by UUID or by the usage name via the ``<auth>``
element in a domain's `<disk> <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ element as
follows:

::

   <auth username='myname'>
     <secret type='ceph' usage='ceph_example'/>
   </auth>

As well as the ``<auth>`` element in a `storage pool
(rbd) <formatstorage.html>`__ ``<source>`` element as follows:

::

   <auth type='ceph' username='myname'>
     <secret usage='ceph_example'/>
   </auth>

Usage type "iscsi"
~~~~~~~~~~~~~~~~~~

This secret is associated with an iSCSI target for CHAP authentication. The
``<usage type='iscsi'>`` element must contain a single ``target`` element that
specifies a usage name for the secret. The iSCSI secret can then be used by UUID
or by this usage name via the ``<auth>`` element of a `disk
device <formatdomain.html#hard-drives-floppy-disks-cdroms>`__ or a `storage pool
(iscsi) <formatstorage.html>`__. :since:`Since 1.0.4` . The following is an
example of the XML that may be used to generate a secret for iSCSI CHAP
authentication. Assume the following sample entry in an iSCSI authentication
file:

::

   <target iqn.2013-07.com.example:iscsi-pool>
   backing-store /home/tgtd/iscsi-pool/disk1
   backing-store /home/tgtd/iscsi-pool/disk2
   incominguser myname mysecret
   </target>

Define an iscsi-secret.xml file to describe the secret. Use the ``incominguser``
username used in your iSCSI authentication configuration file as the value for
the ``username`` attribute. The ``description`` attribute should contain
configuration specific data. The ``target`` name may be any name of your
choosing to be used as the ``usage`` when used in the pool or disk XML
description.

::

   <secret ephemeral='no' private='yes'>
      <description>Passphrase for the iSCSI example.com server</description>
      <usage type='iscsi'>
         <target>libvirtiscsi</target>
      </usage>
   </secret>

Next, use ``virsh secret-define iscsi-secret.xml`` to define the secret and
``virsh secret-set-value`` using the generated UUID value and a base64 generated
secret value in order to define the chosen secret pass phrase. The pass phrase
must match the password used in the iSCSI authentication configuration file.

::

   # virsh secret-define secret.xml
   Secret c4dbe20b-b1a3-4ac1-b6e6-2ac97852ebb6 created

   # virsh secret-list
    UUID                                 Usage
   -----------------------------------------------------------
    c4dbe20b-b1a3-4ac1-b6e6-2ac97852ebb6 iscsi libvirtiscsi


See `Setting secret values in virsh`_ on how to set the value of the secret
using ``virsh secret-set-value``.

The iSCSI secret can then be used by UUID or by the usage name via the
``<auth>`` element in a domain's `<disk> <formatdomain.html#hard-drives-floppy-disks-cdroms>`__
element as follows:

::

   <auth username='myname'>
     <secret type='iscsi' usage='libvirtiscsi'/>
   </auth>

As well as the ``<auth>`` element in a `storage pool
(iscsi) <formatstorage.html>`__ ``<source>`` element as follows:

::

   <auth type='chap' username='myname'>
     <secret usage='libvirtiscsi'/>
   </auth>

Usage type "tls"
~~~~~~~~~~~~~~~~

This secret may be used in order to provide the passphrase for the private key
used to provide TLS credentials. The ``<usage type='tls'>`` element must contain
a single ``name`` element that specifies a usage name for the secret.
:since:`Since 2.3.0` . The following is an example of the expected XML and
processing to define the secret:

::

   # cat tls-secret.xml
   <secret ephemeral='no' private='yes'>
      <description>sample tls secret</description>
      <usage type='tls'>
         <name>TLS_example</name>
      </usage>
   </secret>

   # virsh secret-define tls-secret.xml
   Secret 718c71bd-67b5-4a2b-87ec-a24e8ca200dc created

   # virsh secret-list
    UUID                                 Usage
   -----------------------------------------------------------
    718c71bd-67b5-4a2b-87ec-a24e8ca200dc  tls TLS_example

A secret may also be defined via the
`virSecretDefineXML <html/libvirt-libvirt-secret.html#virSecretDefineXML>`__
API. Once the secret is defined, a secret value will need to be set. The secret
would be the passphrase used to access the TLS credentials. The following is a
simple example of using ``virsh secret-set-value`` to set the secret value. The
`virSecretSetValue <html/libvirt-libvirt-secret.html#virSecretSetValue>`__ API
may also be used to set a more secure secret without using printable/readable
characters.

Usage type "vtpm"
~~~~~~~~~~~~~~~~~

This secret is associated with a virtualized TPM (vTPM) and serves as a
passphrase for deriving a key from for encrypting the state of the vTPM. The
``<usage type='vtpm'>`` element must contain a single ``name`` element that
specifies a usage name for the secret. The vTPM secret can then be used by UUID
via the ``<encryption>`` element of a `tpm <formatdomain.html#tpm-device>`__
when using an emulator. :since:`Since 5.6.0` . The following is an example of
the steps to be taken. First create a vtpm-secret.xml file:

::

   # cat vtpm-secret.xml
   <secret ephemeral='no' private='yes'>
      <description>sample vTPM secret</description>
      <usage type='vtpm'>
         <name>VTPM_example</name>
      </usage>
   </secret>

   # virsh secret-define vtpm-secret.xml
   Secret 6dd3e4a5-1d76-44ce-961f-f119f5aad935 created

   # virsh secret-list
    UUID                                   Usage
   ----------------------------------------------------------------------------------------
    6dd3e4a5-1d76-44ce-961f-f119f5aad935   vtpm VTPM_example

A secret may also be defined via the
`virSecretDefineXML <html/libvirt-libvirt-secret.html#virSecretDefineXML>`__
API. Once the secret is defined, a secret value will need to be set. The secret
would be the passphrase used to decrypt the vTPM state. The following is a
simple example of using ``virsh secret-set-value`` to set the secret value. The
`virSecretSetValue <html/libvirt-libvirt-secret.html#virSecretSetValue>`__ API
may also be used to set a more secure secret without using printable/readable
characters.

Setting secret values in virsh
------------------------------

To set the value of the secret you can use the following virsh commands. If the
secret is a password-like string (printable characters, no newline) you can use:

::

   # virsh secret-set-value --interactive 6dd3e4a5-1d76-44ce-961f-f119f5aad935
   Enter new value for secret:
   Secret value set

Another secure option is to read the secret from a file. This way the secret can
contain any bytes (even NUL and non-printable characters). The length of the
secret is the length of the input file. Alternatively the ``--plain`` option can
be omitted if the file contents are base64-encoded.

::

   # virsh secret-set-value 6dd3e4a5-1d76-44ce-961f-f119f5aad935 --file --plain secretinfile
   Secret value set

**WARNING** The following approach is **insecure** and deprecated. The secret
can also be set via an argument. Note that other users may see the actual secret
in the process listing! The secret must be base64 encoded.

::

   # MYSECRET=`printf %s "open sesame" | base64`
   # virsh secret-set-value 6dd3e4a5-1d76-44ce-961f-f119f5aad935 $MYSECRET
   Secret value set
