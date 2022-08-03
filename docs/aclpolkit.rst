.. role:: since

=====================
Polkit access control
=====================

Libvirt's client `access control framework <acl.html>`__ allows
administrators to setup fine grained permission rules across client
users, managed objects and API operations. This allows client
connections to be locked down to a minimal set of privileges. The polkit
driver provides a simple implementation of the access control framework.

.. contents::

Introduction
------------

A default install of libvirt will typically use
`polkit <https://www.freedesktop.org/wiki/Software/polkit/>`__ to
authenticate the initial user connection to libvirtd. This is a very
coarse grained check though, either allowing full read-write access to
all APIs, or just read-only access. The polkit access control driver in
libvirt builds on this capability to allow for fine grained control over
the operations a user may perform on an object.

Permission names
----------------

The libvirt `object names and permission names <acl.html#objects-and-permissions>`__ are
mapped onto polkit action names using the simple pattern:

::

   org.libvirt.api.$object.$permission

The only caveat is that any underscore characters in the object or
permission names are converted to hyphens. So, for example, the
``search_storage_vols`` permission on the ``storage_pool`` object maps
to the polkit action:

::

   org.libvirt.api.storage-pool.search-storage-vols

The default policy for any permission which corresponds to a "read only"
operation, is to allow access. All other permissions default to deny
access.

Object identity attributes
--------------------------

To allow polkit authorization rules to be written to match against
individual object instances, libvirt provides a number of authorization
detail attributes when performing a permission check. The set of
attributes varies according to the type of object being checked

virConnectPtr
~~~~~~~~~~~~~

============== =====================================
Attribute      Description
============== =====================================
connect_driver Name of the libvirt connection driver
============== =====================================

virDomainPtr
~~~~~~~~~~~~

============== ============================================
Attribute      Description
============== ============================================
connect_driver Name of the libvirt connection driver
domain_name    Name of the domain, unique to the local host
domain_uuid    UUID of the domain, globally unique
============== ============================================

virInterfacePtr
~~~~~~~~~~~~~~~

+-------------------+---------------------------------------------------------+
| Attribute         | Description                                             |
+===================+=========================================================+
| connect_driver    | Name of the libvirt connection driver                   |
+-------------------+---------------------------------------------------------+
| interface_name    | Name of the network interface, unique to the local host |
+-------------------+---------------------------------------------------------+
| interface_macaddr | MAC address of the network interface, not unique        |
+-------------------+---------------------------------------------------------+

virNetworkPtr
~~~~~~~~~~~~~

============== =============================================
Attribute      Description
============== =============================================
connect_driver Name of the libvirt connection driver
network_name   Name of the network, unique to the local host
network_uuid   UUID of the network, globally unique
============== =============================================

virNodeDevicePtr
~~~~~~~~~~~~~~~~

================ =================================================
Attribute        Description
================ =================================================
connect_driver   Name of the libvirt connection driver
node_device_name Name of the node device, unique to the local host
================ =================================================

virNWFilterPtr
~~~~~~~~~~~~~~

============== ====================================================
Attribute      Description
============== ====================================================
connect_driver Name of the libvirt connection driver
nwfilter_name  Name of the network filter, unique to the local host
nwfilter_uuid  UUID of the network filter, globally unique
============== ====================================================

virSecretPtr
~~~~~~~~~~~~

=================== ===========================================
Attribute           Description
=================== ===========================================
connect_driver      Name of the libvirt connection driver
secret_uuid         UUID of the secret, globally unique
secret_usage_volume Name of the associated volume, if any
secret_usage_ceph   Name of the associated Ceph server, if any
secret_usage_target Name of the associated iSCSI target, if any
secret_usage_name   Name of the associated TLS secret, if any
=================== ===========================================

virStoragePoolPtr
~~~~~~~~~~~~~~~~~

============== ==================================================
Attribute      Description
============== ==================================================
connect_driver Name of the libvirt connection driver
pool_name      Name of the storage pool, unique to the local host
pool_uuid      UUID of the storage pool, globally unique
============== ==================================================

virStorageVolPtr
~~~~~~~~~~~~~~~~

============== ==================================================
Attribute      Description
============== ==================================================
connect_driver Name of the libvirt connection driver
pool_name      Name of the storage pool, unique to the local host
pool_uuid      UUID of the storage pool, globally unique
vol_name       Name of the storage volume, unique to the pool
vol_key        Key of the storage volume, globally unique
============== ==================================================

Hypervisor Driver connect_driver
--------------------------------

The ``connect_driver`` parameter describes the client's `remote
Connection Driver <remote.html>`__ name based on the `URI <uri.html>`__
used for the connection.

:since:`Since 4.1.0`, when calling an API outside the scope of the primary
connection driver, the primary driver will attempt to open a secondary
connection to the specific API driver in order to process the API. For
example, when hypervisor domain processing needs to make an API call
within the storage driver or the network filter driver an attempt to
open a connection to the "storage" or "nwfilter" driver will be made.
Similarly, a "storage" primary connection may need to create a
connection to the "secret" driver in order to process secrets for the
API. If successful, then calls to those API's will occur in the
``connect_driver`` context of the secondary connection driver rather
than in the context of the primary driver. This affects the
``connect_driver`` returned from rule generation from the
``action.loookup`` function. The following table provides a list of the
various connection drivers and the ``connect_driver`` name used by each
regardless of primary or secondary connection. The access denied error
message from libvirt will list the connection driver by name that denied
the access.

Connection Driver Name
~~~~~~~~~~~~~~~~~~~~~~

================= =======================
Connection Driver ``connect_driver`` name
================= =======================
bhyve             bhyve
esx               ESX
hyperv            Hyper-V
interface         interface
xen               Xen
lxc               LXC
network           network
nodedev           nodedev
nwfilter          NWFilter
openvz            OPENVZ
qemu              QEMU
secret            secret
storage           storage
vbox              VBOX
vmware            VMWARE
vz                vz
================= =======================

User identity attributes
------------------------

At this point in time, the only attribute provided by libvirt to
identify the user invoking the operation is the PID of the client
program. This means that the polkit access control driver is only useful
if connections to libvirt are restricted to its UNIX domain socket. If
connections are being made to a TCP socket, no identifying information
is available and access will be denied. Also note that if the client is
connecting via an SSH tunnel, it is the local SSH user that will be
identified. In future versions, it is expected that more information
about the client user will be provided, including the SASL / Kerberos
username and/or x509 distinguished name obtained from the authentication
provider in use.

Writing access control policies
-------------------------------

If using versions of polkit prior to 0.106 then it is only possible to
validate (user, permission) pairs via the ``.pkla`` files. Fully
validation of the (user, permission, object) triple requires the new
JavaScript ``.rules`` support that was introduced in version 0.106. The
latter is what will be described here.

Libvirt does not ship any rules files by default. It merely provides a
definition of the default behaviour for each action (permission). As
noted earlier, permissions which correspond to read-only operations in
libvirt will be allowed to all users by default; everything else is
denied by default. Defining custom rules requires creation of a file in
the ``/etc/polkit-1/rules.d`` directory with a name chosen by the
administrator (``100-libvirt-acl.rules`` would be a reasonable choice).
See the ``polkit(8)`` manual page for a description of how to write
these files in general. The key idea is to create a file containing
something like

::

   polkit.addRule(function(action, subject) {
     ....logic to check 'action' and 'subject'...
   });

In this code snippet above, the ``action`` object instance will
represent the libvirt permission being checked along with identifying
attributes for the object it is being applied to. The ``subject``
meanwhile will identify the libvirt client app (with the caveat above
about it only dealing with local clients connected via the UNIX socket).
On the ``action`` object, the permission name is accessible via the
``id`` attribute, while the object identifying attributes are exposed
via the ``lookup`` method.

See `source
code <https://gitlab.com/libvirt/libvirt/-/tree/master/examples/polkit>`__
for a more complex example.

Example: restricting ability to connect to drivers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Consider a local user ``berrange`` who has been granted permission to
connect to libvirt in full read-write mode. The goal is to only allow
them to use the ``QEMU`` driver and not the Xen or LXC drivers which are
also available in libvirtd. To achieve this we need to write a rule
which checks whether the ``connect_driver`` attribute is ``QEMU``, and
match on an action name of ``org.libvirt.api.connect.getattr``. Using
the javascript rules format, this ends up written as

::

   polkit.addRule(function(action, subject) {
       if (action.id == "org.libvirt.api.connect.getattr" &&
           subject.user == "berrange") {
             if (action.lookup("connect_driver") == 'QEMU') {
               return polkit.Result.YES;
             } else {
               return polkit.Result.NO;
             }
       }
   });

Example: restricting access to a single domain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Consider a local user ``berrange`` who has been granted permission to
connect to libvirt in full read-write mode. The goal is to only allow
them to see the domain called ``demo`` on the LXC driver. To achieve
this we need to write a rule which checks whether the ``connect_driver``
attribute is ``LXC`` and the ``domain_name`` attribute is ``demo``, and
match on an action name of ``org.libvirt.api.domain.getattr``. Using the
javascript rules format, this ends up written as

::

   polkit.addRule(function(action, subject) {
       if (action.id == "org.libvirt.api.domain.getattr" &&
           subject.user == "berrange") {
             if (action.lookup("connect_driver") == 'LXC' &&
                 action.lookup("domain_name") == 'demo') {
               return polkit.Result.YES;
             } else {
               return polkit.Result.NO;
             }
       }
   });
