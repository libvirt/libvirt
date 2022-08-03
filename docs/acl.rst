=====================
Client access control
=====================

Libvirt's client access control framework allows administrators to setup fine
grained permission rules across client users, managed objects and API
operations. This allows client connections to be locked down to a minimal set of
privileges.

.. contents::

Access control introduction
---------------------------

In a default configuration, the libvirtd daemon has three levels of access
control. All connections start off in an unauthenticated state, where the only
API operations allowed are those required to complete authentication. After
successful authentication, a connection either has full, unrestricted access to
all libvirt API calls, or is locked down to only "read only" (see 'Anonymous' in
the table below) operations, according to what socket a client connection
originated on.

The access control framework allows authenticated connections to have fine
grained permission rules to be defined by the administrator. Every API call in
libvirt has a set of permissions that will be validated against the object being
used. For example, the ``virDomainSetSchedulerParametersFlags`` method will
check whether the client user has the ``write`` permission on the ``domain``
object instance passed in as a parameter. Further permissions will also be
checked if certain flags are set in the API call. In addition to checks on the
object passed in to an API call, some methods will filter their results. For
example the ``virConnectListAllDomains`` method will check the
``search_domains`` on the ``connect`` object, but will also filter the returned
``domain`` objects to only those on which the client user has the ``getattr``
permission.

Access control drivers
----------------------

The access control framework is designed as a pluggable system to enable future
integration with arbitrary access control technologies. By default, the ``none``
driver is used, which does no access control checks at all. At this time,
libvirt ships with support for using
`polkit <https://www.freedesktop.org/wiki/Software/polkit/>`__ as a real access
control driver. To learn how to use the polkit access driver consult `the
configuration docs <aclpolkit.html>`__.

The access driver is configured in the ``libvirtd.conf`` configuration file,
using the ``access_drivers`` parameter. This parameter accepts an array of
access control driver names. If more than one access driver is requested, then
all must succeed in order for access to be granted. To enable 'polkit' as the
driver:

::

   # augtool -s set '/files/etc/libvirt/libvirtd.conf/access_drivers[1]' polkit

And to reset back to the default (no-op) driver

::

   # augtool -s rm /files/etc/libvirt/libvirtd.conf/access_drivers

**Note:** changes to libvirtd.conf require that the libvirtd daemon be
restarted.

Objects and permissions
-----------------------

Libvirt applies access control to all the main object types in its API. Each
object type, in turn, has a set of permissions defined. To determine what
permissions are checked for specific API call, consult the `API reference
manual <html/index.html>`__ documentation for the API in question.

.. raw:: html

   <div id="include" filename="aclperms.htmlinc"/>
