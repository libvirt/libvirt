===================================
Microsoft Hyper-V hypervisor driver
===================================

.. contents::

The libvirt Microsoft Hyper-V driver can manage Hyper-V 2012 R2 and newer.

Project Links
-------------

-  The `Microsoft Hyper-V <https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-on-windows-server>`__
   hypervisor

Connections to the Microsoft Hyper-V driver
-------------------------------------------

Some example remote connection URIs for the driver are:

::

   hyperv://example-hyperv.com                  (over HTTPS)
   hyperv://example-hyperv.com/?transport=http  (over HTTP)

**Note**: In contrast to other drivers, the Hyper-V driver is a client-side-only
driver. It connects to the Hyper-V server using WS-Management over HTTP(S).
Therefore, the `remote transport mechanism <remote.html>`__ provided by the
remote driver and libvirtd will not work, and you cannot use URIs like
``hyperv+ssh://example.com``.

URI Format
~~~~~~~~~~

URIs have this general form (``[...]`` marks an optional part).

::

   hyperv://[username@]hostname[:port]/[?extraparameters]

The default HTTPS ports is 5986. If the port parameter is given, it overrides
the default port.

Extra parameters
^^^^^^^^^^^^^^^^

Extra parameters can be added to a URI as part of the query string (the part
following ``?``). A single parameter is formed by a ``name=value`` pair.
Multiple parameters are separated by ``&``.

::

   ?transport=http

The driver understands the extra parameters shown below.

+---------------+-----------------------+-------------------------------------+
| Name          | Values                | Meaning                             |
+===============+=======================+=====================================+
| ``transport`` | ``http`` or ``https`` | Overrides the default HTTPS         |
|               |                       | transport. The default HTTP port is |
|               |                       | 5985.                               |
+---------------+-----------------------+-------------------------------------+

Authentication
~~~~~~~~~~~~~~

In order to perform any useful operation the driver needs to log into the
Hyper-V server. Therefore, only ``virConnectOpenAuth`` can be used to connect to
an Hyper-V server, ``virConnectOpen`` and ``virConnectOpenReadOnly`` don't work.
To log into an Hyper-V server the driver will request credentials using the
callback passed to the ``virConnectOpenAuth`` function. The driver passes the
hostname as challenge parameter to the callback.

**Note**: Currently only ``Basic`` authentication is supported by libvirt. This
method is disabled by default on the Hyper-V server and can be enabled via the
WinRM commandline tool.

::

   winrm set winrm/config/service/auth @{Basic="true"}

To allow ``Basic`` authentication with HTTP transport WinRM needs to allow
unencrypted communication. This can be enabled via the WinRM commandline tool.
However, this is not the recommended communication mode.

::

   winrm set winrm/config/service @{AllowUnencrypted="true"}

Version Numbers
---------------

Since Microsoft's build numbers are almost always over 1000, this driver needs
to pack the value differently compared to the format defined by
``virConnectGetVersion``. To preserve all of the digits, the following format is
used:

::

   major * 100000000 + minor * 1000000 + micro

This results in ``virsh version`` producing unexpected output.

.. list-table::
   :header-rows: 1

   * - Windows Release
     - Kernel Version
     - libvirt Representation

   * - Windows Server 2012 R2
     - 6.3.9600
     - 603.9.600

   * - Windows Server 2016
     - 10.0.14393
     - 1000.14.393

   * - Windows Server 2019
     - 10.0.17763
     - 1000.17.763
