==============
Network driver
==============

.. contents::

Platform-specific notes
=======================

FreeBSD
-------

FreeBSD netowork driver uses the pf firewall. Libvirt managed pf rules
are created within anchors. Anchors need to be configured manually by
the user. Sample ``/etc/pf.conf`` might look like:

::

 scrub all

 nat-anchor "libvirt\*"
 anchor "libvirt\*"

 pass all


Users are not expected to manually modify rules in the ``"libvirt\*"``
subanchors because the changes will be lost on restart.
