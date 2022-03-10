==================
Test "mock" driver
==================

The libvirt ``test`` driver is a per-process fake hypervisor driver.

Connections to Test driver
--------------------------

The driver maintains all its state in memory. It can start with
a pre-configured default config, or be given a path to an alternate config. Some
example connection URIs for the libvirt driver are:

::

   test:///default                     (local access, default config)
   test:///path/to/driver/config.xml   (local access, custom config)
   test+unix:///default                (local access, default config, via daemon)
   test://example.com/default          (remote access, TLS/x509)
   test+tcp://example.com/default      (remote access, SASl/Kerberos)
   test+ssh://root@example.com/default (remote access, SSH tunnelled)
