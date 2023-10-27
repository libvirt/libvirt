=========================================
libvirt-test-API: Python based test suite
=========================================

Libvirt-test-API is a powerful test tool designed to complement existing libvirt
test tools such as libvirt-TCK and the internal test suite. It aims at
functional regression testing, trying to exercise nearly all the API by the way
of the Python bindings.

The test API currently covers:

-  domain: all classical lifetime operations, installation of various guests
   OSes, snapshots
-  interfaces: define, create, destroy, undefine, NPIV
-  virtual networks: define, create, destroy, undefine
-  storage: regression tests for most storage types and configurations dir,
   disk, netfs, iSCSI, multipath

Some of the tests need dedicated local resources whose definitions are stored in
a configuration file. The tests are defined using Python modules defining the
code for the test, this is called a test case, and test configuration files
using one or more test case to define a given test scenario.

For more details you can look at:

-  A `documentation
   PDF <https://download.libvirt.org/libvirt-test-API/Libvirt-test-API.pdf>`__
   file describing the test suite and how to write test cases and test
   scenarios.

Libvirt-test-API is maintained using `a GIT
repository <https://gitlab.com/libvirt/libvirt-test-API>`__, and comment,
patches and reviews are carried on the `devel <contact.html>`__
mailing list.
