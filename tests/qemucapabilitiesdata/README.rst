=========================
QEMU capabilities testing
=========================

Purpose
=======

Test data in this directory is used:

 - to excercise the capability parsing code in ``qemucapabilitiestest``

 - provides "real" capabilities data for test suites such as ``domaincapstest``
   ``qemuxml2argvtest``, ``qemuxml2xmltest``, and others

 - provides the required data to validate the QMP commands used by libvirt
   against qemu's QMP schema

Naming
======

Files in this directory have the following naming scheme::

  caps_$QEMUVERSION_$ARCHITECTURE.$SUFFIX

or::

  caps_$QEMUVERSION_$ARCHITECTURE+$VARIANT.$SUFFIX

``$QEMUVERSION``

  Numeric representation of the qemu version, e.g.: ``7.0.0``

``$ARCHITECTURE``

  Architecture string such as ``x86_64``, ``aarch64``, etc.

``$SUFFIX``

  ``.replies`` for the dump of the QMP communication used to probe qemu.
  ``.xml`` for the generated capability dump

``$VARIANT``

  The variant name is an optional arbitrary string, not containing any dot.

  A variant is an additional named version of capabilities for given version and
  architecture tuple. This allows for testing special cases which e.g. depend
  on a specific host platform or operating system feature, which differs from
  the main tests. Note that in the test code the variant name is an empty string
  or includes the '+' sign for ease of use.

Known test variants
-------------------

``+hvf``

  Variant of the test data using the Apple OSX Hypervisor Framework acceleration
  for qemu.


Usage in tests
==============

Test suites such as ``qemucapabilitiestest`` or ``domaincapstest`` pick up the
test data automatically once the corresponding ``.xml`` or ``.replies`` file
is present in ``tests/qemucapabilitiesdata``.

Other test suites such as ``qemuxml2argvtest`` provide macros which invoke test
cases using this data such as ``DO_TEST_CAPS_LATEST``.

Capturing QEMU capabilities
===========================

QEMU capabilities are captured by running the ``qemucapsprobe`` on the QEMU
binary on given architecture and then capturing the output. Since virtualization
acceleration is also probed it's required to run it on real hardware.

The capabilities dumps contain also host-specific information such as the exact
CPU definition of the machine where it was ran on, thus they can differ
significantly when run on other machines.

Probing QEMU
------------

Run the ``qemucapsprobe`` tool::

  $ LIBVIRT_BUILDDIR/tests/qemucapsprobe /path/to/qemu > output.replies

The tool spawns the qemu binary and performs probing as if libvirt would do that.
The QMP conversation between qemu and libvirt is dumped to stdout. User
running the probe must be able to access the virtualization accelerator (e.g.
have proper permissions on ``/dev/kvm``)

Generating the output files
---------------------------

Place the captured output ``.replies`` file into this directory and run::

  $ VIR_TEST_REGENERATE_OUTPUT=1 ninja test

This runs the test-suite instructing it to update and/or generate all new data
the test would normally expect.

Manual modifications the ``.replies`` file
==========================================

In certain cases it's impractical or impossible to re-generate the ``.replies``
file on a code change causing a change to the actual QMP query process.

In such case a careful manual modification of the ``.replies`` is tolerated.

To aid such modification the tool ``tests/qemucapabilitiesnumbering`` can be
used.

The tool validates and updates the numbering of the entries in the QMP dump in
case something was modified.

The tool also allows programatic modification of the ``.replies`` file.

See ``tests/qemucapabilitiesnumbering.c``.
