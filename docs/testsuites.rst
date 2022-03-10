===========
Test suites
===========

There is a few test suites available to developers for testing a given version
of libvirt:

-  the internal test suite: present in the source code, it is run by developers
   before submitting patches upstream, it is also suggested to have it run and
   pass as part of the packaging process for distributions. It is run by
   launching:

   ::

      make check (libvirt 6.6.0 and older)

   ::

      ninja test (libvirt 6.7.0 and newer)

   in a source tree after compilation has finished. It doesn't really make
   functional testing but checks that large portions of the code not interacting
   directly with virtualization functions properly.

-  the `TCK test suite <testtck.html>`__ is a functional test suite implemented
   using the `Perl bindings <https://search.cpan.org/dist/Sys-Virt/>`__ of
   libvirt. It is available separately as a
   `download <ftp://libvirt.org/libvirt/tck/>`__, as a
   `package <https://rpmfind.net/linux/rpm2html/search.php?query=libvirt-tck>`__
   in Fedora distributions, but best is probably to get the `version from
   GIT <https://gitlab.com/libvirt/libvirt-tck>`__.

-  the `libvirt-test-API <testapi.html>`__ is also a functional test suite, but
   implemented using the `Python bindings <python.html>`__ of libvirt. It is
   available separately as a
   `download <ftp://libvirt.org/libvirt/libvirt-test-API/>`__, or directly get
   the `version from GIT <https://gitlab.com/libvirt/libvirt-test-API/>`__.
