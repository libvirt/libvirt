=========================
Advanced test suite usage
=========================

The basic requirement before submitting changes to libvirt is that

::

  $ ninja test

succeed after each commit.

The libvirt test suite, however, support additional features: for
example, it's possible to look for memory leaks and similar issues
by running

::

  $ meson test --setup valgrind --suite bin

`Valgrind <https://valgrind.org/>`__ is a test that checks for
memory management issues, such as leaks or use of uninitialized
variables.

Some tests are skipped by default in a development environment,
based on the time they take in comparison to the likelihood
that those tests will turn up problems during incremental
builds. These tests default to being run when building from a
tarball or with the configure option -Dexpensive_tests=enabled.

If you encounter any failing tests, the VIR_TEST_DEBUG
environment variable may provide extra information to debug the
failures. Larger values of VIR_TEST_DEBUG may provide larger
amounts of information:

::

  $ VIR_TEST_DEBUG=1 ninja test    (or)
  $ VIR_TEST_DEBUG=2 ninja test

When debugging failures during development, it is possible to
focus in on just the failing subtests by using VIR_TEST_RANGE.
I.e. to run all tests from 3 to 20 with the exception of tests
6 and 16, use:

::

  $ VIR_TEST_DEBUG=1 VIR_TEST_RANGE=3-5,7-20,^16 ./run tests/qemuxml2argvtest

Also, individual tests can be run from inside the ``tests/``
directory, like:

::

  $ ./qemuxml2xmltest

If you are adding new test cases, or making changes that alter
existing test output, you can use the environment variable
VIR_TEST_REGENERATE_OUTPUT to quickly update the saved test
data. Of course you still need to review the changes VERY
CAREFULLY to ensure they are correct.

::

  $ VIR_TEST_REGENERATE_OUTPUT=1 ./qemuxml2argvtest

There is also a ``./run`` script at the top level, to make it
easier to run programs that have not yet been installed, as
well as to wrap invocations of various tests under gdb or
Valgrind.

When running our test suite it may happen that the test result
is nondeterministic because of the test suite relying on a
particular file in the system being accessible or having some
specific value. To catch this kind of errors, the test suite
has a module for that prints any path touched that fulfils
constraints described above into a file. To enable it just set
``VIR_TEST_FILE_ACCESS`` environment variable. Then
``VIR_TEST_FILE_ACCESS_OUTPUT`` environment variable can alter
location where the file is stored.

::

  $ VIR_TEST_FILE_ACCESS=1 VIR_TEST_FILE_ACCESS_OUTPUT="/tmp/file_access.txt" ./qemuxml2argvtest

#. The Valgrind test should produce similar output to
``ninja test``. If the output has traces within libvirt API's,
then investigation is required in order to determine the cause
of the issue. Output such as the following indicates some sort
of leak:

::

  ==5414== 4 bytes in 1 blocks are definitely lost in loss record 3 of 89
  ==5414==    at 0x4A0881C: malloc (vg_replace_malloc.c:270)
  ==5414==    by 0x34DE0AAB85: xmlStrndup (in /usr/lib64/libxml2.so.2.7.8)
  ==5414==    by 0x4CC97A6: virDomainVideoDefParseXML (domain_conf.c:7410)
  ==5414==    by 0x4CD581D: virDomainDefParseXML (domain_conf.c:10188)
  ==5414==    by 0x4CD8C73: virDomainDefParseNode (domain_conf.c:10640)
  ==5414==    by 0x4CD8DDB: virDomainDefParse (domain_conf.c:10590)
  ==5414==    by 0x41CB1D: testCompareXMLToArgvHelper (qemuxml2argvtest.c:100)
  ==5414==    by 0x41E20F: virtTestRun (testutils.c:161)
  ==5414==    by 0x41C7CB: mymain (qemuxml2argvtest.c:866)
  ==5414==    by 0x41E84A: virtTestMain (testutils.c:723)
  ==5414==    by 0x34D9021734: (below main) (in /usr/lib64/libc-2.15.so)

In this example, the ``virDomainDefParseXML()`` had an error
path where the ``virDomainVideoDef *video`` pointer was not
properly disposed. By simply adding a
``virDomainVideoDefFree(video);`` in the error path, the issue
was resolved.

Another common mistake is calling a printing function, such as
``VIR_DEBUG()`` without initializing a variable to be printed.
The following example involved a call which could return an
error, but not set variables passed by reference to the call.
The solution was to initialize the variables prior to the call.

::

  ==4749== Use of uninitialised value of size 8
  ==4749==    at 0x34D904650B: _itoa_word (in /usr/lib64/libc-2.15.so)
  ==4749==    by 0x34D9049118: vfprintf (in /usr/lib64/libc-2.15.so)
  ==4749==    by 0x34D9108F60: __vasprintf_chk (in /usr/lib64/libc-2.15.so)
  ==4749==    by 0x4CAEEF7: virVasprintf (stdio2.h:199)
  ==4749==    by 0x4C8A55E: virLogVMessage (virlog.c:814)
  ==4749==    by 0x4C8AA96: virLogMessage (virlog.c:751)
  ==4749==    by 0x4DA0056: virNetTLSContextCheckCertKeyUsage (virnettlscontext.c:225)
  ==4749==    by 0x4DA06DB: virNetTLSContextCheckCert (virnettlscontext.c:439)
  ==4749==    by 0x4DA1620: virNetTLSContextNew (virnettlscontext.c:562)
  ==4749==    by 0x4DA26FC: virNetTLSContextNewServer (virnettlscontext.c:927)
  ==4749==    by 0x409C39: testTLSContextInit (virnettlscontexttest.c:467)
  ==4749==    by 0x40AB8F: virtTestRun (testutils.c:161)

Valgrind will also find some false positives or code paths
which cannot be resolved by making changes to the libvirt code.
For these paths, it is possible to add a filter to avoid the
errors. For example:

::

  ==4643== 7 bytes in 1 blocks are possibly lost in loss record 4 of 20
  ==4643==    at 0x4A0881C: malloc (vg_replace_malloc.c:270)
  ==4643==    by 0x34D90853F1: strdup (in /usr/lib64/libc-2.15.so)
  ==4643==    by 0x34EEC2C08A: ??? (in /usr/lib64/libnl.so.1.1)
  ==4643==    by 0x34EEC15B81: ??? (in /usr/lib64/libnl.so.1.1)
  ==4643==    by 0x34D8C0EE15: call_init.part.0 (in /usr/lib64/ld-2.15.so)
  ==4643==    by 0x34D8C0EECF: _dl_init (in /usr/lib64/ld-2.15.so)
  ==4643==    by 0x34D8C01569: ??? (in /usr/lib64/ld-2.15.so)

In this instance, it is acceptable to modify the
``tests/.valgrind.supp`` file in order to add a suppression
filter. The filter should be unique enough to not suppress real
leaks, but it should be generic enough to cover multiple code
paths. The format of the entry can be found in the
documentation found at the `Valgrind home
page <https://valgrind.org/>`__. The following trace was added
to ``tests/.valgrind.supp`` in order to suppress the warning:

::

  {
      dlInitMemoryLeak1
      Memcheck:Leak
      fun:?alloc
      ...
      fun:call_init.part.0
      fun:_dl_init
      ...
      obj:*/lib*/ld-2.*so*
  }
