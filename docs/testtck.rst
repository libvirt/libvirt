==========================================
libvirt TCK : Technology Compatibility Kit
==========================================

.. contents::

The libvirt TCK provides a framework for performing testing of the integration
between libvirt drivers, the underlying virt hypervisor technology, related
operating system services and system configuration. The idea (and name) is
motivated by the Java TCK.

In particular the libvirt TCK is intended to address the following scenarios:

-  Validate that a new libvirt driver is in compliance with the (possibly
   undocumented!) driver API semantics
-  Validate that an update to an existing driver does not change the API
   semantics in a non-compliant manner
-  Validate that a new hypervisor release is still providing compatibility with
   the corresponding libvirt driver usage
-  Validate that an OS distro deployment consisting of a hypervisor and libvirt
   release is configured correctly

Thus the libvirt TCK will allow developers, administrators and users to
determine the level of compatibility of their platform, and evaluate whether it
will meet their needs, and get awareness of any regressions that may have
occurred since a previous test run.

Libvirt-TCK is maintained using `a GIT
repository <https://gitlab.com/libvirt/libvirt-tck>`__. GitLab is also the place
where the whole TCK development workflow (issues, merge requests, comments)
happens.

Using TCK
---------

TCK can be used independently of the environment, i.e. both on your local host
or in a VM. We strongly recommend using a VM for the tests as TCK might affect
your current host setup, see `Running TCK`_.

Installing dependencies
~~~~~~~~~~~~~~~~~~~~~~~

Since TCK is based on libvirt Perl bindings, you'll need to have the proper
version of the bindings installed for the version of libvirt you wish to test
in order to be able execute the TCK test suite successfully. Additionally, a
number of Perl dependencies will need to be installed as well, some will be
available through the system package manager and some will likely need to be
installed from CPAN (Perl's equivalent of Python's PyPI). Here's where
`libvirt-ci's <https://gitlab.com/libvirt/libvirt-ci.git>`__ lcitool can help
with preparing a test environment in a fresh VM, taking care of the
dependencies along the way:

::

    $ lcitool install --target fedora-36 tck-fedora36 --wait

would get you a new Fedora 36 VM named ``tck-fedora36``. Then

::

    $ lcitool update tck-fedora36 libvirt,libvirt-perl,libvirt-tck+runtime

will install all the necessary dependencies to build libvirt, the corresponding
Perl bindings and all TCK runtime dependencies to be able to execute the tests.
We also recommend executing TCK using the Avocado framework as the test harness
engine which means that you'll have to install Avocado in the test environment
as well. You can get it either from
`PyPI <https://pypi.org/project/avocado-framework/>`__ (recommended), or if
you're on Fedora you can make use of the Avocado `module <https://avocado-framework.readthedocs.io/en/latest/guides/user/chapters/installing.html#installing-from-packages>`__.
Using Avocado is not mandatory for the time being and you can skip it, but
in the future we plan on making the TCK internal coupling with Avocado tighter.

Running TCK
~~~~~~~~~~~

Once you have all the dependencies installed, you can then proceed with running
as root the test suite as root (when running with Avocado):

::

    # avocado --config avocado.config run --tap - ./scripts/

from the TCK's git root.


If you don't want to install Avocado you can execute tests using the
``libvirt-tck`` binary directly (again, from the git root). You'll need to pass
a few options that Avocado takes care of:

::

    # PERL5LIB=./lib perl bin/libvirt-tck -c <path_to_config> --force ./scripts

Running with the ``--force`` argument is not necessary and you can safely omit
it, but it becomes useful if you need to interrupt a test run for some
reason. In such case using ``--force`` ensures the first thing TCK does before
running any tests is that it will clean up all resources from the previous test
run which may have been left behind if you had interrupted the previous TCK's
execution.

Note that running with root privileges is necessary since some tests need
access to system resources or configs. This, along with the fact that some
tests might affect the host system are good reasons to consider using a test VM
as described above.

Contributing a test
-------------------

We'd appreciate if you provided a functional test case whenever you're adding a
new feature or fixing a bug in libvirt with the only complication being that
in case you're adding a new public API then a Perl binding will have to be
introduced first. After that, the best way to start is looking at some existing
tests, copy-pasting one that fits your scenario the best and tweak the
remaining bits.
