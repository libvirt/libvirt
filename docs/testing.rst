=======
Testing
=======

.. contents::

Different types of tests are available to libvirt developers for testing a
given libvirt release.

Unit tests
----------

The unit test suite present in the source code is mainly used to test our
XML parser/formatter, QEMU command line generator, QEMU capabilities probing,
etc. It is run by developers before submitting patches upstream and is
mandatory to pass for any contribution to be accepted upstream. One can run
the test suite in the source tree with the following::

    $ ninja test


Container builds
----------------

Technically speaking these are not tests in the common sense. However, usage of
public container images to build libvirt in predefined and widely accessible
environments makes it possible to expand our coverage across distros,
architectures, toolchain flavors and library versions and as such is a very
valuable marker when accepting upstream contributions. Therefore, it is
recommended to run libvirt builds against your changes in various containers to
either locally or by using GitLab's shared CI runners to make sure everything
runs cleanly before submitting your patches. The images themselves come from
libvirt's GitLab container registry, but this can be overridden if needed, see
below.

Registry
~~~~~~~~

Libvirt project has its container registry hosted by GitLab at
``registry.gitlab.com/libvirt/libvirt`` which will automatically be
used to pull in pre-built layers. This avoids the need to build all the
containers locally using the Dockerfile recipes found in ``ci/containers/``.


Running container builds with GitLab CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As long as your GitLab account has CI minutes available, pipelines will run
automatically on every branch push to your fork.

Running container jobs locally
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

GitLab CI configuration file is the only source of truth when it comes to
various job specifications we execute as part of the upstream pipeline.
Luckily, all "script" (i.e. Bash scripts) were extracted to standalone Shell
functions in ``ci/jobs.sh``. This allows users to run any of the container
GitLab job specifications locally by just referencing the job name.

When it comes to actually running the GitLab jobs locally, we have a
``ci/helper`` script that can pull, build, and test (if applicable) changes on
your current local branch. It supports both the Docker and Podman runtimes
with an automatic selection of whichever runtime is configured on your system.
In case neither has been enabled/configured, please go through the following
prerequisites. We recommend using podman because of its daemonless architecture
and security implications (i.e. rootless container execution by default) over
Docker.

Podman Prerequisites
~~~~~~~~~~~~~~~~~~~~

Install "podman" with the system package manager.

.. code::

  $ sudo dnf install -y podman
  $ podman ps

The last command should print an empty table, to verify the system is ready.

Docker Prerequisites
~~~~~~~~~~~~~~~~~~~~

Install "docker" with the system package manager and start the Docker service
on your development machine, then make sure you have the privilege to run
Docker commands. Typically it means setting up passwordless ``sudo docker``
command or login as root. For example:

.. code::

  $ sudo dnf install -y docker
  $ # or `apt-get install docker` for Ubuntu, etc.
  $ sudo systemctl start docker
  $ sudo docker ps

The last command should print an empty table, to verify the system is ready.

An alternative method to set up permissions is by adding the current user to
"docker" group and making the docker daemon socket file (by default
``/var/run/docker.sock``) accessible to the group:

.. code::

  $ sudo groupadd docker
  $ sudo usermod $USER -a -G docker
  $ sudo chown :docker /var/run/docker.sock

Note that any one of above configurations makes it possible for the user to
exploit the whole host with Docker bind mounting or other privileged
operations.  So only do it on development machines.

Examples of executing local container builds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All of the following examples will utilize ``helper`` script mentioned earlier
sections. Let's start with the basics - listing available container images in
the default libvirt registry:

::

    $ cd <libvirt_git>/ci
    $ ./helper --help
    $ ./helper list-images
    Available x86 container images:

    ...
    alpine-edge
    fedora-rawhide
    ...

    Available cross-compiler container images:

    ...
    debian-sid-cross-s390x
    fedora-rawhide-cross-mingw32
    fedora-rawhide-cross-mingw64
    ...

Now, let's say one would want to run the ``website`` job from GitLab on Debian
11. This is how a GitLab job specification can be referenced on ``ci/helper``'s
command line:

::

    $ ci/helper run --job website debian-10

What if you want to run an rpmbuild of libvirt on an RPM distro?

::

    $ ci/helper run --job rpmbuild fedora-38

Want to use your own, say alpine-edge, container image from your GitLab
container registry?
Proceed with the following:

::

    $ ci/helper run --job build --image-prefix registry.gitlab.com/<user>/libvirt/ci- alpine-edge

Finally, it would be nice if one could get an interactive shell inside the
test environment to debug potential build issues. This can be achieved with the
following:

::

    $ ci/helper run --job shell alpine-edge


Integration tests
-----------------

There are a few frameworks for writing and running functional tests in libvirt
with TCK being the one that runs in our upstream CI.

-  the `TCK test suite <testtck.html>`__ is a functional test suite implemented
   using the `Perl bindings <https://search.cpan.org/dist/Sys-Virt/>`__ of
   libvirt. This is the recommended framework to use for writing upstream
   functional tests at the moment. You can start by cloning the
   `TCK git repo <https://gitlab.com/libvirt/libvirt-tck>`__.

-  the `Avocado VT <https://github.com/avocado-framework/avocado-vt>`__ test
   suite with the libvirt plugin is another framework implementing functional
   testing utilizing the Avocado test framework underneath. Although written in
   Python, the vast majority of the tests are exercising libvirt through the
   command line client ``virsh``.

-  the `libvirt-test-API <testapi.html>`__ is also a functional test suite, but
   implemented using the `Python bindings <python.html>`__ of libvirt.
   Unfortunately this framework is the least recommended one as it's largely
   unmaintained and may be completely deprecated in the future in favour of TCK.
   You can get it by cloning the
   `git repo <https://gitlab.com/libvirt/libvirt-test-API/>`__.
