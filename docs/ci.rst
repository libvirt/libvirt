==============================
Libvirt Continuous Integration
==============================

.. contents::

The libvirt project uses GitLab CI for automated testing.
`Here's <ci-dashboard.html>`__ our CI dashboard which shows the current status
of our pipelines.

Builds and unit tests
=====================

Linux builds and cross-compiled Windows builds happen on GitLab CI's shared
runners, while FreeBSD and macOS coverage is achieved by triggering `Cirrus CI
<https://cirrus-ci.com/>`_ jobs behind the scenes.

Most of the tooling used to build CI pipelines is maintained as part of the
`libvirt-ci <https://gitlab.com/libvirt/libvirt-ci>`_ subproject.

Integration tests
=================

Integration tests in our CI pipelines require dedicated HW which is not
available to forks, see `GitLab CI Custom Runners <ci-runners.html>`__.
Therefore, in order to execute the integration tests as part of your libvirt
fork's GitLab CI you'll need to provide your own runner. You'll also need to
set a few CI variables to run the integration tests as part of the CI pipeline,
see below.

GitLab CI variables
-------------------

* ``LIBVIRT_CI_INTEGRATION`` - enables integration test runs manually or in forks
* ``LIBVIRT_CI_INTEGRATION_RUNNER_TAG`` - overrides the upstream runner tag on the

Retrieving test logs
--------------------

In case the integration test suite fails in our CI pipelines, a job artifact is
generated containing Avocado logs, libvirt debug logs, and the latest traceback
(if one was produced during a daemon's execution).
