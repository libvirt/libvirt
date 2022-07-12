==============================
Libvirt Continuous Integration
==============================

.. contents::

The libvirt project uses GitLab CI for automated testing.
`Here's <ci-dashboard.html>`__ our CI dashboard which shows the current status
of our pipelines.

Linux builds and cross-compiled Windows builds happen on GitLab CI's shared
runners, while FreeBSD and macOS coverage is achieved by triggering `Cirrus CI
<https://cirrus-ci.com/>`_ jobs behind the scenes.

Most of the tooling used to build CI pipelines is maintained as part of the
`libvirt-ci <https://gitlab.com/libvirt/libvirt-ci>`_ subproject.

























