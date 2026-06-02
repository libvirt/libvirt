==============
CI for libvirt
==============

This document provides some information related to the CI capabilities for the
libvirt project.


GitLab CI tuning
================

The behaviour of GitLab CI can be tuned through a number of variables
which can be set at push time, or through the UI. See ``ci/gitlab.yml``
for further details.

Coverity scan integration
=========================

This will be used only by the main repository for master branch by running
scheduled pipeline in GitLab.

The service is proved by `Coverity Scan`_ and requires that the project is
registered there to get free coverity analysis which we already have for
`libvirt project`_.

To run the coverity job it requires two new variables:

  * ``COVERITY_SCAN_PROJECT_NAME``, containing the `libvirt project`_
    name.

  * ``COVERITY_SCAN_TOKEN``, token visible to admins of `libvirt project`_


.. _Coverity Scan: https://scan.coverity.com/
.. _libvirt project: https://scan.coverity.com/projects/libvirt
