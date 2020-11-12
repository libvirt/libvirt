CI job assets
=============

This directory contains assets used in the automated CI jobs, most
notably the Dockerfiles used to build container images in which the
CI jobs then run.

The ``refresh`` script is used to re-create the Dockerfiles using the
``lcitool`` command that is provided by repo
https://gitlab.com/libvirt/libvirt-ci

The containers are built during the CI process and cached in the GitLab
container registry of the project doing the build. The cached containers
can be deleted at any time and will be correctly rebuilt.


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
