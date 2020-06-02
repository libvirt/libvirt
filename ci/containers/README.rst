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
