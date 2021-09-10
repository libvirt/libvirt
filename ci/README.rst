==============
CI for libvirt
==============

This document provides some information related to the CI capabilities for the
libvirt project.


Cirrus CI integration
=====================

libvirt currently supports three non-Linux operating systems: Windows, FreeBSD
and macOS. Windows cross-builds can be prepared on Linux by using `MinGW`_, but
for both FreeBSD and macOS we need to use the actual operating system, and
unfortunately GitLab shared runners are currently not available for either.

To work around this limitation, we take advantage of `Cirrus CI`_'s free
offering: more specifically, we use the `cirrus-run`_ script to trigger Cirrus
CI jobs from GitLab CI jobs so that the workaround is almost entirely
transparent to users and there's no need to constantly check two separate CI
dashboards.

There is, however, some one-time setup required. If you want FreeBSD and macOS
builds to happen when you push to your GitLab repository, you need to

* set up a GitHub repository for the project, eg. ``yourusername/libvirt``.
  This repository needs to exist for cirrus-run to work, but it doesn't need to
  be kept up to date, so you can create it and then forget about it;

* enable the `Cirrus CI GitHub app`_  for your GitHub account;

* sign up for Cirrus CI. It's enough to log into the website using your GitHub
  account;

* grab an API token from the `Cirrus CI settings`_ page;

* it may be necessary to push an empty ``.cirrus.yml`` file to your github fork
  for Cirrus CI to properly recognize the project. You can check whether
  Cirrus CI knows about your project by navigating to:

  ``https://cirrus-ci.com/yourusername/libvirt``

* in the *CI/CD / Variables* section of the settings page for your GitLab
  repository, create two new variables:

  * ``CIRRUS_GITHUB_REPO``, containing the name of the GitHub repository
    created earlier, eg. ``yourusername/libvirt``;

  * ``CIRRUS_API_TOKEN``, containing the Cirrus CI API token generated earlier.
    This variable **must** be marked as *Masked*, because anyone with knowledge
    of it can impersonate you as far as Cirrus CI is concerned.

  Neither of these variables should be marked as *Protected*, because in
  general you'll want to be able to trigger Cirrus CI builds from non-protected
  branches.

Once this one-time setup is complete, you can just keep pushing to your GitLab
repository as usual and you'll automatically get the additional CI coverage.


.. _Cirrus CI GitHub app: https://github.com/marketplace/cirrus-ci
.. _Cirrus CI settings: https://cirrus-ci.com/settings/profile/
.. _Cirrus CI: https://cirrus-ci.com/
.. _MinGW: http://mingw.org/
.. _cirrus-run: https://github.com/sio/cirrus-run/


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
