============
Contributing
============

These are the basics steps you need to follow to contribute to
libvirt software development.

Repositories and external resources
===================================

The official upstream repository is kept in git
(``https://gitlab.com/libvirt/libvirt``) and is browsable
along with other libvirt-related repositories (e.g.
libvirt-python) `online <https://gitlab.com/libvirt>`__.

Patches to translations are maintained via the `Fedora Weblate
service <https://translate.fedoraproject.org/projects/libvirt/libvirt>`__.
If you want to contribute to translations of libvirt, join the appropriate
language team in Weblate.  Translation updates to libvirt will be merged
during the feature freeze window.

Working with the code
=====================

In general you should base your work upon the git master branch.

The `"Git checkout" section <compiling.html#git-checkout>`__
of the libvirt installation instructions give an overview of the
compilation process.

Optionally, `Clangd with libvirt <clangd.html>`__ can be used to
navigate the code base etc. within most code editors (and IDEs).

Preparing patches
=================

Make sure your patches apply against the libvirt git master
branch. The backporting of changes to existing releases is
typically carried out by downstream users at their discretion
after code is merged into the upstream git.

Run the automated tests on your code before submitting any
changes. That is:

::

  $ ninja test

These tests help making sure that your changes don't introduce
regressions in libvirt, as well as validating that any new code
follows the project's `coding style <coding-style.html>`__.

If you're going to submit multiple patches, the automated tests
must pass **after each patch**, not just after the last one.

Update tests and/or documentation, particularly if you are
adding a new feature or changing the output of a program, and
don't forget to update the `release notes <news.html>`__ if your
changes are significant and user-visible.

To test across a variety of build platforms prior to submitting
your changes, you may create your own fork of the project on
gitlab. This will give you access to (a subset of) libvirt's
`continuous integration <ci.html>`__ test suite.

Please note that you should still follow the instructions below,
rather than following gitlab's prompts to open a "merge request".

Submitting patches
==================

Libvirt uses a mailing list based development workflow.

While preparing your patches for submissions, make sure you
follow the `best practices <best-practices.html>`__ and, once
you're satisfied with the result, go ahead and
`submit your patches <submitting-patches.html>`__.

Developer Certificate of Origin
===============================

Contributors to libvirt projects **must** assert that they are
in compliance with the `Developer Certificate of Origin
1.1 <https://developercertificate.org/>`__. This is achieved by
adding a "Signed-off-by" line containing the contributor's name
and e-mail to every commit message. The presence of this line
attests that the contributor has read the above lined DCO and
agrees with its statements.

Further reading
===============

This page only covers the very basics, so it's recommended that
you also take a look at the following documents:

-  `Programming languages <programming-languages.html>`__
-  `Advanced test suite usage <advanced-tests.html>`__
-  `Adoption of GLib APIs <glib-adoption.html>`__
-  `Committer guidelines <committer-guidelines.html>`__
-  `Contributing to libvirt <contribute.html>`__
