======================
Contributor guidelines
======================

.. contents::

General tips for contributing patches
=====================================

#. Official upstream repository is kept in git
   (``https://libvirt.org/git/libvirt.git``) and is browsable
   along with other libvirt-related repositories (e.g.
   libvirt-python) `online <https://libvirt.org/git/>`__.

#. Patches to translations are maintained via the `zanata
   project <https://fedora.zanata.org/>`__. If you want to fix a
   translation in a .po file, join the appropriate language team.
   The libvirt release process automatically pulls the latest
   version of each translation file from zanata.

#. Contributors to libvirt projects **must** assert that they are
   in compliance with the `Developer Certificate of Origin
   1.1 <https://developercertificate.org/>`__. This is achieved by
   adding a "Signed-off-by" line containing the contributor's name
   and e-mail to every commit message. The presence of this line
   attests that the contributor has read the above lined DCO and
   agrees with its statements.

#. Make sure your patches apply against libvirt GIT. Developers
   only follow GIT and don't care much about released versions.

#. Run the automated tests on your code before submitting any
   changes. That is:

   ::

     make check
     make syntax-check

#. Update tests and/or documentation, particularly if you are
   adding a new feature or changing the output of a program.

#. Don't forget to update the `release notes <news.html>`__ by
   changing ``docs/news.xml`` if your changes are significant. All
   user-visible changes, such as adding new XML elements or fixing
   all but the most obscure bugs, must be (briefly) described in a
   release notes entry; changes that are only relevant to other
   libvirt developers, such as code refactoring, don't belong in
   the release notes. Note that ``docs/news.xml`` should be
   updated in its own commit not to get in the way of backports.
