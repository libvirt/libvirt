======================
Contributor guidelines
======================

.. contents::

General tips for contributing patches
=====================================

#. Discuss any large changes on the mailing list first. Post
   patches early and listen to feedback.

#. Official upstream repository is kept in git
   (``https://libvirt.org/git/libvirt.git``) and is browsable
   along with other libvirt-related repositories (e.g.
   libvirt-python) `online <https://libvirt.org/git/>`__.

#. Patches to translations are maintained via the `zanata
   project <https://fedora.zanata.org/>`__. If you want to fix a
   translation in a .po file, join the appropriate language team.
   The libvirt release process automatically pulls the latest
   version of each translation file from zanata.

#. In your commit message, make the summary line reasonably short
   (60 characters is typical), followed by a blank line, followed
   by any longer description of why your patch makes sense. If the
   patch fixes a regression, and you know what commit introduced
   the problem, mentioning that is useful. If the patch resolves a
   bugzilla report, mentioning the URL of the bug number is
   useful; but also summarize the issue rather than making all
   readers follow the link. You can use 'git shortlog -30' to get
   an idea of typical summary lines.

#. Contributors to libvirt projects **must** assert that they are
   in compliance with the `Developer Certificate of Origin
   1.1 <https://developercertificate.org/>`__. This is achieved by
   adding a "Signed-off-by" line containing the contributor's name
   and e-mail to every commit message. The presence of this line
   attests that the contributor has read the above lined DCO and
   agrees with its statements.

#. Split large changes into a series of smaller patches,
   self-contained if possible, with an explanation of each patch
   and an explanation of how the sequence of patches fits
   together. Moreover, please keep in mind that it's required to
   be able to compile cleanly (**including**
   ``make check`` and ``make syntax-check``) after each
   patch. A feature does not have to work until the end of a
   series, but intermediate patches must compile and not cause
   test-suite failures (this is to preserve the usefulness of
   ``git bisect``, among other things).

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

There is more on this subject, including lots of links to
background reading on the subject, on `Richard Jones' guide to
working with open source
projects <http://people.redhat.com/rjones/how-to-supply-code-to-open-source-projects/>`__.
