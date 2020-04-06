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

#. The simplest way to send patches is to use the
   `git-publish <https://github.com/stefanha/git-publish>`__
   tool. All libvirt-related repositories contain a config file
   that tells git-publish to use the correct mailing list and
   subject prefix.

   Alternatively, you may send patches using ``git send-email``.

   Also, for code motion patches, you may find that
   ``git diff --patience`` provides an easier-to-read
   patch. However, the usual workflow of libvirt developer is:

   ::

     git checkout master
     git pull
     git checkout -t origin -b workbranch
     Hack, committing any changes along the way

   More hints on compiling can be found `here <compiling.html>`__.
   When you want to post your patches:

   ::

     git pull --rebase
     (fix any conflicts)
     git send-email --cover-letter --no-chain-reply-to --annotate \
                    --confirm=always --to=libvir-list@redhat.com master

   For a single patch you can omit ``--cover-letter``, but a
   series of two or more patches needs a cover letter.

   Note that the ``git send-email`` subcommand may not be in the
   main git package and using it may require installation of a
   separate package, for example the "git-email" package in Fedora
   and Debian. If this is your first time using
   ``git send-email``, you might need to configure it to point it
   to your SMTP server with something like:

   ::

     git config --global sendemail.smtpServer stmp.youremailprovider.net

   If you get tired of typing ``--to=libvir-list@redhat.com`` all
   the time, you can configure that to be automatically handled as
   well:

   ::

     git config sendemail.to libvir-list@redhat.com

   As a rule, patches should be sent to the mailing list only: all
   developers are subscribed to libvir-list and read it regularly,
   so **please don't CC individual developers** unless they've
   explicitly asked you to.

   Avoid using mail clients for sending patches, as most of them
   will mangle the messages in some way, making them unusable for
   our purposes. Gmail and other Web-based mail clients are
   particularly bad at this.

   If everything went well, your patch should show up on the
   `libvir-list
   archives <https://www.redhat.com/archives/libvir-list/>`__ in a
   matter of minutes; if you still can't find it on there after an
   hour or so, you should double-check your setup. **Note that, if
   you are not already a subscriber, your very first post to the
   mailing list will be subject to moderation**, and it's not
   uncommon for that to take around a day.

   Please follow this as close as you can, especially the rebase
   and ``git send-email`` part, as it makes life easier for other
   developers to review your patch set.

   One should avoid sending patches as attachments, but rather
   send them in email body along with commit message. If a
   developer is sending another version of the patch (e.g. to
   address review comments), they are advised to note differences
   to previous versions after the ``---`` line in the patch so
   that it helps reviewers but doesn't become part of git history.
   Moreover, such patch needs to be prefixed correctly with
   ``--subject-prefix=PATCHv2`` appended to
   ``git send-email`` (substitute ``v2`` with the
   correct version if needed though).

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
