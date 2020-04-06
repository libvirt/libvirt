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
     make -C tests valgrind

   `Valgrind <http://valgrind.org/>`__ is a test that checks for
   memory management issues, such as leaks or use of uninitialized
   variables.

   Some tests are skipped by default in a development environment,
   based on the time they take in comparison to the likelihood
   that those tests will turn up problems during incremental
   builds. These tests default to being run when building from a
   tarball or with the configure option --enable-expensive-tests;
   you can also force a one-time toggle of these tests by setting
   VIR_TEST_EXPENSIVE to 0 or 1 at make time, as in:

   ::

     make check VIR_TEST_EXPENSIVE=1

   If you encounter any failing tests, the VIR_TEST_DEBUG
   environment variable may provide extra information to debug the
   failures. Larger values of VIR_TEST_DEBUG may provide larger
   amounts of information:

   ::

     VIR_TEST_DEBUG=1 make check    (or)
     VIR_TEST_DEBUG=2 make check

   When debugging failures during development, it is possible to
   focus in on just the failing subtests by using VIR_TEST_RANGE.
   I.e. to run all tests from 3 to 20 with the exception of tests
   6 and 16, use:

   ::

     VIR_TEST_DEBUG=1 VIR_TEST_RANGE=3-5,7-20,^16 ./run tests/qemuxml2argvtest

   Also, individual tests can be run from inside the ``tests/``
   directory, like:

   ::

     ./qemuxml2xmltest

   If you are adding new test cases, or making changes that alter
   existing test output, you can use the environment variable
   VIR_TEST_REGENERATE_OUTPUT to quickly update the saved test
   data. Of course you still need to review the changes VERY
   CAREFULLY to ensure they are correct.

   ::

     VIR_TEST_REGENERATE_OUTPUT=1 ./qemuxml2argvtest

   There is also a ``./run`` script at the top level, to make it
   easier to run programs that have not yet been installed, as
   well as to wrap invocations of various tests under gdb or
   Valgrind.

   When running our test suite it may happen that the test result
   is nondeterministic because of the test suite relying on a
   particular file in the system being accessible or having some
   specific value. To catch this kind of errors, the test suite
   has a module for that prints any path touched that fulfils
   constraints described above into a file. To enable it just set
   ``VIR_TEST_FILE_ACCESS`` environment variable. Then
   ``VIR_TEST_FILE_ACCESS_OUTPUT`` environment variable can alter
   location where the file is stored.

   ::

     VIR_TEST_FILE_ACCESS=1 VIR_TEST_FILE_ACCESS_OUTPUT="/tmp/file_access.txt" ./qemuxml2argvtest

#. The Valgrind test should produce similar output to
   ``make check``. If the output has traces within libvirt API's,
   then investigation is required in order to determine the cause
   of the issue. Output such as the following indicates some sort
   of leak:

   ::

     ==5414== 4 bytes in 1 blocks are definitely lost in loss record 3 of 89
     ==5414==    at 0x4A0881C: malloc (vg_replace_malloc.c:270)
     ==5414==    by 0x34DE0AAB85: xmlStrndup (in /usr/lib64/libxml2.so.2.7.8)
     ==5414==    by 0x4CC97A6: virDomainVideoDefParseXML (domain_conf.c:7410)
     ==5414==    by 0x4CD581D: virDomainDefParseXML (domain_conf.c:10188)
     ==5414==    by 0x4CD8C73: virDomainDefParseNode (domain_conf.c:10640)
     ==5414==    by 0x4CD8DDB: virDomainDefParse (domain_conf.c:10590)
     ==5414==    by 0x41CB1D: testCompareXMLToArgvHelper (qemuxml2argvtest.c:100)
     ==5414==    by 0x41E20F: virtTestRun (testutils.c:161)
     ==5414==    by 0x41C7CB: mymain (qemuxml2argvtest.c:866)
     ==5414==    by 0x41E84A: virtTestMain (testutils.c:723)
     ==5414==    by 0x34D9021734: (below main) (in /usr/lib64/libc-2.15.so)

   In this example, the ``virDomainDefParseXML()`` had an error
   path where the ``virDomainVideoDefPtr video`` pointer was not
   properly disposed. By simply adding a
   ``virDomainVideoDefFree(video);`` in the error path, the issue
   was resolved.

   Another common mistake is calling a printing function, such as
   ``VIR_DEBUG()`` without initializing a variable to be printed.
   The following example involved a call which could return an
   error, but not set variables passed by reference to the call.
   The solution was to initialize the variables prior to the call.

   ::

     ==4749== Use of uninitialised value of size 8
     ==4749==    at 0x34D904650B: _itoa_word (in /usr/lib64/libc-2.15.so)
     ==4749==    by 0x34D9049118: vfprintf (in /usr/lib64/libc-2.15.so)
     ==4749==    by 0x34D9108F60: __vasprintf_chk (in /usr/lib64/libc-2.15.so)
     ==4749==    by 0x4CAEEF7: virVasprintf (stdio2.h:199)
     ==4749==    by 0x4C8A55E: virLogVMessage (virlog.c:814)
     ==4749==    by 0x4C8AA96: virLogMessage (virlog.c:751)
     ==4749==    by 0x4DA0056: virNetTLSContextCheckCertKeyUsage (virnettlscontext.c:225)
     ==4749==    by 0x4DA06DB: virNetTLSContextCheckCert (virnettlscontext.c:439)
     ==4749==    by 0x4DA1620: virNetTLSContextNew (virnettlscontext.c:562)
     ==4749==    by 0x4DA26FC: virNetTLSContextNewServer (virnettlscontext.c:927)
     ==4749==    by 0x409C39: testTLSContextInit (virnettlscontexttest.c:467)
     ==4749==    by 0x40AB8F: virtTestRun (testutils.c:161)

   Valgrind will also find some false positives or code paths
   which cannot be resolved by making changes to the libvirt code.
   For these paths, it is possible to add a filter to avoid the
   errors. For example:

   ::

     ==4643== 7 bytes in 1 blocks are possibly lost in loss record 4 of 20
     ==4643==    at 0x4A0881C: malloc (vg_replace_malloc.c:270)
     ==4643==    by 0x34D90853F1: strdup (in /usr/lib64/libc-2.15.so)
     ==4643==    by 0x34EEC2C08A: ??? (in /usr/lib64/libnl.so.1.1)
     ==4643==    by 0x34EEC15B81: ??? (in /usr/lib64/libnl.so.1.1)
     ==4643==    by 0x34D8C0EE15: call_init.part.0 (in /usr/lib64/ld-2.15.so)
     ==4643==    by 0x34D8C0EECF: _dl_init (in /usr/lib64/ld-2.15.so)
     ==4643==    by 0x34D8C01569: ??? (in /usr/lib64/ld-2.15.so)

   In this instance, it is acceptable to modify the
   ``tests/.valgrind.supp`` file in order to add a suppression
   filter. The filter should be unique enough to not suppress real
   leaks, but it should be generic enough to cover multiple code
   paths. The format of the entry can be found in the
   documentation found at the `Valgrind home
   page <http://valgrind.org/>`__. The following trace was added
   to ``tests/.valgrind.supp`` in order to suppress the warning:

   ::

     {
         dlInitMemoryLeak1
         Memcheck:Leak
         fun:?alloc
         ...
         fun:call_init.part.0
         fun:_dl_init
         ...
         obj:*/lib*/ld-2.*so*
     }

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

Language Usage
==============

The libvirt repository makes use of a large number of programming
languages. It is anticipated that in the future libvirt will adopt
use of other new languages. To reduce the overall burden on
developers, there is thus a general desire to phase out usage of
some of the existing languages.

The preferred languages at this time are:

-  C - for the main libvirt codebase. Dialect supported by
   GCC/CLang only.
-  Python - for supporting build scripts / tools. Code must run
   with both version 2.7 and 3.x at this time.

Languages that should not be used for any new contributions:

-  Perl - build scripts must be written in Python instead.
-  Shell - build scripts must be written in Python instead.

Tooling
=======

libvirt includes support for some useful development tools right
in its source repository, meaning users will be able to take
advantage of them without little or no configuration. Examples
include:

-  `color_coded <https://github.com/jeaye/color_coded>`__, a vim
   plugin for libclang-powered semantic syntax highlighting;
-  `YouCompleteMe <http://valloric.github.io/YouCompleteMe/>`__, a
   vim plugin for libclang-powered semantic code completion.

Libvirt committer guidelines
============================

The AUTHORS files indicates the list of people with commit access
right who can actually merge the patches.

The general rule for committing a patch is to make sure it has
been reviewed properly in the mailing-list first, usually if a
couple of people gave an ACK or +1 to a patch and nobody raised an
objection on the list it should be good to go. If the patch
touches a part of the code where you're not the main maintainer,
or where you do not have a very clear idea of how things work,
it's better to wait for a more authoritative feedback though.
Before committing, please also rebuild locally, run 'make check
syntax-check', and make sure you don't raise errors.

An exception to 'review and approval on the list first' is fixing
failures to build:

-  if a recently committed patch breaks compilation on a platform
   or for a given driver, then it's fine to commit a minimal fix
   directly without getting the review feedback first
-  if make check or make syntax-check breaks, if there is an
   obvious fix, it's fine to commit immediately. The patch should
   still be sent to the list (or tell what the fix was if
   trivial), and 'make check syntax-check' should pass too, before
   committing anything
-  fixes for documentation and code comments can be managed in the
   same way, but still make sure they get reviewed if non-trivial.
-  (ir)regular pulls from other repositories or automated updates,
   such as the keycodemap submodule updates, pulling in new
   translations or updating the container images for the CI system
