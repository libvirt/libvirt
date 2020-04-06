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

Naming conventions
==================

When reading libvirt code, a number of different naming
conventions will be evident due to various changes in thinking
over the course of the project's lifetime. The conventions
documented below should be followed when creating any entirely new
files in libvirt. When working on existing files, while it is
desirable to apply these conventions, keeping a consistent style
with existing code in that particular file is generally more
important. The overall guiding principal is that every file, enum,
struct, function, macro and typedef name must have a 'vir' or
'VIR' prefix. All local scope variable names are exempt, and
global variables are exempt, unless exported in a header file.

File names
   File naming varies depending on the subdirectory. The preferred
   style is to have a 'vir' prefix, followed by a name which
   matches the name of the functions / objects inside the file.
   For example, a file containing an object 'virHashtable' is
   stored in files 'virhashtable.c' and 'virhashtable.h'.
   Sometimes, methods which would otherwise be declared 'static'
   need to be exported for use by a test suite. For this purpose a
   second header file should be added with a suffix of 'priv',
   e.g. 'virhashtablepriv.h'. Use of underscores in file names is
   discouraged when using the 'vir' prefix style. The 'vir' prefix
   naming applies to src/util, src/rpc and tests/ directories.
   Most other directories do not follow this convention.

Enum type & field names
   All enums should have a 'vir' prefix in their typedef name, and
   each following word should have its first letter in uppercase.
   The enum name should match the typedef name with a leading
   underscore. The enum member names should be in all uppercase,
   and use an underscore to separate each word. The enum member
   name prefix should match the enum typedef name.

   ::

     typedef enum _virSocketType virSocketType;
     enum _virSocketType {
         VIR_SOCKET_TYPE_IPV4,
         VIR_SOCKET_TYPE_IPV6,
     };

Struct type names
   All structs should have a 'vir' prefix in their typedef name,
   and each following word should have its first letter in
   uppercase. The struct name should be the same as the typedef
   name with a leading underscore. A second typedef should be
   given for a pointer to the struct with a 'Ptr' suffix.

   ::

     typedef struct _virHashTable virHashTable;
     typedef virHashTable *virHashTablePtr;
     struct _virHashTable {
         ...
     };

Function names
   All functions should have a 'vir' prefix in their name,
   followed by one or more words with first letter of each word
   capitalized. Underscores should not be used in function names.
   If the function is operating on an object, then the function
   name prefix should match the object typedef name, otherwise it
   should match the filename. Following this comes the verb /
   action name, and finally an optional subject name. For example,
   given an object 'virHashTable', all functions should have a
   name 'virHashTable$VERB' or 'virHashTable$VERB$SUBJECT", e.g.
   'virHashTableLookup' or 'virHashTableGetValue'.

Macro names
   All macros should have a "VIR" prefix in their name, followed
   by one or more uppercase words separated by underscores. The
   macro argument names should be in lowercase. Aside from having
   a "VIR" prefix there are no common practices for the rest of
   the macro name.

Code indentation
================

Libvirt's C source code generally adheres to some basic
code-formatting conventions. The existing code base is not totally
consistent on this front, but we do prefer that contributed code
be formatted similarly. In short, use spaces-not-TABs for
indentation, use 4 spaces for each indentation level, and other
than that, follow the K&R style.

If you use Emacs, the project includes a file .dir-locals.el that
sets up the preferred indentation. If you use vim, append the
following to your ~/.vimrc file:

::

  set nocompatible
  filetype on
  set autoindent
  set smartindent
  set cindent
  set tabstop=8
  set shiftwidth=4
  set expandtab
  set cinoptions=(0,:0,l1,t0,L3
  filetype plugin indent on
  au FileType make setlocal noexpandtab
  au BufRead,BufNewFile *.am setlocal noexpandtab
  match ErrorMsg /\s\+$\| \+\ze\t/

Or if you don't want to mess your ~/.vimrc up, you can save the
above into a file called .lvimrc (not .vimrc) located at the root
of libvirt source, then install a vim script from
http://www.vim.org/scripts/script.php?script_id=1408, which will
load the .lvimrc only when you edit libvirt code.

Code formatting (especially for new code)
=========================================

With new code, we can be even more strict. Please apply the
following function (using GNU indent) to any new code. Note that
this also gives you an idea of the type of spacing we prefer
around operators and keywords:

::

  indent-libvirt()
  {
    indent -bad -bap -bbb -bli4 -br -ce -brs -cs -i4 -l75 -lc75 \
           -sbi4 -psl -saf -sai -saw -sbi4 -ss -sc -cdw -cli4 -npcs -nbc \
           --no-tabs "$@"
  }

Note that sometimes you'll have to post-process that output
further, by piping it through ``expand -i``, since some leading
TABs can get through. Usually they're in macro definitions or
strings, and should be converted anyhow.

Libvirt requires a C99 compiler for various reasons. However, most
of the code base prefers to stick to C89 syntax unless there is a
compelling reason otherwise. For example, it is preferable to use
``/* */`` comments rather than ``//``. Also, when declaring local
variables, the prevailing style has been to declare them at the
beginning of a scope, rather than immediately before use.

Bracket spacing
---------------

The keywords ``if``, ``for``, ``while``, and ``switch`` must have
a single space following them before the opening bracket. E.g.

::

  if(foo)   // Bad
  if (foo)  // Good

Function implementations must **not** have any whitespace between
the function name and the opening bracket. E.g.

::

  int foo (int wizz)  // Bad
  int foo(int wizz)   // Good

Function calls must **not** have any whitespace between the
function name and the opening bracket. E.g.

::

  bar = foo (wizz);  // Bad
  bar = foo(wizz);   // Good

Function typedefs must **not** have any whitespace between the
closing bracket of the function name and opening bracket of the
arg list. E.g.

::

  typedef int (*foo) (int wizz);  // Bad
  typedef int (*foo)(int wizz);   // Good

There must not be any whitespace immediately following any opening
bracket, or immediately prior to any closing bracket. E.g.

::

  int foo( int wizz );  // Bad
  int foo(int wizz);    // Good

Commas
------

Commas should always be followed by a space or end of line, and
never have leading space; this is enforced during 'make
syntax-check'.

::

  call(a,b ,c);// Bad
  call(a, b, c); // Good

When declaring an enum or using a struct initializer that occupies
more than one line, use a trailing comma. That way, future edits
to extend the list only have to add a line, rather than modify an
existing line to add the intermediate comma. Any sentinel
enumerator value with a name ending in \_LAST is exempt, since you
would extend such an enum before the \_LAST element. Another
reason to favor trailing commas is that it requires less effort to
produce via code generators. Note that the syntax checker is
unable to enforce a style of trailing commas, so there are
counterexamples in existing code which do not use it; also, while
C99 allows trailing commas, remember that JSON and XDR do not.

::

  enum {
      VALUE_ONE,
      VALUE_TWO // Bad
  };
  enum {
      VALUE_THREE,
      VALUE_FOUR, // Good
  };

Semicolons
----------

Semicolons should never have a space beforehand. Inside the
condition of a ``for`` loop, there should always be a space or
line break after each semicolon, except for the special case of an
infinite loop (although more infinite loops use ``while``). While
not enforced, loop counters generally use post-increment.

::

  for (i = 0 ;i < limit ; ++i) { // Bad
  for (i = 0; i < limit; i++) { // Good
  for (;;) { // ok
  while (1) { // Better

Empty loop bodies are better represented with curly braces and a
comment, although use of a semicolon is not currently rejected.

::

  while ((rc = waitpid(pid, &st, 0) == -1) &&
         errno == EINTR); // ok
  while ((rc = waitpid(pid, &st, 0) == -1) &&
         errno == EINTR) { // Better
      /* nothing */
  }

Curly braces
------------

Omit the curly braces around an ``if``, ``while``, ``for`` etc.
body only when both that body and the condition itself occupy a
single line. In every other case we require the braces. This
ensures that it is trivially easy to identify a
single-\ *statement* loop: each has only one *line* in its body.

::

  while (expr)             // single line body; {} is forbidden
      single_line_stmt();

::

  while (expr(arg1,
              arg2))      // indentation makes it obvious it is single line,
      single_line_stmt(); // {} is optional (not enforced either way)

::

  while (expr1 &&
         expr2) {         // multi-line, at same indentation, {} required
      single_line_stmt();
  }

However, the moment your loop/if/else body extends on to a second
line, for whatever reason (even if it's just an added comment),
then you should add braces. Otherwise, it would be too easy to
insert a statement just before that comment (without adding
braces), thinking it is already a multi-statement loop:

::

  while (true) // BAD! multi-line body with no braces
      /* comment... */
      single_line_stmt();

Do this instead:

::

  while (true) { // Always put braces around a multi-line body.
      /* comment... */
      single_line_stmt();
  }

There is one exception: when the second body line is not at the
same indentation level as the first body line:

::

  if (expr)
      die("a diagnostic that would make this line"
          " extend past the 80-column limit"));

It is safe to omit the braces in the code above, since the
further-indented second body line makes it obvious that this is
still a single-statement body.

To reiterate, don't do this:

::

  if (expr)            // BAD: no braces around...
      while (expr_2) { // ... a multi-line body
          ...
      }

Do this, instead:

::

  if (expr) {
      while (expr_2) {
          ...
      }
  }

However, there is one exception in the other direction, when even
a one-line block should have braces. That occurs when that
one-line, brace-less block is an ``if`` or ``else`` block, and the
counterpart block **does** use braces. In that case, put braces
around both blocks. Also, if the ``else`` block is much shorter
than the ``if`` block, consider negating the ``if``-condition and
swapping the bodies, putting the short block first and making the
longer, multi-line block be the ``else`` block.

::

  if (expr) {
      ...
      ...
  }
  else
      x = y;    // BAD: braceless "else" with braced "then",
                // and short block last

  if (expr)
      x = y;    // BAD: braceless "if" with braced "else"
  else {
      ...
      ...
  }

Keeping braces consistent and putting the short block first is
preferred, especially when the multi-line body is more than a few
lines long, because it is easier to read and grasp the semantics
of an if-then-else block when the simpler block occurs first,
rather than after the more involved block:

::

  if (!expr) {
    x = y; // putting the smaller block first is more readable
  } else {
      ...
      ...
  }

But if negating a complex condition is too ugly, then at least add
braces:

::

  if (complex expr not worth negating) {
      ...
      ...
  } else {
      x = y;
  }

Use hanging braces for compound statements: the opening brace of a
compound statement should be on the same line as the condition
being tested. Only top-level function bodies, nested scopes, and
compound structure declarations should ever have { on a line by
itself.

::

  void
  foo(int a, int b)
  {                          // correct - function body
      int 2d[][] = {
        {                    // correct - complex initialization
          1, 2,
        },
      };
      if (a)
      {                      // BAD: compound brace on its own line
          do_stuff();
      }
      {                      // correct - nested scope
          int tmp;
          if (a < b) {       // correct - hanging brace
              tmp = b;
              b = a;
              a = tmp;
          }
      }
  }

Conditional expressions
-----------------------

For readability reasons new code should avoid shortening
comparisons to 0 for numeric types. Boolean and pointer
comparisions may be shortened. All long forms are okay:

::

  virFooPtr foos = NULL;
  size nfoos = 0;
  bool hasFoos = false;

  GOOD:
    if (!foos)
    if (!hasFoos)
    if (nfoos == 0)
    if (foos == NULL)
    if (hasFoos == true)

  BAD:
    if (!nfoos)
    if (nfoos)

New code should avoid the ternary operator as much as possible.
Specifically it must never span more than one line or nest:

::

  BAD:
    char *foo = baz ?
                virDoSomethingReallyComplex(driver, vm, something, baz->foo) :
                NULL;

    char *foo = bar ? bar->baz ? bar->baz->foo : "nobaz" : "nobar";

Preprocessor
------------

Macros defined with an ALL_CAPS name should generally be assumed
to be unsafe with regards to arguments with side-effects (that is,
MAX(a++, b--) might increment a or decrement b too many or too few
times). Exceptions to this rule are explicitly documented for
macros in viralloc.h and virstring.h.

For variadic macros, stick with C99 syntax:

::

  #define vshPrint(_ctl, ...) fprintf(stdout, __VA_ARGS__)

Use parenthesis when checking if a macro is defined, and use
indentation to track nesting:

::

  #if defined(HAVE_POSIX_FALLOCATE) && !defined(HAVE_FALLOCATE)
  # define fallocate(a, ignored, b, c) posix_fallocate(a, b, c)
  #endif

C types
-------

Use the right type.

Scalars
~~~~~~~

-  If you're using ``int`` or ``long``, odds are good that there's
   a better type.
-  If a variable is counting something, be sure to declare it with
   an unsigned type.
-  If it's memory-size-related, use ``size_t`` (use ``ssize_t``
   only if required).
-  If it's file-size related, use uintmax_t, or maybe ``off_t``.
-  If it's file-offset related (i.e., signed), use ``off_t``.
-  If it's just counting small numbers use ``unsigned int``; (on
   all but oddball embedded systems, you can assume that that type
   is at least four bytes wide).
-  If a variable has boolean semantics, give it the ``bool`` type
   and use the corresponding ``true`` and ``false`` macros.
-  In the unusual event that you require a specific width, use a
   standard type like ``int32_t``, ``uint32_t``, ``uint64_t``,
   etc.
-  While using ``bool`` is good for readability, it comes with
   minor caveats:

   -  Don't use ``bool`` in places where the type size must be
      constant across all systems, like public interfaces and
      on-the-wire protocols. Note that it would be possible
      (albeit wasteful) to use ``bool`` in libvirt's logical wire
      protocol, since XDR maps that to its lower-level ``bool_t``
      type, which **is** fixed-size.
   -  Don't compare a bool variable against the literal, ``true``,
      since a value with a logical non-false value need not be
      ``1``. I.e., don't write ``if (seen == true) ...``. Rather,
      write ``if (seen)...``.

Of course, take all of the above with a grain of salt. If you're
about to use some system interface that requires a type like
``size_t``, ``pid_t`` or ``off_t``, use matching types for any
corresponding variables.

Also, if you try to use e.g., ``unsigned int`` as a type, and that
conflicts with the signedness of a related variable, sometimes
it's best just to use the **wrong** type, if *pulling the thread*
and fixing all related variables would be too invasive.

Finally, while using descriptive types is important, be careful
not to go overboard. If whatever you're doing causes warnings, or
requires casts, then reconsider or ask for help.

Pointers
~~~~~~~~

Ensure that all of your pointers are *const-correct*. Unless a
pointer is used to modify the pointed-to storage, give it the
``const`` attribute. That way, the reader knows up-front that this
is a read-only pointer. Perhaps more importantly, if we're
diligent about this, when you see a non-const pointer, you're
guaranteed that it is used to modify the storage it points to, or
it is aliased to another pointer that is.

Attribute annotations
---------------------

Use the following annotations to help the compiler and/or static
analysis tools understand the code better:

+-------------------------------+------------------------------------------------------------+
| Macro                         | Meaning                                                    |
+===============================+============================================================+
| ``ATTRIBUTE_NONNULL``         | passing NULL for this parameter is not allowed             |
+-------------------------------+------------------------------------------------------------+
| ``ATTRIBUTE_PACKED``          | force a structure to be packed                             |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_FALLTHROUGH``        | allow code reuse by multiple switch cases                  |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_NO_INLINE``          | the function is mocked in the test suite                   |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_NORETURN``           | the function never returns                                 |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_NULL_TERMINATED``    | last parameter must be NULL                                |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_PRINTF``             | validate that the formatting string matches parameters     |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_UNUSED``             | parameter is unused in this implementation of the function |
+-------------------------------+------------------------------------------------------------+
| ``G_GNUC_WARN_UNUSED_RESULT`` | the return value must be checked                           |
+-------------------------------+------------------------------------------------------------+

Adoption of GLib APIs
---------------------

Libvirt has adopted use of the `GLib
library <https://developer.gnome.org/glib/stable/>`__. Due to
libvirt's long history of development, there are many APIs in
libvirt, for which GLib provides an alternative solution. The
general rule to follow is that the standard GLib solution will be
preferred over historical libvirt APIs. Existing code will be
ported over to use GLib APIs over time, but new code should use
the GLib APIs straight away where possible.

The following is a list of libvirt APIs that should no longer be
used in new code, and their suggested GLib replacements:

``VIR_ALLOC``, ``VIR_REALLOC``, ``VIR_RESIZE_N``, ``VIR_EXPAND_N``, ``VIR_SHRINK_N``, ``VIR_FREE``, ``VIR_APPEND_ELEMENT``, ``VIR_INSERT_ELEMENT``, ``VIR_DELETE_ELEMENT``
   Prefer the GLib APIs ``g_new0``/``g_renew``/ ``g_free`` in most
   cases. There should rarely be a need to use
   ``g_malloc``/``g_realloc``. Instead of using plain C arrays, it
   is preferrable to use one of the GLib types, ``GArray``,
   ``GPtrArray`` or ``GByteArray``. These all use a struct to
   track the array memory and size together and efficiently
   resize. **NEVER MIX** use of the classic libvirt memory
   allocation APIs and GLib APIs within a single method. Keep the
   style consistent, converting existing code to GLib style in a
   separate, prior commit.
``virStrerror``
   The GLib ``g_strerror()`` function should be used instead,
   which has a simpler calling convention as an added benefit.

The following libvirt APIs have been deleted already:

``VIR_AUTOPTR``, ``VIR_AUTOCLEAN``, ``VIR_AUTOFREE``
   The GLib macros ``g_autoptr``, ``g_auto`` and ``g_autofree``
   must be used instead in all new code. In existing code, the
   GLib macros must never be mixed with libvirt macros within a
   method, nor should they be mixed with ``VIR_FREE``. If
   introducing GLib macros to an existing method, any use of
   libvirt macros must be converted in an independent commit.
``VIR_DEFINE_AUTOPTR_FUNC``, ``VIR_DEFINE_AUTOCLEAN_FUNC``
   The GLib macros ``G_DEFINE_AUTOPTR_CLEANUP_FUNC`` and
   ``G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC`` must be used in all new
   code. Existing code should be converted to the new macros where
   relevant. It is permissible to use ``g_autoptr``, ``g_auto`` on
   an object whose cleanup function is declared with the libvirt
   macros and vice-versa.
``VIR_AUTOUNREF``
   The GLib macros ``g_autoptr`` and
   ``G_DEFINE_AUTOPTR_CLEANUP_FUNC`` should be used to manage
   autoclean of virObject classes. This matches usage with GObject
   classes.
``VIR_STRDUP``, ``VIR_STRNDUP``
   Prefer the GLib APIs ``g_strdup`` and ``g_strndup``.

+-------------------------------+--------------------------------------+-------------------------------------------+
| deleted version               | GLib version                         | Notes                                     |
+===============================+======================================+===========================================+
| ``VIR_AUTOPTR``               | ``g_autoptr``                        |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_AUTOCLEAN``             | ``g_auto``                           |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_AUTOFREE``              | ``g_autofree``                       | The GLib version does not use parentheses |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_AUTOUNREF``             | ``g_autoptr``                        | The cleanup function needs to be defined  |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_DEFINE_AUTOPTR_FUNC``   | ``G_DEFINE_AUTOPTR_CLEANUP_FUNC``    |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_DEFINE_AUTOCLEAN_FUNC`` | ``G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC`` |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_STEAL_PTR``             | ``g_steal_pointer``                  | ``a = f(&b)`` instead of ``f(a, b)``      |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_RETURN_PTR``            | ``return g_steal_pointer``           |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ARRAY_CARDINALITY``         | ``G_N_ELEMENTS``                     |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_FALLTHROUGH``     | ``G_GNUC_FALLTHROUGH``               |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_FMT_PRINTF``      | ``G_GNUC_PRINTF``                    |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_NOINLINE``        | ``G_GNUC_NO_INLINE``                 |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_NORETURN``        | ``G_GNUC_NORETURN``                  |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_RETURN_CHECK``    | ``G_GNUC_WARN_UNUSED_RESULT``        |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_SENTINEL``        | ``G_GNUC_NULL_TERMINATED``           |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``ATTRIBUTE_UNUSED``          | ``G_GNUC_UNUSED``                    |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_STRDUP``                | ``g_strdup``                         |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``VIR_STRNDUP``               | ``g_strndup``                        |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+
| ``virStrerror``               | ``g_strerror``                       |                                           |
+-------------------------------+--------------------------------------+-------------------------------------------+

File handling
-------------

Usage of the ``fdopen()``, ``close()``, ``fclose()`` APIs is
deprecated in libvirt code base to help avoiding double-closing of
files or file descriptors, which is particularly dangerous in a
multi-threaded application. Instead of these APIs, use the macros
from virfile.h

-  Open a file from a file descriptor:

   ::

     if ((file = VIR_FDOPEN(fd, "r")) == NULL) {
         virReportSystemError(errno, "%s",
                              _("failed to open file from file descriptor"));
         return -1;
     }
     /* fd is now invalid; only access the file using file variable */

-  Close a file descriptor:

   ::

     if (VIR_CLOSE(fd) < 0) {
         virReportSystemError(errno, "%s", _("failed to close file"));
     }

-  Close a file:

   ::

     if (VIR_FCLOSE(file) < 0) {
         virReportSystemError(errno, "%s", _("failed to close file"));
     }

-  Close a file or file descriptor in an error path, without
   losing the previous ``errno`` value:

   ::

     VIR_FORCE_CLOSE(fd);
     VIR_FORCE_FCLOSE(file);

String comparisons
------------------

Do not use the strcmp, strncmp, etc functions directly. Instead
use one of the following semantically named macros

-  For strict equality:

   ::

     STREQ(a,b)
     STRNEQ(a,b)

-  For case insensitive equality:

   ::

     STRCASEEQ(a,b)
     STRCASENEQ(a,b)

-  For strict equality of a substring:

   ::

     STREQLEN(a,b,n)
     STRNEQLEN(a,b,n)

-  For case insensitive equality of a substring:

   ::

     STRCASEEQLEN(a,b,n)
     STRCASENEQLEN(a,b,n)

-  For strict equality of a prefix:

   ::

     STRPREFIX(a,b)

-  To avoid having to check if a or b are NULL:

   ::

     STREQ_NULLABLE(a, b)
     STRNEQ_NULLABLE(a, b)

String copying
--------------

Do not use the strncpy function. According to the man page, it
does **not** guarantee a NULL-terminated buffer, which makes it
extremely dangerous to use. Instead, use one of the replacement
functions provided by libvirt:

::

  virStrncpy(char *dest, const char *src, size_t n, size_t destbytes)

The first two arguments have the same meaning as for strncpy,
namely the destination and source of the copy operation. Unlike
strncpy, the function will always copy exactly the number of bytes
requested and make sure the destination is NULL-terminated, as the
source is required to be; sanity checks are performed to ensure
the size of the destination, as specified by the last argument, is
sufficient for the operation to succeed. On success, 0 is
returned; on failure, a value <0 is returned instead.

::

  virStrcpy(char *dest, const char *src, size_t destbytes)

Use this variant if you know you want to copy the entire src
string into dest.

::

  virStrcpyStatic(char *dest, const char *src)

Use this variant if you know you want to copy the entire src
string into dest **and** you know that your destination string is
a static string (i.e. that sizeof(dest) returns something
meaningful). Note that this is a macro, so arguments could be
evaluated more than once.

::

  dst = g_strdup(src);
  dst = g_strndup(src, n);

You should avoid using strdup or strndup directly as they do not
handle out-of-memory errors, and do not allow a NULL source. Use
``g_strdup`` and ``g_strndup`` from GLib which abort on OOM and
handle NULL source by returning NULL.

Variable length string buffer
-----------------------------

If there is a need for complex string concatenations, avoid using
the usual sequence of malloc/strcpy/strcat/snprintf functions and
make use of either the
`GString <https://developer.gnome.org/glib/stable/glib-Strings.html>`__
type from GLib or the virBuffer API. If formatting XML or QEMU
command line is needed, use the virBuffer API described in
virbuffer.h, since it has helper functions for those.

Typical usage is as follows:

::

  char *
  somefunction(...)
  {
     g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

     ...

     virBufferAddLit(&buf, "<domain>\n");

     ...

     if (some_error)
         return NULL; /* g_auto will free the memory used so far */

     ...

     virBufferAddLit(&buf, "</domain>\n");

     ...

     if (virBufferCheckError(&buf) < 0)
         return NULL;

     return virBufferContentAndReset(&buf);
  }

Include files
-------------

There are now quite a large number of include files, both libvirt
internal and external, and system includes. To manage all this
complexity it's best to stick to the following general plan for
all \*.c source files:

::

  /*
   * Copyright notice
   * ....
   * ....
   * ....
   *
   */

  #include <config.h>             Must come first in every file.

  #include <stdio.h>              Any system includes you need.
  #include <string.h>
  #include <limits.h>

  #if WITH_NUMACTL                Some system includes aren't supported
  # include <numa.h>              everywhere so need these #if guards.
  #endif

  #include "internal.h"           Include this first, after system includes.

  #include "util.h"               Any libvirt internal header files.
  #include "buf.h"

  static int
  myInternalFunc()                The actual code.
  {
      ...

Of particular note: **Do not** include libvirt/libvirt.h,
libvirt/virterror.h, libvirt/libvirt-qemu.h, or
libvirt/libvirt-lxc.h. They are included by "internal.h" already
and there are some special reasons why you cannot include these
files explicitly. One of the special cases, "libvirt/libvirt.h" is
included prior to "internal.h" in "remote_protocol.x", to avoid
exposing \*_LAST enum elements.

Printf-style functions
----------------------

Whenever you add a new printf-style function, i.e., one with a
format string argument and following "..." in its prototype, be
sure to use gcc's printf attribute directive in the prototype. For
example, here's the one for virCommandAddEnvFormat in
vircommand.h:

::

  void virCommandAddEnvFormat(virCommandPtr cmd, const char *format, ...)
      G_GNUC_PRINTF(2, 3);

This makes it so gcc's -Wformat and -Wformat-security options can
do their jobs and cross-check format strings with the number and
types of arguments.

When printing to a string, consider using GString or virBuffer for
incremental allocations, g_strdup_printf for a one-shot
allocation, and g_snprintf for fixed-width buffers. Only use
g_sprintf, if you can prove the buffer won't overflow.

Error message format
--------------------

Error messages visible to the user should be short and
descriptive. All error messages are translated using gettext and
thus must be wrapped in ``_()`` macro. To simplify the translation
work, the error message must not be concatenated from various
parts. To simplify searching for the error message in the code the
strings should not be broken even if they result into a line
longer than 80 columns and any formatting modifier should be
enclosed by quotes or other obvious separator. If a string used
with ``%s`` can be NULL the NULLSTR macro must be used.

::

  GOOD: virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to connect to remote host '%s'"), hostname)

  BAD: virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("Failed to %s to remote host '%s'"),
                      "connect", hostname);

  BAD: virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("Failed to connect "
                      "to remote host '%s'),
                      hostname);

Use of goto
-----------

The use of goto is not forbidden, and goto is widely used
throughout libvirt. While the uncontrolled use of goto will
quickly lead to unmaintainable code, there is a place for it in
well structured code where its use increases readability and
maintainability. In general, if goto is used for error recovery,
it's likely to be ok, otherwise, be cautious or avoid it all
together.

The typical use of goto is to jump to cleanup code in the case of
a long list of actions, any of which may fail and cause the entire
operation to fail. In this case, a function will have a single
label at the end of the function. It's almost always ok to use
this style. In particular, if the cleanup code only involves
free'ing memory, then having multiple labels is overkill. g_free()
and most of the functions named XXXFree() in libvirt is required
to handle NULL as its arg. This does not apply to libvirt's public
APIs. Thus you can safely call free on all the variables even if
they were not yet allocated (yes they have to have been
initialized to NULL). This is much simpler and clearer than having
multiple labels. Note that most of libvirt's type declarations can
be marked with either ``g_autofree`` or ``g_autoptr`` which uses
the compiler's ``__attribute__((cleanup))`` that calls the
appropriate free function when the variable goes out of scope.

There are a couple of signs that a particular use of goto is not
ok:

-  You're using multiple labels. If you find yourself using
   multiple labels, you're strongly encouraged to rework your code
   to eliminate all but one of them.
-  The goto jumps back up to a point above the current line of
   code being executed. Please use some combination of looping
   constructs to re-execute code instead; it's almost certainly
   going to be more understandable by others. One well-known
   exception to this rule is restarting an i/o operation following
   EINTR.
-  The goto jumps down to an arbitrary place in the middle of a
   function followed by further potentially failing calls. You
   should almost certainly be using a conditional and a block
   instead of a goto. Perhaps some of your function's logic would
   be better pulled out into a helper function.

Although libvirt does not encourage the Linux kernel wind/unwind
style of multiple labels, there's a good general discussion of the
issue archived at
`KernelTrap <http://kerneltrap.org/node/553/2131>`__

When using goto, please use one of these standard labels if it
makes sense:

::

  error:     A path only taken upon return with an error code
  cleanup:   A path taken upon return with success code + optional error
  no_memory: A path only taken upon return with an OOM error code
  retry:     If needing to jump upwards (e.g., retry on EINTR)

Top-level labels should be indented by one space (putting them on
the beginning of the line confuses function context detection in
git):

::

  int foo()
  {
      /* ... do stuff ... */
   cleanup:
      /* ... do other stuff ... */
  }

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
