============
Coding style
============

.. contents::

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
   name with a leading underscore. For types that are part of the
   public API, a second typedef should be given for a pointer to
   the struct with a 'Ptr' suffix. Do not introduce new such
   typedefs for internal types.

   ::

     typedef struct _virSomeType virSomeType;
     typedef virSomeType *virSomeTypePtr;
     struct _virSomeType {
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
   given an object 'virSomeType', all functions should have a
   name 'virSomeType$VERB' or 'virSomeType$VERB$SUBJECT", e.g.
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
https://www.vim.org/scripts/script.php?script_id=1408, which will
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
    indent -bad -bap -bbb -bli4 -br -ce -brs -cs -i4 -l100 -lc100 \
           -sbi4 -psl -saf -sai -saw -sbi4 -ss -sc -cdw -cli4 -npcs -nbc \
           --no-tabs "$@"
  }

Note that sometimes you'll have to post-process that output
further, by piping it through ``expand -i``, since some leading
TABs can get through. Usually they're in macro definitions or
strings, and should be converted anyhow.

The maximum permitted line length is 100 characters, but lines
should aim to be approximately 80 characters.

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

  if(foo)   /* Bad */
  if (foo)  /* Good */

Function implementations must **not** have any whitespace between
the function name and the opening bracket. E.g.

::

  int foo (int wizz)  /* Bad */
  int foo(int wizz)   /* Good */

Function calls must **not** have any whitespace between the
function name and the opening bracket. E.g.

::

  bar = foo (wizz);  /* Bad */
  bar = foo(wizz);   /* Good */

Function typedefs must **not** have any whitespace between the
closing bracket of the function name and opening bracket of the
arg list. E.g.

::

  typedef int (*foo) (int wizz);  /* Bad */
  typedef int (*foo)(int wizz);   /* Good */

There must not be any whitespace immediately following any opening
bracket, or immediately prior to any closing bracket. E.g.

::

  int foo( int wizz );  /* Bad */
  int foo(int wizz);    /* Good */

Commas
------

Commas should always be followed by a space or end of line, and
never have leading space; this is enforced during 'make
syntax-check'.

::

  call(a,b ,c);     /* Bad */
  call(a, b, c);    /* Good */

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
      VALUE_TWO     /* Bad */
  };
  enum {
      VALUE_THREE,
      VALUE_FOUR,   /* Good */
  };

Semicolons
----------

Semicolons should never have a space beforehand. Inside the
condition of a ``for`` loop, there should always be a space or
line break after each semicolon, except for the special case of an
infinite loop (although more infinite loops use ``while``). While
not enforced, loop counters generally use post-increment.

::

  for (i = 0 ;i < limit ; ++i) {    /* Bad */
  for (i = 0; i < limit; i++) {     /* Good */
  for (;;) {                        /* ok */
  while (1) {                       /* Better */

Empty loop bodies are better represented with curly braces and a
comment, although use of a semicolon is not currently rejected.

::

  while ((rc = waitpid(pid, &st, 0) == -1) &&
         errno == EINTR);           /* ok */
  while ((rc = waitpid(pid, &st, 0) == -1) &&
         errno == EINTR) {          /* Better */
      /* nothing */
  }

Curly braces
------------

Curly braces around an ``if``, ``while``, ``for`` etc. can be omitted if the
body and the condition itself occupy only a single line.
In every other case we require the braces. This
ensures that it is trivially easy to identify a
single-\ *statement* loop: each has only one *line* in its body.

::

  while (expr)              /* single line body; {} is optional */
      single_line_stmt();

::

  while (expr(arg1,
              arg2))        /* indentation makes it obvious it is single line, */
      single_line_stmt();   /* {} is optional (not enforced either way) */

::

  while (expr1 &&
         expr2) {           /* multi-line, at same indentation, {} required */
      single_line_stmt();
  }

However, the moment your loop/if/else body extends on to a second
line, for whatever reason (even if it's just an added comment),
then you should add braces. Otherwise, it would be too easy to
insert a statement just before that comment (without adding
braces), thinking it is already a multi-statement loop:

::

  while (true)              /* BAD! multi-line body with no braces */
      /* comment... */
      single_line_stmt();

Do this instead:

::

  while (true) {            /* Always put braces around a multi-line body. */
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

  if (expr)                 /* BAD: no braces around... */
      while (expr_2) {      /* ... a multi-line body */
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
      x = y;    /* BAD: braceless "else" with braced "then",
                 * and short block last */

  if (expr)
      x = y;    /* BAD: braceless "if" with braced "else" */
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
    x = y;      /* putting the smaller block first is more readable */
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
  {                          /* correct - function body */
      int 2d[][] = {
        {                    /* correct - complex initialization */
          1, 2,
        },
      };
      if (a)
      {                      /* BAD: compound brace on its own line */
          do_stuff();
      }
      {                      /* correct - nested scope */
          int tmp;
          if (a < b) {       /* correct - hanging brace */
              tmp = b;
              b = a;
              a = tmp;
          }
      }
  }

Conditional expressions
-----------------------

For readability reasons new code should avoid shortening
comparisons to 0 for numeric types:

::

  size nfoos = 0;

  GOOD:
    if (nfoos != 0)
    if (nfoos == 0)

  BAD:
    if (nfoos)
    if (!nfoos)

Prefer the shortened version for boolean values. Boolean values
should never be compared against the literal ``true``, as a
logical non-false value need not be ``1``.

::

  bool hasFoos = false;

  GOOD:
    if (hasFoos)
    if (!hasFoos)

  BAD:
    if (hasFoos == true)
    if (hasFoos != false)
    if (hasFoos == false)
    if (hasFoos != true)

Pointer comparisons may be shortened. All long forms are okay.

::

  virFoo *foo = NULL;

  GOOD:
    if (foo)                 # or: if (foo != NULL)
    if (!foo)                # or: if (foo == NULL)

New code should avoid the ternary operator as much as possible.
Its usage in basic cases is warranted (e.g. when deciding between
two constant strings), however, it must never span more than one
line or nest.

::

  BAD:
    char *foo = baz ?
                virDoSomethingReallyComplex(driver, vm, something, baz->foo) :
                NULL;

    char *foo = bar ? bar->baz ? bar->baz->foo : "nobaz" : "nobar";

  GOOD:
    virBufferAsprintf(buf, "<element>%s</element>\n", boolVar ? "yes" : "no");

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

  #if defined(WITH_POSIX_FALLOCATE) && !defined(WITH_FALLOCATE)
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
-  While using ``bool`` is good for readability, it comes with a
   minor caveat: Don't use ``bool`` in places where the type size
   must be constant across all systems, like public interfaces and
   on-the-wire protocols. Note that it would be possible (albeit
   wasteful) to use ``bool`` in libvirt's logical wire protocol,
   since XDR maps that to its lower-level ``bool_t`` type, which
   **is** fixed-size.

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

Defining Local Variables
------------------------

Always define local variables at the top of the block in which they
are used (before any pure code). Although modern C compilers allow
defining a local variable in the middle of a block of code, this
practice can lead to bugs, and must be avoided in all libvirt
code. As indicated in these examples, it is okay to initialize
variables where they are defined, even if the initialization involves
calling another function.

::

  GOOD:
    int
    bob(char *loblaw)
    {
        int x;
        int y = lawBlog();
        char *z = NULL;

        x = y + 20;
        ...
    }

  BAD:
    int
    bob(char *loblaw)
    {
        int x;
        int y = lawBlog();

        x = y + 20;

        char *z = NULL; /* <=== */
        ...
    }

Prefer variable definitions on separate lines. This allows for smaller,
easier to understand diffs when changing them. Define variables in the
smallest possible scope.

::

  GOOD:
    int count = 0;
    int nnodes;

  BAD:
    int count = 0, nnodes;

Attribute annotations
---------------------

Use the following annotations to help the compiler and/or static
analysis tools understand the code better:

``ATTRIBUTE_NONNULL``
   passing NULL for this parameter is not allowed

``ATTRIBUTE_PACKED``
   force a structure to be packed

``G_GNUC_FALLTHROUGH``
   allow code reuse by multiple switch cases

``G_NO_INLINE``
   the function is mocked in the test suite

``G_GNUC_NORETURN``
   the function never returns

``G_GNUC_NULL_TERMINATED``
   last parameter must be NULL

``G_GNUC_PRINTF``
   validate that the formatting string matches parameters

``G_GNUC_UNUSED``
   parameter is unused in this implementation of the function

``G_GNUC_WARN_UNUSED_RESULT``
   the return value must be checked

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

     STREQ(a, b)
     STRNEQ(a, b)

-  For case insensitive equality:

   ::

     STRCASEEQ(a, b)
     STRCASENEQ(a, b)

-  For strict equality of a substring:

   ::

     STREQLEN(a, b, n)
     STRNEQLEN(a, b, n)

-  For case insensitive equality of a substring:

   ::

     STRCASEEQLEN(a, b, n)
     STRCASENEQLEN(a, b, n)

-  For strict equality of a prefix:

   ::

     STRPREFIX(a, b)

-  For case insensitive equality of a prefix:

   ::

     STRCASEPREFIX(a, b)

-  For skipping prefix:

   ::

     /* Instead of:
      *   STRPREFIX(a, b) ? a + strlen(b) : NULL
      * use: */
     STRSKIP(a, b)

-  For skipping prefix case insensitively:

   ::

     /* Instead of:
      *   STRCASEPREFIX(a, b) ? a + strlen(b) : NULL
      * use: */
     STRCASESKIP(a, b)

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

  void virCommandAddEnvFormat(virCommand *cmd, const char *format, ...)
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
parts and all format strings must be permutable by directly
addressing each argument using ``%N$...`` syntax. For example,
``%1$s``, ``%2$llu`` or ``%4$s`` to format the first argument as
string, the second argument as unsigned long long, and the fourth
argument as string, respectively. To simplify searching for the error
message in the code the strings should not be broken even if they
result into a line longer than 80 columns and any formatting modifier
should be enclosed by quotes or other obvious separator. If a string
used with ``%N$s`` can be NULL the NULLSTR macro must be used.

::

  GOOD: virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to connect to remote host '%1$s'"), hostname)

  BAD: virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("Failed to %1$s to remote host '%2$s'"),
                      "connect", hostname);

  BAD: virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("Failed to connect "
                      "to remote host '%1$s'),
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
`KernelTrap <https://web.archive.org/web/20130521051957/http://kerneltrap.org/node/553/2131>`__

When using goto, please use one of these standard labels if it
makes sense:

::

  error:     A path only taken upon return with an error code
  cleanup:   A path taken upon return with success code + optional error
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


XML element and attribute naming
--------------------------------

New elements and/or attributes should be short and descriptive.
In general, they should reflect what the feature does instead of
how exactly it is named in given hypervisor because this creates
an abstraction that other drivers can benefit from (for instance
if the same feature is named differently in two hypervisors).
That is not to say an element or attribute can't have the same
name as in a hypervisor, but proceed with caution.

Single worded names are preferred, but if more words must be
used then they shall be joined in camelCase style.
