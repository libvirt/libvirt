/* A GNU-like <stdlib.h>.

   Copyright (C) 1995, 2001-2004, 2006-2008 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#if defined __need_malloc_and_calloc
/* Special invocation convention inside glibc header files.  */

#@INCLUDE_NEXT@ @NEXT_STDLIB_H@

#else
/* Normal invocation convention.  */

#ifndef _GL_STDLIB_H

/* The include_next requires a split double-inclusion guard.  */
#@INCLUDE_NEXT@ @NEXT_STDLIB_H@

#ifndef _GL_STDLIB_H
#define _GL_STDLIB_H


/* The definition of GL_LINK_WARNING is copied here.  */


/* Some systems do not define EXIT_*, despite otherwise supporting C89.  */
#ifndef EXIT_SUCCESS
# define EXIT_SUCCESS 0
#endif
/* Tandem/NSK and other platforms that define EXIT_FAILURE as -1 interfere
   with proper operation of xargs.  */
#ifndef EXIT_FAILURE
# define EXIT_FAILURE 1
#elif EXIT_FAILURE != 1
# undef EXIT_FAILURE
# define EXIT_FAILURE 1
#endif


#ifdef __cplusplus
extern "C" {
#endif


#if @GNULIB_MALLOC_POSIX@
# if !@HAVE_MALLOC_POSIX@
#  undef malloc
#  define malloc rpl_malloc
extern void * malloc (size_t size);
# endif
#elif defined GNULIB_POSIXCHECK
# undef malloc
# define malloc(s) \
    (GL_LINK_WARNING ("malloc is not POSIX compliant everywhere - " \
                      "use gnulib module malloc-posix for portability"), \
     malloc (s))
#endif


#if @GNULIB_REALLOC_POSIX@
# if !@HAVE_REALLOC_POSIX@
#  undef realloc
#  define realloc rpl_realloc
extern void * realloc (void *ptr, size_t size);
# endif
#elif defined GNULIB_POSIXCHECK
# undef realloc
# define realloc(p,s) \
    (GL_LINK_WARNING ("realloc is not POSIX compliant everywhere - " \
                      "use gnulib module realloc-posix for portability"), \
     realloc (p, s))
#endif


#if @GNULIB_CALLOC_POSIX@
# if !@HAVE_CALLOC_POSIX@
#  undef calloc
#  define calloc rpl_calloc
extern void * calloc (size_t nmemb, size_t size);
# endif
#elif defined GNULIB_POSIXCHECK
# undef calloc
# define calloc(n,s) \
    (GL_LINK_WARNING ("calloc is not POSIX compliant everywhere - " \
                      "use gnulib module calloc-posix for portability"), \
     calloc (n, s))
#endif


#if @GNULIB_GETSUBOPT@
/* Assuming *OPTIONP is a comma separated list of elements of the form
   "token" or "token=value", getsubopt parses the first of these elements.
   If the first element refers to a "token" that is member of the given
   NULL-terminated array of tokens:
     - It replaces the comma with a NUL byte, updates *OPTIONP to point past
       the first option and the comma, sets *VALUEP to the value of the
       element (or NULL if it doesn't contain an "=" sign),
     - It returns the index of the "token" in the given array of tokens.
   Otherwise it returns -1, and *OPTIONP and *VALUEP are undefined.
   For more details see the POSIX:2001 specification.
   http://www.opengroup.org/susv3xsh/getsubopt.html */
# if !@HAVE_GETSUBOPT@
extern int getsubopt (char **optionp, char *const *tokens, char **valuep);
# endif
#elif defined GNULIB_POSIXCHECK
# undef getsubopt
# define getsubopt(o,t,v) \
    (GL_LINK_WARNING ("getsubopt is unportable - " \
                      "use gnulib module getsubopt for portability"), \
     getsubopt (o, t, v))
#endif


#if @GNULIB_MKDTEMP@
# if !@HAVE_MKDTEMP@
/* Create a unique temporary directory from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the directory name unique.
   Returns TEMPLATE, or a null pointer if it cannot get a unique name.
   The directory is created mode 700.  */
extern char * mkdtemp (char * /*template*/);
# endif
#elif defined GNULIB_POSIXCHECK
# undef mkdtemp
# define mkdtemp(t) \
    (GL_LINK_WARNING ("mkdtemp is unportable - " \
                      "use gnulib module mkdtemp for portability"), \
     mkdtemp (t))
#endif


#if @GNULIB_MKSTEMP@
# if @REPLACE_MKSTEMP@
/* Create a unique temporary file from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   The file is then created, ensuring it didn't exist before.
   The file is created read-write (mask at least 0600 & ~umask), but it may be
   world-readable and world-writable (mask 0666 & ~umask), depending on the
   implementation.
   Returns the open file descriptor if successful, otherwise -1 and errno
   set.  */
#  define mkstemp rpl_mkstemp
extern int mkstemp (char * /*template*/);
# else
/* On MacOS X 10.3, only <unistd.h> declares mkstemp.  */
#  include <unistd.h>
# endif
#elif defined GNULIB_POSIXCHECK
# undef mkstemp
# define mkstemp(t) \
    (GL_LINK_WARNING ("mkstemp is unportable - " \
                      "use gnulib module mkstemp for portability"), \
     mkstemp (t))
#endif


#if @GNULIB_PUTENV@
# if @REPLACE_PUTENV@
#  undef putenv
#  define putenv rpl_putenv
extern int putenv (char *string);
# endif
#endif


#if @GNULIB_RPMATCH@
# if !@HAVE_RPMATCH@
/* Test a user response to a question.
   Return 1 if it is affirmative, 0 if it is negative, or -1 if not clear.  */
extern int rpmatch (const char *response);
# endif
#elif defined GNULIB_POSIXCHECK
# undef rpmatch
# define rpmatch(r) \
    (GL_LINK_WARNING ("rpmatch is unportable - " \
                      "use gnulib module rpmatch for portability"), \
     rpmatch (r))
#endif


#if @GNULIB_SETENV@
# if !@HAVE_SETENV@
/* Set NAME to VALUE in the environment.
   If REPLACE is nonzero, overwrite an existing value.  */
extern int setenv (const char *name, const char *value, int replace);
# endif
#endif


#if @GNULIB_UNSETENV@
# if @HAVE_UNSETENV@
#  if @VOID_UNSETENV@
/* On some systems, unsetenv() returns void.
   This is the case for MacOS X 10.3, FreeBSD 4.8, NetBSD 1.6, OpenBSD 3.4.  */
#   define unsetenv(name) ((unsetenv)(name), 0)
#  endif
# else
/* Remove the variable NAME from the environment.  */
extern int unsetenv (const char *name);
# endif
#endif


#if @GNULIB_STRTOD@
# if @REPLACE_STRTOD@
#  define strtod rpl_strtod
# endif
# if !@HAVE_STRTOD@ || @REPLACE_STRTOD@
 /* Parse a double from STRING, updating ENDP if appropriate.  */
extern double strtod (const char *str, char **endp);
# endif
#elif defined GNULIB_POSIXCHECK
# undef strtod
# define strtod(s, e)                           \
    (GL_LINK_WARNING ("strtod is unportable - " \
                      "use gnulib module strtod for portability"), \
     strtod (s, e))
#endif


#ifdef __cplusplus
}
#endif

#endif /* _GL_STDLIB_H */
#endif /* _GL_STDLIB_H */
#endif
