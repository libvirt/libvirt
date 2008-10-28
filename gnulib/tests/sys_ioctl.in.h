/* Substitute for and wrapper around <sys/ioctl.h>.
   Copyright (C) 2008 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _GL_SYS_IOCTL_H

#if __GNUC__ >= 3
@PRAGMA_SYSTEM_HEADER@
#endif

/* The include_next requires a split double-inclusion guard.  */
#if @HAVE_SYS_IOCTL_H@
# @INCLUDE_NEXT@ @NEXT_SYS_IOCTL_H@
#endif

#ifndef _GL_SYS_IOCTL_H
#define _GL_SYS_IOCTL_H

/* AIX 5.1 and Solaris 10 declare ioctl() in <unistd.h> and in <stropts.h>,
   but not in <sys/ioctl.h>.  */
#include <unistd.h>

/* The definition of GL_LINK_WARNING is copied here.  */


/* Declare overridden functions.  */

#ifdef __cplusplus
extern "C" {
#endif


#if @GNULIB_IOCTL@
# if @SYS_IOCTL_H_HAVE_WINSOCK2_H@
#  undef ioctl
#  define ioctl rpl_ioctl
extern int ioctl (int fd, int request, ... /* {void *,char *} arg */);
# endif
#elif @SYS_IOCTL_H_HAVE_WINSOCK2_H@
# undef ioctl
# define ioctl ioctl_used_without_requesting_gnulib_module_ioctl
#elif defined GNULIB_POSIXCHECK
# undef ioctl
# define ioctl(f,c,a) \
    (GL_LINK_WARNING ("ioctl does not portably work on sockets - " \
                      "use gnulib module ioctl for portability"), \
     ioctl (f, c, a))
#endif


#ifdef __cplusplus
}
#endif


#endif /* _GL_SYS_IOCTL_H */
#endif /* _GL_SYS_IOCTL_H */
