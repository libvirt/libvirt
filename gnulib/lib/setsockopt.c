/* setsockopt.c --- wrappers for Windows setsockopt function

   Copyright (C) 2008 Free Software Foundation, Inc.

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

/* Written by Paolo Bonzini */

#include <config.h>

#define WIN32_LEAN_AND_MEAN
/* Get winsock2.h. */
#include <sys/socket.h>

/* Get set_winsock_errno, FD_TO_SOCKET etc. */
#include "w32sock.h"

#undef setsockopt

int
rpl_setsockopt (int fd, int level, int optname, const void *optval, int optlen)
{
  SOCKET sock = FD_TO_SOCKET (fd);
  int r = setsockopt (sock, level, optname, optval, optlen);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
