/* sockets.c --- wrappers for Windows socket functions

   Copyright (C) 2008 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Simon Josefsson */

#include <config.h>

/* This includes winsock2.h on MinGW. */
#include <sys/socket.h>

#include "sockets.h"

int
gl_sockets_startup (int version)
{
#if WINDOWS_SOCKETS
  WSADATA data;
  int err;

  err = WSAStartup (version, &data);
  if (err != 0)
    return 1;

  if (data.wVersion < version)
    return 2;
#endif

  return 0;
}

int
gl_sockets_cleanup (void)
{
#if WINDOWS_SOCKETS
  int err;

  err = WSACleanup ();
  if (err != 0)
    return 1;
#endif

  return 0;
}
