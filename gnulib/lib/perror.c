/* Print a message describing error code.
   Copyright (C) 2008 Free Software Foundation, Inc.
   Written by Bruno Haible and Simon Josefsson.

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

#include <config.h>

/* Specification.  */
#include <stdio.h>

#include <errno.h>
#include <string.h>

void
perror (const char *string)
{
  const char *errno_description = strerror (errno);

  if (string != NULL && *string != '\0')
    fprintf (stderr, "%s: %s\n", string, errno_description);
  else
    fprintf (stderr, "%s\n", errno_description);
}
