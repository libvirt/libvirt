/* Test of fseeko() function.
   Copyright (C) 2007 Free Software Foundation, Inc.

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

/* Written by Bruno Haible <bruno@clisp.org>, 2007.  */

#include <config.h>

#include <stdio.h>

/* Get off_t.  */
#include <sys/types.h>

int
main (int argc, char **argv)
{
  /* Assume stdin is seekable iff argc > 1.  */
  int expected = argc > 1 ? 0 : -1;
  /* Exit with success only if fseek/fseeko agree.  */
  int r1 = fseeko (stdin, (off_t)0, SEEK_CUR);
  int r2 = fseek (stdin, (long)0, SEEK_CUR);
  return ! (r1 == r2 && r1 == expected);
}
