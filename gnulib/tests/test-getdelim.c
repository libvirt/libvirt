/* Test of getdelim() function.
   Copyright (C) 2007 Free Software Foundation, Inc.

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

/* Written by Eric Blake <ebb9@byu.net>, 2007.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(expr) \
  do									     \
    {									     \
      if (!(expr))							     \
        {								     \
          fprintf (stderr, "%s:%d: assertion failed\n", __FILE__, __LINE__); \
          abort ();							     \
        }								     \
    }									     \
  while (0)

int
main (int argc, char **argv)
{
  FILE *f;
  char *line = NULL;
  size_t len = 0;
  ssize_t result;

  /* Create test file.  */
  f = fopen ("test-getdelim.txt", "wb");
  if (!f || fwrite ("anbcnd\0f", 1, 8, f) != 8 || fclose (f) != 0)
    {
      fputs ("Failed to create sample file.\n", stderr);
      remove ("test-getdelim.txt");
      return 1;
    }
  f = fopen ("test-getdelim.txt", "rb");
  if (!f)
    {
      fputs ("Failed to reopen sample file.\n", stderr);
      remove ("test-getdelim.txt");
      return 1;
    }

  /* Test initial allocation, which must include trailing NUL.  */
  result = getdelim (&line, &len, 'n', f);
  ASSERT (result == 2);
  ASSERT (strcmp (line, "an") == 0);
  ASSERT (2 < len);

  /* Test growth of buffer.  */
  free (line);
  line = malloc (1);
  len = 1;
  result = getdelim (&line, &len, 'n', f);
  ASSERT (result == 3);
  ASSERT (strcmp (line, "bcn") == 0);
  ASSERT (3 < len);

  /* Test embedded NULs and EOF behavior.  */
  result = getdelim (&line, &len, 'n', f);
  ASSERT (result == 3);
  ASSERT (memcmp (line, "d\0f", 4) == 0);
  ASSERT (3 < len);

  result = getdelim (&line, &len, 'n', f);
  ASSERT (result == -1);

  free (line);
  fclose (f);
  remove ("test-getdelim.txt");
  return 0;
}
