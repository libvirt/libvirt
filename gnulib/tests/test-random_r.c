/* Test random_r.
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define ASSERT(expr) \
  do									     \
    {									     \
      if (!(expr))							     \
        {								     \
          fprintf (stderr, "%s:%d: assertion failed\n", __FILE__, __LINE__); \
          fflush (stderr);						     \
          abort ();							     \
        }								     \
    }									     \
  while (0)

int
main ()
{
  struct random_data rand_state;
  char buf[128];
  unsigned int i;
  unsigned int n_big = 0;

  rand_state.state = NULL;
  if (initstate_r (time (NULL), buf, sizeof buf, &rand_state))
    return 1;
  for (i = 0; i < 1000; i++)
    {
      int32_t r;
      ASSERT (random_r (&rand_state, &r) == 0);
      ASSERT (0 <= r);
      if (RAND_MAX / 2 < r)
	++n_big;
    }

  /* Fail if none of the numbers were larger than RAND_MAX / 2.  */
  return !n_big;
}
