/*
 * threads.c: basic thread synchronization primitives
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "threads.h"

/* On mingw, we prefer native threading over the sometimes-broken
 * pthreads-win32 library wrapper.  */
#ifdef WIN32
# include "threads-win32.c"
#elif defined HAVE_PTHREAD_MUTEXATTR_INIT
# include "threads-pthread.c"
#else
# error "Either pthreads or Win32 threads are required"
#endif
