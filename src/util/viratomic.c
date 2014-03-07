/*
 * viratomic.c: atomic integer operations
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * Based on code taken from GLib 2.32, under the LGPLv2+
 *
 * Copyright (C) 2011 Ryan Lortie
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "viratomic.h"


#ifdef VIR_ATOMIC_OPS_PTHREAD

pthread_mutex_t virAtomicLock = PTHREAD_MUTEX_INITIALIZER;

#endif
