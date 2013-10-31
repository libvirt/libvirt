/*
 * virportallocator.h: Allocate & track TCP port allocations
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#ifndef __VIR_PORT_ALLOCATOR_H__
# define __VIR_PORT_ALLOCATOR_H__

# include "internal.h"
# include "virobject.h"

typedef struct _virPortAllocator virPortAllocator;
typedef virPortAllocator *virPortAllocatorPtr;

virPortAllocatorPtr virPortAllocatorNew(const char *name,
                                        unsigned short start,
                                        unsigned short end);

int virPortAllocatorAcquire(virPortAllocatorPtr pa,
                            unsigned short *port);

int virPortAllocatorRelease(virPortAllocatorPtr pa,
                            unsigned short port);

#endif /* __VIR_PORT_ALLOCATOR_H__ */
