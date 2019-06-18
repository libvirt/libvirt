/*
 * virnuma.h: helper APIs for managing numa
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
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

#pragma once

#include "internal.h"
#include "virbitmap.h"
#include "virutil.h"


char *virNumaGetAutoPlacementAdvice(unsigned short vcpus,
                                    unsigned long long balloon);

int virNumaSetupMemoryPolicy(virDomainNumatuneMemMode mode,
                             virBitmapPtr nodeset);

virBitmapPtr virNumaGetHostMemoryNodeset(void);
bool virNumaNodesetIsAvailable(virBitmapPtr nodeset) ATTRIBUTE_NOINLINE;
bool virNumaIsAvailable(void) ATTRIBUTE_NOINLINE;
int virNumaGetMaxNode(void) ATTRIBUTE_NOINLINE;
bool virNumaNodeIsAvailable(int node) ATTRIBUTE_NOINLINE;
int virNumaGetDistances(int node,
                        int **distances,
                        int *ndistances) ATTRIBUTE_NOINLINE;
int virNumaGetNodeMemory(int node,
                         unsigned long long *memsize,
                         unsigned long long *memfree) ATTRIBUTE_NOINLINE;

unsigned int virNumaGetMaxCPUs(void);

int virNumaGetNodeCPUs(int node, virBitmapPtr *cpus) ATTRIBUTE_NOINLINE;
int virNumaNodesetToCPUset(virBitmapPtr nodeset,
                           virBitmapPtr *cpuset);

int virNumaGetPageInfo(int node,
                       unsigned int page_size,
                       unsigned long long huge_page_sum,
                       unsigned long long *page_avail,
                       unsigned long long *page_free);
int virNumaGetPages(int node,
                    unsigned int **pages_size,
                    unsigned long long **pages_avail,
                    unsigned long long **pages_free,
                    size_t *npages)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_NOINLINE;
int virNumaSetPagePoolSize(int node,
                           unsigned int page_size,
                           unsigned long long page_count,
                           bool add);
