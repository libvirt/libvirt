/*
 * virhostmem.h: helper APIs for host memory info
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 */

#pragma once

#include "internal.h"

int virHostMemGetStats(int cellNum,
                       virNodeMemoryStatsPtr params,
                       int *nparams,
                       unsigned int flags);
int virHostMemGetCellsFree(unsigned long long *freeMems,
                           int startCell,
                           int maxCells);
int virHostMemGetInfo(unsigned long long *mem,
                      unsigned long long *freeMem);

int virHostMemGetParameters(virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags);

int virHostMemSetParameters(virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags);

int virHostMemGetFreePages(unsigned int npages,
                           unsigned int *pages,
                           int startCell,
                           unsigned int cellCount,
                           int lastCell,
                           unsigned long long *counts);

int virHostMemAllocPages(unsigned int npages,
                         unsigned int *pageSizes,
                         unsigned long long *pageCounts,
                         int startCell,
                         unsigned int cellCount,
                         int lastCell,
                         bool add);

int virHostMemGetTHPSize(unsigned long long *size)
    G_NO_INLINE;
