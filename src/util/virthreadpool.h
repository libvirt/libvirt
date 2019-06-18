/*
 * virthreadpool.h: a generic thread pool implementation
 *
 * Copyright (C) 2010 Hu Tao
 * Copyright (C) 2010 Daniel P. Berrange
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

typedef struct _virThreadPool virThreadPool;
typedef virThreadPool *virThreadPoolPtr;

typedef void (*virThreadPoolJobFunc)(void *jobdata, void *opaque);

#define virThreadPoolNew(min, max, prio, func, opaque) \
    virThreadPoolNewFull(min, max, prio, func, #func, opaque)

virThreadPoolPtr virThreadPoolNewFull(size_t minWorkers,
                                      size_t maxWorkers,
                                      size_t prioWorkers,
                                      virThreadPoolJobFunc func,
                                      const char *funcName,
                                      void *opaque) ATTRIBUTE_NONNULL(4);

size_t virThreadPoolGetMinWorkers(virThreadPoolPtr pool);
size_t virThreadPoolGetMaxWorkers(virThreadPoolPtr pool);
size_t virThreadPoolGetPriorityWorkers(virThreadPoolPtr pool);
size_t virThreadPoolGetCurrentWorkers(virThreadPoolPtr pool);
size_t virThreadPoolGetFreeWorkers(virThreadPoolPtr pool);
size_t virThreadPoolGetJobQueueDepth(virThreadPoolPtr pool);

void virThreadPoolFree(virThreadPoolPtr pool);

int virThreadPoolSendJob(virThreadPoolPtr pool,
                         unsigned int priority,
                         void *jobdata) ATTRIBUTE_NONNULL(1)
                                        ATTRIBUTE_RETURN_CHECK;

int virThreadPoolSetParameters(virThreadPoolPtr pool,
                               long long int minWorkers,
                               long long int maxWorkers,
                               long long int prioWorkers);
