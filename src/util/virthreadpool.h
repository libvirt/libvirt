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
#include "viridentity.h"

typedef struct _virThreadPool virThreadPool;

typedef void (*virThreadPoolJobFunc)(void *jobdata, void *opaque);

virThreadPool *virThreadPoolNewFull(size_t minWorkers,
                                    size_t maxWorkers,
                                    size_t prioWorkers,
                                    virThreadPoolJobFunc func,
                                    const char *name,
                                    virIdentity *identity,
                                    void *opaque) ATTRIBUTE_NONNULL(4);

size_t virThreadPoolGetMinWorkers(virThreadPool *pool);
size_t virThreadPoolGetMaxWorkers(virThreadPool *pool);
size_t virThreadPoolGetPriorityWorkers(virThreadPool *pool);
size_t virThreadPoolGetCurrentWorkers(virThreadPool *pool);
size_t virThreadPoolGetFreeWorkers(virThreadPool *pool);
size_t virThreadPoolGetJobQueueDepth(virThreadPool *pool);

void virThreadPoolFree(virThreadPool *pool);

int virThreadPoolSendJob(virThreadPool *pool,
                         unsigned int priority,
                         void *jobdata) ATTRIBUTE_NONNULL(1)
                                        G_GNUC_WARN_UNUSED_RESULT;

int virThreadPoolSetParameters(virThreadPool *pool,
                               long long int minWorkers,
                               long long int maxWorkers,
                               long long int prioWorkers);

void virThreadPoolStop(virThreadPool *pool);
void virThreadPoolDrain(virThreadPool *pool);
