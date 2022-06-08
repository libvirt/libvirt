/*
 * lock_driver_nop.c: A lock driver which locks nothing
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include "lock_driver_nop.h"
#include "virlog.h"

VIR_LOG_INIT("locking.lock_driver_nop");


static int virLockManagerNopInit(unsigned int version G_GNUC_UNUSED,
                                 const char *configFile G_GNUC_UNUSED,
                                 unsigned int flags_unused G_GNUC_UNUSED)
{
    VIR_DEBUG("version=%u configFile=%s flags=0x%x",
              version, NULLSTR(configFile), flags_unused);

    return 0;
}

static int virLockManagerNopDeinit(void)
{
    VIR_DEBUG(" ");

    return 0;
}


static int virLockManagerNopNew(virLockManager *lock G_GNUC_UNUSED,
                                unsigned int type G_GNUC_UNUSED,
                                size_t nparams G_GNUC_UNUSED,
                                virLockManagerParam *params G_GNUC_UNUSED,
                                unsigned int flags_unused G_GNUC_UNUSED)
{
    return 0;
}

static int virLockManagerNopAddResource(virLockManager *lock G_GNUC_UNUSED,
                                        unsigned int type G_GNUC_UNUSED,
                                        const char *name G_GNUC_UNUSED,
                                        size_t nparams G_GNUC_UNUSED,
                                        virLockManagerParam *params G_GNUC_UNUSED,
                                        unsigned int flags_unused G_GNUC_UNUSED)
{
    return 0;
}


static int virLockManagerNopAcquire(virLockManager *lock G_GNUC_UNUSED,
                                    const char *state G_GNUC_UNUSED,
                                    unsigned int flags_unused G_GNUC_UNUSED,
                                    virDomainLockFailureAction action G_GNUC_UNUSED,
                                    int *fd G_GNUC_UNUSED)
{
    return 0;
}

static int virLockManagerNopRelease(virLockManager *lock G_GNUC_UNUSED,
                                    char **state,
                                    unsigned int flags_unused G_GNUC_UNUSED)
{
    if (state)
        *state = NULL;

    return 0;
}

static int virLockManagerNopInquire(virLockManager *lock G_GNUC_UNUSED,
                                    char **state,
                                    unsigned int flags_unused G_GNUC_UNUSED)
{
    if (state)
        *state = NULL;

    return 0;
}

static void virLockManagerNopFree(virLockManager *lock G_GNUC_UNUSED)
{
}

virLockDriver virLockDriverNop =
{
    .version = VIR_LOCK_MANAGER_VERSION,
    .flags = 0,

    .drvInit = virLockManagerNopInit,
    .drvDeinit = virLockManagerNopDeinit,

    .drvNew = virLockManagerNopNew,
    .drvFree = virLockManagerNopFree,

    .drvAddResource = virLockManagerNopAddResource,

    .drvAcquire = virLockManagerNopAcquire,
    .drvRelease = virLockManagerNopRelease,

    .drvInquire = virLockManagerNopInquire,
};
