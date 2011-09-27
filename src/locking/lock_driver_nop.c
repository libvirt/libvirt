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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "lock_driver_nop.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"


static int virLockManagerNopInit(unsigned int version ATTRIBUTE_UNUSED,
                                 const char *configFile ATTRIBUTE_UNUSED,
                                 unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("version=%u configFile=%s flags=%x",
              version, NULLSTR(configFile), flags_unused);

    return 0;
}

static int virLockManagerNopDeinit(void)
{
    VIR_DEBUG(" ");

    return 0;
}


static int virLockManagerNopNew(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                unsigned int type ATTRIBUTE_UNUSED,
                                size_t nparams ATTRIBUTE_UNUSED,
                                virLockManagerParamPtr params ATTRIBUTE_UNUSED,
                                unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virLockManagerNopAddResource(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                        unsigned int type ATTRIBUTE_UNUSED,
                                        const char *name ATTRIBUTE_UNUSED,
                                        size_t nparams ATTRIBUTE_UNUSED,
                                        virLockManagerParamPtr params ATTRIBUTE_UNUSED,
                                        unsigned int flags_unused ATTRIBUTE_UNUSED)
{

    return 0;
}


static int virLockManagerNopAcquire(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                    const char *state ATTRIBUTE_UNUSED,
                                    unsigned int flags_unused ATTRIBUTE_UNUSED,
                                    int *fd ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virLockManagerNopRelease(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                    char **state,
                                    unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    if (state)
        *state = NULL;

    return 0;
}

static int virLockManagerNopInquire(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                    char **state,
                                    unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    if (state)
        *state = NULL;

    return 0;
}

static void virLockManagerNopFree(virLockManagerPtr lock ATTRIBUTE_UNUSED)
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
