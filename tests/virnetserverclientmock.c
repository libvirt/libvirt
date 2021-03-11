/*
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
 */

#include <config.h>

#include "rpc/virnetsocket.h"
#include "virutil.h"
#include "internal.h"

int virEventAddTimeout(int frequency G_GNUC_UNUSED,
                       virEventTimeoutCallback cb G_GNUC_UNUSED,
                       void *opaque G_GNUC_UNUSED,
                       virFreeCallback ff G_GNUC_UNUSED)
{
    return 0;
}

int virNetSocketGetUNIXIdentity(virNetSocket *sock G_GNUC_UNUSED,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid,
                                unsigned long long *timestamp)
{
    *uid = 666;
    *gid = 7337;
    *pid = 42;
    *timestamp = 12345678;
    return 0;
}

char *virGetUserName(uid_t uid G_GNUC_UNUSED)
{
    return strdup("astrochicken");
}

char *virGetGroupName(gid_t gid G_GNUC_UNUSED)
{
    return strdup("fictionalusers");
}

int virNetSocketGetSELinuxContext(virNetSocket *sock G_GNUC_UNUSED,
                                  char **context)
{
    if (!(*context = strdup("foo_u:bar_r:wizz_t:s0-s0:c0.c1023")))
        return -1;
    return 0;
}
