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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "rpc/virnetsocket.h"
#include "virutil.h"
#include "internal.h"

int virEventAddTimeout(int frequency ATTRIBUTE_UNUSED,
                       virEventTimeoutCallback cb ATTRIBUTE_UNUSED,
                       void *opaque ATTRIBUTE_UNUSED,
                       virFreeCallback ff ATTRIBUTE_UNUSED)
{
    return 0;
}

int virNetSocketGetUNIXIdentity(virNetSocketPtr sock ATTRIBUTE_UNUSED,
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

char *virGetUserName(uid_t uid ATTRIBUTE_UNUSED)
{
    return strdup("astrochicken");
}

char *virGetGroupName(gid_t gid ATTRIBUTE_UNUSED)
{
    return strdup("fictionalusers");
}

int virNetSocketGetSELinuxContext(virNetSocketPtr sock ATTRIBUTE_UNUSED,
                                  char **context)
{
    if (!(*context = strdup("foo_u:bar_r:wizz_t:s0-s0:c0.c1023")))
        return -1;
    return 0;
}
