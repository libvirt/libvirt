/*
 * virhostuptime.c: helper APIs for host uptime
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#ifdef WITH_GETUTXID
# include <utmpx.h>
#endif

#include "virhostuptime.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virthread.h"

#include <math.h>

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.virhostuptime");

static unsigned long long bootTime;
static int bootTimeErrno;
static virOnceControl virHostGetBootTimeOnce = VIR_ONCE_CONTROL_INITIALIZER;

#if defined(__linux__)
# define UPTIME_FILE  "/proc/uptime"
static int
virHostGetBootTimeProcfs(unsigned long long *btime)
{
    unsigned long long now;
    double up;
    g_autofree char *buf = NULL;
    char *tmp;

    if (virTimeMillisNow(&now) < 0)
        return -errno;

    /* 1KiB limit is more than enough. */
    if (virFileReadAll(UPTIME_FILE, 1024, &buf) < 0)
        return -errno;

    /* buf contains two doubles now:
     *   $uptime $idle_time
     * We're interested only in the first one */
    if (!(tmp = strchr(buf, ' '))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("uptime file has unexpected format '%1$s'"),
                       buf);
        return -EINVAL;
    }

    *tmp = '\0';

    if (virStrToDouble(buf, NULL, &up) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse uptime value '%1$s'"),
                       buf);
        return -EINVAL;
    }

    *btime = llround(now / 1000 - up);

    return 0;
}
#endif /* defined(__linux__) */

#if defined(WITH_GETUTXID) || defined(__linux__)
static void
virHostGetBootTimeOnceInit(void)
{
# ifdef WITH_GETUTXID
    struct utmpx id = {.ut_type = BOOT_TIME};
    struct utmpx *res = NULL;

    if (!(res = getutxid(&id))) {
        bootTimeErrno = errno;
    } else {
        bootTime = res->ut_tv.tv_sec;
    }

    endutxent();
# endif /* WITH_GETUTXID */

# ifdef __linux__
    if (bootTimeErrno != 0 || bootTime == 0)
        bootTimeErrno = -virHostGetBootTimeProcfs(&bootTime);
# endif /* __linux__ */
}

#else /* !defined(WITH_GETUTXID) && !defined(__linux__) */

static void
virHostGetBootTimeOnceInit(void)
{
    bootTimeErrno = ENOSYS;
}
#endif /* !defined(WITH_GETUTXID) && !defined(__linux__) */

/**
 * virHostGetBootTime:
 * @when: UNIX timestamp of boot time
 *
 * Get a UNIX timestamp of host boot time and store it at @when.
 *
 * Return: 0 on success,
 *        -1 otherwise.
 */
int
virHostGetBootTime(unsigned long long *when)
{
    if (virHostBootTimeInit() < 0)
        return -1;

    if (bootTimeErrno) {
        errno = bootTimeErrno;
        return -1;
    }

    *when = bootTime;
    return 0;
}


int
virHostBootTimeInit(void)
{
    if (virOnce(&virHostGetBootTimeOnce, virHostGetBootTimeOnceInit) < 0)
        return -1;

    return 0;
}
