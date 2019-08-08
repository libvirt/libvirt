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

#ifdef HAVE_GETUTXID
# include <utmpx.h>
#endif

#include "virhostuptime.h"
#include "virthread.h"

static unsigned long long bootTime;
static int bootTimeErrno;
static virOnceControl virHostGetBootTimeOnce = VIR_ONCE_CONTROL_INITIALIZER;

#ifdef HAVE_GETUTXID
static void
virHostGetBootTimeOnceInit(void)
{
    struct utmpx id = {.ut_type = BOOT_TIME};
    struct utmpx *res = NULL;

    if (!(res = getutxid(&id))) {
        bootTimeErrno = errno;
    } else {
        bootTime = res->ut_tv.tv_sec;
    }

    endutxent();
}

#else /* !HAVE_GETUTXID */

static void
virHostGetBootTimeOnceInit(void)
{
    bootTimeErrno = ENOSYS;
}
#endif /* HAVE_GETUTXID */

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
    if (virOnce(&virHostGetBootTimeOnce, virHostGetBootTimeOnceInit) < 0)
        return -1;

    if (bootTimeErrno) {
        errno = bootTimeErrno;
        return -1;
    }

    *when = bootTime;
    return 0;
}
