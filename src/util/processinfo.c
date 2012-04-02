/*
 * Copyright (C) 2009-2010, 2012 Red Hat, Inc.
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
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sched.h>

#include "processinfo.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#if HAVE_SCHED_GETAFFINITY

int virProcessInfoSetAffinity(pid_t pid,
                              const unsigned char *map,
                              size_t maplen,
                              int maxcpu)
{
    int i;
# ifdef CPU_ALLOC
    /* New method dynamically allocates cpu mask, allowing unlimted cpus */
    int numcpus = 1024;
    size_t masklen;
    cpu_set_t *mask;

    /* Not only may the statically allocated cpu_set_t be too small,
     * but there is no way to ask the kernel what size is large enough.
     * So you have no option but to pick a size, try, catch EINVAL,
     * enlarge, and re-try.
     *
     * http://lkml.org/lkml/2009/7/28/620
     */
realloc:
    masklen = CPU_ALLOC_SIZE(numcpus);
    mask = CPU_ALLOC(numcpus);

    if (!mask) {
        virReportOOMError();
        return -1;
    }

    CPU_ZERO_S(masklen, mask);
    for (i = 0 ; i < maxcpu ; i++) {
        if (VIR_CPU_USABLE(map, maplen, 0, i))
            CPU_SET_S(i, masklen, mask);
    }

    if (sched_setaffinity(pid, masklen, mask) < 0) {
        CPU_FREE(mask);
        if (errno == EINVAL &&
            numcpus < (1024 << 8)) { /* 262144 cpus ought to be enough for anyone */
            numcpus = numcpus << 2;
            goto realloc;
        }
        virReportSystemError(errno,
                             _("cannot set CPU affinity on process %d"), pid);
        return -1;
    }
    CPU_FREE(mask);
# else
    /* Legacy method uses a fixed size cpu mask, only allows upto 1024 cpus */
    cpu_set_t mask;

    CPU_ZERO(&mask);
    for (i = 0 ; i < maxcpu ; i++) {
        if (VIR_CPU_USABLE(map, maplen, 0, i))
            CPU_SET(i, &mask);
    }

    if (sched_setaffinity(pid, sizeof(mask), &mask) < 0) {
        virReportSystemError(errno,
                             _("cannot set CPU affinity on process %d"), pid);
        return -1;
    }
# endif

    return 0;
}

int virProcessInfoGetAffinity(pid_t pid,
                              unsigned char *map,
                              size_t maplen ATTRIBUTE_UNUSED,
                              int maxcpu)
{
    int i;
# ifdef CPU_ALLOC
    /* New method dynamically allocates cpu mask, allowing unlimted cpus */
    int numcpus = 1024;
    size_t masklen;
    cpu_set_t *mask;

    /* Not only may the statically allocated cpu_set_t be too small,
     * but there is no way to ask the kernel what size is large enough.
     * So you have no option but to pick a size, try, catch EINVAL,
     * enlarge, and re-try.
     *
     * http://lkml.org/lkml/2009/7/28/620
     */
realloc:
    masklen = CPU_ALLOC_SIZE(numcpus);
    mask = CPU_ALLOC(numcpus);

    if (!mask) {
        virReportOOMError();
        return -1;
    }

    CPU_ZERO_S(masklen, mask);
    if (sched_getaffinity(pid, masklen, mask) < 0) {
        CPU_FREE(mask);
        if (errno == EINVAL &&
            numcpus < (1024 << 8)) { /* 262144 cpus ought to be enough for anyone */
            numcpus = numcpus << 2;
            goto realloc;
        }
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        return -1;
    }

    for (i = 0 ; i < maxcpu ; i++)
        if (CPU_ISSET_S(i, masklen, mask))
            VIR_USE_CPU(map, i);
    CPU_FREE(mask);
# else
    /* Legacy method uses a fixed size cpu mask, only allows upto 1024 cpus */
    cpu_set_t mask;

    CPU_ZERO(&mask);
    if (sched_getaffinity(pid, sizeof(mask), &mask) < 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        return -1;
    }

    for (i = 0 ; i < maxcpu ; i++)
        if (CPU_ISSET(i, &mask))
            VIR_USE_CPU(map, i);
# endif

    return 0;
}

#else /* HAVE_SCHED_GETAFFINITY */

int virProcessInfoSetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                              const unsigned char *map ATTRIBUTE_UNUSED,
                              size_t maplen ATTRIBUTE_UNUSED,
                              int maxcpu ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return -1;
}

int virProcessInfoGetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                              unsigned char *map ATTRIBUTE_UNUSED,
                              size_t maplen ATTRIBUTE_UNUSED,
                              int maxcpu ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return -1;
}
#endif /* HAVE_SCHED_GETAFFINITY */
