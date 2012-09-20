/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
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

#include <selinux/selinux.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
/*
 * The kernel policy will not allow us to arbitrarily change
 * test process context. This helper is used as an LD_PRELOAD
 * so that the libvirt code /thinks/ it is changing/reading
 * the process context, where as in fact we're faking it all
 */

int getcon(security_context_t *context)
{
    if (getenv("FAKE_CONTEXT") == NULL) {
        *context = NULL;
        errno = EINVAL;
        return -1;
    }
    if (!(*context = strdup(getenv("FAKE_CONTEXT"))))
        return -1;
    return 0;
}

int getpidcon(pid_t pid, security_context_t *context)
{
    if (pid != getpid()) {
        *context = NULL;
        errno = ESRCH;
        return -1;
    }
    if (getenv("FAKE_CONTEXT") == NULL) {
        *context = NULL;
        errno = EINVAL;
        return -1;
    }
    if (!(*context = strdup(getenv("FAKE_CONTEXT"))))
        return -1;
    return 0;
}

int setcon(security_context_t context)
{
    return setenv("FAKE_CONTEXT", context, 1);
}
