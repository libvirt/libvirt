/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
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

/* This file is only compiled on Linux, and only if xattr support was
 * detected. */

#include <dlfcn.h>
#include <errno.h>
#if HAVE_LINUX_MAGIC_H
# include <linux/magic.h>
#endif
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <attr/xattr.h>

#ifndef NFS_SUPER_MAGIC
# define NFS_SUPER_MAGIC 0x6969
#endif

#include "virstring.h"

static int (*realstatfs)(const char *path, struct statfs *buf);
static int (*realsecurity_get_boolean_active)(const char *name);

static void init_syms(void)
{
    if (realstatfs)
        return;

#define LOAD_SYM(name)                                                  \
    do {                                                                \
        if (!(real ## name = dlsym(RTLD_NEXT, #name))) {                \
            fprintf(stderr, "Cannot find real '%s' symbol\n", #name);   \
            abort();                                                    \
        }                                                               \
    } while (0)

    LOAD_SYM(statfs);
    LOAD_SYM(security_get_boolean_active);

#undef LOAD_SYM
}


/*
 * The kernel policy will not allow us to arbitrarily change
 * test process context. This helper is used as an LD_PRELOAD
 * so that the libvirt code /thinks/ it is changing/reading
 * the process context, whereas in fact we're faking it all.
 * Furthermore, we fake out that we are using an nfs subdirectory,
 * where we control whether selinux is enforcing and whether
 * the virt_use_nfs bool is set.
 */

int getcon_raw(security_context_t *context)
{
    if (getenv("FAKE_CONTEXT") == NULL) {
        *context = NULL;
        errno = EINVAL;
        return -1;
    }
    return VIR_STRDUP_QUIET(*context, getenv("FAKE_CONTEXT"));
}

int getcon(security_context_t *context)
{
    return getcon_raw(context);
}

int getpidcon_raw(pid_t pid, security_context_t *context)
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
    return VIR_STRDUP_QUIET(*context, getenv("FAKE_CONTEXT"));
}

int getpidcon(pid_t pid, security_context_t *context)
{
    return getpidcon_raw(pid, context);
}

int setcon_raw(security_context_t context)
{
    return setenv("FAKE_CONTEXT", context, 1);
}

int setcon(security_context_t context)
{
    return setcon_raw(context);
}


int setfilecon_raw(const char *path, security_context_t con)
{
    const char *constr = con;
    if (STRPREFIX(path, abs_builddir "/securityselinuxlabeldata/nfs/")) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return setxattr(path, "user.libvirt.selinux",
                    constr, strlen(constr), 0);
}

int setfilecon(const char *path, security_context_t con)
{
    return setfilecon_raw(path, con);
}

int getfilecon_raw(const char *path, security_context_t *con)
{
    char *constr = NULL;
    ssize_t len = getxattr(path, "user.libvirt.selinux",
                           NULL, 0);
    if (STRPREFIX(path, abs_builddir "/securityselinuxlabeldata/nfs/")) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (len < 0)
        return -1;
    if (!(constr = malloc(len+1)))
        return -1;
    memset(constr, 0, len);
    if (getxattr(path, "user.libvirt.selinux", constr, len) < 0) {
        free(constr);
        return -1;
    }
    *con = constr;
    constr[len] = '\0';
    return 0;
}


int getfilecon(const char *path, security_context_t *con)
{
    return getfilecon_raw(path, con);
}


int statfs(const char *path, struct statfs *buf)
{
    int ret;

    init_syms();

    ret = realstatfs(path, buf);
    if (!ret && STREQ(path, abs_builddir "/securityselinuxlabeldata/nfs"))
        buf->f_type = NFS_SUPER_MAGIC;
    return ret;
}


int security_getenforce(void)
{
    /* For the purpose of our test, we are enforcing.  */
    return 1;
}


int security_get_boolean_active(const char *name)
{
    /* For the purpose of our test, nfs is not permitted.  */
    if (STREQ(name, "virt_use_nfs"))
        return 0;

    init_syms();
    return realsecurity_get_boolean_active(name);
}
