/*
 * Copyright (C) 2011-2013, 2016 Red Hat, Inc.
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

#include "virmock.h"
#include <linux/magic.h>
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <sys/xattr.h>

#ifndef NFS_SUPER_MAGIC
# define NFS_SUPER_MAGIC 0x6969
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

#include "viralloc.h"

static int (*real_statfs)(const char *path, struct statfs *buf);
static int (*real_security_get_boolean_active)(const char *name);
static int (*real_is_selinux_enabled)(void);

static const char *(*real_selinux_virtual_domain_context_path)(void);
static const char *(*real_selinux_virtual_image_context_path)(void);

static const char *(*real_selinux_lxc_contexts_path)(void);

static struct selabel_handle *(*real_selabel_open)(unsigned int backend,
                                                  const struct selinux_opt *opts,
                                                  unsigned nopts);
static void (*real_selabel_close)(struct selabel_handle *handle);
static int (*real_selabel_lookup_raw)(struct selabel_handle *handle,
                                     char **con,
                                     const char *key,
                                     int type);

static void init_syms(void)
{
    if (real_statfs)
        return;

    VIR_MOCK_REAL_INIT(statfs);
    VIR_MOCK_REAL_INIT(security_get_boolean_active);
    VIR_MOCK_REAL_INIT(is_selinux_enabled);

    VIR_MOCK_REAL_INIT(selinux_virtual_domain_context_path);
    VIR_MOCK_REAL_INIT(selinux_virtual_image_context_path);

    VIR_MOCK_REAL_INIT(selinux_lxc_contexts_path);

    VIR_MOCK_REAL_INIT(selabel_open);
    VIR_MOCK_REAL_INIT(selabel_close);
    VIR_MOCK_REAL_INIT(selabel_lookup_raw);
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

int getcon_raw(char **context)
{
    if (!is_selinux_enabled()) {
        errno = EINVAL;
        return -1;
    }
    if (getenv("FAKE_SELINUX_CONTEXT") == NULL) {
        *context = NULL;
        errno = EINVAL;
        return -1;
    }
    *context = g_strdup(getenv("FAKE_SELINUX_CONTEXT"));
    return 0;
}

int getcon(char **context)
{
    return getcon_raw(context);
}

int getpidcon_raw(pid_t pid, char **context)
{
    if (!is_selinux_enabled()) {
        errno = EINVAL;
        return -1;
    }
    if (pid != getpid()) {
        *context = NULL;
        errno = ESRCH;
        return -1;
    }
    if (getenv("FAKE_SELINUX_CONTEXT") == NULL) {
        *context = NULL;
        errno = EINVAL;
        return -1;
    }
    *context = g_strdup(getenv("FAKE_SELINUX_CONTEXT"));
    return 0;
}

int getpidcon(pid_t pid, char **context)
{
    return getpidcon_raw(pid, context);
}

int setcon_raw(const char *context)
{
    if (!is_selinux_enabled()) {
        errno = EINVAL;
        return -1;
    }
    return g_setenv("FAKE_SELINUX_CONTEXT", context, TRUE) == TRUE ? 0 : -1;
}

int setcon(const char *context)
{
    return setcon_raw(context);
}


int setfilecon_raw(const char *path, const char *con)
{
    const char *constr = con;
    if (STRPREFIX(path, abs_builddir "/securityselinuxlabeldata/nfs/")) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return setxattr(path, "user.libvirt.selinux",
                    constr, strlen(constr), 0);
}

int setfilecon(const char *path, const char *con)
{
    return setfilecon_raw(path, con);
}

int getfilecon_raw(const char *path, char **con)
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


int getfilecon(const char *path, char **con)
{
    return getfilecon_raw(path, con);
}


int statfs(const char *path, struct statfs *buf)
{
    int ret;

    init_syms();

    ret = real_statfs(path, buf);
    if (!ret && STREQ(path, abs_builddir "/securityselinuxlabeldata/nfs"))
        buf->f_type = NFS_SUPER_MAGIC;
    return ret;
}

int is_selinux_enabled(void)
{
    return getenv("FAKE_SELINUX_DISABLED") == NULL;
}

int security_disable(void)
{
    if (!is_selinux_enabled()) {
        errno = ENOENT;
        return -1;
    }

    return g_setenv("FAKE_SELINUX_DISABLED", "1", TRUE) == TRUE ? 0 : -1;
}

int security_getenforce(void)
{
    if (!is_selinux_enabled()) {
        errno = ENOENT;
        return -1;
    }

    /* For the purpose of our test, we are enforcing.  */
    return 1;
}


int security_get_boolean_active(const char *name)
{
    if (!is_selinux_enabled()) {
        errno = ENOENT;
        return -1;
    }

    /* For the purpose of our test, nfs is not permitted.  */
    if (STREQ(name, "virt_use_nfs"))
        return 0;

    init_syms();
    return real_security_get_boolean_active(name);
}

const char *selinux_virtual_domain_context_path(void)
{
    init_syms();

    if (real_is_selinux_enabled())
        return real_selinux_virtual_domain_context_path();

    return abs_srcdir "/securityselinuxhelperdata/virtual_domain_context";
}

const char *selinux_virtual_image_context_path(void)
{
    init_syms();

    if (real_is_selinux_enabled())
        return real_selinux_virtual_image_context_path();

    return abs_srcdir "/securityselinuxhelperdata/virtual_image_context";
}

const char *selinux_lxc_contexts_path(void)
{
    init_syms();

    if (real_is_selinux_enabled())
        return real_selinux_lxc_contexts_path();

    return abs_srcdir "/securityselinuxhelperdata/lxc_contexts";
}

struct selabel_handle *
selabel_open(unsigned int backend,
             const struct selinux_opt *opts,
             unsigned nopts)
{
    char *fake_handle;

    init_syms();

    if (real_is_selinux_enabled())
        return real_selabel_open(backend, opts, nopts);

    /* struct selabel_handle is opaque; fake it */
    fake_handle = g_new0(char, 1);
    return (struct selabel_handle *)fake_handle;
}

void selabel_close(struct selabel_handle *handle)
{
    init_syms();

    if (real_is_selinux_enabled())
        return real_selabel_close(handle);

    VIR_FREE(handle);
}

int selabel_lookup_raw(struct selabel_handle *handle,
                       char **con,
                       const char *key,
                       int type)
{
    init_syms();

    if (real_is_selinux_enabled())
        return real_selabel_lookup_raw(handle, con, key, type);

    /* Unimplemented */
    errno = ENOENT;
    return -1;
}
