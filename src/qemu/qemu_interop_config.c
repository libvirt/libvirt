/*
 * qemu_interop_config.c: QEMU firmware/vhost-user etc configs
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

#include "qemu_interop_config.h"
#include "configmake.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_configs");

static int
qemuBuildFileList(GHashTable *files, const char *dir)
{
    g_autoptr(DIR) dirp = NULL;
    struct dirent *ent = NULL;
    int rc;

    if ((rc = virDirOpenIfExists(&dirp, dir)) < 0)
        return -1;

    if (rc == 0)
        return 0;

    while ((rc = virDirRead(dirp, &ent, dir)) > 0) {
        g_autofree char *filename = NULL;
        g_autofree char *path = NULL;
        struct stat sb;

        if (STRPREFIX(ent->d_name, "."))
            continue;

        filename = g_strdup(ent->d_name);

        path = g_strdup_printf("%s/%s", dir, filename);

        if (stat(path, &sb) < 0) {
            virReportSystemError(errno, _("Unable to access %1$s"), path);
            return -1;
        }

        if (!S_ISREG(sb.st_mode) && !S_ISLNK(sb.st_mode))
            continue;

        if (virHashUpdateEntry(files, filename, path) < 0)
            return -1;

        path = NULL;
    }

    if (rc < 0)
        return -1;

    return 0;
}

#define QEMU_CONFDIR SYSCONFDIR "/qemu"

int
qemuInteropFetchConfigs(const char *name,
                        char ***configs,
                        bool privileged)
{
    g_autoptr(GHashTable) files = virHashNew(g_free);
    g_autofree char *homeConfig = NULL;
    g_autofree char *xdgConfig = NULL;
    g_autofree char *dataLocation = virFileBuildPath(QEMU_DATADIR, name, NULL);
    g_autofree char *confLocation = virFileBuildPath(QEMU_CONFDIR, name, NULL);
    g_autofree virHashKeyValuePair *pairs = NULL;
    size_t npairs;
    virHashKeyValuePair *tmp = NULL;
    size_t nconfigs = 0;

    *configs = NULL;

    if (!privileged) {
        /* This is a slight divergence from the specification.
         * Since the system daemon runs as root, it doesn't make
         * much sense to parse files in root's home directory. It
         * makes sense only for session daemon which runs under
         * regular user. */
        xdgConfig = g_strdup(getenv("XDG_CONFIG_HOME"));

        if (!xdgConfig) {
            g_autofree char *home = virGetUserDirectory();

            xdgConfig = g_strdup_printf("%s/.config", home);
        }

        homeConfig = g_strdup_printf("%s/qemu/%s", xdgConfig, name);
    }

    if (qemuBuildFileList(files, dataLocation) < 0)
        return -1;

    if (qemuBuildFileList(files, confLocation) < 0)
        return -1;

    if (homeConfig &&
        qemuBuildFileList(files, homeConfig) < 0)
        return -1;

    /* At this point, the @files hash table contains unique set of filenames
     * where each filename (as key) has the highest priority full pathname
     * associated with it. */

    if (!(pairs = virHashGetItems(files, &npairs, true)))
        return -1;

    if (npairs == 0)
        return 0;

    *configs = g_new0(char *, npairs + 1);

    for (tmp = pairs; tmp->key; tmp++) {
        const char *path = tmp->value;
        off_t len;

        if ((len = virFileLength(path, -1)) < 0) {
            virReportSystemError(errno,
                                 _("unable to get size of '%1$s'"),
                                 path);
            return -1;
        }

        VIR_DEBUG("%s description path '%s' len=%jd",
                  name, path, (intmax_t) len);

        if (len == 0) {
            /* Empty files are used to mask less specific instances
             * of the same file. */
            continue;
        }

        (*configs)[nconfigs++] = g_strdup(path);
    }

    return 0;
}
