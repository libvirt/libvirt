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
#include "viralloc.h"
#include "virenum.h"
#include "virfile.h"
#include "virhash.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_configs");

static int
qemuBuildFileList(virHashTablePtr files, const char *dir)
{
    DIR *dirp;
    struct dirent *ent = NULL;
    int rc;
    int ret = -1;

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

        if (VIR_STRDUP(filename, ent->d_name) < 0)
            goto cleanup;

        if (virAsprintf(&path, "%s/%s", dir, filename) < 0)
            goto cleanup;

        if (stat(path, &sb) < 0) {
            virReportSystemError(errno, _("Unable to access %s"), path);
            goto cleanup;
        }

        if (!S_ISREG(sb.st_mode) && !S_ISLNK(sb.st_mode))
            continue;

        if (virHashUpdateEntry(files, filename, path) < 0)
            goto cleanup;

        path = NULL;
    }

    if (rc < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virDirClose(&dirp);
    return ret;
}

static int
qemuConfigFilesSorter(const virHashKeyValuePair *a,
                      const virHashKeyValuePair *b)
{
    return strcmp(a->key, b->key);
}

#define QEMU_SYSTEM_LOCATION PREFIX "/share/qemu"
#define QEMU_ETC_LOCATION SYSCONFDIR "/qemu"

int
qemuInteropFetchConfigs(const char *name,
                        char ***configs,
                        bool privileged)
{
    VIR_AUTOPTR(virHashTable) files = NULL;
    g_autofree char *homeConfig = NULL;
    g_autofree char *xdgConfig = NULL;
    g_autofree char *sysLocation = virFileBuildPath(QEMU_SYSTEM_LOCATION, name, NULL);
    g_autofree char *etcLocation = virFileBuildPath(QEMU_ETC_LOCATION, name, NULL);
    g_autofree virHashKeyValuePairPtr pairs = NULL;
    virHashKeyValuePairPtr tmp = NULL;

    *configs = NULL;

    if (!privileged) {
        /* This is a slight divergence from the specification.
         * Since the system daemon runs as root, it doesn't make
         * much sense to parse files in root's home directory. It
         * makes sense only for session daemon which runs under
         * regular user. */
        if (VIR_STRDUP(xdgConfig, getenv("XDG_CONFIG_HOME")) < 0)
            return -1;

        if (!xdgConfig) {
            g_autofree char *home = virGetUserDirectory();

            if (!home)
                return -1;

            if (virAsprintf(&xdgConfig, "%s/.config", home) < 0)
                return -1;
        }

        if (virAsprintf(&homeConfig, "%s/qemu/%s", xdgConfig, name) < 0)
            return -1;
    }

    if (!(files = virHashCreate(10, virHashValueFree)))
        return -1;

    if (qemuBuildFileList(files, sysLocation) < 0)
        return -1;

    if (qemuBuildFileList(files, etcLocation) < 0)
        return -1;

    if (homeConfig &&
        qemuBuildFileList(files, homeConfig) < 0)
        return -1;

    /* At this point, the @files hash table contains unique set of filenames
     * where each filename (as key) has the highest priority full pathname
     * associated with it. */

    if (virHashSize(files) == 0)
        return 0;

    if (!(pairs = virHashGetItems(files, qemuConfigFilesSorter)))
        return -1;

    for (tmp = pairs; tmp->key; tmp++) {
        const char *path = tmp->value;
        off_t len;

        if ((len = virFileLength(path, -1)) < 0) {
            virReportSystemError(errno,
                                 _("unable to get size of '%s'"),
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

        if (virStringListAdd(configs, path) < 0)
            return -1;
    }

    return 0;
}
