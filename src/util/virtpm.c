/*
 * virtpm.c: TPM support
 *
 * Copyright (C) 2013 IBM Corporation
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

#include <sys/stat.h>

#include "virstring.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtpm.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/**
 * virTPMCreateCancelPath:
 * @devpath: Path to the TPM device
 *
 * Create the cancel path given the path to the TPM device
 */
char *
virTPMCreateCancelPath(const char *devpath)
{
    char *path = NULL;
    const char *dev;
    const char *prefix[] = {"misc/", "tpm/"};
    size_t i;

    if (devpath) {
        dev = strrchr(devpath, '/');
        if (dev) {
            dev++;
            for (i = 0; i < ARRAY_CARDINALITY(prefix); i++) {
                if (virAsprintf(&path, "/sys/class/%s%s/device/cancel",
                                prefix[i], dev) < 0)
                     goto cleanup;

                if (virFileExists(path))
                    break;

                VIR_FREE(path);
            }
            if (!path)
                ignore_value(VIR_STRDUP(path, "/dev/null"));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("TPM device path %s is invalid"), devpath);
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing TPM device path"));
    }

 cleanup:
    return path;
}

/*
 * executables for the swtpm; to be found on the host
 */
static virMutex swtpm_tools_lock = VIR_MUTEX_INITIALIZER;
static char *swtpm_path;
static char *swtpm_setup;
static char *swtpm_ioctl;

char *
virTPMGetSwtpm(void)
{
    char *s;

    if (!swtpm_path && virTPMEmulatorInit() < 0)
        return NULL;

    virMutexLock(&swtpm_tools_lock);
    ignore_value(VIR_STRDUP(s, swtpm_path));
    virMutexUnlock(&swtpm_tools_lock);

    return s;
}

char *
virTPMGetSwtpmSetup(void)
{
    char *s;

    if (!swtpm_setup && virTPMEmulatorInit() < 0)
        return NULL;

    virMutexLock(&swtpm_tools_lock);
    ignore_value(VIR_STRDUP(s, swtpm_setup));
    virMutexUnlock(&swtpm_tools_lock);

    return s;
}

char *
virTPMGetSwtpmIoctl(void)
{
    char *s;

    if (!swtpm_ioctl && virTPMEmulatorInit() < 0)
        return NULL;

    virMutexLock(&swtpm_tools_lock);
    ignore_value(VIR_STRDUP(s, swtpm_ioctl));
    virMutexUnlock(&swtpm_tools_lock);

    return s;
}

/*
 * virTPMEmulatorInit
 *
 * Initialize the Emulator functions by searching for necessary
 * executables that we will use to start and setup the swtpm
 */
int
virTPMEmulatorInit(void)
{
    int ret = -1;

    virMutexLock(&swtpm_tools_lock);

    if (!swtpm_path) {
        swtpm_path = virFindFileInPath("swtpm");
        if (!swtpm_path) {
            virReportSystemError(ENOENT, "%s",
                                 _("Unable to find 'swtpm' binary in $PATH"));
            goto cleanup;
        }
        if (!virFileIsExecutable(swtpm_path)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("TPM emulator %s is not an executable"),
                           swtpm_path);
            VIR_FREE(swtpm_path);
            goto cleanup;
        }
    }

    if (!swtpm_setup) {
        swtpm_setup = virFindFileInPath("swtpm_setup");
        if (!swtpm_setup) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find 'swtpm_setup' in PATH"));
            goto cleanup;
        }
        if (!virFileIsExecutable(swtpm_setup)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("'%s' is not an executable"),
                           swtpm_setup);
            VIR_FREE(swtpm_setup);
            goto cleanup;
        }
    }

    if (!swtpm_ioctl) {
        swtpm_ioctl = virFindFileInPath("swtpm_ioctl");
        if (!swtpm_ioctl) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find swtpm_ioctl in PATH"));
            goto cleanup;
        }
        if (!virFileIsExecutable(swtpm_ioctl)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("swtpm_ioctl program %s is not an executable"),
                           swtpm_ioctl);
            VIR_FREE(swtpm_ioctl);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virMutexUnlock(&swtpm_tools_lock);

    return ret;
}
