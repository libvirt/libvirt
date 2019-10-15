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
#include "vircommand.h"
#include "virbitmap.h"
#include "virjson.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_TPM

VIR_LOG_INIT("util.tpm");

VIR_ENUM_IMPL(virTPMSwtpmFeature,
              VIR_TPM_SWTPM_FEATURE_LAST,
              "cmdarg-pwd-fd",
);

VIR_ENUM_IMPL(virTPMSwtpmSetupFeature,
              VIR_TPM_SWTPM_SETUP_FEATURE_LAST,
              "cmdarg-pwdfile-fd",
);

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
            for (i = 0; i < G_N_ELEMENTS(prefix); i++) {
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
 * executables for the swtpm; to be found on the host along with
 * capabilties bitmap
 */
static virMutex swtpm_tools_lock = VIR_MUTEX_INITIALIZER;
static char *swtpm_path;
static struct stat swtpm_stat;
static virBitmapPtr swtpm_caps;

static char *swtpm_setup;
static struct stat swtpm_setup_stat;
static virBitmapPtr swtpm_setup_caps;

static char *swtpm_ioctl;
static struct stat swtpm_ioctl_stat;

typedef int (*TypeFromStringFn)(const char *);

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

/* virTPMExecGetCaps
 *
 * Execute the prepared command and parse the returned JSON object
 * to get the capabilities supported by the executable.
 * A JSON object like this is expected:
 *
 * {
 *  "type": "swtpm",
 *  "features": [
 *    "cmdarg-seccomp",
 *    "cmdarg-key-fd",
 *    "cmdarg-pwd-fd"
 *  ]
 * }
 */
static virBitmapPtr
virTPMExecGetCaps(virCommandPtr cmd,
                  TypeFromStringFn typeFromStringFn)
{
    int exitstatus;
    virBitmapPtr bitmap;
    g_autofree char *outbuf = NULL;
    g_autoptr(virJSONValue) json = NULL;
    virJSONValuePtr featureList;
    virJSONValuePtr item;
    size_t idx;
    const char *str;
    int typ;

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, &exitstatus) < 0)
        return NULL;

    if (!(bitmap = virBitmapNewEmpty()))
        return NULL;

    /* older version does not support --print-capabilties -- that's fine */
    if (exitstatus != 0) {
        VIR_DEBUG("Found swtpm that doesn't support --print-capabilities");
        return bitmap;
    }

    json = virJSONValueFromString(outbuf);
    if (!json)
        goto error_bad_json;

    featureList = virJSONValueObjectGetArray(json, "features");
    if (!featureList)
        goto error_bad_json;

    if (!virJSONValueIsArray(featureList))
        goto error_bad_json;

    for (idx = 0; idx < virJSONValueArraySize(featureList); idx++) {
        item = virJSONValueArrayGet(featureList, idx);
        if (!item)
            continue;

        str = virJSONValueGetString(item);
        if (!str)
            goto error_bad_json;
        typ = typeFromStringFn(str);
        if (typ < 0)
            continue;

        if (virBitmapSetBitExpand(bitmap, typ) < 0)
            goto cleanup;
    }

 cleanup:
    return bitmap;

 error_bad_json:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected JSON format: %s"), outbuf);
    goto cleanup;
}

static virBitmapPtr
virTPMGetCaps(TypeFromStringFn typeFromStringFn,
                  const char *exec, const char *param1)
{
    g_autoptr(virCommand) cmd = NULL;

    if (!(cmd = virCommandNew(exec)))
        return NULL;

    if (param1)
        virCommandAddArg(cmd, param1);
    virCommandAddArg(cmd, "--print-capabilities");
    virCommandClearCaps(cmd);

    return virTPMExecGetCaps(cmd, typeFromStringFn);
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
    static const struct {
        const char *name;
        char **path;
        struct stat *stat;
        const char *parm;
        virBitmapPtr *caps;
        TypeFromStringFn typeFromStringFn;
    } prgs[] = {
        {
            .name = "swtpm",
            .path = &swtpm_path,
            .stat = &swtpm_stat,
            .parm = "socket",
            .caps = &swtpm_caps,
            .typeFromStringFn = virTPMSwtpmFeatureTypeFromString,
        },
        {
            .name = "swtpm_setup",
            .path = &swtpm_setup,
            .stat = &swtpm_setup_stat,
            .caps = &swtpm_setup_caps,
            .typeFromStringFn = virTPMSwtpmSetupFeatureTypeFromString,
        },
        {
            .name = "swtpm_ioctl",
            .path = &swtpm_ioctl,
            .stat = &swtpm_ioctl_stat,
        }
    };
    size_t i;

    virMutexLock(&swtpm_tools_lock);

    for (i = 0; i < G_N_ELEMENTS(prgs); i++) {
        g_autofree char *path = NULL;
        bool findit = *prgs[i].path == NULL;
        struct stat statbuf;
        char *tmp;

        if (!findit) {
            /* has executables changed? */
            if (stat(*prgs[i].path, &statbuf) < 0)
                findit = true;

            if (!findit &&
                &statbuf.st_mtime != &prgs[i].stat->st_mtime)
                findit = true;
        }

        if (findit) {
            tmp = *prgs[i].path;
            VIR_FREE(tmp);
            *prgs[i].path = NULL;

            path = virFindFileInPath(prgs[i].name);
            if (!path) {
                virReportSystemError(ENOENT,
                                _("Unable to find '%s' binary in $PATH"),
                                prgs[i].name);
                goto cleanup;
            }
            if (!virFileIsExecutable(path)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("%s is not an executable"),
                               path);
                goto cleanup;
            }
            if (stat(path, prgs[i].stat) < 0) {
                virReportSystemError(errno,
                                     _("Could not stat %s"), path);
                goto cleanup;
            }
            *prgs[i].path = path;

            if (prgs[i].caps) {
                *prgs[i].caps = virTPMGetCaps(prgs[i].typeFromStringFn,
                                              path, prgs[i].parm);
                path = NULL;
                if (!*prgs[i].caps)
                    goto cleanup;
            }
            path = NULL;
        }
    }

    ret = 0;

 cleanup:
    virMutexUnlock(&swtpm_tools_lock);

    return ret;
}

bool
virTPMSwtpmCapsGet(unsigned int cap)
{
    if (virTPMEmulatorInit() < 0)
        return false;
    return virBitmapIsBitSet(swtpm_caps, cap);
}

bool
virTPMSwtpmSetupCapsGet(unsigned int cap)
{
    if (virTPMEmulatorInit() < 0)
        return false;
    return virBitmapIsBitSet(swtpm_setup_caps, cap);
}
