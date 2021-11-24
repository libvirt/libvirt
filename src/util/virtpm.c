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
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_TPM

VIR_LOG_INIT("util.tpm");

VIR_ENUM_IMPL(virTPMSwtpmFeature,
              VIR_TPM_SWTPM_FEATURE_LAST,
              "cmdarg-pwd-fd",
);

VIR_ENUM_IMPL(virTPMSwtpmSetupFeature,
              VIR_TPM_SWTPM_SETUP_FEATURE_LAST,
              "cmdarg-pwdfile-fd",
              "cmdarg-create-config-files",
              "tpm12-not-need-root",
              "cmdarg-reconfigure-pcr-banks",
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
    if (!devpath) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing TPM device path"));
        return NULL;
    }

    if (!(dev = strrchr(devpath, '/'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("TPM device path %s is invalid"), devpath);
        return NULL;
    }

    dev++;
    for (i = 0; i < G_N_ELEMENTS(prefix); i++) {
        path = g_strdup_printf("/sys/class/%s%s/device/cancel", prefix[i],
                               dev);

        if (virFileExists(path))
            break;

        VIR_FREE(path);
    }
    if (!path)
        path = g_strdup("/dev/null");

    return path;
}

/*
 * executables for the swtpm; to be found on the host along with
 * capabilities bitmap
 */
static virMutex swtpm_tools_lock = VIR_MUTEX_INITIALIZER;
static char *swtpm_path;
static struct stat swtpm_stat;
static virBitmap *swtpm_caps;

static char *swtpm_setup_path;
static struct stat swtpm_setup_stat;
static virBitmap *swtpm_setup_caps;

static char *swtpm_ioctl_path;
static struct stat swtpm_ioctl_stat;

typedef int (*virTPMBinaryCapsParse)(const char *);

static char *
virTPMBinaryGetPath(char **path_var)
{
    char *s;

    if (!*path_var && virTPMEmulatorInit() < 0)
        return NULL;

    virMutexLock(&swtpm_tools_lock);
    s = g_strdup(*path_var);
    virMutexUnlock(&swtpm_tools_lock);

    return s;
}

char *
virTPMGetSwtpm(void)
{
    return virTPMBinaryGetPath(&swtpm_path);
}

char *
virTPMGetSwtpmSetup(void)
{
    return virTPMBinaryGetPath(&swtpm_setup_path);
}

char *
virTPMGetSwtpmIoctl(void)
{
    return virTPMBinaryGetPath(&swtpm_ioctl_path);
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
static virBitmap *
virTPMExecGetCaps(virCommand *cmd,
                  virTPMBinaryCapsParse capsParse)
{
    int exitstatus;
    virBitmap *bitmap;
    g_autofree char *outbuf = NULL;
    g_autoptr(virJSONValue) json = NULL;
    virJSONValue *featureList;
    virJSONValue *item;
    size_t idx;
    const char *str;
    int typ;

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, &exitstatus) < 0)
        return NULL;

    bitmap = virBitmapNew(0);

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
        typ = capsParse(str);
        if (typ < 0)
            continue;

        if (virBitmapSetBitExpand(bitmap, typ) < 0)
            return bitmap;
    }

    return bitmap;

 error_bad_json:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected JSON format: %s"), outbuf);
    return bitmap;
}

static virBitmap *
virTPMGetCaps(virTPMBinaryCapsParse capsParse,
              const char *exec, const char *param1)
{
    g_autoptr(virCommand) cmd = NULL;

    if (!(cmd = virCommandNew(exec)))
        return NULL;

    if (param1)
        virCommandAddArg(cmd, param1);
    virCommandAddArg(cmd, "--print-capabilities");
    virCommandClearCaps(cmd);

    return virTPMExecGetCaps(cmd, capsParse);
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
        virBitmap **caps;
        virTPMBinaryCapsParse capsParse;
    } prgs[] = {
        {
            .name = "swtpm",
            .path = &swtpm_path,
            .stat = &swtpm_stat,
            .parm = "socket",
            .caps = &swtpm_caps,
            .capsParse = virTPMSwtpmFeatureTypeFromString,
        },
        {
            .name = "swtpm_setup",
            .path = &swtpm_setup_path,
            .stat = &swtpm_setup_stat,
            .caps = &swtpm_setup_caps,
            .capsParse = virTPMSwtpmSetupFeatureTypeFromString,
        },
        {
            .name = "swtpm_ioctl",
            .path = &swtpm_ioctl_path,
            .stat = &swtpm_ioctl_stat,
        }
    };
    size_t i;

    virMutexLock(&swtpm_tools_lock);

    for (i = 0; i < G_N_ELEMENTS(prgs); i++) {
        g_autofree char *path = NULL;
        bool findit = *prgs[i].path == NULL;
        struct stat statbuf;

        if (!findit) {
            /* has executables changed? */
            if (stat(*prgs[i].path, &statbuf) < 0)
                findit = true;

            if (!findit &&
                statbuf.st_mtime != prgs[i].stat->st_mtime)
                findit = true;
        }

        if (findit) {
            VIR_FREE(*prgs[i].path);

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
            *prgs[i].path = g_steal_pointer(&path);

            if (prgs[i].caps) {
                *prgs[i].caps = virTPMGetCaps(prgs[i].capsParse,
                                              *prgs[i].path, prgs[i].parm);
                if (!*prgs[i].caps)
                    goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    virMutexUnlock(&swtpm_tools_lock);

    return ret;
}

static bool
virTPMBinaryGetCaps(virBitmap **caps_var,
                    unsigned int cap)
{
    if (virTPMEmulatorInit() < 0)
        return false;
    return virBitmapIsBitSet(*caps_var, cap);
}

bool
virTPMSwtpmCapsGet(unsigned int cap)
{
    return virTPMBinaryGetCaps(&swtpm_caps, cap);
}

bool
virTPMSwtpmSetupCapsGet(unsigned int cap)
{
    return virTPMBinaryGetCaps(&swtpm_setup_caps, cap);
}
