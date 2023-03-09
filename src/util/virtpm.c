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
              "cmdarg-migration",
);

VIR_ENUM_IMPL(virTPMSwtpmSetupFeature,
              VIR_TPM_SWTPM_SETUP_FEATURE_LAST,
              "cmdarg-pwdfile-fd",
              "cmdarg-create-config-files",
              "tpm12-not-need-root",
              "cmdarg-reconfigure-pcr-banks",
              "tpm-1.2",
              "tpm-2.0",
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
                       _("TPM device path %1$s is invalid"), devpath);
        return NULL;
    }

    dev++;
    for (i = 0; i < G_N_ELEMENTS(prefix); i++) {
        g_autofree char *path = g_strdup_printf("/sys/class/%s%s/device/cancel",
                                                prefix[i], dev);

        if (virFileExists(path))
            return g_steal_pointer(&path);
    }

    return g_strdup("/dev/null");
}

/*
 * executables for the swtpm; to be found on the host along with
 * capabilities bitmap
 */
static virMutex swtpm_tools_lock = VIR_MUTEX_INITIALIZER;

typedef int (*virTPMBinaryCapsParse)(const char *);

typedef enum _virTPMBinary {
    VIR_TPM_BINARY_SWTPM,
    VIR_TPM_BINARY_SWTPM_SETUP,
    VIR_TPM_BINARY_SWTPM_IOCTL,

    VIR_TPM_BINARY_LAST
} virTPMBinary;

VIR_ENUM_DECL(virTPMBinary);
VIR_ENUM_IMPL(virTPMBinary,
              VIR_TPM_BINARY_LAST,
              "swtpm", "swtpm_setup", "swtpm_ioctl");

typedef struct _virTPMBinaryInfo {
    char *path;
    struct stat stat;
    const char *parm;
    virBitmap *caps;
    virTPMBinaryCapsParse capsParse;
} virTPMBinaryInfo;

static virTPMBinaryInfo swtpmBinaries[VIR_TPM_BINARY_LAST] = {
    [VIR_TPM_BINARY_SWTPM] = {
        .parm = "socket",
        .capsParse = virTPMSwtpmFeatureTypeFromString,
    },
    [VIR_TPM_BINARY_SWTPM_SETUP] = {
        .capsParse = virTPMSwtpmSetupFeatureTypeFromString,
    },
    [VIR_TPM_BINARY_SWTPM_IOCTL] = {
    },
};

static int virTPMEmulatorInit(bool quiet);

static char *
virTPMBinaryGetPath(virTPMBinary binary)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&swtpm_tools_lock);

    if (virTPMEmulatorInit(false) < 0)
        return NULL;

    return g_strdup(swtpmBinaries[binary].path);
}

char *
virTPMGetSwtpm(void)
{
    return virTPMBinaryGetPath(VIR_TPM_BINARY_SWTPM);
}

char *
virTPMGetSwtpmSetup(void)
{
    return virTPMBinaryGetPath(VIR_TPM_BINARY_SWTPM_SETUP);
}

char *
virTPMGetSwtpmIoctl(void)
{
    return virTPMBinaryGetPath(VIR_TPM_BINARY_SWTPM_IOCTL);
}

bool virTPMHasSwtpm(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&swtpm_tools_lock);

    if (virTPMEmulatorInit(true) < 0)
        return false;

    return swtpmBinaries[VIR_TPM_BINARY_SWTPM].path != NULL &&
        swtpmBinaries[VIR_TPM_BINARY_SWTPM_SETUP].path != NULL &&
        swtpmBinaries[VIR_TPM_BINARY_SWTPM_IOCTL].path != NULL;
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

        virBitmapSetBitExpand(bitmap, typ);
    }

    return bitmap;

 error_bad_json:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected JSON format: %1$s"), outbuf);
    return bitmap;
}

static virBitmap *
virTPMGetCaps(virTPMBinaryCapsParse capsParse,
              const char *exec, const char *param1)
{
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNew(exec);

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
static int
virTPMEmulatorInit(bool quiet)
{
    size_t i;

    for (i = 0; i < VIR_TPM_BINARY_LAST; i++) {
        g_autofree char *path = NULL;
        bool findit = swtpmBinaries[i].path == NULL;
        struct stat statbuf;

        if (!findit) {
            /* has executables changed? */
            if (stat(swtpmBinaries[i].path, &statbuf) < 0)
                findit = true;

            if (!findit &&
                statbuf.st_mtime != swtpmBinaries[i].stat.st_mtime)
                findit = true;
        }

        if (findit) {
            VIR_FREE(swtpmBinaries[i].path);

            path = virFindFileInPath(virTPMBinaryTypeToString(i));
            if (!path) {
                if (!quiet)
                    virReportSystemError(ENOENT,
                                         _("Unable to find '%1$s' binary in $PATH"),
                                         virTPMBinaryTypeToString(i));
                return -1;
            }
            if (!virFileIsExecutable(path)) {
                if (!quiet)
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("%1$s is not an executable"),
                                   path);
                return -1;
            }
            if (stat(path, &swtpmBinaries[i].stat) < 0) {
                if (!quiet)
                    virReportSystemError(errno,
                                         _("Could not stat %1$s"), path);
                return -1;
            }
            swtpmBinaries[i].path = g_steal_pointer(&path);
            g_clear_pointer(&swtpmBinaries[i].caps, virBitmapFree);
        }
    }

    return 0;
}

static bool
virTPMBinaryGetCaps(virTPMBinary binary,
                    unsigned int cap)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&swtpm_tools_lock);

    if (virTPMEmulatorInit(false) < 0)
        return false;

    if (!swtpmBinaries[binary].caps &&
        swtpmBinaries[binary].capsParse) {
        swtpmBinaries[binary].caps = virTPMGetCaps(
            swtpmBinaries[binary].capsParse,
            swtpmBinaries[binary].path,
            swtpmBinaries[binary].parm);
    }

    if (!swtpmBinaries[binary].caps)
        return false;

    return virBitmapIsBitSet(swtpmBinaries[binary].caps, cap);
}

bool
virTPMSwtpmCapsGet(virTPMSwtpmFeature cap)
{
    return virTPMBinaryGetCaps(VIR_TPM_BINARY_SWTPM, cap);
}

bool
virTPMSwtpmSetupCapsGet(virTPMSwtpmSetupFeature cap)
{
    return virTPMBinaryGetCaps(VIR_TPM_BINARY_SWTPM_SETUP, cap);
}
