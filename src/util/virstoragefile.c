/*
 * virstoragefile.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2017 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
#include "virstoragefile.h"

#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "vircommand.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("util.storagefile");


#ifdef WITH_UDEV
/* virStorageFileGetSCSIKey
 * @path: Path to the SCSI device
 * @key: Unique key to be returned
 * @ignoreError: Used to not report ENOSYS
 *
 * Using a udev specific function, query the @path to get and return a
 * unique @key for the caller to use.
 *
 * Returns:
 *     0 On success, with the @key filled in or @key=NULL if the
 *       returned string was empty.
 *    -1 When WITH_UDEV is undefined and a system error is reported
 *    -2 When WITH_UDEV is defined, but calling virCommandRun fails
 */
int
virStorageFileGetSCSIKey(const char *path,
                         char **key,
                         bool ignoreError G_GNUC_UNUSED)
{
    int status;
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList("/lib/udev/scsi_id",
                               "--replace-whitespace",
                               "--whitelisted",
                               "--device", path,
                               NULL
                               );
    *key = NULL;

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, key);
    if (virCommandRun(cmd, &status) < 0)
        return -2;

    /* Explicitly check status == 0, rather than passing NULL
     * to virCommandRun because we don't want to raise an actual
     * error in this scenario, just return a NULL key.
     */
    if (status == 0 && *key) {
        char *nl = strchr(*key, '\n');
        if (nl)
            *nl = '\0';
    }

    if (*key && STREQ(*key, ""))
        VIR_FREE(*key);

    return 0;
}
#else
int virStorageFileGetSCSIKey(const char *path,
                             char **key G_GNUC_UNUSED,
                             bool ignoreError)
{
    if (!ignoreError)
        virReportSystemError(ENOSYS, _("Unable to get SCSI key for %1$s"), path);
    return -1;
}
#endif


#ifdef WITH_UDEV
/* virStorageFileGetNPIVKey
 * @path: Path to the NPIV device
 * @key: Unique key to be returned
 *
 * Using a udev specific function, query the @path to get and return a
 * unique @key for the caller to use. Unlike the GetSCSIKey method, an
 * NPIV LUN is uniquely identified by its ID_TARGET_PORT value.
 *
 * Returns:
 *     0 On success, with the @key filled in or @key=NULL if the
 *       returned output string didn't have the data we need to
 *       formulate a unique key value
 *    -1 When WITH_UDEV is undefined and a system error is reported
 *    -2 When WITH_UDEV is defined, but calling virCommandRun fails
 */
# define ID_SERIAL "ID_SERIAL="
# define ID_TARGET_PORT "ID_TARGET_PORT="
int
virStorageFileGetNPIVKey(const char *path,
                         char **key)
{
    int status;
    const char *serial;
    const char *port;
    g_autofree char *outbuf = NULL;
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList("/lib/udev/scsi_id",
                               "--replace-whitespace",
                               "--whitelisted",
                               "--export",
                               "--device", path,
                               NULL
                               );
    *key = NULL;

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, &status) < 0)
        return -2;

    /* Explicitly check status == 0, rather than passing NULL
     * to virCommandRun because we don't want to raise an actual
     * error in this scenario, just return a NULL key.
     */
    if (status == 0 && *outbuf &&
        (serial = strstr(outbuf, ID_SERIAL)) &&
        (port = strstr(outbuf, ID_TARGET_PORT))) {
        char *tmp;

        serial += strlen(ID_SERIAL);
        port += strlen(ID_TARGET_PORT);

        if ((tmp = strchr(serial, '\n')))
            *tmp = '\0';

        if ((tmp = strchr(port, '\n')))
            *tmp = '\0';

        if (*serial != '\0' && *port != '\0')
            *key = g_strdup_printf("%s_PORT%s", serial, port);
    }

    return 0;
}
#else
int virStorageFileGetNPIVKey(const char *path G_GNUC_UNUSED,
                             char **key G_GNUC_UNUSED)
{
    return -1;
}
#endif


/**
 * virStorageFileParseBackingStoreStr:
 * @str: backing store specifier string to parse
 * @target: returns target device portion of the string
 * @chainIndex: returns the backing store portion of the string
 *
 * Parses the backing store specifier string such as vda[1], or sda into
 * components and returns them via arguments. If the string did not specify an
 * index, 0 is assumed.
 *
 * Returns 0 on success -1 on error
 */
int
virStorageFileParseBackingStoreStr(const char *str,
                                   char **target,
                                   unsigned int *chainIndex)
{
    unsigned int idx = 0;
    char *suffix;
    g_auto(GStrv) strings = NULL;

    *chainIndex = 0;

    if (!(strings = g_strsplit(str, "[", 2)))
        return -1;

    if (strings[0] && strings[1]) {
        if (virStrToLong_uip(strings[1], &suffix, 10, &idx) < 0 ||
            STRNEQ(suffix, "]"))
            return -1;
    }

    if (target)
        *target = g_strdup(strings[0]);

    *chainIndex = idx;
    return 0;
}
