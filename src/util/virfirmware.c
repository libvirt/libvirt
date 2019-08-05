/*
 * virfirmware.c: Definition of firmware object and supporting functions
 *
 * Copyright (C) 2016 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include "viralloc.h"
#include "virerror.h"
#include "virfirmware.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.firmware");


void
virFirmwareFree(virFirmwarePtr firmware)
{
    if (!firmware)
        return;

    VIR_FREE(firmware->name);
    VIR_FREE(firmware->nvram);
    VIR_FREE(firmware);
}


void
virFirmwareFreeList(virFirmwarePtr *firmwares, size_t nfirmwares)
{
    size_t i;

    for (i = 0; i < nfirmwares; i++)
        virFirmwareFree(firmwares[i]);

    VIR_FREE(firmwares);
}


int
virFirmwareParse(const char *str, virFirmwarePtr firmware)
{
    int ret = -1;
    char **token;

    if (!(token = virStringSplit(str, ":", 0)))
        goto cleanup;

    if (token[0]) {
        virSkipSpaces((const char **) &token[0]);
        if (token[1])
            virSkipSpaces((const char **) &token[1]);
    }

    /* Exactly two tokens are expected */
    if (!token[0] || !token[1] || token[2] ||
        STREQ(token[0], "") || STREQ(token[1], "")) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("Invalid nvram format: '%s'"),
                       str);
        goto cleanup;
    }

    if (VIR_STRDUP(firmware->name, token[0]) < 0 ||
        VIR_STRDUP(firmware->nvram, token[1]) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virStringListFree(token);
    return ret;
}


int
virFirmwareParseList(const char *list,
                     virFirmwarePtr **firmwares,
                     size_t *nfirmwares)
{
    int ret = -1;
    char **token;
    size_t i, j;

    if (!(token = virStringSplit(list, ":", 0)))
        goto cleanup;

    for (i = 0; token[i]; i += 2) {
        if (!token[i] || !token[i + 1] ||
            STREQ(token[i], "") || STREQ(token[i + 1], "")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid --with-loader-nvram list: %s"),
                           list);
            goto cleanup;
        }
    }

    if (i) {
        if (VIR_ALLOC_N(*firmwares, i / 2) < 0)
            goto cleanup;
        *nfirmwares = i / 2;

        for (j = 0; j < i / 2; j++) {
            virFirmwarePtr *fws = *firmwares;

            if (VIR_ALLOC(fws[j]) < 0)
                goto cleanup;
            if (VIR_STRDUP(fws[j]->name, token[2 * j]) < 0 ||
                VIR_STRDUP(fws[j]->nvram, token[2 * j + 1]) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virStringListFree(token);
    return ret;
}
