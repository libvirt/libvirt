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

#include "virerror.h"
#include "virfirmware.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.firmware");


void
virFirmwareFree(virFirmware *firmware)
{
    if (!firmware)
        return;

    g_free(firmware->name);
    g_free(firmware->nvram);
    g_free(firmware);
}


void
virFirmwareFreeList(virFirmware **firmwares, size_t nfirmwares)
{
    size_t i;

    for (i = 0; i < nfirmwares; i++)
        virFirmwareFree(firmwares[i]);

    g_free(firmwares);
}


int
virFirmwareParse(const char *str, virFirmware *firmware)
{
    g_auto(GStrv) token = NULL;

    if (!(token = g_strsplit(str, ":", 0)))
        return -1;

    if (token[0]) {
        virSkipSpaces((const char **) &token[0]);
        if (token[1])
            virSkipSpaces((const char **) &token[1]);
    }

    /* Exactly two tokens are expected */
    if (!token[0] || !token[1] || token[2] ||
        STREQ(token[0], "") || STREQ(token[1], "")) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("Invalid nvram format: '%1$s'"),
                       str);
        return -1;
    }

    firmware->name = g_strdup(token[0]);
    firmware->nvram = g_strdup(token[1]);

    return 0;
}


int
virFirmwareParseList(const char *list,
                     virFirmware ***firmwares,
                     size_t *nfirmwares)
{
    g_auto(GStrv) token = NULL;
    size_t i, j;

    if (!(token = g_strsplit(list, ":", 0)))
        return -1;

    for (i = 0; token[i]; i += 2) {
        if (!token[i] || !token[i + 1] ||
            STREQ(token[i], "") || STREQ(token[i + 1], "")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid --with-loader-nvram list: %1$s"),
                           list);
            return -1;
        }
    }

    if (i) {
        *firmwares = g_new0(virFirmware *, i / 2);
        *nfirmwares = i / 2;

        for (j = 0; j < i / 2; j++) {
            virFirmware **fws = *firmwares;

            fws[j] = g_new0(virFirmware, 1);
            fws[j]->name = g_strdup(token[2 * j]);
            fws[j]->nvram = g_strdup(token[2 * j + 1]);
        }
    }

    return 0;
}
