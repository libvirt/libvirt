/*
 * sysinfo.c: get SMBIOS/sysinfo information from the host
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2010 Daniel Veillard
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "virterror_internal.h"
#include "sysinfo.h"
#include "util.h"
#include "conf/domain_conf.h"
#include "logging.h"
#include "memory.h"
#include "command.h"

#define VIR_FROM_THIS VIR_FROM_SYSINFO

#define virSmbiosReportError(code, ...)                               \
    virReportErrorHelper(NULL, VIR_FROM_SYSINFO, code, __FILE__,      \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#define SYSINFO_SMBIOS_DECODER "dmidecode"

/**
 * virSysinfoDefFree:
 * @def: a sysinfo structure
 *
 * Free up the sysinfo structure
 */

void virSysinfoDefFree(virSysinfoDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->bios_vendor);
    VIR_FREE(def->bios_version);
    VIR_FREE(def->bios_date);
    VIR_FREE(def->bios_release);

    VIR_FREE(def->system_manufacturer);
    VIR_FREE(def->system_product);
    VIR_FREE(def->system_version);
    VIR_FREE(def->system_serial);
    VIR_FREE(def->system_uuid);
    VIR_FREE(def->system_sku);
    VIR_FREE(def->system_family);
    VIR_FREE(def);
}

/**
 * virSysinfoRead:
 *
 * Tries to read the SMBIOS information from the current host
 *
 * Returns: a filled up sysinfo structure or NULL in case of error
 */
#ifdef WIN32
virSysinfoDefPtr
virSysinfoRead(void) {
    /*
     * this can probably be extracted from Windows using API or registry
     * http://www.microsoft.com/whdc/system/platform/firmware/SMBIOS.mspx
     */
    virReportSystemError(ENOSYS, "%s",
                 _("Host sysinfo extraction not supported on this platform"));
    return NULL;
}
#else
virSysinfoDefPtr
virSysinfoRead(void) {
    char *path, *cur, *eol, *base;
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;
    virCommandPtr cmd;

    path = virFindFileInPath(SYSINFO_SMBIOS_DECODER);
    if (path == NULL) {
        virSmbiosReportError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to find path for %s binary"),
                             SYSINFO_SMBIOS_DECODER);
        return NULL;
    }

    cmd = virCommandNewArgList(path, "-q", "-t", "0,1", NULL);
    VIR_FREE(path);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0) {
        virSmbiosReportError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to execute command %s"),
                             path);
        goto cleanup;
    }

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    ret->type = VIR_DOMAIN_SYSINFO_SMBIOS;

    base = outbuf;

    if ((cur = strstr(base, "Vendor: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->bios_vendor = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->bios_version = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "Release Date: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->bios_date = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "BIOS Revision: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->bios_release = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((base = strstr(outbuf, "System Information")) == NULL)
        goto cleanup;
    if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if ((eol) &&
            ((ret->system_manufacturer = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "Product Name: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->system_product = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->system_version = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "Serial Number: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->system_serial = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "UUID: ")) != NULL) {
        cur += 6;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->system_uuid = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "SKU Number: ")) != NULL) {
        cur += 12;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->system_sku = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }
    if ((cur = strstr(base, "Family: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        if ((eol) && ((ret->system_family = strndup(cur, eol - cur)) == NULL))
            goto no_memory;
    }

cleanup:
    VIR_FREE(outbuf);
    virCommandFree(cmd);

    return ret;

no_memory:
    virReportOOMError();

    virSysinfoDefFree(ret);
    ret = NULL;
    goto cleanup;
}
#endif
