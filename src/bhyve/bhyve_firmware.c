/*
 * bhyve_firmware.c: bhyve firmware management
 *
 * Copyright (C) 2021 Roman Bogorodskiy
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
 *
 */

#include <config.h>
#include <dirent.h>

#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "bhyve_conf.h"
#include "bhyve_firmware.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_firmware");


#define BHYVE_DEFAULT_FIRMWARE  "BHYVE_UEFI.fd"

int
bhyveFirmwareFillDomain(bhyveConn *driver,
                        virDomainDef *def,
                        unsigned int flags)
{
    g_autoptr(DIR) dir = NULL;
    g_autoptr(virBhyveDriverConfig) cfg = virBhyveDriverGetConfig(driver);
    const char *firmware_dir = cfg->firmwareDir;
    struct dirent *entry;
    g_autofree char *matching_firmware = NULL;
    g_autofree char *first_found = NULL;

    virCheckFlags(0, -1);

    if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_NONE)
        return 0;

    if (virDirOpenIfExists(&dir, firmware_dir) > 0) {
        while ((virDirRead(dir, &entry, firmware_dir)) > 0) {
            if (g_str_has_prefix(entry->d_name, "."))
                continue;

            if (STREQ(entry->d_name, BHYVE_DEFAULT_FIRMWARE)) {
                matching_firmware = g_strdup(entry->d_name);
                break;
            }
            if (!first_found)
                first_found = g_strdup(entry->d_name);
        }
    }

    if (!matching_firmware) {
        if (!first_found) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no firmwares found in %1$s"),
                           firmware_dir);
            return -1;
        } else {
            matching_firmware = g_steal_pointer(&first_found);
        }
    }

    if (!def->os.loader)
        def->os.loader = virDomainLoaderDefNew();

    if (!def->os.loader->format)
        def->os.loader->format = VIR_STORAGE_FILE_RAW;

    if (def->os.loader->format != VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported loader format '%1$s'"),
                       virStorageFileFormatTypeToString(def->os.loader->format));
        return -1;
    }

    def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
    def->os.loader->readonly = VIR_TRISTATE_BOOL_YES;

    VIR_FREE(def->os.loader->path);

    def->os.loader->path = g_build_filename(firmware_dir, matching_firmware, NULL);

    return 0;
}
