/*
 * bhyve_firmware.c: bhyve firmware management
 *
 * Copyright (C) 2019 Red Hat, Inc.
 * Copyright (C) 2021 Roman Bogorodskiy
 * Copyright (C) 2025 The FreeBSD Foundation
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
#include "virstring.h"
#include "bhyve_conf.h"
#include "bhyve_firmware.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_firmware");


#define BHYVE_DEFAULT_FIRMWARE  "BHYVE_UEFI.fd"
#define BHYVE_DEFAULT_NVRAM_TEMPLATE    "BHYVE_UEFI_VARS.fd"

static void
bhyveFirmwareEnsureNVRAM(virDomainDef *def,
                         bhyveConn *driver)
{
    g_autoptr(virBhyveDriverConfig) cfg = virBhyveDriverGetConfig(driver);
    virDomainLoaderDef *loader = def->os.loader;
    const char *ext = NULL;

    if (!loader)
        return;

    if (loader->type != VIR_DOMAIN_LOADER_TYPE_PFLASH)
        return;

    if (loader->readonly != VIR_TRISTATE_BOOL_YES)
        return;

    if (loader->stateless == VIR_TRISTATE_BOOL_YES)
        return;

    /* If the NVRAM format hasn't been set yet, inherit the same as
     * the loader */
    if (loader->nvram && !loader->nvram->format)
        loader->nvram->format = loader->format;

    if (loader->nvram) {
        /* Nothing to do if a proper NVRAM backend is already configured */
        if (!virStorageSourceIsEmpty(loader->nvram))
            return;

        /* otherwise we want to reset and re-populate the definition */
        virObjectUnref(loader->nvram);
    } else {
        /* Only add nvram for "<os firmware='efi'/>" */
        if (def->os.firmware != VIR_DOMAIN_OS_DEF_FIRMWARE_EFI)
            return;
    }

    loader->nvram = virStorageSourceNew();
    loader->nvram->type = VIR_STORAGE_TYPE_FILE;

    /* The nvram template format should be always present but as a failsafe,
     * duplicate the loader format if it is not available. */
    if (loader->nvramTemplateFormat > VIR_STORAGE_FILE_NONE)
        loader->nvram->format = loader->nvramTemplateFormat;
    else
        loader->nvram->format = loader->format;

    /* The extension used by raw edk2 builds has historically
     * been .fd, but more recent aarch64 builds have started
     * using the .raw extension instead.
     *
     * If we're defining a new domain, we should try to match the
     * extension for the file backing its NVRAM store with the
     * one used by the template to keep things nice and
     * consistent.
     *
     * If we're loading an existing domain, however, we need to
     * stick with the .fd extension to ensure compatibility */
    if (loader->nvramTemplate &&
        virStringHasSuffix(loader->nvramTemplate, ".raw"))
        ext = ".raw";
    else
        ext = ".fd";

    loader->nvram->path = g_strdup_printf("%s/%s_VARS%s",
                                          cfg->nvramDir, def->name,
                                          NULLSTR_EMPTY(ext));
}

int
bhyveFirmwareFillDomain(bhyveConn *driver,
                        virDomainDef *def,
                        unsigned int flags)
{
    g_autoptr(DIR) dir = NULL;
    g_autoptr(virBhyveDriverConfig) cfg = virBhyveDriverGetConfig(driver);
    virDomainLoaderDef *loader = def->os.loader;
    const char *firmware_dir = cfg->firmwareDir;
    struct dirent *entry;
    g_autofree char *matching_firmware = NULL;
    g_autofree char *matching_nvram_template = NULL;
    g_autofree char *first_found = NULL;

    virCheckFlags(0, -1);

    if (!ARCH_IS_X86(def->os.arch))
        return 0;

    if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_NONE)
        goto out;

    if (virDirOpenIfExists(&dir, firmware_dir) > 0) {
        while ((virDirRead(dir, &entry, firmware_dir)) > 0) {
            if (g_str_has_prefix(entry->d_name, "."))
                continue;

            if (!matching_firmware &&
                STREQ(entry->d_name, BHYVE_DEFAULT_FIRMWARE))
                matching_firmware = g_strdup(entry->d_name);

            if (!matching_nvram_template &&
                STREQ(entry->d_name, BHYVE_DEFAULT_NVRAM_TEMPLATE))
                matching_nvram_template = g_strdup(entry->d_name);

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

    if (!loader) {
        loader = virDomainLoaderDefNew();
        def->os.loader = loader;
    }

    if (!loader->format)
        loader->format = VIR_STORAGE_FILE_RAW;

    if (loader->format != VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported loader format '%1$s'"),
                       virStorageFileFormatTypeToString(loader->format));
        return -1;
    }

    if (!loader->nvramTemplate
        && matching_firmware && matching_nvram_template) {
        loader->nvramTemplate = g_build_filename(firmware_dir,
                                                 matching_nvram_template,
                                                 NULL);
    }

    loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
    loader->readonly = VIR_TRISTATE_BOOL_YES;

    VIR_FREE(loader->path);

    loader->path = g_build_filename(firmware_dir, matching_firmware, NULL);

 out:
    bhyveFirmwareEnsureNVRAM(def, driver);

    return 0;
}
