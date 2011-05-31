/*
 * sysinfo.c: get SMBIOS/sysinfo information from the host
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
#include "logging.h"
#include "memory.h"
#include "command.h"

#define VIR_FROM_THIS VIR_FROM_SYSINFO

#define virSmbiosReportError(code, ...)                               \
    virReportErrorHelper(VIR_FROM_SYSINFO, code, __FILE__,            \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#define SYSINFO_SMBIOS_DECODER "dmidecode"

VIR_ENUM_IMPL(virSysinfo, VIR_SYSINFO_LAST,
              "smbios");

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

#else /* !WIN32 */

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

    ret->type = VIR_SYSINFO_SMBIOS;

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
#endif /* !WIN32 */

/**
 * virSysinfoFormat:
 * @def: structure to convert to xml string
 * @prefix: string to prefix before each line of xml
 *
 * This returns the XML description of the sysinfo, or NULL after
 * generating an error message.
 */
char *
virSysinfoFormat(virSysinfoDefPtr def, const char *prefix)
{
    const char *type = virSysinfoTypeToString(def->type);
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t len = strlen(prefix);

    if (!type) {
        virSmbiosReportError(VIR_ERR_INTERNAL_ERROR,
                             _("unexpected sysinfo type model %d"),
                             def->type);
        return NULL;
    }

    virBufferAsprintf(&buf, "%s<sysinfo type='%s'>\n", prefix, type);
    if ((def->bios_vendor != NULL) || (def->bios_version != NULL) ||
        (def->bios_date != NULL) || (def->bios_release != NULL)) {
        virBufferAsprintf(&buf, "%s  <bios>\n", prefix);
        if (def->bios_vendor != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='vendor'>%s</entry>\n",
                                  def->bios_vendor);
        }
        if (def->bios_version != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='version'>%s</entry>\n",
                                  def->bios_version);
        }
        if (def->bios_date != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='date'>%s</entry>\n",
                                  def->bios_date);
        }
        if (def->bios_release != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='release'>%s</entry>\n",
                                  def->bios_release);
        }
        virBufferAsprintf(&buf, "%s  </bios>\n", prefix);
    }
    if ((def->system_manufacturer != NULL) || (def->system_product != NULL) ||
        (def->system_version != NULL) || (def->system_serial != NULL) ||
        (def->system_uuid != NULL) || (def->system_sku != NULL) ||
        (def->system_family != NULL)) {
        virBufferAsprintf(&buf, "%s  <system>\n", prefix);
        if (def->system_manufacturer != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='manufacturer'>%s</entry>\n",
                                  def->system_manufacturer);
        }
        if (def->system_product != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='product'>%s</entry>\n",
                                  def->system_product);
        }
        if (def->system_version != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='version'>%s</entry>\n",
                                  def->system_version);
        }
        if (def->system_serial != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='serial'>%s</entry>\n",
                                  def->system_serial);
        }
        if (def->system_uuid != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='uuid'>%s</entry>\n",
                                  def->system_uuid);
        }
        if (def->system_sku != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='sku'>%s</entry>\n",
                                  def->system_sku);
        }
        if (def->system_family != NULL) {
            virBufferAdd(&buf, prefix, len);
            virBufferEscapeString(&buf,
                                  "    <entry name='family'>%s</entry>\n",
                                  def->system_family);
        }
        virBufferAsprintf(&buf, "%s  </system>\n", prefix);
    }

    virBufferAsprintf(&buf, "%s</sysinfo>\n", prefix);

    return virBufferContentAndReset(&buf);
}

bool virSysinfoIsEqual(virSysinfoDefPtr src,
                       virSysinfoDefPtr dst)
{
    bool identical = false;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virSmbiosReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                             _("Target sysinfo does not match source"));
        goto cleanup;
    }

    if (src->type != dst->type) {
        virSmbiosReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                             _("Target sysinfo %s does not match source %s"),
                             virSysinfoTypeToString(dst->type),
                             virSysinfoTypeToString(src->type));
        goto cleanup;
    }

#define CHECK_FIELD(name, desc)                                         \
    do {                                                                \
        if (STRNEQ_NULLABLE(src->name, dst->name)) {                    \
            virSmbiosReportError(VIR_ERR_CONFIG_UNSUPPORTED,            \
                                 _("Target sysinfo %s %s does not match source %s"), \
                                 desc, NULLSTR(src->name), NULLSTR(dst->name)); \
        }                                                               \
    } while (0)

    CHECK_FIELD(bios_vendor, "BIOS vendor");
    CHECK_FIELD(bios_version, "BIOS version");
    CHECK_FIELD(bios_date, "BIOS date");
    CHECK_FIELD(bios_release, "BIOS release");

    CHECK_FIELD(system_manufacturer, "system vendor");
    CHECK_FIELD(system_product, "system product");
    CHECK_FIELD(system_version, "system version");
    CHECK_FIELD(system_serial, "system serial");
    CHECK_FIELD(system_uuid, "system uuid");
    CHECK_FIELD(system_sku, "system sku");
    CHECK_FIELD(system_family, "system family");

#undef CHECK_FIELD

    identical = true;

cleanup:
    return identical;
}
