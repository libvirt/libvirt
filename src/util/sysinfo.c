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
    int i;

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

    for (i = 0;i < def->nprocessor;i++) {
        VIR_FREE(def->processor[i].processor_socket_destination);
        VIR_FREE(def->processor[i].processor_type);
        VIR_FREE(def->processor[i].processor_family);
        VIR_FREE(def->processor[i].processor_manufacturer);
        VIR_FREE(def->processor[i].processor_signature);
        VIR_FREE(def->processor[i].processor_version);
        VIR_FREE(def->processor[i].processor_external_clock);
        VIR_FREE(def->processor[i].processor_max_speed);
        VIR_FREE(def->processor[i].processor_status);
        VIR_FREE(def->processor[i].processor_serial_number);
        VIR_FREE(def->processor[i].processor_part_number);
    }
    VIR_FREE(def->processor);
    for (i = 0;i < def->nmemory;i++) {
        VIR_FREE(def->memory[i].memory_size);
        VIR_FREE(def->memory[i].memory_form_factor);
        VIR_FREE(def->memory[i].memory_locator);
        VIR_FREE(def->memory[i].memory_bank_locator);
        VIR_FREE(def->memory[i].memory_type);
        VIR_FREE(def->memory[i].memory_type_detail);
        VIR_FREE(def->memory[i].memory_speed);
        VIR_FREE(def->memory[i].memory_manufacturer);
        VIR_FREE(def->memory[i].memory_serial_number);
        VIR_FREE(def->memory[i].memory_part_number);
    }
    VIR_FREE(def->memory);

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

static char *
virSysinfoParseBIOS(char *base, virSysinfoDefPtr ret)
{
    char *cur, *eol = NULL;

    if ((cur = strstr(base, "BIOS Information")) == NULL)
        return base;

    base = cur;
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

    return base + strlen("BIOS Information");

no_memory:
    return NULL;
}

static char *
virSysinfoParseSystem(char *base, virSysinfoDefPtr ret)
{
    char *cur, *eol = NULL;

    if ((cur = strstr(base, "System Information")) == NULL)
        return base;

    base = cur;
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

    return base + strlen("System Information");

no_memory:
    return NULL;
}

static char *
virSysinfoParseProcessor(char *base, virSysinfoDefPtr ret)
{
    char *cur, *eol, *tmp_base;
    virSysinfoProcessorDefPtr processor;

    while((tmp_base = strstr(base, "Processor Information")) != NULL) {
        base = tmp_base;
        eol = NULL;

        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0) {
            goto no_memory;
        }
        processor = &ret->processor[ret->nprocessor - 1];

        if ((cur = strstr(base, "Socket Designation: ")) != NULL) {
            cur += 20;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_socket_destination = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Type: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_type = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Family: ")) != NULL) {
            cur += 8;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_family = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_manufacturer = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Signature: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_signature = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Version: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_version = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "External Clock: ")) != NULL) {
            cur += 16;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_external_clock = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Max Speed: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_max_speed = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Status: ")) != NULL) {
            cur += 8;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_status = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_serial_number = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Part Number: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((processor->processor_part_number = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }

        base += strlen("Processor Information");
    }

    return base;

no_memory:
    return NULL;
}

static char *
virSysinfoParseMemory(char *base, virSysinfoDefPtr ret)
{
    char *cur, *eol, *tmp_base;
    virSysinfoMemoryDefPtr memory;

    while ((tmp_base = strstr(base, "Memory Device")) != NULL) {
        base = tmp_base;
        eol = NULL;

        if (VIR_EXPAND_N(ret->memory, ret->nmemory, 1) < 0) {
            goto no_memory;
        }
        memory = &ret->memory[ret->nmemory - 1];

        if ((cur = strstr(base, "Size: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            if (STREQLEN(cur, "No Module Installed", eol - cur))
                goto next;

            if ((eol) &&
                ((memory->memory_size = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Form Factor: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_form_factor = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Locator: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_locator = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Bank Locator: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_bank_locator = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Type: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_type = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Type Detail: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_type_detail = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Speed: ")) != NULL) {
            cur += 7;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_speed = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_manufacturer = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_serial_number = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }
        if ((cur = strstr(base, "Part Number: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            if ((eol) &&
                ((memory->memory_part_number = strndup(cur, eol - cur)) == NULL))
                goto no_memory;
        }

    next:
        base += strlen("Memory Device");
    }

    return base;

no_memory:
    return NULL;
}

virSysinfoDefPtr
virSysinfoRead(void) {
    char *path, *base;
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

    cmd = virCommandNewArgList(path, "-q", "-t", "0,1,4,17", NULL);
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

    if ((base = virSysinfoParseBIOS(base, ret)) == NULL)
        goto no_memory;

    if ((base = virSysinfoParseSystem(base, ret)) == NULL)
        goto no_memory;

    ret->nprocessor = 0;
    ret->processor = NULL;
    if ((base = virSysinfoParseProcessor(base, ret)) == NULL)
        goto no_memory;

    ret->nmemory = 0;
    ret->memory = NULL;
    if (virSysinfoParseMemory(base, ret) == NULL)
        goto no_memory;

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

static void
virSysinfoBIOSFormat(virSysinfoDefPtr def, const char *prefix,
                     virBufferPtr buf)
{
    int len = strlen(prefix);

    if ((def->bios_vendor != NULL) || (def->bios_version != NULL) ||
        (def->bios_date != NULL) || (def->bios_release != NULL)) {
        virBufferAsprintf(buf, "%s  <bios>\n", prefix);
        if (def->bios_vendor != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='vendor'>%s</entry>\n",
                                  def->bios_vendor);
        }
        if (def->bios_version != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='version'>%s</entry>\n",
                                  def->bios_version);
        }
        if (def->bios_date != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='date'>%s</entry>\n",
                                  def->bios_date);
        }
        if (def->bios_release != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='release'>%s</entry>\n",
                                  def->bios_release);
        }
        virBufferAsprintf(buf, "%s  </bios>\n", prefix);
    }

    return;
}

static void
virSysinfoSystemFormat(virSysinfoDefPtr def, const char *prefix,
                       virBufferPtr buf)
{
    int len = strlen(prefix);

    if ((def->system_manufacturer != NULL) || (def->system_product != NULL) ||
        (def->system_version != NULL) || (def->system_serial != NULL) ||
        (def->system_uuid != NULL) || (def->system_sku != NULL) ||
        (def->system_family != NULL)) {
        virBufferAsprintf(buf, "%s  <system>\n", prefix);
        if (def->system_manufacturer != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='manufacturer'>%s</entry>\n",
                                  def->system_manufacturer);
        }
        if (def->system_product != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='product'>%s</entry>\n",
                                  def->system_product);
        }
        if (def->system_version != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='version'>%s</entry>\n",
                                  def->system_version);
        }
        if (def->system_serial != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='serial'>%s</entry>\n",
                                  def->system_serial);
        }
        if (def->system_uuid != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='uuid'>%s</entry>\n",
                                  def->system_uuid);
        }
        if (def->system_sku != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='sku'>%s</entry>\n",
                                  def->system_sku);
        }
        if (def->system_family != NULL) {
            virBufferAdd(buf, prefix, len);
            virBufferEscapeString(buf,
                                  "    <entry name='family'>%s</entry>\n",
                                  def->system_family);
        }
        virBufferAsprintf(buf, "%s  </system>\n", prefix);
    }

    return;
}

static void
virSysinfoProcessorFormat(virSysinfoDefPtr def, const char *prefix,
                          virBufferPtr buf)
{
    int i;
    int len = strlen(prefix);
    virSysinfoProcessorDefPtr processor;

    for (i = 0; i < def->nprocessor; i++) {
        processor = &def->processor[i];

        if ((processor->processor_socket_destination != NULL) ||
            (processor->processor_type != NULL) ||
            (processor->processor_family != NULL) ||
            (processor->processor_manufacturer != NULL) ||
            (processor->processor_signature != NULL) ||
            (processor->processor_version != NULL) ||
            (processor->processor_external_clock != NULL) ||
            (processor->processor_max_speed != NULL) ||
            (processor->processor_status != NULL) ||
            (processor->processor_serial_number != NULL) ||
            (processor->processor_part_number != NULL)) {
            virBufferAsprintf(buf, "%s  <processor>\n", prefix);
            if (processor->processor_socket_destination != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='socket_destination'>%s</entry>\n",
                                      processor->processor_socket_destination);
            }
            if (processor->processor_type != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='type'>%s</entry>\n",
                                      processor->processor_type);
            }
            if (processor->processor_family != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='family'>%s</entry>\n",
                                      processor->processor_family);
            }
            if (processor->processor_manufacturer != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='manufacturer'>%s</entry>\n",
                                      processor->processor_manufacturer);
            }
            if (processor->processor_signature != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='signature'>%s</entry>\n",
                                      processor->processor_signature);
            }
            if (processor->processor_version != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='version'>%s</entry>\n",
                                      processor->processor_version);
            }
            if (processor->processor_external_clock != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='external_clock'>%s</entry>\n",
                                      processor->processor_external_clock);
            }
            if (processor->processor_max_speed != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='max_speed'>%s</entry>\n",
                                      processor->processor_max_speed);
            }
            if (processor->processor_status != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='status'>%s</entry>\n",
                                      processor->processor_status);
            }
            if (processor->processor_serial_number != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='serial_number'>%s</entry>\n",
                                      processor->processor_serial_number);
            }
            if (processor->processor_part_number != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='part_number'>%s</entry>\n",
                                      processor->processor_part_number);
            }
            virBufferAsprintf(buf, "%s  </processor>\n", prefix);
        }
    }

    return;
}

static void
virSysinfoMemoryFormat(virSysinfoDefPtr def, const char *prefix,
                             virBufferPtr buf)
{
    int i;
    int len = strlen(prefix);
    virSysinfoMemoryDefPtr memory;

    for (i = 0; i < def->nmemory; i++) {
        memory = &def->memory[i];

        if ((memory->memory_size != NULL) ||
            (memory->memory_form_factor != NULL) ||
            (memory->memory_locator != NULL) ||
            (memory->memory_bank_locator != NULL) ||
            (memory->memory_type != NULL) ||
            (memory->memory_type_detail != NULL) ||
            (memory->memory_speed != NULL) ||
            (memory->memory_manufacturer != NULL) ||
            (memory->memory_serial_number != NULL) ||
            (memory->memory_part_number != NULL)) {
            virBufferAsprintf(buf, "%s  <memory_device>\n", prefix);
            if (memory->memory_size != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='size'>%s</entry>\n",
                                      memory->memory_size);
            }
            if (memory->memory_form_factor != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='form_factor'>%s</entry>\n",
                                      memory->memory_form_factor);
            }
            if (memory->memory_locator != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='locator'>%s</entry>\n",
                                      memory->memory_locator);
            }
            if (memory->memory_bank_locator != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='bank_locator'>%s</entry>\n",
                                      memory->memory_bank_locator);
            }
            if (memory->memory_type != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='type'>%s</entry>\n",
                                      memory->memory_type);
            }
            if (memory->memory_type_detail != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='type_detail'>%s</entry>\n",
                                      memory->memory_type_detail);
            }
            if (memory->memory_speed != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='speed'>%s</entry>\n",
                                      memory->memory_speed);
            }
            if (memory->memory_manufacturer != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='manufacturer'>%s</entry>\n",
                                      memory->memory_manufacturer);
            }
            if (memory->memory_serial_number != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='serial_number'>%s</entry>\n",
                                      memory->memory_serial_number);
            }
            if (memory->memory_part_number != NULL) {
                virBufferAdd(buf, prefix, len);
                virBufferEscapeString(buf,
                                      "    <entry name='part_number'>%s</entry>\n",
                                      memory->memory_part_number);
            }
            virBufferAsprintf(buf, "%s  </memory_device>\n", prefix);
        }
    }

    return;
}

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

    if (!type) {
        virSmbiosReportError(VIR_ERR_INTERNAL_ERROR,
                             _("unexpected sysinfo type model %d"),
                             def->type);
        return NULL;
    }

    virBufferAsprintf(&buf, "%s<sysinfo type='%s'>\n", prefix, type);

    virSysinfoBIOSFormat(def, prefix, &buf);
    virSysinfoSystemFormat(def, prefix, &buf);
    virSysinfoProcessorFormat(def, prefix, &buf);
    virSysinfoMemoryFormat(def, prefix, &buf);

    virBufferAsprintf(&buf, "%s</sysinfo>\n", prefix);

    if (virBufferError(&buf)) {
        virReportOOMError();
        return NULL;
    }

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
