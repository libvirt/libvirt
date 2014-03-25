/*
 * virsysinfo.c: get SMBIOS/sysinfo information from the host
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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

#include "virerror.h"
#include "virsysinfo.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SYSINFO


VIR_ENUM_IMPL(virSysinfo, VIR_SYSINFO_LAST,
              "smbios");

static const char *sysinfoDmidecode = DMIDECODE;
static const char *sysinfoSysinfo = "/proc/sysinfo";
static const char *sysinfoCpuinfo = "/proc/cpuinfo";

#define SYSINFO_SMBIOS_DECODER sysinfoDmidecode
#define SYSINFO sysinfoSysinfo
#define CPUINFO sysinfoCpuinfo

/* only to be used test programs, therefore not in sysinfo.h */
extern void virSysinfoSetup(const char *dmidecode, const char *sysinfo,
                            const char *cpuinfo);

void virSysinfoSetup(const char *dmidecode, const char *sysinfo,
                     const char *cpuinfo)
{
    sysinfoDmidecode = dmidecode;
    sysinfoSysinfo = sysinfo;
    sysinfoCpuinfo = cpuinfo;
}

/**
 * virSysinfoDefFree:
 * @def: a sysinfo structure
 *
 * Free up the sysinfo structure
 */

void virSysinfoDefFree(virSysinfoDefPtr def)
{
    size_t i;

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

    for (i = 0; i < def->nprocessor; i++) {
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
    for (i = 0; i < def->nmemory; i++) {
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

#if defined(__powerpc__)
static int
virSysinfoParseSystem(const char *base, virSysinfoDefPtr ret)
{
    char *eol = NULL;
    const char *cur;

    if ((cur = strstr(base, "platform")) == NULL)
        return 0;

    base = cur;
    /* Account for format 'platform    : XXXX'*/
    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (eol && VIR_STRNDUP(ret->system_family, cur, eol - cur) < 0)
        return -1;

    if ((cur = strstr(base, "model")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(ret->system_serial, cur, eol - cur) < 0)
            return -1;
    }

    if ((cur = strstr(base, "machine")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(ret->system_version, cur, eol - cur) < 0)
            return -1;
    }

    return 0;
}

static int
virSysinfoParseProcessor(const char *base, virSysinfoDefPtr ret)
{
    const char *cur;
    char *eol, *tmp_base;
    virSysinfoProcessorDefPtr processor;

    while ((tmp_base = strstr(base, "processor")) != NULL) {
        base = tmp_base;
        eol = strchr(base, '\n');
        cur = strchr(base, ':') + 1;

        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0) {
            return -1;
        }
        processor = &ret->processor[ret->nprocessor - 1];

        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(processor->processor_socket_destination,
                               cur, eol - cur) < 0)
            return -1;

        if ((cur = strstr(base, "cpu")) != NULL) {
            cur = strchr(cur, ':') + 1;
            eol = strchr(cur, '\n');
            virSkipSpaces(&cur);
            if (eol && VIR_STRNDUP(processor->processor_type,
                                   cur, eol - cur) < 0)
                return -1;
        }

        if ((cur = strstr(base, "revision")) != NULL) {
            cur = strchr(cur, ':') + 1;
            eol = strchr(cur, '\n');
            virSkipSpaces(&cur);
            if (eol && VIR_STRNDUP(processor->processor_version,
                                   cur, eol - cur) < 0)
                return -1;
        }

        base = cur;
    }

    return 0;
}

/* virSysinfoRead for PowerPC
 * Gathers sysinfo data from /proc/cpuinfo */
virSysinfoDefPtr
virSysinfoRead(void)
{
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    if (virFileReadAll(CPUINFO, 2048, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return NULL;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseProcessor(outbuf, ret) < 0)
        goto no_memory;

    if (virSysinfoParseSystem(outbuf, ret) < 0)
        goto no_memory;

    return ret;

 no_memory:
    VIR_FREE(outbuf);
    return NULL;
}

#elif defined(__arm__) || defined(__aarch64__)
static int
virSysinfoParseSystem(const char *base, virSysinfoDefPtr ret)
{
    char *eol = NULL;
    const char *cur;

    if ((cur = strstr(base, "platform")) == NULL)
        return 0;

    base = cur;
    /* Account for format 'platform    : XXXX'*/
    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (eol && VIR_STRNDUP(ret->system_family, cur, eol - cur) < 0)
        return -1;

    if ((cur = strstr(base, "model")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(ret->system_serial, cur, eol - cur) < 0)
            return -1;
    }

    if ((cur = strstr(base, "machine")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(ret->system_version, cur, eol - cur) < 0)
            return -1;
    }

    return 0;
}

static int
virSysinfoParseProcessor(const char *base, virSysinfoDefPtr ret)
{
    const char *cur;
    char *eol, *tmp_base;
    virSysinfoProcessorDefPtr processor;
    char *processor_type = NULL;

    if (!(tmp_base = strstr(base, "Processor")))
        return 0;

    base = tmp_base;
    eol = strchr(base, '\n');
    cur = strchr(base, ':') + 1;
    virSkipSpaces(&cur);
    if (eol && VIR_STRNDUP(processor_type, cur, eol - cur) < 0)
        goto error;
    base = cur;

    while ((tmp_base = strstr(base, "processor")) != NULL) {
        base = tmp_base;
        eol = strchr(base, '\n');
        cur = strchr(base, ':') + 1;

        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            goto error;
        processor = &ret->processor[ret->nprocessor - 1];

        virSkipSpaces(&cur);
        if (eol &&
            VIR_STRNDUP(processor->processor_socket_destination,
                        cur, eol - cur) < 0)
            goto error;

        if (processor_type &&
            VIR_STRDUP(processor->processor_type, processor_type) < 0)
            goto error;

        base = cur;
    }

    VIR_FREE(processor_type);
    return 0;

 error:
    VIR_FREE(processor_type);
    return -1;
}

/* virSysinfoRead for ARMv7
 * Gathers sysinfo data from /proc/cpuinfo */
virSysinfoDefPtr
virSysinfoRead(void)
{
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    if (virFileReadAll(CPUINFO, 2048, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return NULL;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseProcessor(outbuf, ret) < 0)
        goto no_memory;

    if (virSysinfoParseSystem(outbuf, ret) < 0)
        goto no_memory;

    return ret;

 no_memory:
    VIR_FREE(outbuf);
    return NULL;
}


#elif defined(__s390__) || defined(__s390x__)
/*
  we need to ignore warnings about strchr caused by -Wlogical-op
  for some GCC versions.
  Doing it via a local pragma keeps the damage smaller than
  disabling it on the package level.
  Unfortunately, the affected GCCs don't allow diagnostic push/pop
  which would have further reduced the impact.
 */
# if BROKEN_GCC_WLOGICALOP
#  pragma GCC diagnostic ignored "-Wlogical-op"
# endif

static char *
virSysinfoParseDelimited(const char *base, const char *name, char **value,
                         char delim1, char delim2)
{
    const char *start;
    char *end;

    if (delim1 != delim2 &&
        (start = strstr(base, name)) &&
        (start = strchr(start, delim1))) {
        start += 1;
        end = strchrnul(start, delim2);
        virSkipSpaces(&start);
        if (VIR_STRNDUP(*value, start, end - start) < 0)
            return NULL;
        virTrimSpaces(*value, NULL);
        return end;
    }
    return NULL;
}

static char *
virSysinfoParseLine(const char *base, const char *name, char **value)
{
    return virSysinfoParseDelimited(base, name, value, ':', '\n');
}

static int
virSysinfoParseSystem(const char *base, virSysinfoDefPtr ret)
{
    if (virSysinfoParseLine(base, "Manufacturer",
                            &ret->system_manufacturer) &&
        virSysinfoParseLine(base, "Type",
                            &ret->system_family) &&
        virSysinfoParseLine(base, "Sequence Code",
                            &ret->system_serial))
        return 0;
    else
        return -1;
}

static int
virSysinfoParseProcessor(const char *base, virSysinfoDefPtr ret)
{
    char *tmp_base;
    char *manufacturer = NULL;
    char *procline = NULL;
    int result = -1;
    virSysinfoProcessorDefPtr processor;

    if (!(tmp_base = virSysinfoParseLine(base, "vendor_id", &manufacturer)))
        goto cleanup;

    /* Find processor N: line and gather the processor manufacturer,
       version, serial number, and family */
    while ((tmp_base = strstr(tmp_base, "processor "))
           && (tmp_base = virSysinfoParseLine(tmp_base, "processor ",
                                              &procline))) {
        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            goto cleanup;
        processor = &ret->processor[ret->nprocessor - 1];
        if (VIR_STRDUP(processor->processor_manufacturer, manufacturer) < 0)
            goto cleanup;
        if (!virSysinfoParseDelimited(procline, "version",
                                      &processor->processor_version,
                                      '=', ',') ||
            !virSysinfoParseDelimited(procline, "identification",
                                      &processor->processor_serial_number,
                                      '=', ',') ||
            !virSysinfoParseDelimited(procline, "machine",
                                      &processor->processor_family,
                                      '=', '\n'))
            goto cleanup;
    }
    result = 0;

 cleanup:
    VIR_FREE(manufacturer);
    VIR_FREE(procline);
    return result;
}

/* virSysinfoRead for s390x
 * Gathers sysinfo data from /proc/sysinfo and /proc/cpuinfo */
virSysinfoDefPtr
virSysinfoRead(void)
{
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    /* Gather info from /proc/cpuinfo */
    if (virFileReadAll(CPUINFO, 8192, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return NULL;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseProcessor(outbuf, ret) < 0)
        goto no_memory;

    /* Free buffer before reading next file */
    VIR_FREE(outbuf);

    /* Gather info from /proc/sysinfo */
    if (virFileReadAll(SYSINFO, 8192, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), SYSINFO);
        return NULL;
    }

    if (virSysinfoParseSystem(outbuf, ret) < 0)
        goto no_memory;

    return ret;

 no_memory:
    virSysinfoDefFree(ret);
    VIR_FREE(outbuf);
    return NULL;
}

#elif defined(WIN32) || \
    !(defined(__x86_64__) || \
      defined(__i386__) ||   \
      defined(__amd64__) || \
      defined(__arm__) || \
      defined(__aarch64__) || \
      defined(__powerpc__))
virSysinfoDefPtr
virSysinfoRead(void)
{
    /*
     * this can probably be extracted from Windows using API or registry
     * http://www.microsoft.com/whdc/system/platform/firmware/SMBIOS.mspx
     */
    virReportSystemError(ENOSYS, "%s",
                         _("Host sysinfo extraction not supported on this platform"));
    return NULL;
}

#else /* !WIN32 && x86 */

static int
virSysinfoParseBIOS(const char *base, virSysinfoDefPtr ret)
{
    const char *cur, *eol = NULL;

    if ((cur = strstr(base, "BIOS Information")) == NULL)
        return 0;

    base = cur;
    if ((cur = strstr(base, "Vendor: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->bios_vendor, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->bios_version, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "Release Date: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->bios_date, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "BIOS Revision: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->bios_release, cur, eol - cur) < 0)
            return -1;
    }

    return 0;
}

static int
virSysinfoParseSystem(const char *base, virSysinfoDefPtr ret)
{
    const char *cur, *eol = NULL;

    if ((cur = strstr(base, "System Information")) == NULL)
        return 0;

    base = cur;
    if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_manufacturer, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "Product Name: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_product, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_version, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "Serial Number: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_serial, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "UUID: ")) != NULL) {
        cur += 6;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_uuid, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "SKU Number: ")) != NULL) {
        cur += 12;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_sku, cur, eol - cur) < 0)
            return -1;
    }
    if ((cur = strstr(base, "Family: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(ret->system_family, cur, eol - cur) < 0)
            return -1;
    }

    return 0;
}

static int
virSysinfoParseProcessor(const char *base, virSysinfoDefPtr ret)
{
    const char *cur, *tmp_base;
    char *eol;
    virSysinfoProcessorDefPtr processor;

    while ((tmp_base = strstr(base, "Processor Information")) != NULL) {
        base = tmp_base;
        eol = NULL;

        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            return -1;
        processor = &ret->processor[ret->nprocessor - 1];

        if ((cur = strstr(base, "Socket Designation: ")) != NULL) {
            cur += 20;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_socket_destination,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Type: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_type, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Family: ")) != NULL) {
            cur += 8;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_family, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_manufacturer,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Signature: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_signature,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Version: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_version,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "External Clock: ")) != NULL) {
            cur += 16;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_external_clock,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Max Speed: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_max_speed,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Status: ")) != NULL) {
            cur += 8;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_status, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_serial_number,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Part Number: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(processor->processor_part_number,
                                   cur, eol - cur) < 0)
                return -1;
        }

        base += strlen("Processor Information");
    }

    return 0;
}

static int
virSysinfoParseMemory(const char *base, virSysinfoDefPtr ret)
{
    const char *cur, *tmp_base;
    char *eol;
    virSysinfoMemoryDefPtr memory;

    while ((tmp_base = strstr(base, "Memory Device")) != NULL) {
        base = tmp_base;
        eol = NULL;

        if (VIR_EXPAND_N(ret->memory, ret->nmemory, 1) < 0)
            return -1;
        memory = &ret->memory[ret->nmemory - 1];

        if ((cur = strstr(base, "Size: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            if (STREQLEN(cur, "No Module Installed", eol - cur))
                goto next;

            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_size, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Form Factor: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_form_factor,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Locator: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_locator, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Bank Locator: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_bank_locator,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Type: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_type, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Type Detail: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_type_detail, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Speed: ")) != NULL) {
            cur += 7;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_speed, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_manufacturer, cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_serial_number,
                                   cur, eol - cur) < 0)
                return -1;
        }
        if ((cur = strstr(base, "Part Number: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol && VIR_STRNDUP(memory->memory_part_number, cur, eol - cur) < 0)
                return -1;
        }

    next:
        base += strlen("Memory Device");
    }

    return 0;
}

virSysinfoDefPtr
virSysinfoRead(void)
{
    char *path;
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;
    virCommandPtr cmd;

    path = virFindFileInPath(SYSINFO_SMBIOS_DECODER);
    if (path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find path for %s binary"),
                       SYSINFO_SMBIOS_DECODER);
        return NULL;
    }

    cmd = virCommandNewArgList(path, "-q", "-t", "0,1,4,17", NULL);
    VIR_FREE(path);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_ALLOC(ret) < 0)
        goto error;

    ret->type = VIR_SYSINFO_SMBIOS;

    if (virSysinfoParseBIOS(outbuf, ret) < 0)
        goto error;

    if (virSysinfoParseSystem(outbuf, ret) < 0)
        goto error;

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseProcessor(outbuf, ret) < 0)
        goto error;

    ret->nmemory = 0;
    ret->memory = NULL;
    if (virSysinfoParseMemory(outbuf, ret) < 0)
        goto error;

 cleanup:
    VIR_FREE(outbuf);
    virCommandFree(cmd);

    return ret;

 error:
    virSysinfoDefFree(ret);
    ret = NULL;
    goto cleanup;
}
#endif /* !WIN32 && x86 */

static void
virSysinfoBIOSFormat(virBufferPtr buf, virSysinfoDefPtr def)
{
    if (!def->bios_vendor && !def->bios_version &&
        !def->bios_date && !def->bios_release)
        return;

    virBufferAddLit(buf, "<bios>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<entry name='vendor'>%s</entry>\n",
                          def->bios_vendor);
    virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                          def->bios_version);
    virBufferEscapeString(buf, "<entry name='date'>%s</entry>\n",
                          def->bios_date);
    virBufferEscapeString(buf, "<entry name='release'>%s</entry>\n",
                          def->bios_release);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bios>\n");
}

static void
virSysinfoSystemFormat(virBufferPtr buf, virSysinfoDefPtr def)
{
    if (!def->system_manufacturer && !def->system_product &&
        !def->system_version && !def->system_serial &&
        !def->system_uuid && !def->system_sku && !def->system_family)
        return;

    virBufferAddLit(buf, "<system>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<entry name='manufacturer'>%s</entry>\n",
                          def->system_manufacturer);
    virBufferEscapeString(buf, "<entry name='product'>%s</entry>\n",
                          def->system_product);
    virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                          def->system_version);
    virBufferEscapeString(buf, "<entry name='serial'>%s</entry>\n",
                          def->system_serial);
    virBufferEscapeString(buf, "<entry name='uuid'>%s</entry>\n",
                          def->system_uuid);
    virBufferEscapeString(buf, "<entry name='sku'>%s</entry>\n",
                          def->system_sku);
    virBufferEscapeString(buf, "<entry name='family'>%s</entry>\n",
                          def->system_family);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</system>\n");
}

static void
virSysinfoProcessorFormat(virBufferPtr buf, virSysinfoDefPtr def)
{
    size_t i;
    virSysinfoProcessorDefPtr processor;

    for (i = 0; i < def->nprocessor; i++) {
        processor = &def->processor[i];

        if (!processor->processor_socket_destination &&
            !processor->processor_type &&
            !processor->processor_family &&
            !processor->processor_manufacturer &&
            !processor->processor_signature &&
            !processor->processor_version &&
            !processor->processor_external_clock &&
            !processor->processor_max_speed &&
            !processor->processor_status &&
            !processor->processor_serial_number &&
            !processor->processor_part_number)
            continue;

        virBufferAddLit(buf, "<processor>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf,
                              "<entry name='socket_destination'>%s</entry>\n",
                              processor->processor_socket_destination);
        virBufferEscapeString(buf, "<entry name='type'>%s</entry>\n",
                              processor->processor_type);
        virBufferEscapeString(buf, "<entry name='family'>%s</entry>\n",
                              processor->processor_family);
        virBufferEscapeString(buf, "<entry name='manufacturer'>%s</entry>\n",
                              processor->processor_manufacturer);
        virBufferEscapeString(buf, "<entry name='signature'>%s</entry>\n",
                              processor->processor_signature);
        virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                              processor->processor_version);
        virBufferEscapeString(buf, "<entry name='external_clock'>%s</entry>\n",
                              processor->processor_external_clock);
        virBufferEscapeString(buf, "<entry name='max_speed'>%s</entry>\n",
                              processor->processor_max_speed);
        virBufferEscapeString(buf, "<entry name='status'>%s</entry>\n",
                              processor->processor_status);
        virBufferEscapeString(buf, "<entry name='serial_number'>%s</entry>\n",
                              processor->processor_serial_number);
        virBufferEscapeString(buf, "<entry name='part_number'>%s</entry>\n",
                              processor->processor_part_number);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</processor>\n");
    }
}

static void
virSysinfoMemoryFormat(virBufferPtr buf, virSysinfoDefPtr def)
{
    size_t i;
    virSysinfoMemoryDefPtr memory;

    for (i = 0; i < def->nmemory; i++) {
        memory = &def->memory[i];

        if (!memory->memory_size &&
            !memory->memory_form_factor &&
            !memory->memory_locator &&
            !memory->memory_bank_locator &&
            !memory->memory_type &&
            !memory->memory_type_detail &&
            !memory->memory_speed &&
            !memory->memory_manufacturer &&
            !memory->memory_serial_number &&
            !memory->memory_part_number)
            continue;

        virBufferAddLit(buf, "<memory_device>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<entry name='size'>%s</entry>\n",
                              memory->memory_size);
        virBufferEscapeString(buf,
                              "<entry name='form_factor'>%s</entry>\n",
                              memory->memory_form_factor);
        virBufferEscapeString(buf, "<entry name='locator'>%s</entry>\n",
                              memory->memory_locator);
        virBufferEscapeString(buf,
                              "<entry name='bank_locator'>%s</entry>\n",
                              memory->memory_bank_locator);
        virBufferEscapeString(buf, "<entry name='type'>%s</entry>\n",
                              memory->memory_type);
        virBufferEscapeString(buf,
                              "<entry name='type_detail'>%s</entry>\n",
                              memory->memory_type_detail);
        virBufferEscapeString(buf, "<entry name='speed'>%s</entry>\n",
                              memory->memory_speed);
        virBufferEscapeString(buf,
                              "<entry name='manufacturer'>%s</entry>\n",
                              memory->memory_manufacturer);
        virBufferEscapeString(buf,
                              "<entry name='serial_number'>%s</entry>\n",
                              memory->memory_serial_number);
        virBufferEscapeString(buf,
                              "<entry name='part_number'>%s</entry>\n",
                              memory->memory_part_number);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</memory_device>\n");
    }
}

/**
 * virSysinfoFormat:
 * @buf: buffer to append output to (may use auto-indentation)
 * @def: structure to convert to xml string
 *
 * Returns 0 on success, -1 on failure after generating an error message.
 */
int
virSysinfoFormat(virBufferPtr buf, virSysinfoDefPtr def)
{
    const char *type = virSysinfoTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected sysinfo type model %d"),
                       def->type);
        virBufferFreeAndReset(buf);
        return -1;
    }

    virBufferAsprintf(buf, "<sysinfo type='%s'>\n", type);
    virBufferAdjustIndent(buf, 2);

    virSysinfoBIOSFormat(buf, def);
    virSysinfoSystemFormat(buf, def);
    virSysinfoProcessorFormat(buf, def);
    virSysinfoMemoryFormat(buf, def);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</sysinfo>\n");

    if (virBufferError(buf)) {
        virReportOOMError();
        return -1;
    }

    return 0;
}

bool virSysinfoIsEqual(virSysinfoDefPtr src,
                       virSysinfoDefPtr dst)
{
    bool identical = false;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target sysinfo does not match source"));
        goto cleanup;
    }

    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sysinfo %s does not match source %s"),
                       virSysinfoTypeToString(dst->type),
                       virSysinfoTypeToString(src->type));
        goto cleanup;
    }

#define CHECK_FIELD(name, desc)                                         \
    do {                                                                \
        if (STRNEQ_NULLABLE(src->name, dst->name)) {                    \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,                  \
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
