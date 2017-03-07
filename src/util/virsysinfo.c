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

#define __VIR_SYSINFO_PRIV_H_ALLOW__
#include "virsysinfopriv.h"

#define VIR_FROM_THIS VIR_FROM_SYSINFO


VIR_ENUM_IMPL(virSysinfo, VIR_SYSINFO_LAST,
              "smbios");

static const char *sysinfoDmidecode = DMIDECODE;
static const char *sysinfoSysinfo = "/proc/sysinfo";
static const char *sysinfoCpuinfo = "/proc/cpuinfo";

#define SYSINFO_SMBIOS_DECODER sysinfoDmidecode
#define SYSINFO sysinfoSysinfo
#define CPUINFO sysinfoCpuinfo
#define CPUINFO_FILE_LEN (1024*1024)	/* 1MB limit for /proc/cpuinfo file */


void
virSysinfoSetup(const char *dmidecode,
                const char *sysinfo,
                const char *cpuinfo)
{
    sysinfoDmidecode = dmidecode;
    sysinfoSysinfo = sysinfo;
    sysinfoCpuinfo = cpuinfo;
}

void virSysinfoBIOSDefFree(virSysinfoBIOSDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->vendor);
    VIR_FREE(def->version);
    VIR_FREE(def->date);
    VIR_FREE(def->release);
    VIR_FREE(def);
}

void virSysinfoSystemDefFree(virSysinfoSystemDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->manufacturer);
    VIR_FREE(def->product);
    VIR_FREE(def->version);
    VIR_FREE(def->serial);
    VIR_FREE(def->uuid);
    VIR_FREE(def->sku);
    VIR_FREE(def->family);
    VIR_FREE(def);
}

void virSysinfoBaseBoardDefClear(virSysinfoBaseBoardDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->manufacturer);
    VIR_FREE(def->product);
    VIR_FREE(def->version);
    VIR_FREE(def->serial);
    VIR_FREE(def->asset);
    VIR_FREE(def->location);
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

    virSysinfoBIOSDefFree(def->bios);
    virSysinfoSystemDefFree(def->system);

    for (i = 0; i < def->nbaseBoard; i++)
        virSysinfoBaseBoardDefClear(def->baseBoard + i);
    VIR_FREE(def->baseBoard);

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


static int
virSysinfoParsePPCSystem(const char *base, virSysinfoSystemDefPtr *sysdef)
{
    int ret = -1;
    char *eol = NULL;
    const char *cur;
    virSysinfoSystemDefPtr def;

    if ((cur = strstr(base, "platform")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    /* Account for format 'platform    : XXXX'*/
    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (eol && VIR_STRNDUP(def->family, cur, eol - cur) < 0)
        goto cleanup;

    if ((cur = strstr(base, "model")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(def->serial, cur, eol - cur) < 0)
            goto cleanup;
    }

    if ((cur = strstr(base, "machine")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(def->version, cur, eol - cur) < 0)
            goto cleanup;
    }

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoSystemDefFree(def);
    return ret;
}

static int
virSysinfoParsePPCProcessor(const char *base, virSysinfoDefPtr ret)
{
    const char *cur;
    char *eol, *tmp_base;
    virSysinfoProcessorDefPtr processor;

    while ((tmp_base = strstr(base, "processor")) != NULL) {
        base = tmp_base;
        eol = strchr(base, '\n');
        cur = strchr(base, ':') + 1;

        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            return -1;
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
virSysinfoReadPPC(void)
{
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        goto no_memory;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParsePPCProcessor(outbuf, ret) < 0)
        goto no_memory;

    if (virSysinfoParsePPCSystem(outbuf, &ret->system) < 0)
        goto no_memory;

    VIR_FREE(outbuf);
    return ret;

 no_memory:
    VIR_FREE(outbuf);
    virSysinfoDefFree(ret);
    return NULL;
}


static int
virSysinfoParseARMSystem(const char *base, virSysinfoSystemDefPtr *sysdef)
{
    int ret = -1;
    char *eol = NULL;
    const char *cur;
    virSysinfoSystemDefPtr def;

    if ((cur = strstr(base, "platform")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    /* Account for format 'platform    : XXXX'*/
    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (eol && VIR_STRNDUP(def->family, cur, eol - cur) < 0)
        goto cleanup;

    if ((cur = strstr(base, "model")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(def->serial, cur, eol - cur) < 0)
            goto cleanup;
    }

    if ((cur = strstr(base, "machine")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol && VIR_STRNDUP(def->version, cur, eol - cur) < 0)
            goto cleanup;
    }

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoSystemDefFree(def);
    return ret;
}

static int
virSysinfoParseARMProcessor(const char *base, virSysinfoDefPtr ret)
{
    const char *cur;
    char *eol, *tmp_base;
    virSysinfoProcessorDefPtr processor;
    char *processor_type = NULL;

    if (!(tmp_base = strstr(base, "model name")) &&
        !(tmp_base = strstr(base, "Processor")))
        return 0;

    eol = strchr(tmp_base, '\n');
    cur = strchr(tmp_base, ':') + 1;
    virSkipSpaces(&cur);
    if (eol && VIR_STRNDUP(processor_type, cur, eol - cur) < 0)
        goto error;

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

        if (VIR_STRDUP(processor->processor_type, processor_type) < 0)
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
virSysinfoReadARM(void)
{
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        goto no_memory;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseARMProcessor(outbuf, ret) < 0)
        goto no_memory;

    if (virSysinfoParseARMSystem(outbuf, &ret->system) < 0)
        goto no_memory;

    VIR_FREE(outbuf);
    return ret;

 no_memory:
    VIR_FREE(outbuf);
    virSysinfoDefFree(ret);
    return NULL;
}



VIR_WARNINGS_NO_WLOGICALOP_STRCHR

static char *
virSysinfoParseS390Delimited(const char *base, const char *name, char **value,
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
virSysinfoParseS390Line(const char *base, const char *name, char **value)
{
    return virSysinfoParseS390Delimited(base, name, value, ':', '\n');
}

static int
virSysinfoParseS390System(const char *base, virSysinfoSystemDefPtr *sysdef)
{
    int ret = -1;
    virSysinfoSystemDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return ret;

    if (!virSysinfoParseS390Line(base, "Manufacturer", &def->manufacturer))
        goto cleanup;

    if (!virSysinfoParseS390Line(base, "Type", &def->family))
        goto cleanup;

    if (!virSysinfoParseS390Line(base, "Sequence Code", &def->serial))
        goto cleanup;

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoSystemDefFree(def);
    return ret;
}

static int
virSysinfoParseS390Processor(const char *base, virSysinfoDefPtr ret)
{
    char *tmp_base;
    char *manufacturer = NULL;
    char *procline = NULL;
    int result = -1;
    virSysinfoProcessorDefPtr processor;

    if (!(tmp_base = virSysinfoParseS390Line(base, "vendor_id", &manufacturer)))
        goto cleanup;

    /* Find processor N: line and gather the processor manufacturer,
       version, serial number, and family */
    while ((tmp_base = strstr(tmp_base, "processor "))
           && (tmp_base = virSysinfoParseS390Line(tmp_base, "processor ",
                                                  &procline))) {
        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            goto cleanup;
        processor = &ret->processor[ret->nprocessor - 1];
        if (VIR_STRDUP(processor->processor_manufacturer, manufacturer) < 0)
            goto cleanup;
        if (!virSysinfoParseS390Delimited(procline, "version",
                                          &processor->processor_version,
                                          '=', ',') ||
            !virSysinfoParseS390Delimited(procline, "identification",
                                          &processor->processor_serial_number,
                                          '=', ',') ||
            !virSysinfoParseS390Delimited(procline, "machine",
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
virSysinfoReadS390(void)
{
    virSysinfoDefPtr ret = NULL;
    char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    /* Gather info from /proc/cpuinfo */
    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        goto no_memory;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseS390Processor(outbuf, ret) < 0)
        goto no_memory;

    /* Free buffer before reading next file */
    VIR_FREE(outbuf);

    /* Gather info from /proc/sysinfo */
    if (virFileReadAll(SYSINFO, 8192, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), SYSINFO);
        goto no_memory;
    }

    if (virSysinfoParseS390System(outbuf, &ret->system) < 0)
        goto no_memory;

    VIR_FREE(outbuf);
    return ret;

 no_memory:
    virSysinfoDefFree(ret);
    VIR_FREE(outbuf);
    return NULL;
}


static int
virSysinfoParseBIOS(const char *base, virSysinfoBIOSDefPtr *bios)
{
    int ret = -1;
    const char *cur, *eol = NULL;
    virSysinfoBIOSDefPtr def;

    if ((cur = strstr(base, "BIOS Information")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    if ((cur = strstr(base, "Vendor: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->vendor, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->version, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "Release Date: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->date, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "BIOS Revision: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->release, cur, eol - cur) < 0)
            goto cleanup;
    }

    if (!def->vendor && !def->version &&
        !def->date && !def->release) {
        virSysinfoBIOSDefFree(def);
        def = NULL;
    }

    *bios = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoBIOSDefFree(def);
    return ret;
}

static int
virSysinfoParseX86System(const char *base, virSysinfoSystemDefPtr *sysdef)
{
    int ret = -1;
    const char *cur, *eol = NULL;
    virSysinfoSystemDefPtr def;

    if ((cur = strstr(base, "System Information")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->manufacturer, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "Product Name: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->product, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->version, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "Serial Number: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->serial, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "UUID: ")) != NULL) {
        cur += 6;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->uuid, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "SKU Number: ")) != NULL) {
        cur += 12;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->sku, cur, eol - cur) < 0)
            goto cleanup;
    }
    if ((cur = strstr(base, "Family: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        if (eol && VIR_STRNDUP(def->family, cur, eol - cur) < 0)
            goto cleanup;
    }

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoSystemDefFree(def);
    return ret;
}

static int
virSysinfoParseX86BaseBoard(const char *base,
                            virSysinfoBaseBoardDefPtr *baseBoard,
                            size_t *nbaseBoard)
{
    int ret = -1;
    const char *cur, *eol = NULL;
    virSysinfoBaseBoardDefPtr boards = NULL;
    size_t nboards = 0;
    char *board_type = NULL;

    while (base && (cur = strstr(base, "Base Board Information"))) {
        virSysinfoBaseBoardDefPtr def;

        if (VIR_EXPAND_N(boards, nboards, 1) < 0)
            goto cleanup;

        def = &boards[nboards - 1];

        base = cur + 22;
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            if (eol && VIR_STRNDUP(def->manufacturer, cur, eol - cur) < 0)
                goto cleanup;
        }
        if ((cur = strstr(base, "Product Name: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            if (eol && VIR_STRNDUP(def->product, cur, eol - cur) < 0)
                goto cleanup;
        }
        if ((cur = strstr(base, "Version: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            if (eol && VIR_STRNDUP(def->version, cur, eol - cur) < 0)
                goto cleanup;
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            if (eol && VIR_STRNDUP(def->serial, cur, eol - cur) < 0)
                goto cleanup;
        }
        if ((cur = strstr(base, "Asset Tag: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            if (eol && VIR_STRNDUP(def->asset, cur, eol - cur) < 0)
                goto cleanup;
        }
        if ((cur = strstr(base, "Location In Chassis: ")) != NULL) {
            cur += 21;
            eol = strchr(cur, '\n');
            if (eol && VIR_STRNDUP(def->location, cur, eol - cur) < 0)
                goto cleanup;
        }

        if (!def->manufacturer && !def->product && !def->version &&
            !def->serial && !def->asset && !def->location)
            nboards--;
    }

    /* This is safe, as we can be only shrinking the memory */
    ignore_value(VIR_REALLOC_N(boards, nboards));

    *baseBoard = boards;
    *nbaseBoard = nboards;
    boards = NULL;
    nboards = 0;
    ret = 0;
 cleanup:
    while (nboards--)
        virSysinfoBaseBoardDefClear(&boards[nboards]);
    VIR_FREE(boards);
    VIR_FREE(board_type);
    return ret;
}

static int
virSysinfoParseX86Processor(const char *base, virSysinfoDefPtr ret)
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
virSysinfoParseX86Memory(const char *base, virSysinfoDefPtr ret)
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
virSysinfoReadX86(void)
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

    cmd = virCommandNewArgList(path, "-q", "-t", "0,1,2,4,17", NULL);
    VIR_FREE(path);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_ALLOC(ret) < 0)
        goto error;

    ret->type = VIR_SYSINFO_SMBIOS;

    if (virSysinfoParseBIOS(outbuf, &ret->bios) < 0)
        goto error;

    if (virSysinfoParseX86System(outbuf, &ret->system) < 0)
        goto error;

    if (virSysinfoParseX86BaseBoard(outbuf, &ret->baseBoard, &ret->nbaseBoard) < 0)
        goto error;

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseX86Processor(outbuf, ret) < 0)
        goto error;

    ret->nmemory = 0;
    ret->memory = NULL;
    if (virSysinfoParseX86Memory(outbuf, ret) < 0)
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


/**
 * virSysinfoRead:
 *
 * Tries to read the SMBIOS information from the current host
 *
 * Returns: a filled up sysinfo structure or NULL in case of error
 */
virSysinfoDefPtr
virSysinfoRead(void)
{
#if defined(__powerpc__)
    return virSysinfoReadPPC();
#elif defined(__arm__) || defined(__aarch64__)
    return virSysinfoReadARM();
#elif defined(__s390__) || defined(__s390x__)
    return virSysinfoReadS390();
#elif defined(WIN32) || \
    !(defined(__x86_64__) || \
      defined(__i386__) ||   \
      defined(__amd64__) || \
      defined(__arm__) || \
      defined(__aarch64__) || \
      defined(__powerpc__))
    /*
     * this can probably be extracted from Windows using API or registry
     * http://www.microsoft.com/whdc/system/platform/firmware/SMBIOS.mspx
     */
    virReportSystemError(ENOSYS, "%s",
                         _("Host sysinfo extraction not supported on this platform"));
    return NULL;
#else /* !WIN32 && x86 */
    return virSysinfoReadX86();
#endif /* !WIN32 && x86 */
}


static void
virSysinfoBIOSFormat(virBufferPtr buf, virSysinfoBIOSDefPtr def)
{
    if (!def)
        return;

    virBufferAddLit(buf, "<bios>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<entry name='vendor'>%s</entry>\n",
                          def->vendor);
    virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                          def->version);
    virBufferEscapeString(buf, "<entry name='date'>%s</entry>\n",
                          def->date);
    virBufferEscapeString(buf, "<entry name='release'>%s</entry>\n",
                          def->release);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bios>\n");
}

static void
virSysinfoSystemFormat(virBufferPtr buf, virSysinfoSystemDefPtr def)
{
    if (!def)
        return;

    virBufferAddLit(buf, "<system>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<entry name='manufacturer'>%s</entry>\n",
                          def->manufacturer);
    virBufferEscapeString(buf, "<entry name='product'>%s</entry>\n",
                          def->product);
    virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                          def->version);
    virBufferEscapeString(buf, "<entry name='serial'>%s</entry>\n",
                          def->serial);
    virBufferEscapeString(buf, "<entry name='uuid'>%s</entry>\n",
                          def->uuid);
    virBufferEscapeString(buf, "<entry name='sku'>%s</entry>\n",
                          def->sku);
    virBufferEscapeString(buf, "<entry name='family'>%s</entry>\n",
                          def->family);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</system>\n");
}

static void
virSysinfoBaseBoardFormat(virBufferPtr buf,
                          virSysinfoBaseBoardDefPtr baseBoard,
                          size_t nbaseBoard)
{
    virSysinfoBaseBoardDefPtr def;
    size_t i;

    for (i = 0; i < nbaseBoard; i++) {
        def = baseBoard + i;

        virBufferAddLit(buf, "<baseBoard>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<entry name='manufacturer'>%s</entry>\n",
                              def->manufacturer);
        virBufferEscapeString(buf, "<entry name='product'>%s</entry>\n",
                              def->product);
        virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                              def->version);
        virBufferEscapeString(buf, "<entry name='serial'>%s</entry>\n",
                              def->serial);
        virBufferEscapeString(buf, "<entry name='asset'>%s</entry>\n",
                              def->asset);
        virBufferEscapeString(buf, "<entry name='location'>%s</entry>\n",
                              def->location);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</baseBoard>\n");
    }
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
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;
    const char *type = virSysinfoTypeToString(def->type);
    int indent = virBufferGetIndent(buf, false);
    int ret = -1;

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected sysinfo type model %d"),
                       def->type);
        virBufferFreeAndReset(buf);
        goto cleanup;
    }

    virBufferAdjustIndent(&childrenBuf, indent + 2);

    virSysinfoBIOSFormat(&childrenBuf, def->bios);
    virSysinfoSystemFormat(&childrenBuf, def->system);
    virSysinfoBaseBoardFormat(&childrenBuf, def->baseBoard, def->nbaseBoard);
    virSysinfoProcessorFormat(&childrenBuf, def);
    virSysinfoMemoryFormat(&childrenBuf, def);

    virBufferAsprintf(buf, "<sysinfo type='%s'", type);
    if (virBufferUse(&childrenBuf)) {
        virBufferAddLit(buf, ">\n");
        virBufferAddBuffer(buf, &childrenBuf);
        virBufferAddLit(buf, "</sysinfo>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    if (virBufferCheckError(buf) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&childrenBuf);
    return ret;
}

#define CHECK_FIELD(name, desc)                                         \
    do {                                                                \
        if (STRNEQ_NULLABLE(src->name, dst->name)) {                    \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,                  \
                           _("Target sysinfo %s %s does not match source %s"), \
                           desc, NULLSTR(dst->name), NULLSTR(src->name)); \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

static bool
virSysinfoBIOSIsEqual(virSysinfoBIOSDefPtr src,
                      virSysinfoBIOSDefPtr dst)
{
    bool identical = false;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target sysinfo does not match source"));
        goto cleanup;
    }

    CHECK_FIELD(vendor, "BIOS vendor");
    CHECK_FIELD(version, "BIOS version");
    CHECK_FIELD(date, "BIOS date");
    CHECK_FIELD(release, "BIOS release");

    identical = true;
 cleanup:
    return identical;
}

static bool
virSysinfoSystemIsEqual(virSysinfoSystemDefPtr src,
                        virSysinfoSystemDefPtr dst)
{
    bool identical = false;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target sysinfo does not match source"));
        goto cleanup;
    }

    CHECK_FIELD(manufacturer, "system vendor");
    CHECK_FIELD(product, "system product");
    CHECK_FIELD(version, "system version");
    CHECK_FIELD(serial, "system serial");
    CHECK_FIELD(uuid, "system uuid");
    CHECK_FIELD(sku, "system sku");
    CHECK_FIELD(family, "system family");

    identical = true;
 cleanup:
    return identical;
}

static bool
virSysinfoBaseBoardIsEqual(virSysinfoBaseBoardDefPtr src,
                           virSysinfoBaseBoardDefPtr dst)
{
    bool identical = false;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target base board does not match source"));
        goto cleanup;
    }

    CHECK_FIELD(manufacturer, "base board vendor");
    CHECK_FIELD(product, "base board product");
    CHECK_FIELD(version, "base board version");
    CHECK_FIELD(serial, "base board serial");
    CHECK_FIELD(asset, "base board asset");
    CHECK_FIELD(location, "base board location");

    identical = true;
 cleanup:
    return identical;
}

#undef CHECK_FIELD

bool virSysinfoIsEqual(virSysinfoDefPtr src,
                       virSysinfoDefPtr dst)
{
    bool identical = false;
    size_t i;

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

    if (!virSysinfoBIOSIsEqual(src->bios, dst->bios))
        goto cleanup;

    if (!virSysinfoSystemIsEqual(src->system, dst->system))
        goto cleanup;

    if (src->nbaseBoard != dst->nbaseBoard) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sysinfo base board count '%zu' does not match source '%zu'"),
                       dst->nbaseBoard, src->nbaseBoard);
        goto cleanup;
    }

    for (i = 0; i < src->nbaseBoard; i++)
        if (!virSysinfoBaseBoardIsEqual(src->baseBoard + i,
                                        dst->baseBoard + i))
            goto cleanup;

    identical = true;

 cleanup:
    return identical;
}
