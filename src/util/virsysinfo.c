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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virerror.h"
#include "virsysinfo.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virlog.h"
#include "virfile.h"
#include "virstring.h"

#define LIBVIRT_VIRSYSINFOPRIV_H_ALLOW
#include "virsysinfopriv.h"

#define VIR_FROM_THIS VIR_FROM_SYSINFO

VIR_LOG_INIT("util.sysinfo");

VIR_ENUM_IMPL(virSysinfo,
              VIR_SYSINFO_LAST,
              "smbios",
              "fwcfg"
);

static const char *sysinfoSysinfo = "/proc/sysinfo";
static const char *sysinfoCpuinfo = "/proc/cpuinfo";

#define SYSINFO sysinfoSysinfo
#define CPUINFO sysinfoCpuinfo
#define CPUINFO_FILE_LEN (1024*1024)    /* 1MB limit for /proc/cpuinfo file */


void
virSysinfoSetup(const char *sysinfo,
                const char *cpuinfo)
{
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


void virSysinfoChassisDefFree(virSysinfoChassisDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->manufacturer);
    VIR_FREE(def->version);
    VIR_FREE(def->serial);
    VIR_FREE(def->asset);
    VIR_FREE(def->sku);
    VIR_FREE(def);
}


void virSysinfoOEMStringsDefFree(virSysinfoOEMStringsDefPtr def)
{
    size_t i;

    if (def == NULL)
        return;

    for (i = 0; i < def->nvalues; i++)
        VIR_FREE(def->values[i]);
    VIR_FREE(def->values);

    VIR_FREE(def);
}


static void
virSysinfoFWCfgDefClear(virSysinfoFWCfgDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->value);
    VIR_FREE(def->file);
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

    virSysinfoChassisDefFree(def->chassis);

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

    virSysinfoOEMStringsDefFree(def->oemStrings);

    for (i = 0; i < def->nfw_cfgs; i++)
        virSysinfoFWCfgDefClear(&def->fw_cfgs[i]);
    VIR_FREE(def->fw_cfgs);

    VIR_FREE(def);
}


static bool
virSysinfoDefIsEmpty(const virSysinfoDef *def)
{
    return !(def->bios || def->system || def->nbaseBoard > 0 ||
             def->chassis || def->nprocessor > 0 ||
             def->nmemory > 0 || def->oemStrings);
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
    if (eol)
        def->family = g_strndup(cur, eol - cur);

    if ((cur = strstr(base, "model")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol)
            def->serial = g_strndup(cur, eol - cur);
    }

    if ((cur = strstr(base, "machine")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol)
            def->version = g_strndup(cur, eol - cur);
    }

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
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
        if (eol)
            processor->processor_socket_destination = g_strndup(cur,
                                                                eol - cur);
        base = cur;

        if ((cur = strstr(base, "cpu")) != NULL) {
            cur = strchr(cur, ':') + 1;
            eol = strchr(cur, '\n');
            virSkipSpaces(&cur);
            if (eol)
                processor->processor_type = g_strndup(cur, eol - cur);
            base = cur;
        }

        if ((cur = strstr(base, "revision")) != NULL) {
            cur = strchr(cur, ':') + 1;
            eol = strchr(cur, '\n');
            virSkipSpaces(&cur);
            if (eol)
                processor->processor_version = g_strndup(cur, eol - cur);
            base = cur;
        }

    }

    return 0;
}

/* virSysinfoRead for PowerPC
 * Gathers sysinfo data from /proc/cpuinfo */
virSysinfoDefPtr
virSysinfoReadPPC(void)
{
    g_auto(virSysinfoDefPtr) ret = NULL;
    g_autofree char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return NULL;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParsePPCProcessor(outbuf, ret) < 0)
        return NULL;

    if (virSysinfoParsePPCSystem(outbuf, &ret->system) < 0)
        return NULL;

    return g_steal_pointer(&ret);
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
    if (eol)
        def->family = g_strndup(cur, eol - cur);

    if ((cur = strstr(base, "model")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol)
            def->serial = g_strndup(cur, eol - cur);
    }

    if ((cur = strstr(base, "machine")) != NULL) {
        cur = strchr(cur, ':') + 1;
        eol = strchr(cur, '\n');
        virSkipSpaces(&cur);
        if (eol)
            def->version = g_strndup(cur, eol - cur);
    }

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
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
    if (eol)
        processor_type = g_strndup(cur, eol - cur);

    while ((tmp_base = strstr(base, "processor")) != NULL) {
        base = tmp_base;
        eol = strchr(base, '\n');
        cur = strchr(base, ':') + 1;

        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            goto error;
        processor = &ret->processor[ret->nprocessor - 1];

        virSkipSpaces(&cur);
        if (eol)
            processor->processor_socket_destination = g_strndup(cur,
                                                                eol - cur);

        processor->processor_type = g_strdup(processor_type);

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
    g_auto(virSysinfoDefPtr) ret = NULL;
    g_autofree char *outbuf = NULL;

    /* Some ARM systems have DMI tables available. */
    if ((ret = virSysinfoReadDMI())) {
        if (!virSysinfoDefIsEmpty(ret))
            return g_steal_pointer(&ret);
        virSysinfoDefFree(ret);
    }

    /* Well, we've tried. Fall back to parsing cpuinfo */
    virResetLastError();

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return NULL;
    }

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseARMProcessor(outbuf, ret) < 0)
        return NULL;

    if (virSysinfoParseARMSystem(outbuf, &ret->system) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}

static const char *
virSysinfoParseS390Delimited(const char *base, const char *name, char **value,
                             char delim1, char delim2)
{
    const char *start;
    const char *end;

    if (delim1 != delim2 &&
        (start = strstr(base, name)) &&
        (start = strchr(start, delim1))) {
        start += 1;
        end = strchr(start, delim2);
        if (!end)
            end = start + strlen(start);
        virSkipSpaces(&start);
        *value = g_strndup(start, end - start);
        virTrimSpaces(*value, NULL);
        return end;
    }
    return NULL;
}

static const char *
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
    const char *tmp_base;
    char *manufacturer = NULL;
    char *procline = NULL;
    char *ncpu = NULL;
    int result = -1;
    virSysinfoProcessorDefPtr processor;

    if (!(tmp_base = virSysinfoParseS390Line(base, "vendor_id", &manufacturer)))
        goto error;

    /* Find processor N: line and gather the processor manufacturer,
       version, serial number, and family */
    while ((tmp_base = strstr(tmp_base, "processor "))
           && (tmp_base = virSysinfoParseS390Line(tmp_base, "processor ",
                                                  &procline))) {
        if (VIR_EXPAND_N(ret->processor, ret->nprocessor, 1) < 0)
            goto error;
        processor = &ret->processor[ret->nprocessor - 1];
        processor->processor_manufacturer = g_strdup(manufacturer);
        if (!virSysinfoParseS390Delimited(procline, "version",
                                          &processor->processor_version,
                                          '=', ',') ||
            !virSysinfoParseS390Delimited(procline, "identification",
                                          &processor->processor_serial_number,
                                          '=', ',') ||
            !virSysinfoParseS390Delimited(procline, "machine",
                                          &processor->processor_family,
                                          '=', '\n'))
            goto error;

        VIR_FREE(procline);
    }

    /* now, for each processor found, extract the frequency information */
    tmp_base = base;

    while ((tmp_base = strstr(tmp_base, "cpu number")) &&
           (tmp_base = virSysinfoParseS390Line(tmp_base, "cpu number", &ncpu))) {
        unsigned int n;
        char *mhz = NULL;

        if (virStrToLong_uip(ncpu, NULL, 10, &n) < 0)
            goto error;

        if (n >= ret->nprocessor) {
            VIR_DEBUG("CPU number '%u' out of range", n);
            goto cleanup;
        }

        if (!(tmp_base = strstr(tmp_base, "cpu MHz static")) ||
            !virSysinfoParseS390Line(tmp_base, "cpu MHz static", &mhz))
            goto cleanup;

        ret->processor[n].processor_max_speed = mhz;

        VIR_FREE(ncpu);
    }

 cleanup:
    result = 0;

 error:
    VIR_FREE(manufacturer);
    VIR_FREE(procline);
    VIR_FREE(ncpu);
    return result;
}

/* virSysinfoRead for s390x
 * Gathers sysinfo data from /proc/sysinfo and /proc/cpuinfo */
virSysinfoDefPtr
virSysinfoReadS390(void)
{
    g_auto(virSysinfoDefPtr) ret = NULL;
    g_autofree char *outbuf = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    /* Gather info from /proc/cpuinfo */
    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return NULL;
    }

    if (virSysinfoParseS390Processor(outbuf, ret) < 0)
        return NULL;

    /* Free buffer before reading next file */
    VIR_FREE(outbuf);

    /* Gather info from /proc/sysinfo */
    if (virFileReadAll(SYSINFO, 8192, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), SYSINFO);
        return NULL;
    }

    if (virSysinfoParseS390System(outbuf, &ret->system) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


static int
virSysinfoParseBIOS(const char *base, virSysinfoBIOSDefPtr *bios)
{
    int ret = -1;
    const char *cur;
    char *eol = NULL;
    virSysinfoBIOSDefPtr def;

    if ((cur = strstr(base, "BIOS Information")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    if ((cur = strstr(base, "Vendor: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->vendor = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->version = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Release Date: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->date = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "BIOS Revision: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->release = g_strndup(cur, eol - cur);
    }

    if (!def->vendor && !def->version &&
        !def->date && !def->release) {
        virSysinfoBIOSDefFree(def);
        def = NULL;
    }

    *bios = def;
    def = NULL;
    ret = 0;
    virSysinfoBIOSDefFree(def);
    return ret;
}

static int
virSysinfoParseX86System(const char *base, virSysinfoSystemDefPtr *sysdef)
{
    int ret = -1;
    const char *cur;
    char *eol = NULL;
    virSysinfoSystemDefPtr def;

    if ((cur = strstr(base, "System Information")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->manufacturer = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Product Name: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->product = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->version = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Serial Number: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->serial = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "UUID: ")) != NULL) {
        cur += 6;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->uuid = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "SKU Number: ")) != NULL) {
        cur += 12;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->sku = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Family: ")) != NULL) {
        cur += 8;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->family = g_strndup(cur, eol - cur);
    }

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
    virSysinfoSystemDefFree(def);
    return ret;
}

static int
virSysinfoParseX86BaseBoard(const char *base,
                            virSysinfoBaseBoardDefPtr *baseBoard,
                            size_t *nbaseBoard)
{
    int ret = -1;
    const char *cur;
    char *eol = NULL;
    virSysinfoBaseBoardDefPtr boards = NULL;
    size_t nboards = 0;

    while (base && (cur = strstr(base, "Base Board Information"))) {
        virSysinfoBaseBoardDefPtr def;

        if (VIR_EXPAND_N(boards, nboards, 1) < 0)
            goto cleanup;

        def = &boards[nboards - 1];

        base = cur + 22;
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                def->manufacturer = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Product Name: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                def->product = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Version: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                def->version = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                def->serial = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Asset Tag: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                def->asset = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Location In Chassis: ")) != NULL) {
            cur += 21;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                def->location = g_strndup(cur, eol - cur);
        }

        if (!def->manufacturer && !def->product && !def->version &&
            !def->serial && !def->asset && !def->location)
            nboards--;
    }

    if (nboards == 0) {
        VIR_FREE(boards);
    } else {
        /* This is safe, as we can be only shrinking the memory */
        ignore_value(VIR_REALLOC_N(boards, nboards));
    }

    *baseBoard = boards;
    *nbaseBoard = nboards;
    boards = NULL;
    nboards = 0;
    ret = 0;
 cleanup:
    while (nboards--)
        virSysinfoBaseBoardDefClear(&boards[nboards]);
    VIR_FREE(boards);
    return ret;
}


static int
virSysinfoParseX86Chassis(const char *base,
                          virSysinfoChassisDefPtr *chassisdef)
{
    int ret = -1;
    const char *cur;
    char *eol = NULL;
    virSysinfoChassisDefPtr def;

    if ((cur = strstr(base, "Chassis Information")) == NULL)
        return 0;

    if (VIR_ALLOC(def) < 0)
        return ret;

    base = cur;
    if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
        cur += 14;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->manufacturer = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Version: ")) != NULL) {
        cur += 9;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->version = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Serial Number: ")) != NULL) {
        cur += 15;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->serial = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "Asset Tag: ")) != NULL) {
        cur += 11;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->asset = g_strndup(cur, eol - cur);
    }
    if ((cur = strstr(base, "SKU Number: ")) != NULL) {
        cur += 12;
        eol = strchr(cur, '\n');
        virSkipSpacesBackwards(cur, &eol);
        if (eol)
            def->sku = g_strndup(cur, eol - cur);
    }

    if (!def->manufacturer && !def->version &&
        !def->serial && !def->asset && !def->sku) {
        virSysinfoChassisDefFree(def);
        def = NULL;
    }

    *chassisdef = def;
    def = NULL;
    ret = 0;
    virSysinfoChassisDefFree(def);
    return ret;
}


static int
virSysinfoDMIDecodeOEMString(size_t i,
                             char **str)
{
    g_autofree char *err = NULL;
    g_autoptr(virCommand) cmd = virCommandNewArgList(DMIDECODE, "--dump",
                                                     "--oem-string", NULL);
    virCommandAddArgFormat(cmd, "%zu", i);
    virCommandSetOutputBuffer(cmd, str);
    virCommandSetErrorBuffer(cmd, &err);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    /* Unfortunately, dmidecode returns 0 even if OEM String index is out
     * of bounds, but it prints an error message in that case. Check stderr
     * and return success/failure accordingly. */

    if (err && *err != '\0')
        return -1;

    return 0;
}


static int
virSysinfoParseOEMStrings(const char *base,
                          virSysinfoOEMStringsDefPtr *stringsRet)
{
    virSysinfoOEMStringsDefPtr strings = NULL;
    size_t i = 1;
    int ret = -1;
    const char *cur;

    if (!(cur = strstr(base, "OEM Strings")))
        return 0;

    if (VIR_ALLOC(strings) < 0)
        return -1;

    while ((cur = strstr(cur, "String "))) {
        char *eol;

        cur += 7;

        if (!(eol = strchr(cur, '\n'))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed output of dmidecode"));
            goto cleanup;
        }

        while (g_ascii_isdigit(*cur))
            cur++;

        if (*cur != ':') {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed output of dmidecode"));
            goto cleanup;
        }

        cur += 2;

        virSkipSpacesBackwards(cur, &eol);
        if (!eol)
            continue;

        if (VIR_EXPAND_N(strings->values, strings->nvalues, 1) < 0)
            goto cleanup;

        /* If OEM String contains newline, dmidecode escapes it as a dot.
         * If this is the case then run dmidecode again to get raw string.
         * Unfortunately, we can't dinstinguish between dot an new line at
         * this level. */
        if (memchr(cur, '.', eol - cur)) {
            char *str;

            if (virSysinfoDMIDecodeOEMString(i, &str) < 0)
                goto cleanup;

            strings->values[strings->nvalues - 1] = g_steal_pointer(&str);
        } else {
            strings->values[strings->nvalues - 1] = g_strndup(cur, eol - cur);
        }

        i++;
        cur = eol;
    }

    *stringsRet = g_steal_pointer(&strings);
    ret = 0;

 cleanup:
    virSysinfoOEMStringsDefFree(strings);
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
            if (eol)
                processor->processor_socket_destination = g_strndup(cur,
                                                                    eol - cur);
        }
        if ((cur = strstr(base, "Type: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_type = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Family: ")) != NULL) {
            cur += 8;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_family = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_manufacturer = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Signature: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_signature = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Version: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_version = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "External Clock: ")) != NULL) {
            cur += 16;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_external_clock = g_strndup(cur,
                                                                eol - cur);
        }
        if ((cur = strstr(base, "Max Speed: ")) != NULL) {
            cur += 11;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_max_speed = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Status: ")) != NULL) {
            cur += 8;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_status = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_serial_number = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Part Number: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                processor->processor_part_number = g_strndup(cur, eol - cur);
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
            if (eol)
                memory->memory_size = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Form Factor: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_form_factor = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Locator: ")) != NULL) {
            cur += 9;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_locator = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Bank Locator: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_bank_locator = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Type: ")) != NULL) {
            cur += 6;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_type = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Type Detail: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_type_detail = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Speed: ")) != NULL) {
            cur += 7;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_speed = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Manufacturer: ")) != NULL) {
            cur += 14;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_manufacturer = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Serial Number: ")) != NULL) {
            cur += 15;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_serial_number = g_strndup(cur, eol - cur);
        }
        if ((cur = strstr(base, "Part Number: ")) != NULL) {
            cur += 13;
            eol = strchr(cur, '\n');
            virSkipSpacesBackwards(cur, &eol);
            if (eol)
                memory->memory_part_number = g_strndup(cur, eol - cur);
        }

    next:
        base += strlen("Memory Device");
    }

    return 0;
}

virSysinfoDefPtr
virSysinfoReadDMI(void)
{
    g_auto(virSysinfoDefPtr) ret = NULL;
    g_autofree char *outbuf = NULL;
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(DMIDECODE, "-q", "-t", "0,1,2,3,4,11,17", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        return NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->type = VIR_SYSINFO_SMBIOS;

    if (virSysinfoParseBIOS(outbuf, &ret->bios) < 0)
        return NULL;

    if (virSysinfoParseX86System(outbuf, &ret->system) < 0)
        return NULL;

    if (virSysinfoParseX86BaseBoard(outbuf, &ret->baseBoard, &ret->nbaseBoard) < 0)
        return NULL;

    if (virSysinfoParseX86Chassis(outbuf, &ret->chassis) < 0)
        return NULL;

    if (virSysinfoParseOEMStrings(outbuf, &ret->oemStrings) < 0)
        return NULL;

    ret->nprocessor = 0;
    ret->processor = NULL;
    if (virSysinfoParseX86Processor(outbuf, ret) < 0)
        return NULL;

    ret->nmemory = 0;
    ret->memory = NULL;
    if (virSysinfoParseX86Memory(outbuf, ret) < 0)
        return NULL;

    return g_steal_pointer(&ret);
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
#elif !defined(WIN32) && \
    (defined(__x86_64__) || \
     defined(__i386__) || \
     defined(__amd64__))
    return virSysinfoReadDMI();
#else /* WIN32 || not supported arch */
    /*
     * this can probably be extracted from Windows using API or registry
     * https://www.microsoft.com/whdc/system/platform/firmware/SMBIOS.mspx
     */
    virReportSystemError(ENOSYS, "%s",
                         _("Host sysinfo extraction not supported on this platform"));
    return NULL;
#endif /* WIN32 || not supported arch */
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
virSysinfoChassisFormat(virBufferPtr buf,
                        virSysinfoChassisDefPtr def)
{
    if (!def)
        return;

    virBufferAddLit(buf, "<chassis>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<entry name='manufacturer'>%s</entry>\n",
                          def->manufacturer);
    virBufferEscapeString(buf, "<entry name='version'>%s</entry>\n",
                          def->version);
    virBufferEscapeString(buf, "<entry name='serial'>%s</entry>\n",
                          def->serial);
    virBufferEscapeString(buf, "<entry name='asset'>%s</entry>\n",
                          def->asset);
    virBufferEscapeString(buf, "<entry name='sku'>%s</entry>\n",
                          def->sku);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</chassis>\n");
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

static void
virSysinfoOEMStringsFormat(virBufferPtr buf, virSysinfoOEMStringsDefPtr def)
{
    size_t i;

    if (!def)
        return;

    virBufferAddLit(buf, "<oemStrings>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < def->nvalues; i++) {
        virBufferEscapeString(buf, "<entry>%s</entry>\n",
                              def->values[i]);
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</oemStrings>\n");
}


static void
virSysinfoFormatSMBIOS(virBufferPtr buf,
                       virSysinfoDefPtr def)
{
    virSysinfoBIOSFormat(buf, def->bios);
    virSysinfoSystemFormat(buf, def->system);
    virSysinfoBaseBoardFormat(buf, def->baseBoard, def->nbaseBoard);
    virSysinfoChassisFormat(buf, def->chassis);
    virSysinfoProcessorFormat(buf, def);
    virSysinfoMemoryFormat(buf, def);
    virSysinfoOEMStringsFormat(buf, def->oemStrings);
}


static void
virSysinfoFormatFWCfg(virBufferPtr buf,
                      virSysinfoDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nfw_cfgs; i++) {
        const virSysinfoFWCfgDef *f = &def->fw_cfgs[i];

        virBufferAsprintf(buf, "<entry name='%s'", f->name);

        if (f->file)
            virBufferEscapeString(buf, " file='%s'/>\n", f->file);
        else
            virBufferEscapeString(buf, ">%s</entry>\n", f->value);
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
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
    const char *type = virSysinfoTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected sysinfo type model %d"),
                       def->type);
        return -1;
    }

    switch (def->type) {
    case VIR_SYSINFO_SMBIOS:
        virSysinfoFormatSMBIOS(&childrenBuf, def);
        break;
    case VIR_SYSINFO_FWCFG:
        virSysinfoFormatFWCfg(&childrenBuf, def);
        break;
    case VIR_SYSINFO_LAST:
        break;
    }

    virBufferAsprintf(&attrBuf, " type='%s'", type);

    virXMLFormatElement(buf, "sysinfo", &attrBuf, &childrenBuf);

    return 0;
}

#define CHECK_FIELD(name, desc) \
    do { \
        if (STRNEQ_NULLABLE(src->name, dst->name)) { \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                           _("Target sysinfo %s %s does not match source %s"), \
                           desc, NULLSTR(dst->name), NULLSTR(src->name)); \
            return false; \
        } \
    } while (0)

static bool
virSysinfoBIOSIsEqual(virSysinfoBIOSDefPtr src,
                      virSysinfoBIOSDefPtr dst)
{
    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target sysinfo does not match source"));
        return false;
    }

    CHECK_FIELD(vendor, "BIOS vendor");
    CHECK_FIELD(version, "BIOS version");
    CHECK_FIELD(date, "BIOS date");
    CHECK_FIELD(release, "BIOS release");

    return true;
}

static bool
virSysinfoSystemIsEqual(virSysinfoSystemDefPtr src,
                        virSysinfoSystemDefPtr dst)
{
    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target sysinfo does not match source"));
        return false;
    }

    CHECK_FIELD(manufacturer, "system vendor");
    CHECK_FIELD(product, "system product");
    CHECK_FIELD(version, "system version");
    CHECK_FIELD(serial, "system serial");
    CHECK_FIELD(uuid, "system uuid");
    CHECK_FIELD(sku, "system sku");
    CHECK_FIELD(family, "system family");

    return true;
}

static bool
virSysinfoBaseBoardIsEqual(virSysinfoBaseBoardDefPtr src,
                           virSysinfoBaseBoardDefPtr dst)
{
    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target base board does not match source"));
        return false;
    }

    CHECK_FIELD(manufacturer, "base board vendor");
    CHECK_FIELD(product, "base board product");
    CHECK_FIELD(version, "base board version");
    CHECK_FIELD(serial, "base board serial");
    CHECK_FIELD(asset, "base board asset");
    CHECK_FIELD(location, "base board location");

    return true;
}


static bool
virSysinfoChassisIsEqual(virSysinfoChassisDefPtr src,
                         virSysinfoChassisDefPtr dst)
{
    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target chassis does not match source"));
        return false;
    }

    CHECK_FIELD(manufacturer, "chassis vendor");
    CHECK_FIELD(version, "chassis version");
    CHECK_FIELD(serial, "chassis serial");
    CHECK_FIELD(asset, "chassis asset");
    CHECK_FIELD(sku, "chassis sku");

    return true;
}


#undef CHECK_FIELD

bool virSysinfoIsEqual(virSysinfoDefPtr src,
                       virSysinfoDefPtr dst)
{
    size_t i;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target sysinfo does not match source"));
        return false;
    }

    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sysinfo %s does not match source %s"),
                       virSysinfoTypeToString(dst->type),
                       virSysinfoTypeToString(src->type));
        return false;
    }

    if (!virSysinfoBIOSIsEqual(src->bios, dst->bios))
        return false;

    if (!virSysinfoSystemIsEqual(src->system, dst->system))
        return false;

    if (src->nbaseBoard != dst->nbaseBoard) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sysinfo base board count '%zu' does not match source '%zu'"),
                       dst->nbaseBoard, src->nbaseBoard);
        return false;
    }

    for (i = 0; i < src->nbaseBoard; i++)
        if (!virSysinfoBaseBoardIsEqual(src->baseBoard + i,
                                        dst->baseBoard + i))
            return false;

    if (!virSysinfoChassisIsEqual(src->chassis, dst->chassis))
        return false;

    return true;
}
