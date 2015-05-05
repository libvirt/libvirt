/*
 * domain_capabilities.c: domain capabilities XML processing
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "domain_capabilities.h"
#include "domain_conf.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

static virClassPtr virDomainCapsClass;

static void virDomainCapsDispose(void *obj);

static int virDomainCapsOnceInit(void)
{
    if (!(virDomainCapsClass = virClassNew(virClassForObjectLockable(),
                                           "virDomainCapsClass",
                                           sizeof(virDomainCaps),
                                           virDomainCapsDispose)))
        return -1;
    return 0;
}


VIR_ONCE_GLOBAL_INIT(virDomainCaps)


static void
virDomainCapsStringValuesFree(virDomainCapsStringValuesPtr values)
{
    size_t i;

    if (!values || !values->values)
        return;

    for (i = 0; i < values->nvalues; i++)
        VIR_FREE(values->values[i]);
    VIR_FREE(values->values);
}


static void
virDomainCapsDispose(void *obj)
{
    virDomainCapsPtr caps = obj;

    VIR_FREE(caps->path);
    VIR_FREE(caps->machine);

    virDomainCapsStringValuesFree(&caps->os.loader.values);
}


virDomainCapsPtr
virDomainCapsNew(const char *path,
                 const char *machine,
                 virArch arch,
                 virDomainVirtType virttype)
{
    virDomainCapsPtr caps = NULL;

    if (virDomainCapsInitialize() < 0)
        return NULL;

    if (!(caps = virObjectLockableNew(virDomainCapsClass)))
        return NULL;

    if (VIR_STRDUP(caps->path, path) < 0 ||
        VIR_STRDUP(caps->machine, machine) < 0)
        goto error;
    caps->arch = arch;
    caps->virttype = virttype;

    return caps;
 error:
    virObjectUnref(caps);
    return NULL;
}


int
virDomainCapsEnumSet(virDomainCapsEnumPtr capsEnum,
                     const char *capsEnumName,
                     size_t nvalues,
                     unsigned int *values)
{
    int ret = -1;
    size_t i;

    for (i = 0; i < nvalues; i++) {
        unsigned int val = 1 << values[i];

        if (!val) {
            /* Integer overflow */
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("integer overflow on %s. Please contact the "
                             "libvirt development team at libvir-list@redhat.com"),
                           capsEnumName);
            goto cleanup;
        }

        capsEnum->values |= val;
    }

    ret = 0;
 cleanup:
    return ret;
}


void
virDomainCapsEnumClear(virDomainCapsEnumPtr capsEnum)
{
    capsEnum->values = 0;
}


static int
virDomainCapsEnumFormat(virBufferPtr buf,
                        virDomainCapsEnumPtr capsEnum,
                        const char *capsEnumName,
                        virDomainCapsValToStr valToStr)
{
    int ret = -1;
    size_t i;

    virBufferAsprintf(buf, "<enum name='%s'", capsEnumName);
    if (!capsEnum->values) {
        virBufferAddLit(buf, "/>\n");
        ret = 0;
        goto cleanup;
    }
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < sizeof(capsEnum->values) * CHAR_BIT; i++) {
        const char *val;

        if (!(capsEnum->values & (1 << i)))
            continue;

        if ((val = (valToStr)(i)))
            virBufferAsprintf(buf, "<value>%s</value>\n", val);
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</enum>\n");

    ret = 0;
 cleanup:
    return ret;
}


static void
virDomainCapsStringValuesFormat(virBufferPtr buf,
                                virDomainCapsStringValuesPtr values)
{
    size_t i;

    for (i = 0; i < values->nvalues; i++)
        virBufferEscapeString(buf, "<value>%s</value>\n", values->values[i]);
}


#define FORMAT_PROLOGUE(item)                                       \
    do {                                                            \
        virBufferAsprintf(buf, "<" #item " supported='%s'%s\n",     \
                          item->device.supported ? "yes" : "no",    \
                          item->device.supported ? ">" : "/>");     \
        if (!item->device.supported)                                \
            return;                                                 \
        virBufferAdjustIndent(buf, 2);                              \
    } while (0)

#define FORMAT_EPILOGUE(item)                                       \
    do {                                                            \
        virBufferAdjustIndent(buf, -2);                             \
        virBufferAddLit(buf, "</" #item ">\n");                     \
    } while (0)

#define ENUM_PROCESS(master, capsEnum, valToStr)                    \
    do {                                                            \
        virDomainCapsEnumFormat(buf, &master->capsEnum,             \
                                #capsEnum, valToStr);               \
    } while (0)


static void
virDomainCapsLoaderFormat(virBufferPtr buf,
                          virDomainCapsLoaderPtr loader)
{
    FORMAT_PROLOGUE(loader);

    virDomainCapsStringValuesFormat(buf, &loader->values);
    ENUM_PROCESS(loader, type, virDomainLoaderTypeToString);
    ENUM_PROCESS(loader, readonly, virTristateBoolTypeToString);

    FORMAT_EPILOGUE(loader);
}

static void
virDomainCapsOSFormat(virBufferPtr buf,
                      virDomainCapsOSPtr os)
{
    virDomainCapsLoaderPtr loader = &os->loader;

    FORMAT_PROLOGUE(os);

    virDomainCapsLoaderFormat(buf, loader);

    FORMAT_EPILOGUE(os);
}

static void
virDomainCapsDeviceDiskFormat(virBufferPtr buf,
                              virDomainCapsDeviceDiskPtr const disk)
{
    FORMAT_PROLOGUE(disk);

    ENUM_PROCESS(disk, diskDevice, virDomainDiskDeviceTypeToString);
    ENUM_PROCESS(disk, bus, virDomainDiskBusTypeToString);

    FORMAT_EPILOGUE(disk);
}


static void
virDomainCapsDeviceHostdevFormat(virBufferPtr buf,
                                 virDomainCapsDeviceHostdevPtr const hostdev)
{
    FORMAT_PROLOGUE(hostdev);

    ENUM_PROCESS(hostdev, mode, virDomainHostdevModeTypeToString);
    ENUM_PROCESS(hostdev, startupPolicy, virDomainStartupPolicyTypeToString);
    ENUM_PROCESS(hostdev, subsysType, virDomainHostdevSubsysTypeToString);
    ENUM_PROCESS(hostdev, capsType, virDomainHostdevCapsTypeToString);
    ENUM_PROCESS(hostdev, pciBackend, virDomainHostdevSubsysPCIBackendTypeToString);

    FORMAT_EPILOGUE(hostdev);
}


static int
virDomainCapsFormatInternal(virBufferPtr buf,
                            virDomainCapsPtr const caps)
{
    const char *virttype_str = virDomainVirtTypeToString(caps->virttype);
    const char *arch_str = virArchToString(caps->arch);

    virBufferAddLit(buf, "<domainCapabilities>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<path>%s</path>\n", caps->path);
    virBufferAsprintf(buf, "<domain>%s</domain>\n", virttype_str);
    virBufferAsprintf(buf, "<machine>%s</machine>\n", caps->machine);
    virBufferAsprintf(buf, "<arch>%s</arch>\n", arch_str);

    if (caps->maxvcpus)
        virBufferAsprintf(buf, "<vcpu max='%d'/>\n", caps->maxvcpus);

    virDomainCapsOSFormat(buf, &caps->os);

    virBufferAddLit(buf, "<devices>\n");
    virBufferAdjustIndent(buf, 2);

    virDomainCapsDeviceDiskFormat(buf, &caps->disk);
    virDomainCapsDeviceHostdevFormat(buf, &caps->hostdev);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</devices>\n");

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</domainCapabilities>\n");
    return 0;
}


char *
virDomainCapsFormat(virDomainCapsPtr const caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virDomainCapsFormatInternal(&buf, caps) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}
