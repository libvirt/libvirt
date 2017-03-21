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

VIR_ENUM_IMPL(virDomainCapsCPUUsable, VIR_DOMCAPS_CPU_USABLE_LAST,
              "unknown", "yes", "no");

static virClassPtr virDomainCapsClass;
static virClassPtr virDomainCapsCPUModelsClass;

static void virDomainCapsDispose(void *obj);
static void virDomainCapsCPUModelsDispose(void *obj);

static int virDomainCapsOnceInit(void)
{
    if (!(virDomainCapsClass = virClassNew(virClassForObjectLockable(),
                                           "virDomainCapsClass",
                                           sizeof(virDomainCaps),
                                           virDomainCapsDispose)))
        return -1;

    virDomainCapsCPUModelsClass = virClassNew(virClassForObject(),
                                              "virDomainCapsCPUModelsClass",
                                              sizeof(virDomainCapsCPUModels),
                                              virDomainCapsCPUModelsDispose);
    if (!virDomainCapsCPUModelsClass)
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
    virObjectUnref(caps->cpu.custom);

    virDomainCapsStringValuesFree(&caps->os.loader.values);
}


static void
virDomainCapsCPUModelsDispose(void *obj)
{
    virDomainCapsCPUModelsPtr cpuModels = obj;
    size_t i;

    for (i = 0; i < cpuModels->nmodels; i++)
        VIR_FREE(cpuModels->models[i].name);

    VIR_FREE(cpuModels->models);
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


virDomainCapsCPUModelsPtr
virDomainCapsCPUModelsNew(size_t nmodels)
{
    virDomainCapsCPUModelsPtr cpuModels = NULL;

    if (virDomainCapsInitialize() < 0)
        return NULL;

    if (!(cpuModels = virObjectNew(virDomainCapsCPUModelsClass)))
        return NULL;

    if (VIR_ALLOC_N(cpuModels->models, nmodels) < 0)
        goto error;
    cpuModels->nmodels_max = nmodels;

    return cpuModels;

 error:
    virObjectUnref(cpuModels);
    return NULL;
}


virDomainCapsCPUModelsPtr
virDomainCapsCPUModelsCopy(virDomainCapsCPUModelsPtr old)
{
    virDomainCapsCPUModelsPtr cpuModels;
    size_t i;

    if (!(cpuModels = virDomainCapsCPUModelsNew(old->nmodels)))
        return NULL;

    for (i = 0; i < old->nmodels; i++) {
        if (virDomainCapsCPUModelsAdd(cpuModels,
                                      old->models[i].name, -1,
                                      old->models[i].usable) < 0)
            goto error;
    }

    return cpuModels;

 error:
    virObjectUnref(cpuModels);
    return NULL;
}


virDomainCapsCPUModelsPtr
virDomainCapsCPUModelsFilter(virDomainCapsCPUModelsPtr old,
                             const char **models,
                             const char **blacklist)
{
    virDomainCapsCPUModelsPtr cpuModels;
    size_t i;

    if (!(cpuModels = virDomainCapsCPUModelsNew(0)))
        return NULL;

    for (i = 0; i < old->nmodels; i++) {
        if (models && !virStringListHasString(models, old->models[i].name))
            continue;

        if (blacklist && virStringListHasString(blacklist, old->models[i].name))
            continue;

        if (virDomainCapsCPUModelsAdd(cpuModels,
                                      old->models[i].name, -1,
                                      old->models[i].usable) < 0)
            goto error;
    }

    return cpuModels;

 error:
    virObjectUnref(cpuModels);
    return NULL;
}


int
virDomainCapsCPUModelsAddSteal(virDomainCapsCPUModelsPtr cpuModels,
                               char **name,
                               virDomainCapsCPUUsable usable)
{
    if (VIR_RESIZE_N(cpuModels->models, cpuModels->nmodels_max,
                     cpuModels->nmodels, 1) < 0)
        return -1;

    cpuModels->models[cpuModels->nmodels].usable = usable;
    VIR_STEAL_PTR(cpuModels->models[cpuModels->nmodels].name, *name);
    cpuModels->nmodels++;
    return 0;
}


int
virDomainCapsCPUModelsAdd(virDomainCapsCPUModelsPtr cpuModels,
                          const char *name,
                          ssize_t nameLen,
                          virDomainCapsCPUUsable usable)
{
    char *copy = NULL;

    if (VIR_STRNDUP(copy, name, nameLen) < 0)
        goto error;

    if (virDomainCapsCPUModelsAddSteal(cpuModels, &copy, usable) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(copy);
    return -1;
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
                          item->supported ? "yes" : "no",           \
                          item->supported ? ">" : "/>");            \
        if (!item->supported)                                       \
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
virDomainCapsCPUCustomFormat(virBufferPtr buf,
                             virDomainCapsCPUModelsPtr custom)
{
    size_t i;

    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < custom->nmodels; i++) {
        virDomainCapsCPUModelPtr model = custom->models + i;
        virBufferAsprintf(buf, "<model usable='%s'>%s</model>\n",
                          virDomainCapsCPUUsableTypeToString(model->usable),
                          model->name);
    }

    virBufferAdjustIndent(buf, -2);
}

static void
virDomainCapsCPUFormat(virBufferPtr buf,
                       virDomainCapsCPUPtr cpu)
{
    virBufferAddLit(buf, "<cpu>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<mode name='%s' supported='%s'/>\n",
                      virCPUModeTypeToString(VIR_CPU_MODE_HOST_PASSTHROUGH),
                      cpu->hostPassthrough ? "yes" : "no");

    virBufferAsprintf(buf, "<mode name='%s' ",
                      virCPUModeTypeToString(VIR_CPU_MODE_HOST_MODEL));
    if (cpu->hostModel) {
        virBufferAddLit(buf, "supported='yes'>\n");
        virBufferAdjustIndent(buf, 2);

        virCPUDefFormatBuf(buf, cpu->hostModel, false);

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</mode>\n");
    } else {
        virBufferAddLit(buf, "supported='no'/>\n");
    }

    virBufferAsprintf(buf, "<mode name='%s' ",
                      virCPUModeTypeToString(VIR_CPU_MODE_CUSTOM));
    if (cpu->custom && cpu->custom->nmodels) {
        virBufferAddLit(buf, "supported='yes'>\n");
        virDomainCapsCPUCustomFormat(buf, cpu->custom);
        virBufferAddLit(buf, "</mode>\n");
    } else {
        virBufferAddLit(buf, "supported='no'/>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cpu>\n");
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
virDomainCapsDeviceGraphicsFormat(virBufferPtr buf,
                                  virDomainCapsDeviceGraphicsPtr const graphics)
{
    FORMAT_PROLOGUE(graphics);

    ENUM_PROCESS(graphics, type, virDomainGraphicsTypeToString);

    FORMAT_EPILOGUE(graphics);
}


static void
virDomainCapsDeviceVideoFormat(virBufferPtr buf,
                               virDomainCapsDeviceVideoPtr const video)
{
    FORMAT_PROLOGUE(video);

    ENUM_PROCESS(video, modelType, virDomainVideoTypeToString);

    FORMAT_EPILOGUE(video);
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


/**
 * virDomainCapsFeatureGICFormat:
 * @buf: target buffer
 * @gic: GIC features
 *
 * Format GIC features for inclusion in the domcapabilities XML.
 *
 * The resulting XML will look like
 *
 *   <gic supported='yes'>
 *     <enum name='version>
 *       <value>2</value>
 *       <value>3</value>
 *     </enum>
 *   </gic>
 */
static void
virDomainCapsFeatureGICFormat(virBufferPtr buf,
                              virDomainCapsFeatureGICPtr const gic)
{
    FORMAT_PROLOGUE(gic);

    ENUM_PROCESS(gic, version, virGICVersionTypeToString);

    FORMAT_EPILOGUE(gic);
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
    if (caps->machine)
        virBufferAsprintf(buf, "<machine>%s</machine>\n", caps->machine);
    virBufferAsprintf(buf, "<arch>%s</arch>\n", arch_str);

    if (caps->maxvcpus)
        virBufferAsprintf(buf, "<vcpu max='%d'/>\n", caps->maxvcpus);

    virDomainCapsOSFormat(buf, &caps->os);
    virDomainCapsCPUFormat(buf, &caps->cpu);

    virBufferAddLit(buf, "<devices>\n");
    virBufferAdjustIndent(buf, 2);

    virDomainCapsDeviceDiskFormat(buf, &caps->disk);
    virDomainCapsDeviceGraphicsFormat(buf, &caps->graphics);
    virDomainCapsDeviceVideoFormat(buf, &caps->video);
    virDomainCapsDeviceHostdevFormat(buf, &caps->hostdev);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</devices>\n");

    virBufferAddLit(buf, "<features>\n");
    virBufferAdjustIndent(buf, 2);

    virDomainCapsFeatureGICFormat(buf, &caps->gic);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</features>\n");

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
