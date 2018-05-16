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
 */

#include <config.h>

#include "device_conf.h"
#include "domain_capabilities.h"
#include "domain_conf.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

VIR_ENUM_IMPL(virDomainCapsCPUUsable,
              VIR_DOMCAPS_CPU_USABLE_LAST,
              "unknown", "yes", "no",
);

static virClassPtr virDomainCapsClass;
static virClassPtr virDomainCapsCPUModelsClass;

static void virDomainCapsDispose(void *obj);
static void virDomainCapsCPUModelsDispose(void *obj);

static int virDomainCapsOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainCaps, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virDomainCapsCPUModels, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virDomainCaps);


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


void
virSEVCapabilitiesFree(virSEVCapability *cap)
{
    if (!cap)
        return;

    VIR_FREE(cap->pdh);
    VIR_FREE(cap->cert_chain);
    VIR_FREE(cap);
}


static void
virDomainCapsDispose(void *obj)
{
    virDomainCapsPtr caps = obj;

    VIR_FREE(caps->path);
    VIR_FREE(caps->machine);
    virObjectUnref(caps->cpu.custom);
    virCPUDefFree(caps->cpu.hostModel);
    virSEVCapabilitiesFree(caps->sev);

    virDomainCapsStringValuesFree(&caps->os.loader.values);
}


static void
virDomainCapsCPUModelsDispose(void *obj)
{
    virDomainCapsCPUModelsPtr cpuModels = obj;
    size_t i;

    for (i = 0; i < cpuModels->nmodels; i++) {
        VIR_FREE(cpuModels->models[i].name);
        virStringListFree(cpuModels->models[i].blockers);
    }

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
                                      old->models[i].usable,
                                      old->models[i].blockers) < 0)
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
                                      old->models[i].usable,
                                      old->models[i].blockers) < 0)
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
                               virDomainCapsCPUUsable usable,
                               char ***blockers)
{
    if (VIR_RESIZE_N(cpuModels->models, cpuModels->nmodels_max,
                     cpuModels->nmodels, 1) < 0)
        return -1;

    cpuModels->models[cpuModels->nmodels].usable = usable;
    VIR_STEAL_PTR(cpuModels->models[cpuModels->nmodels].name, *name);

    if (blockers)
        VIR_STEAL_PTR(cpuModels->models[cpuModels->nmodels].blockers, *blockers);

    cpuModels->nmodels++;
    return 0;
}


int
virDomainCapsCPUModelsAdd(virDomainCapsCPUModelsPtr cpuModels,
                          const char *name,
                          ssize_t nameLen,
                          virDomainCapsCPUUsable usable,
                          char **blockers)
{
    char *nameCopy = NULL;
    char **blockersCopy = NULL;

    if (VIR_STRNDUP(nameCopy, name, nameLen) < 0)
        goto error;

    if (virStringListCopy(&blockersCopy, (const char **)blockers) < 0)
        goto error;

    if (virDomainCapsCPUModelsAddSteal(cpuModels, &nameCopy,
                                       usable, &blockersCopy) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(nameCopy);
    virStringListFree(blockersCopy);
    return -1;
}


virDomainCapsCPUModelPtr
virDomainCapsCPUModelsGet(virDomainCapsCPUModelsPtr cpuModels,
                          const char *name)
{
    size_t i;

    if (!cpuModels)
        return NULL;

    for (i = 0; i < cpuModels->nmodels; i++) {
        if (STREQ(cpuModels->models[i].name, name))
            return cpuModels->models + i;
    }

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

    if (!capsEnum->report) {
        ret = 0;
        goto cleanup;
    }

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


#define FORMAT_PROLOGUE(item) \
    do { \
        if (item->supported == VIR_TRISTATE_BOOL_ABSENT) \
            return; \
        virBufferAsprintf(buf, "<" #item " supported='%s'%s\n", \
                (item->supported == VIR_TRISTATE_BOOL_YES) ? "yes" : "no", \
                (item->supported == VIR_TRISTATE_BOOL_YES) ? ">" : "/>"); \
        if (item->supported == VIR_TRISTATE_BOOL_NO) \
            return; \
        virBufferAdjustIndent(buf, 2); \
    } while (0)

#define FORMAT_EPILOGUE(item) \
    do { \
        virBufferAdjustIndent(buf, -2); \
        virBufferAddLit(buf, "</" #item ">\n"); \
    } while (0)

#define FORMAT_SINGLE(name, supported) \
    do { \
        if (supported != VIR_TRISTATE_BOOL_ABSENT) { \
            virBufferAsprintf(&buf, "<%s supported='%s'/>\n", name, \
                    (supported == VIR_TRISTATE_BOOL_YES) ? "yes" : "no"); \
        } \
    } while (0)

#define ENUM_PROCESS(master, capsEnum, valToStr) \
    do { \
        virDomainCapsEnumFormat(buf, &master->capsEnum, \
                                #capsEnum, valToStr); \
    } while (0)


static void
virDomainCapsLoaderFormat(virBufferPtr buf,
                          virDomainCapsLoaderPtr loader)
{
    FORMAT_PROLOGUE(loader);

    virDomainCapsStringValuesFormat(buf, &loader->values);
    ENUM_PROCESS(loader, type, virDomainLoaderTypeToString);
    ENUM_PROCESS(loader, readonly, virTristateBoolTypeToString);
    ENUM_PROCESS(loader, secure, virTristateBoolTypeToString);

    FORMAT_EPILOGUE(loader);
}

static void
virDomainCapsOSFormat(virBufferPtr buf,
                      virDomainCapsOSPtr os)
{
    virDomainCapsLoaderPtr loader = &os->loader;

    FORMAT_PROLOGUE(os);

    ENUM_PROCESS(os, firmware, virDomainOsDefFirmwareTypeToString);

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

        virCPUDefFormatBuf(buf, cpu->hostModel);

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
    ENUM_PROCESS(disk, model, virDomainDiskModelTypeToString);

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


static void
virDomainCapsDeviceRNGFormat(virBufferPtr buf,
                             virDomainCapsDeviceRNGPtr const rng)
{
    FORMAT_PROLOGUE(rng);

    ENUM_PROCESS(rng, model, virDomainRNGModelTypeToString);
    ENUM_PROCESS(rng, backendModel, virDomainRNGBackendTypeToString);

    FORMAT_EPILOGUE(rng);
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

static void
virDomainCapsFeatureSEVFormat(virBufferPtr buf,
                              virSEVCapabilityPtr const sev)
{
    if (!sev) {
        virBufferAddLit(buf, "<sev supported='no'/>\n");
    } else {
        virBufferAddLit(buf, "<sev supported='yes'>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<cbitpos>%d</cbitpos>\n", sev->cbitpos);
        virBufferAsprintf(buf, "<reducedPhysBits>%d</reducedPhysBits>\n",
                          sev->reduced_phys_bits);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</sev>\n");
    }

    return;
}


char *
virDomainCapsFormat(virDomainCapsPtr const caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *virttype_str = virDomainVirtTypeToString(caps->virttype);
    const char *arch_str = virArchToString(caps->arch);

    virBufferAddLit(&buf, "<domainCapabilities>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferEscapeString(&buf, "<path>%s</path>\n", caps->path);
    virBufferAsprintf(&buf, "<domain>%s</domain>\n", virttype_str);
    if (caps->machine)
        virBufferAsprintf(&buf, "<machine>%s</machine>\n", caps->machine);
    virBufferAsprintf(&buf, "<arch>%s</arch>\n", arch_str);

    if (caps->maxvcpus)
        virBufferAsprintf(&buf, "<vcpu max='%d'/>\n", caps->maxvcpus);

    FORMAT_SINGLE("iothreads", caps->iothreads);

    virDomainCapsOSFormat(&buf, &caps->os);
    virDomainCapsCPUFormat(&buf, &caps->cpu);

    virBufferAddLit(&buf, "<devices>\n");
    virBufferAdjustIndent(&buf, 2);

    virDomainCapsDeviceDiskFormat(&buf, &caps->disk);
    virDomainCapsDeviceGraphicsFormat(&buf, &caps->graphics);
    virDomainCapsDeviceVideoFormat(&buf, &caps->video);
    virDomainCapsDeviceHostdevFormat(&buf, &caps->hostdev);
    virDomainCapsDeviceRNGFormat(&buf, &caps->rng);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</devices>\n");

    virBufferAddLit(&buf, "<features>\n");
    virBufferAdjustIndent(&buf, 2);

    virDomainCapsFeatureGICFormat(&buf, &caps->gic);
    FORMAT_SINGLE("vmcoreinfo", caps->vmcoreinfo);
    FORMAT_SINGLE("genid", caps->genid);
    virDomainCapsFeatureSEVFormat(&buf, caps->sev);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</features>\n");

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domainCapabilities>\n");

    virBufferCheckError(&buf);
    return virBufferContentAndReset(&buf);
}


#define ENUM_VALUE_MISSING(capsEnum, value) !(capsEnum.values & (1 << value))

#define ENUM_VALUE_ERROR(valueLabel, valueString) \
    do { \
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                       _("domain configuration does not support '%s' value '%s'"), \
                       valueLabel, valueString); \
    } while (0)


static int
virDomainCapsDeviceRNGDefValidate(virDomainCapsPtr const caps,
                                  const virDomainRNGDef *dev)
{
    if (ENUM_VALUE_MISSING(caps->rng.model, dev->model)) {
        ENUM_VALUE_ERROR("rng model",
                         virDomainRNGModelTypeToString(dev->model));
        return -1;
    }

    return 0;
}


int
virDomainCapsDeviceDefValidate(virDomainCapsPtr const caps,
                               const virDomainDeviceDef *dev,
                               const virDomainDef *def ATTRIBUTE_UNUSED)
{
    int ret = 0;

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_RNG:
        ret = virDomainCapsDeviceRNGDefValidate(caps, dev->data.rng);
        break;

    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }

    return ret;
}
