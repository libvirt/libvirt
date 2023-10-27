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

#include "domain_capabilities.h"
#include "domain_conf.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

VIR_ENUM_IMPL(virDomainCapsCPUUsable,
              VIR_DOMCAPS_CPU_USABLE_LAST,
              "unknown", "yes", "no",
);


VIR_ENUM_DECL(virDomainCapsFeature);
VIR_ENUM_IMPL(virDomainCapsFeature,
              VIR_DOMAIN_CAPS_FEATURE_LAST,
              "iothreads",
              "vmcoreinfo",
              "genid",
              "backingStoreInput",
              "backup",
              "async-teardown",
              "s390-pv",
);

static virClass *virDomainCapsClass;
static virClass *virDomainCapsCPUModelsClass;

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


void
virSEVCapabilitiesFree(virSEVCapability *cap)
{
    if (!cap)
        return;

    g_free(cap->pdh);
    g_free(cap->cert_chain);
    g_free(cap);
}


void
virSGXCapabilitiesFree(virSGXCapability *cap)
{
    if (!cap)
        return;

    g_free(cap->sgxSections);
    g_free(cap);
}


static void
virDomainCapsDispose(void *obj)
{
    virDomainCaps *caps = obj;
    virDomainCapsStringValues *values;
    size_t i;

    g_free(caps->path);
    g_free(caps->machine);
    virObjectUnref(caps->cpu.custom);
    virCPUDefFree(caps->cpu.hostModel);
    virSEVCapabilitiesFree(caps->sev);
    virSGXCapabilitiesFree(caps->sgx);
    g_free(caps->hyperv);

    values = &caps->os.loader.values;
    for (i = 0; i < values->nvalues; i++)
        g_free(values->values[i]);
    g_free(values->values);
}


static void
virDomainCapsCPUModelsDispose(void *obj)
{
    virDomainCapsCPUModels *cpuModels = obj;
    size_t i;

    for (i = 0; i < cpuModels->nmodels; i++) {
        g_free(cpuModels->models[i].name);
        g_strfreev(cpuModels->models[i].blockers);
        g_free(cpuModels->models[i].vendor);
    }

    g_free(cpuModels->models);
}


virDomainCaps *
virDomainCapsNew(const char *path,
                 const char *machine,
                 virArch arch,
                 virDomainVirtType virttype)
{
    virDomainCaps *caps = NULL;

    if (virDomainCapsInitialize() < 0)
        return NULL;

    if (!(caps = virObjectLockableNew(virDomainCapsClass)))
        return NULL;

    caps->path = g_strdup(path);
    caps->machine = g_strdup(machine);
    caps->arch = arch;
    caps->virttype = virttype;

    return caps;
}


virDomainCapsCPUModels *
virDomainCapsCPUModelsNew(size_t nmodels)
{
    virDomainCapsCPUModels *cpuModels = NULL;

    if (virDomainCapsInitialize() < 0)
        return NULL;

    if (!(cpuModels = virObjectNew(virDomainCapsCPUModelsClass)))
        return NULL;

    cpuModels->models = g_new0(virDomainCapsCPUModel, nmodels);
    cpuModels->nmodels_max = nmodels;

    return cpuModels;
}


virDomainCapsCPUModels *
virDomainCapsCPUModelsCopy(virDomainCapsCPUModels *old)
{
    virDomainCapsCPUModels *cpuModels = NULL;
    size_t i;

    if (!(cpuModels = virDomainCapsCPUModelsNew(old->nmodels)))
        return NULL;

    for (i = 0; i < old->nmodels; i++) {
        virDomainCapsCPUModelsAdd(cpuModels,
                                  old->models[i].name,
                                  old->models[i].usable,
                                  old->models[i].blockers,
                                  old->models[i].deprecated,
                                  old->models[i].vendor);
    }

    return cpuModels;
}


void
virDomainCapsCPUModelsAdd(virDomainCapsCPUModels *cpuModels,
                          const char *name,
                          virDomainCapsCPUUsable usable,
                          char **blockers,
                          bool deprecated,
                          const char *vendor)
{
    virDomainCapsCPUModel *cpu;

    VIR_RESIZE_N(cpuModels->models, cpuModels->nmodels_max,
                 cpuModels->nmodels, 1);

    cpu = cpuModels->models + cpuModels->nmodels;
    cpuModels->nmodels++;

    cpu->usable = usable;
    cpu->name = g_strdup(name);
    cpu->blockers = g_strdupv(blockers);
    cpu->deprecated = deprecated;
    cpu->vendor = g_strdup(vendor);
}


virDomainCapsCPUModel *
virDomainCapsCPUModelsGet(virDomainCapsCPUModels *cpuModels,
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
virDomainCapsEnumSet(virDomainCapsEnum *capsEnum,
                     const char *capsEnumName,
                     size_t nvalues,
                     unsigned int *values)
{
    size_t i;

    for (i = 0; i < nvalues; i++) {
        unsigned int val = 1 << values[i];

        if (!val) {
            /* Integer overflow */
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("integer overflow on %1$s. Please contact the libvirt development team at devel@lists.libvirt.org"),
                           capsEnumName);
            return -1;
        }

        capsEnum->values |= val;
    }

    return 0;
}


void
virDomainCapsEnumClear(virDomainCapsEnum *capsEnum)
{
    capsEnum->values = 0;
}


static void
virDomainCapsEnumFormat(virBuffer *buf,
                        const virDomainCapsEnum *capsEnum,
                        const char *capsEnumName,
                        virDomainCapsValToStr valToStr)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    if (!capsEnum->report)
        return;

    virBufferAsprintf(&attrBuf, " name='%s'", capsEnumName);

    for (i = 0; i < sizeof(capsEnum->values) * CHAR_BIT; i++) {
        const char *val;

        if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(*capsEnum, i))
            continue;

        if ((val = (valToStr)(i)))
            virBufferAsprintf(&childBuf, "<value>%s</value>\n", val);
    }

    virXMLFormatElement(buf, "enum", &attrBuf, &childBuf);
}


static void
virDomainCapsStringValuesFormat(virBuffer *buf,
                                const virDomainCapsStringValues *values)
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

#define ENUM_PROCESS(master, capsEnum, valToStr) \
    do { \
        virDomainCapsEnumFormat(buf, &master->capsEnum, \
                                #capsEnum, valToStr); \
    } while (0)


static void
virDomainCapsFeatureFormatSimple(virBuffer *buf,
                                 const char *featurename,
                                 virTristateBool supported)
{
    if (supported == VIR_TRISTATE_BOOL_ABSENT)
        return;

    virBufferAsprintf(buf, "<%s supported='%s'/>\n", featurename,
                      virTristateBoolTypeToString(supported));
}


static void
virDomainCapsLoaderFormat(virBuffer *buf,
                          const virDomainCapsLoader *loader)
{
    FORMAT_PROLOGUE(loader);

    virDomainCapsStringValuesFormat(buf, &loader->values);
    ENUM_PROCESS(loader, type, virDomainLoaderTypeToString);
    ENUM_PROCESS(loader, readonly, virTristateBoolTypeToString);
    ENUM_PROCESS(loader, secure, virTristateBoolTypeToString);

    FORMAT_EPILOGUE(loader);
}

static void
virDomainCapsOSFormat(virBuffer *buf,
                      const virDomainCapsOS *os)
{
    const virDomainCapsLoader *loader = &os->loader;

    FORMAT_PROLOGUE(os);

    ENUM_PROCESS(os, firmware, virDomainOsDefFirmwareTypeToString);

    virDomainCapsLoaderFormat(buf, loader);

    FORMAT_EPILOGUE(os);
}

static void
virDomainCapsCPUCustomFormat(virBuffer *buf,
                             virDomainCapsCPUModels *custom)
{
    size_t i;

    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < custom->nmodels; i++) {
        virDomainCapsCPUModel *model = custom->models + i;

        virBufferAsprintf(buf, "<model usable='%s'",
                          virDomainCapsCPUUsableTypeToString(model->usable));

        if (model->deprecated)
            virBufferAddLit(buf, " deprecated='yes'");

        if (model->vendor)
            virBufferAsprintf(buf, " vendor='%s'", model->vendor);
        else
            virBufferAddLit(buf, " vendor='unknown'");

        virBufferAsprintf(buf, ">%s</model>\n", model->name);
    }

    virBufferAdjustIndent(buf, -2);
}

static void
virDomainCapsCPUFormat(virBuffer *buf,
                       const virDomainCapsCPU *cpu)
{
    virBufferAddLit(buf, "<cpu>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<mode name='%s' supported='%s'",
                      virCPUModeTypeToString(VIR_CPU_MODE_HOST_PASSTHROUGH),
                      cpu->hostPassthrough ? "yes" : "no");

    if (cpu->hostPassthrough && cpu->hostPassthroughMigratable.report) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        ENUM_PROCESS(cpu, hostPassthroughMigratable,
                     virTristateSwitchTypeToString);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</mode>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    virBufferAsprintf(buf, "<mode name='%s' supported='%s'",
                      virCPUModeTypeToString(VIR_CPU_MODE_MAXIMUM),
                      cpu->maximum ? "yes" : "no");

    if (cpu->maximum && cpu->maximumMigratable.report) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        ENUM_PROCESS(cpu, maximumMigratable,
                     virTristateSwitchTypeToString);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</mode>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

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
virDomainCapsMemoryBackingFormat(virBuffer *buf,
                                 const virDomainCapsMemoryBacking *memoryBacking)
{
    FORMAT_PROLOGUE(memoryBacking);

    ENUM_PROCESS(memoryBacking, sourceType, virDomainMemorySourceTypeToString);

    FORMAT_EPILOGUE(memoryBacking);
}


static void
virDomainCapsDeviceDiskFormat(virBuffer *buf,
                              const virDomainCapsDeviceDisk *disk)
{
    FORMAT_PROLOGUE(disk);

    ENUM_PROCESS(disk, diskDevice, virDomainDiskDeviceTypeToString);
    ENUM_PROCESS(disk, bus, virDomainDiskBusTypeToString);
    ENUM_PROCESS(disk, model, virDomainDiskModelTypeToString);

    FORMAT_EPILOGUE(disk);
}


static void
virDomainCapsDeviceGraphicsFormat(virBuffer *buf,
                                  const virDomainCapsDeviceGraphics *graphics)
{
    FORMAT_PROLOGUE(graphics);

    ENUM_PROCESS(graphics, type, virDomainGraphicsTypeToString);

    FORMAT_EPILOGUE(graphics);
}


static void
virDomainCapsDeviceVideoFormat(virBuffer *buf,
                               const virDomainCapsDeviceVideo *video)
{
    FORMAT_PROLOGUE(video);

    ENUM_PROCESS(video, modelType, virDomainVideoTypeToString);

    FORMAT_EPILOGUE(video);
}


static void
virDomainCapsDeviceHostdevFormat(virBuffer *buf,
                                 const virDomainCapsDeviceHostdev *hostdev)
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
virDomainCapsDeviceRNGFormat(virBuffer *buf,
                             const virDomainCapsDeviceRNG *rng)
{
    FORMAT_PROLOGUE(rng);

    ENUM_PROCESS(rng, model, virDomainRNGModelTypeToString);
    ENUM_PROCESS(rng, backendModel, virDomainRNGBackendTypeToString);

    FORMAT_EPILOGUE(rng);
}


static void
virDomainCapsDeviceTPMFormat(virBuffer *buf,
                             const virDomainCapsDeviceTPM *tpm)
{
    FORMAT_PROLOGUE(tpm);

    ENUM_PROCESS(tpm, model, virDomainTPMModelTypeToString);
    ENUM_PROCESS(tpm, backendModel, virDomainTPMBackendTypeToString);
    ENUM_PROCESS(tpm, backendVersion, virDomainTPMVersionTypeToString);

    FORMAT_EPILOGUE(tpm);
}


static void
virDomainCapsDeviceFilesystemFormat(virBuffer *buf,
                                    const virDomainCapsDeviceFilesystem *filesystem)
{
    FORMAT_PROLOGUE(filesystem);

    ENUM_PROCESS(filesystem, driverType, virDomainFSDriverTypeToString);

    FORMAT_EPILOGUE(filesystem);
}


static void
virDomainCapsDeviceRedirdevFormat(virBuffer *buf,
                                  const virDomainCapsDeviceRedirdev *redirdev)
{
    FORMAT_PROLOGUE(redirdev);

    ENUM_PROCESS(redirdev, bus, virDomainRedirdevBusTypeToString);

    FORMAT_EPILOGUE(redirdev);
}


static void
virDomainCapsDeviceChannelFormat(virBuffer *buf,
                                 const virDomainCapsDeviceChannel *channel)
{
    FORMAT_PROLOGUE(channel);

    ENUM_PROCESS(channel, type, virDomainChrTypeToString);

    FORMAT_EPILOGUE(channel);
}


static void
virDomainCapsDeviceCryptoFormat(virBuffer *buf,
                                const virDomainCapsDeviceCrypto *crypto)
{
    FORMAT_PROLOGUE(crypto);

    ENUM_PROCESS(crypto, model, virDomainCryptoModelTypeToString);
    ENUM_PROCESS(crypto, type, virDomainCryptoTypeTypeToString);
    ENUM_PROCESS(crypto, backendModel, virDomainCryptoBackendTypeToString);

    FORMAT_EPILOGUE(crypto);
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
virDomainCapsFeatureGICFormat(virBuffer *buf,
                              const virDomainCapsFeatureGIC *gic)
{
    FORMAT_PROLOGUE(gic);

    ENUM_PROCESS(gic, version, virGICVersionTypeToString);

    FORMAT_EPILOGUE(gic);
}

static void
virDomainCapsFeatureSEVFormat(virBuffer *buf,
                              const virSEVCapability *sev)
{
    if (!sev) {
        virBufferAddLit(buf, "<sev supported='no'/>\n");
        return;
    }

    virBufferAddLit(buf, "<sev supported='yes'>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<cbitpos>%d</cbitpos>\n", sev->cbitpos);
    virBufferAsprintf(buf, "<reducedPhysBits>%d</reducedPhysBits>\n",
                      sev->reduced_phys_bits);
    virBufferAsprintf(buf, "<maxGuests>%d</maxGuests>\n", sev->max_guests);
    virBufferAsprintf(buf, "<maxESGuests>%d</maxESGuests>\n", sev->max_es_guests);

    if (sev->cpu0_id != NULL)
        virBufferAsprintf(buf, "<cpu0Id>%s</cpu0Id>\n", sev->cpu0_id);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</sev>\n");
}

static void
virDomainCapsFeatureSGXFormat(virBuffer *buf,
                              const virSGXCapability *sgx)
{
    if (!sgx) {
        virBufferAddLit(buf, "<sgx supported='no'/>\n");
        return;
    }

    virBufferAddLit(buf, "<sgx supported='yes'>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<flc>%s</flc>\n", sgx->flc ? "yes" : "no");
    virBufferAsprintf(buf, "<sgx1>%s</sgx1>\n", sgx->sgx1 ? "yes" : "no");
    virBufferAsprintf(buf, "<sgx2>%s</sgx2>\n", sgx->sgx2 ? "yes" : "no");
    virBufferAsprintf(buf, "<section_size unit='KiB'>%llu</section_size>\n", sgx->section_size);

    if (sgx->nSgxSections > 0) {
        size_t i;

        virBufferAddLit(buf, "<sections>\n");

        for (i = 0; i < sgx->nSgxSections; i++) {
            virBufferAdjustIndent(buf, 2);
            virBufferAsprintf(buf, "<section node='%d' ", sgx->sgxSections[i].node);
            virBufferAsprintf(buf, "size='%llu' ", sgx->sgxSections[i].size);
            virBufferAddLit(buf, "unit='KiB'/>\n");
            virBufferAdjustIndent(buf, -2);
        }
        virBufferAddLit(buf, "</sections>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</sgx>\n");
}

static void
virDomainCapsFeatureHypervFormat(virBuffer *buf,
                                 const virDomainCapsFeatureHyperv *hyperv)
{
    if (!hyperv)
        return;

    FORMAT_PROLOGUE(hyperv);

    ENUM_PROCESS(hyperv, features, virDomainHypervTypeToString);

    FORMAT_EPILOGUE(hyperv);
}

static void
virDomainCapsFormatFeatures(const virDomainCaps *caps,
                            virBuffer *buf)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    virDomainCapsFeatureGICFormat(&childBuf, &caps->gic);

    for (i = 0; i < VIR_DOMAIN_CAPS_FEATURE_LAST; i++) {
        if (i == VIR_DOMAIN_CAPS_FEATURE_IOTHREADS)
            continue;

        virDomainCapsFeatureFormatSimple(&childBuf,
                                         virDomainCapsFeatureTypeToString(i),
                                         caps->features[i]);
    }

    virDomainCapsFeatureSEVFormat(&childBuf, caps->sev);
    virDomainCapsFeatureSGXFormat(&childBuf, caps->sgx);
    virDomainCapsFeatureHypervFormat(&childBuf, caps->hyperv);

    virXMLFormatElement(buf, "features", NULL, &childBuf);
}


char *
virDomainCapsFormat(const virDomainCaps *caps)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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

    virDomainCapsFeatureFormatSimple(&buf, "iothreads",
                                     caps->features[VIR_DOMAIN_CAPS_FEATURE_IOTHREADS]);

    virDomainCapsOSFormat(&buf, &caps->os);
    virDomainCapsCPUFormat(&buf, &caps->cpu);

    virDomainCapsMemoryBackingFormat(&buf, &caps->memoryBacking);

    virBufferAddLit(&buf, "<devices>\n");
    virBufferAdjustIndent(&buf, 2);

    virDomainCapsDeviceDiskFormat(&buf, &caps->disk);
    virDomainCapsDeviceGraphicsFormat(&buf, &caps->graphics);
    virDomainCapsDeviceVideoFormat(&buf, &caps->video);
    virDomainCapsDeviceHostdevFormat(&buf, &caps->hostdev);
    virDomainCapsDeviceRNGFormat(&buf, &caps->rng);
    virDomainCapsDeviceFilesystemFormat(&buf, &caps->filesystem);
    virDomainCapsDeviceTPMFormat(&buf, &caps->tpm);
    virDomainCapsDeviceRedirdevFormat(&buf, &caps->redirdev);
    virDomainCapsDeviceChannelFormat(&buf, &caps->channel);
    virDomainCapsDeviceCryptoFormat(&buf, &caps->crypto);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</devices>\n");

    virDomainCapsFormatFeatures(caps, &buf);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domainCapabilities>\n");

    return virBufferContentAndReset(&buf);
}
