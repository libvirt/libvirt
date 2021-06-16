/*
 * qemu_firmware.c: QEMU firmware
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "qemu_firmware.h"
#include "qemu_interop_config.h"
#include "configmake.h"
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "virarch.h"
#include "virjson.h"
#include "virlog.h"
#include "virstring.h"
#include "viralloc.h"
#include "virenum.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_firmware");


typedef enum {
    QEMU_FIRMWARE_OS_INTERFACE_NONE = 0,
    QEMU_FIRMWARE_OS_INTERFACE_BIOS,
    QEMU_FIRMWARE_OS_INTERFACE_OPENFIRMWARE,
    QEMU_FIRMWARE_OS_INTERFACE_UBOOT,
    QEMU_FIRMWARE_OS_INTERFACE_UEFI,

    QEMU_FIRMWARE_OS_INTERFACE_LAST
} qemuFirmwareOSInterface;

VIR_ENUM_DECL(qemuFirmwareOSInterface);
VIR_ENUM_IMPL(qemuFirmwareOSInterface,
              QEMU_FIRMWARE_OS_INTERFACE_LAST,
              "",
              "bios",
              "openfirmware",
              "uboot",
              "uefi",
);


typedef struct _qemuFirmwareFlashFile qemuFirmwareFlashFile;
struct _qemuFirmwareFlashFile {
    char *filename;
    char *format;
};


typedef struct _qemuFirmwareMappingFlash qemuFirmwareMappingFlash;
struct _qemuFirmwareMappingFlash {
    qemuFirmwareFlashFile executable;
    qemuFirmwareFlashFile nvram_template;
};


typedef struct _qemuFirmwareMappingKernel qemuFirmwareMappingKernel;
struct _qemuFirmwareMappingKernel {
    char *filename;
};


typedef struct _qemuFirmwareMappingMemory qemuFirmwareMappingMemory;
struct _qemuFirmwareMappingMemory {
    char *filename;
};


typedef enum {
    QEMU_FIRMWARE_DEVICE_NONE = 0,
    QEMU_FIRMWARE_DEVICE_FLASH,
    QEMU_FIRMWARE_DEVICE_KERNEL,
    QEMU_FIRMWARE_DEVICE_MEMORY,

    QEMU_FIRMWARE_DEVICE_LAST
} qemuFirmwareDevice;

VIR_ENUM_DECL(qemuFirmwareDevice);
VIR_ENUM_IMPL(qemuFirmwareDevice,
              QEMU_FIRMWARE_DEVICE_LAST,
              "",
              "flash",
              "kernel",
              "memory",
);


typedef struct _qemuFirmwareMapping qemuFirmwareMapping;
struct _qemuFirmwareMapping {
    qemuFirmwareDevice device;

    union {
        qemuFirmwareMappingFlash flash;
        qemuFirmwareMappingKernel kernel;
        qemuFirmwareMappingMemory memory;
    } data;
};


typedef struct _qemuFirmwareTarget qemuFirmwareTarget;
struct _qemuFirmwareTarget {
    virArch architecture;
    size_t nmachines;
    char **machines;
};


typedef enum {
    QEMU_FIRMWARE_FEATURE_NONE = 0,
    QEMU_FIRMWARE_FEATURE_ACPI_S3,
    QEMU_FIRMWARE_FEATURE_ACPI_S4,
    QEMU_FIRMWARE_FEATURE_AMD_SEV,
    QEMU_FIRMWARE_FEATURE_AMD_SEV_ES,
    QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS,
    QEMU_FIRMWARE_FEATURE_REQUIRES_SMM,
    QEMU_FIRMWARE_FEATURE_SECURE_BOOT,
    QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC,
    QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC,

    QEMU_FIRMWARE_FEATURE_LAST
} qemuFirmwareFeature;

VIR_ENUM_DECL(qemuFirmwareFeature);
VIR_ENUM_IMPL(qemuFirmwareFeature,
              QEMU_FIRMWARE_FEATURE_LAST,
              "",
              "acpi-s3",
              "acpi-s4",
              "amd-sev",
              "amd-sev-es",
              "enrolled-keys",
              "requires-smm",
              "secure-boot",
              "verbose-dynamic",
              "verbose-static"
);


struct _qemuFirmware {
    /* Description intentionally not parsed. */

    size_t ninterfaces;
    qemuFirmwareOSInterface *interfaces;

    qemuFirmwareMapping mapping;

    size_t ntargets;
    qemuFirmwareTarget **targets;

    size_t nfeatures;
    qemuFirmwareFeature *features;

    /* Tags intentionally not parsed. */
};


static void
qemuFirmwareOSInterfaceFree(qemuFirmwareOSInterface *interfaces)
{
    g_free(interfaces);
}


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuFirmwareOSInterface, qemuFirmwareOSInterfaceFree);


static void
qemuFirmwareFlashFileFreeContent(qemuFirmwareFlashFile *flash)
{
    g_free(flash->filename);
    g_free(flash->format);
}


static void
qemuFirmwareMappingFlashFreeContent(qemuFirmwareMappingFlash *flash)
{
    qemuFirmwareFlashFileFreeContent(&flash->executable);
    qemuFirmwareFlashFileFreeContent(&flash->nvram_template);
}


static void
qemuFirmwareMappingKernelFreeContent(qemuFirmwareMappingKernel *kernel)
{
    g_free(kernel->filename);
}


static void
qemuFirmwareMappingMemoryFreeContent(qemuFirmwareMappingMemory *memory)
{
    g_free(memory->filename);
}


static void
qemuFirmwareMappingFreeContent(qemuFirmwareMapping *mapping)
{
    switch (mapping->device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        qemuFirmwareMappingFlashFreeContent(&mapping->data.flash);
        break;
    case QEMU_FIRMWARE_DEVICE_KERNEL:
        qemuFirmwareMappingKernelFreeContent(&mapping->data.kernel);
        break;
    case QEMU_FIRMWARE_DEVICE_MEMORY:
        qemuFirmwareMappingMemoryFreeContent(&mapping->data.memory);
        break;
    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        break;
    }
}


static void
qemuFirmwareTargetFree(qemuFirmwareTarget *target)
{
    if (!target)
        return;

    g_strfreev(target->machines);

    g_free(target);
}


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuFirmwareTarget, qemuFirmwareTargetFree);


static void
qemuFirmwareFeatureFree(qemuFirmwareFeature *features)
{
    g_free(features);
}


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuFirmwareFeature, qemuFirmwareFeatureFree);


void
qemuFirmwareFree(qemuFirmware *fw)
{
    size_t i;

    if (!fw)
        return;

    qemuFirmwareOSInterfaceFree(fw->interfaces);
    qemuFirmwareMappingFreeContent(&fw->mapping);
    for (i = 0; i < fw->ntargets; i++)
        qemuFirmwareTargetFree(fw->targets[i]);
    g_free(fw->targets);
    qemuFirmwareFeatureFree(fw->features);

    g_free(fw);
}


static int
qemuFirmwareInterfaceParse(const char *path,
                           virJSONValue *doc,
                           qemuFirmware *fw)
{
    virJSONValue *interfacesJSON;
    g_autoptr(qemuFirmwareOSInterface) interfaces = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t ninterfaces;
    size_t i;

    if (!(interfacesJSON = virJSONValueObjectGetArray(doc, "interface-types"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get interface-types from '%s'"),
                       path);
        return -1;
    }

    ninterfaces = virJSONValueArraySize(interfacesJSON);

    interfaces = g_new0(qemuFirmwareOSInterface, ninterfaces);

    for (i = 0; i < ninterfaces; i++) {
        virJSONValue *item = virJSONValueArrayGet(interfacesJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuFirmwareOSInterfaceTypeFromString(tmpStr)) <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown interface type: '%s'"),
                           tmpStr);
            return -1;
        }

        virBufferAsprintf(&buf, " %s", tmpStr);
        interfaces[i] = tmp;
    }

    VIR_DEBUG("firmware description path '%s' supported interfaces: %s",
              path, NULLSTR_MINUS(virBufferCurrentContent(&buf)));

    fw->interfaces = g_steal_pointer(&interfaces);
    fw->ninterfaces = ninterfaces;
    return 0;
}


static int
qemuFirmwareFlashFileParse(const char *path,
                           virJSONValue *doc,
                           qemuFirmwareFlashFile *flash)
{
    const char *filename;
    const char *format;

    if (!(filename = virJSONValueObjectGetString(doc, "filename"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'filename' in '%s'"),
                       path);
        return -1;
    }

    flash->filename = g_strdup(filename);

    if (!(format = virJSONValueObjectGetString(doc, "format"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'format' in '%s'"),
                       path);
        return -1;
    }

    flash->format = g_strdup(format);

    return 0;
}


static int
qemuFirmwareMappingFlashParse(const char *path,
                              virJSONValue *doc,
                              qemuFirmwareMappingFlash *flash)
{
    virJSONValue *executable;
    virJSONValue *nvram_template;

    if (!(executable = virJSONValueObjectGet(doc, "executable"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'executable' in '%s'"),
                       path);
        return -1;
    }

    if (qemuFirmwareFlashFileParse(path, executable, &flash->executable) < 0)
        return -1;

    if (!(nvram_template = virJSONValueObjectGet(doc, "nvram-template"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'nvram-template' in '%s'"),
                       path);
        return -1;
    }

    if (qemuFirmwareFlashFileParse(path, nvram_template, &flash->nvram_template) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingKernelParse(const char *path,
                               virJSONValue *doc,
                               qemuFirmwareMappingKernel *kernel)
{
    const char *filename;

    if (!(filename = virJSONValueObjectGetString(doc, "filename"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'filename' in '%s'"),
                       path);
    }

    kernel->filename = g_strdup(filename);

    return 0;
}


static int
qemuFirmwareMappingMemoryParse(const char *path,
                               virJSONValue *doc,
                               qemuFirmwareMappingMemory *memory)
{
    const char *filename;

    if (!(filename = virJSONValueObjectGetString(doc, "filename"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'filename' in '%s'"),
                       path);
    }

    memory->filename = g_strdup(filename);

    return 0;
}


static int
qemuFirmwareMappingParse(const char *path,
                         virJSONValue *doc,
                         qemuFirmware *fw)
{
    virJSONValue *mapping;
    const char *deviceStr;
    int tmp;

    if (!(mapping = virJSONValueObjectGet(doc, "mapping"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing mapping in '%s'"),
                       path);
        return -1;
    }

    if (!(deviceStr = virJSONValueObjectGetString(mapping, "device"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing device type in '%s'"),
                       path);
        return -1;
    }

    if ((tmp = qemuFirmwareDeviceTypeFromString(deviceStr)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown device type in '%s'"),
                       path);
        return -1;
    }

    fw->mapping.device = tmp;

    switch (fw->mapping.device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        if (qemuFirmwareMappingFlashParse(path, mapping, &fw->mapping.data.flash) < 0)
            return -1;
        break;
    case QEMU_FIRMWARE_DEVICE_KERNEL:
        if (qemuFirmwareMappingKernelParse(path, mapping, &fw->mapping.data.kernel) < 0)
            return -1;
        break;
    case QEMU_FIRMWARE_DEVICE_MEMORY:
        if (qemuFirmwareMappingMemoryParse(path, mapping, &fw->mapping.data.memory) < 0)
            return -1;
        break;

    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        break;
    }

    return 0;
}


static int
qemuFirmwareTargetParse(const char *path,
                        virJSONValue *doc,
                        qemuFirmware *fw)
{
    virJSONValue *targetsJSON;
    qemuFirmwareTarget **targets = NULL;
    size_t ntargets;
    size_t i;
    int ret = -1;

    if (!(targetsJSON = virJSONValueObjectGetArray(doc, "targets"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get targets from '%s'"),
                       path);
        return -1;
    }

    ntargets = virJSONValueArraySize(targetsJSON);

    targets = g_new0(qemuFirmwareTarget *, ntargets);

    for (i = 0; i < ntargets; i++) {
        virJSONValue *item = virJSONValueArrayGet(targetsJSON, i);
        virJSONValue *machines;
        g_autoptr(qemuFirmwareTarget) t = NULL;
        const char *architectureStr = NULL;
        size_t nmachines;
        size_t j;

        t = g_new0(qemuFirmwareTarget, 1);

        if (!(architectureStr = virJSONValueObjectGetString(item, "architecture"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing 'architecture' in '%s'"),
                           path);
            goto cleanup;
        }

        if ((t->architecture = virQEMUCapsArchFromString(architectureStr)) == VIR_ARCH_NONE) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown architecture '%s'"),
                           architectureStr);
            goto cleanup;
        }

        if (!(machines = virJSONValueObjectGetArray(item, "machines"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing 'machines' in '%s'"),
                           path);
            goto cleanup;
        }

        nmachines = virJSONValueArraySize(machines);

        t->machines = g_new0(char *, nmachines + 1);

        for (j = 0; j < nmachines; j++) {
            virJSONValue *machine = virJSONValueArrayGet(machines, j);
            g_autofree char *machineStr = NULL;

            machineStr = g_strdup(virJSONValueGetString(machine));

            VIR_APPEND_ELEMENT_INPLACE(t->machines, t->nmachines, machineStr);
        }

        targets[i] = g_steal_pointer(&t);
    }

    fw->targets = g_steal_pointer(&targets);
    fw->ntargets = ntargets;
    ntargets = 0;
    ret = 0;

 cleanup:
    for (i = 0; i < ntargets; i++)
        qemuFirmwareTargetFree(targets[i]);
    VIR_FREE(targets);
    return ret;
}


static int
qemuFirmwareFeatureParse(const char *path,
                         virJSONValue *doc,
                         qemuFirmware *fw)
{
    virJSONValue *featuresJSON;
    g_autoptr(qemuFirmwareFeature) features = NULL;
    size_t nfeatures;
    size_t nparsed = 0;
    size_t i;

    if (!(featuresJSON = virJSONValueObjectGetArray(doc, "features"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get features from '%s'"),
                       path);
        return -1;
    }

    nfeatures = virJSONValueArraySize(featuresJSON);

    features = g_new0(qemuFirmwareFeature, nfeatures);

    for (i = 0; i < nfeatures; i++) {
        virJSONValue *item = virJSONValueArrayGet(featuresJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuFirmwareFeatureTypeFromString(tmpStr)) <= 0) {
            VIR_DEBUG("ignoring unknown QEMU firmware feature '%s'", tmpStr);
            continue;
        }

        features[nparsed] = tmp;
        nparsed++;
    }

    fw->features = g_steal_pointer(&features);
    fw->nfeatures = nparsed;
    return 0;
}


/* 1MiB should be enough for everybody (TM) */
#define DOCUMENT_SIZE (1024 * 1024)

qemuFirmware *
qemuFirmwareParse(const char *path)
{
    g_autofree char *cont = NULL;
    g_autoptr(virJSONValue) doc = NULL;
    g_autoptr(qemuFirmware) fw = NULL;

    if (virFileReadAll(path, DOCUMENT_SIZE, &cont) < 0)
        return NULL;

    if (!(doc = virJSONValueFromString(cont))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse json file '%s'"),
                       path);
        return NULL;
    }

    fw = g_new0(qemuFirmware, 1);

    if (qemuFirmwareInterfaceParse(path, doc, fw) < 0)
        return NULL;

    if (qemuFirmwareMappingParse(path, doc, fw) < 0)
        return NULL;

    if (qemuFirmwareTargetParse(path, doc, fw) < 0)
        return NULL;

    if (qemuFirmwareFeatureParse(path, doc, fw) < 0)
        return NULL;

    return g_steal_pointer(&fw);
}


static int
qemuFirmwareInterfaceFormat(virJSONValue *doc,
                            qemuFirmware *fw)
{
    g_autoptr(virJSONValue) interfacesJSON = NULL;
    size_t i;

    interfacesJSON = virJSONValueNewArray();

    for (i = 0; i < fw->ninterfaces; i++) {
        if (virJSONValueArrayAppendString(interfacesJSON,
                                          qemuFirmwareOSInterfaceTypeToString(fw->interfaces[i])) < 0)
            return -1;
    }

    if (virJSONValueObjectAppend(doc,
                                 "interface-types",
                                 &interfacesJSON) < 0)
        return -1;

    return 0;
}


static virJSONValue *
qemuFirmwareFlashFileFormat(qemuFirmwareFlashFile flash)
{
    g_autoptr(virJSONValue) json = virJSONValueNewObject();
    virJSONValue *ret;

    if (virJSONValueObjectAppendString(json,
                                       "filename",
                                       flash.filename) < 0)
        return NULL;

    if (virJSONValueObjectAppendString(json,
                                       "format",
                                       flash.format) < 0)
        return NULL;

    ret = g_steal_pointer(&json);
    return ret;
}


static int
qemuFirmwareMappingFlashFormat(virJSONValue *mapping,
                               qemuFirmwareMappingFlash *flash)
{
    g_autoptr(virJSONValue) executable = NULL;
    g_autoptr(virJSONValue) nvram_template = NULL;

    if (!(executable = qemuFirmwareFlashFileFormat(flash->executable)))
        return -1;

    if (!(nvram_template = qemuFirmwareFlashFileFormat(flash->nvram_template)))
        return -1;

    if (virJSONValueObjectAppend(mapping,
                                 "executable",
                                 &executable) < 0)
        return -1;


    if (virJSONValueObjectAppend(mapping,
                                 "nvram-template",
                                 &nvram_template) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingKernelFormat(virJSONValue *mapping,
                                qemuFirmwareMappingKernel *kernel)
{
    if (virJSONValueObjectAppendString(mapping,
                                       "filename",
                                       kernel->filename) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingMemoryFormat(virJSONValue *mapping,
                                qemuFirmwareMappingMemory *memory)
{
    if (virJSONValueObjectAppendString(mapping,
                                       "filename",
                                       memory->filename) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingFormat(virJSONValue *doc,
                          qemuFirmware *fw)
{
    g_autoptr(virJSONValue) mapping = virJSONValueNewObject();

    if (virJSONValueObjectAppendString(mapping,
                                       "device",
                                       qemuFirmwareDeviceTypeToString(fw->mapping.device)) < 0)
        return -1;

    switch (fw->mapping.device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        if (qemuFirmwareMappingFlashFormat(mapping, &fw->mapping.data.flash) < 0)
            return -1;
        break;
    case QEMU_FIRMWARE_DEVICE_KERNEL:
        if (qemuFirmwareMappingKernelFormat(mapping, &fw->mapping.data.kernel) < 0)
            return -1;
        break;
    case QEMU_FIRMWARE_DEVICE_MEMORY:
        if (qemuFirmwareMappingMemoryFormat(mapping, &fw->mapping.data.memory) < 0)
            return -1;
        break;

    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        break;
    }

    if (virJSONValueObjectAppend(doc, "mapping", &mapping) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareTargetFormat(virJSONValue *doc,
                         qemuFirmware *fw)
{
    g_autoptr(virJSONValue) targetsJSON = NULL;
    size_t i;

    targetsJSON = virJSONValueNewArray();

    for (i = 0; i < fw->ntargets; i++) {
        qemuFirmwareTarget *t = fw->targets[i];
        g_autoptr(virJSONValue) target = virJSONValueNewObject();
        g_autoptr(virJSONValue) machines = NULL;
        size_t j;

        if (virJSONValueObjectAppendString(target,
                                           "architecture",
                                           virQEMUCapsArchToString(t->architecture)) < 0)
            return -1;

        machines = virJSONValueNewArray();

        for (j = 0; j < t->nmachines; j++) {
            if (virJSONValueArrayAppendString(machines,
                                              t->machines[j]) < 0)
                return -1;
        }

        if (virJSONValueObjectAppend(target, "machines", &machines) < 0)
            return -1;

        if (virJSONValueArrayAppend(targetsJSON, &target) < 0)
            return -1;
    }

    if (virJSONValueObjectAppend(doc, "targets", &targetsJSON) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareFeatureFormat(virJSONValue *doc,
                          qemuFirmware *fw)
{
    g_autoptr(virJSONValue) featuresJSON = NULL;
    size_t i;

    featuresJSON = virJSONValueNewArray();

    for (i = 0; i < fw->nfeatures; i++) {
        if (virJSONValueArrayAppendString(featuresJSON,
                                          qemuFirmwareFeatureTypeToString(fw->features[i])) < 0)
            return -1;
    }

    if (virJSONValueObjectAppend(doc,
                                 "features",
                                 &featuresJSON) < 0)
        return -1;

    return 0;
}


char *
qemuFirmwareFormat(qemuFirmware *fw)
{
    g_autoptr(virJSONValue) doc = virJSONValueNewObject();

    if (!fw)
        return NULL;

    if (qemuFirmwareInterfaceFormat(doc, fw) < 0)
        return NULL;

    if (qemuFirmwareMappingFormat(doc, fw) < 0)
        return NULL;

    if (qemuFirmwareTargetFormat(doc, fw) < 0)
        return NULL;

    if (qemuFirmwareFeatureFormat(doc, fw) < 0)
        return NULL;

    return virJSONValueToString(doc, true);
}


int
qemuFirmwareFetchConfigs(char ***firmwares,
                         bool privileged)
{
    return qemuInteropFetchConfigs("firmware", firmwares, privileged);
}


static bool
qemuFirmwareMatchesMachineArch(const qemuFirmware *fw,
                               const char *machine,
                               virArch arch)
{
    size_t i;

    for (i = 0; i < fw->ntargets; i++) {
        size_t j;

        if (arch != fw->targets[i]->architecture)
            continue;

        for (j = 0; j < fw->targets[i]->nmachines; j++) {
            if (g_pattern_match_simple(fw->targets[i]->machines[j], machine))
                return true;
        }
    }

    return false;
}


static qemuFirmwareOSInterface
qemuFirmwareOSInterfaceTypeFromOsDefFirmware(int fw)
{
    switch (fw) {
    case VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS:
        return QEMU_FIRMWARE_OS_INTERFACE_BIOS;
    case VIR_DOMAIN_OS_DEF_FIRMWARE_EFI:
        return QEMU_FIRMWARE_OS_INTERFACE_UEFI;
    case VIR_DOMAIN_OS_DEF_FIRMWARE_NONE:
    case VIR_DOMAIN_OS_DEF_FIRMWARE_LAST:
        break;
    }

    return QEMU_FIRMWARE_OS_INTERFACE_NONE;
}


#define VIR_QEMU_FIRMWARE_AMD_SEV_ES_POLICY (1 << 2)


static bool
qemuFirmwareMatchDomain(const virDomainDef *def,
                        const qemuFirmware *fw,
                        const char *path)
{
    size_t i;
    qemuFirmwareOSInterface want;
    bool supportsS3 = false;
    bool supportsS4 = false;
    bool requiresSMM = false;
    bool supportsSEV = false;
    bool supportsSEVES = false;
    bool supportsSecureBoot = false;
    bool hasEnrolledKeys = false;
    int reqSecureBoot;
    int reqEnrolledKeys;

    want = qemuFirmwareOSInterfaceTypeFromOsDefFirmware(def->os.firmware);

    if (want == QEMU_FIRMWARE_OS_INTERFACE_NONE &&
        def->os.loader) {
        want = qemuFirmwareOSInterfaceTypeFromOsDefFirmware(def->os.loader->type);

        if (fw->mapping.device != QEMU_FIRMWARE_DEVICE_FLASH ||
            STRNEQ(def->os.loader->path, fw->mapping.data.flash.executable.filename)) {
            VIR_DEBUG("Not matching FW interface %s or loader "
                      "path '%s' for user provided path '%s'",
                      qemuFirmwareDeviceTypeToString(fw->mapping.device),
                      fw->mapping.data.flash.executable.filename,
                      def->os.loader->path);
            return false;
        }
    }

    for (i = 0; i < fw->ninterfaces; i++) {
        if (fw->interfaces[i] == want)
            break;
    }

    if (i == fw->ninterfaces) {
        VIR_DEBUG("No matching interface in '%s'", path);
        return false;
    }

    if (!qemuFirmwareMatchesMachineArch(fw, def->os.machine, def->os.arch)) {
        VIR_DEBUG("No matching machine type in '%s'", path);
        return false;
    }

    for (i = 0; i < fw->nfeatures; i++) {
        switch (fw->features[i]) {
        case QEMU_FIRMWARE_FEATURE_ACPI_S3:
            supportsS3 = true;
            break;
        case QEMU_FIRMWARE_FEATURE_ACPI_S4:
            supportsS4 = true;
            break;
        case QEMU_FIRMWARE_FEATURE_AMD_SEV:
            supportsSEV = true;
            break;

        case QEMU_FIRMWARE_FEATURE_AMD_SEV_ES:
            supportsSEVES = true;
            break;

        case QEMU_FIRMWARE_FEATURE_REQUIRES_SMM:
            requiresSMM = true;
            break;

        case QEMU_FIRMWARE_FEATURE_SECURE_BOOT:
            supportsSecureBoot = true;
            break;

        case QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS:
            hasEnrolledKeys = true;
            break;

        case QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC:
        case QEMU_FIRMWARE_FEATURE_NONE:
        case QEMU_FIRMWARE_FEATURE_LAST:
            break;
        }
    }

    if (def->pm.s3 == VIR_TRISTATE_BOOL_YES &&
        !supportsS3) {
        VIR_DEBUG("Domain requires S3, firmware '%s' doesn't support it", path);
        return false;
    }

    if (def->pm.s4 == VIR_TRISTATE_BOOL_YES &&
        !supportsS4) {
        VIR_DEBUG("Domain requires S4, firmware '%s' doesn't support it", path);
        return false;
    }

    if (def->os.firmwareFeatures) {
        reqSecureBoot = def->os.firmwareFeatures[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_SECURE_BOOT];
        if (reqSecureBoot != VIR_TRISTATE_BOOL_ABSENT) {
            if (reqSecureBoot == VIR_TRISTATE_BOOL_YES && !supportsSecureBoot) {
                VIR_DEBUG("User requested Secure Boot, firmware '%s' doesn't support it",
                          path);
                return false;
            }

            if (reqSecureBoot == VIR_TRISTATE_BOOL_NO && supportsSecureBoot) {
                VIR_DEBUG("User refused Secure Boot, firmware '%s' supports it", path);
                return false;
            }
        }

        reqEnrolledKeys = def->os.firmwareFeatures[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_ENROLLED_KEYS];
        if (reqEnrolledKeys != VIR_TRISTATE_BOOL_ABSENT) {
            if (reqEnrolledKeys == VIR_TRISTATE_BOOL_YES && !hasEnrolledKeys) {
                VIR_DEBUG("User requested Enrolled keys, firmware '%s' doesn't have them",
                          path);
                return false;
            }

            if (reqEnrolledKeys == VIR_TRISTATE_BOOL_NO && hasEnrolledKeys) {
                VIR_DEBUG("User refused Enrolled keys, firmware '%s' has them", path);
                return false;
            }
        }
    }

    if (def->os.loader &&
        def->os.loader->secure == VIR_TRISTATE_BOOL_YES &&
        !requiresSMM) {
        VIR_DEBUG("Domain restricts pflash programming to SMM, "
                  "but firmware '%s' doesn't support SMM", path);
        return false;
    }

    if (def->sec) {
        switch ((virDomainLaunchSecurity) def->sec->sectype) {
        case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
            if (!supportsSEV) {
                VIR_DEBUG("Domain requires SEV, firmware '%s' doesn't support it",
                          path);
                return false;
            }

            if (def->sec->data.sev.policy & VIR_QEMU_FIRMWARE_AMD_SEV_ES_POLICY &&
                !supportsSEVES) {
                VIR_DEBUG("Domain requires SEV-ES, firmware '%s' doesn't support it",
                          path);
                return false;
            }
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_PV:
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
        case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
            virReportEnumRangeError(virDomainLaunchSecurity, def->sec->sectype);
            return -1;
        }
    }

    VIR_DEBUG("Firmware '%s' matches domain requirements", path);
    return true;
}


static int
qemuFirmwareEnableFeatures(virQEMUDriver *driver,
                           virDomainDef *def,
                           const qemuFirmware *fw)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const qemuFirmwareMappingFlash *flash = &fw->mapping.data.flash;
    const qemuFirmwareMappingKernel *kernel = &fw->mapping.data.kernel;
    const qemuFirmwareMappingMemory *memory = &fw->mapping.data.memory;
    size_t i;

    switch (fw->mapping.device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        if (!def->os.loader)
            def->os.loader = g_new0(virDomainLoaderDef, 1);

        def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
        def->os.loader->readonly = VIR_TRISTATE_BOOL_YES;

        if (STRNEQ(flash->executable.format, "raw")) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("unsupported flash format '%s'"),
                           flash->executable.format);
            return -1;
        }

        VIR_FREE(def->os.loader->path);
        def->os.loader->path = g_strdup(flash->executable.filename);

        if (STRNEQ(flash->nvram_template.format, "raw")) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("unsupported nvram template format '%s'"),
                           flash->nvram_template.format);
            return -1;
        }

        VIR_FREE(def->os.loader->templt);
        def->os.loader->templt = g_strdup(flash->nvram_template.filename);

        qemuDomainNVRAMPathGenerate(cfg, def);

        VIR_DEBUG("decided on firmware '%s' varstore template '%s'",
                  def->os.loader->path,
                  def->os.loader->templt);
        break;

    case QEMU_FIRMWARE_DEVICE_KERNEL:
        VIR_FREE(def->os.kernel);
        def->os.kernel = g_strdup(kernel->filename);

        VIR_DEBUG("decided on kernel '%s'",
                  def->os.kernel);
        break;

    case QEMU_FIRMWARE_DEVICE_MEMORY:
        if (!def->os.loader)
            def->os.loader = g_new0(virDomainLoaderDef, 1);

        def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_ROM;
        def->os.loader->path = g_strdup(memory->filename);

        VIR_DEBUG("decided on loader '%s'",
                  def->os.loader->path);
        break;

    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        break;
    }

    for (i = 0; i < fw->nfeatures; i++) {
        switch (fw->features[i]) {
        case QEMU_FIRMWARE_FEATURE_REQUIRES_SMM:
            switch (def->features[VIR_DOMAIN_FEATURE_SMM]) {
            case VIR_TRISTATE_SWITCH_OFF:
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("domain has SMM turned off "
                                 "but chosen firmware requires it"));
                return -1;
            case VIR_TRISTATE_SWITCH_ABSENT:
                VIR_DEBUG("Enabling SMM feature");
                def->features[VIR_DOMAIN_FEATURE_SMM] = VIR_TRISTATE_SWITCH_ON;
                break;

            case VIR_TRISTATE_SWITCH_ON:
            case VIR_TRISTATE_SWITCH_LAST:
                break;
            }
            break;

        case QEMU_FIRMWARE_FEATURE_NONE:
        case QEMU_FIRMWARE_FEATURE_ACPI_S3:
        case QEMU_FIRMWARE_FEATURE_ACPI_S4:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV_ES:
        case QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS:
        case QEMU_FIRMWARE_FEATURE_SECURE_BOOT:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC:
        case QEMU_FIRMWARE_FEATURE_LAST:
            break;
        }
    }

    return 0;
}


static void
qemuFirmwareSanityCheck(const qemuFirmware *fw,
                        const char *filename)
{
    size_t i;
    bool requiresSMM = false;
    bool supportsSecureBoot = false;

    for (i = 0; i < fw->nfeatures; i++) {
        switch (fw->features[i]) {
        case QEMU_FIRMWARE_FEATURE_REQUIRES_SMM:
            requiresSMM = true;
            break;
        case QEMU_FIRMWARE_FEATURE_SECURE_BOOT:
            supportsSecureBoot = true;
            break;
        case QEMU_FIRMWARE_FEATURE_NONE:
        case QEMU_FIRMWARE_FEATURE_ACPI_S3:
        case QEMU_FIRMWARE_FEATURE_ACPI_S4:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV_ES:
        case QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC:
        case QEMU_FIRMWARE_FEATURE_LAST:
            break;
        }
    }

    if (supportsSecureBoot != requiresSMM) {
        VIR_WARN("Firmware description '%s' has invalid set of features: "
                 "%s = %d, %s = %d",
                 filename,
                 qemuFirmwareFeatureTypeToString(QEMU_FIRMWARE_FEATURE_REQUIRES_SMM),
                 requiresSMM,
                 qemuFirmwareFeatureTypeToString(QEMU_FIRMWARE_FEATURE_SECURE_BOOT),
                 supportsSecureBoot);
    }
}


static ssize_t
qemuFirmwareFetchParsedConfigs(bool privileged,
                               qemuFirmware ***firmwaresRet,
                               char ***pathsRet)
{
    g_auto(GStrv) paths = NULL;
    size_t npaths;
    qemuFirmware **firmwares = NULL;
    size_t i;

    if (qemuFirmwareFetchConfigs(&paths, privileged) < 0)
        return -1;

    if (!paths)
        return 0;

    npaths = g_strv_length(paths);

    firmwares = g_new0(qemuFirmware *, npaths);

    for (i = 0; i < npaths; i++) {
        if (!(firmwares[i] = qemuFirmwareParse(paths[i])))
            goto error;
    }

    *firmwaresRet = g_steal_pointer(&firmwares);
    if (pathsRet)
        *pathsRet = g_steal_pointer(&paths);
    return npaths;

 error:
    while (i > 0)
        qemuFirmwareFree(firmwares[--i]);
    VIR_FREE(firmwares);
    return -1;
}


int
qemuFirmwareFillDomain(virQEMUDriver *driver,
                       virDomainDef *def,
                       unsigned int flags)
{
    g_auto(GStrv) paths = NULL;
    qemuFirmware **firmwares = NULL;
    ssize_t nfirmwares = 0;
    const qemuFirmware *theone = NULL;
    bool needResult = true;
    size_t i;
    int ret = -1;

    /* Fill in FW paths if either os.firmware is enabled, or
     * loader path was provided with no nvram varstore. */
    if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_NONE) {
        /* This is horrific check, but loosely said, if UEFI
         * image was provided by the old method (by specifying
         * its path in domain XML) but no template for NVRAM was
         * specified and the varstore doesn't exist ... */
        if (!virDomainDefHasOldStyleROUEFI(def) ||
            def->os.loader->templt ||
            virFileExists(def->os.loader->nvram))
            return 0;

        /* ... then we want to consult JSON FW descriptors first,
         * but we don't want to fail if we haven't found a match. */
        needResult = false;
    } else {
        /* Domain has FW autoselection enabled => do nothing if
         * we are not starting it from scratch. */
        if (!(flags & VIR_QEMU_PROCESS_START_NEW))
            return 0;
    }

    if ((nfirmwares = qemuFirmwareFetchParsedConfigs(driver->privileged,
                                                     &firmwares, &paths)) < 0)
        return -1;

    for (i = 0; i < nfirmwares; i++) {
        if (qemuFirmwareMatchDomain(def, firmwares[i], paths[i])) {
            theone = firmwares[i];
            VIR_DEBUG("Found matching firmware (description path '%s')",
                      paths[i]);
            break;
        }
    }

    if (!theone) {
        if (needResult) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Unable to find any firmware to satisfy '%s'"),
                           virDomainOsDefFirmwareTypeToString(def->os.firmware));
        } else {
            VIR_DEBUG("Unable to find NVRAM template for '%s', "
                      "falling back to old style",
                      NULLSTR(def->os.loader ? def->os.loader->path : NULL));
            ret = 0;
        }
        goto cleanup;
    }

    /* Firstly, let's do some sanity checks. If either of these
     * fail we can still start the domain successfully, but it's
     * likely that admin/FW manufacturer messed up. */
    qemuFirmwareSanityCheck(theone, paths[i]);

    if (qemuFirmwareEnableFeatures(driver, def, theone) < 0)
        goto cleanup;

    def->os.firmware = VIR_DOMAIN_OS_DEF_FIRMWARE_NONE;

    ret = 0;
 cleanup:
    for (i = 0; i < nfirmwares; i++)
        qemuFirmwareFree(firmwares[i]);
    VIR_FREE(firmwares);
    return ret;
}


/**
 * qemuFirmwareGetSupported:
 * @machine: machine type
 * @arch: architecture
 * @privileged: whether running as privileged user
 * @supported: returned bitmap of supported interfaces
 * @secure: true if at least one secure boot enabled FW was found
 * @fws: (optional) list of found firmwares
 * @nfws: (optional) number of members in @fws
 *
 * Parse all FW descriptors (depending whether running as @privileged this may
 * or may not include user's $HOME) and for given combination of @machine and
 * @arch extract information to be later reported in domain capabilities.
 * The @supported contains a bitmap of found interfaces (and ORed values of 1
 * << VIR_DOMAIN_OS_DEF_FIRMWARE_*). Then, @supported is true if at least one
 * FW descriptor signalizes secure boot (although, this is checked against SMM
 * rather than SECURE_BOOT because reasons).
 *
 * If @fws and @nfws are not NULL, then @fws is allocated (must be freed by
 * caller when no longer needed) and contains list of firmwares found in form
 * of virFirmware. This can be useful if caller wants to know the paths to
 * firmware images (e.g. to present them in domain capabilities XML).
 * Moreover, to allow the caller distinguish between no FW descriptors found
 * and no matching FW descriptors found (nfws == 0 in both cases), the @fws is
 * going to be allocated in case of the latter anyway (with no real content
 * though).
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
qemuFirmwareGetSupported(const char *machine,
                         virArch arch,
                         bool privileged,
                         uint64_t *supported,
                         bool *secure,
                         virFirmware ***fws,
                         size_t *nfws)
{
    qemuFirmware **firmwares = NULL;
    ssize_t nfirmwares = 0;
    size_t i;

    *supported = VIR_DOMAIN_OS_DEF_FIRMWARE_NONE;
    *secure = false;

    if (fws) {
        *fws = NULL;
        *nfws = 0;
    }

    if ((nfirmwares = qemuFirmwareFetchParsedConfigs(privileged,
                                                     &firmwares, NULL)) < 0)
        return -1;

    for (i = 0; i < nfirmwares; i++) {
        qemuFirmware *fw = firmwares[i];
        const qemuFirmwareMappingFlash *flash = &fw->mapping.data.flash;
        const qemuFirmwareMappingMemory *memory = &fw->mapping.data.memory;
        const char *fwpath = NULL;
        const char *nvrampath = NULL;
        size_t j;

        if (!qemuFirmwareMatchesMachineArch(fw, machine, arch))
            continue;

        for (j = 0; j < fw->ninterfaces; j++) {
            switch (fw->interfaces[j]) {
            case QEMU_FIRMWARE_OS_INTERFACE_UEFI:
                *supported |= 1ULL << VIR_DOMAIN_OS_DEF_FIRMWARE_EFI;
                break;
            case QEMU_FIRMWARE_OS_INTERFACE_BIOS:
                *supported |= 1ULL << VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS;
                break;
            case QEMU_FIRMWARE_OS_INTERFACE_NONE:
            case QEMU_FIRMWARE_OS_INTERFACE_OPENFIRMWARE:
            case QEMU_FIRMWARE_OS_INTERFACE_UBOOT:
            case QEMU_FIRMWARE_OS_INTERFACE_LAST:
            default:
                break;
            }
        }

        for (j = 0; j < fw->nfeatures; j++) {
            switch (fw->features[j]) {
            case QEMU_FIRMWARE_FEATURE_REQUIRES_SMM:
                *secure = true;
                break;
            case QEMU_FIRMWARE_FEATURE_NONE:
            case QEMU_FIRMWARE_FEATURE_ACPI_S3:
            case QEMU_FIRMWARE_FEATURE_ACPI_S4:
            case QEMU_FIRMWARE_FEATURE_AMD_SEV:
            case QEMU_FIRMWARE_FEATURE_AMD_SEV_ES:
            case QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS:
            case QEMU_FIRMWARE_FEATURE_SECURE_BOOT:
            case QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC:
            case QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC:
            case QEMU_FIRMWARE_FEATURE_LAST:
                break;
            }
        }

        switch (fw->mapping.device) {
        case QEMU_FIRMWARE_DEVICE_FLASH:
            fwpath = flash->executable.filename;
            nvrampath = flash->nvram_template.filename;
            break;

        case QEMU_FIRMWARE_DEVICE_MEMORY:
            fwpath = memory->filename;
            break;

        case QEMU_FIRMWARE_DEVICE_KERNEL:
        case QEMU_FIRMWARE_DEVICE_NONE:
        case QEMU_FIRMWARE_DEVICE_LAST:
            break;
        }

        if (fws && fwpath) {
            g_autoptr(virFirmware) tmp = NULL;

            /* Append only unique pairs. */
            for (j = 0; j < *nfws; j++) {
                if (STREQ((*fws)[j]->name, fwpath) &&
                    STREQ_NULLABLE((*fws)[j]->nvram, nvrampath))
                    break;
            }

            if (j == *nfws) {
                tmp = g_new0(virFirmware, 1);

                tmp->name = g_strdup(fwpath);
                tmp->nvram = g_strdup(nvrampath);
                VIR_APPEND_ELEMENT(*fws, *nfws, tmp);
            }
        }
    }

    if (fws && !*fws && nfirmwares)
        VIR_REALLOC_N(*fws, 0);

    for (i = 0; i < nfirmwares; i++)
        qemuFirmwareFree(firmwares[i]);
    VIR_FREE(firmwares);
    return 0;
}
