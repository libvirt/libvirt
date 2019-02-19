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
#include "qemu_capabilities.h"
#include "virarch.h"
#include "virfile.h"
#include "virjson.h"
#include "virlog.h"
#include "virstring.h"

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
typedef qemuFirmwareFlashFile *qemuFirmwareFlashFilePtr;
struct _qemuFirmwareFlashFile {
    char *filename;
    char *format;
};


typedef struct _qemuFirmwareMappingFlash qemuFirmwareMappingFlash;
typedef qemuFirmwareMappingFlash *qemuFirmwareMappingFlashPtr;
struct _qemuFirmwareMappingFlash {
    qemuFirmwareFlashFile executable;
    qemuFirmwareFlashFile nvram_template;
};


typedef struct _qemuFirmwareMappingKernel qemuFirmwareMappingKernel;
typedef qemuFirmwareMappingKernel *qemuFirmwareMappingKernelPtr;
struct _qemuFirmwareMappingKernel {
    char *filename;
};


typedef struct _qemuFirmwareMappingMemory qemuFirmwareMappingMemory;
typedef qemuFirmwareMappingMemory *qemuFirmwareMappingMemoryPtr;
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
typedef qemuFirmwareMapping *qemuFirmwareMappingPtr;
struct _qemuFirmwareMapping {
    qemuFirmwareDevice device;

    union {
        qemuFirmwareMappingFlash flash;
        qemuFirmwareMappingKernel kernel;
        qemuFirmwareMappingMemory memory;
    } data;
};


typedef struct _qemuFirmwareTarget qemuFirmwareTarget;
typedef qemuFirmwareTarget *qemuFirmwareTargetPtr;
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
    qemuFirmwareTargetPtr *targets;

    size_t nfeatures;
    qemuFirmwareFeature *features;

    /* Tags intentionally not parsed. */
};


static void
qemuFirmwareOSInterfaceFree(qemuFirmwareOSInterface *interfaces)
{
    VIR_FREE(interfaces);
}


VIR_DEFINE_AUTOPTR_FUNC(qemuFirmwareOSInterface, qemuFirmwareOSInterfaceFree);


static void
qemuFirmwareFlashFileFree(qemuFirmwareFlashFile flash)
{
    VIR_FREE(flash.filename);
    VIR_FREE(flash.format);
}


static void
qemuFirmwareMappingFlashFree(qemuFirmwareMappingFlash flash)
{
    qemuFirmwareFlashFileFree(flash.executable);
    qemuFirmwareFlashFileFree(flash.nvram_template);
}


static void
qemuFirmwareMappingKernelFree(qemuFirmwareMappingKernel kernel)
{
    VIR_FREE(kernel.filename);
}


static void
qemuFirmwareMappingMemoryFree(qemuFirmwareMappingMemory memory)
{
    VIR_FREE(memory.filename);
}


static void
qemuFirmwareMappingFree(qemuFirmwareMapping mapping)
{
    switch (mapping.device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        qemuFirmwareMappingFlashFree(mapping.data.flash);
        break;
    case QEMU_FIRMWARE_DEVICE_KERNEL:
        qemuFirmwareMappingKernelFree(mapping.data.kernel);
        break;
    case QEMU_FIRMWARE_DEVICE_MEMORY:
        qemuFirmwareMappingMemoryFree(mapping.data.memory);
        break;
    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        break;
    }
}


static void
qemuFirmwareTargetFree(qemuFirmwareTargetPtr target)
{
    if (!target)
        return;

    virStringListFreeCount(target->machines, target->nmachines);

    VIR_FREE(target);
}


VIR_DEFINE_AUTOPTR_FUNC(qemuFirmwareTarget, qemuFirmwareTargetFree);


static void
qemuFirmwareFeatureFree(qemuFirmwareFeature *features)
{
    VIR_FREE(features);
}


VIR_DEFINE_AUTOPTR_FUNC(qemuFirmwareFeature, qemuFirmwareFeatureFree);


void
qemuFirmwareFree(qemuFirmwarePtr fw)
{
    size_t i;

    if (!fw)
        return;

    qemuFirmwareOSInterfaceFree(fw->interfaces);
    qemuFirmwareMappingFree(fw->mapping);
    for (i = 0; i < fw->ntargets; i++)
        qemuFirmwareTargetFree(fw->targets[i]);
    VIR_FREE(fw->targets);
    qemuFirmwareFeatureFree(fw->features);

    VIR_FREE(fw);
}


static int
qemuFirmwareInterfaceParse(const char *path,
                           virJSONValuePtr doc,
                           qemuFirmwarePtr fw)
{
    virJSONValuePtr interfacesJSON;
    VIR_AUTOPTR(qemuFirmwareOSInterface) interfaces = NULL;
    VIR_AUTOCLEAN(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t ninterfaces;
    size_t i;

    if (!(interfacesJSON = virJSONValueObjectGetArray(doc, "interface-types"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get interface-types from '%s'"),
                       path);
        return -1;
    }

    ninterfaces = virJSONValueArraySize(interfacesJSON);

    if (VIR_ALLOC_N(interfaces, ninterfaces) < 0)
        return -1;

    for (i = 0; i < ninterfaces; i++) {
        virJSONValuePtr item = virJSONValueArrayGet(interfacesJSON, i);
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

    VIR_STEAL_PTR(fw->interfaces, interfaces);
    fw->ninterfaces = ninterfaces;
    return 0;
}


static int
qemuFirmwareFlashFileParse(const char *path,
                           virJSONValuePtr doc,
                           qemuFirmwareFlashFilePtr flash)
{
    const char *filename;
    const char *format;

    if (!(filename = virJSONValueObjectGetString(doc, "filename"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'filename' in '%s'"),
                       path);
        return -1;
    }

    if (VIR_STRDUP(flash->filename, filename) < 0)
        return -1;

    if (!(format = virJSONValueObjectGetString(doc, "format"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'format' in '%s'"),
                       path);
        return -1;
    }

    if (VIR_STRDUP(flash->format, format) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingFlashParse(const char *path,
                              virJSONValuePtr doc,
                              qemuFirmwareMappingFlashPtr flash)
{
    virJSONValuePtr executable;
    virJSONValuePtr nvram_template;

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
                               virJSONValuePtr doc,
                               qemuFirmwareMappingKernelPtr kernel)
{
    const char *filename;

    if (!(filename = virJSONValueObjectGetString(doc, "filename"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'filename' in '%s'"),
                       path);
    }

    if (VIR_STRDUP(kernel->filename, filename) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingMemoryParse(const char *path,
                               virJSONValuePtr doc,
                               qemuFirmwareMappingMemoryPtr memory)
{
    const char *filename;

    if (!(filename = virJSONValueObjectGetString(doc, "filename"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'filename' in '%s'"),
                       path);
    }

    if (VIR_STRDUP(memory->filename, filename) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingParse(const char *path,
                         virJSONValuePtr doc,
                         qemuFirmwarePtr fw)
{
    virJSONValuePtr mapping = virJSONValueObjectGet(doc, "mapping");
    const char *deviceStr;
    int tmp;

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
                        virJSONValuePtr doc,
                        qemuFirmwarePtr fw)
{
    virJSONValuePtr targetsJSON;
    qemuFirmwareTargetPtr *targets = NULL;
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

    if (VIR_ALLOC_N(targets, ntargets) < 0)
        return -1;

    for (i = 0; i < ntargets; i++) {
        virJSONValuePtr item = virJSONValueArrayGet(targetsJSON, i);
        virJSONValuePtr machines;
        VIR_AUTOPTR(qemuFirmwareTarget) t = NULL;
        const char *architectureStr = NULL;
        size_t nmachines;
        size_t j;

        if (VIR_ALLOC(t) < 0)
            goto cleanup;

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

        if (VIR_ALLOC_N(t->machines, nmachines) < 0)
            goto cleanup;

        for (j = 0; j < nmachines; j++) {
            virJSONValuePtr machine = virJSONValueArrayGet(machines, j);
            VIR_AUTOFREE(char *) machineStr = NULL;

            if (VIR_STRDUP(machineStr, virJSONValueGetString(machine)) < 0)
                goto cleanup;

            VIR_APPEND_ELEMENT_INPLACE(t->machines, t->nmachines, machineStr);
        }

        VIR_STEAL_PTR(targets[i], t);
    }

    VIR_STEAL_PTR(fw->targets, targets);
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
                         virJSONValuePtr doc,
                         qemuFirmwarePtr fw)
{
    virJSONValuePtr featuresJSON;
    VIR_AUTOPTR(qemuFirmwareFeature) features = NULL;
    size_t nfeatures;
    size_t i;

    if (!(featuresJSON = virJSONValueObjectGetArray(doc, "features"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get features from '%s'"),
                       path);
        return -1;
    }

    nfeatures = virJSONValueArraySize(featuresJSON);

    if (VIR_ALLOC_N(features, nfeatures) < 0)
        return -1;

    fw->nfeatures = nfeatures;

    for (i = 0; i < nfeatures; i++) {
        virJSONValuePtr item = virJSONValueArrayGet(featuresJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuFirmwareFeatureTypeFromString(tmpStr)) <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown feature %s"),
                           tmpStr);
            return -1;
        }

        features[i] = tmp;
    }

    VIR_STEAL_PTR(fw->features, features);
    fw->nfeatures = nfeatures;
    return 0;
}


/* 1MiB should be enough for everybody (TM) */
#define DOCUMENT_SIZE (1024 * 1024)

qemuFirmwarePtr
qemuFirmwareParse(const char *path)
{
    VIR_AUTOFREE(char *) cont = NULL;
    VIR_AUTOPTR(virJSONValue) doc = NULL;
    VIR_AUTOPTR(qemuFirmware) fw = NULL;
    qemuFirmwarePtr ret = NULL;

    if (virFileReadAll(path, DOCUMENT_SIZE, &cont) < 0)
        return NULL;

    if (!(doc = virJSONValueFromString(cont))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse json file '%s'"),
                       path);
        return NULL;
    }

    if (VIR_ALLOC(fw) < 0)
        return NULL;

    if (qemuFirmwareInterfaceParse(path, doc, fw) < 0)
        return NULL;

    if (qemuFirmwareMappingParse(path, doc, fw) < 0)
        return NULL;

    if (qemuFirmwareTargetParse(path, doc, fw) < 0)
        return NULL;

    if (qemuFirmwareFeatureParse(path, doc, fw) < 0)
        return NULL;

    VIR_STEAL_PTR(ret, fw);
    return ret;
}


static int
qemuFirmwareInterfaceFormat(virJSONValuePtr doc,
                            qemuFirmwarePtr fw)
{
    VIR_AUTOPTR(virJSONValue) interfacesJSON = NULL;
    size_t i;

    if (!(interfacesJSON = virJSONValueNewArray()))
        return -1;

    for (i = 0; i < fw->ninterfaces; i++) {
        if (virJSONValueArrayAppendString(interfacesJSON,
                                          qemuFirmwareOSInterfaceTypeToString(fw->interfaces[i])) < 0)
            return -1;
    }

    if (virJSONValueObjectAppend(doc,
                                 "interface-types",
                                 interfacesJSON) < 0)
        return -1;

    interfacesJSON = NULL;
    return 0;
}


static virJSONValuePtr
qemuFirmwareFlashFileFormat(qemuFirmwareFlashFile flash)
{
    VIR_AUTOPTR(virJSONValue) json = NULL;
    virJSONValuePtr ret;

    if (!(json = virJSONValueNewObject()))
        return NULL;

    if (virJSONValueObjectAppendString(json,
                                       "filename",
                                       flash.filename) < 0)
        return NULL;

    if (virJSONValueObjectAppendString(json,
                                       "format",
                                       flash.format) < 0)
        return NULL;

    VIR_STEAL_PTR(ret, json);
    return ret;
}


static int
qemuFirmwareMappingFlashFormat(virJSONValuePtr mapping,
                               qemuFirmwareMappingFlashPtr flash)
{
    VIR_AUTOPTR(virJSONValue) executable = NULL;
    VIR_AUTOPTR(virJSONValue) nvram_template = NULL;

    if (!(executable = qemuFirmwareFlashFileFormat(flash->executable)))
        return -1;

    if (!(nvram_template = qemuFirmwareFlashFileFormat(flash->nvram_template)))
        return -1;

    if (virJSONValueObjectAppend(mapping,
                                 "executable",
                                 executable) < 0)
        return -1;

    executable = NULL;

    if (virJSONValueObjectAppend(mapping,
                                 "nvram-template",
                                 nvram_template) < 0)
        return -1;

    nvram_template = NULL;

    return 0;
}


static int
qemuFirmwareMappingKernelFormat(virJSONValuePtr mapping,
                                qemuFirmwareMappingKernelPtr kernel)
{
    if (virJSONValueObjectAppendString(mapping,
                                       "filename",
                                       kernel->filename) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingMemoryFormat(virJSONValuePtr mapping,
                                qemuFirmwareMappingMemoryPtr memory)
{
    if (virJSONValueObjectAppendString(mapping,
                                       "filename",
                                       memory->filename) < 0)
        return -1;

    return 0;
}


static int
qemuFirmwareMappingFormat(virJSONValuePtr doc,
                          qemuFirmwarePtr fw)
{
    VIR_AUTOPTR(virJSONValue) mapping = NULL;

    if (!(mapping = virJSONValueNewObject()))
        return -1;

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

    if (virJSONValueObjectAppend(doc, "mapping", mapping) < 0)
        return -1;

    mapping = NULL;
    return 0;
}


static int
qemuFirmwareTargetFormat(virJSONValuePtr doc,
                         qemuFirmwarePtr fw)
{
    VIR_AUTOPTR(virJSONValue) targetsJSON = NULL;
    size_t i;

    if (!(targetsJSON = virJSONValueNewArray()))
        return -1;

    for (i = 0; i < fw->ntargets; i++) {
        qemuFirmwareTargetPtr t = fw->targets[i];
        VIR_AUTOPTR(virJSONValue) target = NULL;
        VIR_AUTOPTR(virJSONValue) machines = NULL;
        size_t j;

        if (!(target = virJSONValueNewObject()))
            return -1;

        if (virJSONValueObjectAppendString(target,
                                           "architecture",
                                           virQEMUCapsArchToString(t->architecture)) < 0)
            return -1;

        if (!(machines = virJSONValueNewArray()))
            return -1;

        for (j = 0; j < t->nmachines; j++) {
            if (virJSONValueArrayAppendString(machines,
                                              t->machines[j]) < 0)
                return -1;
        }

        if (virJSONValueObjectAppend(target, "machines", machines) < 0)
            return -1;

        machines = NULL;

        if (virJSONValueArrayAppend(targetsJSON, target) < 0)
            return -1;

        target = NULL;
    }

    if (virJSONValueObjectAppend(doc, "targets", targetsJSON) < 0)
        return -1;

    targetsJSON = NULL;
    return 0;
}


static int
qemuFirmwareFeatureFormat(virJSONValuePtr doc,
                          qemuFirmwarePtr fw)
{
    VIR_AUTOPTR(virJSONValue) featuresJSON = NULL;
    size_t i;

    if (!(featuresJSON = virJSONValueNewArray()))
        return -1;

    for (i = 0; i < fw->nfeatures; i++) {
        if (virJSONValueArrayAppendString(featuresJSON,
                                          qemuFirmwareFeatureTypeToString(fw->features[i])) < 0)
            return -1;
    }

    if (virJSONValueObjectAppend(doc,
                                 "features",
                                 featuresJSON) < 0)
        return -1;

    featuresJSON = NULL;
    return 0;
}


char *
qemuFirmwareFormat(qemuFirmwarePtr fw)
{
    VIR_AUTOPTR(virJSONValue) doc = NULL;

    if (!fw)
        return NULL;

    if (!(doc = virJSONValueNewObject()))
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
