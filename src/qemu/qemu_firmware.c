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
#include "domain_validate.h"
#include "virarch.h"
#include "virjson.h"
#include "virlog.h"
#include "viralloc.h"
#include "virenum.h"
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


typedef enum {
    QEMU_FIRMWARE_FLASH_MODE_SPLIT,
    QEMU_FIRMWARE_FLASH_MODE_COMBINED,
    QEMU_FIRMWARE_FLASH_MODE_STATELESS,

    QEMU_FIRMWARE_FLASH_MODE_LAST,
} qemuFirmwareFlashMode;

VIR_ENUM_DECL(qemuFirmwareFlashMode);
VIR_ENUM_IMPL(qemuFirmwareFlashMode,
              QEMU_FIRMWARE_FLASH_MODE_LAST,
              "split",
              "combined",
              "stateless",
);

typedef struct _qemuFirmwareFlashFile qemuFirmwareFlashFile;
struct _qemuFirmwareFlashFile {
    char *filename;
    char *format;
};


typedef struct _qemuFirmwareMappingFlash qemuFirmwareMappingFlash;
struct _qemuFirmwareMappingFlash {
    qemuFirmwareFlashMode mode;
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
                       _("failed to get interface-types from '%1$s'"),
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
                           _("unknown interface type: '%1$s'"),
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
                       _("missing 'filename' in '%1$s'"),
                       path);
        return -1;
    }

    flash->filename = g_strdup(filename);

    if (!(format = virJSONValueObjectGetString(doc, "format"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'format' in '%1$s'"),
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
    virJSONValue *mode;
    virJSONValue *executable;
    virJSONValue *nvram_template;

    if (!(mode = virJSONValueObjectGet(doc, "mode"))) {
        /* Historical default */
        flash->mode = QEMU_FIRMWARE_FLASH_MODE_SPLIT;
    } else {
        const char *modestr = virJSONValueGetString(mode);
        int modeval;
        if (!modestr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Firmware flash mode value was malformed"));
            return -1;
        }
        modeval = qemuFirmwareFlashModeTypeFromString(modestr);
        if (modeval < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Firmware flash mode value '%1$s' unexpected"),
                           modestr);
            return -1;
        }
        flash->mode = modeval;
    }

    if (!(executable = virJSONValueObjectGet(doc, "executable"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'executable' in '%1$s'"),
                       path);
        return -1;
    }

    if (qemuFirmwareFlashFileParse(path, executable, &flash->executable) < 0)
        return -1;

    if (flash->mode == QEMU_FIRMWARE_FLASH_MODE_SPLIT) {
        if (!(nvram_template = virJSONValueObjectGet(doc, "nvram-template"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing 'nvram-template' in '%1$s'"),
                           path);
            return -1;
        }

        if (qemuFirmwareFlashFileParse(path, nvram_template, &flash->nvram_template) < 0)
            return -1;
    }

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
                       _("missing 'filename' in '%1$s'"),
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
                       _("missing 'filename' in '%1$s'"),
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
                       _("missing mapping in '%1$s'"),
                       path);
        return -1;
    }

    if (!(deviceStr = virJSONValueObjectGetString(mapping, "device"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing device type in '%1$s'"),
                       path);
        return -1;
    }

    if ((tmp = qemuFirmwareDeviceTypeFromString(deviceStr)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown device type in '%1$s'"),
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
                       _("failed to get targets from '%1$s'"),
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
                           _("missing 'architecture' in '%1$s'"),
                           path);
            goto cleanup;
        }

        if ((t->architecture = virQEMUCapsArchFromString(architectureStr)) == VIR_ARCH_NONE) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown architecture '%1$s'"),
                           architectureStr);
            goto cleanup;
        }

        if (!(machines = virJSONValueObjectGetArray(item, "machines"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing 'machines' in '%1$s'"),
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
                       _("failed to get features from '%1$s'"),
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
                       _("unable to parse json file '%1$s'"),
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

    if (virJSONValueObjectAppendString(mapping,
                                       "mode",
                                       qemuFirmwareFlashModeTypeToString(flash->mode)) < 0)
        return -1;

    if (!(executable = qemuFirmwareFlashFileFormat(flash->executable)))
        return -1;

    if (virJSONValueObjectAppend(mapping,
                                 "executable",
                                 &executable) < 0)
        return -1;

    if (flash->mode == QEMU_FIRMWARE_FLASH_MODE_SPLIT) {
        if (!(nvram_template = qemuFirmwareFlashFileFormat(flash->nvram_template)))
            return -1;

        if (virJSONValueObjectAppend(mapping,
                                     "nvram-template",
                                     &nvram_template) < 0)
            return -1;
    }

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


/**
 * qemuFirmwareMatchesPaths:
 * @fw: firmware definition
 * @loader: loader definition
 * @kernelPath: path to kernel image
 *
 * Checks whether @fw is compatible with the information provided as
 * part of the domain definition.
 *
 * Returns: true if @fw is compatible with @loader and @kernelPath,
 *          false otherwise
 */
static bool
qemuFirmwareMatchesPaths(const qemuFirmware *fw,
                         const virDomainLoaderDef *loader,
                         const char *kernelPath)
{
    const qemuFirmwareMappingFlash *flash = &fw->mapping.data.flash;
    const qemuFirmwareMappingKernel *kernel = &fw->mapping.data.kernel;
    const qemuFirmwareMappingMemory *memory = &fw->mapping.data.memory;

    switch (fw->mapping.device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        if (loader && loader->path &&
            STRNEQ(loader->path, flash->executable.filename))
            return false;
        if (loader && loader->nvramTemplate) {
            if (flash->mode != QEMU_FIRMWARE_FLASH_MODE_SPLIT)
                return false;
            if (STRNEQ(loader->nvramTemplate, flash->nvram_template.filename))
                return false;
        }
        break;
    case QEMU_FIRMWARE_DEVICE_MEMORY:
        if (loader && loader->path &&
            STRNEQ(loader->path, memory->filename))
            return false;
        break;
    case QEMU_FIRMWARE_DEVICE_KERNEL:
        if (kernelPath &&
            STRNEQ(kernelPath, kernel->filename))
            return false;
        break;
    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        return false;
    }

    return true;
}


static qemuFirmwareOSInterface
qemuFirmwareOSInterfaceTypeFromOsDefFirmware(virDomainOsDefFirmware fw)
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


static virDomainOsDefFirmware
qemuFirmwareOSInterfaceTypeToOsDefFirmware(qemuFirmwareOSInterface interface)
{
    switch (interface) {
    case QEMU_FIRMWARE_OS_INTERFACE_BIOS:
        return VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS;
    case QEMU_FIRMWARE_OS_INTERFACE_UEFI:
        return VIR_DOMAIN_OS_DEF_FIRMWARE_EFI;
    case QEMU_FIRMWARE_OS_INTERFACE_UBOOT:
    case QEMU_FIRMWARE_OS_INTERFACE_OPENFIRMWARE:
    case QEMU_FIRMWARE_OS_INTERFACE_NONE:
    case QEMU_FIRMWARE_OS_INTERFACE_LAST:
        break;
    }

    return VIR_DOMAIN_OS_DEF_FIRMWARE_NONE;
}


static qemuFirmwareOSInterface
qemuFirmwareOSInterfaceTypeFromOsDefLoaderType(virDomainLoader type)
{
    switch (type) {
    case VIR_DOMAIN_LOADER_TYPE_ROM:
        return QEMU_FIRMWARE_OS_INTERFACE_BIOS;
    case VIR_DOMAIN_LOADER_TYPE_PFLASH:
        return QEMU_FIRMWARE_OS_INTERFACE_UEFI;
    case VIR_DOMAIN_LOADER_TYPE_NONE:
    case VIR_DOMAIN_LOADER_TYPE_LAST:
        break;
    }

    return QEMU_FIRMWARE_OS_INTERFACE_NONE;
}


/**
 * qemuFirmwareEnsureNVRAM:
 * @def: domain definition
 * @driver: QEMU driver
 * @abiUpdate: whether a new domain is being defined
 *
 * Make sure that a source for the NVRAM file exists, possibly by
 * creating it. This might involve automatically generating the
 * corresponding path.
 */
static void
qemuFirmwareEnsureNVRAM(virDomainDef *def,
                        virQEMUDriver *driver,
                        bool abiUpdate)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainLoaderDef *loader = def->os.loader;
    const char *ext = NULL;

    if (!loader)
        return;

    if (loader->type != VIR_DOMAIN_LOADER_TYPE_PFLASH)
        return;

    if (loader->readonly != VIR_TRISTATE_BOOL_YES)
        return;

    if (loader->stateless == VIR_TRISTATE_BOOL_YES)
        return;

    /* If the NVRAM format hasn't been set yet, inherit the same as
     * the loader */
    if (loader->nvram && !loader->nvram->format)
        loader->nvram->format = loader->format;

    /* If the source already exists and is fully specified, including
     * the path, leave it alone */
    if (loader->nvram && loader->nvram->path)
        return;

    if (loader->nvram)
        virObjectUnref(loader->nvram);

    loader->nvram = virStorageSourceNew();
    loader->nvram->type = VIR_STORAGE_TYPE_FILE;
    loader->nvram->format = loader->format;

    if (loader->nvram->format == VIR_STORAGE_FILE_RAW) {
        /* The extension used by raw edk2 builds has historically
         * been .fd, but more recent aarch64 builds have started
         * using the .raw extension instead.
         *
         * If we're defining a new domain, we should try to match the
         * extension for the file backing its NVRAM store with the
         * one used by the template to keep things nice and
         * consistent.
         *
         * If we're loading an existing domain, however, we need to
         * stick with the .fd extension to ensure compatibility */
        if (abiUpdate &&
            loader->nvramTemplate &&
            virStringHasSuffix(loader->nvramTemplate, ".raw"))
            ext = ".raw";
        else
            ext = ".fd";
    }
    if (loader->nvram->format == VIR_STORAGE_FILE_QCOW2)
        ext = ".qcow2";

    loader->nvram->path = g_strdup_printf("%s/%s_VARS%s",
                                          cfg->nvramDir, def->name,
                                          ext ? ext : "");
}



/**
 * qemuFirmwareSetOsFeatures:
 * @def: domain definition
 * @secureBoot: whether the 'secure-boot' feature is enabled
 * @enrolledKeys: whether the 'enrolled-keys' feature is enabled
 *
 * Set firmware features for @def to match those declared by the JSON
 * descriptor that was found to match autoselection requirements.
 */
static void
qemuFirmwareSetOsFeatures(virDomainDef *def,
                          bool secureBoot,
                          bool enrolledKeys)
{
    int *features = def->os.firmwareFeatures;
    virDomainLoaderDef *loader = def->os.loader;

    if (!features) {
        features = g_new0(int, VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_LAST);
        def->os.firmwareFeatures = features;
    }

    features[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_SECURE_BOOT] = virTristateBoolFromBool(secureBoot);
    features[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_ENROLLED_KEYS] = virTristateBoolFromBool(enrolledKeys);

    /* If the NVRAM template is blank at this point and we're not dealing
     * with a stateless firmware image, then it means that the NVRAM file
     * is not local. In this scenario we can't really make any assumptions
     * about its contents, so it's preferable to leave the state of the
     * enrolled-keys feature unspecified */
    if (loader &&
        loader->type == VIR_DOMAIN_LOADER_TYPE_PFLASH &&
        loader->stateless != VIR_TRISTATE_BOOL_YES &&
        !loader->nvramTemplate) {
        features[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_ENROLLED_KEYS] = VIR_TRISTATE_BOOL_ABSENT;
    }
}


#define VIR_QEMU_FIRMWARE_AMD_SEV_ES_POLICY (1 << 2)


static bool
qemuFirmwareMatchDomain(const virDomainDef *def,
                        const qemuFirmware *fw,
                        const char *path)
{
    const virDomainLoaderDef *loader = def->os.loader;
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

    if (want == QEMU_FIRMWARE_OS_INTERFACE_NONE && loader) {
        want = qemuFirmwareOSInterfaceTypeFromOsDefLoaderType(loader->type);
    }

    for (i = 0; i < fw->ninterfaces; i++) {
        if (fw->interfaces[i] == want)
            break;
    }

    if (i == fw->ninterfaces) {
        VIR_DEBUG("No matching interface in '%s'", path);
        return false;
    }

    if (!qemuFirmwareMatchesPaths(fw, def->os.loader, def->os.kernel)) {
        VIR_DEBUG("No matching path in '%s'", path);
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
        if (reqSecureBoot == VIR_TRISTATE_BOOL_YES && !supportsSecureBoot) {
            VIR_DEBUG("User requested Secure Boot, firmware '%s' doesn't support it",
                      path);
            return false;
        }
        if (reqSecureBoot == VIR_TRISTATE_BOOL_NO && supportsSecureBoot) {
            VIR_DEBUG("User refused Secure Boot, firmware '%s' supports it", path);
            return false;
        }

        reqEnrolledKeys = def->os.firmwareFeatures[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_ENROLLED_KEYS];
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

    if (requiresSMM) {
        if (def->features[VIR_DOMAIN_FEATURE_SMM] == VIR_TRISTATE_SWITCH_OFF) {
            VIR_DEBUG("Domain explicitly disables SMM, "
                      "but firmware '%s' requires it to be enabled", path);
            return false;
        }
        if (loader && loader->secure == VIR_TRISTATE_BOOL_NO) {
            VIR_DEBUG("Domain doesn't restrict pflash programming to SMM, "
                      "but firmware '%s' requires use of SMM", path);
            return false;
        }
    } else {
        if (loader && loader->secure == VIR_TRISTATE_BOOL_YES) {
            VIR_DEBUG("Domain restricts pflash programming to SMM, "
                      "but firmware '%s' doesn't support SMM", path);
            return false;
        }
    }

    if (fw->mapping.device == QEMU_FIRMWARE_DEVICE_FLASH) {
        const qemuFirmwareMappingFlash *flash = &fw->mapping.data.flash;

        if (loader && loader->stateless == VIR_TRISTATE_BOOL_YES) {
            if (flash->mode != QEMU_FIRMWARE_FLASH_MODE_STATELESS) {
                VIR_DEBUG("Discarding loader without stateless flash");
                return false;
            }
        } else {
            if (flash->mode != QEMU_FIRMWARE_FLASH_MODE_SPLIT) {
                VIR_DEBUG("Discarding loader without split flash");
                return false;
            }
        }

        if (loader &&
            loader->readonly == VIR_TRISTATE_BOOL_NO &&
            flash->mode != QEMU_FIRMWARE_FLASH_MODE_COMBINED) {
            VIR_DEBUG("Discarding readonly loader");
            return false;
        }

        if (STRNEQ(flash->executable.format, "raw") &&
            STRNEQ(flash->executable.format, "qcow2")) {
            VIR_DEBUG("Discarding loader with unsupported flash format '%s'",
                      flash->executable.format);
            return false;
        }
        if (loader && loader->format &&
            STRNEQ(flash->executable.format, virStorageFileFormatTypeToString(loader->format))) {
            VIR_DEBUG("Discarding loader with mismatching flash format '%s' != '%s'",
                      flash->executable.format,
                      virStorageFileFormatTypeToString(loader->format));
            return false;
        }
        if (flash->mode == QEMU_FIRMWARE_FLASH_MODE_SPLIT) {
            if (STRNEQ(flash->nvram_template.format, "raw") &&
                STRNEQ(flash->nvram_template.format, "qcow2")) {
                VIR_DEBUG("Discarding loader with unsupported nvram template format '%s'",
                          flash->nvram_template.format);
                return false;
            }
            if (loader && loader->nvram && loader->nvram->format &&
                STRNEQ(flash->nvram_template.format, virStorageFileFormatTypeToString(loader->nvram->format))) {
                VIR_DEBUG("Discarding loader with mismatching nvram template format '%s' != '%s'",
                          flash->nvram_template.format,
                          virStorageFileFormatTypeToString(loader->nvram->format));
                return false;
            }
        }
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
qemuFirmwareEnableFeaturesModern(virDomainDef *def,
                                 const qemuFirmware *fw)
{
    const qemuFirmwareMappingFlash *flash = &fw->mapping.data.flash;
    const qemuFirmwareMappingKernel *kernel = &fw->mapping.data.kernel;
    const qemuFirmwareMappingMemory *memory = &fw->mapping.data.memory;
    virDomainLoaderDef *loader = NULL;
    virStorageFileFormat format;
    bool hasSecureBoot = false;
    bool hasEnrolledKeys = false;
    size_t i;

    switch (fw->mapping.device) {
    case QEMU_FIRMWARE_DEVICE_FLASH:
        if ((format = virStorageFileFormatTypeFromString(flash->executable.format)) < 0)
            return -1;

        if (!def->os.loader)
            def->os.loader = virDomainLoaderDefNew();
        loader = def->os.loader;

        loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
        loader->readonly = VIR_TRISTATE_BOOL_YES;
        loader->format = format;

        VIR_FREE(loader->path);
        loader->path = g_strdup(flash->executable.filename);

        if (flash->mode == QEMU_FIRMWARE_FLASH_MODE_SPLIT) {
            /* Only fill in nvramTemplate if the NVRAM location is already
             * known to be a local path or hasn't been provided, in which
             * case a local path will be generated by libvirt later.
             *
             * We can't create or reset non-local NVRAM files, so filling
             * in nvramTemplate for those would be misleading */
            VIR_FREE(loader->nvramTemplate);
            if (!loader->nvram ||
                (loader->nvram && virStorageSourceIsLocalStorage(loader->nvram))) {
                loader->nvramTemplate = g_strdup(flash->nvram_template.filename);
            }
        }

        VIR_DEBUG("decided on firmware '%s' template '%s'",
                  loader->path, NULLSTR(loader->nvramTemplate));
        break;

    case QEMU_FIRMWARE_DEVICE_KERNEL:
        VIR_FREE(def->os.kernel);
        def->os.kernel = g_strdup(kernel->filename);

        VIR_DEBUG("decided on kernel '%s'",
                  def->os.kernel);
        break;

    case QEMU_FIRMWARE_DEVICE_MEMORY:
        if (!def->os.loader)
            def->os.loader = virDomainLoaderDefNew();
        loader = def->os.loader;

        loader->type = VIR_DOMAIN_LOADER_TYPE_ROM;

        VIR_FREE(loader->path);
        loader->path = g_strdup(memory->filename);

        VIR_DEBUG("decided on loader '%s'",
                  loader->path);
        break;

    case QEMU_FIRMWARE_DEVICE_NONE:
    case QEMU_FIRMWARE_DEVICE_LAST:
        break;
    }

    for (i = 0; i < fw->nfeatures; i++) {
        switch (fw->features[i]) {
        case QEMU_FIRMWARE_FEATURE_REQUIRES_SMM:
            VIR_DEBUG("Enabling SMM feature");
            def->features[VIR_DOMAIN_FEATURE_SMM] = VIR_TRISTATE_SWITCH_ON;

            VIR_DEBUG("Enabling secure loader");
            def->os.loader->secure = VIR_TRISTATE_BOOL_YES;
            break;

        case QEMU_FIRMWARE_FEATURE_SECURE_BOOT:
            hasSecureBoot = true;
            break;

        case QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS:
            hasEnrolledKeys = true;
            break;

        case QEMU_FIRMWARE_FEATURE_ACPI_S3:
        case QEMU_FIRMWARE_FEATURE_ACPI_S4:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV_ES:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC:
        case QEMU_FIRMWARE_FEATURE_NONE:
        case QEMU_FIRMWARE_FEATURE_LAST:
            break;
        }
    }

    if (!def->os.firmware) {
        /* If a firmware type for autoselection was not already present,
         * pick the first reasonable one from the descriptor list */
        for (i = 0; i < fw->ninterfaces; i++) {
            def->os.firmware = qemuFirmwareOSInterfaceTypeToOsDefFirmware(fw->interfaces[i]);
            if (def->os.firmware)
                break;
        }
    }
    if (def->os.firmware) {
        qemuFirmwareSetOsFeatures(def, hasSecureBoot, hasEnrolledKeys);
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
    bool hasEnrolledKeys = false;

    for (i = 0; i < fw->nfeatures; i++) {
        switch (fw->features[i]) {
        case QEMU_FIRMWARE_FEATURE_REQUIRES_SMM:
            requiresSMM = true;
            break;
        case QEMU_FIRMWARE_FEATURE_SECURE_BOOT:
            supportsSecureBoot = true;
            break;
        case QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS:
            hasEnrolledKeys = true;
            break;
        case QEMU_FIRMWARE_FEATURE_NONE:
        case QEMU_FIRMWARE_FEATURE_ACPI_S3:
        case QEMU_FIRMWARE_FEATURE_ACPI_S4:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV:
        case QEMU_FIRMWARE_FEATURE_AMD_SEV_ES:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_DYNAMIC:
        case QEMU_FIRMWARE_FEATURE_VERBOSE_STATIC:
        case QEMU_FIRMWARE_FEATURE_LAST:
            break;
        }
    }

    if ((supportsSecureBoot != requiresSMM) ||
        (hasEnrolledKeys && !supportsSecureBoot)) {
        VIR_WARN("Firmware description '%s' has invalid set of features: "
                 "%s = %d, %s = %d, %s = %d",
                 filename,
                 qemuFirmwareFeatureTypeToString(QEMU_FIRMWARE_FEATURE_REQUIRES_SMM),
                 requiresSMM,
                 qemuFirmwareFeatureTypeToString(QEMU_FIRMWARE_FEATURE_SECURE_BOOT),
                 supportsSecureBoot,
                 qemuFirmwareFeatureTypeToString(QEMU_FIRMWARE_FEATURE_ENROLLED_KEYS),
                 hasEnrolledKeys);
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


/**
 * qemuFirmwareFillDomainLegacy:
 * @driver: QEMU driver
 * @def: domain definition
 *
 * Go through the legacy list of CODE:VARS pairs looking for a
 * suitable NVRAM template for the user-provided firmware path.
 *
 * Should only be used as a fallback in case looking at the firmware
 * descriptors yielded no results.
 *
 * Returns: 0 on success,
 *          1 if a matching firmware could not be found,
 *          -1 on error.
 */
static int
qemuFirmwareFillDomainLegacy(virQEMUDriver *driver,
                             virDomainDef *def)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainLoaderDef *loader = def->os.loader;
    size_t i;

    if (!loader)
        return 1;

    if (loader->type != VIR_DOMAIN_LOADER_TYPE_PFLASH) {
        VIR_DEBUG("Ignoring legacy entries for '%s' loader",
                  virDomainLoaderTypeToString(loader->type));
        return 1;
    }

    if (loader->readonly == VIR_TRISTATE_BOOL_NO) {
        VIR_DEBUG("Ignoring legacy entries for read-write loader");
        return 1;
    }

    if (loader->stateless == VIR_TRISTATE_BOOL_YES) {
        VIR_DEBUG("Ignoring legacy entries for stateless loader");
        return 1;
    }

    if (loader->format &&
        loader->format != VIR_STORAGE_FILE_RAW) {
        VIR_DEBUG("Ignoring legacy entries for loader with flash format '%s'",
                  virStorageFileFormatTypeToString(loader->format));
        return 1;
    }

    for (i = 0; i < cfg->nfirmwares; i++) {
        virFirmware *fw = cfg->firmwares[i];

        if (STRNEQ(fw->name, loader->path)) {
            VIR_DEBUG("Not matching loader path '%s' for user provided path '%s'",
                      fw->name, loader->path);
            continue;
        }

        loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
        loader->readonly = VIR_TRISTATE_BOOL_YES;
        loader->format = VIR_STORAGE_FILE_RAW;

        /* Only use the default template path if one hasn't been
         * provided by the user.
         *
         * In addition to fully-custom templates, which are a valid
         * use case, we could simply be in a situation where
         * qemu.conf contains
         *
         *   nvram = [
         *     "/path/to/OVMF_CODE.secboot.fd:/path/to/OVMF_VARS.fd",
         *     "/path/to/OVMF_CODE.secboot.fd:/path/to/OVMF_VARS.secboot.fd"
         *   ]
         *
         * and the domain has been configured as
         *
         *   <os>
         *     <loader readonly='yes' type='pflash'>/path/to/OVMF_CODE.secboot.fd</loader>
         *     <nvram template='/path/to/OVMF/OVMF_VARS.secboot.fd'>
         *   </os>
         *
         * In this case, the global default is to have Secure Boot
         * disabled, but the domain configuration explicitly enables
         * it, and we shouldn't overrule this choice */
        if (!loader->nvramTemplate)
            loader->nvramTemplate = g_strdup(cfg->firmwares[i]->nvram);

        VIR_DEBUG("decided on firmware '%s' template '%s'",
                  loader->path, NULLSTR(loader->nvramTemplate));

        return 0;
    }

    return 1;
}


/**
 * qemuFirmwareFillDomainModern:
 * @driver: QEMU driver
 * @def: domain definition
 *
 * Look at the firmware descriptors available on the system and try
 * to find one that matches the user's requested configuration. If
 * successful, @def will be updated so that it explicitly points to
 * the corresponding paths.
 *
 * Returns: 0 on success,
 *          1 if a matching firmware could not be found,
 *          -1 on error.
 */
static int
qemuFirmwareFillDomainModern(virQEMUDriver *driver,
                             virDomainDef *def)
{
    g_auto(GStrv) paths = NULL;
    qemuFirmware **firmwares = NULL;
    ssize_t nfirmwares = 0;
    const qemuFirmware *theone = NULL;
    size_t i;
    int ret = -1;

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
        ret = 1;
        goto cleanup;
    }

    /* Firstly, let's do some sanity checks. If either of these
     * fail we can still start the domain successfully, but it's
     * likely that admin/FW manufacturer messed up. */
    qemuFirmwareSanityCheck(theone, paths[i]);

    if (qemuFirmwareEnableFeaturesModern(def, theone) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    for (i = 0; i < nfirmwares; i++)
        qemuFirmwareFree(firmwares[i]);
    VIR_FREE(firmwares);
    return ret;
}


/**
 * qemuFirmwareFillDomain:
 * @driver: QEMU driver
 * @def: domain definition
 * @abiUpdate: whether a new domain is being defined
 *
 * Perform firmware selection.
 *
 * When firmware autoselection is used, this means looking at the
 * firmware descriptors available on the system and finding one that
 * matches the user's requested parameters; when manual firmware
 * selection is used, the path to the firmware itself is usually
 * already provided, but other information such as the path to the
 * NVRAM template might be missing.
 *
 * The idea is that calling this function a first time (at PostParse
 * time) will convert whatever partial configuration the user might
 * have provided into a fully specified firmware configuration, such
 * as that calling it a second time (at domain start time) will
 * result in an early successful exit. The same thing should happen
 * if the input configuration wasn't missing any information in the
 * first place.
 *
 * Returns: 0 on success,
 *          -1 on error.
 */
int
qemuFirmwareFillDomain(virQEMUDriver *driver,
                       virDomainDef *def,
                       bool abiUpdate)
{
    virDomainLoaderDef *loader = def->os.loader;
    virStorageSource *nvram = loader ? loader->nvram : NULL;
    bool autoSelection = (def->os.firmware != VIR_DOMAIN_OS_DEF_FIRMWARE_NONE);
    int ret;

    /* Start by performing a thorough validation of the input.
     *
     * We need to do this here because the firmware selection logic
     * can only work correctly if the request is constructed
     * properly; at the same time, we can't rely on Validate having
     * been called ahead of time, because in some situations (such as
     * when loading the configuration of existing domains from disk)
     * that entire phase is intentionally skipped */
    if (virDomainDefOSValidate(def, NULL) < 0)
        return -1;

    if (loader &&
        loader->format &&
        loader->format != VIR_STORAGE_FILE_RAW &&
        loader->format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported loader format '%1$s'"),
                       virStorageFileFormatTypeToString(loader->format));
        return -1;
    }
    if (nvram &&
        nvram->format &&
        nvram->format != VIR_STORAGE_FILE_RAW &&
        nvram->format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported nvram format '%1$s'"),
                       virStorageFileFormatTypeToString(nvram->format));
        return -1;
    }

    /* If firmware autoselection is disabled and the loader is a ROM
     * instead of a PFLASH device, then we're using BIOS and we don't
     * need any information at all */
    if (!autoSelection &&
        (!loader || (loader && loader->type == VIR_DOMAIN_LOADER_TYPE_ROM))) {
        return 0;
    }

    /* Look for the information we need in firmware descriptors */
    if ((ret = qemuFirmwareFillDomainModern(driver, def)) < 0)
        return -1;

    if (ret == 1) {
        /* If we haven't found any match among firmware descriptors,
         * that would normally be the end of it.
         *
         * However, in order to handle legacy configurations
         * correctly, we make another attempt at locating the missing
         * information by going through the hardcoded list of
         * CODE:NVRAM pairs that might have been provided at build
         * time */
        if (!autoSelection) {
            if ((ret = qemuFirmwareFillDomainLegacy(driver, def)) < 0)
                return -1;

            /* If we've gotten this far without finding a match, it
             * means that we're dealing with a set of completely
             * custom paths. In that case, unless the user has
             * specified otherwise, we have to assume that they're in
             * raw format */
            if (ret == 1) {
                if (loader && !loader->format) {
                    loader->format = VIR_STORAGE_FILE_RAW;
                }
            }
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Unable to find '%1$s' firmware that is compatible with the current configuration"),
                           virDomainOsDefFirmwareTypeToString(def->os.firmware));
            return -1;
        }
    }

    /* Always ensure that the NVRAM path is present, even if we
     * haven't found a match: the configuration might simply be
     * referring to a custom firmware build */
    qemuFirmwareEnsureNVRAM(def, driver, abiUpdate);

    return 0;
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
