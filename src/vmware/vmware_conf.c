/*---------------------------------------------------------------------------*/
/*
 * Copyright (C) 2011-2014 Red Hat, Inc.
 * Copyright (C) 2010-2014, diateam (www.diateam.net)
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
/*---------------------------------------------------------------------------*/

#include <config.h>


#include "vircommand.h"
#include "cpu/cpu.h"
#include "viralloc.h"
#include "virfile.h"
#include "virerror.h"
#include "vmx.h"
#include "vmware_conf.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_VMWARE

VIR_LOG_INIT("vmware.vmware_conf");

VIR_ENUM_IMPL(vmwareDriver,
              VMWARE_DRIVER_LAST,
              "player",
              "ws",
              "fusion",
);

/* Free all memory associated with a vmware_driver structure */
void
vmwareFreeDriver(struct vmware_driver *driver)
{
    if (!driver)
        return;

    virMutexDestroy(&driver->lock);
    virObjectUnref(driver->domains);
    virObjectUnref(driver->caps);
    virObjectUnref(driver->xmlopt);
    g_free(driver->vmrun);
    g_free(driver);
}


virCaps *
vmwareCapsInit(void)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest = NULL;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto error;

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        goto error;

    if (virCapabilitiesInitCaches(caps) < 0)
        VIR_WARN("Failed to get host CPU cache info");

    /* i686 guests are always supported */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    VIR_ARCH_I686, NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE,
                                  NULL, NULL, 0, NULL);
    guest = NULL;

    if (!(caps->host.cpu = virCPUProbeHost(caps->host.arch)))
        goto error;

    /* x86_64 guests are supported if
     *  - Host arch is x86_64
     * Or
     *  - Host CPU is x86_64 with virtualization extensions
     */
    if (caps->host.arch == VIR_ARCH_X86_64 ||
        (virCPUCheckFeature(caps->host.cpu->arch, caps->host.cpu, "lm") &&
         (virCPUCheckFeature(caps->host.cpu->arch, caps->host.cpu, "vmx") ||
          virCPUCheckFeature(caps->host.cpu->arch, caps->host.cpu, "svm")))) {

        guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                        VIR_ARCH_X86_64, NULL, NULL, 0, NULL);

        virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE,
                                      NULL, NULL, 0, NULL);
        guest = NULL;
    }

    return g_steal_pointer(&caps);

 error:
    virCapabilitiesFreeGuest(guest);
    return NULL;
}

int
vmwareLoadDomains(struct vmware_driver *driver)
{
    virDomainObj *vm = NULL;
    char *vmxPath = NULL;
    g_autofree char *vmx = NULL;
    vmwareDomainPtr pDomain;
    int ret = -1;
    virVMXContext ctx;
    g_autofree char *outbuf = NULL;
    char *str;
    char *saveptr = NULL;
    g_autoptr(virCommand) cmd = NULL;

    ctx.parseFileName = vmwareParseVMXFileName;
    ctx.formatFileName = NULL;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    cmd = virCommandNewArgList(driver->vmrun, "-T",
                               vmwareDriverTypeToString(driver->type),
                               "list", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    for (str = outbuf; (vmxPath = strtok_r(str, "\n", &saveptr)) != NULL; str = NULL) {
        g_autoptr(virDomainDef) vmdef = NULL;

        if (!g_path_is_absolute(vmxPath))
            continue;

        if (virFileReadAll(vmxPath, 10000, &vmx) < 0)
            goto cleanup;

        if ((vmdef =
             virVMXParseConfig(&ctx, driver->xmlopt,
                               driver->caps, vmx)) == NULL) {
            goto cleanup;
        }

        if (!(vm = virDomainObjListAdd(driver->domains, &vmdef,
                                       driver->xmlopt,
                                       0, NULL)))
            goto cleanup;

        pDomain = vm->privateData;

        pDomain->vmxPath = g_strdup(vmxPath);

        vmwareDomainConfigDisplay(pDomain, vm->def);

        if ((vm->def->id = vmwareExtractPid(vmxPath)) < 0)
            goto cleanup;
        /* vmrun list only reports running vms */
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);
        vm->persistent = 1;

        virDomainObjEndAPI(&vm);
    }

    ret = 0;

 cleanup:
    virObjectUnref(vm);
    return ret;
}

void
vmwareSetSentinal(const char **prog, const char *key)
{
    const char **tmp = prog;

    while (tmp && *tmp) {
        if (*tmp == PROGRAM_SENTINEL) {
            *tmp = key;
            break;
        }
        tmp++;
    }
}

int
vmwareParseVersionStr(int type, const char *verbuf, unsigned long *version)
{
    unsigned long long tmpver;
    const char *pattern;
    const char *tmp;

    switch (type) {
        case VMWARE_DRIVER_PLAYER:
            pattern = "VMware Player ";
            break;
        case VMWARE_DRIVER_WORKSTATION:
            pattern = "VMware Workstation ";
            break;
        case VMWARE_DRIVER_FUSION:
            pattern = "\nVMware Fusion Information:\nVMware Fusion ";
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid driver type: %1$d"), type);
            return -1;
    }

    if ((tmp = strstr(verbuf, pattern)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find version pattern \"%1$s\""), pattern);
        return -1;
    }

    if ((tmp = STRSKIP(tmp, pattern)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse %1$sversion"), pattern);
        return -1;
    }

    if (virStringParseVersion(&tmpver, tmp, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("version parsing error"));
        return -1;
    }

    *version = tmpver;

    return 0;
}

int
vmwareExtractVersion(struct vmware_driver *driver)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *outbuf = NULL;
    g_autofree char *bin = NULL;
    g_autofree char *vmwarePath = NULL;

    vmwarePath = g_path_get_dirname(driver->vmrun);

    switch (driver->type) {
        case VMWARE_DRIVER_PLAYER:
            bin = g_strdup_printf("%s/%s", vmwarePath, "vmplayer");
            break;

        case VMWARE_DRIVER_WORKSTATION:
            bin = g_strdup_printf("%s/%s", vmwarePath, "vmware");
            break;

        case VMWARE_DRIVER_FUSION:
            bin = g_strdup_printf("%s/%s", vmwarePath, "vmware-vmx");
            break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("invalid driver type for version detection"));
            return -1;
    }

    cmd = virCommandNewArgList(bin, "-v", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    virCommandSetErrorBuffer(cmd, &outbuf);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (vmwareParseVersionStr(driver->type, outbuf, &driver->version) < 0)
        return -1;

    return 0;
}

int
vmwareDomainConfigDisplay(vmwareDomainPtr pDomain, virDomainDef *def)
{
    size_t i;

    if (def->ngraphics == 0) {
        pDomain->gui = true;
        return 0;
    } else {
        pDomain->gui = false;
        for (i = 0; i < def->ngraphics; i++) {
            if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP) {
                pDomain->gui = true;
                return 0;
            }
        }
        return 0;
    }
}

static int
vmwareParsePath(const char *path, char **directory, char **filename)
{
    char *separator;

    separator = strrchr(path, '/');

    if (separator != NULL) {
        separator++;

        if (*separator == '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("path '%1$s' doesn't reference a file"), path);
            return -1;
        }

        *directory = g_strndup(path, separator - path - 1);
        *filename = g_strdup(separator);

    } else {
        *filename = g_strdup(path);
    }

    return 0;
}

void
vmwareConstructVmxPath(char *directoryName, char *name, char **vmxPath)
{
    if (directoryName != NULL)
        *vmxPath = g_strdup_printf("%s/%s.vmx", directoryName, name);
    else
        *vmxPath = g_strdup_printf("%s.vmx", name);
}

int
vmwareVmxPath(virDomainDef *vmdef, char **vmxPath)
{
    virDomainDiskDef *disk = NULL;
    g_autofree char *directoryName = NULL;
    g_autofree char *fileName = NULL;
    size_t i;
    const char *src;

    /*
     * Build VMX URL. Use the source of the first file-based harddisk
     * to deduce the path for the VMX file. Don't just use the
     * first disk, because it may be CDROM disk and ISO images are normally not
     * located in the virtual machine's directory. This approach
     * isn't perfect but should work in the majority of cases.
     */
    if (vmdef->ndisks < 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain XML doesn't contain any disks, cannot deduce datastore and path for VMX file"));
        return -1;
    }

    for (i = 0; i < vmdef->ndisks; ++i) {
        if (vmdef->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
            virDomainDiskGetType(vmdef->disks[i]) == VIR_STORAGE_TYPE_FILE) {
            disk = vmdef->disks[i];
            break;
        }
    }

    if (disk == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain XML doesn't contain any file-based harddisks, cannot deduce datastore and path for VMX file"));
        return -1;
    }

    src = virDomainDiskGetSource(disk);
    if (!src) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("First file-based harddisk has no source, cannot deduce datastore and path for VMX file"));
        return -1;
    }

    if (vmwareParsePath(src, &directoryName, &fileName) < 0)
        return -1;

    if (!virStringHasCaseSuffix(fileName, ".vmdk")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting source '%1$s' of first file-based harddisk to be a VMDK image"),
                       src);
        return -1;
    }

    vmwareConstructVmxPath(directoryName, vmdef->name, vmxPath);

    return 0;
}

int
vmwareMoveFile(char *srcFile, char *dstFile)
{
    g_autoptr(virCommand) cmd = NULL;

    if (!virFileExists(srcFile)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("file %1$s does not exist"),
                       srcFile);
        return -1;
    }

    if (STREQ(srcFile, dstFile))
        return 0;

    cmd = virCommandNewArgList("mv", srcFile, dstFile, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to move file to %1$s "), dstFile);
        return -1;
    }

    return 0;
}

int
vmwareMakePath(char *srcDir, char *srcName, char *srcExt, char **outpath)
{
    *outpath = g_strdup_printf("%s/%s.%s", srcDir, srcName, srcExt);
    return 0;
}

int
vmwareExtractPid(const char * vmxPath)
{
    g_autofree char *vmxDir = NULL;
    g_autofree char *logFilePath = NULL;
    FILE *logFile = NULL;
    char line[1024];
    char *tmp = NULL;
    int pid_value = -1;

    vmxDir = g_path_get_dirname(vmxPath);

    logFilePath = g_strdup_printf("%s/vmware.log", vmxDir);

    if ((logFile = fopen(logFilePath, "r")) == NULL)
        goto cleanup;

    if (!fgets(line, sizeof(line), logFile)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to read vmware log file"));
        goto cleanup;
    }

    if ((tmp = strstr(line, " pid=")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot find pid in vmware log file"));
        goto cleanup;
    }

    tmp += strlen(" pid=");

    /* Although 64-bit windows allows 64-bit pid_t, a domain id has to be
     * 32 bits.  For now, we just reject pid values that overflow int.  */
    if (virStrToLong_i(tmp, &tmp, 10, &pid_value) < 0 || *tmp != ' ') {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot parse pid in vmware log file"));
        goto cleanup;
    }

 cleanup:
    VIR_FORCE_FCLOSE(logFile);
    return pid_value;
}

int
vmwareParseVMXFileName(const char *datastorePath,
                       void *opaque G_GNUC_UNUSED,
                       char **out,
                       bool allow_missing G_GNUC_UNUSED)
{
    *out = g_strdup(datastorePath);

    return *out ? 0 : -1;
}

char *
vmwareFormatVMXFileName(const char *datastorePath,
                        void *opaque G_GNUC_UNUSED)
{
    return g_strdup(datastorePath);
}
