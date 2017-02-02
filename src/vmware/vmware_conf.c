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

#include <string.h>

#include "vircommand.h"
#include "cpu/cpu.h"
#include "dirname.h"
#include "viralloc.h"
#include "nodeinfo.h"
#include "virfile.h"
#include "viruuid.h"
#include "virerror.h"
#include "vmx.h"
#include "vmware_conf.h"
#include "virstring.h"

VIR_ENUM_IMPL(vmwareDriver, VMWARE_DRIVER_LAST,
              "player",
              "ws",
              "fusion");

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
    VIR_FREE(driver->vmrun);
    VIR_FREE(driver);
}


virCapsPtr
vmwareCapsInit(void)
{
    virCapsPtr caps = NULL;
    virCapsGuestPtr guest = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUDataPtr data = NULL;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto error;

    if (nodeCapsInitNUMA(caps) < 0)
        goto error;

    /* i686 guests are always supported */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_HVM,
                                         VIR_ARCH_I686,
                                         NULL, NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_VMWARE,
                                      NULL, NULL, 0, NULL) == NULL)
        goto error;

    if (VIR_ALLOC(cpu) < 0)
        goto error;

    cpu->arch = caps->host.arch;
    cpu->type = VIR_CPU_TYPE_HOST;

    if (!(data = cpuNodeData(cpu->arch))
        || cpuDecode(cpu, data, NULL, 0, NULL) < 0) {
        goto error;
    }

    /* x86_64 guests are supported if
     *  - Host arch is x86_64
     * Or
     *  - Host CPU is x86_64 with virtualization extensions
     */
    if (caps->host.arch == VIR_ARCH_X86_64 ||
        (virCPUDataCheckFeature(data, "lm") &&
         (virCPUDataCheckFeature(data, "vmx") ||
          virCPUDataCheckFeature(data, "svm")))) {

        if ((guest = virCapabilitiesAddGuest(caps,
                                             VIR_DOMAIN_OSTYPE_HVM,
                                             VIR_ARCH_X86_64,
                                             NULL, NULL, 0, NULL)) == NULL)
            goto error;

        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_VMWARE,
                                          NULL, NULL, 0, NULL) == NULL)
            goto error;
    }

 cleanup:
    virCPUDefFree(cpu);
    virCPUDataFree(data);

    return caps;

 error:
    virObjectUnref(caps);
    goto cleanup;
}

int
vmwareLoadDomains(struct vmware_driver *driver)
{
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    char *vmxPath = NULL;
    char *vmx = NULL;
    vmwareDomainPtr pDomain;
    char *directoryName = NULL;
    char *fileName = NULL;
    int ret = -1;
    virVMXContext ctx;
    char *outbuf = NULL;
    char *str;
    char *saveptr = NULL;
    virCommandPtr cmd;

    ctx.parseFileName = vmwareCopyVMXFileName;
    ctx.formatFileName = NULL;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    cmd = virCommandNewArgList(driver->vmrun, "-T",
                               vmwareDriverTypeToString(driver->type),
                               "list", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    for (str = outbuf; (vmxPath = strtok_r(str, "\n", &saveptr)) != NULL;
        str = NULL) {

        if (vmxPath[0] != '/')
            continue;

        if (virFileReadAll(vmxPath, 10000, &vmx) < 0)
            goto cleanup;

        if ((vmdef =
             virVMXParseConfig(&ctx, driver->xmlopt,
                               driver->caps, vmx)) == NULL) {
            goto cleanup;
        }

        if (!(vm = virDomainObjListAdd(driver->domains, vmdef,
                                       driver->xmlopt,
                                       0, NULL)))
            goto cleanup;

        pDomain = vm->privateData;

        if (VIR_STRDUP(pDomain->vmxPath, vmxPath) < 0)
            goto cleanup;

        vmwareDomainConfigDisplay(pDomain, vmdef);

        if ((vm->def->id = vmwareExtractPid(vmxPath)) < 0)
            goto cleanup;
        /* vmrun list only reports running vms */
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);
        vm->persistent = 1;

        virObjectUnlock(vm);

        vmdef = NULL;
        vm = NULL;
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    virDomainDefFree(vmdef);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);
    VIR_FREE(vmx);
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
                           _("Invalid driver type: %d"), type);
            return -1;
    }

    if ((tmp = strstr(verbuf, pattern)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find version pattern \"%s\""), pattern);
        return -1;
    }

    if ((tmp = STRSKIP(tmp, pattern)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse %sversion"), pattern);
        return -1;
    }

    if (virParseVersionString(tmp, version, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("version parsing error"));
        return -1;
    }

    return 0;
}

int
vmwareExtractVersion(struct vmware_driver *driver)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char * outbuf = NULL;
    char *bin = NULL;
    char *vmwarePath = NULL;

    if ((vmwarePath = mdir_name(driver->vmrun)) == NULL)
        goto cleanup;

    switch (driver->type) {
        case VMWARE_DRIVER_PLAYER:
            if (virAsprintf(&bin, "%s/%s", vmwarePath, "vmplayer") < 0)
                goto cleanup;
            break;

        case VMWARE_DRIVER_WORKSTATION:
            if (virAsprintf(&bin, "%s/%s", vmwarePath, "vmware") < 0)
                goto cleanup;
            break;

        case VMWARE_DRIVER_FUSION:
            if (virAsprintf(&bin, "%s/%s", vmwarePath, "vmware-vmx") < 0)
                goto cleanup;
            break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("invalid driver type for version detection"));
            goto cleanup;
    }

    cmd = virCommandNewArgList(bin, "-v", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    virCommandSetErrorBuffer(cmd, &outbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (vmwareParseVersionStr(driver->type, outbuf, &driver->version) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    VIR_FREE(bin);
    VIR_FREE(vmwarePath);
    return ret;
}

int
vmwareDomainConfigDisplay(vmwareDomainPtr pDomain, virDomainDefPtr def)
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
                           _("path '%s' doesn't reference a file"), path);
            return -1;
        }

        if (VIR_STRNDUP(*directory, path, separator - path - 1) < 0)
            goto error;
        if (VIR_STRDUP(*filename, separator) < 0) {
            VIR_FREE(*directory);
            goto error;
        }

    } else {
        if (VIR_STRDUP(*filename, path) < 0)
            goto error;
    }

    return 0;

 error:
    return -1;
}

int
vmwareConstructVmxPath(char *directoryName, char *name, char **vmxPath)
{
    int ret;

    if (directoryName != NULL)
        ret = virAsprintf(vmxPath, "%s/%s.vmx", directoryName, name);
    else
        ret = virAsprintf(vmxPath, "%s.vmx", name);

    if (ret < 0)
        return -1;
    return 0;
}

int
vmwareVmxPath(virDomainDefPtr vmdef, char **vmxPath)
{
    virDomainDiskDefPtr disk = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    int ret = -1;
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
                       _("Domain XML doesn't contain any disks, "
                         "cannot deduce datastore and path for VMX file"));
        goto cleanup;
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
                       _("Domain XML doesn't contain any file-based harddisks, "
                         "cannot deduce datastore and path for VMX file"));
        goto cleanup;
    }

    src = virDomainDiskGetSource(disk);
    if (!src) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("First file-based harddisk has no source, cannot "
                         "deduce datastore and path for VMX file"));
        goto cleanup;
    }

    if (vmwareParsePath(src, &directoryName, &fileName) < 0)
        goto cleanup;

    if (!virFileHasSuffix(fileName, ".vmdk")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting source '%s' of first file-based harddisk "
                         "to be a VMDK image"), src);
        goto cleanup;
    }

    if (vmwareConstructVmxPath(directoryName, vmdef->name, vmxPath) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(directoryName);
    VIR_FREE(fileName);
    return ret;
}

int
vmwareMoveFile(char *srcFile, char *dstFile)
{
    const char *cmdmv[] =
        { "mv", PROGRAM_SENTINEL, PROGRAM_SENTINEL, NULL };

    if (!virFileExists(srcFile)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("file %s does not exist"),
                       srcFile);
        return -1;
    }

    if (STREQ(srcFile, dstFile))
        return 0;

    vmwareSetSentinal(cmdmv, srcFile);
    vmwareSetSentinal(cmdmv, dstFile);
    if (virRun(cmdmv, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to move file to %s "), dstFile);
        return -1;
    }

    return 0;
}

int
vmwareMakePath(char *srcDir, char *srcName, char *srcExt, char **outpath)
{
    if (virAsprintf(outpath, "%s/%s.%s", srcDir, srcName, srcExt) < 0)
        return -1;
    return 0;
}

int
vmwareExtractPid(const char * vmxPath)
{
    char *vmxDir = NULL;
    char *logFilePath = NULL;
    FILE *logFile = NULL;
    char line[1024];
    char *tmp = NULL;
    int pid_value = -1;

    if ((vmxDir = mdir_name(vmxPath)) == NULL)
        goto cleanup;

    if (virAsprintf(&logFilePath, "%s/vmware.log",
                    vmxDir) < 0)
        goto cleanup;

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
    VIR_FREE(vmxDir);
    VIR_FREE(logFilePath);
    VIR_FORCE_FCLOSE(logFile);
    return pid_value;
}

char *
vmwareCopyVMXFileName(const char *datastorePath, void *opaque ATTRIBUTE_UNUSED)
{
    char *path;

    ignore_value(VIR_STRDUP(path, datastorePath));
    return path;
}
