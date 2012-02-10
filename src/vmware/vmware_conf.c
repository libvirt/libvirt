/*---------------------------------------------------------------------------*/
/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
 * Copyright 2010, diateam (www.diateam.net)
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
/*---------------------------------------------------------------------------*/

#include <config.h>

#include <string.h>
#include <sys/utsname.h>

#include "command.h"
#include "cpu/cpu.h"
#include "dirname.h"
#include "memory.h"
#include "nodeinfo.h"
#include "virfile.h"
#include "uuid.h"
#include "virterror_internal.h"
#include "vmx.h"

#include "vmware_conf.h"

/* Free all memory associated with a vmware_driver structure */
void
vmwareFreeDriver(struct vmware_driver *driver)
{
    if (!driver)
        return;

    virMutexDestroy(&driver->lock);
    virDomainObjListDeinit(&driver->domains);
    virCapabilitiesFree(driver->caps);
    VIR_FREE(driver);
}


static int vmwareDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
}


virCapsPtr
vmwareCapsInit(void)
{
    struct utsname utsname;
    virCapsPtr caps = NULL;
    virCapsGuestPtr guest = NULL;
    virCPUDefPtr cpu = NULL;
    union cpuData *data = NULL;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine, 0, 0)) == NULL)
        goto error;

    if (nodeCapsInitNUMA(caps) < 0)
        goto error;

    virCapabilitiesSetMacPrefix(caps, (unsigned char[]) {0x52, 0x54, 0x00});

    /* i686 guests are always supported */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         "i686",
                                         32,
                                         NULL, NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "vmware",
                                      NULL, NULL, 0, NULL) == NULL)
        goto error;

    if (VIR_ALLOC(cpu) < 0
        || !(cpu->arch = strdup(utsname.machine))) {
        virReportOOMError();
        goto error;
    }

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
    if (STREQ(utsname.machine, "x86_64") ||
        (cpuHasFeature(utsname.machine, data, "lm") &&
         (cpuHasFeature(utsname.machine, data, "vmx") ||
          cpuHasFeature(utsname.machine, data, "svm")))) {

        if ((guest = virCapabilitiesAddGuest(caps,
                                             "hvm",
                                             "x86_64",
                                             64,
                                             NULL, NULL, 0, NULL)) == NULL)
            goto error;

        if (virCapabilitiesAddGuestDomain(guest,
                                          "vmware",
                                          NULL, NULL, 0, NULL) == NULL)
            goto error;
    }

    caps->defaultConsoleTargetType = vmwareDefaultConsoleType;

cleanup:
    virCPUDefFree(cpu);
    cpuDataFree(utsname.machine, data);

    return caps;

error:
    virCapabilitiesFree(caps);
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

    cmd = virCommandNewArgList(VMRUN, "-T",
                               driver->type == TYPE_PLAYER ? "player" : "ws",
                               "list", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    for(str = outbuf ; (vmxPath = strtok_r(str, "\n", &saveptr)) != NULL;
        str = NULL) {

        if (vmxPath[0] != '/')
            continue;

        if (virFileReadAll(vmxPath, 10000, &vmx) < 0)
            goto cleanup;

        if ((vmdef =
             virVMXParseConfig(&ctx, driver->caps, vmx)) == NULL) {
            goto cleanup;
        }

        if (!(vm = virDomainAssignDef(driver->caps,
                                      &driver->domains, vmdef, false)))
            goto cleanup;

        pDomain = vm->privateData;

        pDomain->vmxPath = strdup(vmxPath);
        if (pDomain->vmxPath == NULL) {
            virReportOOMError();
            goto cleanup;
        }

        vmwareDomainConfigDisplay(pDomain, vmdef);

        if ((vm->def->id = vmwareExtractPid(vmxPath)) < 0)
            goto cleanup;
        /* vmrun list only reports running vms */
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);
        vm->persistent = 1;

        virDomainObjUnlock(vm);

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
    /* any non-NULL vm here has not been shared, so unref will return 0 */
    if (vm)
        ignore_value(virDomainObjUnref(vm));
    return ret;
}

void
vmwareSetSentinal(const char **prog, const char *key)
{
    const char **tmp = prog;

    while (tmp && *tmp) {
        if (*tmp == PROGRAM_SENTINAL) {
            *tmp = key;
            break;
        }
        tmp++;
    }
}

int
vmwareExtractVersion(struct vmware_driver *driver)
{
    unsigned long version = 0;
    char *tmp;
    int ret = -1;
    virCommandPtr cmd;
    char * outbuf = NULL;
    const char * bin = (driver->type == TYPE_PLAYER) ? "vmplayer" : "vmware";
    const char * pattern = (driver->type == TYPE_PLAYER) ?
                "VMware Player " : "VMware Workstation ";

    cmd = virCommandNewArgList(bin, "-v", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if ((tmp = STRSKIP(outbuf, pattern)) == NULL) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    _("failed to parse %s version"), bin);
        goto cleanup;
    }

    if (virParseVersionString(tmp, &version, false) < 0) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("version parsing error"));
        goto cleanup;
    }

    driver->version = version;
    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    return ret;
}

int
vmwareDomainConfigDisplay(vmwareDomainPtr pDomain, virDomainDefPtr def)
{
    int i = 0;

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

int
vmwareParsePath(char *path, char **directory, char **filename)
{
    char *separator;

    separator = strrchr(path, '/');

    if (separator != NULL) {
        *separator++ = '\0';

        if (*separator == '\0') {
            vmwareError(VIR_ERR_INTERNAL_ERROR,
                        _("path '%s' doesn't reference a file"), path);
            return -1;
        }

        if ((*directory = strdup(path)) == NULL)
            goto no_memory;
        if ((*filename = strdup(separator)) == NULL) {
            VIR_FREE(*directory);
            goto no_memory;
        }

    } else {
        if ((*filename = strdup(path)) == NULL)
            goto no_memory;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

int
vmwareConstructVmxPath(char *directoryName, char *name, char **vmxPath)
{
    if (directoryName != NULL) {
        if (virAsprintf(vmxPath, "%s/%s.vmx", directoryName, name) < 0) {
            virReportOOMError();
            return -1;
        }
    } else {
        if (virAsprintf(vmxPath, "%s.vmx", name) < 0) {
            virReportOOMError();
            return -1;
        }
    }
    return 0;
}

int
vmwareVmxPath(virDomainDefPtr vmdef, char **vmxPath)
{
    virDomainDiskDefPtr disk = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    int ret = -1;
    int i = 0;

    /*
     * Build VMX URL. Use the source of the first file-based harddisk
     * to deduce the path for the VMX file. Don't just use the
     * first disk, because it may be CDROM disk and ISO images are normaly not
     * located in the virtual machine's directory. This approach
     * isn't perfect but should work in the majority of cases.
     */
    if (vmdef->ndisks < 1) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Domain XML doesn't contain any disks, "
                      "cannot deduce datastore and path for VMX file"));
        goto cleanup;
    }

    for (i = 0; i < vmdef->ndisks; ++i) {
        if (vmdef->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
            vmdef->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE) {
            disk = vmdef->disks[i];
            break;
        }
    }

    if (disk == NULL) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Domain XML doesn't contain any file-based harddisks, "
                      "cannot deduce datastore and path for VMX file"));
        goto cleanup;
    }

    if (disk->src == NULL) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("First file-based harddisk has no source, cannot "
                      "deduce datastore and path for VMX file"));
        goto cleanup;
    }

    if (vmwareParsePath(disk->src, &directoryName, &fileName) < 0) {
        goto cleanup;
    }

    if (!virFileHasSuffix(fileName, ".vmdk")) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    _("Expecting source '%s' of first file-based harddisk "
                      "to be a VMDK image"), disk->src);
        goto cleanup;
    }

    if (vmwareConstructVmxPath(directoryName, vmdef->name, vmxPath) < 0) {
        virReportOOMError();
        goto cleanup;
    }

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
        { "mv", PROGRAM_SENTINAL, PROGRAM_SENTINAL, NULL };

    if (!virFileExists(srcFile)) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, _("file %s does not exist"),
                    srcFile);
        return -1;
    }

    if (STREQ(srcFile, dstFile))
        return 0;

    vmwareSetSentinal(cmdmv, srcFile);
    vmwareSetSentinal(cmdmv, dstFile);
    if (virRun(cmdmv, NULL) < 0) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    _("failed to move file to %s "), dstFile);
        return -1;
    }

    return 0;
}

int
vmwareMakePath(char *srcDir, char *srcName, char *srcExt, char **outpath)
{
    if (virAsprintf(outpath, "%s/%s.%s", srcDir, srcName, srcExt) < 0) {
        virReportOOMError();
        return -1;
    }
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
                    vmxDir) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if ((logFile = fopen(logFilePath, "r")) == NULL)
        goto cleanup;

    if (!fgets(line, sizeof(line), logFile)) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("unable to read vmware log file"));
        goto cleanup;
    }

    if ((tmp = strstr(line, " pid=")) == NULL) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot find pid in vmware log file"));
        goto cleanup;
    }

    tmp += strlen(" pid=");

    /* Although 64-bit windows allows 64-bit pid_t, a domain id has to be
     * 32 bits.  For now, we just reject pid values that overflow int.  */
    if (virStrToLong_i(tmp, &tmp, 10, &pid_value) < 0 || *tmp != ' ') {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
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
    char *path = strdup(datastorePath);

    if (path == NULL) {
        virReportOOMError();
        return NULL;
    }

    return path;
}
