/*
 * virt-host-validate-common.c: Sanity check helper APIs
 *
 * Copyright (C) 2012, 2014 Red Hat, Inc.
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
 */

#include <config.h>

#include <stdarg.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include "viracpi.h"
#include "viralloc.h"
#include "vircgroup.h"
#include "virfile.h"
#include "virt-host-validate-common.h"
#include "virstring.h"
#include "virarch.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_ENUM_IMPL(virHostValidateCPUFlag,
              VIR_HOST_VALIDATE_CPU_FLAG_LAST,
              "vmx",
              "svm",
              "sie",
              "158",
              "sev");

static bool quiet;

void virHostMsgSetQuiet(bool quietFlag)
{
    quiet = quietFlag;
}

void virHostMsgCheck(const char *prefix,
                     const char *format,
                     ...)
{
    va_list args;
    g_autofree char *msg = NULL;

    if (quiet)
        return;

    va_start(args, format);
    msg = g_strdup_vprintf(format, args);
    va_end(args);

    fprintf(stdout, _("%1$6s: Checking %2$-60s: "), prefix, msg);
}

static bool virHostMsgWantEscape(void)
{
    static bool detectTty = true;
    static bool wantEscape;
    if (detectTty) {
        if (isatty(STDOUT_FILENO))
            wantEscape = true;
        detectTty = false;
    }
    return wantEscape;
}

void virHostMsgPass(void)
{
    if (quiet)
        return;

    if (virHostMsgWantEscape())
        fprintf(stdout, "\033[32m%s\033[0m\n", _("PASS"));
    else
        fprintf(stdout, "%s\n", _("PASS"));
}


static const char * failMessages[] = {
    N_("FAIL"),
    N_("WARN"),
    N_("NOTE"),
};

G_STATIC_ASSERT(G_N_ELEMENTS(failMessages) == VIR_HOST_VALIDATE_LAST);

static const char *failEscapeCodes[] = {
    "\033[31m",
    "\033[33m",
    "\033[34m",
};

G_STATIC_ASSERT(G_N_ELEMENTS(failEscapeCodes) == VIR_HOST_VALIDATE_LAST);

void virHostMsgFail(virHostValidateLevel level,
                    const char *format,
                    ...)
{
    va_list args;
    g_autofree char *msg = NULL;

    if (quiet)
        return;

    va_start(args, format);
    msg = g_strdup_vprintf(format, args);
    va_end(args);

    if (virHostMsgWantEscape())
        fprintf(stdout, "%s%s\033[0m (%s)\n",
                failEscapeCodes[level], _(failMessages[level]), msg);
    else
        fprintf(stdout, "%s (%s)\n",
                _(failMessages[level]), msg);
}


int virHostValidateDeviceExists(const char *hvname,
                                const char *dev_name,
                                virHostValidateLevel level,
                                const char *hint)
{
    virHostMsgCheck(hvname, "if device %s exists", dev_name);

    if (access(dev_name, F_OK) < 0) {
        virHostMsgFail(level, "%s", hint);
        return VIR_HOST_VALIDATE_FAILURE(level);
    }

    virHostMsgPass();
    return 0;
}


int virHostValidateDeviceAccessible(const char *hvname,
                                    const char *dev_name,
                                    virHostValidateLevel level,
                                    const char *hint)
{
    virHostMsgCheck(hvname, "if device %s is accessible", dev_name);

    if (access(dev_name, R_OK|W_OK) < 0) {
        virHostMsgFail(level, "%s", hint);
        return VIR_HOST_VALIDATE_FAILURE(level);
    }

    virHostMsgPass();
    return 0;
}


int virHostValidateNamespace(const char *hvname,
                             const char *ns_name,
                             virHostValidateLevel level,
                             const char *hint)
{
    char nspath[100];

    virHostMsgCheck(hvname, "for namespace %s", ns_name);

    g_snprintf(nspath, sizeof(nspath), "/proc/self/ns/%s", ns_name);

    if (access(nspath, F_OK) < 0) {
        virHostMsgFail(level, "%s", hint);
        return VIR_HOST_VALIDATE_FAILURE(level);
    }

    virHostMsgPass();
    return 0;
}


virBitmap *virHostValidateGetCPUFlags(void)
{
    FILE *fp;
    virBitmap *flags = NULL;

    if (!(fp = fopen("/proc/cpuinfo", "r")))
        return NULL;

    flags = virBitmapNew(VIR_HOST_VALIDATE_CPU_FLAG_LAST);

    do {
        char line[1024];
        char *start;
        g_auto(GStrv) tokens = NULL;
        GStrv next;

        if (!fgets(line, sizeof(line), fp))
            break;

        /* The line we're interested in is marked differently depending
         * on the architecture, so check possible prefixes */
        if (!STRPREFIX(line, "flags") &&
            !STRPREFIX(line, "Features") &&
            !STRPREFIX(line, "features") &&
            !STRPREFIX(line, "facilities"))
            continue;

        /* fgets() includes the trailing newline in the output buffer,
         * so we need to clean that up ourselves. We can safely access
         * line[strlen(line) - 1] because the checks above would cause
         * us to skip empty strings */
        line[strlen(line) - 1] = '\0';

        /* Skip to the separator */
        if (!(start = strchr(line, ':')))
            continue;

        /* Split the line using " " as a delimiter. The first token
         * will always be ":", but that's okay */
        if (!(tokens = g_strsplit(start, " ", 0)))
            continue;

        /* Go through all flags and check whether one of those we
         * might want to check for later on is present; if that's
         * the case, set the relevant bit in the bitmap */
        for (next = tokens; *next; next++) {
            int value;

            if ((value = virHostValidateCPUFlagTypeFromString(*next)) >= 0)
                ignore_value(virBitmapSetBit(flags, value));
        }
    } while (1);

    VIR_FORCE_FCLOSE(fp);

    return flags;
}


int virHostValidateLinuxKernel(const char *hvname,
                               int version,
                               virHostValidateLevel level,
                               const char *hint)
{
    struct utsname uts;
    unsigned long long thisversion;

    uname(&uts);

    virHostMsgCheck(hvname, _("for Linux >= %1$d.%2$d.%3$d"),
                    ((version >> 16) & 0xff),
                    ((version >> 8) & 0xff),
                    (version & 0xff));

    if (STRNEQ(uts.sysname, "Linux")) {
        virHostMsgFail(level, "%s", hint);
        return VIR_HOST_VALIDATE_FAILURE(level);
    }

    if (virStringParseVersion(&thisversion, uts.release, true) < 0) {
        virHostMsgFail(level, "%s", hint);
        return VIR_HOST_VALIDATE_FAILURE(level);
    }

    if (thisversion < version) {
        virHostMsgFail(level, "%s", hint);
        return VIR_HOST_VALIDATE_FAILURE(level);
    } else {
        virHostMsgPass();
        return 0;
    }
}

#ifdef __linux__
int virHostValidateCGroupControllers(const char *hvname,
                                     int controllers,
                                     virHostValidateLevel level)
{
    g_autoptr(virCgroup) group = NULL;
    int ret = 0;
    size_t i;

    if (virCgroupNew("/", -1, &group) < 0) {
        fprintf(stderr, "Unable to initialize cgroups: %s\n",
                virGetLastErrorMessage());
        return VIR_HOST_VALIDATE_FAILURE(level);
    }

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        int flag = 1 << i;
        const char *cg_name = virCgroupControllerTypeToString(i);

        if (!(controllers & flag))
            continue;

        virHostMsgCheck(hvname, "for cgroup '%s' controller support", cg_name);

        if (!virCgroupHasController(group, i)) {
            ret = VIR_HOST_VALIDATE_FAILURE(level);
            virHostMsgFail(level, "Enable '%s' in kernel Kconfig file or "
                           "mount/enable cgroup controller in your system",
                           cg_name);
        } else {
            virHostMsgPass();
        }
    }

    return ret;
}
#else /*  !__linux__ */
int virHostValidateCGroupControllers(const char *hvname G_GNUC_UNUSED,
                                     int controllers G_GNUC_UNUSED,
                                     virHostValidateLevel level)
{
    virHostMsgFail(level, "%s", "This platform does not support cgroups");
    return VIR_HOST_VALIDATE_FAILURE(level);
}
#endif /* !__linux__ */

int virHostValidateIOMMU(const char *hvname,
                         virHostValidateLevel level)
{
    g_autoptr(virBitmap) flags = NULL;
    struct stat sb;
    const char *bootarg = NULL;
    bool isAMD = false, isIntel = false;
    virArch arch = virArchFromHost();
    struct dirent *dent;
    int rc;

    virHostMsgCheck(hvname, "%s", _("for device assignment IOMMU support"));

    flags = virHostValidateGetCPUFlags();

    if (flags && virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_VMX))
        isIntel = true;
    else if (flags && virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SVM))
        isAMD = true;

    if (isIntel) {
        if (access("/sys/firmware/acpi/tables/DMAR", F_OK) == 0) {
            virHostMsgPass();
            bootarg = "intel_iommu=on";
        } else {
            virHostMsgFail(level,
                           "No ACPI DMAR table found, IOMMU either "
                           "disabled in BIOS or not supported by this "
                           "hardware platform");
            return VIR_HOST_VALIDATE_FAILURE(level);
        }
    } else if (isAMD) {
        if (access("/sys/firmware/acpi/tables/IVRS", F_OK) == 0) {
            virHostMsgPass();
            bootarg = "iommu=pt iommu=1";
        } else {
            virHostMsgFail(level,
                           "No ACPI IVRS table found, IOMMU either "
                           "disabled in BIOS or not supported by this "
                           "hardware platform");
            return VIR_HOST_VALIDATE_FAILURE(level);
        }
    } else if (ARCH_IS_PPC64(arch)) {
        virHostMsgPass();
    } else if (ARCH_IS_S390(arch)) {
        g_autoptr(DIR) dir = NULL;

        /* On s390x, we skip the IOMMU check if there are no PCI
         * devices (which is quite usual on s390x). If there are
         * no PCI devices the directory is still there but is
         * empty. */
        if (!virDirOpen(&dir, "/sys/bus/pci/devices")) {
            virHostMsgFail(VIR_HOST_VALIDATE_NOTE,
                           "Skipped - PCI support disabled");
            return VIR_HOST_VALIDATE_FAILURE(VIR_HOST_VALIDATE_NOTE);
        }
        rc = virDirRead(dir, &dent, NULL);
        if (rc <= 0) {
            virHostMsgFail(VIR_HOST_VALIDATE_NOTE,
                           "Skipped - No PCI devices are online");
            return VIR_HOST_VALIDATE_FAILURE(VIR_HOST_VALIDATE_NOTE);
        }
        virHostMsgPass();
    } else if (ARCH_IS_ARM(arch)) {
        if (access("/sys/firmware/acpi/tables/IORT", F_OK) != 0) {
            virHostMsgFail(level,
                           "No ACPI IORT table found, IOMMU not "
                           "supported by this hardware platform");
            return VIR_HOST_VALIDATE_FAILURE(level);
        } else {
            rc = virAcpiHasSMMU();
            if (rc < 0) {
                virHostMsgFail(level,
                               "Failed to parse ACPI IORT table");
                return VIR_HOST_VALIDATE_FAILURE(level);
            } else if (rc == 0) {
                virHostMsgFail(level,
                               "No SMMU found");
                return VIR_HOST_VALIDATE_FAILURE(level);
            } else {
                virHostMsgPass();
            }
        }
    } else {
        virHostMsgFail(level,
                       "Unknown if this platform has IOMMU support");
        return VIR_HOST_VALIDATE_FAILURE(level);
    }


    /* We can only check on newer kernels with iommu groups & vfio */
    if (stat("/sys/kernel/iommu_groups", &sb) < 0)
        return 0;

    if (!S_ISDIR(sb.st_mode))
        return 0;

    virHostMsgCheck(hvname, "%s", _("if IOMMU is enabled by kernel"));
    if (sb.st_nlink <= 2) {
        if (bootarg)
            virHostMsgFail(level,
                           "IOMMU appears to be disabled in kernel. "
                           "Add %s to kernel cmdline arguments", bootarg);
        else
            virHostMsgFail(level, "IOMMU capability not compiled into kernel.");
        return VIR_HOST_VALIDATE_FAILURE(level);
    }
    virHostMsgPass();
    return 0;
}


bool virHostKernelModuleIsLoaded(const char *module)
{
    FILE *fp;
    bool ret = false;

    if (!(fp = fopen("/proc/modules", "r")))
        return false;

    do {
        char line[1024];

        if (!fgets(line, sizeof(line), fp))
            break;

        if (STRPREFIX(line, module)) {
            ret = true;
            break;
        }

    } while (1);

    VIR_FORCE_FCLOSE(fp);

    return ret;
}


int virHostValidateSecureGuests(const char *hvname,
                                virHostValidateLevel level)
{
    g_autoptr(virBitmap) flags = NULL;
    bool hasFac158 = false;
    bool hasAMDSev = false;
    virArch arch = virArchFromHost();
    g_autofree char *cmdline = NULL;
    static const char *kIBMValues[] = {"y", "Y", "on", "ON", "oN", "On", "1"};
    g_autofree char *mod_value = NULL;

    flags = virHostValidateGetCPUFlags();

    if (flags && virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_FACILITY_158))
        hasFac158 = true;
    else if (flags && virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SEV))
        hasAMDSev = true;

    virHostMsgCheck(hvname, "%s", _("for secure guest support"));
    if (ARCH_IS_S390(arch)) {
        if (hasFac158) {
            if (!virFileIsDir("/sys/firmware/uv")) {
                virHostMsgFail(level, "IBM Secure Execution not supported by "
                                      "the currently used kernel");
                return VIR_HOST_VALIDATE_FAILURE(level);
            }

            /* we're prefix matching rather than equality matching here, because
             * kernel would treat even something like prot_virt='yFOO' as
             * enabled
             */
            if (virFileReadValueString(&cmdline, "/proc/cmdline") >= 0 &&
                virKernelCmdlineMatchParam(cmdline, "prot_virt", kIBMValues,
                                           G_N_ELEMENTS(kIBMValues),
                                           VIR_KERNEL_CMDLINE_FLAGS_SEARCH_FIRST |
                                           VIR_KERNEL_CMDLINE_FLAGS_CMP_PREFIX)) {
                virHostMsgPass();
                return 1;
            } else {
                virHostMsgFail(level,
                               "IBM Secure Execution appears to be disabled "
                               "in kernel. Add prot_virt=1 to kernel cmdline "
                               "arguments");
                return VIR_HOST_VALIDATE_FAILURE(level);
            }
        } else {
            virHostMsgFail(level, "Hardware or firmware does not provide "
                                  "support for IBM Secure Execution");
            return VIR_HOST_VALIDATE_FAILURE(level);
        }
    } else if (hasAMDSev) {
        if (virFileReadValueString(&mod_value, "/sys/module/kvm_amd/parameters/sev") < 0) {
            virHostMsgFail(level, "AMD Secure Encrypted Virtualization not "
                                  "supported by the currently used kernel");
            return VIR_HOST_VALIDATE_FAILURE(level);
        }

        if (mod_value[0] != '1' && mod_value[0] != 'Y' && mod_value[0] != 'y') {
            virHostMsgFail(level,
                           "AMD Secure Encrypted Virtualization appears to be "
                           "disabled in kernel. Add kvm_amd.sev=1 "
                           "to the kernel cmdline arguments");
            return VIR_HOST_VALIDATE_FAILURE(level);
        }

        if (virFileExists("/dev/sev")) {
            virHostMsgPass();
            return 1;
        } else {
            virHostMsgFail(level,
                           "AMD Secure Encrypted Virtualization appears to be "
                           "disabled in firmware.");
            return VIR_HOST_VALIDATE_FAILURE(level);
        }
    }

    virHostMsgFail(level,
                   "Unknown if this platform has Secure Guest support");
    return VIR_HOST_VALIDATE_FAILURE(level);
}
