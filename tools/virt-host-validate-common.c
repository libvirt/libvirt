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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>
#ifdef HAVE_MNTENT_H
# include <mntent.h>
#endif /* HAVE_MNTENT_H */
#include <sys/stat.h>

#include "viralloc.h"
#include "virfile.h"
#include "virt-host-validate-common.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_ENUM_IMPL(virHostValidateCPUFlag, VIR_HOST_VALIDATE_CPU_FLAG_LAST,
              "vmx",
              "svm",
              "sie");

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
    char *msg;

    if (quiet)
        return;

    va_start(args, format);
    if (virVasprintf(&msg, format, args) < 0) {
        perror("malloc");
        abort();
    }
    va_end(args);

    fprintf(stdout, _("%6s: Checking %-60s: "), prefix, msg);
    VIR_FREE(msg);
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

verify(ARRAY_CARDINALITY(failMessages) == VIR_HOST_VALIDATE_LAST);

static const char *failEscapeCodes[] = {
    "\033[31m",
    "\033[33m",
    "\033[34m",
};

verify(ARRAY_CARDINALITY(failEscapeCodes) == VIR_HOST_VALIDATE_LAST);

void virHostMsgFail(virHostValidateLevel level,
                    const char *format,
                    ...)
{
    va_list args;
    char *msg;

    if (quiet)
        return;

    va_start(args, format);
    if (virVasprintf(&msg, format, args) < 0) {
        perror("malloc");
        abort();
    }
    va_end(args);

    if (virHostMsgWantEscape())
        fprintf(stdout, "%s%s\033[0m (%s)\n",
                failEscapeCodes[level], _(failMessages[level]), msg);
    else
        fprintf(stdout, "%s (%s)\n",
                _(failMessages[level]), msg);
    VIR_FREE(msg);
}


int virHostValidateDeviceExists(const char *hvname,
                                const char *dev_name,
                                virHostValidateLevel level,
                                const char *hint)
{
    virHostMsgCheck(hvname, "if device %s exists", dev_name);

    if (access(dev_name, F_OK) < 0) {
        virHostMsgFail(level, "%s", hint);
        return -1;
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
        return -1;
    }

    virHostMsgPass();
    return 0;
}


int virHostValidateNamespace(const char *hvname,
                             const char *ns_name,
                             virHostValidateLevel level,
                             const char *hint)
{
    virHostMsgCheck(hvname, "for namespace %s", ns_name);
    char nspath[100];

    snprintf(nspath, sizeof(nspath), "/proc/self/ns/%s", ns_name);

    if (access(nspath, F_OK) < 0) {
        virHostMsgFail(level, "%s", hint);
        return -1;
    }

    virHostMsgPass();
    return 0;
}


virBitmapPtr virHostValidateGetCPUFlags(void)
{
    FILE *fp;
    virBitmapPtr flags = NULL;

    if (!(fp = fopen("/proc/cpuinfo", "r")))
        return NULL;

    if (!(flags = virBitmapNewQuiet(VIR_HOST_VALIDATE_CPU_FLAG_LAST)))
        goto cleanup;

    do {
        char line[1024];
        char *start;
        char **tokens;
        size_t ntokens;
        size_t i;

        if (!fgets(line, sizeof(line), fp))
            break;

        /* The line we're interested in is marked differently depending
         * on the architecture, so check possible prefixes */
        if (!STRPREFIX(line, "flags") &&
            !STRPREFIX(line, "Features") &&
            !STRPREFIX(line, "features"))
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
        if (!(tokens = virStringSplitCount(start, " ", 0, &ntokens)))
            continue;

        /* Go through all flags and check whether one of those we
         * might want to check for later on is present; if that's
         * the case, set the relevant bit in the bitmap */
        for (i = 0; i < ntokens; i++) {
            int value;

            if ((value = virHostValidateCPUFlagTypeFromString(tokens[i])) >= 0)
                ignore_value(virBitmapSetBit(flags, value));
        }

        virStringFreeListCount(tokens, ntokens);
    } while (1);

 cleanup:
    VIR_FORCE_FCLOSE(fp);

    return flags;
}


int virHostValidateLinuxKernel(const char *hvname,
                               int version,
                               virHostValidateLevel level,
                               const char *hint)
{
    struct utsname uts;
    unsigned long thisversion;

    uname(&uts);

    virHostMsgCheck(hvname, _("for Linux >= %d.%d.%d"),
                    ((version >> 16) & 0xff),
                    ((version >> 8) & 0xff),
                    (version & 0xff));

    if (STRNEQ(uts.sysname, "Linux")) {
        virHostMsgFail(level, "%s", hint);
        return -1;
    }

    if (virParseVersionString(uts.release, &thisversion, true) < 0) {
        virHostMsgFail(level, "%s", hint);
        return -1;
    }

    if (thisversion < version) {
        virHostMsgFail(level, "%s", hint);
        return -1;
    } else {
        virHostMsgPass();
        return 0;
    }
}


static int virHostValidateCGroupSupport(const char *hvname,
                                        const char *cg_name,
                                        virHostValidateLevel level,
                                        const char *config_name)
{
    virHostMsgCheck(hvname, "for cgroup '%s' controller support", cg_name);
    FILE *fp = fopen("/proc/self/cgroup", "r");
    size_t len = 0;
    char *line = NULL;
    ssize_t ret;
    bool matched = false;

    if (!fp)
        goto error;

    while ((ret = getline(&line, &len, fp)) >= 0 && !matched) {
        char **cgroups;
        char *start;
        char *end;
        size_t ncgroups;
        size_t i;

        /* Each line in this file looks like
         *
         *   4:cpu,cpuacct:/machine.slice/machine-qemu\x2dtest.scope/emulator
         *
         * Since multiple cgroups can be part of the same line and some cgroup
         * names can appear as part of other cgroup names (eg. 'cpu' is a
         * prefix for both 'cpuacct' and 'cpuset'), it's not enough to simply
         * check whether the cgroup name is present somewhere inside the file.
         *
         * Moreover, there's nothing stopping the cgroup name from appearing
         * in an unrelated mount point name as well */

        /* Look for the first colon.
         * The part we're interested in starts right after it */
        if (!(start = strchr(line, ':')))
            continue;
        start++;

        /* Look for the second colon.
         * The part we're interested in ends exactly there */
        if (!(end = strchr(start, ':')))
            continue;
        *end = '\0';

        if (!(cgroups = virStringSplitCount(start, ",", 0, &ncgroups)))
            continue;

        /* Look for the matching cgroup */
        for (i = 0; i < ncgroups; i++) {
            if (STREQ(cgroups[i], cg_name))
                matched = true;
        }

        virStringFreeListCount(cgroups, ncgroups);
    }

    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
    if (!matched)
        goto error;

    virHostMsgPass();
    return 0;

 error:
    VIR_FREE(line);
    virHostMsgFail(level, "Enable CONFIG_%s in kernel Kconfig file", config_name);
    return -1;
}

#ifdef HAVE_MNTENT_H
static int virHostValidateCGroupMount(const char *hvname,
                                      const char *cg_name,
                                      virHostValidateLevel level)
{
    virHostMsgCheck(hvname, "for cgroup '%s' controller mount-point", cg_name);
    FILE *fp = setmntent("/proc/mounts", "r");
    struct mntent ent;
    char mntbuf[1024];
    bool matched = false;

    if (!fp)
        goto error;

    while (getmntent_r(fp, &ent, mntbuf, sizeof(mntbuf)) && !matched) {
        char **opts;
        size_t nopts;
        size_t i;

        /* Ignore non-cgroup mounts */
        if (STRNEQ(ent.mnt_type, "cgroup"))
            continue;

        if (!(opts = virStringSplitCount(ent.mnt_opts, ",", 0, &nopts)))
            continue;

        /* Look for a mount option matching the cgroup name */
        for (i = 0; i < nopts; i++) {
            if (STREQ(opts[i], cg_name))
                matched = true;
        }

        virStringFreeListCount(opts, nopts);
    }
    endmntent(fp);
    if (!matched)
        goto error;

    virHostMsgPass();
    return 0;

 error:
    virHostMsgFail(level, "Mount '%s' cgroup controller (suggested at /sys/fs/cgroup/%s)",
                   cg_name, cg_name);
    return -1;
}
#else /* ! HAVE_MNTENT_H */
static int virHostValidateCGroupMount(const char *hvname,
                                      const char *cg_name,
                                      virHostValidateLevel level)
{
    virHostMsgCheck(hvname, "for cgroup '%s' controller mount-point", cg_name);
    virHostMsgFail(level, "%s", "This platform does not support cgroups");
    return -1;
}
#endif /* ! HAVE_MNTENT_H */

int virHostValidateCGroupController(const char *hvname,
                                    const char *cg_name,
                                    virHostValidateLevel level,
                                    const char *config_name)
{
    if (virHostValidateCGroupSupport(hvname,
                                     cg_name,
                                     level,
                                     config_name) < 0)
        return -1;
    if (virHostValidateCGroupMount(hvname,
                                   cg_name,
                                   level) < 0)
        return -1;
    return 0;
}

int virHostValidateIOMMU(const char *hvname,
                         virHostValidateLevel level)
{
    virBitmapPtr flags;
    struct stat sb;
    const char *bootarg = NULL;
    bool isAMD = false, isIntel = false;

    flags = virHostValidateGetCPUFlags();

    if (flags && virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_VMX))
        isIntel = true;
    else if (flags && virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SVM))
        isAMD = true;

    virBitmapFree(flags);

    virHostMsgCheck(hvname, "%s", _("for device assignment IOMMU support"));

    if (isIntel) {
        if (access("/sys/firmware/acpi/tables/DMAR", F_OK) == 0) {
            virHostMsgPass();
            bootarg = "intel_iommu=on";
        } else {
            virHostMsgFail(level,
                           "No ACPI DMAR table found, IOMMU either "
                           "disabled in BIOS or not supported by this "
                           "hardware platform");
            return -1;
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
            return -1;
        }
    } else {
        virHostMsgFail(level,
                       "Unknown if this platform has IOMMU support");
        return -1;
    }


    /* We can only check on newer kernels with iommu groups & vfio */
    if (stat("/sys/kernel/iommu_groups", &sb) < 0)
        return 0;

    if (!S_ISDIR(sb.st_mode))
        return 0;

    virHostMsgCheck(hvname, "%s", _("if IOMMU is enabled by kernel"));
    if (sb.st_nlink <= 2) {
        virHostMsgFail(level,
                       "IOMMU appears to be disabled in kernel. "
                       "Add %s to kernel cmdline arguments", bootarg);
        return -1;
    }
    virHostMsgPass();
    return 0;
}
