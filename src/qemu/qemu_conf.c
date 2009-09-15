/*
 * qemu_conf.c: QEMU configuration management
 *
 * Copyright (C) 2006, 2007, 2008, 2009 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <mntent.h>

#include "c-ctype.h"
#include "virterror_internal.h"
#include "qemu_conf.h"
#include "uuid.h"
#include "buf.h"
#include "conf.h"
#include "util.h"
#include "memory.h"
#include "verify.h"
#include "datatypes.h"
#include "xml.h"
#include "nodeinfo.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_ENUM_DECL(virDomainDiskQEMUBus)
VIR_ENUM_IMPL(virDomainDiskQEMUBus, VIR_DOMAIN_DISK_BUS_LAST,
              "ide",
              "floppy",
              "scsi",
              "virtio",
              "xen",
              "usb",
              "uml")


VIR_ENUM_DECL(qemuDiskCacheV1)
VIR_ENUM_DECL(qemuDiskCacheV2)

VIR_ENUM_IMPL(qemuDiskCacheV1, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "off",
              "off", /* writethrough not supported, so for safety, disable */
              "on"); /* Old 'on' was equivalent to 'writeback' */

VIR_ENUM_IMPL(qemuDiskCacheV2, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback");

VIR_ENUM_DECL(qemuVideo)

VIR_ENUM_IMPL(qemuVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "std",
              "cirrus",
              "vmware",
              NULL, /* no arg needed for xen */
              NULL /* don't support vbox */);

#define PROC_MOUNT_BUF_LEN 255

int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename) {
    virConfPtr conf;
    virConfValuePtr p;
    char *user;
    char *group;
    int i;

    /* Setup 2 critical defaults */
    if (!(driver->vncListen = strdup("127.0.0.1"))) {
        virReportOOMError(NULL);
        return -1;
    }
    if (!(driver->vncTLSx509certdir = strdup(SYSCONF_DIR "/pki/libvirt-vnc"))) {
        virReportOOMError(NULL);
        return -1;
    }

#ifdef HAVE_MNTENT_H
    /* For privileged driver, try and find hugepage mount automatically.
     * Non-privileged driver requires admin to create a dir for the
     * user, chown it, and then let user configure it manually */
    if (driver->privileged &&
        !(driver->hugetlbfs_mount = virFileFindMountPoint("hugetlbfs"))) {
        if (errno != ENOENT) {
            virReportSystemError(NULL, errno, "%s",
                                 _("unable to find hugetlbfs mountpoint"));
            return -1;
        }
    }
#endif


    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access (filename, R_OK) == -1) return 0;

    conf = virConfReadFile (filename, 0);
    if (!conf) return 0;


#define CHECK_TYPE(name,typ) if (p && p->type != (typ)) {               \
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,      \
                         "remoteReadConfigFile: %s: %s: expected type " #typ "\n", \
                         filename, (name));                             \
        virConfFree(conf);                                              \
        return -1;                                                      \
    }

    p = virConfGetValue (conf, "vnc_tls");
    CHECK_TYPE ("vnc_tls", VIR_CONF_LONG);
    if (p) driver->vncTLS = p->l;

    p = virConfGetValue (conf, "vnc_tls_x509_verify");
    CHECK_TYPE ("vnc_tls_x509_verify", VIR_CONF_LONG);
    if (p) driver->vncTLSx509verify = p->l;

    p = virConfGetValue (conf, "vnc_tls_x509_cert_dir");
    CHECK_TYPE ("vnc_tls_x509_cert_dir", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncTLSx509certdir);
        if (!(driver->vncTLSx509certdir = strdup(p->str))) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_listen");
    CHECK_TYPE ("vnc_listen", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncListen);
        if (!(driver->vncListen = strdup(p->str))) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_password");
    CHECK_TYPE ("vnc_password", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncPassword);
        if (!(driver->vncPassword = strdup(p->str))) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "security_driver");
    CHECK_TYPE ("security_driver", VIR_CONF_STRING);
    if (p && p->str) {
        if (!(driver->securityDriverName = strdup(p->str))) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_sasl");
    CHECK_TYPE ("vnc_sasl", VIR_CONF_LONG);
    if (p) driver->vncSASL = p->l;

    p = virConfGetValue (conf, "vnc_sasl_dir");
    CHECK_TYPE ("vnc_sasl_dir", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncSASLdir);
        if (!(driver->vncSASLdir = strdup(p->str))) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "user");
    CHECK_TYPE ("user", VIR_CONF_STRING);
    if (!(user = strdup(p && p->str ? p->str : QEMU_USER))) {
        virReportOOMError(NULL);
        virConfFree(conf);
        return -1;
    }
    if (virGetUserID(NULL, user, &driver->user) < 0) {
        VIR_FREE(user);
        virConfFree(conf);
        return -1;
    }
    VIR_FREE(user);

    p = virConfGetValue (conf, "group");
    CHECK_TYPE ("group", VIR_CONF_STRING);
    if (!(group = strdup(p && p->str ? p->str : QEMU_GROUP))) {
        virReportOOMError(NULL);
        virConfFree(conf);
        return -1;
    }


    if (virGetGroupID(NULL, group, &driver->group) < 0) {
        VIR_FREE(group);
        virConfFree(conf);
        return -1;
    }
    VIR_FREE(group);

    p = virConfGetValue (conf, "cgroup_controllers");
    CHECK_TYPE ("cgroup_controllers", VIR_CONF_LIST);
    if (p) {
        virConfValuePtr pp;
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            int ctl;
            if (pp->type != VIR_CONF_STRING) {
                VIR_ERROR("%s", _("cgroup_device_acl must be a list of strings"));
                virConfFree(conf);
                return -1;
            }
            ctl = virCgroupControllerTypeFromString(pp->str);
            if (ctl < 0) {
                VIR_ERROR("Unknown cgroup controller '%s'", pp->str);
                virConfFree(conf);
                return -1;
            }
            driver->cgroupControllers |= (1 << ctl);
        }
    } else {
        driver->cgroupControllers =
            (1 << VIR_CGROUP_CONTROLLER_CPU) |
            (1 << VIR_CGROUP_CONTROLLER_DEVICES);
    }
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        if (driver->cgroupControllers & (1 << i)) {
            VIR_INFO("Configured cgroup controller '%s'",
                     virCgroupControllerTypeToString(i));
        }
    }

    p = virConfGetValue (conf, "cgroup_device_acl");
    CHECK_TYPE ("cgroup_device_acl", VIR_CONF_LIST);
    if (p) {
        int len = 0;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(driver->cgroupDeviceACL, 1+len) < 0) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                VIR_ERROR("%s", _("cgroup_device_acl must be a list of strings"));
                virConfFree(conf);
                return -1;
            }
            driver->cgroupDeviceACL[i] = strdup (pp->str);
            if (driver->cgroupDeviceACL[i] == NULL) {
                virReportOOMError(NULL);
                virConfFree(conf);
                return -1;
            }

        }
        driver->cgroupDeviceACL[i] = NULL;
    }

    p = virConfGetValue (conf, "save_image_format");
    CHECK_TYPE ("save_image_format", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->saveImageFormat);
        if (!(driver->saveImageFormat = strdup(p->str))) {
            virReportOOMError(NULL);
            virConfFree(conf);
            return -1;
        }
    }

     p = virConfGetValue (conf, "hugetlbfs_mount");
     CHECK_TYPE ("hugetlbfs_mount", VIR_CONF_STRING);
     if (p && p->str) {
         VIR_FREE(driver->hugetlbfs_mount);
         if (!(driver->hugetlbfs_mount = strdup(p->str))) {
             virReportOOMError(NULL);
             virConfFree(conf);
             return -1;
         }
     }

    virConfFree (conf);
    return 0;
}

struct qemu_feature_flags {
    const char *name;
    const int default_on;
    const int toggle;
};

struct qemu_arch_info {
    const char *arch;
    int wordsize;
    const char *machine;
    const char *binary;
    const char *altbinary;
    const struct qemu_feature_flags *flags;
    int nflags;
};

/* Feature flags for the architecture info */
static const struct qemu_feature_flags const arch_info_i686_flags [] = {
    { "pae",  1, 0 },
    { "nonpae",  1, 0 },
    { "acpi", 1, 1 },
    { "apic", 1, 0 },
};

static const struct qemu_feature_flags const arch_info_x86_64_flags [] = {
    { "acpi", 1, 1 },
    { "apic", 1, 0 },
};

/* The archicture tables for supported QEMU archs */
static const struct qemu_arch_info const arch_info_hvm[] = {
    {  "i686",   32, NULL, "/usr/bin/qemu",
       "/usr/bin/qemu-system-x86_64", arch_info_i686_flags, 4 },
    {  "x86_64", 64, NULL, "/usr/bin/qemu-system-x86_64",
       NULL, arch_info_x86_64_flags, 2 },
    {  "arm",    32, NULL, "/usr/bin/qemu-system-arm",    NULL, NULL, 0 },
    {  "mips",   32, NULL, "/usr/bin/qemu-system-mips",   NULL, NULL, 0 },
    {  "mipsel", 32, NULL, "/usr/bin/qemu-system-mipsel", NULL, NULL, 0 },
    {  "sparc",  32, NULL, "/usr/bin/qemu-system-sparc",  NULL, NULL, 0 },
    {  "ppc",    32, NULL, "/usr/bin/qemu-system-ppc",    NULL, NULL, 0 },
};

static const struct qemu_arch_info const arch_info_xen[] = {
    {  "i686",   32, "xenner", "/usr/bin/xenner", NULL, arch_info_i686_flags, 4 },
    {  "x86_64", 64, "xenner", "/usr/bin/xenner", NULL, arch_info_x86_64_flags, 2 },
};


/* Format is:
 * <machine> <desc> [(default)|(alias of <canonical>)]
 */
static int
qemudParseMachineTypesStr(const char *output,
                          virCapsGuestMachinePtr **machines,
                          int *nmachines)
{
    const char *p = output;
    const char *next;
    virCapsGuestMachinePtr *list = NULL;
    int nitems = 0;

    do {
        const char *t;
        virCapsGuestMachinePtr machine;

        if ((next = strchr(p, '\n')))
            ++next;

        if (STRPREFIX(p, "Supported machines are:"))
            continue;

        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (VIR_ALLOC(machine) < 0)
            goto error;

        if (!(machine->name = strndup(p, t - p))) {
            VIR_FREE(machine);
            goto error;
        }

        if (VIR_REALLOC_N(list, nitems + 1) < 0) {
            VIR_FREE(machine->name);
            VIR_FREE(machine);
            goto error;
        }

        p = t;
        if (!(t = strstr(p, "(default)")) || (next && t >= next)) {
            list[nitems++] = machine;
        } else {
            /* put the default first in the list */
            memmove(list + 1, list, sizeof(*list) * nitems);
            list[0] = machine;
            nitems++;
        }

        if ((t = strstr(p, "(alias of ")) && (!next || t < next)) {
            p = t + strlen("(alias of ");
            if (!(t = strchr(p, ')')) || (next && t >= next))
                continue;

            if (!(machine->canonical = strndup(p, t - p)))
                goto error;
        }
    } while ((p = next));

    *machines = list;
    *nmachines = nitems;

    return 0;

error:
    virCapabilitiesFreeMachines(list, nitems);
    return -1;
}

int
qemudProbeMachineTypes(const char *binary,
                       virCapsGuestMachinePtr **machines,
                       int *nmachines)
{
    const char *const qemuarg[] = { binary, "-M", "?", NULL };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    char *output;
    enum { MAX_MACHINES_OUTPUT_SIZE = 1024*4 };
    pid_t child;
    int newstdout = -1, len;
    int ret = -1, status;

    if (virExec(NULL, qemuarg, qemuenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_CLEAR_CAPS) < 0)
        return -1;

    len = virFileReadLimFD(newstdout, MAX_MACHINES_OUTPUT_SIZE, &output);
    if (len < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Unable to read 'qemu -M ?' output"));
        goto cleanup;
    }

    if (qemudParseMachineTypesStr(output, machines, nmachines) < 0)
        goto cleanup2;

    ret = 0;

cleanup2:
    VIR_FREE(output);
cleanup:
    if (close(newstdout) < 0)
        ret = -1;

rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        VIR_ERROR(_("Unexpected exit status from qemu %d pid %lu"),
                  WEXITSTATUS(status), (unsigned long)child);
        ret = -1;
    }
    /* Check & log unexpected exit status, but don't fail,
     * as there's really no need to throw an error if we did
     * actually read a valid version number above */
    if (WEXITSTATUS(status) != 0) {
        VIR_WARN(_("Unexpected exit status '%d', qemu probably failed"),
                 WEXITSTATUS(status));
    }

    return ret;
}

static int
qemudGetOldMachinesFromInfo(virCapsGuestDomainInfoPtr info,
                            const char *emulator,
                            time_t emulator_mtime,
                            virCapsGuestMachinePtr **machines,
                            int *nmachines)
{
    virCapsGuestMachinePtr *list;
    int i;

    if (!info->emulator || !STREQ(emulator, info->emulator))
        return 0;

    if (emulator_mtime != info->emulator_mtime) {
        VIR_DEBUG("mtime on %s has changed, refreshing machine types",
                  info->emulator);
        return 0;
    }

    if (VIR_ALLOC_N(list, info->nmachines) < 0)
        return 0;

    for (i = 0; i < info->nmachines; i++) {
        if (VIR_ALLOC(list[i]) < 0) {
            virCapabilitiesFreeMachines(list, info->nmachines);
            return 0;
        }
        if (info->machines[i]->name &&
            !(list[i]->name = strdup(info->machines[i]->name))) {
            virCapabilitiesFreeMachines(list, info->nmachines);
            return 0;
        }
        if (info->machines[i]->canonical &&
            !(list[i]->canonical = strdup(info->machines[i]->canonical))) {
            virCapabilitiesFreeMachines(list, info->nmachines);
            return 0;
        }
    }

    *machines = list;
    *nmachines = info->nmachines;

    return 1;
}

static int
qemudGetOldMachines(const char *ostype,
                    const char *arch,
                    int wordsize,
                    const char *emulator,
                    time_t emulator_mtime,
                    virCapsPtr old_caps,
                    virCapsGuestMachinePtr **machines,
                    int *nmachines)
{
    int i;

    for (i = 0; i < old_caps->nguests; i++) {
        virCapsGuestPtr guest = old_caps->guests[i];
        int j;

        if (!STREQ(ostype, guest->ostype) ||
            !STREQ(arch, guest->arch.name) ||
            wordsize != guest->arch.wordsize)
            continue;

        for (j = 0; j < guest->arch.ndomains; j++) {
            virCapsGuestDomainPtr dom = guest->arch.domains[j];

            if (qemudGetOldMachinesFromInfo(&dom->info,
                                            emulator, emulator_mtime,
                                            machines, nmachines))
                return 1;
        }

        if (qemudGetOldMachinesFromInfo(&guest->arch.defaultInfo,
                                        emulator, emulator_mtime,
                                        machines, nmachines))
            return 1;
    }

    return 0;
}

static int
qemudCapsInitGuest(virCapsPtr caps,
                   virCapsPtr old_caps,
                   const char *hostmachine,
                   const struct qemu_arch_info *info,
                   int hvm) {
    virCapsGuestPtr guest;
    int i;
    int haskvm = 0;
    int haskqemu = 0;
    const char *kvmbin = NULL;
    const char *binary = NULL;
    time_t binary_mtime;
    virCapsGuestMachinePtr *machines = NULL;
    int nmachines = 0;
    struct stat st;

    /* Check for existance of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    if (access(info->binary, X_OK) == 0)
        binary = info->binary;
    else if (info->altbinary && access(info->altbinary, X_OK) == 0)
        binary = info->altbinary;

    /* Can use acceleration for KVM/KQEMU if
     *  - host & guest arches match
     * Or
     *  - hostarch is x86_64 and guest arch is i686
     * The latter simply needs "-cpu qemu32"
     */
    if (STREQ(info->arch, hostmachine) ||
        (STREQ(hostmachine, "x86_64") && STREQ(info->arch, "i686"))) {
        const char *const kvmbins[] = { "/usr/bin/qemu-kvm", /* Fedora */
                                        "/usr/bin/kvm" }; /* Upstream .spec */

        for (i = 0; i < ARRAY_CARDINALITY(kvmbins); ++i) {
            if (access(kvmbins[i], X_OK) == 0 &&
                access("/dev/kvm", F_OK) == 0) {
                haskvm = 1;
                kvmbin = kvmbins[i];
                if (!binary)
                    binary = kvmbin;
                break;
            }
        }

        if (access("/dev/kqemu", F_OK) == 0)
            haskqemu = 1;
    }

    if (!binary)
        return 0;

    if (stat(binary, &st) == 0) {
        binary_mtime = st.st_mtime;
    } else {
        char ebuf[1024];
        VIR_WARN(_("Failed to stat %s, most peculiar : %s"),
                 binary, virStrerror(errno, ebuf, sizeof(ebuf)));
        binary_mtime = 0;
    }

    if (info->machine) {
        virCapsGuestMachinePtr machine;

        if (VIR_ALLOC(machine) < 0)
            return -1;

        if (!(machine->name = strdup(info->machine))) {
            VIR_FREE(machine);
            return -1;
        }

        if (VIR_ALLOC_N(machines, nmachines) < 0) {
            VIR_FREE(machine->name);
            VIR_FREE(machine);
            return -1;
        }

        machines[0] = machine;
        nmachines = 1;
    } else {
        int probe = 1;
        if (old_caps && binary_mtime)
            probe = !qemudGetOldMachines(hvm ? "hvm" : "xen", info->arch,
                                         info->wordsize, binary, binary_mtime,
                                         old_caps, &machines, &nmachines);
        if (probe &&
            qemudProbeMachineTypes(binary, &machines, &nmachines) < 0)
            return -1;
    }

    /* We register kvm as the base emulator too, since we can
     * just give -no-kvm to disable acceleration if required */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         hvm ? "hvm" : "xen",
                                         info->arch,
                                         info->wordsize,
                                         binary,
                                         NULL,
                                         nmachines,
                                         machines)) == NULL) {
        for (i = 0; i < nmachines; i++) {
            VIR_FREE(machines[i]->name);
            VIR_FREE(machines[i]);
        }
        VIR_FREE(machines);
        return -1;
    }

    guest->arch.defaultInfo.emulator_mtime = binary_mtime;

    if (hvm) {
        if (virCapabilitiesAddGuestDomain(guest,
                                          "qemu",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            return -1;

        if (haskqemu &&
            virCapabilitiesAddGuestDomain(guest,
                                          "kqemu",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            return -1;

        if (haskvm) {
            virCapsGuestDomainPtr dom;

            if (stat(kvmbin, &st) == 0) {
                binary_mtime = st.st_mtime;
            } else {
                char ebuf[1024];
                VIR_WARN(_("Failed to stat %s, most peculiar : %s"),
                         binary, virStrerror(errno, ebuf, sizeof(ebuf)));
                binary_mtime = 0;
            }

            machines = NULL;
            nmachines = 0;

            if (!STREQ(binary, kvmbin)) {
                int probe = 1;
                if (old_caps && binary_mtime)
                    probe = !qemudGetOldMachines("hvm", info->arch, info->wordsize,
                                                 kvmbin, binary_mtime,
                                                 old_caps, &machines, &nmachines);
                if (probe &&
                    qemudProbeMachineTypes(kvmbin, &machines, &nmachines) < 0)
                    return -1;
            }

            if ((dom = virCapabilitiesAddGuestDomain(guest,
                                                     "kvm",
                                                     kvmbin,
                                                     NULL,
                                                     nmachines,
                                                     machines)) == NULL) {
                for (i = 0; i < nmachines; i++) {
                    VIR_FREE(machines[i]->name);
                    VIR_FREE(machines[i]);
                }
                VIR_FREE(machines);
                return -1;
            }

            dom->info.emulator_mtime = binary_mtime;
        }
    } else {
        if (virCapabilitiesAddGuestDomain(guest,
                                          "kvm",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            return -1;
    }

    if (info->nflags) {
        for (i = 0 ; i < info->nflags ; i++) {
            if (virCapabilitiesAddGuestFeature(guest,
                                               info->flags[i].name,
                                               info->flags[i].default_on,
                                               info->flags[i].toggle) == NULL)
                return -1;
        }
    }

    return 0;
}

virCapsPtr qemudCapsInit(virCapsPtr old_caps) {
    struct utsname utsname;
    virCapsPtr caps;
    int i;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   1, 1)) == NULL)
        goto no_memory;

    /* Using KVM's mac prefix for QEMU too */
    virCapabilitiesSetMacPrefix(caps, (unsigned char[]){ 0x52, 0x54, 0x00 });

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN0("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    virCapabilitiesAddHostMigrateTransport(caps,
                                           "tcp");

    /* First the pure HVM guests */
    for (i = 0 ; i < ARRAY_CARDINALITY(arch_info_hvm) ; i++)
        if (qemudCapsInitGuest(caps, old_caps,
                               utsname.machine,
                               &arch_info_hvm[i], 1) < 0)
            goto no_memory;

    /* Then possibly the Xen paravirt guests (ie Xenner */
    if (access("/usr/bin/xenner", X_OK) == 0 &&
        access("/dev/kvm", F_OK) == 0) {
        for (i = 0 ; i < ARRAY_CARDINALITY(arch_info_xen) ; i++)
            /* Allow Xen 32-on-32, 32-on-64 and 64-on-64 */
            if (STREQ(arch_info_xen[i].arch, utsname.machine) ||
                (STREQ(utsname.machine, "x86_64") &&
                 STREQ(arch_info_xen[i].arch, "i686"))) {
                if (qemudCapsInitGuest(caps, old_caps,
                                       utsname.machine,
                                       &arch_info_xen[i], 0) < 0)
                    goto no_memory;
            }
    }

    /* QEMU Requires an emulator in the XML */
    virCapabilitiesSetEmulatorRequired(caps);

    return caps;

 no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}

static unsigned int qemudComputeCmdFlags(const char *help,
                                         unsigned int version,
                                         unsigned int is_kvm,
                                         unsigned int kvm_version)
{
    unsigned int flags = 0;

    if (strstr(help, "-no-kqemu"))
        flags |= QEMUD_CMD_FLAG_KQEMU;
    if (strstr(help, "-no-kvm"))
        flags |= QEMUD_CMD_FLAG_KVM;
    if (strstr(help, "-no-reboot"))
        flags |= QEMUD_CMD_FLAG_NO_REBOOT;
    if (strstr(help, "-name"))
        flags |= QEMUD_CMD_FLAG_NAME;
    if (strstr(help, "-uuid"))
        flags |= QEMUD_CMD_FLAG_UUID;
    if (strstr(help, "-domid"))
        flags |= QEMUD_CMD_FLAG_DOMID;
    if (strstr(help, "-drive")) {
        flags |= QEMUD_CMD_FLAG_DRIVE;
        if (strstr(help, "cache=writethrough|writeback|none"))
            flags |= QEMUD_CMD_FLAG_DRIVE_CACHE_V2;
        if (strstr(help, "format="))
            flags |= QEMUD_CMD_FLAG_DRIVE_FORMAT;
    }
    if (strstr(help, "-vga") && !strstr(help, "-std-vga"))
        flags |= QEMUD_CMD_FLAG_VGA;
    if (strstr(help, "boot=on"))
        flags |= QEMUD_CMD_FLAG_DRIVE_BOOT;
    if (strstr(help, "serial=s"))
        flags |= QEMUD_CMD_FLAG_DRIVE_SERIAL;
    if (strstr(help, "-pcidevice"))
        flags |= QEMUD_CMD_FLAG_PCIDEVICE;
    if (strstr(help, "-mem-path"))
        flags |= QEMUD_CMD_FLAG_MEM_PATH;

    if (version >= 9000)
        flags |= QEMUD_CMD_FLAG_VNC_COLON;

    if (is_kvm && (version >= 10000 || kvm_version >= 74))
        flags |= QEMUD_CMD_FLAG_VNET_HDR;

    /*
     * Handling of -incoming arg with varying features
     *  -incoming tcp    (kvm >= 79, qemu >= 0.10.0)
     *  -incoming exec   (kvm >= 80, qemu >= 0.10.0)
     *  -incoming stdio  (all earlier kvm)
     *
     * NB, there was a pre-kvm-79 'tcp' support, but it
     * was broken, because it blocked the monitor console
     * while waiting for data, so pretend it doesn't exist
     */
    if (version >= 10000) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP;
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC;
    } else if (kvm_version >= 79) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP;
        if (kvm_version >= 80)
            flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC;
    } else if (kvm_version > 0) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO;
    }

    if (version >= 10000)
        flags |= QEMUD_CMD_FLAG_0_10;

    return flags;
}

/* We parse the output of 'qemu -help' to get the QEMU
 * version number. The first bit is easy, just parse
 * 'QEMU PC emulator version x.y.z'.
 *
 * With qemu-kvm, however, that is followed by a string
 * in parenthesis as follows:
 *  - qemu-kvm-x.y.z in stable releases
 *  - kvm-XX for kvm versions up to kvm-85
 *  - qemu-kvm-devel-XX for kvm version kvm-86 and later
 *
 * For qemu-kvm versions before 0.10.z, we need to detect
 * the KVM version number for some features. With 0.10.z
 * and later, we just need the QEMU version number and
 * whether it is KVM QEMU or mainline QEMU.
 */
#define QEMU_VERSION_STR    "QEMU PC emulator version"
#define QEMU_KVM_VER_PREFIX "(qemu-kvm-"
#define KVM_VER_PREFIX      "(kvm-"

#define SKIP_BLANKS(p) do { while ((*(p) == ' ') || (*(p) == '\t')) (p)++; } while (0)

int qemudParseHelpStr(const char *help,
                      unsigned int *flags,
                      unsigned int *version,
                      unsigned int *is_kvm,
                      unsigned int *kvm_version)
{
    unsigned major, minor, micro;
    const char *p = help;

    *flags = *version = *is_kvm = *kvm_version = 0;

    if (!STRPREFIX(p, QEMU_VERSION_STR))
        goto fail;

    p += strlen(QEMU_VERSION_STR);

    SKIP_BLANKS(p);

    major = virParseNumber(&p);
    if (major == -1 || *p != '.')
        goto fail;

    ++p;

    minor = virParseNumber(&p);
    if (major == -1 || *p != '.')
        goto fail;

    ++p;

    micro = virParseNumber(&p);
    if (major == -1)
        goto fail;

    SKIP_BLANKS(p);

    if (STRPREFIX(p, QEMU_KVM_VER_PREFIX)) {
        *is_kvm = 1;
        p += strlen(QEMU_KVM_VER_PREFIX);
    } else if (STRPREFIX(p, KVM_VER_PREFIX)) {
        int ret;

        *is_kvm = 1;
        p += strlen(KVM_VER_PREFIX);

        ret = virParseNumber(&p);
        if (ret == -1)
            goto fail;

        *kvm_version = ret;
    }

    *version = (major * 1000 * 1000) + (minor * 1000) + micro;

    *flags = qemudComputeCmdFlags(help, *version, *is_kvm, *kvm_version);

    qemudDebug("Version %u.%u.%u, cooked version %u, flags %u",
               major, minor, micro, *version, *flags);
    if (*kvm_version)
        qemudDebug("KVM version %d detected", *kvm_version);
    else if (*is_kvm)
        qemudDebug("qemu-kvm version %u.%u.%u detected", major, minor, micro);

    return 0;

fail:
    p = strchr(help, '\n');
    if (p)
        p = strndup(help, p - help);

    qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("cannot parse QEMU version number in '%s'"),
                     p ? p : help);

    VIR_FREE(p);

    return -1;
}

int qemudExtractVersionInfo(const char *qemu,
                            unsigned int *retversion,
                            unsigned int *retflags) {
    const char *const qemuarg[] = { qemu, "-help", NULL };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    pid_t child;
    int newstdout = -1;
    int ret = -1, status;
    unsigned int version, is_kvm, kvm_version;
    unsigned int flags = 0;

    if (retflags)
        *retflags = 0;
    if (retversion)
        *retversion = 0;

    if (virExec(NULL, qemuarg, qemuenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_CLEAR_CAPS) < 0)
        return -1;

    char *help = NULL;
    enum { MAX_HELP_OUTPUT_SIZE = 1024*64 };
    int len = virFileReadLimFD(newstdout, MAX_HELP_OUTPUT_SIZE, &help);
    if (len < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Unable to read QEMU help output"));
        goto cleanup2;
    }

    if (qemudParseHelpStr(help, &flags, &version, &is_kvm, &kvm_version) == -1)
        goto cleanup2;

    if (retversion)
        *retversion = version;
    if (retflags)
        *retflags = flags;

    ret = 0;

cleanup2:
    VIR_FREE(help);
    if (close(newstdout) < 0)
        ret = -1;

rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        VIR_ERROR(_("Unexpected exit status from qemu %d pid %lu"),
                  WEXITSTATUS(status), (unsigned long)child);
        ret = -1;
    }
    /* Check & log unexpected exit status, but don't fail,
     * as there's really no need to throw an error if we did
     * actually read a valid version number above */
    if (WEXITSTATUS(status) != 0) {
        VIR_WARN(_("Unexpected exit status '%d', qemu probably failed"),
                 WEXITSTATUS(status));
    }

    return ret;
}

static void
uname_normalize (struct utsname *ut)
{
    uname(ut);

    /* Map i386, i486, i586 to i686.  */
    if (ut->machine[0] == 'i' &&
        ut->machine[1] != '\0' &&
        ut->machine[2] == '8' &&
        ut->machine[3] == '6' &&
        ut->machine[4] == '\0')
        ut->machine[1] = '6';
}

int qemudExtractVersion(virConnectPtr conn,
                        struct qemud_driver *driver) {
    const char *binary;
    struct stat sb;
    struct utsname ut;

    if (driver->qemuVersion > 0)
        return 0;

    uname_normalize(&ut);
    if ((binary = virCapabilitiesDefaultGuestEmulator(driver->caps,
                                                      "hvm",
                                                      ut.machine,
                                                      "qemu")) == NULL)
        return -1;

    if (stat(binary, &sb) < 0) {
        char ebuf[1024];
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot find QEMU binary %s: %s"), binary,
                         virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    }

    if (qemudExtractVersionInfo(binary, &driver->qemuVersion, NULL) < 0) {
        return -1;
    }

    return 0;
}


int
qemudNetworkIfaceConnect(virConnectPtr conn,
                         struct qemud_driver *driver,
                         virDomainNetDefPtr net,
                         int qemuCmdFlags)
{
    char *brname = NULL;
    int err;
    int tapfd = -1;
    int vnet_hdr = 0;
    int template_ifname = 0;

    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        virNetworkPtr network = virNetworkLookupByName(conn,
                                                      net->data.network.name);
        if (!network)
            return -1;

        brname = virNetworkGetBridgeName(network);

        virNetworkFree(network);

        if (brname == NULL)
            return -1;
    } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        brname = strdup(net->data.bridge.brname);
    } else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Network type %d is not supported"), net->type);
        return -1;
    }

    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        virReportSystemError(conn, err, "%s",
                             _("cannot initialize bridge support"));
        goto cleanup;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, "vnet") ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (!(net->ifname = strdup("vnet%d"))) {
            virReportOOMError(conn);
            goto cleanup;
        }
        /* avoid exposing vnet%d in dumpxml or error outputs */
        template_ifname = 1;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_VNET_HDR &&
        net->model && STREQ(net->model, "virtio"))
        vnet_hdr = 1;

    if ((err = brAddTap(driver->brctl, brname,
                        &net->ifname, vnet_hdr, &tapfd))) {
        if (errno == ENOTSUP) {
            /* In this particular case, give a better diagnostic. */
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to add tap interface to bridge. "
                               "%s is not a bridge device"), brname);
        } else if (template_ifname) {
            virReportSystemError(conn, err,
                                 _("Failed to add tap interface to bridge '%s'"),
                                 brname);
        } else {
            virReportSystemError(conn, err,
                                 _("Failed to add tap interface '%s' to bridge '%s'"),
                                 net->ifname, brname);
        }
        if (template_ifname)
            VIR_FREE(net->ifname);
        tapfd = -1;
    }

cleanup:
    VIR_FREE(brname);

    return tapfd;
}

static const char *
qemuNetTypeToHostNet(int type)
{
    switch (type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        return "tap";

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        return "socket";

    case VIR_DOMAIN_NET_TYPE_USER:
    default:
        return "user";
    }
}

int
qemuAssignNetNames(virDomainDefPtr def,
                   virDomainNetDefPtr net)
{
    char *nic_name, *hostnet_name;
    int i, nic_index = 0, hostnet_index = 0;

    for (i = 0; i < def->nnets; i++) {
        if (def->nets[i] == net)
            continue;

        if (!def->nets[i]->nic_name || !def->nets[i]->hostnet_name)
            continue;

        if ((def->nets[i]->model == NULL && net->model == NULL) ||
            (def->nets[i]->model != NULL && net->model != NULL &&
             STREQ(def->nets[i]->model, net->model)))
            ++nic_index;

        if (STREQ(qemuNetTypeToHostNet(def->nets[i]->type),
                  qemuNetTypeToHostNet(net->type)))
            ++hostnet_index;
    }

    if (virAsprintf(&nic_name, "%s.%d",
                    net->model ? net->model : "nic",
                    nic_index) < 0)
        return -1;

    if (virAsprintf(&hostnet_name, "%s.%d",
                    qemuNetTypeToHostNet(net->type),
                    hostnet_index) < 0) {
        VIR_FREE(nic_name);
        return -1;
    }

    net->nic_name = nic_name;
    net->hostnet_name = hostnet_name;

    return 0;
}

int
qemuBuildNicStr(virConnectPtr conn,
                virDomainNetDefPtr net,
                const char *prefix,
                char type_sep,
                int vlan,
                char **str)
{
    if (virAsprintf(str,
                    "%snic%cmacaddr=%02x:%02x:%02x:%02x:%02x:%02x,vlan=%d%s%s%s%s",
                    prefix ? prefix : "",
                    type_sep,
                    net->mac[0], net->mac[1],
                    net->mac[2], net->mac[3],
                    net->mac[4], net->mac[5],
                    vlan,
                    (net->model ? ",model=" : ""),
                    (net->model ? net->model : ""),
                    (net->nic_name ? ",name=" : ""),
                    (net->nic_name ? net->nic_name : "")) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    return 0;
}

int
qemuBuildHostNetStr(virConnectPtr conn,
                    virDomainNetDefPtr net,
                    const char *prefix,
                    char type_sep,
                    int vlan,
                    const char *tapfd,
                    char **str)
{
    switch (net->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (virAsprintf(str, "%stap%cfd=%s,vlan=%d%s%s",
                        prefix ? prefix : "",
                        type_sep, tapfd, vlan,
                        (net->hostnet_name ? ",name=" : ""),
                        (net->hostnet_name ? net->hostnet_name : "")) < 0) {
            virReportOOMError(conn);
            return -1;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        {
            virBuffer buf = VIR_BUFFER_INITIALIZER;

            if (prefix)
                virBufferAdd(&buf, prefix, strlen(prefix));
            virBufferAddLit(&buf, "tap");
            if (net->ifname) {
                virBufferVSprintf(&buf, "%cifname=%s", type_sep, net->ifname);
                type_sep = ',';
            }
            if (net->data.ethernet.script) {
                virBufferVSprintf(&buf, "%cscript=%s", type_sep,
                                  net->data.ethernet.script);
                type_sep = ',';
            }
            virBufferVSprintf(&buf, "%cvlan=%d", type_sep, vlan);
            if (net->hostnet_name) {
                virBufferVSprintf(&buf, "%cname=%s", type_sep,
                                  net->hostnet_name);
                type_sep = ','; /* dead-store, but leave it, in case... */
            }
            if (virBufferError(&buf)) {
                virReportOOMError(conn);
                return -1;
            }

            *str = virBufferContentAndReset(&buf);
        }
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        {
            const char *mode = NULL;

            switch (net->type) {
            case VIR_DOMAIN_NET_TYPE_CLIENT:
                mode = "connect";
                break;
            case VIR_DOMAIN_NET_TYPE_SERVER:
                mode = "listen";
                break;
            case VIR_DOMAIN_NET_TYPE_MCAST:
                mode = "mcast";
                break;
            }

            if (virAsprintf(str, "%ssocket%c%s=%s:%d,vlan=%d%s%s",
                            prefix ? prefix : "",
                            type_sep, mode,
                            net->data.socket.address,
                            net->data.socket.port,
                            vlan,
                            (net->hostnet_name ? ",name=" : ""),
                            (net->hostnet_name ? net->hostnet_name : "")) < 0) {
                virReportOOMError(conn);
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
    default:
        if (virAsprintf(str, "%suser%cvlan=%d%s%s",
                        prefix ? prefix : "",
                        type_sep, vlan,
                        (net->hostnet_name ? ",name=" : ""),
                        (net->hostnet_name ? net->hostnet_name : "")) < 0) {
            virReportOOMError(conn);
            return -1;
        }
        break;
    }

    return 0;
}

static int qemudBuildCommandLineChrDevStr(virDomainChrDefPtr dev,
                                          char *buf,
                                          int buflen)
{
    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        strncpy(buf, "null", buflen);
        buf[buflen-1] = '\0';
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        strncpy(buf, "vc", buflen);
        buf[buflen-1] = '\0';
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        strncpy(buf, "pty", buflen);
        buf[buflen-1] = '\0';
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (snprintf(buf, buflen, "%s",
                     dev->data.file.path) >= buflen)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        if (snprintf(buf, buflen, "file:%s",
                     dev->data.file.path) >= buflen)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (snprintf(buf, buflen, "pipe:%s",
                     dev->data.file.path) >= buflen)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        strncpy(buf, "stdio", buflen);
        buf[buflen-1] = '\0';
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (snprintf(buf, buflen, "udp:%s:%s@%s:%s",
                     dev->data.udp.connectHost,
                     dev->data.udp.connectService,
                     dev->data.udp.bindHost,
                     dev->data.udp.bindService) >= buflen)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET) {
            if (snprintf(buf, buflen, "telnet:%s:%s%s",
                         dev->data.tcp.host,
                         dev->data.tcp.service,
                         dev->data.tcp.listen ? ",server,nowait" : "") >= buflen)
                return -1;
        } else {
            if (snprintf(buf, buflen, "tcp:%s:%s%s",
                         dev->data.tcp.host,
                         dev->data.tcp.service,
                         dev->data.tcp.listen ? ",server,nowait" : "") >= buflen)
                return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (snprintf(buf, buflen, "unix:%s%s",
                     dev->data.nix.path,
                     dev->data.nix.listen ? ",server,nowait" : "") >= buflen)
            return -1;
        break;
    }

    return 0;
}

#define QEMU_SERIAL_PARAM_ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

static int
qemuSafeSerialParamValue(virConnectPtr conn,
                         const char *value)
{
    if (strspn(value, QEMU_SERIAL_PARAM_ACCEPTED_CHARS) != strlen (value)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("driver serial '%s' contains unsafe characters"),
                         value);
        return -1;
    }

    return 0;
}

/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 */
int qemudBuildCommandLine(virConnectPtr conn,
                          struct qemud_driver *driver,
                          virDomainDefPtr def,
                          virDomainChrDefPtr monitor_chr,
                          unsigned int qemuCmdFlags,
                          const char ***retargv,
                          const char ***retenv,
                          int **tapfds,
                          int *ntapfds,
                          const char *migrateFrom) {
    int i;
    char memory[50];
    char vcpus[50];
    char boot[VIR_DOMAIN_BOOT_LAST];
    struct utsname ut;
    int disableKQEMU = 0;
    int disableKVM = 0;
    int qargc = 0, qarga = 0;
    const char **qargv = NULL;
    int qenvc = 0, qenva = 0;
    const char **qenv = NULL;
    const char *emulator;
    char uuid[VIR_UUID_STRING_BUFLEN];
    char domid[50];
    const char *cpu = NULL;

    uname_normalize(&ut);

    virUUIDFormat(def->uuid, uuid);

    /* Migration is very annoying due to wildly varying syntax & capabilities
     * over time of KVM / QEMU codebases
     */
    if (migrateFrom) {
        if (STRPREFIX(migrateFrom, "tcp")) {
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                                 "%s", _("TCP migration is not supported with this QEMU binary"));
                return -1;
            }
        } else if (STREQ(migrateFrom, "stdio")) {
            if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC) {
                migrateFrom = "exec:cat";
            } else if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                                 "%s", _("STDIO migration is not supported with this QEMU binary"));
                return -1;
            }
        } else if (STRPREFIX(migrateFrom, "exec")) {
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                                 "%s", _("STDIO migration is not supported with this QEMU binary"));
                return -1;
            }
        }
    }

    emulator = def->emulator;

    /* Need to explicitly disable KQEMU if
     * 1. Guest domain is 'qemu'
     * 2. The qemu binary has the -no-kqemu flag
     */
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU) &&
        def->virtType == VIR_DOMAIN_VIRT_QEMU)
        disableKQEMU = 1;

    /* Need to explicitly disable KVM if
     * 1. Guest domain is 'qemu'
     * 2. The qemu binary has the -no-kvm flag
     */
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_KVM) &&
        def->virtType == VIR_DOMAIN_VIRT_QEMU)
        disableKVM = 1;

    /*
     * Need to force a 32-bit guest CPU type if
     *
     *  1. guest OS is i686
     *  2. host OS is x86_64
     *  3. emulator is qemu-kvm or kvm
     *
     * Or
     *
     *  1. guest OS is i686
     *  2. emulator is qemu-system-x86_64
     */
    if (STREQ(def->os.arch, "i686") &&
        ((STREQ(ut.machine, "x86_64") &&
          strstr(emulator, "kvm")) ||
         strstr(emulator, "x86_64")))
        cpu = "qemu32";

#define ADD_ARG_SPACE                                                   \
    do { \
        if (qargc == qarga) {                                           \
            qarga += 10;                                                \
            if (VIR_REALLOC_N(qargv, qarga) < 0)                        \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ARG(thisarg)                                                \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        qargv[qargc++] = thisarg;                                       \
    } while (0)

#define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        if ((qargv[qargc++] = strdup(thisarg)) == NULL)                 \
            goto no_memory;                                             \
    } while (0)

#define ADD_USBDISK(thisarg)                                            \
    do {                                                                \
        ADD_ARG_LIT("-usbdevice");                                      \
        ADD_ARG_SPACE;                                                  \
        if ((virAsprintf((char **)&(qargv[qargc++]),                    \
                         "disk:%s", thisarg)) == -1) {                  \
            goto no_memory;                                             \
        }                                                               \
    } while (0)

#define ADD_ENV_SPACE                                                   \
    do {                                                                \
        if (qenvc == qenva) {                                           \
            qenva += 10;                                                \
            if (VIR_REALLOC_N(qenv, qenva) < 0)                         \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

#define ADD_ENV(thisarg)                                                \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        qenv[qenvc++] = thisarg;                                        \
    } while (0)

#define ADD_ENV_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        if ((qenv[qenvc++] = strdup(thisarg)) == NULL)                  \
            goto no_memory;                                             \
    } while (0)

#define ADD_ENV_PAIR(envname, val)                                      \
    do {                                                                \
        char *envval;                                                   \
        ADD_ENV_SPACE;                                                  \
        if (virAsprintf(&envval, "%s=%s", envname, val) < 0)            \
            goto no_memory;                                             \
        qenv[qenvc++] = envval;                                         \
    } while (0)

#define ADD_ENV_COPY(envname)                                           \
    do {                                                                \
        char *val = getenv(envname);                                    \
        if (val != NULL) {                                              \
            ADD_ENV_PAIR(envname, val);                                 \
        }                                                               \
    } while (0)

    /* Set '-m MB' based on maxmem, because the lower 'memory' limit
     * is set post-startup using the balloon driver. If balloon driver
     * is not supported, then they're out of luck anyway
     */
    snprintf(memory, sizeof(memory), "%lu", def->maxmem/1024);
    snprintf(vcpus, sizeof(vcpus), "%lu", def->vcpus);
    snprintf(domid, sizeof(domid), "%d", def->id);

    ADD_ENV_LIT("LC_ALL=C");

    ADD_ENV_COPY("LD_PRELOAD");
    ADD_ENV_COPY("LD_LIBRARY_PATH");
    ADD_ENV_COPY("PATH");
    ADD_ENV_COPY("HOME");
    ADD_ENV_COPY("USER");
    ADD_ENV_COPY("LOGNAME");
    ADD_ENV_COPY("TMPDIR");

    ADD_ARG_LIT(emulator);
    ADD_ARG_LIT("-S");

    /* This should *never* be NULL, since we always provide
     * a machine in the capabilities data for QEMU. So this
     * check is just here as a safety in case the unexpected
     * happens */
    if (def->os.machine) {
        ADD_ARG_LIT("-M");
        ADD_ARG_LIT(def->os.machine);
    }
    if (cpu) {
        ADD_ARG_LIT("-cpu");
        ADD_ARG_LIT(cpu);
    }

    if (disableKQEMU)
        ADD_ARG_LIT("-no-kqemu");
    if (disableKVM)
        ADD_ARG_LIT("-no-kvm");
    ADD_ARG_LIT("-m");
    ADD_ARG_LIT(memory);
    if (def->hugepage_backed) {
        if (!driver->hugetlbfs_mount) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("hugetlbfs filesystem is not mounted"));
            goto error;
        }
        if (!driver->hugepage_path) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("hugepages are disabled by administrator config"));
            goto error;
        }
        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MEM_PATH)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("hugepage backing not supported by '%s'"),
                             def->emulator);
            goto error;
        }
        ADD_ARG_LIT("-mem-path");
        ADD_ARG_LIT(driver->hugepage_path);
    }
    ADD_ARG_LIT("-smp");
    ADD_ARG_LIT(vcpus);

    if (qemuCmdFlags & QEMUD_CMD_FLAG_NAME) {
        ADD_ARG_LIT("-name");
        ADD_ARG_LIT(def->name);
    }
    if (qemuCmdFlags & QEMUD_CMD_FLAG_UUID) {
        ADD_ARG_LIT("-uuid");
        ADD_ARG_LIT(uuid);
    }
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DOMID) {
        ADD_ARG_LIT("-domid");
        ADD_ARG_LIT(domid);
    }

    /*
     * NB, -nographic *MUST* come before any serial, or monitor
     * or parallel port flags due to QEMU craziness, where it
     * decides to change the serial port & monitor to be on stdout
     * if you ask for nographic. So we have to make sure we override
     * these defaults ourselves...
     */
    if (!def->graphics)
        ADD_ARG_LIT("-nographic");

    if (monitor_chr) {
        char buf[4096];

        if (qemudBuildCommandLineChrDevStr(monitor_chr, buf, sizeof(buf)) < 0)
            goto error;

        ADD_ARG_LIT("-monitor");
        ADD_ARG_LIT(buf);
    }

    if (def->localtime)
        ADD_ARG_LIT("-localtime");

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NO_REBOOT) &&
        def->onReboot != VIR_DOMAIN_LIFECYCLE_RESTART)
        ADD_ARG_LIT("-no-reboot");

    if (!(def->features & (1 << VIR_DOMAIN_FEATURE_ACPI)))
        ADD_ARG_LIT("-no-acpi");

    if (!def->os.bootloader) {
        for (i = 0 ; i < def->os.nBootDevs ; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case VIR_DOMAIN_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case VIR_DOMAIN_BOOT_DISK:
                boot[i] = 'c';
                break;
            case VIR_DOMAIN_BOOT_NET:
                boot[i] = 'n';
                break;
            default:
                boot[i] = 'c';
                break;
            }
        }
        boot[def->os.nBootDevs] = '\0';
        ADD_ARG_LIT("-boot");
        ADD_ARG_LIT(boot);

        if (def->os.kernel) {
            ADD_ARG_LIT("-kernel");
            ADD_ARG_LIT(def->os.kernel);
        }
        if (def->os.initrd) {
            ADD_ARG_LIT("-initrd");
            ADD_ARG_LIT(def->os.initrd);
        }
        if (def->os.cmdline) {
            ADD_ARG_LIT("-append");
            ADD_ARG_LIT(def->os.cmdline);
        }
    } else {
        ADD_ARG_LIT("-bootloader");
        ADD_ARG_LIT(def->os.bootloader);
    }

    for (i = 0 ; i < def->ndisks ; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        if (disk->driverName != NULL &&
            !STREQ(disk->driverName, "qemu")) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("unsupported driver name '%s' for disk '%s'"),
                             disk->driverName, disk->src);
            goto error;
        }
    }

    /* If QEMU supports -drive param instead of old -hda, -hdb, -cdrom .. */
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE) {
        int bootCD = 0, bootFloppy = 0, bootDisk = 0;

        /* If QEMU supports boot=on for -drive param... */
        if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_BOOT) {
            for (i = 0 ; i < def->os.nBootDevs ; i++) {
                switch (def->os.bootDevs[i]) {
                case VIR_DOMAIN_BOOT_CDROM:
                    bootCD = 1;
                    break;
                case VIR_DOMAIN_BOOT_FLOPPY:
                    bootFloppy = 1;
                    break;
                case VIR_DOMAIN_BOOT_DISK:
                    bootDisk = 1;
                    break;
                }
            }
        }

        for (i = 0 ; i < def->ndisks ; i++) {
            virBuffer opt = VIR_BUFFER_INITIALIZER;
            char *optstr;
            int bootable = 0;
            virDomainDiskDefPtr disk = def->disks[i];
            int idx = virDiskNameToIndex(disk->dst);
            const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);

            if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    ADD_USBDISK(disk->src);
                } else {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("unsupported usb disk type for '%s'"), disk->src);
                    goto error;
                }
                continue;
            }

            ADD_ARG_SPACE;

            if (idx < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unsupported disk type '%s'"), disk->dst);
                goto error;
            }

            switch (disk->device) {
            case VIR_DOMAIN_DISK_DEVICE_CDROM:
                bootable = bootCD;
                bootCD = 0;
                break;
            case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
                bootable = bootFloppy;
                bootFloppy = 0;
                break;
            case VIR_DOMAIN_DISK_DEVICE_DISK:
                bootable = bootDisk;
                bootDisk = 0;
                break;
            }

            virBufferVSprintf(&opt, "file=%s", disk->src ? disk->src : "");
            virBufferVSprintf(&opt, ",if=%s", bus);
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                virBufferAddLit(&opt, ",media=cdrom");
            virBufferVSprintf(&opt, ",index=%d", idx);
            if (bootable &&
                disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
                virBufferAddLit(&opt, ",boot=on");
            if (disk->driverType &&
                qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_FORMAT)
                virBufferVSprintf(&opt, ",format=%s", disk->driverType);
            if (disk->serial &&
                (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_SERIAL)) {
                if (qemuSafeSerialParamValue(conn, disk->serial) < 0)
                    goto error;
                virBufferVSprintf(&opt, ",serial=%s", disk->serial);
            }

            if (disk->cachemode) {
                const char *mode =
                    (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_CACHE_V2) ?
                    qemuDiskCacheV2TypeToString(disk->cachemode) :
                    qemuDiskCacheV1TypeToString(disk->cachemode);

                virBufferVSprintf(&opt, ",cache=%s", mode);
            } else if (disk->shared && !disk->readonly) {
                virBufferAddLit(&opt, ",cache=off");
            }

            if (virBufferError(&opt)) {
                virReportOOMError(conn);
                goto error;
            }

            optstr = virBufferContentAndReset(&opt);

            if ((qargv[qargc++] = strdup("-drive")) == NULL) {
                VIR_FREE(optstr);
                goto no_memory;
            }
            ADD_ARG(optstr);
        }
    } else {
        for (i = 0 ; i < def->ndisks ; i++) {
            char dev[NAME_MAX];
            char file[PATH_MAX];
            virDomainDiskDefPtr disk = def->disks[i];

            if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    ADD_USBDISK(disk->src);
                } else {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("unsupported usb disk type for '%s'"), disk->src);
                    goto error;
                }
                continue;
            }

            if (STREQ(disk->dst, "hdc") &&
                disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                if (disk->src) {
                    snprintf(dev, NAME_MAX, "-%s", "cdrom");
                } else {
                    continue;
                }
            } else {
                if (STRPREFIX(disk->dst, "hd") ||
                    STRPREFIX(disk->dst, "fd")) {
                    snprintf(dev, NAME_MAX, "-%s", disk->dst);
                } else {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("unsupported disk type '%s'"), disk->dst);
                    goto error;
                }
            }

            snprintf(file, PATH_MAX, "%s", disk->src);

            ADD_ARG_LIT(dev);
            ADD_ARG_LIT(file);
        }
    }

    if (!def->nnets) {
        ADD_ARG_LIT("-net");
        ADD_ARG_LIT("none");
    } else {
        for (i = 0 ; i < def->nnets ; i++) {
            virDomainNetDefPtr net = def->nets[i];
            char *nic, *host;
            char *tapfd_name = NULL;

            net->vlan = i;

            ADD_ARG_SPACE;
            if ((qemuCmdFlags & QEMUD_CMD_FLAG_NET_NAME) &&
                qemuAssignNetNames(def, net) < 0)
                goto no_memory;

            if (qemuBuildNicStr(conn, net, NULL, ',', net->vlan, &nic) < 0)
                goto error;

            if ((qargv[qargc++] = strdup("-net")) == NULL) {
                VIR_FREE(nic);
                goto no_memory;
            }
            ADD_ARG(nic);


            ADD_ARG_SPACE;
            if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK ||
                net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                int tapfd = qemudNetworkIfaceConnect(conn, driver, net, qemuCmdFlags);
                if (tapfd < 0)
                    goto error;

                if (VIR_REALLOC_N(*tapfds, (*ntapfds)+1) < 0) {
                    close(tapfd);
                    goto no_memory;
                }

                (*tapfds)[(*ntapfds)++] = tapfd;

                if (virAsprintf(&tapfd_name, "%d", tapfd) < 0)
                    goto no_memory;
            }

            if (qemuBuildHostNetStr(conn, net, NULL, ',',
                                    net->vlan, tapfd_name, &host) < 0) {
                VIR_FREE(tapfd_name);
                goto error;
            }

            if ((qargv[qargc++] = strdup("-net")) == NULL) {
                VIR_FREE(host);
                goto no_memory;
            }
            ADD_ARG(host);

            VIR_FREE(tapfd_name);
        }
    }

    if (!def->nserials) {
        ADD_ARG_LIT("-serial");
        ADD_ARG_LIT("none");
    } else {
        for (i = 0 ; i < def->nserials ; i++) {
            char buf[4096];
            virDomainChrDefPtr serial = def->serials[i];

            if (qemudBuildCommandLineChrDevStr(serial, buf, sizeof(buf)) < 0)
                goto error;

            ADD_ARG_LIT("-serial");
            ADD_ARG_LIT(buf);
        }
    }

    if (!def->nparallels) {
        ADD_ARG_LIT("-parallel");
        ADD_ARG_LIT("none");
    } else {
        for (i = 0 ; i < def->nparallels ; i++) {
            char buf[4096];
            virDomainChrDefPtr parallel = def->parallels[i];

            if (qemudBuildCommandLineChrDevStr(parallel, buf, sizeof(buf)) < 0)
                goto error;

            ADD_ARG_LIT("-parallel");
            ADD_ARG_LIT(buf);
        }
    }

    ADD_ARG_LIT("-usb");
    for (i = 0 ; i < def->ninputs ; i++) {
        virDomainInputDefPtr input = def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            ADD_ARG_LIT("-usbdevice");
            ADD_ARG_LIT(input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ? "mouse" : "tablet");
        }
    }

    if ((def->ngraphics == 1) &&
        def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBuffer opt = VIR_BUFFER_INITIALIZER;
        char *optstr;

        if (qemuCmdFlags & QEMUD_CMD_FLAG_VNC_COLON) {
            if (def->graphics[0]->data.vnc.listenAddr)
                virBufferAdd(&opt, def->graphics[0]->data.vnc.listenAddr, -1);
            else if (driver->vncListen)
                virBufferAdd(&opt, driver->vncListen, -1);

            virBufferVSprintf(&opt, ":%d",
                              def->graphics[0]->data.vnc.port - 5900);

            if (def->graphics[0]->data.vnc.passwd ||
                driver->vncPassword)
                virBufferAddLit(&opt, ",password");

            if (driver->vncTLS) {
                virBufferAddLit(&opt, ",tls");
                if (driver->vncTLSx509verify) {
                    virBufferVSprintf(&opt, ",x509verify=%s",
                                      driver->vncTLSx509certdir);
                } else {
                    virBufferVSprintf(&opt, ",x509=%s",
                                      driver->vncTLSx509certdir);
                }
            }

            if (driver->vncSASL) {
                virBufferAddLit(&opt, ",sasl");

                if (driver->vncSASLdir)
                    ADD_ENV_PAIR("SASL_CONF_DIR", driver->vncSASLdir);

                /* TODO: Support ACLs later */
            }
        } else {
            virBufferVSprintf(&opt, "%d",
                              def->graphics[0]->data.vnc.port - 5900);
        }
        if (virBufferError(&opt))
            goto no_memory;

        optstr = virBufferContentAndReset(&opt);

        ADD_ARG_LIT("-vnc");
        ADD_ARG(optstr);
        if (def->graphics[0]->data.vnc.keymap) {
            ADD_ARG_LIT("-k");
            ADD_ARG_LIT(def->graphics[0]->data.vnc.keymap);
        }
    } else if ((def->ngraphics == 1) &&
               def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        char *xauth = NULL;
        char *display = NULL;

        if (def->graphics[0]->data.sdl.xauth &&
            virAsprintf(&xauth, "XAUTHORITY=%s",
                        def->graphics[0]->data.sdl.xauth) < 0)
            goto no_memory;
        if (def->graphics[0]->data.sdl.display &&
            virAsprintf(&display, "DISPLAY=%s",
                        def->graphics[0]->data.sdl.display) < 0) {
            VIR_FREE(xauth);
            goto no_memory;
        }

        if (xauth)
            ADD_ENV(xauth);
        if (display)
            ADD_ENV(display);
        if (def->graphics[0]->data.sdl.fullscreen)
            ADD_ARG_LIT("-full-screen");
    }

    if (def->nvideos) {
        if (def->nvideos > 1) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("only one video card is currently supported"));
            goto error;
        }

        if (qemuCmdFlags & QEMUD_CMD_FLAG_VGA) {
            if (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_XEN) {
                /* nothing - vga has no effect on Xen pvfb */
            } else {
                const char *vgastr = qemuVideoTypeToString(def->videos[0]->type);
                if (!vgastr) {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("video type %s is not supported with QEMU"),
                                     virDomainVideoTypeToString(def->videos[0]->type));
                    goto error;
                }

                ADD_ARG_LIT("-vga");
                ADD_ARG_LIT(vgastr);
            }
        } else {

            switch (def->videos[0]->type) {
            case VIR_DOMAIN_VIDEO_TYPE_VGA:
                ADD_ARG_LIT("-std-vga");
                break;

            case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
                ADD_ARG_LIT("-vmwarevga");
                break;

            case VIR_DOMAIN_VIDEO_TYPE_XEN:
            case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
                /* No special args - this is the default */
                break;

            default:
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("video type %s is not supported with QEMU"),
                                 virDomainVideoTypeToString(def->videos[0]->type));
                goto error;
            }
        }
    }

    /* Add sound hardware */
    if (def->nsounds) {
        int size = 100;
        char *modstr;
        if (VIR_ALLOC_N(modstr, size+1) < 0)
            goto no_memory;

        for (i = 0 ; i < def->nsounds && size > 0 ; i++) {
            virDomainSoundDefPtr sound = def->sounds[i];
            const char *model = virDomainSoundModelTypeToString(sound->model);
            if (!model) {
                VIR_FREE(modstr);
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("invalid sound model"));
                goto error;
            }
            strncat(modstr, model, size);
            size -= strlen(model);
            if (i < (def->nsounds - 1))
               strncat(modstr, ",", size--);
        }
        ADD_ARG_LIT("-soundhw");
        ADD_ARG(modstr);
    }

    /* Add host passthrough hardware */
    for (i = 0 ; i < def->nhostdevs ; i++) {
        int ret;
        char* usbdev;
        char* pcidev;
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];

        /* USB */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            if(hostdev->source.subsys.u.usb.vendor) {
                    ret = virAsprintf(&usbdev, "host:%.4x:%.4x",
                               hostdev->source.subsys.u.usb.vendor,
                               hostdev->source.subsys.u.usb.product);

            } else {
                    ret = virAsprintf(&usbdev, "host:%.3d.%.3d",
                               hostdev->source.subsys.u.usb.bus,
                               hostdev->source.subsys.u.usb.device);
            }
            if (ret < 0)
                goto error;

            ADD_ARG_LIT("-usbdevice");
            ADD_ARG_LIT(usbdev);
            VIR_FREE(usbdev);
        }

        /* PCI */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_PCIDEVICE)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT, "%s",
                                 _("PCI device assignment is not supported by this version of qemu"));
                goto error;
            }
            ret = virAsprintf(&pcidev, "host=%.2x:%.2x.%.1x",
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
            if (ret < 0) {
                pcidev = NULL;
                goto error;
            }
            ADD_ARG_LIT("-pcidevice");
            ADD_ARG_LIT(pcidev);
            VIR_FREE(pcidev);
        }
    }

    if (migrateFrom) {
        ADD_ARG_LIT("-incoming");
        ADD_ARG_LIT(migrateFrom);
    }

    ADD_ARG(NULL);
    ADD_ENV(NULL);

    *retargv = qargv;
    *retenv = qenv;
    return 0;

 no_memory:
    virReportOOMError(conn);
 error:
    if (tapfds &&
        *tapfds) {
        for (i = 0; i < *ntapfds; i++)
            close((*tapfds)[i]);
        VIR_FREE(*tapfds);
        *ntapfds = 0;
    }
    if (qargv) {
        for (i = 0 ; i < qargc ; i++)
            VIR_FREE((qargv)[i]);
        VIR_FREE(qargv);
    }
    if (qenv) {
        for (i = 0 ; i < qenvc ; i++)
            VIR_FREE((qenv)[i]);
        VIR_FREE(qenv);
    }
    return -1;

#undef ADD_ARG
#undef ADD_ARG_LIT
#undef ADD_ARG_SPACE
#undef ADD_USBDISK
#undef ADD_ENV
#undef ADD_ENV_COPY
#undef ADD_ENV_LIT
#undef ADD_ENV_SPACE
}


/*
 * This method takes a string representing a QEMU command line ARGV set
 * optionall prefixed by a list of environment variables. It then tries
 * to split it up into a NULL terminated list of env & argv, splitting
 * on space
 */
static int qemuStringToArgvEnv(const char *args,
                               const char ***retenv,
                               const char ***retargv)
{
    char **arglist = NULL;
    int argcount = 0;
    int argalloc = 0;
    int envend;
    int i;
    const char *curr = args;
    const char **progenv = NULL;
    const char **progargv = NULL;

    /* Iterate over string, splitting on sequences of ' ' */
    while (curr && *curr != '\0') {
        char *arg;
        const char *next;
        if (*curr == '\'') {
            curr++;
            next = strchr(curr, '\'');
        } else if (*curr == '"') {
            curr++;
            next = strchr(curr, '"');
        } else {
            next = strchr(curr, ' ');
        }
        if (!next)
            next = strchr(curr, '\n');

        if (next) {
            arg = strndup(curr, next-curr);
            if (*next == '\'' ||
                *next == '"')
                next++;
        } else {
            arg = strdup(curr);
        }

        if (!arg)
            goto no_memory;

        if (argalloc == argcount) {
            if (VIR_REALLOC_N(arglist, argalloc+10) < 0) {
                VIR_FREE(arg);
                goto no_memory;
            }
            argalloc+=10;
        }

        arglist[argcount++] = arg;

        while (next && c_isspace(*next))
            next++;

        curr = next;
    }

    /* Iterate over list of args, finding first arg not containining
     * the '=' character (eg, skip over env vars FOO=bar) */
    for (envend = 0 ; ((envend < argcount) &&
                       (strchr(arglist[envend], '=') != NULL));
         envend++)
        ; /* nada */

    /* Copy the list of env vars */
    if (envend > 0) {
        if (VIR_REALLOC_N(progenv, envend+1) < 0)
            goto no_memory;
        for (i = 0 ; i < envend ; i++) {
            progenv[i] = arglist[i];
            arglist[i] = NULL;
        }
        progenv[i] = NULL;
    }

    /* Copy the list of argv */
    if (VIR_REALLOC_N(progargv, argcount-envend + 1) < 0)
        goto no_memory;
    for (i = envend ; i < argcount ; i++)
        progargv[i-envend] = arglist[i];
    progargv[i-envend] = NULL;

    VIR_FREE(arglist);

    *retenv = progenv;
    *retargv = progargv;

    return 0;

no_memory:
    for (i = 0 ; progenv && progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);
    for (i = 0 ; i < argcount ; i++)
        VIR_FREE(arglist[i]);
    VIR_FREE(arglist);
    return -1;
}


/*
 * Search for a named env variable, and return the value part
 */
static const char *qemuFindEnv(const char **progenv,
                               const char *name)
{
    int i;
    int len = strlen(name);

    for (i = 0 ; progenv && progenv[i] ; i++) {
        if (STREQLEN(progenv[i], name, len) &&
            progenv[i][len] == '=')
            return progenv[i] + len + 1;
    }
    return NULL;
}

/*
 * Takes a string containing a set of key=value,key=value,key...
 * parameters and splits them up, returning two arrays with
 * the individual keys and values
 */
static int
qemuParseCommandLineKeywords(virConnectPtr conn,
                             const char *str,
                             char ***retkeywords,
                             char ***retvalues)
{
    int keywordCount = 0;
    int keywordAlloc = 0;
    char **keywords = NULL;
    char **values = NULL;
    const char *start = str;
    int i;

    *retkeywords = NULL;
    *retvalues = NULL;

    while (start) {
        const char *separator;
        const char *endmark;
        char *keyword;
        char *value;

        if (!(separator = strchr(start, '='))) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("malformed keyword arguments in '%s'"), str);
            goto error;
        }
        if (!(keyword = strndup(start, separator - start)))
            goto no_memory;

        separator++;
        endmark = strchr(separator, ',');

        value = endmark ?
            strndup(separator, endmark - separator) :
            strdup(separator);
        if (!value) {
            VIR_FREE(keyword);
            goto no_memory;
        }

        if (keywordAlloc == keywordCount) {
            if (VIR_REALLOC_N(keywords, keywordAlloc + 10) < 0 ||
                VIR_REALLOC_N(values, keywordAlloc + 10) < 0) {
                VIR_FREE(keyword);
                VIR_FREE(value);
                goto no_memory;
            }
            keywordAlloc += 10;
        }

        keywords[keywordCount] = keyword;
        values[keywordCount] = value;
        keywordCount++;

        start = endmark ? endmark + 1 : NULL;
    }

    *retkeywords = keywords;
    *retvalues = values;

    return keywordCount;

no_memory:
    virReportOOMError(conn);
error:
    for (i = 0 ; i < keywordCount ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return -1;
}

/*
 * Tries to parse new style QEMU -drive  args.
 *
 * eg -drive file=/dev/HostVG/VirtData1,if=ide,index=1
 *
 * Will fail if not using the 'index' keyword
 */
static virDomainDiskDefPtr
qemuParseCommandLineDisk(virConnectPtr conn,
                         const char *val)
{
    virDomainDiskDefPtr def = NULL;
    char **keywords;
    char **values;
    int nkeywords;
    int i;
    int idx = -1;

    if ((nkeywords = qemuParseCommandLineKeywords(conn, val,
                                                  &keywords,
                                                  &values)) < 0)
        return NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    def->bus = VIR_DOMAIN_DISK_BUS_IDE;
    def->device = VIR_DOMAIN_DISK_DEVICE_DISK;

    for (i = 0 ; i < nkeywords ; i++) {
        if (STREQ(keywords[i], "file")) {
            if (values[i] && STRNEQ(values[i], "")) {
                def->src = values[i];
                values[i] = NULL;
                if (STRPREFIX(def->src, "/dev/"))
                    def->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                else
                    def->type = VIR_DOMAIN_DISK_TYPE_FILE;
            } else {
                def->type = VIR_DOMAIN_DISK_TYPE_FILE;
            }
        } else if (STREQ(keywords[i], "if")) {
            if (STREQ(values[i], "ide"))
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STREQ(values[i], "scsi"))
                def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else if (STREQ(values[i], "virtio"))
                def->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            else if (STREQ(values[i], "xen"))
                def->bus = VIR_DOMAIN_DISK_BUS_XEN;
        } else if (STREQ(keywords[i], "media")) {
            if (STREQ(values[i], "cdrom")) {
                def->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                def->readonly = 1;
            } else if (STREQ(values[i], "floppy"))
                def->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
        } else if (STREQ(keywords[i], "format")) {
            def->driverName = strdup("qemu");
            if (!def->driverName) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportOOMError(conn);
                goto cleanup;
            }
            def->driverType = values[i];
            values[i] = NULL;
        } else if (STREQ(keywords[i], "cache")) {
            if (STREQ(values[i], "off") ||
                STREQ(values[i], "none"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DISABLE;
            else if (STREQ(values[i], "writeback") ||
                     STREQ(values[i], "on"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITEBACK;
            else if (STREQ(values[i], "writethrough"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITETHRU;
        } else if (STREQ(keywords[i], "index")) {
            if (virStrToLong_i(values[i], NULL, 10, &idx) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse drive index '%s'"), val);
                goto cleanup;
            }
        }
    }

    if (!def->src &&
        def->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("missing file parameter in drive '%s'"), val);
        virDomainDiskDefFree(def);
        def = NULL;
        goto cleanup;
    }
    if (idx == -1) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("missing index parameter in drive '%s'"), val);
        virDomainDiskDefFree(def);
        def = NULL;
        goto cleanup;
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        def->dst = strdup("hda");
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        def->dst = strdup("sda");
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        def->dst = strdup("vda");
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_XEN) {
        def->dst = strdup("xvda");
    } else {
        def->dst = strdup("hda");
    }

    if (!def->dst) {
        virDomainDiskDefFree(def);
        def = NULL;
        virReportOOMError(conn);
        goto cleanup;
    }
    if (STREQ(def->dst, "xvda"))
        def->dst[3] = 'a' + idx;
    else
        def->dst[2] = 'a' + idx;

cleanup:
    for (i = 0 ; i < nkeywords ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;
}

/*
 * Tries to find a NIC definition matching a vlan we want
 */
static const char *
qemuFindNICForVLAN(virConnectPtr conn,
                   int nnics,
                   const char **nics,
                   int wantvlan)
{
    int i;
    for (i = 0 ; i < nnics ; i++) {
        int gotvlan;
        const char *tmp = strstr(nics[i], "vlan=");
        char *end;
        if (!tmp)
            continue;

        tmp += strlen("vlan=");

        if (virStrToLong_i(tmp, &end, 10, &gotvlan) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot parse NIC vlan in '%s'"), nics[i]);
            return NULL;
        }

        if (gotvlan == wantvlan)
            return nics[i];
    }

    if (wantvlan == 0 && nnics > 0)
        return nics[0];

    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("cannot find NIC definition for vlan %d"), wantvlan);
    return NULL;
}


/*
 * Tries to parse a QEMU -net backend argument. Gets given
 * a list of all known -net frontend arguments to try and
 * match up against. Horribly complicated stuff
 */
static virDomainNetDefPtr
qemuParseCommandLineNet(virConnectPtr conn,
                        virCapsPtr caps,
                        const char *val,
                        int nnics,
                        const char **nics)
{
    virDomainNetDefPtr def = NULL;
    char **keywords = NULL;
    char **values = NULL;
    int nkeywords;
    const char *nic;
    int wantvlan = 0;
    const char *tmp;
    int genmac = 1;
    int i;

    tmp = strchr(val, ',');

    if (tmp) {
        if ((nkeywords = qemuParseCommandLineKeywords(conn,
                                                      tmp+1,
                                                      &keywords,
                                                      &values)) < 0)
            return NULL;
    } else {
        nkeywords = 0;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    /* 'tap' could turn into libvirt type=ethernet, type=bridge or
     * type=network, but we can't tell, so use the generic config */
    if (STRPREFIX(val, "tap,"))
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
    else if (STRPREFIX(val, "socket"))
        def->type = VIR_DOMAIN_NET_TYPE_CLIENT;
    else if (STRPREFIX(val, "user"))
        def->type = VIR_DOMAIN_NET_TYPE_USER;
    else
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;

    for (i = 0 ; i < nkeywords ; i++) {
        if (STREQ(keywords[i], "vlan")) {
            if (virStrToLong_i(values[i], NULL, 10, &wantvlan) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse vlan in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "script") && STRNEQ(values[i], "")) {
            def->data.ethernet.script = values[i];
            values[i] = NULL;
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "ifname")) {
            def->ifname = values[i];
            values[i] = NULL;
        }
    }


    /* Done parsing the nic backend. Now to try and find corresponding
     * frontend, based off vlan number. NB this assumes a 1-1 mapping
     */

    nic = qemuFindNICForVLAN(conn, nnics, nics, wantvlan);
    if (!nic) {
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    if (!STRPREFIX(nic, "nic")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse NIC definition '%s'"), nic);
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    for (i = 0 ; i < nkeywords ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);

    if (STRPREFIX(nic, "nic,")) {
        if ((nkeywords = qemuParseCommandLineKeywords(conn,
                                                      nic + strlen("nic,"),
                                                      &keywords,
                                                      &values)) < 0) {
            virDomainNetDefFree(def);
            def = NULL;
            goto cleanup;
        }
    } else {
        nkeywords = 0;
    }

    for (i = 0 ; i < nkeywords ; i++) {
        if (STREQ(keywords[i], "macaddr")) {
            genmac = 0;
            virParseMacAddr(values[i], def->mac);
        } else if (STREQ(keywords[i], "model")) {
            def->model = values[i];
            values[i] = NULL;
        }
    }

    if (genmac)
        virCapabilitiesGenerateMac(caps, def->mac);

cleanup:
    for (i = 0 ; i < nkeywords ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;
}


/*
 * Tries to parse a QEMU PCI device
 */
static virDomainHostdevDefPtr
qemuParseCommandLinePCI(virConnectPtr conn,
                        const char *val)
{
    virDomainHostdevDefPtr def = NULL;
    int bus = 0, slot = 0, func = 0;
    const char *start;
    char *end;

    if (!STRPREFIX(val, "host=")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown PCI device syntax '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }

    start = val + strlen("host=");
    if (virStrToLong_i(start, &end, 16, &bus) < 0 || !end || *end != ':') {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot extract PCI device bus '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }
    start = end + 1;
    if (virStrToLong_i(start, &end, 16, &slot) < 0 || !end || *end != '.') {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot extract PCI device slot '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }
    start = end + 1;
    if (virStrToLong_i(start, NULL, 16, &func) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot extract PCI device function '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = 1;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    def->source.subsys.u.pci.bus = bus;
    def->source.subsys.u.pci.slot = slot;
    def->source.subsys.u.pci.function = func;

cleanup:
    return def;
}


/*
 * Tries to parse a QEMU USB device
 */
static virDomainHostdevDefPtr
qemuParseCommandLineUSB(virConnectPtr conn,
                        const char *val)
{
    virDomainHostdevDefPtr def = NULL;
    int first = 0, second = 0;
    const char *start;
    char *end;

    if (!STRPREFIX(val, "host:")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown PCI device syntax '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }

    start = val + strlen("host:");
    if (strchr(start, ':')) {
        if (virStrToLong_i(start, &end, 16, &first) < 0 || !end || *end != ':') {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot extract USB device vendor '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 16, &second) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot extract PCI device product '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
    } else {
        if (virStrToLong_i(start, &end, 10, &first) < 0 || !end || *end != '.') {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot extract PCI device bus '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 10, &second) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot extract PCI device address '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = 0;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;
    if (*end == '.') {
        def->source.subsys.u.usb.bus = first;
        def->source.subsys.u.usb.device = second;
    } else {
        def->source.subsys.u.usb.vendor = first;
        def->source.subsys.u.usb.product = second;
    }

cleanup:
    return def;
}


/*
 * Tries to parse a QEMU serial/parallel device
 */
static virDomainChrDefPtr
qemuParseCommandLineChr(virConnectPtr conn,
                        const char *val)
{
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    if (STREQ(val, "null")) {
        def->type = VIR_DOMAIN_CHR_TYPE_NULL;
    } else if (STREQ(val, "vc")) {
        def->type = VIR_DOMAIN_CHR_TYPE_VC;
    } else if (STREQ(val, "pty")) {
        def->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if (STRPREFIX(val, "file:")) {
        def->type = VIR_DOMAIN_CHR_TYPE_FILE;
        def->data.file.path = strdup(val+strlen("file:"));
        if (!def->data.file.path)
            goto no_memory;
    } else if (STRPREFIX(val, "pipe:")) {
        def->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        def->data.file.path = strdup(val+strlen("pipe:"));
        if (!def->data.file.path)
            goto no_memory;
    } else if (STREQ(val, "stdio")) {
        def->type = VIR_DOMAIN_CHR_TYPE_STDIO;
    } else if (STRPREFIX(val, "udp:")) {
        const char *svc1, *host2, *svc2;
        def->type = VIR_DOMAIN_CHR_TYPE_UDP;
        val += strlen("udp:");
        svc1 = strchr(val, ':');
        host2 = svc1 ? strchr(svc1, '@') : NULL;
        svc2 = host2 ? strchr(host2, ':') : NULL;

        if (svc1)
            def->data.udp.connectHost = strndup(val, svc1-val);
        else
            def->data.udp.connectHost = strdup(val);
        if (svc1) {
            svc1++;
            if (host2)
                def->data.udp.connectService = strndup(svc1, host2-svc1);
            else
                def->data.udp.connectService = strdup(svc1);
        }

        if (host2) {
            host2++;
            if (svc2)
                def->data.udp.bindHost = strndup(host2, svc2-host2);
            else
                def->data.udp.bindHost = strdup(host2);
        }
        if (svc2) {
            svc2++;
            def->data.udp.bindService = strdup(svc2);
        }
    } else if (STRPREFIX(val, "tcp:") ||
               STRPREFIX(val, "telnet:")) {
        const char *opt, *svc;
        def->type = VIR_DOMAIN_CHR_TYPE_TCP;
        if (STRPREFIX(val, "tcp:")) {
            val += strlen("tcp:");
        } else {
            val += strlen("telnet:");
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        }
        svc = strchr(val, ':');
        if (!svc) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot find port number in character device %s"), val);
            goto error;
        }
        opt = strchr(svc, ',');
        if (opt && strstr(opt, "server"))
            def->data.tcp.listen = 1;

        def->data.tcp.host = strndup(val, svc-val);
        svc++;
        if (opt) {
            def->data.tcp.service = strndup(svc, opt-svc);
        } else {
            def->data.tcp.service = strdup(svc);
        }
    } else if (STRPREFIX(val, "unix:")) {
        const char *opt;
        val += strlen("unix:");
        opt = strchr(val, ',');
        def->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        if (opt) {
            if (strstr(opt, "listen"))
                def->data.nix.listen = 1;
            def->data.nix.path = strndup(val, opt-val);
        } else {
            def->data.nix.path = strdup(val);
        }
        if (!def->data.nix.path)
            goto no_memory;

    } else if (STRPREFIX(val, "/dev")) {
        def->type = VIR_DOMAIN_CHR_TYPE_DEV;
        def->data.file.path = strdup(val);
        if (!def->data.file.path)
            goto no_memory;
    } else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown character device syntax %s"), val);
        goto error;
    }

    return def;

no_memory:
    virReportOOMError(conn);
error:
    virDomainChrDefFree(def);
    return NULL;
}

/*
 * Analyse the env and argv settings and reconstruct a
 * virDomainDefPtr representing these settings as closely
 * as is practical. This is not an exact science....
 */
virDomainDefPtr qemuParseCommandLine(virConnectPtr conn,
                                     virCapsPtr caps,
                                     const char **progenv,
                                     const char **progargv)
{
    virDomainDefPtr def;
    int i;
    int nographics = 0;
    int fullscreen = 0;
    char *path;
    int nnics = 0;
    const char **nics = NULL;
    int video = VIR_DOMAIN_VIDEO_TYPE_CIRRUS;

    if (!progargv[0]) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("no emulator path found"));
        return NULL;
    }

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    virUUIDGenerate(def->uuid);

    def->id = -1;
    def->memory = def->maxmem = 64 * 1024;
    def->vcpus = 1;
    def->features = (1 << VIR_DOMAIN_FEATURE_ACPI)
        /*| (1 << VIR_DOMAIN_FEATURE_APIC)*/;
    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->virtType = VIR_DOMAIN_VIRT_QEMU;
    if (!(def->emulator = strdup(progargv[0])))
        goto no_memory;

    if (strstr(def->emulator, "kvm")) {
        def->virtType = VIR_DOMAIN_VIRT_KVM;
        def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);
    }


    if (strstr(def->emulator, "xenner")) {
        def->virtType = VIR_DOMAIN_VIRT_KVM;
        def->os.type = strdup("xen");
    } else {
        def->os.type = strdup("hvm");
    }
    if (!def->os.type)
        goto no_memory;

    if (STRPREFIX(def->emulator, "qemu"))
        path = def->emulator;
    else
        path = strstr(def->emulator, "qemu");
    if (path &&
        STRPREFIX(path, "qemu-system-"))
        def->os.arch = strdup(path + strlen("qemu-system-"));
    else
        def->os.arch = strdup("i686");
    if (!def->os.arch)
        goto no_memory;

#define WANT_VALUE()                                                   \
    const char *val = progargv[++i];                                   \
    if (!val) {                                                        \
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,     \
                         _("missing value for %s argument"), arg);     \
        goto error;                                                    \
    }

    /* One initial loop to get list of NICs, so we
     * can correlate them later */
    for (i = 1 ; progargv[i] ; i++) {
        const char *arg = progargv[i];
        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (STRPREFIX(val, "nic")) {
                if (VIR_REALLOC_N(nics, nnics+1) < 0)
                    goto no_memory;
                nics[nnics++] = val;
            }
        }
    }

    /* Now the real processing loop */
    for (i = 1 ; progargv[i] ; i++) {
        const char *arg = progargv[i];
        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-vnc")) {
            virDomainGraphicsDefPtr vnc;
            char *tmp;
            WANT_VALUE();
            if (VIR_ALLOC(vnc) < 0)
                goto no_memory;
            vnc->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

            tmp = strchr(val, ':');
            if (tmp) {
                char *opts;
                if (virStrToLong_i(tmp+1, &opts, 10, &vnc->data.vnc.port) < 0) {
                    VIR_FREE(vnc);
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, \
                                     _("cannot parse VNC port '%s'"), tmp+1);
                    goto error;
                }
                vnc->data.vnc.listenAddr = strndup(val, tmp-val);
                if (!vnc->data.vnc.listenAddr) {
                    VIR_FREE(vnc);
                    goto no_memory;
                }
                vnc->data.vnc.port += 5900;
                vnc->data.vnc.autoport = 0;
            } else {
                vnc->data.vnc.autoport = 1;
            }

            if (VIR_REALLOC_N(def->graphics, def->ngraphics+1) < 0) {
                virDomainGraphicsDefFree(vnc);
                goto no_memory;
            }
            def->graphics[def->ngraphics++] = vnc;
        } else if (STREQ(arg, "-m")) {
            int mem;
            WANT_VALUE();
            if (virStrToLong_i(val, NULL, 10, &mem) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, \
                                 _("cannot parse memory level '%s'"), val);
                goto error;
            }
            def->memory = def->maxmem = mem * 1024;
        } else if (STREQ(arg, "-smp")) {
            int vcpus;
            WANT_VALUE();
            if (virStrToLong_i(val, NULL, 10, &vcpus) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, \
                                 _("cannot parse CPU count '%s'"), val);
                goto error;
            }
            def->vcpus = vcpus;
        } else if (STREQ(arg, "-uuid")) {
            WANT_VALUE();
            if (virUUIDParse(val, def->uuid) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, \
                                 _("cannot parse UUID '%s'"), val);
                goto error;
            }
        } else if (STRPREFIX(arg, "-hd") ||
                   STRPREFIX(arg, "-sd") ||
                   STRPREFIX(arg, "-fd") ||
                   STREQ(arg, "-cdrom")) {
            WANT_VALUE();
            virDomainDiskDefPtr disk;
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            if (STRPREFIX(val, "/dev/"))
                disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
            else
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            if (STREQ(arg, "-cdrom")) {
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                disk->dst = strdup("hdc");
                disk->readonly = 1;
            } else {
                if (STRPREFIX(arg, "-fd")) {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                    disk->bus = VIR_DOMAIN_DISK_BUS_FDC;
                } else {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                    if (STRPREFIX(arg, "-hd"))
                        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
                    else
                        disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                }
                disk->dst = strdup(arg + 1);
            }
            disk->src = strdup(val);
            if (!disk->src ||
                !disk->dst) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            def->disks[def->ndisks++] = disk;
        } else if (STREQ(arg, "-no-acpi")) {
            def->features &= ~(1 << VIR_DOMAIN_FEATURE_ACPI);
        } else if (STREQ(arg, "-no-reboot")) {
            def->onReboot = VIR_DOMAIN_LIFECYCLE_DESTROY;
        } else if (STREQ(arg, "-no-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_QEMU;
        } else if (STREQ(arg, "-nographic")) {
            nographics = 1;
        } else if (STREQ(arg, "-full-screen")) {
            fullscreen = 1;
        } else if (STREQ(arg, "-localtime")) {
            def->localtime = 1;
        } else if (STREQ(arg, "-kernel")) {
            WANT_VALUE();
            if (!(def->os.kernel = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-initrd")) {
            WANT_VALUE();
            if (!(def->os.initrd = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-append")) {
            WANT_VALUE();
            if (!(def->os.cmdline = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-boot")) {
            int n, b = 0;
            WANT_VALUE();
            for (n = 0 ; val[n] && b < VIR_DOMAIN_BOOT_LAST ; n++) {
                if (val[n] == 'a')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_FLOPPY;
                else if (val[n] == 'c')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_DISK;
                else if (val[n] == 'd')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_CDROM;
                else if (val[n] == 'n')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_NET;
            }
            def->os.nBootDevs = b;
        } else if (STREQ(arg, "-name")) {
            WANT_VALUE();
            if (!(def->name = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-M")) {
            WANT_VALUE();
            if (!(def->os.machine = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-serial")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;
                if (!(chr = qemuParseCommandLineChr(conn, val)))
                    goto error;
                if (VIR_REALLOC_N(def->serials, def->nserials+1) < 0) {
                    virDomainChrDefFree(chr);
                    goto no_memory;
                }
                chr->dstPort = def->nserials;
                def->serials[def->nserials++] = chr;
            }
        } else if (STREQ(arg, "-parallel")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;
                if (!(chr = qemuParseCommandLineChr(conn, val)))
                    goto error;
                if (VIR_REALLOC_N(def->parallels, def->nparallels+1) < 0) {
                    virDomainChrDefFree(chr);
                    goto no_memory;
                }
                chr->dstPort = def->nparallels;
                def->parallels[def->nparallels++] = chr;
            }
        } else if (STREQ(arg, "-usbdevice")) {
            WANT_VALUE();
            if (STREQ(val, "tablet") ||
                STREQ(val, "mouse")) {
                virDomainInputDefPtr input;
                if (VIR_ALLOC(input) < 0)
                    goto no_memory;
                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                if (STREQ(val, "tablet"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                else
                    input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                if (VIR_REALLOC_N(def->inputs, def->ninputs+1) < 0) {
                    virDomainInputDefFree(input);
                    goto no_memory;
                }
                def->inputs[def->ninputs++] = input;
            } else if (STRPREFIX(val, "disk:")) {
                virDomainDiskDefPtr disk;
                if (VIR_ALLOC(disk) < 0)
                    goto no_memory;
                disk->src = strdup(val + strlen("disk:"));
                if (!disk->src) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                if (STRPREFIX(disk->src, "/dev/"))
                    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                else
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                disk->bus = VIR_DOMAIN_DISK_BUS_USB;
                if (!(disk->dst = strdup("sda"))) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                def->disks[def->ndisks++] = disk;
            } else {
                virDomainHostdevDefPtr hostdev;
                if (!(hostdev = qemuParseCommandLineUSB(conn, val)))
                    goto error;
                if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
                    virDomainHostdevDefFree(hostdev);
                    goto no_memory;
                }
                def->hostdevs[def->nhostdevs++] = hostdev;
            }
        } else if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (!STRPREFIX(val, "nic") && STRNEQ(val, "none")) {
                virDomainNetDefPtr net;
                if (!(net = qemuParseCommandLineNet(conn, caps, val, nnics, nics)))
                    goto error;
                if (VIR_REALLOC_N(def->nets, def->nnets+1) < 0) {
                    virDomainNetDefFree(net);
                    goto no_memory;
                }
                def->nets[def->nnets++] = net;
            }
        } else if (STREQ(arg, "-drive")) {
            virDomainDiskDefPtr disk;
            WANT_VALUE();
            if (!(disk = qemuParseCommandLineDisk(conn, val)))
                goto error;
            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            def->disks[def->ndisks++] = disk;
        } else if (STREQ(arg, "-pcidevice")) {
            virDomainHostdevDefPtr hostdev;
            WANT_VALUE();
            if (!(hostdev = qemuParseCommandLinePCI(conn, val)))
                goto error;
            if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
                virDomainHostdevDefFree(hostdev);
                goto no_memory;
            }
            def->hostdevs[def->nhostdevs++] = hostdev;
        } else if (STREQ(arg, "-soundhw")) {
            const char *start;
            WANT_VALUE();
            start = val;
            while (start) {
                const char *tmp = strchr(start, ',');
                int type = -1;
                if (STRPREFIX(start, "pcspk")) {
                    type = VIR_DOMAIN_SOUND_MODEL_PCSPK;
                } else if (STRPREFIX(start, "sb16")) {
                    type = VIR_DOMAIN_SOUND_MODEL_SB16;
                } else if (STRPREFIX(start, "es1370")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ES1370;
                } else if (STRPREFIX(start, "ac97")) {
                    type = VIR_DOMAIN_SOUND_MODEL_AC97;
                }

                if (type != -1) {
                    virDomainSoundDefPtr snd;
                    if (VIR_ALLOC(snd) < 0)
                        goto no_memory;
                    snd->model = type;
                    if (VIR_REALLOC_N(def->sounds, def->nsounds+1) < 0) {
                        VIR_FREE(snd);
                        goto no_memory;
                    }
                    def->sounds[def->nsounds++] = snd;
                }

                start = tmp ? tmp + 1 : NULL;
            }
        } else if (STREQ(arg, "-bootloader")) {
            WANT_VALUE();
            def->os.bootloader = strdup(val);
            if (!def->os.bootloader)
                goto no_memory;
        } else if (STREQ(arg, "-vmwarevga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VMVGA;
        } else if (STREQ(arg, "-std-vga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VGA;
        } else if (STREQ(arg, "-vga")) {
            WANT_VALUE();
            video = qemuVideoTypeFromString(val);
            if (video < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown video adapter type '%s'"), val);
                goto error;
            }
        } else if (STREQ(arg, "-domid")) {
            WANT_VALUE();
            /* ignore, generted on the fly */
        } else if (STREQ(arg, "-usb")) {
            /* ignore, always added by libvirt */
        } else if (STREQ(arg, "-pidfile")) {
            WANT_VALUE();
            /* ignore, used by libvirt as needed */
        } else if (STREQ(arg, "-incoming")) {
            WANT_VALUE();
            /* ignore, used via restore/migrate APIs */
        } else if (STREQ(arg, "-monitor")) {
            WANT_VALUE();
            /* ignore, used internally by libvirt */
        } else if (STREQ(arg, "-S")) {
            /* ignore, always added by libvirt */
        } else {
            VIR_WARN(_("unknown QEMU argument '%s' during conversion"), arg);
#if 0
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("unknown argument '%s'"), arg);
            goto error;
#endif
        }
    }

#undef WANT_VALUE

    if (!nographics && def->ngraphics == 0) {
        virDomainGraphicsDefPtr sdl;
        const char *display = qemuFindEnv(progenv, "DISPLAY");
        const char *xauth = qemuFindEnv(progenv, "XAUTHORITY");
        if (VIR_ALLOC(sdl) < 0)
            goto no_memory;
        sdl->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        sdl->data.sdl.fullscreen = fullscreen;
        if (display &&
            !(sdl->data.sdl.display = strdup(display))) {
            VIR_FREE(sdl);
            goto no_memory;
        }
        if (xauth &&
            !(sdl->data.sdl.xauth = strdup(xauth))) {
            VIR_FREE(sdl);
            goto no_memory;
        }

        if (VIR_REALLOC_N(def->graphics, def->ngraphics+1) < 0) {
            virDomainGraphicsDefFree(sdl);
            goto no_memory;
        }
        def->graphics[def->ngraphics++] = sdl;
    }

    if (def->ngraphics) {
        virDomainVideoDefPtr vid;
        if (VIR_ALLOC(vid) < 0)
            goto no_memory;
        if (def->virtType == VIR_DOMAIN_VIRT_XEN)
            vid->type = VIR_DOMAIN_VIDEO_TYPE_XEN;
        else
            vid->type = video;
        vid->vram = virDomainVideoDefaultRAM(def, vid->type);
        vid->heads = 1;

        if (VIR_REALLOC_N(def->videos, def->nvideos+1) < 0) {
            virDomainVideoDefFree(vid);
            goto no_memory;
        }
        def->videos[def->nvideos++] = vid;
    }

    VIR_FREE(nics);

    if (!def->name) {
        if (!(def->name = strdup("unnamed")))
            goto no_memory;
    }

    return def;

no_memory:
    virReportOOMError(conn);
error:
    virDomainDefFree(def);
    VIR_FREE(nics);
    return NULL;
}


virDomainDefPtr qemuParseCommandLineString(virConnectPtr conn,
                                           virCapsPtr caps,
                                           const char *args)
{
    const char **progenv = NULL;
    const char **progargv = NULL;
    virDomainDefPtr def = NULL;
    int i;

    if (qemuStringToArgvEnv(args, &progenv, &progargv) < 0)
        goto cleanup;

    def = qemuParseCommandLine(conn, caps, progenv, progargv);

cleanup:
    for (i = 0 ; progargv && progargv[i] ; i++)
        VIR_FREE(progargv[i]);
    VIR_FREE(progargv);

    for (i = 0 ; progenv && progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);

    return def;
}
