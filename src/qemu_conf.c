/*
 * config.c: VM configuration management
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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

#ifdef WITH_QEMU

#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>

#if HAVE_NUMACTL
#include <numa.h>
#endif

#include "internal.h"
#include "qemu_conf.h"
#include "uuid.h"
#include "buf.h"
#include "conf.h"
#include "util.h"
#include "memory.h"
#include "verify.h"
#include "c-ctype.h"
#include "xml.h"

#define qemudLog(level, msg...) fprintf(stderr, msg)

void qemudReportError(virConnectPtr conn,
                      virDomainPtr dom,
                      virNetworkPtr net,
                      int code, const char *fmt, ...) {
    va_list args;
    char errorMessage[QEMUD_MAX_ERROR_LEN];
    const char *virerr;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, QEMUD_MAX_ERROR_LEN-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    virerr = __virErrorMsg(code, (errorMessage[0] ? errorMessage : NULL));
    __virRaiseError(conn, dom, net, VIR_FROM_QEMU, code, VIR_ERR_ERROR,
                    virerr, errorMessage, NULL, -1, -1, virerr, errorMessage);
}

int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename) {
    virConfPtr conf;
    virConfValuePtr p;

    /* Setup 2 critical defaults */
    strcpy(driver->vncListen, "127.0.0.1");
    if (!(driver->vncTLSx509certdir = strdup(SYSCONF_DIR "/pki/libvirt-vnc"))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate vncTLSx509certdir"));
        return -1;
    }

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access (filename, R_OK) == -1) return 0;

    conf = virConfReadFile (filename);
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
            qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_MEMORY,
                             "%s", _("failed to allocate vncTLSx509certdir"));
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_listen");
    CHECK_TYPE ("vnc_listen", VIR_CONF_STRING);
    if (p && p->str) {
        strncpy(driver->vncListen, p->str, sizeof(driver->vncListen));
        driver->vncListen[sizeof(driver->vncListen)-1] = '\0';
    }

    virConfFree (conf);
    return 0;
}


struct qemud_vm *qemudFindVMByID(const struct qemud_driver *driver, int id) {
    struct qemud_vm *vm = driver->vms;

    while (vm) {
        if (qemudIsActiveVM(vm) && vm->id == id)
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_vm *qemudFindVMByUUID(const struct qemud_driver *driver,
                                   const unsigned char *uuid) {
    struct qemud_vm *vm = driver->vms;

    while (vm) {
        if (!memcmp(vm->def->uuid, uuid, VIR_UUID_BUFLEN))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_vm *qemudFindVMByName(const struct qemud_driver *driver,
                                   const char *name) {
    struct qemud_vm *vm = driver->vms;

    while (vm) {
        if (STREQ(vm->def->name, name))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_network *qemudFindNetworkByUUID(const struct qemud_driver *driver,
                                             const unsigned char *uuid) {
    struct qemud_network *network = driver->networks;

    while (network) {
        if (!memcmp(network->def->uuid, uuid, VIR_UUID_BUFLEN))
            return network;
        network = network->next;
    }

    return NULL;
}

struct qemud_network *qemudFindNetworkByName(const struct qemud_driver *driver,
                                             const char *name) {
    struct qemud_network *network = driver->networks;

    while (network) {
        if (STREQ(network->def->name, name))
            return network;
        network = network->next;
    }

    return NULL;
}


/* Free all memory associated with a struct qemud_vm object */
void qemudFreeVMDef(struct qemud_vm_def *def) {
    struct qemud_vm_disk_def *disk = def->disks;
    struct qemud_vm_net_def *net = def->nets;
    struct qemud_vm_input_def *input = def->inputs;
    struct qemud_vm_chr_def *serial = def->serials;
    struct qemud_vm_chr_def *parallel = def->parallels;
    struct qemud_vm_sound_def *sound = def->sounds;

    while (disk) {
        struct qemud_vm_disk_def *prev = disk;
        disk = disk->next;
        VIR_FREE(prev);
    }
    while (net) {
        struct qemud_vm_net_def *prev = net;
        net = net->next;
        VIR_FREE(prev);
    }
    while (input) {
        struct qemud_vm_input_def *prev = input;
        input = input->next;
        VIR_FREE(prev);
    }
    while (serial) {
        struct qemud_vm_chr_def *prev = serial;
        serial = serial->next;
        VIR_FREE(prev);
    }
    while (parallel) {
        struct qemud_vm_chr_def *prev = parallel;
        parallel = parallel->next;
        VIR_FREE(prev);
    }
    while (sound) {
        struct qemud_vm_sound_def *prev = sound;
        sound = sound->next;
        VIR_FREE(prev);
    }
    xmlFree(def->keymap);
    VIR_FREE(def);
}

void qemudFreeVM(struct qemud_vm *vm) {
    qemudFreeVMDef(vm->def);
    if (vm->newDef)
        qemudFreeVMDef(vm->newDef);
    VIR_FREE(vm);
}


/* The list of possible machine types for various architectures,
   as supported by QEMU - taken from 'qemu -M ?' for each arch */
static const char *const arch_info_hvm_x86_machines[] = {
    "pc", "isapc"
};
static const char *const arch_info_hvm_mips_machines[] = {
    "mips"
};
static const char *const arch_info_hvm_sparc_machines[] = {
    "sun4m"
};
static const char *const arch_info_hvm_ppc_machines[] = {
    "g3bw", "mac99", "prep"
};

static const char *const arch_info_xen_x86_machines[] = {
    "xenner"
};

struct qemu_feature_flags {
    const char *name;
    const int default_on;
    const int toggle;
};

struct qemu_arch_info {
    const char *arch;
    int wordsize;
    const char *const *machines;
    int nmachines;
    const char *binary;
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
    {  "i686", 32, arch_info_hvm_x86_machines, 2,
       "/usr/bin/qemu", arch_info_i686_flags, 4 },
    {  "x86_64", 64, arch_info_hvm_x86_machines, 2,
       "/usr/bin/qemu-system-x86_64", arch_info_x86_64_flags, 2 },
    {  "mips", 32, arch_info_hvm_mips_machines, 1,
       "/usr/bin/qemu-system-mips", NULL, 0 },
    {  "mipsel", 32, arch_info_hvm_mips_machines, 1,
       "/usr/bin/qemu-system-mipsel", NULL, 0 },
    {  "sparc", 32, arch_info_hvm_sparc_machines, 1,
       "/usr/bin/qemu-system-sparc", NULL, 0 },
    {  "ppc", 32, arch_info_hvm_ppc_machines, 3,
       "/usr/bin/qemu-system-ppc", NULL, 0 },
};

static const struct qemu_arch_info const arch_info_xen[] = {
    {  "i686", 32, arch_info_xen_x86_machines, 1,
       "/usr/bin/xenner", arch_info_i686_flags, 4 },
    {  "x86_64", 64, arch_info_xen_x86_machines, 1,
       "/usr/bin/xenner", arch_info_x86_64_flags, 2 },
};

static int
qemudCapsInitGuest(virCapsPtr caps,
                   const char *hostmachine,
                   const struct qemu_arch_info *info,
                   int hvm) {
    virCapsGuestPtr guest;
    int i;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         hvm ? "hvm" : "xen",
                                         info->arch,
                                         info->wordsize,
                                         info->binary,
                                         NULL,
                                         info->nmachines,
                                         info->machines)) == NULL)
        return -1;

    if (hvm) {
        /* Check for existance of base emulator */
        if (access(info->binary, X_OK) == 0 &&
            virCapabilitiesAddGuestDomain(guest,
                                          "qemu",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            return -1;

        /* If guest & host match, then we can accelerate */
        if (STREQ(info->arch, hostmachine)) {
            if (access("/dev/kqemu", F_OK) == 0 &&
                virCapabilitiesAddGuestDomain(guest,
                                              "kqemu",
                                              NULL,
                                              NULL,
                                              0,
                                              NULL) == NULL)
                return -1;

            if (access("/dev/kvm", F_OK) == 0 &&
                virCapabilitiesAddGuestDomain(guest,
                                              "kvm",
                                              "/usr/bin/qemu-kvm",
                                              NULL,
                                              0,
                                              NULL) == NULL)
                return -1;
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

#if HAVE_NUMACTL
#define MAX_CPUS 4096
#define MAX_CPUS_MASK_SIZE (sizeof(unsigned long))
#define MAX_CPUS_MASK_LEN (MAX_CPUS / MAX_CPUS_MASK_SIZE)
#define MAX_CPUS_MASK_BYTES (MAX_CPUS / 8)

#define MASK_CPU_ISSET(mask, cpu) \
    (((mask)[((cpu) / MAX_CPUS_MASK_SIZE)] >> ((cpu) % MAX_CPUS_MASK_SIZE)) & 1)

static int
qemudCapsInitNUMA(virCapsPtr caps)
{
    int n, i;
    unsigned long *mask = NULL;
    int ncpus;
    int *cpus = NULL;
    int ret = -1;

    if (numa_available() < 0)
        return 0;

    if (VIR_ALLOC_N(mask, MAX_CPUS_MASK_LEN) < 0)
        goto cleanup;

    for (n = 0 ; n <= numa_max_node() ; n++) {
        if (numa_node_to_cpus(n, mask, MAX_CPUS_MASK_BYTES) < 0)
            goto cleanup;

        for (ncpus = 0, i = 0 ; i < MAX_CPUS ; i++)
            if (MASK_CPU_ISSET(mask, i))
                ncpus++;

        if (VIR_ALLOC_N(cpus, ncpus) < 0)
            goto cleanup;

        for (ncpus = 0, i = 0 ; i < MAX_CPUS ; i++)
            if (MASK_CPU_ISSET(mask, i))
                cpus[ncpus++] = i;

        if (virCapabilitiesAddHostNUMACell(caps,
                                           n,
                                           ncpus,
                                           cpus) < 0)
            goto cleanup;

        VIR_FREE(cpus);
    }

    ret = 0;

cleanup:
    VIR_FREE(cpus);
    VIR_FREE(mask);
    return ret;
}
#else
static int qemudCapsInitNUMA(virCapsPtr caps ATTRIBUTE_UNUSED) { return 0; }
#endif

virCapsPtr qemudCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    int i;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto no_memory;

    if (qemudCapsInitNUMA(caps) < 0)
        goto no_memory;

    for (i = 0 ; i < (sizeof(arch_info_hvm)/sizeof(arch_info_hvm[0])) ; i++)
        if (qemudCapsInitGuest(caps,
                               utsname.machine,
                               &arch_info_hvm[i], 1) < 0)
            goto no_memory;

    if (access("/usr/bin/xenner", X_OK) == 0 &&
        access("/dev/kvm", F_OK) == 0) {
        for (i = 0 ; i < (sizeof(arch_info_xen)/sizeof(arch_info_xen[0])) ; i++)
            /* Allow Xen 32-on-32, 32-on-64 and 64-on-64 */
            if (STREQ(arch_info_xen[i].arch, utsname.machine) ||
                (STREQ(utsname.machine, "x86_64") &&
                 STREQ(arch_info_xen[i].arch, "i686"))) {
                if (qemudCapsInitGuest(caps,
                                       utsname.machine,
                                       &arch_info_xen[i], 0) < 0)
                    goto no_memory;
            }
    }

    return caps;

 no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}


static int qemudExtractVersionInfo(const char *qemu, int *version, int *flags) {
    pid_t child;
    int newstdout[2];

    *flags = 0;
    *version = 0;

    if (pipe(newstdout) < 0) {
        return -1;
    }

    if ((child = fork()) < 0) {
        close(newstdout[0]);
        close(newstdout[1]);
        return -1;
    }

    if (child == 0) { /* Kid */
        /* Just in case QEMU is translated someday we force to C locale.. */
        const char *const qemuenv[] = { "LANG=C", NULL };

        if (close(STDIN_FILENO) < 0)
            goto cleanup1;
        if (close(STDERR_FILENO) < 0)
            goto cleanup1;
        if (close(newstdout[0]) < 0)
            goto cleanup1;
        if (dup2(newstdout[1], STDOUT_FILENO) < 0)
            goto cleanup1;

        /* Passing -help, rather than relying on no-args which doesn't
           always work */
        execle(qemu, qemu, "-help", (char*)NULL, qemuenv);

    cleanup1:
        _exit(-1); /* Just in case */
    } else { /* Parent */
        char help[8192]; /* Ought to be enough to hold QEMU help screen */
        int got = 0, ret = -1;
        int major, minor, micro;

        if (close(newstdout[1]) < 0)
            goto cleanup2;

        while (got < (sizeof(help)-1)) {
            int len;
            if ((len = read(newstdout[0], help+got, sizeof(help)-got-1)) <= 0) {
                if (!len)
                    break;
                if (errno == EINTR)
                    continue;
                goto cleanup2;
            }
            got += len;
        }
        help[got] = '\0';

        if (sscanf(help, "QEMU PC emulator version %d.%d.%d", &major,&minor, &micro) != 3) {
            goto cleanup2;
        }

        *version = (major * 1000 * 1000) + (minor * 1000) + micro;
        if (strstr(help, "-no-kqemu"))
            *flags |= QEMUD_CMD_FLAG_KQEMU;
        if (strstr(help, "-no-reboot"))
            *flags |= QEMUD_CMD_FLAG_NO_REBOOT;
        if (strstr(help, "-name"))
            *flags |= QEMUD_CMD_FLAG_NAME;
        if (strstr(help, "-drive"))
            *flags |= QEMUD_CMD_FLAG_DRIVE;
        if (strstr(help, "boot=on"))
            *flags |= QEMUD_CMD_FLAG_DRIVE_BOOT;
        if (*version >= 9000)
            *flags |= QEMUD_CMD_FLAG_VNC_COLON;
        ret = 0;

        qemudDebug("Version %d %d %d  Cooked version: %d, with flags ? %d",
                   major, minor, micro, *version, *flags);

    cleanup2:
        if (close(newstdout[0]) < 0)
            ret = -1;

    rewait:
        if (waitpid(child, &got, 0) != child) {
            if (errno == EINTR) {
                goto rewait;
            }
            qemudLog(QEMUD_ERR,
                     _("Unexpected exit status from qemu %d pid %lu"),
                     got, (unsigned long)child);
            ret = -1;
        }
        /* Check & log unexpected exit status, but don't fail,
         * as there's really no need to throw an error if we did
         * actually read a valid version number above */
        if (WEXITSTATUS(got) != 0) {
            qemudLog(QEMUD_WARN,
                     _("Unexpected exit status '%d', qemu probably failed"),
                     got);
        }

        return ret;
    }
}

int qemudExtractVersion(virConnectPtr conn,
                        struct qemud_driver *driver) {
    const char *binary;
    struct stat sb;
    int ignored;

    if (driver->qemuVersion > 0)
        return 0;

    if ((binary = virCapabilitiesDefaultGuestEmulator(driver->caps,
                                                      "hvm",
                                                      "i686",
                                                      "qemu")) == NULL)
        return -1;

    if (stat(binary, &sb) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot find QEMU binary %s: %s"), binary,
                         strerror(errno));
        return -1;
    }

    if (qemudExtractVersionInfo(binary, &driver->qemuVersion, &ignored) < 0) {
        return -1;
    }

    return 0;
}

/* Converts def->virtType to applicable string type
 * @param type integer virt type
 * @return string type on success, NULL on fail
 */
const char * qemudVirtTypeToString(int type) {
    switch (type) {
        case QEMUD_VIRT_QEMU:
            return "qemu";
        case QEMUD_VIRT_KQEMU:
            return "kqemu";
        case QEMUD_VIRT_KVM:
            return "kvm";
    }
    return NULL;
}

/* Parse the XML definition for a disk
 * @param disk pre-allocated & zero'd disk record
 * @param node XML nodeset to parse for disk definition
 * @return 0 on success, -1 on failure
 */
static int qemudParseDiskXML(virConnectPtr conn,
                             struct qemud_vm_disk_def *disk,
                             xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar *device = NULL;
    xmlChar *source = NULL;
    xmlChar *target = NULL;
    xmlChar *type = NULL;
    xmlChar *bus = NULL;
    int typ = 0;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "file"))
            typ = QEMUD_DISK_FILE;
        else if (xmlStrEqual(type, BAD_CAST "block"))
            typ = QEMUD_DISK_BLOCK;
        else {
            typ = QEMUD_DISK_FILE;
        }
        xmlFree(type);
        type = NULL;
    }

    device = xmlGetProp(node, BAD_CAST "device");

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((source == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "source"))) {

                if (typ == QEMUD_DISK_FILE)
                    source = xmlGetProp(cur, BAD_CAST "file");
                else
                    source = xmlGetProp(cur, BAD_CAST "dev");
            } else if ((target == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "target"))) {
                target = xmlGetProp(cur, BAD_CAST "dev");
                bus = xmlGetProp(cur, BAD_CAST "bus");
            } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
                disk->readonly = 1;
            }
        }
        cur = cur->next;
    }

    if (source == NULL) {
        /* There is a case without the source
         * to the CD-ROM device
         */
        if (!device || STRNEQ((const char *) device, "cdrom")) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SOURCE,
                             target ? "%s" : NULL, target);
            goto error;
        }
    }

    if (target == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_TARGET, source ? "%s" : NULL, source);
        goto error;
    }

    if (device &&
        STREQ((const char *)device, "floppy") &&
        STRNEQ((const char *)target, "fda") &&
        STRNEQ((const char *)target, "fdb")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Invalid floppy device name: %s"), target);
        goto error;
    }

    if (device &&
        STREQ((const char *)device, "cdrom") &&
        STRNEQ((const char *)target, "hdc")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Invalid cdrom device name: %s"), target);
        goto error;
    }

    if (device &&
        STREQ((const char *)device, "cdrom"))
        disk->readonly = 1;

    if ((!device || STREQ((const char *)device, "disk")) &&
        !STRPREFIX((const char *)target, "hd") &&
        !STRPREFIX((const char *)target, "sd") &&
        !STRPREFIX((const char *)target, "vd") &&
        !STRPREFIX((const char *)target, "xvd")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Invalid harddisk device name: %s"), target);
        goto error;
    }

    strncpy(disk->src, (source ? (const char *) source : "\0"), NAME_MAX-1);
    disk->src[NAME_MAX-1] = '\0';

    strncpy(disk->dst, (const char *)target, NAME_MAX-1);
    disk->dst[NAME_MAX-1] = '\0';
    disk->type = typ;

    if (!device)
        disk->device = QEMUD_DISK_DISK;
    else if (STREQ((const char *)device, "disk"))
        disk->device = QEMUD_DISK_DISK;
    else if (STREQ((const char *)device, "cdrom"))
        disk->device = QEMUD_DISK_CDROM;
    else if (STREQ((const char *)device, "floppy"))
        disk->device = QEMUD_DISK_FLOPPY;
    else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Invalid device type: %s"), device);
        goto error;
    }

    if (!bus) {
        if (disk->device == QEMUD_DISK_FLOPPY) {
            disk->bus = QEMUD_DISK_BUS_FDC;
        } else {
            if (STRPREFIX((const char *)target, "hd"))
                disk->bus = QEMUD_DISK_BUS_IDE;
            else if (STRPREFIX((const char *)target, "sd"))
                disk->bus = QEMUD_DISK_BUS_SCSI;
            else if (STRPREFIX((const char *)target, "vd"))
                disk->bus = QEMUD_DISK_BUS_VIRTIO;
            else if (STRPREFIX((const char *)target, "xvd"))
                disk->bus = QEMUD_DISK_BUS_XEN;
            else
                disk->bus = QEMUD_DISK_BUS_IDE;
        }
    } else if (STREQ((const char *)bus, "ide"))
        disk->bus = QEMUD_DISK_BUS_IDE;
    else if (STREQ((const char *)bus, "fdc"))
        disk->bus = QEMUD_DISK_BUS_FDC;
    else if (STREQ((const char *)bus, "scsi"))
        disk->bus = QEMUD_DISK_BUS_SCSI;
    else if (STREQ((const char *)bus, "virtio"))
        disk->bus = QEMUD_DISK_BUS_VIRTIO;
    else if (STREQ((const char *)bus, "xen"))
        disk->bus = QEMUD_DISK_BUS_XEN;
    else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Invalid bus type: %s"), bus);
        goto error;
    }

    if (disk->device == QEMUD_DISK_FLOPPY &&
        disk->bus != QEMUD_DISK_BUS_FDC) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Invalid bus type '%s' for floppy disk"), bus);
        goto error;
    }

    xmlFree(device);
    xmlFree(target);
    xmlFree(source);
    xmlFree(bus);

    return 0;

 error:
    xmlFree(bus);
    xmlFree(type);
    xmlFree(target);
    xmlFree(source);
    xmlFree(device);
    return -1;
}

static void qemudRandomMAC(struct qemud_vm_net_def *net) {
    net->mac[0] = 0x52;
    net->mac[1] = 0x54;
    net->mac[2] = 0x00;
    net->mac[3] = 1 + (int)(256*(rand()/(RAND_MAX+1.0)));
    net->mac[4] = 1 + (int)(256*(rand()/(RAND_MAX+1.0)));
    net->mac[5] = 1 + (int)(256*(rand()/(RAND_MAX+1.0)));
}


/* Parse the XML definition for a network interface
 * @param net pre-allocated & zero'd net record
 * @param node XML nodeset to parse for net definition
 * @return 0 on success, -1 on failure
 */
static int qemudParseInterfaceXML(virConnectPtr conn,
                                  struct qemud_vm_net_def *net,
                                  xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar *macaddr = NULL;
    xmlChar *type = NULL;
    xmlChar *network = NULL;
    xmlChar *bridge = NULL;
    xmlChar *ifname = NULL;
    xmlChar *script = NULL;
    xmlChar *address = NULL;
    xmlChar *port = NULL;
    xmlChar *model = NULL;

    net->type = QEMUD_NET_USER;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "user"))
            net->type = QEMUD_NET_USER;
        else if (xmlStrEqual(type, BAD_CAST "ethernet"))
            net->type = QEMUD_NET_ETHERNET;
        else if (xmlStrEqual(type, BAD_CAST "server"))
            net->type = QEMUD_NET_SERVER;
        else if (xmlStrEqual(type, BAD_CAST "client"))
            net->type = QEMUD_NET_CLIENT;
        else if (xmlStrEqual(type, BAD_CAST "mcast"))
            net->type = QEMUD_NET_MCAST;
        else if (xmlStrEqual(type, BAD_CAST "network"))
            net->type = QEMUD_NET_NETWORK;
        else if (xmlStrEqual(type, BAD_CAST "bridge"))
            net->type = QEMUD_NET_BRIDGE;
        else
            net->type = QEMUD_NET_USER;
        xmlFree(type);
        type = NULL;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((macaddr == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "mac"))) {
                macaddr = xmlGetProp(cur, BAD_CAST "address");
            } else if ((network == NULL) &&
                       (net->type == QEMUD_NET_NETWORK) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                network = xmlGetProp(cur, BAD_CAST "network");
            } else if ((network == NULL) &&
                       (net->type == QEMUD_NET_BRIDGE) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                bridge = xmlGetProp(cur, BAD_CAST "bridge");
            } else if ((network == NULL) &&
                       ((net->type == QEMUD_NET_SERVER) ||
                        (net->type == QEMUD_NET_CLIENT) ||
                        (net->type == QEMUD_NET_MCAST)) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                address = xmlGetProp(cur, BAD_CAST "address");
                port = xmlGetProp(cur, BAD_CAST "port");
            } else if ((ifname == NULL) &&
                       ((net->type == QEMUD_NET_NETWORK) ||
                        (net->type == QEMUD_NET_ETHERNET) ||
                        (net->type == QEMUD_NET_BRIDGE)) &&
                       xmlStrEqual(cur->name, BAD_CAST "target")) {
                ifname = xmlGetProp(cur, BAD_CAST "dev");
                if (STRPREFIX((const char*)ifname, "vnet")) {
                    /* An auto-generated target name, blank it out */
                    xmlFree(ifname);
                    ifname = NULL;
                }
            } else if ((script == NULL) &&
                       (net->type == QEMUD_NET_ETHERNET) &&
                       xmlStrEqual(cur->name, BAD_CAST "script")) {
                script = xmlGetProp(cur, BAD_CAST "path");
            } else if (xmlStrEqual (cur->name, BAD_CAST "model")) {
                model = xmlGetProp (cur, BAD_CAST "type");
            }
        }
        cur = cur->next;
    }

    if (macaddr) {
        unsigned int mac[6];
        sscanf((const char *)macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
               (unsigned int*)&mac[0],
               (unsigned int*)&mac[1],
               (unsigned int*)&mac[2],
               (unsigned int*)&mac[3],
               (unsigned int*)&mac[4],
               (unsigned int*)&mac[5]);
        net->mac[0] = mac[0];
        net->mac[1] = mac[1];
        net->mac[2] = mac[2];
        net->mac[3] = mac[3];
        net->mac[4] = mac[4];
        net->mac[5] = mac[5];

        xmlFree(macaddr);
        macaddr = NULL;
    } else {
        qemudRandomMAC(net);
    }

    if (net->type == QEMUD_NET_NETWORK) {
        int len;

        if (network == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("No <source> 'network' attribute specified with <interface type='network'/>"));
            goto error;
        } else if ((len = xmlStrlen(network)) >= (QEMUD_MAX_NAME_LEN-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Network name '%s' too long"), network);
            goto error;
        } else {
            strncpy(net->dst.network.name, (char *)network, len);
            net->dst.network.name[len] = '\0';
        }

        if (network) {
            xmlFree(network);
            network = NULL;
        }

        if (ifname != NULL) {
            if ((len = xmlStrlen(ifname)) >= (BR_IFNAME_MAXLEN-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("TAP interface name '%s' is too long"),
                                 ifname);
                goto error;
            } else {
                strncpy(net->dst.network.ifname, (char *)ifname, len);
                net->dst.network.ifname[len] = '\0';
            }
            xmlFree(ifname);
            ifname = NULL;
        }
    } else if (net->type == QEMUD_NET_ETHERNET) {
        int len;

        if (script != NULL) {
            if ((len = xmlStrlen(script)) >= (PATH_MAX-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("TAP script path '%s' is too long"), script);
                goto error;
            } else {
                strncpy(net->dst.ethernet.script, (char *)script, len);
                net->dst.ethernet.script[len] = '\0';
            }
            xmlFree(script);
            script = NULL;
        }
        if (ifname != NULL) {
            if ((len = xmlStrlen(ifname)) >= (BR_IFNAME_MAXLEN-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("TAP interface name '%s' is too long"),
                                 ifname);
                goto error;
            } else {
                strncpy(net->dst.ethernet.ifname, (char *)ifname, len);
                net->dst.ethernet.ifname[len] = '\0';
            }
            xmlFree(ifname);
        }
    } else if (net->type == QEMUD_NET_BRIDGE) {
        int len;

        if (bridge == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("No <source> 'dev' attribute specified with <interface type='bridge'/>"));
            goto error;
        } else if ((len = xmlStrlen(bridge)) >= (BR_IFNAME_MAXLEN-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("TAP bridge path '%s' is too long"), bridge);
            goto error;
        } else {
            strncpy(net->dst.bridge.brname, (char *)bridge, len);
            net->dst.bridge.brname[len] = '\0';
        }

        xmlFree(bridge);
        bridge = NULL;

        if (ifname != NULL) {
            if ((len = xmlStrlen(ifname)) >= (BR_IFNAME_MAXLEN-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("TAP interface name '%s' is too long"), ifname);
                goto error;
            } else {
                strncpy(net->dst.bridge.ifname, (char *)ifname, len);
                net->dst.bridge.ifname[len] = '\0';
            }
            xmlFree(ifname);
        }
    } else if (net->type == QEMUD_NET_CLIENT ||
               net->type == QEMUD_NET_SERVER ||
               net->type == QEMUD_NET_MCAST) {
        int len = 0;
        char *ret;

        if (port == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("No <source> 'port' attribute specified with socket interface"));
            goto error;
        }
        if (!(net->dst.socket.port = strtol((char*)port, &ret, 10)) &&
            ret == (char*)port) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Cannot parse <source> 'port' attribute with socket interface"));
            goto error;
        }
        xmlFree(port);
        port = NULL;

        if (address == NULL) {
            if (net->type == QEMUD_NET_CLIENT ||
                net->type == QEMUD_NET_MCAST) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("No <source> 'address' attribute specified with socket interface"));
                goto error;
            }
        } else if ((len = xmlStrlen(address)) >= (BR_INET_ADDR_MAXLEN)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("IP address '%s' is too long"), address);
            goto error;
        }
        if (address == NULL) {
            net->dst.socket.address[0] = '\0';
        } else {
            strncpy(net->dst.socket.address, (char*)address,len);
            net->dst.socket.address[len] = '\0';
        }
        xmlFree(address);
    }

    /* NIC model (see -net nic,model=?).  We only check that it looks
     * reasonable, not that it is a supported NIC type.  FWIW kvm
     * supports these types as of April 2008:
     * i82551 i82557b i82559er ne2k_pci pcnet rtl8139 e1000 virtio
     */
    if (model != NULL) {
        int i, len;

        len = xmlStrlen (model);
        if (len >= QEMUD_MODEL_MAX_LEN) {
            qemudReportError (conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                              _("Model name '%s' is too long"), model);
            goto error;
        }
        for (i = 0; i < len; ++i) {
            int char_ok = c_isalnum(model[i]) || model[i] == '_';
            if (!char_ok) {
                qemudReportError (conn, NULL, NULL, VIR_ERR_INVALID_ARG, "%s",
                                  _("Model name contains invalid characters"));
                goto error;
            }
        }
        strncpy (net->model, (const char*) model, len);
        net->model[len] = '\0';

        xmlFree (model);
        model = NULL;
    } else
        net->model[0] = '\0';

    return 0;

 error:
    xmlFree(network);
    xmlFree(address);
    xmlFree(port);
    xmlFree(ifname);
    xmlFree(script);
    xmlFree(bridge);
    xmlFree(model);
    return -1;
}


/* Parse the XML definition for a character device
 * @param net pre-allocated & zero'd net record
 * @param node XML nodeset to parse for net definition
 * @return 0 on success, -1 on failure
 *
 * The XML we're dealing with looks like
 *
 * <serial type="pty">
 *   <source path="/dev/pts/3"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="dev">
 *   <source path="/dev/ttyS0"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="tcp">
 *   <source mode="connect" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="tcp">
 *   <source mode="bind" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="udp">
 *   <source mode="bind" host="0.0.0.0" service="2445"/>
 *   <source mode="connect" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="unix">
 *   <source mode="bind" path="/tmp/foo"/>
 *   <target port="1"/>
 * </serial>
 *
 */
static int qemudParseCharXML(virConnectPtr conn,
                             struct qemud_vm_chr_def *chr,
                             int portNum,
                             xmlNodePtr node) {
    xmlNodePtr cur;
    xmlChar *type = NULL;
    xmlChar *bindHost = NULL;
    xmlChar *bindService = NULL;
    xmlChar *connectHost = NULL;
    xmlChar *connectService = NULL;
    xmlChar *path = NULL;
    xmlChar *mode = NULL;
    xmlChar *protocol = NULL;
    int ret = -1;

    chr->srcType = QEMUD_CHR_SRC_TYPE_PTY;
    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "null"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_NULL;
        else if (xmlStrEqual(type, BAD_CAST "vc"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_VC;
        else if (xmlStrEqual(type, BAD_CAST "pty"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_PTY;
        else if (xmlStrEqual(type, BAD_CAST "dev"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_DEV;
        else if (xmlStrEqual(type, BAD_CAST "file"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_FILE;
        else if (xmlStrEqual(type, BAD_CAST "pipe"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_PIPE;
        else if (xmlStrEqual(type, BAD_CAST "stdio"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_STDIO;
        else if (xmlStrEqual(type, BAD_CAST "udp"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_UDP;
        else if (xmlStrEqual(type, BAD_CAST "tcp"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_TCP;
        else if (xmlStrEqual(type, BAD_CAST "unix"))
            chr->srcType = QEMUD_CHR_SRC_TYPE_UNIX;
        else
            chr->srcType = QEMUD_CHR_SRC_TYPE_NULL;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                if (mode == NULL)
                    mode = xmlGetProp(cur, BAD_CAST "mode");

                switch (chr->srcType) {
                case QEMUD_CHR_SRC_TYPE_PTY:
                case QEMUD_CHR_SRC_TYPE_DEV:
                case QEMUD_CHR_SRC_TYPE_FILE:
                case QEMUD_CHR_SRC_TYPE_PIPE:
                case QEMUD_CHR_SRC_TYPE_UNIX:
                    if (path == NULL)
                        path = xmlGetProp(cur, BAD_CAST "path");

                    break;

                case QEMUD_CHR_SRC_TYPE_UDP:
                case QEMUD_CHR_SRC_TYPE_TCP:
                    if (mode == NULL ||
                        STREQ((const char *)mode, "connect")) {

                        if (connectHost == NULL)
                            connectHost = xmlGetProp(cur, BAD_CAST "host");
                        if (connectService == NULL)
                            connectService = xmlGetProp(cur, BAD_CAST "service");
                    } else {
                        if (bindHost == NULL)
                            bindHost = xmlGetProp(cur, BAD_CAST "host");
                        if (bindService == NULL)
                            bindService = xmlGetProp(cur, BAD_CAST "service");
                    }

                    if (chr->srcType == QEMUD_CHR_SRC_TYPE_UDP) {
                        xmlFree(mode);
                        mode = NULL;
                    }
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "protocol")) {
                if (protocol == NULL)
                    protocol = xmlGetProp(cur, BAD_CAST "type");
            }
        }
        cur = cur->next;
    }


    chr->dstPort = portNum;

    switch (chr->srcType) {
    case QEMUD_CHR_SRC_TYPE_NULL:
        /* Nada */
        break;

    case QEMUD_CHR_SRC_TYPE_VC:
        break;

    case QEMUD_CHR_SRC_TYPE_PTY:
        /* @path attribute is an output only property - pty is auto-allocted */
        break;

    case QEMUD_CHR_SRC_TYPE_DEV:
    case QEMUD_CHR_SRC_TYPE_FILE:
    case QEMUD_CHR_SRC_TYPE_PIPE:
        if (path == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Missing source path attribute for char device"));
            goto cleanup;
        }

        strncpy(chr->srcData.file.path, (const char *)path,
                sizeof(chr->srcData.file.path));
        NUL_TERMINATE(chr->srcData.file.path);
        break;

    case QEMUD_CHR_SRC_TYPE_STDIO:
        /* Nada */
        break;

    case QEMUD_CHR_SRC_TYPE_TCP:
        if (mode == NULL ||
            STREQ((const char *)mode, "connect")) {
            if (connectHost == NULL) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source host attribute for char device"));
                goto cleanup;
            }
            if (connectService == NULL) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source service attribute for char device"));
                goto cleanup;
            }

            strncpy(chr->srcData.tcp.host, (const char *)connectHost,
                    sizeof(chr->srcData.tcp.host));
            NUL_TERMINATE(chr->srcData.tcp.host);
            strncpy(chr->srcData.tcp.service, (const char *)connectService,
                    sizeof(chr->srcData.tcp.service));
            NUL_TERMINATE(chr->srcData.tcp.service);

            chr->srcData.tcp.listen = 0;
        } else {
            if (bindHost == NULL) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source host attribute for char device"));
                goto cleanup;
            }
            if (bindService == NULL) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source service attribute for char device"));
                goto cleanup;
            }

            strncpy(chr->srcData.tcp.host, (const char *)bindHost,
                    sizeof(chr->srcData.tcp.host));
            NUL_TERMINATE(chr->srcData.tcp.host);
            strncpy(chr->srcData.tcp.service, (const char *)bindService,
                    sizeof(chr->srcData.tcp.service));
            NUL_TERMINATE(chr->srcData.tcp.service);

            chr->srcData.tcp.listen = 1;
        }
        if (protocol != NULL &&
            STREQ((const char *)protocol, "telnet"))
            chr->srcData.tcp.protocol = QEMUD_CHR_SRC_TCP_PROTOCOL_TELNET;
        else
            chr->srcData.tcp.protocol = QEMUD_CHR_SRC_TCP_PROTOCOL_RAW;
        break;

    case QEMUD_CHR_SRC_TYPE_UDP:
        if (connectService == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Missing source service attribute for char device"));
            goto cleanup;
        }

        if (connectHost != NULL) {
            strncpy(chr->srcData.udp.connectHost, (const char *)connectHost,
                    sizeof(chr->srcData.udp.connectHost));
            NUL_TERMINATE(chr->srcData.udp.connectHost);
        }
        strncpy(chr->srcData.udp.connectService, (const char *)connectService,
                sizeof(chr->srcData.udp.connectService));
        NUL_TERMINATE(chr->srcData.udp.connectService);

        if (bindHost != NULL) {
            strncpy(chr->srcData.udp.bindHost, (const char *)bindHost,
                    sizeof(chr->srcData.udp.bindHost));
            NUL_TERMINATE(chr->srcData.udp.bindHost);
        }
        if (bindService != NULL) {
            strncpy(chr->srcData.udp.bindService, (const char *)bindService,
                    sizeof(chr->srcData.udp.bindService));
            NUL_TERMINATE(chr->srcData.udp.bindService);
        }
        break;

    case QEMUD_CHR_SRC_TYPE_UNIX:
        if (path == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Missing source path attribute for char device"));
            goto cleanup;
        }

        if (mode != NULL &&
            STRNEQ((const char *)mode, "connect"))
            chr->srcData.nix.listen = 1;
        else
            chr->srcData.nix.listen = 0;

        strncpy(chr->srcData.nix.path, (const char *)path,
                sizeof(chr->srcData.nix.path));
        NUL_TERMINATE(chr->srcData.nix.path);
        break;
    }

    ret = 0;

cleanup:
    xmlFree(mode);
    xmlFree(protocol);
    xmlFree(type);
    xmlFree(bindHost);
    xmlFree(bindService);
    xmlFree(connectHost);
    xmlFree(connectService);
    xmlFree(path);

    return ret;
}


static int qemudParseCharXMLDevices(virConnectPtr conn,
                                    xmlXPathContextPtr ctxt,
                                    const char *xpath,
                                    unsigned int *ndevs,
                                    struct qemud_vm_chr_def **devs)
{
    xmlXPathObjectPtr obj;
    int i, ret = -1;

    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        struct qemud_vm_chr_def *prev = *devs;
        if (ndevs == NULL &&
            obj->nodesetval->nodeNr > 1) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("too many character devices"));
            goto cleanup;
        }

        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            struct qemud_vm_chr_def *chr;
            if (VIR_ALLOC(chr) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                                 "%s",
                                 _("failed to allocate space for char device"));
                goto cleanup;
            }

            if (qemudParseCharXML(conn, chr, i, obj->nodesetval->nodeTab[i]) < 0) {
                VIR_FREE(chr);
                goto cleanup;
            }
            if (ndevs)
                (*ndevs)++;
            chr->next = NULL;
            if (i == 0) {
                *devs = chr;
            } else {
                prev->next = chr;
            }
            prev = chr;
        }
    }

    ret = 0;

cleanup:
    xmlXPathFreeObject(obj);
    return ret;
}


/* Parse the XML definition for a network interface */
static int qemudParseInputXML(virConnectPtr conn,
                              const struct qemud_vm_def *vm,
                              struct qemud_vm_input_def *input,
                              xmlNodePtr node) {
    xmlChar *type = NULL;
    xmlChar *bus = NULL;

    type = xmlGetProp(node, BAD_CAST "type");
    bus = xmlGetProp(node, BAD_CAST "bus");

    if (!type) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing input device type"));
        goto error;
    }

    if (STREQ((const char *)type, "mouse")) {
        input->type = QEMU_INPUT_TYPE_MOUSE;
    } else if (STREQ((const char *)type, "tablet")) {
        input->type = QEMU_INPUT_TYPE_TABLET;
    } else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unsupported input device type %s"),
                         (const char*)type);
        goto error;
    }

    if (bus) {
        if (STREQ(vm->os.type, "hvm")) {
            if (STREQ((const char*)bus, "ps2")) { /* Only allow mouse */
                if (input->type != QEMU_INPUT_TYPE_MOUSE) {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("ps2 bus does not support %s input device"),
                                     (const char*)type);
                    goto error;
                }
                input->bus = QEMU_INPUT_BUS_PS2;
            } else if (STREQ((const char *)bus, "usb")) { /* Allow mouse & tablet */
                input->bus = QEMU_INPUT_BUS_USB;
            } else {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unsupported input bus %s"), (const char*)bus);
                goto error;
            }
        } else {
            if (STREQ((const char *)bus, "xen")) { /* Allow mouse only */
                input->bus = QEMU_INPUT_BUS_XEN;
                if (input->type != QEMU_INPUT_TYPE_MOUSE) {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("xen bus does not support %s input device"),
                                     (const char*)type);
                    goto error;
                }
            } else {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unsupported input bus %s"), (const char*)bus);
                goto error;
            }
        }
    } else {
        if (STREQ(vm->os.type, "hvm")) {
            if (input->type == QEMU_INPUT_TYPE_MOUSE)
                input->bus = QEMU_INPUT_BUS_PS2;
            else
                input->bus = QEMU_INPUT_BUS_USB;
        } else {
            input->bus = QEMU_INPUT_BUS_XEN;
        }
    }

    xmlFree(type);
    xmlFree(bus);

    return 0;

 error:
    xmlFree(type);
    xmlFree(bus);

    return -1;
}

static int qemudDiskCompare(const void *aptr, const void *bptr) {
    struct qemud_vm_disk_def *a = (struct qemud_vm_disk_def *) aptr;
    struct qemud_vm_disk_def *b = (struct qemud_vm_disk_def *) bptr;
    if (a->bus == b->bus)
        return virDiskNameToIndex(a->dst) - virDiskNameToIndex(b->dst);
    else
        return a->bus - b->bus;
}

static const char *qemudBusIdToName(int busId, int qemuIF) {
    const char *busnames[] = { "ide",
                               (qemuIF ? "floppy" : "fdc"),
                               "scsi",
                               "virtio",
                               "xen"};
    verify_true(ARRAY_CARDINALITY(busnames) == QEMUD_DISK_BUS_LAST);

    return busnames[busId];
}

/* Sound device helper functions */
static int qemudSoundModelFromString(const char *model) {
    if (STREQ(model, "sb16")) {
        return QEMU_SOUND_SB16;
    } else if (STREQ(model, "es1370")) {
        return QEMU_SOUND_ES1370;
    } else if (STREQ(model, "pcspk")) {
        return QEMU_SOUND_PCSPK;
    }

    return -1;
}

static const char *qemudSoundModelToString(const int model) {

    if (model == QEMU_SOUND_SB16) {
        return "sb16";
    } else if (model == QEMU_SOUND_ES1370) {
        return "es1370";
    } else if (model == QEMU_SOUND_PCSPK) {
        return "pcspk";
    }

    return NULL;
}


static int qemudParseSoundXML(virConnectPtr conn,
                              struct qemud_vm_sound_def *sound,
                              const xmlNodePtr node) {

    int err = -1;
    xmlChar *model = NULL;
    model = xmlGetProp(node, BAD_CAST "model");

    if (!model) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing sound model"));
        goto error;
    }
    if ((sound->model = qemudSoundModelFromString((char *) model)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("invalid sound model '%s'"), (char *) model);
        goto error;
    }

    err = 0;
 error:
    xmlFree(model);
    return err;
}

/*
 * Parses a libvirt XML definition of a guest, and populates the
 * the qemud_vm struct with matching data about the guests config
 */
static struct qemud_vm_def *qemudParseXML(virConnectPtr conn,
                                          struct qemud_driver *driver,
                                          xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlChar *prop = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    char *conv = NULL;
    int i;
    struct qemud_vm_def *def;

    if (VIR_ALLOC(def) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for xmlXPathContext"));
        return NULL;
    }

    /* Prepare parser / xpath context */
    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "domain"))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("incorrect root element"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for xmlXPathContext"));
        goto error;
    }


    /* Find out what type of QEMU virtualization to use */
    if (!(prop = xmlGetProp(root, BAD_CAST "type"))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing domain type attribute"));
        goto error;
    }

    if (STREQ((char *)prop, "qemu"))
        def->virtType = QEMUD_VIRT_QEMU;
    else if (STREQ((char *)prop, "kqemu"))
        def->virtType = QEMUD_VIRT_KQEMU;
    else if (STREQ((char *)prop, "kvm"))
        def->virtType = QEMUD_VIRT_KVM;
    else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("invalid domain type attribute"));
        goto error;
    }
    VIR_FREE(prop);


    /* Extract domain name */
    obj = xmlXPathEval(BAD_CAST "string(/domain/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_NAME, NULL);
        goto error;
    }
    if (strlen((const char *)obj->stringval) >= (QEMUD_MAX_NAME_LEN-1)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("domain name length too long"));
        goto error;
    }
    strcpy(def->name, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);


    /* Extract domain uuid */
    obj = xmlXPathEval(BAD_CAST "string(/domain/uuid[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        int err;
        if ((err = virUUIDGenerate(def->uuid))) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to generate UUID: %s"), strerror(err));
            goto error;
        }
    } else if (virUUIDParse((const char *)obj->stringval, def->uuid) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("malformed uuid element"));
        goto error;
    }
    xmlXPathFreeObject(obj);


    /* Extract domain memory */
    obj = xmlXPathEval(BAD_CAST "string(/domain/memory[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing memory element"));
        goto error;
    } else {
        conv = NULL;
        def->maxmem = strtoll((const char*)obj->stringval, &conv, 10);
        if (conv == (const char*)obj->stringval) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("malformed memory information"));
            goto error;
        }
    }
    xmlXPathFreeObject(obj);


    /* Extract domain memory */
    obj = xmlXPathEval(BAD_CAST "string(/domain/currentMemory[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        def->memory = def->maxmem;
    } else {
        conv = NULL;
        def->memory = strtoll((const char*)obj->stringval, &conv, 10);
        if (def->memory > def->maxmem)
            def->memory = def->maxmem;
        if (conv == (const char*)obj->stringval) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("malformed memory information"));
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    /* Extract domain vcpu info */
    obj = xmlXPathEval(BAD_CAST "string(/domain/vcpu[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        def->vcpus = 1;
    } else {
        conv = NULL;
        def->vcpus = strtoll((const char*)obj->stringval, &conv, 10);
        if (conv == (const char*)obj->stringval) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("malformed vcpu information"));
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    /* Extract domain vcpu info */
    obj = xmlXPathEval(BAD_CAST "string(/domain/vcpu[1]/@cpuset)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        /* Allow use on all CPUS */
        memset(def->cpumask, 1, QEMUD_CPUMASK_LEN);
    } else {
        char *set = (char *)obj->stringval;
        memset(def->cpumask, 0, QEMUD_CPUMASK_LEN);
        if (virParseCpuSet(conn, (const char **)&set,
                           0, def->cpumask,
                           QEMUD_CPUMASK_LEN) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("malformed vcpu mask information"));
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    /* See if ACPI feature is requested */
    obj = xmlXPathEval(BAD_CAST "/domain/features/acpi", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
        def->features |= QEMUD_FEATURE_ACPI;
    }
    xmlXPathFreeObject(obj);


    /* See if we disable reboots */
    obj = xmlXPathEval(BAD_CAST "string(/domain/on_reboot)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        def->noReboot = 0;
    } else {
        if (STREQ((char*)obj->stringval, "destroy"))
            def->noReboot = 1;
        else
            def->noReboot = 0;
    }
    xmlXPathFreeObject(obj);

    /* See if we set clock to localtime */
    obj = xmlXPathEval(BAD_CAST "string(/domain/clock/@offset)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        def->localtime = 0;
    } else {
        if (STREQ((char*)obj->stringval, "localtime"))
            def->localtime = 1;
        else
            def->localtime = 0;
    }
    xmlXPathFreeObject(obj);


    /* Extract bootloader */
    obj = xmlXPathEval(BAD_CAST "string(/domain/bootloader)", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        strncpy(def->os.bootloader, (const char*)obj->stringval, sizeof(def->os.bootloader));
        NUL_TERMINATE(def->os.bootloader);

        /* Set a default OS type, since <type> is optional with bootloader */
        strcpy(def->os.type, "xen");
    }
    xmlXPathFreeObject(obj);

    /* Extract OS type info */
    obj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        if (!def->os.type[0]) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OS_TYPE,
                             "%s", _("no OS type"));
            goto error;
        }
    } else {
        strcpy(def->os.type, (const char *)obj->stringval);
    }
    xmlXPathFreeObject(obj);
    obj = NULL;

    if (!virCapabilitiesSupportsGuestOSType(driver->caps, def->os.type)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OS_TYPE,
                         "%s", def->os.type);
        goto error;
    }

    obj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1]/@arch)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        const char *defaultArch = virCapabilitiesDefaultGuestArch(driver->caps, def->os.type);
        if (defaultArch == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("unsupported architecture"));
            goto error;
        }
        if (strlen(defaultArch) >= (QEMUD_OS_TYPE_MAX_LEN-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("architecture type too long"));
            goto error;
        }
        strcpy(def->os.arch, defaultArch);
    } else {
        if (strlen((const char *)obj->stringval) >= (QEMUD_OS_TYPE_MAX_LEN-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("architecture type too long"));
            goto error;
        }
        strcpy(def->os.arch, (const char *)obj->stringval);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1]/@machine)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        const char *defaultMachine = virCapabilitiesDefaultGuestMachine(driver->caps,
                                                                        def->os.type,
                                                                        def->os.arch);
        if (defaultMachine == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("unsupported architecture"));
            goto error;
        }
        if (strlen(defaultMachine) >= (QEMUD_OS_MACHINE_MAX_LEN-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("machine type too long"));
            goto error;
        }
        strcpy(def->os.machine, defaultMachine);
    } else {
        if (strlen((const char *)obj->stringval) >= (QEMUD_OS_MACHINE_MAX_LEN-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("architecture type too long"));
            goto error;
        }
        strcpy(def->os.machine, (const char *)obj->stringval);
    }
    xmlXPathFreeObject(obj);


    if (!def->os.bootloader[0]) {
        obj = xmlXPathEval(BAD_CAST "string(/domain/os/kernel[1])", ctxt);
        if ((obj != NULL) && (obj->type == XPATH_STRING) &&
            (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
            if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("kernel path too long"));
                goto error;
            }
            strcpy(def->os.kernel, (const char *)obj->stringval);
        }
        xmlXPathFreeObject(obj);


        obj = xmlXPathEval(BAD_CAST "string(/domain/os/initrd[1])", ctxt);
        if ((obj != NULL) && (obj->type == XPATH_STRING) &&
            (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
            if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("initrd path too long"));
                goto error;
            }
            strcpy(def->os.initrd, (const char *)obj->stringval);
        }
        xmlXPathFreeObject(obj);


        obj = xmlXPathEval(BAD_CAST "string(/domain/os/cmdline[1])", ctxt);
        if ((obj != NULL) && (obj->type == XPATH_STRING) &&
            (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
            if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("cmdline arguments too long"));
                goto error;
            }
            strcpy(def->os.cmdline, (const char *)obj->stringval);
        }
        xmlXPathFreeObject(obj);


        /* analysis of the disk devices */
        obj = xmlXPathEval(BAD_CAST "/domain/os/boot", ctxt);
        if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
            (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
            for (i = 0; i < obj->nodesetval->nodeNr && i < QEMUD_MAX_BOOT_DEVS ; i++) {
                if (!(prop = xmlGetProp(obj->nodesetval->nodeTab[i], BAD_CAST "dev")))
                    continue;
                if (STREQ((char *)prop, "hd")) {
                    def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_DISK;
                } else if (STREQ((char *)prop, "fd")) {
                    def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_FLOPPY;
                } else if (STREQ((char *)prop, "cdrom")) {
                    def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_CDROM;
                } else if (STREQ((char *)prop, "network")) {
                    def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_NET;
                } else {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown boot device \'%s\'"), (char*)prop);
                    goto error;
                }
                xmlFree(prop);
                prop = NULL;
            }
        }
        xmlXPathFreeObject(obj);
        if (def->os.nBootDevs == 0) {
            def->os.nBootDevs = 1;
            def->os.bootDevs[0] = QEMUD_BOOT_DISK;
        }
    }

    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/emulator[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        const char *type = qemudVirtTypeToString(def->virtType);
        if (!type) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("unknown virt type"));
            goto error;
        }
        const char *emulator = virCapabilitiesDefaultGuestEmulator(driver->caps,
                                                                   def->os.type,
                                                                   def->os.arch,
                                                                   type);
        if (!emulator) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("unsupported guest type"));
            goto error;
        }
        strcpy(def->os.binary, emulator);
    } else {
        if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("emulator path too long"));
            goto error;
        }
        strcpy(def->os.binary, (const char *)obj->stringval);
    }
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "/domain/devices/graphics", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr == 0)) {
        def->graphicsType = QEMUD_GRAPHICS_NONE;
    } else if ((prop = xmlGetProp(obj->nodesetval->nodeTab[0], BAD_CAST "type"))) {
        if (STREQ((char *)prop, "vnc")) {
            xmlChar *vncport, *vnclisten;
            def->graphicsType = QEMUD_GRAPHICS_VNC;
            vncport = xmlGetProp(obj->nodesetval->nodeTab[0], BAD_CAST "port");
            if (vncport) {
                conv = NULL;
                def->vncPort = strtoll((const char*)vncport, &conv, 10);
            } else {
                def->vncPort = -1;
            }
            vnclisten = xmlGetProp(obj->nodesetval->nodeTab[0], BAD_CAST "listen");
            if (vnclisten && *vnclisten)
                strncpy(def->vncListen, (char *)vnclisten, BR_INET_ADDR_MAXLEN-1);
            else
                strcpy(def->vncListen, driver->vncListen);
            def->vncListen[BR_INET_ADDR_MAXLEN-1] = '\0';
            def->keymap = (char *) xmlGetProp(obj->nodesetval->nodeTab[0], BAD_CAST "keymap");
            xmlFree(vncport);
            xmlFree(vnclisten);
        } else if (STREQ((char *)prop, "sdl")) {
            def->graphicsType = QEMUD_GRAPHICS_SDL;
        } else {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Unsupported graphics type %s"), prop);
            goto error;
        }
        xmlFree(prop);
        prop = NULL;
    }
    xmlXPathFreeObject(obj);

    /* analysis of the disk devices */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/disk", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            struct qemud_vm_disk_def *disk;
            if (VIR_ALLOC(disk) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                           "%s", _("failed to allocate space for disk string"));
                goto error;
            }
            if (qemudParseDiskXML(conn, disk, obj->nodesetval->nodeTab[i]) < 0) {
                VIR_FREE(disk);
                goto error;
            }
            def->ndisks++;
            if (i == 0) {
                disk->next = NULL;
                def->disks = disk;
            } else {
                struct qemud_vm_disk_def *ptr = def->disks;
                while (ptr) {
                    if (!ptr->next || qemudDiskCompare(disk, ptr->next) < 0) {
                        disk->next = ptr->next;
                        ptr->next = disk;
                        break;
                    }
                    ptr = ptr->next;
                }
            }
        }
    }
    xmlXPathFreeObject(obj);
    obj = NULL;

    /* analysis of the character devices */
    if (qemudParseCharXMLDevices(conn, ctxt,
                                 "/domain/devices/parallel",
                                 &def->nparallels,
                                 &def->parallels) < 0)
        goto error;
    if (qemudParseCharXMLDevices(conn, ctxt,
                                 "/domain/devices/serial",
                                 &def->nserials,
                                 &def->serials) < 0)
        goto error;

    /*
     * If no serial devices were listed, then look for console
     * devices which is the legacy syntax for the same thing
     */
    if (def->nserials == 0) {
        obj = xmlXPathEval(BAD_CAST "/domain/devices/console", ctxt);
        if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
            (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
            struct qemud_vm_chr_def *chr;
            if (VIR_ALLOC(chr) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                                 "%s",
                                 _("failed to allocate space for char device"));
                goto error;
            }

            if (qemudParseCharXML(conn, chr, 0, obj->nodesetval->nodeTab[0]) < 0) {
                VIR_FREE(chr);
                goto error;
            }
            def->nserials = 1;
            def->serials = chr;
        }
        xmlXPathFreeObject(obj);
    }


    /* analysis of the network devices */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        struct qemud_vm_net_def *prev = NULL;
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            struct qemud_vm_net_def *net;
            if (VIR_ALLOC(net) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                           "%s", _("failed to allocate space for net string"));
                goto error;
            }
            if (qemudParseInterfaceXML(conn, net, obj->nodesetval->nodeTab[i]) < 0) {
                VIR_FREE(net);
                goto error;
            }
            def->nnets++;
            net->next = NULL;
            if (i == 0) {
                def->nets = net;
            } else {
                prev->next = net;
            }
            prev = net;
        }
    }
    xmlXPathFreeObject(obj);

    /* analysis of the input devices */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/input", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        struct qemud_vm_input_def *prev = NULL;
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            struct qemud_vm_input_def *input;
            if (VIR_ALLOC(input) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for input string"));
                goto error;
            }
            if (qemudParseInputXML(conn, def, input, obj->nodesetval->nodeTab[i]) < 0) {
                VIR_FREE(input);
                goto error;
            }
            /* Mouse + PS/2 is implicit with graphics, so don't store it */
            if (input->bus == QEMU_INPUT_BUS_PS2 &&
                input->type == QEMU_INPUT_TYPE_MOUSE) {
                VIR_FREE(input);
                continue;
            }
            def->ninputs++;
            input->next = NULL;
            if (def->inputs == NULL) {
                def->inputs = input;
            } else {
                prev->next = input;
            }
            prev = input;
        }
    }
    xmlXPathFreeObject(obj);

    /* Parse sound driver xml */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/sound", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        struct qemud_vm_sound_def *prev = NULL;
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {

            struct qemud_vm_sound_def *sound;
            struct qemud_vm_sound_def *check = def->sounds;
            int collision = 0;
            if (VIR_ALLOC(sound) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for sound dev"));
                goto error;
            }
            if (qemudParseSoundXML(conn, sound,
                                   obj->nodesetval->nodeTab[i]) < 0) {
                VIR_FREE(sound);
                goto error;
            }

            // Check that model type isn't already present in sound dev list
            while(check) {
                if (check->model == sound->model) {
                    collision = 1;
                    break;
                }
                check = check->next;
            }
            if (collision) {
                VIR_FREE(sound);
                continue;
            }

            def->nsounds++;
            sound->next = NULL;
            if (def->sounds == NULL) {
                def->sounds = sound;
            } else {
                prev->next = sound;
            }
            prev = sound;
        }
    }
    xmlXPathFreeObject(obj);
    obj = NULL;

    /* If graphics are enabled, there's an implicit PS2 mouse */
    if (def->graphicsType != QEMUD_GRAPHICS_NONE) {
        int hasPS2mouse = 0;
        struct qemud_vm_input_def *input = def->inputs;
        while (input) {
            if (input->type == QEMU_INPUT_TYPE_MOUSE &&
                input->bus == QEMU_INPUT_BUS_PS2)
                hasPS2mouse = 1;
            input = input->next;
        }

        if (!hasPS2mouse) {
            if (VIR_ALLOC(input) < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for input string"));
                goto error;
            }
            input->type = QEMU_INPUT_TYPE_MOUSE;
            input->bus = QEMU_INPUT_BUS_PS2;
            input->next = def->inputs;
            def->inputs = input;
            def->ninputs++;
        }
    }

    xmlXPathFreeContext(ctxt);

    return def;

 error:
    VIR_FREE(prop);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    qemudFreeVMDef(def);
    return NULL;
}


static char *
qemudNetworkIfaceConnect(virConnectPtr conn,
                         struct qemud_driver *driver,
                         struct qemud_vm *vm,
                         struct qemud_vm_net_def *net,
                         int vlan)
{
    struct qemud_network *network = NULL;
    char *brname;
    char *ifname;
    char tapfdstr[4+3+32+7];
    char *retval = NULL;
    int err;
    int tapfd = -1;

    if (net->type == QEMUD_NET_NETWORK) {
        if (!(network = qemudFindNetworkByName(driver, net->dst.network.name))) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Network '%s' not found"),
                             net->dst.network.name);
            goto error;
        } else if (network->bridge[0] == '\0') {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Network '%s' not active"),
                             net->dst.network.name);
            goto error;
        }
        brname = network->bridge;
        if (net->dst.network.ifname[0] == '\0' ||
            STRPREFIX(net->dst.network.ifname, "vnet") ||
            strchr(net->dst.network.ifname, '%')) {
            strcpy(net->dst.network.ifname, "vnet%d");
        }
        ifname = net->dst.network.ifname;
    } else if (net->type == QEMUD_NET_BRIDGE) {
        brname = net->dst.bridge.brname;
        if (net->dst.bridge.ifname[0] == '\0' ||
            STRPREFIX(net->dst.bridge.ifname, "vnet") ||
            strchr(net->dst.bridge.ifname, '%')) {
            strcpy(net->dst.bridge.ifname, "vnet%d");
        }
        ifname = net->dst.bridge.ifname;
    } else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Network type %d is not supported"), net->type);
        goto error;
    }

    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot initialize bridge support: %s"),
                         strerror(err));
        goto error;
    }

    if ((err = brAddTap(driver->brctl, brname,
                        ifname, BR_IFNAME_MAXLEN, &tapfd))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("Failed to add tap interface '%s' to bridge '%s' : %s"),
                         ifname, brname, strerror(err));
        goto error;
    }

    snprintf(tapfdstr, sizeof(tapfdstr),
             "tap,fd=%d,script=,vlan=%d,ifname=%s",
             tapfd, vlan, ifname);

    if (!(retval = strdup(tapfdstr)))
        goto no_memory;

    if (VIR_REALLOC_N(vm->tapfds, vm->ntapfds+2) < 0)
        goto no_memory;

    vm->tapfds[vm->ntapfds++] = tapfd;
    vm->tapfds[vm->ntapfds]   = -1;

    return retval;

 no_memory:
    qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for tapfds string"));
 error:
    VIR_FREE(retval);
    if (tapfd != -1)
        close(tapfd);
    return NULL;
}

static int qemudBuildCommandLineChrDevStr(struct qemud_vm_chr_def *dev,
                                          char *buf,
                                          int buflen)
{
    switch (dev->srcType) {
    case QEMUD_CHR_SRC_TYPE_NULL:
        strncpy(buf, "null", buflen);
        buf[buflen-1] = '\0';
        break;

    case QEMUD_CHR_SRC_TYPE_VC:
        strncpy(buf, "vc", buflen);
        buf[buflen-1] = '\0';
        break;

    case QEMUD_CHR_SRC_TYPE_PTY:
        strncpy(buf, "pty", buflen);
        buf[buflen-1] = '\0';
        break;

    case QEMUD_CHR_SRC_TYPE_DEV:
        if (snprintf(buf, buflen, "%s",
                     dev->srcData.file.path) >= buflen)
            return -1;
        break;

    case QEMUD_CHR_SRC_TYPE_FILE:
        if (snprintf(buf, buflen, "file:%s",
                     dev->srcData.file.path) >= buflen)
            return -1;
        break;

    case QEMUD_CHR_SRC_TYPE_PIPE:
        if (snprintf(buf, buflen, "pipe:%s",
                     dev->srcData.file.path) >= buflen)
            return -1;
        break;

    case QEMUD_CHR_SRC_TYPE_STDIO:
        strncpy(buf, "stdio", buflen);
        buf[buflen-1] = '\0';
        break;

    case QEMUD_CHR_SRC_TYPE_UDP:
        if (snprintf(buf, buflen, "udp:%s:%s@%s:%s",
                     dev->srcData.udp.connectHost,
                     dev->srcData.udp.connectService,
                     dev->srcData.udp.bindHost,
                     dev->srcData.udp.bindService) >= buflen)
            return -1;
        break;

    case QEMUD_CHR_SRC_TYPE_TCP:
        if (snprintf(buf, buflen, "%s:%s:%s%s",
                     dev->srcData.tcp.protocol == QEMUD_CHR_SRC_TCP_PROTOCOL_TELNET ? "telnet" : "tcp",
                     dev->srcData.tcp.host,
                     dev->srcData.tcp.service,
                     dev->srcData.tcp.listen ? ",listen" : "") >= buflen)
            return -1;
        break;

    case QEMUD_CHR_SRC_TYPE_UNIX:
        if (snprintf(buf, buflen, "unix:%s%s",
                     dev->srcData.nix.path,
                     dev->srcData.nix.listen ? ",listen" : "") >= buflen)
            return -1;
        break;
    }

    return 0;
}

/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 */
int qemudBuildCommandLine(virConnectPtr conn,
                          struct qemud_driver *driver,
                          struct qemud_vm *vm,
                          char ***retargv) {
    int i;
    char memory[50];
    char vcpus[50];
    char boot[QEMUD_MAX_BOOT_DEVS+1];
    struct qemud_vm_disk_def *disk = vm->def->disks;
    struct qemud_vm_net_def *net = vm->def->nets;
    struct qemud_vm_input_def *input = vm->def->inputs;
    struct qemud_vm_sound_def *sound = vm->def->sounds;
    struct qemud_vm_chr_def *serial = vm->def->serials;
    struct qemud_vm_chr_def *parallel = vm->def->parallels;
    struct utsname ut;
    int disableKQEMU = 0;
    int qargc = 0, qarga = 0;
    char **qargv = NULL;

    if (vm->qemuVersion == 0) {
        if (qemudExtractVersionInfo(vm->def->os.binary,
                                    &(vm->qemuVersion),
                                    &(vm->qemuCmdFlags)) < 0)
            return -1;
    }

    uname(&ut);

    /* Nasty hack make i?86 look like i686 to simplify next comparison */
    if (ut.machine[0] == 'i' &&
        ut.machine[2] == '8' &&
        ut.machine[3] == '6' &&
        !ut.machine[4])
        ut.machine[1] = '6';

    /* Need to explicitly disable KQEMU if
     * 1. Arch matches host arch
     * 2. Guest is 'qemu'
     * 3. The qemu binary has the -no-kqemu flag
     */
    if ((vm->qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU) &&
        STREQ(ut.machine, vm->def->os.arch) &&
        vm->def->virtType == QEMUD_VIRT_QEMU)
        disableKQEMU = 1;

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

    snprintf(memory, sizeof(memory), "%lu", vm->def->memory/1024);
    snprintf(vcpus, sizeof(vcpus), "%d", vm->def->vcpus);


    ADD_ARG_LIT(vm->def->os.binary);
    ADD_ARG_LIT("-S");
    ADD_ARG_LIT("-M");
    ADD_ARG_LIT(vm->def->os.machine);
    if (disableKQEMU)
        ADD_ARG_LIT("-no-kqemu");
    ADD_ARG_LIT("-m");
    ADD_ARG_LIT(memory);
    ADD_ARG_LIT("-smp");
    ADD_ARG_LIT(vcpus);

    if (vm->qemuCmdFlags & QEMUD_CMD_FLAG_NAME) {
        ADD_ARG_LIT("-name");
        ADD_ARG_LIT(vm->def->name);
    }
    /*
     * NB, -nographic *MUST* come before any serial, or monitor
     * or parallel port flags due to QEMU craziness, where it
     * decides to change the serial port & monitor to be on stdout
     * if you ask for nographic. So we have to make sure we override
     * these defaults ourselves...
     */
    if (vm->def->graphicsType == QEMUD_GRAPHICS_NONE)
        ADD_ARG_LIT("-nographic");

    ADD_ARG_LIT("-monitor");
    ADD_ARG_LIT("pty");

    if (vm->def->localtime)
        ADD_ARG_LIT("-localtime");

    if ((vm->qemuCmdFlags & QEMUD_CMD_FLAG_NO_REBOOT) &&
        vm->def->noReboot)
        ADD_ARG_LIT("-no-reboot");

    if (!(vm->def->features & QEMUD_FEATURE_ACPI))
        ADD_ARG_LIT("-no-acpi");

    if (!vm->def->os.bootloader[0]) {
        for (i = 0 ; i < vm->def->os.nBootDevs ; i++) {
            switch (vm->def->os.bootDevs[i]) {
            case QEMUD_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case QEMUD_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case QEMUD_BOOT_DISK:
                boot[i] = 'c';
                break;
            case QEMUD_BOOT_NET:
                boot[i] = 'n';
                break;
            default:
                boot[i] = 'c';
                break;
            }
        }
        boot[vm->def->os.nBootDevs] = '\0';
        ADD_ARG_LIT("-boot");
        ADD_ARG_LIT(boot);

        if (vm->def->os.kernel[0]) {
            ADD_ARG_LIT("-kernel");
            ADD_ARG_LIT(vm->def->os.kernel);
        }
        if (vm->def->os.initrd[0]) {
            ADD_ARG_LIT("-initrd");
            ADD_ARG_LIT(vm->def->os.initrd);
        }
        if (vm->def->os.cmdline[0]) {
            ADD_ARG_LIT("-append");
            ADD_ARG_LIT(vm->def->os.cmdline);
        }
    } else {
        ADD_ARG_LIT("-bootloader");
        ADD_ARG_LIT(vm->def->os.bootloader);
    }

    /* If QEMU supports -drive param instead of old -hda, -hdb, -cdrom .. */
    if (vm->qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE) {
        int bootCD = 0, bootFloppy = 0, bootDisk = 0;

        /* If QEMU supports boot=on for -drive param... */
        if (vm->qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_BOOT) {
            for (i = 0 ; i < vm->def->os.nBootDevs ; i++) {
                switch (vm->def->os.bootDevs[i]) {
                case QEMUD_BOOT_CDROM:
                    bootCD = 1;
                    break;
                case QEMUD_BOOT_FLOPPY:
                    bootFloppy = 1;
                    break;
                case QEMUD_BOOT_DISK:
                    bootDisk = 1;
                    break;
                }
            }
        }

        while (disk) {
            char opt[PATH_MAX];
            const char *media = NULL;
            int bootable = 0;
            int idx = virDiskNameToIndex(disk->dst);

            if (idx < 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("unsupported disk type '%s'"), disk->dst);
                goto error;
            }

            if (disk->device == QEMUD_DISK_CDROM)
                media = "media=cdrom,";

            switch (disk->device) {
            case QEMUD_DISK_CDROM:
                bootable = bootCD;
                bootCD = 0;
                break;
            case QEMUD_DISK_FLOPPY:
                bootable = bootFloppy;
                bootFloppy = 0;
                break;
            case QEMUD_DISK_DISK:
                bootable = bootDisk;
                bootDisk = 0;
                break;
            }

            snprintf(opt, PATH_MAX, "file=%s,if=%s,%sindex=%d%s",
                     disk->src, qemudBusIdToName(disk->bus, 1),
                     media ? media : "",
                     idx,
                     bootable ? ",boot=on" : "");

            ADD_ARG_LIT("-drive");
            ADD_ARG_LIT(opt);
            disk = disk->next;
        }
    } else {
        while (disk) {
            char dev[NAME_MAX];
            char file[PATH_MAX];

            if (STREQ(disk->dst, "hdc") &&
                disk->device == QEMUD_DISK_CDROM) {
                if (disk->src[0]) {
                    snprintf(dev, NAME_MAX, "-%s", "cdrom");
                } else {
                    disk = disk->next;
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

            disk = disk->next;
        }
    }

    if (!net) {
        ADD_ARG_LIT("-net");
        ADD_ARG_LIT("none");
    } else {
        int vlan = 0;
        while (net) {
            char nic[100];

            if (snprintf(nic, sizeof(nic),
                         "nic,macaddr=%02x:%02x:%02x:%02x:%02x:%02x,vlan=%d%s%s",
                         net->mac[0], net->mac[1],
                         net->mac[2], net->mac[3],
                         net->mac[4], net->mac[5],
                         vlan,
                         (net->model[0] ? ",model=" : ""), net->model) >= sizeof(nic))
                goto error;

            ADD_ARG_LIT("-net");
            ADD_ARG_LIT(nic);
            ADD_ARG_LIT("-net");

            switch (net->type) {
            case QEMUD_NET_NETWORK:
            case QEMUD_NET_BRIDGE:
                {
                    char *tap = qemudNetworkIfaceConnect(conn, driver, vm, net, vlan);
                    if (tap == NULL)
                        goto error;
                    ADD_ARG(tap);
                    break;
                }

            case QEMUD_NET_ETHERNET:
                {
                    char arg[PATH_MAX];
                    if (snprintf(arg, PATH_MAX-1, "tap,ifname=%s,script=%s,vlan=%d",
                                 net->dst.ethernet.ifname,
                                 net->dst.ethernet.script,
                                 vlan) >= (PATH_MAX-1))
                        goto error;

                    ADD_ARG_LIT(arg);
                }
                break;

            case QEMUD_NET_CLIENT:
            case QEMUD_NET_SERVER:
            case QEMUD_NET_MCAST:
                {
                    char arg[PATH_MAX];
                    const char *mode = NULL;
                    switch (net->type) {
                    case QEMUD_NET_CLIENT:
                        mode = "connect";
                        break;
                    case QEMUD_NET_SERVER:
                        mode = "listen";
                        break;
                    case QEMUD_NET_MCAST:
                        mode = "mcast";
                        break;
                    }
                    if (snprintf(arg, PATH_MAX-1, "socket,%s=%s:%d,vlan=%d",
                                 mode,
                                 net->dst.socket.address,
                                 net->dst.socket.port,
                                 vlan) >= (PATH_MAX-1))
                        goto error;

                    ADD_ARG_LIT(arg);
                }
                break;

            case QEMUD_NET_USER:
            default:
                {
                    char arg[PATH_MAX];
                    if (snprintf(arg, PATH_MAX-1, "user,vlan=%d", vlan) >= (PATH_MAX-1))
                        goto error;

                    ADD_ARG_LIT(arg);
                }
            }

            net = net->next;
            vlan++;
        }
    }

    if (!serial) {
        ADD_ARG_LIT("-serial");
        ADD_ARG_LIT("none");
    } else {
        while (serial) {
            char buf[4096];

            if (qemudBuildCommandLineChrDevStr(serial, buf, sizeof(buf)) < 0)
                goto error;

            ADD_ARG_LIT("-serial");
            ADD_ARG_LIT(buf);

            serial = serial->next;
        }
    }

    if (!parallel) {
        ADD_ARG_LIT("-parallel");
        ADD_ARG_LIT("none");
    } else {
        while (parallel) {
            char buf[4096];

            if (qemudBuildCommandLineChrDevStr(parallel, buf, sizeof(buf)) < 0)
                goto error;

            ADD_ARG_LIT("-parallel");
            ADD_ARG_LIT(buf);

            parallel = parallel->next;
        }
    }

    ADD_ARG_LIT("-usb");
    while (input) {
        if (input->bus == QEMU_INPUT_BUS_USB) {
            ADD_ARG_LIT("-usbdevice");
            ADD_ARG_LIT(input->type == QEMU_INPUT_TYPE_MOUSE ? "mouse" : "tablet");
        }

        input = input->next;
    }

    if (vm->def->graphicsType == QEMUD_GRAPHICS_VNC) {
        char vncdisplay[PATH_MAX];
        int ret;

        if (vm->qemuCmdFlags & QEMUD_CMD_FLAG_VNC_COLON) {
            char options[PATH_MAX] = "";
            if (driver->vncTLS) {
                strcat(options, ",tls");
                if (driver->vncTLSx509verify) {
                    strcat(options, ",x509verify=");
                } else {
                    strcat(options, ",x509=");
                }
                strncat(options, driver->vncTLSx509certdir,
                        sizeof(options) - (strlen(driver->vncTLSx509certdir)-1));
                options[sizeof(options)-1] = '\0';
            }
            ret = snprintf(vncdisplay, sizeof(vncdisplay), "%s:%d%s",
                           vm->def->vncListen,
                           vm->def->vncActivePort - 5900,
                           options);
        } else {
            ret = snprintf(vncdisplay, sizeof(vncdisplay), "%d",
                           vm->def->vncActivePort - 5900);
        }
        if (ret < 0 || ret >= (int)sizeof(vncdisplay))
            goto error;

        ADD_ARG_LIT("-vnc");
        ADD_ARG_LIT(vncdisplay);
        if (vm->def->keymap) {
            ADD_ARG_LIT("-k");
            ADD_ARG_LIT(vm->def->keymap);
        }
    } else if (vm->def->graphicsType == QEMUD_GRAPHICS_NONE) {
        /* Nada - we added -nographic earlier in this function */
    } else {
        /* SDL is the default. no args needed */
    }

    /* Add sound hardware */
    if (sound) {
        int size = 100;
        char *modstr;
        if (VIR_ALLOC_N(modstr, size+1) < 0)
            goto no_memory;

        while(sound && size > 0) {
            const char *model = qemudSoundModelToString(sound->model);
            if (!model) {
                VIR_FREE(modstr);
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("invalid sound model"));
                goto error;
            }
            strncat(modstr, model, size);
            size -= strlen(model);
            sound = sound->next;
            if (sound)
               strncat(modstr, ",", size--);
        }
        ADD_ARG_LIT("-soundhw");
        ADD_ARG(modstr);
    }

    if (vm->migrateFrom[0]) {
        ADD_ARG_LIT("-incoming");
        ADD_ARG_LIT(vm->migrateFrom);
    }

    ADD_ARG(NULL);

    *retargv = qargv;
    return 0;

 no_memory:
    qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for argv string"));
 error:
    if (vm->tapfds) {
        for (i = 0; vm->tapfds[i] != -1; i++)
            close(vm->tapfds[i]);
        VIR_FREE(vm->tapfds);
        vm->tapfds = NULL;
        vm->ntapfds = 0;
    }
    if (qargv) {
        for (i = 0 ; i < qargc ; i++)
            VIR_FREE((qargv)[i]);
        VIR_FREE(qargv);
    }
    return -1;

#undef ADD_ARG
#undef ADD_ARG_LIT
#undef ADD_ARG_SPACE
}


/* Save a guest's config data into a persistent file */
static int qemudSaveConfig(virConnectPtr conn,
                           struct qemud_driver *driver,
                           struct qemud_vm *vm,
                           struct qemud_vm_def *def) {
    char *xml;
    int fd = -1, ret = -1;
    int towrite;

    if (!(xml = qemudGenerateXML(conn, driver, vm, def, 0)))
        return -1;

    if ((fd = open(vm->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot create config file %s: %s"),
                         vm->configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot write config file %s: %s"),
                         vm->configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot save config file %s: %s"),
                         vm->configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (fd != -1)
        close(fd);

    VIR_FREE(xml);

    return ret;
}

struct qemud_vm_device_def *
qemudParseVMDeviceDef(virConnectPtr conn,
                      const struct qemud_vm_def *def,
                      const char *xmlStr)
{
    xmlDocPtr xml;
    xmlNodePtr node;
    struct qemud_vm_device_def *dev;

    if (VIR_ALLOC(dev) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, "device.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_XML_ERROR, NULL);
        goto error;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_XML_ERROR,
                         "%s", _("missing root element"));
        goto error;
    }
    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        dev->type = QEMUD_DEVICE_DISK;
        qemudParseDiskXML(conn, &(dev->data.disk), node);
    } else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        dev->type = QEMUD_DEVICE_NET;
        qemudParseInterfaceXML(conn, &(dev->data.net), node);
    } else if (xmlStrEqual(node->name, BAD_CAST "input")) {
        dev->type = QEMUD_DEVICE_DISK;
        qemudParseInputXML(conn, def, &(dev->data.input), node);
    } else if (xmlStrEqual(node->name, BAD_CAST "sound")) {
        dev->type = QEMUD_DEVICE_SOUND;
        qemudParseSoundXML(conn, &(dev->data.sound), node);
    } else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_XML_ERROR,
                         "%s", _("unknown device type"));
        goto error;
    }

    xmlFreeDoc(xml);

    return dev;

  error:
    if (xml) xmlFreeDoc(xml);
    VIR_FREE(dev);
    return NULL;
}

struct qemud_vm_def *
qemudParseVMDef(virConnectPtr conn,
                struct qemud_driver *driver,
                const char *xmlStr,
                const char *displayName) {
    xmlDocPtr xml;
    struct qemud_vm_def *def = NULL;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, displayName ? displayName : "domain.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    def = qemudParseXML(conn, driver, xml);

    xmlFreeDoc(xml);

    return def;
}

struct qemud_vm *
qemudAssignVMDef(virConnectPtr conn,
                 struct qemud_driver *driver,
                 struct qemud_vm_def *def)
{
    struct qemud_vm *vm = NULL;

    if ((vm = qemudFindVMByName(driver, def->name))) {
        if (!qemudIsActiveVM(vm)) {
            qemudFreeVMDef(vm->def);
            vm->def = def;
        } else {
            if (vm->newDef)
                qemudFreeVMDef(vm->newDef);
            vm->newDef = def;
        }
        /* Reset version, because the emulator path might have changed */
        vm->qemuVersion = 0;
        vm->qemuCmdFlags = 0;
        return vm;
    }

    if (VIR_ALLOC(vm) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for vm string"));
        return NULL;
    }

    vm->stdin = -1;
    vm->stdout = -1;
    vm->stderr = -1;
    vm->monitor = -1;
    vm->pid = -1;
    vm->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
    vm->def = def;
    vm->next = driver->vms;

    driver->vms = vm;
    driver->ninactivevms++;

    return vm;
}

void
qemudRemoveInactiveVM(struct qemud_driver *driver,
                      struct qemud_vm *vm)
{
    struct qemud_vm *prev = NULL, *curr;

    curr = driver->vms;
    while (curr != vm) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            driver->vms = curr->next;

        driver->ninactivevms--;
    }

    qemudFreeVM(vm);
}

int
qemudSaveVMDef(virConnectPtr conn,
               struct qemud_driver *driver,
               struct qemud_vm *vm,
               struct qemud_vm_def *def) {
    if (vm->configFile[0] == '\0') {
        int err;

        if ((err = virFileMakePath(driver->configDir))) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create config directory %s: %s"),
                             driver->configDir, strerror(err));
            return -1;
        }

        if (virFileBuildPath(driver->configDir, def->name, ".xml",
                             vm->configFile, PATH_MAX) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot construct config file path"));
            return -1;
        }

        if (virFileBuildPath(driver->autostartDir, def->name, ".xml",
                             vm->autostartLink, PATH_MAX) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot construct autostart link path"));
            vm->configFile[0] = '\0';
            return -1;
        }
    }

    return qemudSaveConfig(conn, driver, vm, def);
}

static int qemudSaveNetworkConfig(virConnectPtr conn,
                                  struct qemud_driver *driver,
                                  struct qemud_network *network,
                                  struct qemud_network_def *def) {
    char *xml;
    int fd, ret = -1;
    int towrite;
    int err;

    if (!(xml = qemudGenerateNetworkXML(conn, driver, network, def))) {
        return -1;
    }

    if ((err = virFileMakePath(driver->networkConfigDir))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot create config directory %s: %s"),
                         driver->networkConfigDir, strerror(err));
        goto cleanup;
    }

    if ((fd = open(network->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot create config file %s: %s"),
                         network->configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot write config file %s: %s"),
                         network->configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot save config file %s: %s"),
                         network->configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:

    VIR_FREE(xml);

    return ret;
}

void qemudFreeNetworkDef(struct qemud_network_def *def) {
    struct qemud_dhcp_range_def *range = def->ranges;
    while (range) {
        struct qemud_dhcp_range_def *next = range->next;
        VIR_FREE(range);
        range = next;
    }
    VIR_FREE(def);
}

void qemudFreeNetwork(struct qemud_network *network) {
    qemudFreeNetworkDef(network->def);
    if (network->newDef)
        qemudFreeNetworkDef(network->newDef);
    VIR_FREE(network);
}

static int qemudParseBridgeXML(struct qemud_driver *driver ATTRIBUTE_UNUSED,
                               struct qemud_network_def *def,
                               xmlNodePtr node) {
    xmlChar *name, *stp, *delay;

    name = xmlGetProp(node, BAD_CAST "name");
    if (name != NULL) {
        strncpy(def->bridge, (const char *)name, IF_NAMESIZE-1);
        def->bridge[IF_NAMESIZE-1] = '\0';
        xmlFree(name);
        name = NULL;
    }

    stp = xmlGetProp(node, BAD_CAST "stp");
    if (stp != NULL) {
        if (xmlStrEqual(stp, BAD_CAST "off")) {
            def->disableSTP = 1;
        }
        xmlFree(stp);
        stp = NULL;
    }

    delay = xmlGetProp(node, BAD_CAST "delay");
    if (delay != NULL) {
        def->forwardDelay = strtol((const char *)delay, NULL, 10);
        xmlFree(delay);
        delay = NULL;
    }

    return 1;
}

static int qemudParseDhcpRangesXML(virConnectPtr conn,
                                   struct qemud_driver *driver ATTRIBUTE_UNUSED,
                                   struct qemud_network_def *def,
                                   xmlNodePtr node) {

    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        struct qemud_dhcp_range_def *range;
        xmlChar *start, *end;

        if (cur->type != XML_ELEMENT_NODE ||
            !xmlStrEqual(cur->name, BAD_CAST "range")) {
            cur = cur->next;
            continue;
        }

        if (VIR_ALLOC(range) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for range string"));
            return 0;
        }

        start = xmlGetProp(cur, BAD_CAST "start");
        end = xmlGetProp(cur, BAD_CAST "end");

        if (start && start[0] && end && end[0]) {
            strncpy(range->start, (const char *)start, BR_INET_ADDR_MAXLEN-1);
            range->start[BR_INET_ADDR_MAXLEN-1] = '\0';

            strncpy(range->end, (const char *)end, BR_INET_ADDR_MAXLEN-1);
            range->end[BR_INET_ADDR_MAXLEN-1] = '\0';

            range->next = def->ranges;
            def->ranges = range;
            def->nranges++;
        } else {
            VIR_FREE(range);
        }

        xmlFree(start);
        xmlFree(end);

        cur = cur->next;
    }

    return 1;
}

static int qemudParseInetXML(virConnectPtr conn,
                             struct qemud_driver *driver ATTRIBUTE_UNUSED,
                             struct qemud_network_def *def,
                             xmlNodePtr node) {
    xmlChar *address, *netmask;
    xmlNodePtr cur;

    address = xmlGetProp(node, BAD_CAST "address");
    if (address != NULL) {
        strncpy(def->ipAddress, (const char *)address, BR_INET_ADDR_MAXLEN-1);
        def->ipAddress[BR_INET_ADDR_MAXLEN-1] = '\0';
        xmlFree(address);
        address = NULL;
    }

    netmask = xmlGetProp(node, BAD_CAST "netmask");
    if (netmask != NULL) {
        strncpy(def->netmask, (const char *)netmask, BR_INET_ADDR_MAXLEN-1);
        def->netmask[BR_INET_ADDR_MAXLEN-1] = '\0';
        xmlFree(netmask);
        netmask = NULL;
    }

    if (def->ipAddress[0] && def->netmask[0]) {
        struct in_addr inaddress, innetmask;
        char *netaddr;

        inet_aton((const char*)def->ipAddress, &inaddress);
        inet_aton((const char*)def->netmask, &innetmask);

        inaddress.s_addr &= innetmask.s_addr;

        netaddr = inet_ntoa(inaddress);

        snprintf(def->network,sizeof(def->network)-1,
                 "%s/%s", netaddr, (const char *)def->netmask);
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "dhcp") &&
            !qemudParseDhcpRangesXML(conn, driver, def, cur))
            return 0;
        cur = cur->next;
    }

    return 1;
}


static struct qemud_network_def *qemudParseNetworkXML(virConnectPtr conn,
                                                      struct qemud_driver *driver,
                                                      xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL, tmp = NULL;
    struct qemud_network_def *def;

    if (VIR_ALLOC(def) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                   "%s", _("failed to allocate space for network_def string"));
        return NULL;
    }

    /* Prepare parser / xpath context */
    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "network"))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("incorrect root element"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
               "%s", _("failed to allocate space for xmlXPathContext string"));
        goto error;
    }


    /* Extract network name */
    obj = xmlXPathEval(BAD_CAST "string(/network/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_NAME, NULL);
        goto error;
    }
    if (strlen((const char *)obj->stringval) >= (QEMUD_MAX_NAME_LEN-1)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("network name length too long"));
        goto error;
    }
    strcpy(def->name, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);


    /* Extract network uuid */
    obj = xmlXPathEval(BAD_CAST "string(/network/uuid[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        int err;
        if ((err = virUUIDGenerate(def->uuid))) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to generate UUID: %s"), strerror(err));
            goto error;
        }
    } else if (virUUIDParse((const char *)obj->stringval, def->uuid) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("malformed uuid element"));
        goto error;
    }
    xmlXPathFreeObject(obj);

    /* Parse bridge information */
    obj = xmlXPathEval(BAD_CAST "/network/bridge[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
        if (!qemudParseBridgeXML(driver, def, obj->nodesetval->nodeTab[0])) {
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    /* Parse IP information */
    obj = xmlXPathEval(BAD_CAST "/network/ip[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
        if (!qemudParseInetXML(conn, driver, def, obj->nodesetval->nodeTab[0])) {
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    /* IPv4 forwarding setup */
    obj = xmlXPathEval(BAD_CAST "count(/network/forward) > 0", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_BOOLEAN) &&
        obj->boolval) {
        if (!def->ipAddress[0] ||
            !def->netmask[0]) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Forwarding requested, but no IPv4 address/netmask provided"));
            goto error;
        }

        def->forward = 1;

        tmp = xmlXPathEval(BAD_CAST "string(/network/forward[1]/@mode)", ctxt);
        if ((tmp != NULL) && (tmp->type == XPATH_STRING) &&
            (tmp->stringval != NULL) && (xmlStrEqual(tmp->stringval, BAD_CAST "route"))) {
            def->forwardMode = QEMUD_NET_FORWARD_ROUTE;
        } else {
            def->forwardMode = QEMUD_NET_FORWARD_NAT;
        }
        xmlXPathFreeObject(tmp);
        tmp = NULL;

        tmp = xmlXPathEval(BAD_CAST "string(/network/forward[1]/@dev)", ctxt);
        if ((tmp != NULL) && (tmp->type == XPATH_STRING) &&
            (tmp->stringval != NULL) && (tmp->stringval[0] != 0)) {
            int len;
            if ((len = xmlStrlen(tmp->stringval)) >= (BR_IFNAME_MAXLEN-1)) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("forward device name '%s' is too long"),
                                 (char*)tmp->stringval);
                goto error;
            }
            strcpy(def->forwardDev, (char*)tmp->stringval);
        } else {
            def->forwardDev[0] = '\0';
        }
        xmlXPathFreeObject(tmp);
        tmp = NULL;
    } else {
        def->forward = 0;
    }
    xmlXPathFreeObject(obj);

    xmlXPathFreeContext(ctxt);

    return def;

 error:
    /* XXX free all the stuff in the qemud_network struct, or leave it upto
       the caller ? */
    xmlXPathFreeObject(obj);
    xmlXPathFreeObject(tmp);
    xmlXPathFreeContext(ctxt);
    qemudFreeNetworkDef(def);
    return NULL;
}

struct qemud_network_def *
qemudParseNetworkDef(virConnectPtr conn,
                     struct qemud_driver *driver,
                     const char *xmlStr,
                     const char *displayName) {
    xmlDocPtr xml;
    struct qemud_network_def *def;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, displayName ? displayName : "network.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    def = qemudParseNetworkXML(conn, driver, xml);

    xmlFreeDoc(xml);

    return def;
}

struct qemud_network *
qemudAssignNetworkDef(virConnectPtr conn,
                      struct qemud_driver *driver,
                      struct qemud_network_def *def) {
    struct qemud_network *network;

    if ((network = qemudFindNetworkByName(driver, def->name))) {
        if (!qemudIsActiveNetwork(network)) {
            qemudFreeNetworkDef(network->def);
            network->def = def;
        } else {
            if (network->newDef)
                qemudFreeNetworkDef(network->newDef);
            network->newDef = def;
        }

        return network;
    }

    if (VIR_ALLOC(network) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for network string"));
        return NULL;
    }

    network->def = def;
    network->next = driver->networks;

    driver->networks = network;
    driver->ninactivenetworks++;

    return network;
}

void
qemudRemoveInactiveNetwork(struct qemud_driver *driver,
                           struct qemud_network *network)
{
    struct qemud_network *prev = NULL, *curr;

    curr = driver->networks;
    while (curr != network) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            driver->networks = curr->next;

        driver->ninactivenetworks--;
    }

    qemudFreeNetwork(network);
}

int
qemudSaveNetworkDef(virConnectPtr conn,
                    struct qemud_driver *driver,
                    struct qemud_network *network,
                    struct qemud_network_def *def) {

    if (network->configFile[0] == '\0') {
        int err;

        if ((err = virFileMakePath(driver->networkConfigDir))) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create config directory %s: %s"),
                             driver->networkConfigDir, strerror(err));
            return -1;
        }

        if (virFileBuildPath(driver->networkConfigDir, def->name, ".xml",
                             network->configFile, PATH_MAX) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot construct config file path"));
            return -1;
        }

        if (virFileBuildPath(driver->networkAutostartDir, def->name, ".xml",
                             network->autostartLink, PATH_MAX) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot construct autostart link path"));
            network->configFile[0] = '\0';
            return -1;
        }
    }

    return qemudSaveNetworkConfig(conn, driver, network, def);
}


static struct qemud_vm *
qemudLoadConfig(struct qemud_driver *driver,
                const char *file,
                const char *path,
                const char *xml,
                const char *autostartLink) {
    struct qemud_vm_def *def;
    struct qemud_vm *vm;

    if (!(def = qemudParseVMDef(NULL, driver, xml, file))) {
        virErrorPtr err = virGetLastError();
        qemudLog(QEMUD_WARN, _("Error parsing QEMU guest config '%s' : %s"),
                 path, (err ? err->message :
                        _("BUG: unknown error - please report it\n")));
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        qemudLog(QEMUD_WARN,
                 _("QEMU guest config filename '%s'"
                   " does not match guest name '%s'"),
                 path, def->name);
        qemudFreeVMDef(def);
        return NULL;
    }

    if (!(vm = qemudAssignVMDef(NULL, driver, def))) {
        qemudLog(QEMUD_WARN,
                 _("Failed to load QEMU guest config '%s': out of memory"),
                 path);
        qemudFreeVMDef(def);
        return NULL;
    }

    strncpy(vm->configFile, path, PATH_MAX);
    vm->configFile[PATH_MAX-1] = '\0';

    strncpy(vm->autostartLink, autostartLink, PATH_MAX);
    vm->autostartLink[PATH_MAX-1] = '\0';

    vm->autostart = virFileLinkPointsTo(vm->autostartLink, vm->configFile);

    return vm;
}

static struct qemud_network *
qemudLoadNetworkConfig(struct qemud_driver *driver,
                       const char *file,
                       const char *path,
                       const char *xml,
                       const char *autostartLink) {
    struct qemud_network_def *def;
    struct qemud_network *network;

    if (!(def = qemudParseNetworkDef(NULL, driver, xml, file))) {
        virErrorPtr err = virGetLastError();
        qemudLog(QEMUD_WARN, _("Error parsing network config '%s' : %s"),
                 path, err->message);
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        qemudLog(QEMUD_WARN,
                 _("Network config filename '%s'"
                   " does not match network name '%s'"),
                 path, def->name);
        qemudFreeNetworkDef(def);
        return NULL;
    }

    if (!(network = qemudAssignNetworkDef(NULL, driver, def))) {
        qemudLog(QEMUD_WARN,
                 _("Failed to load network config '%s': out of memory"), path);
        qemudFreeNetworkDef(def);
        return NULL;
    }

    strncpy(network->configFile, path, PATH_MAX);
    network->configFile[PATH_MAX-1] = '\0';

    strncpy(network->autostartLink, autostartLink, PATH_MAX);
    network->autostartLink[PATH_MAX-1] = '\0';

    network->autostart = virFileLinkPointsTo(network->autostartLink, network->configFile);

    return network;
}

static
int qemudScanConfigDir(struct qemud_driver *driver,
                       const char *configDir,
                       const char *autostartDir,
                       int isGuest) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        qemudLog(QEMUD_ERR, _("Failed to open dir '%s': %s"),
                 configDir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir))) {
        char *xml;
        char path[PATH_MAX];
        char autostartLink[PATH_MAX];

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        if (virFileBuildPath(configDir, entry->d_name, NULL, path, PATH_MAX) < 0) {
            qemudLog(QEMUD_WARN, _("Config filename '%s/%s' is too long"),
                     configDir, entry->d_name);
            continue;
        }

        if (virFileBuildPath(autostartDir, entry->d_name, NULL,
                             autostartLink, PATH_MAX) < 0) {
            qemudLog(QEMUD_WARN, _("Autostart link path '%s/%s' is too long"),
                     autostartDir, entry->d_name);
            continue;
        }

        if (virFileReadAll(path, QEMUD_MAX_XML_LEN, &xml) < 0)
            continue;

        if (isGuest)
            qemudLoadConfig(driver, entry->d_name, path, xml, autostartLink);
        else
            qemudLoadNetworkConfig(driver, entry->d_name, path, xml, autostartLink);

        VIR_FREE(xml);
    }

    closedir(dir);

    return 0;
}

/* Scan for all guest and network config files */
int qemudScanConfigs(struct qemud_driver *driver) {
    if (qemudScanConfigDir(driver, driver->configDir, driver->autostartDir, 1) < 0)
        return -1;

    if (qemudScanConfigDir(driver, driver->networkConfigDir, driver->networkAutostartDir, 0) < 0)
        return -1;

    return 0;
}

static int qemudGenerateXMLChar(virBufferPtr buf,
                                const struct qemud_vm_chr_def *dev,
                                const char *type)
{
    const char *const types[] = {
        "null",
        "vc",
        "pty",
        "dev",
        "file",
        "pipe",
        "stdio",
        "udp",
        "tcp",
        "unix"
    };
    verify_true(ARRAY_CARDINALITY(types) == QEMUD_CHR_SRC_TYPE_LAST);

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    if (STREQ(type, "console") &&
        dev->srcType == QEMUD_CHR_SRC_TYPE_PTY &&
        dev->srcData.file.path[0] != '\0') {
        virBufferVSprintf(buf, "    <%s type='%s' tty='%s'>\n",
                          type, types[dev->srcType],
                          dev->srcData.file.path);
    } else {
        virBufferVSprintf(buf, "    <%s type='%s'>\n",
                          type, types[dev->srcType]);
    }

    switch (dev->srcType) {
    case QEMUD_CHR_SRC_TYPE_NULL:
    case QEMUD_CHR_SRC_TYPE_VC:
    case QEMUD_CHR_SRC_TYPE_STDIO:
        /* nada */
        break;

    case QEMUD_CHR_SRC_TYPE_PTY:
    case QEMUD_CHR_SRC_TYPE_DEV:
    case QEMUD_CHR_SRC_TYPE_FILE:
    case QEMUD_CHR_SRC_TYPE_PIPE:
        if (dev->srcType != QEMUD_CHR_SRC_TYPE_PTY ||
            dev->srcData.file.path[0]) {
            virBufferVSprintf(buf, "      <source path='%s'/>\n",
                              dev->srcData.file.path);
        }
        break;

    case QEMUD_CHR_SRC_TYPE_UDP:
        if (dev->srcData.udp.bindService[0] != '\0' &&
            dev->srcData.udp.bindHost[0] != '\0') {
            virBufferVSprintf(buf, "      <source mode='bind' host='%s' service='%s'/>\n",
                              dev->srcData.udp.bindHost,
                              dev->srcData.udp.bindService);
        } else if (dev->srcData.udp.bindHost[0] !='\0') {
            virBufferVSprintf(buf, "      <source mode='bind' host='%s'/>\n",
                              dev->srcData.udp.bindHost);
        } else if (dev->srcData.udp.bindService[0] != '\0') {
            virBufferVSprintf(buf, "      <source mode='bind' service='%s'/>\n",
                              dev->srcData.udp.bindService);
        }

        if (dev->srcData.udp.connectService[0] != '\0' &&
            dev->srcData.udp.connectHost[0] != '\0') {
            virBufferVSprintf(buf, "      <source mode='connect' host='%s' service='%s'/>\n",
                              dev->srcData.udp.connectHost,
                              dev->srcData.udp.connectService);
        } else if (dev->srcData.udp.connectHost[0] != '\0') {
            virBufferVSprintf(buf, "      <source mode='connect' host='%s'/>\n",
                              dev->srcData.udp.connectHost);
        } else if (dev->srcData.udp.connectService[0] != '\0') {
            virBufferVSprintf(buf, "      <source mode='connect' service='%s'/>\n",
                              dev->srcData.udp.connectService);
        }
        break;

    case QEMUD_CHR_SRC_TYPE_TCP:
        virBufferVSprintf(buf, "      <source mode='%s' host='%s' service='%s'/>\n",
                          dev->srcData.tcp.listen ? "bind" : "connect",
                          dev->srcData.tcp.host,
                          dev->srcData.tcp.service);
        virBufferVSprintf(buf, "      <protocol type='%s'/>\n",
                          dev->srcData.tcp.protocol == QEMUD_CHR_SRC_TCP_PROTOCOL_TELNET
                          ? "telnet" : "raw");
        break;

    case QEMUD_CHR_SRC_TYPE_UNIX:
        virBufferVSprintf(buf, "      <source mode='%s' path='%s'/>\n",
                          dev->srcData.nix.listen ? "bind" : "connect",
                          dev->srcData.nix.path);
        break;
    }

    virBufferVSprintf(buf, "      <target port='%d'/>\n",
                      dev->dstPort);

    virBufferVSprintf(buf, "    </%s>\n",
                      type);

    return 0;
}


/* Generate an XML document describing the guest's configuration */
char *qemudGenerateXML(virConnectPtr conn,
                       struct qemud_driver *driver ATTRIBUTE_UNUSED,
                       struct qemud_vm *vm,
                       struct qemud_vm_def *def,
                       int live) {
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const struct qemud_vm_disk_def *disk;
    const struct qemud_vm_net_def *net;
    const struct qemud_vm_input_def *input;
    const struct qemud_vm_sound_def *sound;
    const struct qemud_vm_chr_def *chr;
    const char *type = NULL, *tmp;
    int n, allones = 1;

    if (!(type = qemudVirtTypeToString(def->virtType))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected domain type %d"), def->virtType);
        goto cleanup;
    }

    if (qemudIsActiveVM(vm) && live)
        virBufferVSprintf(&buf, "<domain type='%s' id='%d'>\n", type, vm->id);
    else
        virBufferVSprintf(&buf, "<domain type='%s'>\n", type);

    virBufferVSprintf(&buf, "  <name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);

    virBufferVSprintf(&buf, "  <memory>%lu</memory>\n", def->maxmem);
    virBufferVSprintf(&buf, "  <currentMemory>%lu</currentMemory>\n", def->memory);

    for (n = 0 ; n < QEMUD_CPUMASK_LEN ; n++)
        if (def->cpumask[n] != 1)
            allones = 0;

    if (allones) {
        virBufferVSprintf(&buf, "  <vcpu>%d</vcpu>\n", def->vcpus);
    } else {
        char *cpumask = NULL;
        if ((cpumask = virSaveCpuSet(conn, def->cpumask, QEMUD_CPUMASK_LEN)) == NULL) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                             "%s", _("allocating cpu mask"));
            goto cleanup;
        }
        virBufferVSprintf(&buf, "  <vcpu cpuset='%s'>%d</vcpu>\n", cpumask, def->vcpus);
        VIR_FREE(cpumask);
    }

    if (def->os.bootloader[0])
        virBufferVSprintf(&buf, "  <bootloader>%s</bootloader>\n", def->os.bootloader);
    virBufferAddLit(&buf, "  <os>\n");

    if (def->virtType == QEMUD_VIRT_QEMU)
        virBufferVSprintf(&buf, "    <type arch='%s' machine='%s'>%s</type>\n",
                          def->os.arch, def->os.machine, def->os.type);
    else
        virBufferVSprintf(&buf, "    <type>%s</type>\n", def->os.type);

    if (!def->os.bootloader[0]) {
        if (def->os.kernel[0])
            virBufferVSprintf(&buf, "    <kernel>%s</kernel>\n", def->os.kernel);
        if (def->os.initrd[0])
            virBufferVSprintf(&buf, "    <initrd>%s</initrd>\n", def->os.initrd);
        if (def->os.cmdline[0])
            virBufferVSprintf(&buf, "    <cmdline>%s</cmdline>\n", def->os.cmdline);

        for (n = 0 ; n < def->os.nBootDevs ; n++) {
            const char *boottype = "hd";
            switch (def->os.bootDevs[n]) {
            case QEMUD_BOOT_FLOPPY:
                boottype = "fd";
                break;
            case QEMUD_BOOT_DISK:
                boottype = "hd";
                break;
            case QEMUD_BOOT_CDROM:
                boottype = "cdrom";
                break;
            case QEMUD_BOOT_NET:
                boottype = "network";
                break;
            }
            virBufferVSprintf(&buf, "    <boot dev='%s'/>\n", boottype);
        }
    }

    virBufferAddLit(&buf, "  </os>\n");

    if (def->features & QEMUD_FEATURE_ACPI) {
        virBufferAddLit(&buf, "  <features>\n");
        virBufferAddLit(&buf, "    <acpi/>\n");
        virBufferAddLit(&buf, "  </features>\n");
    }

    virBufferVSprintf(&buf, "  <clock offset='%s'/>\n", def->localtime ? "localtime" : "utc");

    virBufferAddLit(&buf, "  <on_poweroff>destroy</on_poweroff>\n");
    if (def->noReboot)
        virBufferAddLit(&buf, "  <on_reboot>destroy</on_reboot>\n");
    else
        virBufferAddLit(&buf, "  <on_reboot>restart</on_reboot>\n");

    virBufferAddLit(&buf, "  <on_crash>destroy</on_crash>\n");
    virBufferAddLit(&buf, "  <devices>\n");

    virBufferVSprintf(&buf, "    <emulator>%s</emulator>\n", def->os.binary);

    disk = def->disks;
    while (disk) {
        const char *types[] = {
            "block",
            "file",
        };
        const char *typeAttrs[] = {
            "dev",
            "file",
        };
        const char *devices[] = {
            "disk",
            "cdrom",
            "floppy",
        };
        virBufferVSprintf(&buf, "    <disk type='%s' device='%s'>\n",
                          types[disk->type], devices[disk->device]);

        if (disk->src[0])
            virBufferVSprintf(&buf, "      <source %s='%s'/>\n",
                              typeAttrs[disk->type], disk->src);

        virBufferVSprintf(&buf, "      <target dev='%s' bus='%s'/>\n",
                          disk->dst, qemudBusIdToName(disk->bus, 0));

        if (disk->readonly)
            virBufferAddLit(&buf, "      <readonly/>\n");

        virBufferAddLit(&buf, "    </disk>\n");

        disk = disk->next;
    }

    net = def->nets;
    while (net) {
        const char *types[] = {
            "user",
            "ethernet",
            "server",
            "client",
            "mcast",
            "network",
            "bridge",
        };
        virBufferVSprintf(&buf, "    <interface type='%s'>\n",
                          types[net->type]);

        virBufferVSprintf(&buf, "      <mac address='%02x:%02x:%02x:%02x:%02x:%02x'/>\n",
                          net->mac[0], net->mac[1], net->mac[2],
                          net->mac[3], net->mac[4], net->mac[5]);

        switch (net->type) {
        case QEMUD_NET_NETWORK:
            virBufferVSprintf(&buf, "      <source network='%s'/>\n", net->dst.network.name);

            if (net->dst.network.ifname[0] != '\0')
                virBufferVSprintf(&buf, "      <target dev='%s'/>\n", net->dst.network.ifname);
            break;

        case QEMUD_NET_ETHERNET:
            if (net->dst.ethernet.ifname[0] != '\0')
                virBufferVSprintf(&buf, "      <target dev='%s'/>\n", net->dst.ethernet.ifname);
            if (net->dst.ethernet.script[0] != '\0')
                virBufferVSprintf(&buf, "      <script path='%s'/>\n", net->dst.ethernet.script);
            break;

        case QEMUD_NET_BRIDGE:
            virBufferVSprintf(&buf, "      <source bridge='%s'/>\n", net->dst.bridge.brname);
            if (net->dst.bridge.ifname[0] != '\0')
                virBufferVSprintf(&buf, "      <target dev='%s'/>\n", net->dst.bridge.ifname);
            break;

        case QEMUD_NET_SERVER:
        case QEMUD_NET_CLIENT:
        case QEMUD_NET_MCAST:
            if (net->dst.socket.address[0] != '\0')
                virBufferVSprintf(&buf, "      <source address='%s' port='%d'/>\n",
                                  net->dst.socket.address, net->dst.socket.port);
            else
                virBufferVSprintf(&buf, "      <source port='%d'/>\n",
                                  net->dst.socket.port);
        }

        if (net->model && net->model[0] != '\0') {
            virBufferVSprintf(&buf, "      <model type='%s'/>\n",
                              net->model);
        }

        virBufferAddLit(&buf, "    </interface>\n");

        net = net->next;
    }

    chr = def->serials;
    while (chr) {
        if (qemudGenerateXMLChar(&buf, chr, "serial") < 0)
            goto no_memory;

        chr = chr->next;
    }

    chr = def->parallels;
    while (chr) {
        if (qemudGenerateXMLChar(&buf, chr, "parallel") < 0)
            goto no_memory;

        chr = chr->next;
    }

    /* First serial device is the primary console */
    if (def->nserials > 0 &&
        qemudGenerateXMLChar(&buf, def->serials, "console") < 0)
        goto no_memory;

    input = def->inputs;
    while (input) {
        if (input->bus == QEMU_INPUT_BUS_USB)
            virBufferVSprintf(&buf, "    <input type='%s' bus='usb'/>\n",
                              input->type == QEMU_INPUT_TYPE_MOUSE ? "mouse" : "tablet");
        input = input->next;
    }
    /* If graphics is enable, add implicit mouse */
    if (def->graphicsType != QEMUD_GRAPHICS_NONE)
        virBufferVSprintf(&buf, "    <input type='mouse' bus='%s'/>\n",
                          STREQ(def->os.type, "hvm") ? "ps2" : "xen");

    switch (def->graphicsType) {
    case QEMUD_GRAPHICS_VNC:
        virBufferAddLit(&buf, "    <graphics type='vnc'");

        if (def->vncPort)
            virBufferVSprintf(&buf, " port='%d'",
                              qemudIsActiveVM(vm) && live ? def->vncActivePort : def->vncPort);

        if (def->vncListen[0])
            virBufferVSprintf(&buf, " listen='%s'",
                              def->vncListen);

        if (def->keymap)
            virBufferVSprintf(&buf, " keymap='%s'",
                              def->keymap);

        virBufferAddLit(&buf, "/>\n");
        break;

    case QEMUD_GRAPHICS_SDL:
        virBufferAddLit(&buf, "    <graphics type='sdl'/>\n");
        break;

    case QEMUD_GRAPHICS_NONE:
    default:
        break;
    }

    sound = def->sounds;
    while(sound) {
        const char *model = qemudSoundModelToString(sound->model);
        if (!model) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("invalid sound model"));
            goto cleanup;
        }
        virBufferVSprintf(&buf, "    <sound model='%s'/>\n", model);
        sound = sound->next;
    }

    virBufferAddLit(&buf, "  </devices>\n");
    virBufferAddLit(&buf, "</domain>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to generate XML: out of memory"));
 cleanup:
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
    return NULL;
}


char *qemudGenerateNetworkXML(virConnectPtr conn,
                              struct qemud_driver *driver ATTRIBUTE_UNUSED,
                              struct qemud_network *network,
                              struct qemud_network_def *def) {
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char *tmp;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virBufferAddLit(&buf, "<network>\n");

    virBufferVSprintf(&buf, "  <name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);

    if (def->forward) {
        if (def->forwardDev[0]) {
            virBufferVSprintf(&buf, "  <forward dev='%s' mode='%s'/>\n",
                              def->forwardDev, (def->forwardMode == QEMUD_NET_FORWARD_ROUTE ? "route" : "nat"));
        } else {
            virBufferVSprintf(&buf, "  <forward mode='%s'/>\n", (def->forwardMode == QEMUD_NET_FORWARD_ROUTE ? "route" : "nat"));
        }
    }

    virBufferAddLit(&buf, "  <bridge");
    if (qemudIsActiveNetwork(network)) {
        virBufferVSprintf(&buf, " name='%s'", network->bridge);
    } else if (def->bridge[0]) {
        virBufferVSprintf(&buf, " name='%s'", def->bridge);
    }
    virBufferVSprintf(&buf, " stp='%s' forwardDelay='%d' />\n",
                      def->disableSTP ? "off" : "on",
                      def->forwardDelay);

    if (def->ipAddress[0] || def->netmask[0]) {
        virBufferAddLit(&buf, "  <ip");

        if (def->ipAddress[0])
            virBufferVSprintf(&buf, " address='%s'", def->ipAddress);

        if (def->netmask[0])
            virBufferVSprintf(&buf, " netmask='%s'", def->netmask);

        virBufferAddLit(&buf, ">\n");

        if (def->ranges) {
            struct qemud_dhcp_range_def *range = def->ranges;
            virBufferAddLit(&buf, "    <dhcp>\n");
            while (range) {
                virBufferVSprintf(&buf, "      <range start='%s' end='%s' />\n",
                                  range->start, range->end);
                range = range->next;
            }
            virBufferAddLit(&buf, "    </dhcp>\n");
        }

        virBufferAddLit(&buf, "  </ip>\n");
    }

    virBufferAddLit(&buf, "</network>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to generate XML: out of memory"));
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
    return NULL;
}


int qemudDeleteConfig(virConnectPtr conn,
                      struct qemud_driver *driver ATTRIBUTE_UNUSED,
                      const char *configFile,
                      const char *name) {
    if (!configFile[0]) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("no config file for %s"), name);
        return -1;
    }

    if (unlink(configFile) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot remove config for %s"), name);
        return -1;
    }

    return 0;
}

#endif /* WITH_QEMU */
