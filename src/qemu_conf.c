/*
 * config.c: VM configuration management
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


int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename) {
    virConfPtr conf;
    virConfValuePtr p;

    /* Setup 2 critical defaults */
    if (!(driver->vncListen = strdup("127.0.0.1"))) {
        virReportOOMError(NULL);
        return -1;
    }
    if (!(driver->vncTLSx509certdir = strdup(SYSCONF_DIR "/pki/libvirt-vnc"))) {
        virReportOOMError(NULL);
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

    virConfFree (conf);
    return 0;
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
    {  "i686", 32, arch_info_hvm_x86_machines, 2,
       "/usr/bin/qemu", "/usr/bin/qemu-system-x86_64", arch_info_i686_flags, 4 },
    {  "x86_64", 64, arch_info_hvm_x86_machines, 2,
       "/usr/bin/qemu-system-x86_64", NULL, arch_info_x86_64_flags, 2 },
    {  "mips", 32, arch_info_hvm_mips_machines, 1,
       "/usr/bin/qemu-system-mips", NULL, NULL, 0 },
    {  "mipsel", 32, arch_info_hvm_mips_machines, 1,
       "/usr/bin/qemu-system-mipsel", NULL, NULL, 0 },
    {  "sparc", 32, arch_info_hvm_sparc_machines, 1,
       "/usr/bin/qemu-system-sparc", NULL, NULL, 0 },
    {  "ppc", 32, arch_info_hvm_ppc_machines, 3,
       "/usr/bin/qemu-system-ppc", NULL, NULL, 0 },
};

static const struct qemu_arch_info const arch_info_xen[] = {
    {  "i686", 32, arch_info_xen_x86_machines, 1,
       "/usr/bin/xenner", NULL, arch_info_i686_flags, 4 },
    {  "x86_64", 64, arch_info_xen_x86_machines, 1,
       "/usr/bin/xenner", NULL, arch_info_x86_64_flags, 2 },
};

static int
qemudCapsInitGuest(virCapsPtr caps,
                   const char *hostmachine,
                   const struct qemu_arch_info *info,
                   int hvm) {
    virCapsGuestPtr guest;
    int i;
    int hasbase = 0;
    int hasaltbase = 0;
    int haskvm = 0;
    int haskqemu = 0;
    const char *kvmbin = NULL;

    /* Check for existance of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    hasbase = (access(info->binary, X_OK) == 0);
    hasaltbase = (info->altbinary && access(info->altbinary, X_OK) == 0);

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
                break;
            }
        }

        if (access("/dev/kqemu", F_OK) == 0)
            haskqemu = 1;
    }


    if (!hasbase && !hasaltbase && !haskvm)
        return 0;

    /* We register kvm as the base emulator too, since we can
     * just give -no-kvm to disable acceleration if required */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         hvm ? "hvm" : "xen",
                                         info->arch,
                                         info->wordsize,
                                         (hasbase ? info->binary :
                                          (hasaltbase ? info->altbinary : kvmbin)),
                                         NULL,
                                         info->nmachines,
                                         info->machines)) == NULL)
        return -1;

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

        if (haskvm &&
            virCapabilitiesAddGuestDomain(guest,
                                          "kvm",
                                          kvmbin,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            return -1;
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

virCapsPtr qemudCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    int i;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto no_memory;

    /* Using KVM's mac prefix for QEMU too */
    virCapabilitiesSetMacPrefix(caps, (unsigned char[]){ 0x52, 0x54, 0x00 });

    if (virCapsInitNUMA(caps) < 0)
        goto no_memory;

    /* First the pure HVM guests */
    for (i = 0 ; i < ARRAY_CARDINALITY(arch_info_hvm) ; i++)
        if (qemudCapsInitGuest(caps,
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


int qemudExtractVersionInfo(const char *qemu,
                            unsigned int *retversion,
                            unsigned int *retflags) {
    const char *const qemuarg[] = { qemu, "-help", NULL };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    pid_t child;
    int newstdout = -1;
    int ret = -1, status;
    unsigned int major, minor, micro;
    unsigned int version, kvm_version;
    unsigned int flags = 0;

    if (retflags)
        *retflags = 0;
    if (retversion)
        *retversion = 0;

    if (virExec(NULL, qemuarg, qemuenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_NONE) < 0)
        return -1;

    char *help = NULL;
    enum { MAX_HELP_OUTPUT_SIZE = 8192 };
    int len = virFileReadLimFD(newstdout, MAX_HELP_OUTPUT_SIZE, &help);
    if (len < 0)
        goto cleanup2;

    if (sscanf(help, "QEMU PC emulator version %u.%u.%u (kvm-%u)",
               &major, &minor, &micro, &kvm_version) != 4)
        kvm_version = 0;

    if (!kvm_version && sscanf(help, "QEMU PC emulator version %u.%u.%u",
               &major, &minor, &micro) != 3)
        goto cleanup2;

    version = (major * 1000 * 1000) + (minor * 1000) + micro;

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
    }
    if (strstr(help, "boot=on"))
        flags |= QEMUD_CMD_FLAG_DRIVE_BOOT;
    if (version >= 9000)
        flags |= QEMUD_CMD_FLAG_VNC_COLON;
    if (kvm_version >= 74)
        flags |= QEMUD_CMD_FLAG_VNET_HDR;

    /*
     * Handling of -incoming arg with varying features
     *  -incoming tcp    (kvm >= 79)
     *  -incoming exec   (kvm >= 80)
     *  -incoming stdio  (all earlier kvm)
     *
     * NB, there was a pre-kvm-79 'tcp' support, but it
     * was broken, because it blocked the monitor console
     * while waiting for data, so pretend it doesn't exist
     *
     * XXX when next QEMU release after 0.9.1 arrives,
     * we'll need to add MIGRATE_QEMU_TCP/EXEC here too
     */
    if (kvm_version >= 79) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP;
        if (kvm_version >= 80)
            flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC;
    } else if (kvm_version > 0) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO;
    }

    if (retversion)
        *retversion = version;
    if (retflags)
        *retflags = flags;

    ret = 0;

    qemudDebug("Version %d %d %d  Cooked version: %d, with flags ? %d",
               major, minor, micro, version, flags);
    if (kvm_version)
        qemudDebug("KVM version %d detected", kvm_version);

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


static char *
qemudNetworkIfaceConnect(virConnectPtr conn,
                         struct qemud_driver *driver,
                         int **tapfds,
                         int *ntapfds,
                         virDomainNetDefPtr net,
                         int vlan,
                         int vnet_hdr)
{
    char *brname;
    char tapfdstr[4+3+32+7];
    char *retval = NULL;
    int err;
    int tapfd = -1;

    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        virNetworkPtr network = virNetworkLookupByName(conn,
                                                      net->data.network.name);
        if (!network) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Network '%s' not found"),
                             net->data.network.name);
            goto error;
        }
        brname = virNetworkGetBridgeName(network);

        virNetworkFree(network);

        if (brname == NULL) {
            goto error;
        }
    } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        brname = net->data.bridge.brname;
    } else {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Network type %d is not supported"), net->type);
        goto error;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, "vnet") ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (!(net->ifname = strdup("vnet%d"))) {
            virReportOOMError(conn);
            goto error;
        }
    }

    char ebuf[1024];
    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot initialize bridge support: %s"),
                         virStrerror(err, ebuf, sizeof ebuf));
        goto error;
    }

    if ((err = brAddTap(driver->brctl, brname,
                        &net->ifname, vnet_hdr, &tapfd))) {
        if (errno == ENOTSUP) {
            /* In this particular case, give a better diagnostic. */
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to add tap interface to bridge. "
                               "%s is not a bridge device"), brname);
        } else {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to add tap interface '%s' "
                               "to bridge '%s' : %s"),
                             net->ifname, brname, virStrerror(err, ebuf, sizeof ebuf));
        }
        goto error;
    }

    snprintf(tapfdstr, sizeof(tapfdstr),
             "tap,fd=%d,script=,vlan=%d,ifname=%s",
             tapfd, vlan, net->ifname);

    if (!(retval = strdup(tapfdstr)))
        goto no_memory;

    if (VIR_REALLOC_N(*tapfds, (*ntapfds)+1) < 0)
        goto no_memory;

    (*tapfds)[(*ntapfds)++] = tapfd;

    return retval;

 no_memory:
    virReportOOMError(conn);
 error:
    VIR_FREE(retval);
    if (tapfd != -1)
        close(tapfd);
    return NULL;
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

/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 */
int qemudBuildCommandLine(virConnectPtr conn,
                          struct qemud_driver *driver,
                          virDomainObjPtr vm,
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
    char *pidfile;
    const char *cpu = NULL;

    uname_normalize(&ut);

    virUUIDFormat(vm->def->uuid, uuid);

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

    emulator = vm->def->emulator;
    if (!emulator)
        emulator = virDomainDefDefaultEmulator(conn, vm->def, driver->caps);
    if (!emulator)
        return -1;


    /* Need to explicitly disable KQEMU if
     * 1. Arch matches host arch
     * 2. Guest domain is 'qemu'
     * 3. The qemu binary has the -no-kqemu flag
     */
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU) &&
        STREQ(ut.machine, vm->def->os.arch) &&
        vm->def->virtType == VIR_DOMAIN_VIRT_QEMU)
        disableKQEMU = 1;

    /* Need to explicitly disable KVM if
     * 1. Arch matches host arch
     * 2. Guest domain is 'qemu'
     * 3. The qemu binary has the -no-kvm flag
     */
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_KVM) &&
        STREQ(ut.machine, vm->def->os.arch) &&
        vm->def->virtType == VIR_DOMAIN_VIRT_QEMU)
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
    if (STREQ(vm->def->os.arch, "i686") &&
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
    snprintf(memory, sizeof(memory), "%lu", vm->def->maxmem/1024);
    snprintf(vcpus, sizeof(vcpus), "%lu", vm->def->vcpus);
    snprintf(domid, sizeof(domid), "%d", vm->def->id);
    pidfile = virFilePid(driver->stateDir, vm->def->name);
    if (!pidfile)
        goto error;

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
    if (vm->def->os.machine) {
        ADD_ARG_LIT("-M");
        ADD_ARG_LIT(vm->def->os.machine);
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
    ADD_ARG_LIT("-smp");
    ADD_ARG_LIT(vcpus);

    if (qemuCmdFlags & QEMUD_CMD_FLAG_NAME) {
        ADD_ARG_LIT("-name");
        ADD_ARG_LIT(vm->def->name);
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
    if (!vm->def->graphics)
        ADD_ARG_LIT("-nographic");

    ADD_ARG_LIT("-monitor");
    ADD_ARG_LIT("pty");

    ADD_ARG_LIT("-pidfile");
    ADD_ARG(pidfile);

    if (vm->def->localtime)
        ADD_ARG_LIT("-localtime");

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NO_REBOOT) &&
        vm->def->onReboot != VIR_DOMAIN_LIFECYCLE_RESTART)
        ADD_ARG_LIT("-no-reboot");

    if (!(vm->def->features & (1 << VIR_DOMAIN_FEATURE_ACPI)))
        ADD_ARG_LIT("-no-acpi");

    if (!vm->def->os.bootloader) {
        for (i = 0 ; i < vm->def->os.nBootDevs ; i++) {
            switch (vm->def->os.bootDevs[i]) {
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
        boot[vm->def->os.nBootDevs] = '\0';
        ADD_ARG_LIT("-boot");
        ADD_ARG_LIT(boot);

        if (vm->def->os.kernel) {
            ADD_ARG_LIT("-kernel");
            ADD_ARG_LIT(vm->def->os.kernel);
        }
        if (vm->def->os.initrd) {
            ADD_ARG_LIT("-initrd");
            ADD_ARG_LIT(vm->def->os.initrd);
        }
        if (vm->def->os.cmdline) {
            ADD_ARG_LIT("-append");
            ADD_ARG_LIT(vm->def->os.cmdline);
        }
    } else {
        ADD_ARG_LIT("-bootloader");
        ADD_ARG_LIT(vm->def->os.bootloader);
    }

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

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
            for (i = 0 ; i < vm->def->os.nBootDevs ; i++) {
                switch (vm->def->os.bootDevs[i]) {
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

        for (i = 0 ; i < vm->def->ndisks ; i++) {
            virBuffer opt = VIR_BUFFER_INITIALIZER;
            char *optstr;
            int bootable = 0;
            virDomainDiskDefPtr disk = vm->def->disks[i];
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
            if (disk->driverType)
                virBufferVSprintf(&opt, ",fmt=%s", disk->driverType);

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

            ADD_ARG_LIT("-drive");
            ADD_ARG(optstr);
        }
    } else {
        for (i = 0 ; i < vm->def->ndisks ; i++) {
            char dev[NAME_MAX];
            char file[PATH_MAX];
            virDomainDiskDefPtr disk = vm->def->disks[i];

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

    if (!vm->def->nnets) {
        ADD_ARG_LIT("-net");
        ADD_ARG_LIT("none");
    } else {
        int vlan = 0;
        for (i = 0 ; i < vm->def->nnets ; i++) {
            char nic[100];
            virDomainNetDefPtr net = vm->def->nets[i];

            if (snprintf(nic, sizeof(nic),
                         "nic,macaddr=%02x:%02x:%02x:%02x:%02x:%02x,vlan=%d%s%s",
                         net->mac[0], net->mac[1],
                         net->mac[2], net->mac[3],
                         net->mac[4], net->mac[5],
                         vlan,
                         (net->model ? ",model=" : ""),
                         (net->model ? net->model : "")) >= sizeof(nic))
                goto error;

            ADD_ARG_LIT("-net");
            ADD_ARG_LIT(nic);
            ADD_ARG_LIT("-net");

            switch (net->type) {
            case VIR_DOMAIN_NET_TYPE_NETWORK:
            case VIR_DOMAIN_NET_TYPE_BRIDGE:
                {
                    char *tap;
                    int vnet_hdr = 0;

                    if (qemuCmdFlags & QEMUD_CMD_FLAG_VNET_HDR &&
                        net->model && STREQ(net->model, "virtio"))
                        vnet_hdr = 1;

                    tap = qemudNetworkIfaceConnect(conn, driver,
                                                   tapfds, ntapfds,
                                                   net, vlan, vnet_hdr);
                    if (tap == NULL)
                        goto error;
                    ADD_ARG(tap);
                    break;
                }

            case VIR_DOMAIN_NET_TYPE_ETHERNET:
                {
                    char arg[PATH_MAX];
                    if (net->ifname) {
                        if (snprintf(arg, PATH_MAX-1, "tap,ifname=%s,script=%s,vlan=%d",
                                     net->ifname,
                                     net->data.ethernet.script,
                                     vlan) >= (PATH_MAX-1))
                            goto error;
                    } else {
                        if (snprintf(arg, PATH_MAX-1, "tap,script=%s,vlan=%d",
                                     net->data.ethernet.script,
                                     vlan) >= (PATH_MAX-1))
                            goto error;
                    }

                    ADD_ARG_LIT(arg);
                }
                break;

            case VIR_DOMAIN_NET_TYPE_CLIENT:
            case VIR_DOMAIN_NET_TYPE_SERVER:
            case VIR_DOMAIN_NET_TYPE_MCAST:
                {
                    char arg[PATH_MAX];
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
                    if (snprintf(arg, PATH_MAX-1, "socket,%s=%s:%d,vlan=%d",
                                 mode,
                                 net->data.socket.address,
                                 net->data.socket.port,
                                 vlan) >= (PATH_MAX-1))
                        goto error;

                    ADD_ARG_LIT(arg);
                }
                break;

            case VIR_DOMAIN_NET_TYPE_USER:
            default:
                {
                    char arg[PATH_MAX];
                    if (snprintf(arg, PATH_MAX-1, "user,vlan=%d", vlan) >= (PATH_MAX-1))
                        goto error;

                    ADD_ARG_LIT(arg);
                }
            }

            vlan++;
        }
    }

    if (!vm->def->nserials) {
        ADD_ARG_LIT("-serial");
        ADD_ARG_LIT("none");
    } else {
        for (i = 0 ; i < vm->def->nserials ; i++) {
            char buf[4096];
            virDomainChrDefPtr serial = vm->def->serials[i];

            if (qemudBuildCommandLineChrDevStr(serial, buf, sizeof(buf)) < 0)
                goto error;

            ADD_ARG_LIT("-serial");
            ADD_ARG_LIT(buf);
        }
    }

    if (!vm->def->nparallels) {
        ADD_ARG_LIT("-parallel");
        ADD_ARG_LIT("none");
    } else {
        for (i = 0 ; i < vm->def->nparallels ; i++) {
            char buf[4096];
            virDomainChrDefPtr parallel = vm->def->parallels[i];

            if (qemudBuildCommandLineChrDevStr(parallel, buf, sizeof(buf)) < 0)
                goto error;

            ADD_ARG_LIT("-parallel");
            ADD_ARG_LIT(buf);
        }
    }

    ADD_ARG_LIT("-usb");
    for (i = 0 ; i < vm->def->ninputs ; i++) {
        virDomainInputDefPtr input = vm->def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            ADD_ARG_LIT("-usbdevice");
            ADD_ARG_LIT(input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ? "mouse" : "tablet");
        }
    }

    if (vm->def->graphics &&
        vm->def->graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBuffer opt = VIR_BUFFER_INITIALIZER;
        char *optstr;

        if (qemuCmdFlags & QEMUD_CMD_FLAG_VNC_COLON) {
            if (vm->def->graphics->data.vnc.listenAddr)
                virBufferAdd(&opt, vm->def->graphics->data.vnc.listenAddr, -1);
            else if (driver->vncListen)
                virBufferAdd(&opt, driver->vncListen, -1);

            virBufferVSprintf(&opt, ":%d",
                              vm->def->graphics->data.vnc.port - 5900);

            if (vm->def->graphics->data.vnc.passwd ||
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
                              vm->def->graphics->data.vnc.port - 5900);
        }
        if (virBufferError(&opt))
            goto no_memory;

        optstr = virBufferContentAndReset(&opt);

        ADD_ARG_LIT("-vnc");
        ADD_ARG(optstr);
        if (vm->def->graphics->data.vnc.keymap) {
            ADD_ARG_LIT("-k");
            ADD_ARG_LIT(vm->def->graphics->data.vnc.keymap);
        }
    } else if (vm->def->graphics &&
               vm->def->graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        char *xauth = NULL;
        char *display = NULL;

        if (vm->def->graphics->data.sdl.xauth &&
            virAsprintf(&xauth, "XAUTHORITY=%s",
                        vm->def->graphics->data.sdl.xauth) < 0)
            goto no_memory;
        if (vm->def->graphics->data.sdl.display &&
            virAsprintf(&display, "DISPLAY=%s",
                        vm->def->graphics->data.sdl.display) < 0) {
            VIR_FREE(xauth);
            goto no_memory;
        }

        if (xauth)
            ADD_ENV(xauth);
        if (display)
            ADD_ENV(display);
        if (vm->def->graphics->data.sdl.fullscreen)
            ADD_ARG_LIT("-full-screen");
    }

    /* Add sound hardware */
    if (vm->def->nsounds) {
        int size = 100;
        char *modstr;
        if (VIR_ALLOC_N(modstr, size+1) < 0)
            goto no_memory;

        for (i = 0 ; i < vm->def->nsounds && size > 0 ; i++) {
            virDomainSoundDefPtr sound = vm->def->sounds[i];
            const char *model = virDomainSoundModelTypeToString(sound->model);
            if (!model) {
                VIR_FREE(modstr);
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("invalid sound model"));
                goto error;
            }
            strncat(modstr, model, size);
            size -= strlen(model);
            if (i < (vm->def->nsounds - 1))
               strncat(modstr, ",", size--);
        }
        ADD_ARG_LIT("-soundhw");
        ADD_ARG(modstr);
    }

    /* Add host passthrough hardware */
    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        int ret;
        char* usbdev;
        char* pcidev;
        virDomainHostdevDefPtr hostdev = vm->def->hostdevs[i];

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


/* Called from SAX on parsing errors in the XML. */
static void
catchXMLError (void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt) {
        virConnectPtr conn = ctxt->_private;

        if (ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            qemudReportError (conn, NULL, NULL, VIR_ERR_XML_DETAIL,
                                  _("at line %d: %s"),
                                  ctxt->lastError.line,
                                  ctxt->lastError.message);
        }
    }
}


/**
 * qemudDomainStatusParseFile
 *
 * read the last known status of a domain
 *
 * Returns 0 on success
 */
qemudDomainStatusPtr
qemudDomainStatusParseFile(virConnectPtr conn,
                           virCapsPtr caps,
                           const char *filename, int flags)
{
    xmlParserCtxtPtr pctxt = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlDocPtr xml = NULL;
    xmlNodePtr root, config_root;
    virDomainDefPtr def = NULL;
    char *tmp = NULL;
    long val;
    qemudDomainStatusPtr status = NULL;

    if (VIR_ALLOC(status) < 0) {
        virReportOOMError(conn);
        goto error;
    }

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto error;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadFile (pctxt, filename, NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              qemudReportError(conn, NULL, NULL, VIR_ERR_XML_ERROR,
                                   "%s", _("failed to parse xml document"));
        goto error;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto error;
    }

    if (!xmlStrEqual(root->name, BAD_CAST "domstatus")) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("incorrect root element"));
        goto error;
    }

    ctxt->node = root;
    if(!(tmp = virXPathString(conn, "string(./@state)", ctxt))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("invalid domain state"));
        goto error;
    } else {
        status->state = virDomainStateTypeFromString(tmp);
        VIR_FREE(tmp);
    }

    if((virXPathLong(conn, "string(./@pid)", ctxt, &val)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("invalid pid"));
        goto error;
    } else
        status->pid = (pid_t)val;

    if(!(tmp = virXPathString(conn, "string(./monitor[1]/@path)", ctxt))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("no monitor path"));
        goto error;
    } else
        status->monitorpath = tmp;

    if(!(config_root = virXPathNode(conn, "./domain", ctxt))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("no domain config"));
        goto error;
    }
    if(!(def = virDomainDefParseNode(conn, caps, xml, config_root, flags)))
        goto error;
    else
        status->def = def;

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc (xml);
    return status;

error:
    VIR_FREE(tmp);
    VIR_FREE(status);
    goto cleanup;
}


/**
 * qemudDomainStatusFormat
 *
 * Get the state of a running domain as XML
 *
 * Returns xml on success
 */
static char*
qemudDomainStatusFormat(virConnectPtr conn,
                        virDomainObjPtr vm)
{
    char *config_xml = NULL, *xml = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferVSprintf(&buf, "<domstatus state='%s' pid='%d'>\n",
                      virDomainStateTypeToString(vm->state),
                      vm->pid);
    virBufferEscapeString(&buf, "  <monitor path='%s'/>\n", vm->monitorpath);

    if (!(config_xml = virDomainDefFormat(conn,
                                          vm->def,
                                          VIR_DOMAIN_XML_SECURE)))
        goto cleanup;

    virBufferAdd(&buf, config_xml, strlen(config_xml));
    virBufferAddLit(&buf, "</domstatus>\n");

    xml = virBufferContentAndReset(&buf);
cleanup:
    VIR_FREE(config_xml);
    return xml;
}


/**
 * qemudSaveDomainStatus
 *
 * Save the current status of a running domain
 *
 * Returns 0 on success
 */
int
qemudSaveDomainStatus(virConnectPtr conn,
                      struct qemud_driver *driver,
                      virDomainObjPtr vm)
{
    int ret = -1;
    char *xml = NULL;

    if (!(xml = qemudDomainStatusFormat(conn, vm)))
        goto cleanup;

    if ((ret = virDomainSaveXML(conn, driver->stateDir, vm->def, xml)))
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(xml);
    return ret;
}
