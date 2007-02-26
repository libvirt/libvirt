/*
 * config.c: VM configuration management
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>

#include <libvirt/virterror.h>

#include "protocol.h"
#include "internal.h"
#include "conf.h"
#include "driver.h"
#include "iptables.h"

static int qemudParseUUID(const char *uuid,
                          unsigned char *rawuuid) {
    const char *cur;
    int i;

    /*
     * do a liberal scan allowing '-' and ' ' anywhere between character
     * pairs as long as there is 32 of them in the end.
     */
    cur = uuid;
    for (i = 0;i < 16;) {
        rawuuid[i] = 0;
        if (*cur == 0)
            goto error;
        if ((*cur == '-') || (*cur == ' ')) {
            cur++;
            continue;
        }
        if ((*cur >= '0') && (*cur <= '9'))
            rawuuid[i] = *cur - '0';
        else if ((*cur >= 'a') && (*cur <= 'f'))
            rawuuid[i] = *cur - 'a' + 10;
        else if ((*cur >= 'A') && (*cur <= 'F'))
            rawuuid[i] = *cur - 'A' + 10;
        else
            goto error;
        rawuuid[i] *= 16;
        cur++;
        if (*cur == 0)
            goto error;
        if ((*cur >= '0') && (*cur <= '9'))
            rawuuid[i] += *cur - '0';
        else if ((*cur >= 'a') && (*cur <= 'f'))
            rawuuid[i] += *cur - 'a' + 10;
        else if ((*cur >= 'A') && (*cur <= 'F'))
            rawuuid[i] += *cur - 'A' + 10;
        else
            goto error;
        i++;
        cur++;
    }

    return 0;

 error:
    return -1;
}

/* Free all memory associated with a struct qemud_vm object */
void qemudFreeVMDef(struct qemud_vm_def *def) {
    struct qemud_vm_disk_def *disk = def->disks;
    struct qemud_vm_net_def *net = def->nets;

    while (disk) {
        struct qemud_vm_disk_def *prev = disk;
        disk = disk->next;
        free(prev);
    }
    while (net) {
        struct qemud_vm_net_def *prev = net;
        net = net->next;
        free(prev);
    }
    free(def);
}

void qemudFreeVM(struct qemud_vm *vm) {
    qemudFreeVMDef(vm->def);
    if (vm->newDef)
        qemudFreeVMDef(vm->newDef);
    free(vm);
}

/* Build up a fully qualfiied path for a config file to be
 * associated with a persistent guest or network */
static int
qemudMakeConfigPath(const char *configDir,
                    const char *name,
                    const char *ext,
                    char *buf,
                    unsigned int buflen) {
    if ((strlen(configDir) + 1 + strlen(name) + (ext ? strlen(ext) : 0) + 1) > buflen)
        return -1;

    strcpy(buf, configDir);
    strcat(buf, "/");
    strcat(buf, name);
    if (ext)
        strcat(buf, ext);
    return 0;
}

int
qemudEnsureDir(const char *path)
{
    struct stat st;
    char parent[PATH_MAX];
    char *p;
    int err;

    if (stat(path, &st) >= 0)
        return 0;

    strncpy(parent, path, PATH_MAX);
    parent[PATH_MAX - 1] = '\0';

    if (!(p = strrchr(parent, '/')))
        return EINVAL;

    if (p == parent)
        return EPERM;

    *p = '\0';

    if ((err = qemudEnsureDir(parent)))
        return err;

    if (mkdir(path, 0777) < 0 && errno != EEXIST)
        return errno;

    return 0;
}

struct qemu_arch_info {
    const char *arch;
    const char **machines;
    const char *binary;
};

/* The list of possible machine types for various architectures,
   as supported by QEMU - taken from 'qemu -M ?' for each arch */
static const char *arch_info_x86_machines[] = {
    "pc", "isapc"
};
static const char *arch_info_mips_machines[] = {
    "mips"
};
static const char *arch_info_sparc_machines[] = {
    "sun4m"
};
static const char *arch_info_ppc_machines[] = {
    "g3bw", "mac99", "prep"
};

/* The archicture tables for supported QEMU archs */
static struct qemu_arch_info archs[] = { 
    {  "i686", arch_info_x86_machines, "qemu" },
    {  "x86_64", arch_info_x86_machines, "qemu-system-x86_64" },
    {  "mips", arch_info_mips_machines, "qemu-system-mips" },
    {  "mipsel", arch_info_mips_machines, "qemu-system-mipsel" },
    {  "sparc", arch_info_sparc_machines, "qemu-system-sparc" },
    {  "ppc", arch_info_ppc_machines, "qemu-system-ppc" },
};

/* Return the default architecture if none is explicitly requested*/
static const char *qemudDefaultArch(void) {
    return archs[0].arch;
}

/* Return the default machine type for a given architecture */
static const char *qemudDefaultMachineForArch(const char *arch) {
    int i;

    for (i = 0 ; i < (int)(sizeof(archs) / sizeof(struct qemu_arch_info)) ; i++) {
        if (!strcmp(archs[i].arch, arch)) {
            return archs[i].machines[0];
        }
    }

    return NULL;
}

/* Return the default binary name for a particular architecture */
static const char *qemudDefaultBinaryForArch(const char *arch) {
    int i;

    for (i = 0 ; i < (int)(sizeof(archs) / sizeof(struct qemu_arch_info)) ; i++) {
        if (!strcmp(archs[i].arch, arch)) {
            return archs[i].binary;
        }
    }

    return NULL;
}

/* Find the fully qualified path to the binary for an architecture */
static char *qemudLocateBinaryForArch(struct qemud_server *server,
                                      int virtType, const char *arch) {
    const char *name;
    char *path;

    if (virtType == QEMUD_VIRT_KVM)
        name = "qemu-kvm";
    else
        name = qemudDefaultBinaryForArch(arch);

    if (!name) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "cannot determin binary for architecture %s", arch);
        return NULL;
    }

    /* XXX lame. should actually use $PATH ... */
    path = malloc(strlen(name) + strlen("/usr/bin/") + 1);
    if (!path) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "path");
        return NULL;
    }
    strcpy(path, "/usr/bin/");
    strcat(path, name);
    return path;
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
        if (close(STDIN_FILENO) < 0)
            goto cleanup1;
        if (close(STDERR_FILENO) < 0)
            goto cleanup1;
        if (close(newstdout[0]) < 0)
            goto cleanup1;
        if (dup2(newstdout[1], STDOUT_FILENO) < 0)
            goto cleanup1;

        /* Just in case QEMU is translated someday.. */
        setenv("LANG", "C", 1);
        execl(qemu, qemu, (char*)NULL);

    cleanup1:
        _exit(-1); /* Just in case */
    } else { /* Parent */
        char help[4096]; /* Ought to be enough to hold QEMU help screen */
        int got, ret = -1;
        int major, minor, micro;

        if (close(newstdout[1]) < 0)
            goto cleanup2;

    reread:
        if ((got = read(newstdout[0], help, sizeof(help)-1)) < 0) {
            if (errno == EINTR)
                goto reread;
            goto cleanup2;
        }
        help[got] = '\0';

        if (sscanf(help, "QEMU PC emulator version %d.%d.%d", &major,&minor, &micro) != 3) {
            goto cleanup2;
        }

        *version = (major * 1000 * 1000) + (minor * 1000) + micro;
        if (strstr(help, "-no-kqemu"))
            *flags |= QEMUD_CMD_FLAG_KQEMU;
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
            qemudLog(QEMUD_ERR, "Unexpected exit status from qemu %d pid %lu", got, (unsigned long)child);
            ret = -1;
        }
        /* Check & log unexpected exit status, but don't fail,
         * as there's really no need to throw an error if we did
         * actually read a valid version number above */
        if (WEXITSTATUS(got) != 1) {
            qemudLog(QEMUD_WARN, "Unexpected exit status '%d', qemu probably failed", got);
        }

        return ret;
    }
}

int qemudExtractVersion(struct qemud_server *server) {
    char *binary = NULL;

    if (server->qemuVersion > 0)
        return 0;

    if (!(binary = qemudLocateBinaryForArch(server, QEMUD_VIRT_QEMU, "i686")))
        return -1;

    if (qemudExtractVersionInfo(binary, &server->qemuVersion, &server->qemuCmdFlags) < 0) {
        free(binary);
        return -1;
    }

    free(binary);
    return 0;
}


/* Parse the XML definition for a disk */
static struct qemud_vm_disk_def *qemudParseDiskXML(struct qemud_server *server,
                                                   xmlNodePtr node) {
    struct qemud_vm_disk_def *disk = calloc(1, sizeof(struct qemud_vm_disk_def));
    xmlNodePtr cur;
    xmlChar *device = NULL;
    xmlChar *source = NULL;
    xmlChar *target = NULL;
    xmlChar *type = NULL;
    int typ = 0;

    if (!disk) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "disk");
        return NULL;
    }

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
            } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
                disk->readonly = 1;
            }
        }
        cur = cur->next;
    }

    if (source == NULL) {
        qemudReportError(server, VIR_ERR_NO_SOURCE, target ? "%s" : NULL, target);
        goto error;
    }
    if (target == NULL) {
        qemudReportError(server, VIR_ERR_NO_TARGET, source ? "%s" : NULL, source);
        goto error;
    }

    if (device &&
        !strcmp((const char *)device, "floppy") &&
        strcmp((const char *)target, "fda") &&
        strcmp((const char *)target, "fdb")) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "Invalid floppy device name: %s", target);
        goto error;
    }
  
    if (device &&
        !strcmp((const char *)device, "cdrom") &&
        strcmp((const char *)target, "hdc")) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "Invalid cdrom device name: %s", target);
        goto error;
    }

    if (device &&
        !strcmp((const char *)device, "cdrom"))
        disk->readonly = 1;

    if ((!device || !strcmp((const char *)device, "disk")) &&
        strcmp((const char *)target, "hda") &&
        strcmp((const char *)target, "hdb") &&
        strcmp((const char *)target, "hdc") &&
        strcmp((const char *)target, "hdd")) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "Invalid harddisk device name: %s", target);
        goto error;
    }

    strncpy(disk->src, (const char *)source, NAME_MAX-1);
    disk->src[NAME_MAX-1] = '\0';

    strncpy(disk->dst, (const char *)target, NAME_MAX-1);
    disk->dst[NAME_MAX-1] = '\0';
    disk->type = typ;

    if (!device)
        disk->device = QEMUD_DISK_DISK;
    else if (!strcmp((const char *)device, "disk"))
        disk->device = QEMUD_DISK_DISK;
    else if (!strcmp((const char *)device, "cdrom"))
        disk->device = QEMUD_DISK_CDROM;
    else if (!strcmp((const char *)device, "floppy"))
        disk->device = QEMUD_DISK_FLOPPY;
    else {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "Invalid device type: %s", device);
        goto error;
    }

    xmlFree(device);
    xmlFree(target);
    xmlFree(source);

    return disk;

 error:
    if (type)
        xmlFree(type);
    if (target)
        xmlFree(target);
    if (source)
        xmlFree(source);
    if (device)
        xmlFree(device);
    free(disk);
    return NULL;
}


/* Parse the XML definition for a network interface */
static struct qemud_vm_net_def *qemudParseInterfaceXML(struct qemud_server *server,
                                                       xmlNodePtr node) {
    struct qemud_vm_net_def *net = calloc(1, sizeof(struct qemud_vm_net_def));
    xmlNodePtr cur;
    xmlChar *macaddr = NULL;
    xmlChar *type = NULL;
    xmlChar *network = NULL;
    xmlChar *tapifname = NULL;

    if (!net) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "net");
        return NULL;
    }

    net->type = QEMUD_NET_USER;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
        if (xmlStrEqual(type, BAD_CAST "user"))
            net->type = QEMUD_NET_USER;
        else if (xmlStrEqual(type, BAD_CAST "tap"))
            net->type = QEMUD_NET_TAP;
        else if (xmlStrEqual(type, BAD_CAST "server"))
            net->type = QEMUD_NET_SERVER;
        else if (xmlStrEqual(type, BAD_CAST "client"))
            net->type = QEMUD_NET_CLIENT;
        else if (xmlStrEqual(type, BAD_CAST "mcast"))
            net->type = QEMUD_NET_MCAST;
        else if (xmlStrEqual(type, BAD_CAST "network"))
            net->type = QEMUD_NET_NETWORK;
        /*
        else if (xmlStrEqual(type, BAD_CAST "vde"))
          typ = QEMUD_NET_VDE;
        */
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
            } else if ((tapifname == NULL) &&
                       (net->type == QEMUD_NET_NETWORK) &&
                       xmlStrEqual(cur->name, BAD_CAST "tap")) {
                tapifname = xmlGetProp(cur, BAD_CAST "ifname");
            }
        }
        cur = cur->next;
    }

    net->vlan = 0;

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
    }

    if (net->type == QEMUD_NET_NETWORK) {
        int len;

        if (network == NULL) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "No <source> 'network' attribute specified with <interface type='network'/>");
            goto error;
        } else if ((len = xmlStrlen(network)) >= QEMUD_MAX_NAME_LEN) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "Network name '%s' too long", network);
            goto error;
        } else {
            strncpy(net->dst.network.name, (char *)network, len);
            net->dst.network.name[len] = '\0';
        }

        if (network)
            xmlFree(network);

        if (tapifname != NULL) {
            if ((len == xmlStrlen(tapifname)) >= BR_IFNAME_MAXLEN) {
                qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                                 "TAP interface name '%s' is too long", tapifname);
                goto error;
            } else {
                strncpy(net->dst.network.tapifname, (char *)tapifname, len);
                net->dst.network.tapifname[len] = '\0';
            }
            xmlFree(tapifname);
        }
    }

    return net;

 error:
    if (network)
        xmlFree(network);
    if (tapifname)
        xmlFree(tapifname);
    free(net);
    return NULL;
}


/*
 * Parses a libvirt XML definition of a guest, and populates the
 * the qemud_vm struct with matching data about the guests config
 */
static struct qemud_vm_def *qemudParseXML(struct qemud_server *server,
                                          xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlChar *prop = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    char *conv = NULL;
    int i;
    struct qemud_vm_def *def;

    if (!(def = calloc(1, sizeof(struct qemud_vm_def)))) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "xmlXPathContext");
        return NULL;
    }

    /* Prepare parser / xpath context */
    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "domain"))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "incorrect root element");
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "xmlXPathContext");
        goto error;
    }


    /* Find out what type of QEMU virtualization to use */
    if (!(prop = xmlGetProp(root, BAD_CAST "type"))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "missing domain type attribute");
        goto error;
    }

    if (!strcmp((char *)prop, "qemu"))
        def->virtType = QEMUD_VIRT_QEMU;
    else if (!strcmp((char *)prop, "kqemu"))
        def->virtType = QEMUD_VIRT_KQEMU;
    else if (!strcmp((char *)prop, "kvm"))
        def->virtType = QEMUD_VIRT_KVM;
    else {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "invalid domain type attribute");
        goto error;
    }
    free(prop);
    prop = NULL;


    /* Extract domain name */
    obj = xmlXPathEval(BAD_CAST "string(/domain/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(server, VIR_ERR_NO_NAME, NULL);
        goto error;
    }
    if (strlen((const char *)obj->stringval) >= (QEMUD_MAX_NAME_LEN-1)) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "domain name length too long");
        goto error;
    }
    strcpy(def->name, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);


    /* Extract domain uuid */
    obj = xmlXPathEval(BAD_CAST "string(/domain/uuid[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        /* XXX auto-generate a UUID */
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "missing uuid element");
        goto error;
    }
    if (qemudParseUUID((const char *)obj->stringval, def->uuid) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "malformed uuid element");
        goto error;
    }
    xmlXPathFreeObject(obj);


    /* Extract domain memory */
    obj = xmlXPathEval(BAD_CAST "string(/domain/memory[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "missing memory element");
        goto error;
    } else {
        conv = NULL;
        def->maxmem = strtoll((const char*)obj->stringval, &conv, 10);
        if (conv == (const char*)obj->stringval) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "malformed memory information");
            goto error;
        }
    }
    if (obj)
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
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "malformed memory information");
            goto error;
        }
    }
    if (obj)
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
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "malformed vcpu information");
            goto error;
        }
    }
    if (obj)
        xmlXPathFreeObject(obj);

    /* See if ACPI feature is requested */
    obj = xmlXPathEval(BAD_CAST "/domain/features/acpi", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr == 1)) {
        def->features |= QEMUD_FEATURE_ACPI;
    }
    xmlXPathFreeObject(obj);

    /* Extract OS type info */
    obj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(server, VIR_ERR_OS_TYPE, NULL);
        goto error;
    }
    if (strcmp((const char *)obj->stringval, "hvm")) {
        qemudReportError(server, VIR_ERR_OS_TYPE, "%s", obj->stringval);
        goto error;
    }
    strcpy(def->os.type, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);


    obj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1]/@arch)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        const char *defaultArch = qemudDefaultArch();
        if (strlen(defaultArch) >= (QEMUD_OS_TYPE_MAX_LEN-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "architecture type too long");
            goto error;
        }
        strcpy(def->os.arch, defaultArch);
    } else {
        if (strlen((const char *)obj->stringval) >= (QEMUD_OS_TYPE_MAX_LEN-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "architecture type too long");
            goto error;
        }
        strcpy(def->os.arch, (const char *)obj->stringval);
    }
    if (obj)
        xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/os/type[1]/@machine)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        const char *defaultMachine = qemudDefaultMachineForArch(def->os.arch);
        if (strlen(defaultMachine) >= (QEMUD_OS_MACHINE_MAX_LEN-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "machine type too long");
            goto error;
        }
        strcpy(def->os.machine, defaultMachine);
    } else {
        if (strlen((const char *)obj->stringval) >= (QEMUD_OS_MACHINE_MAX_LEN-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "architecture type too long");
            goto error;
        }
        strcpy(def->os.machine, (const char *)obj->stringval);
    }
    if (obj)
        xmlXPathFreeObject(obj);


    obj = xmlXPathEval(BAD_CAST "string(/domain/os/kernel[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "kernel path too long");
            goto error;
        }
        strcpy(def->os.kernel, (const char *)obj->stringval);
    }
    if (obj)
        xmlXPathFreeObject(obj);


    obj = xmlXPathEval(BAD_CAST "string(/domain/os/initrd[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "initrd path too long");
            goto error;
        }
        strcpy(def->os.initrd, (const char *)obj->stringval);
    }
    if (obj)
        xmlXPathFreeObject(obj);


    obj = xmlXPathEval(BAD_CAST "string(/domain/os/cmdline[1])", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "cmdline arguments too long");
            goto error;
        }
        strcpy(def->os.cmdline, (const char *)obj->stringval);
    }
    if (obj)
        xmlXPathFreeObject(obj);


    /* analysis of the disk devices */
    obj = xmlXPathEval(BAD_CAST "/domain/os/boot", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        for (i = 0; i < obj->nodesetval->nodeNr && i < QEMUD_MAX_BOOT_DEVS ; i++) {
            if (!(prop = xmlGetProp(obj->nodesetval->nodeTab[i], BAD_CAST "dev")))
                continue;
            if (!strcmp((char *)prop, "hd")) {
                def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_DISK;
            } else if (!strcmp((char *)prop, "fd")) {
                def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_FLOPPY;
            } else if (!strcmp((char *)prop, "cdrom")) {
                def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_CDROM;
            } else if (!strcmp((char *)prop, "net")) {
                def->os.bootDevs[def->os.nBootDevs++] = QEMUD_BOOT_NET;
            } else {
                xmlFree(prop);
                goto error;
            }
            xmlFree(prop);
        }
    }
    xmlXPathFreeObject(obj);
    if (def->os.nBootDevs == 0) {
        def->os.nBootDevs = 1;
        def->os.bootDevs[0] = QEMUD_BOOT_DISK;
    }


    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/emulator[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        char *tmp = qemudLocateBinaryForArch(server, def->virtType, def->os.arch);
        if (!tmp) {
            goto error;
        }
        strcpy(def->os.binary, tmp);
        free(tmp);
    } else {
        if (strlen((const char *)obj->stringval) >= (PATH_MAX-1)) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "emulator path too long");
            goto error;
        }
        strcpy(def->os.binary, (const char *)obj->stringval);
    }
    if (obj)
        xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "/domain/devices/graphics", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr == 0)) {
        def->graphicsType = QEMUD_GRAPHICS_NONE;
    } else if ((prop = xmlGetProp(obj->nodesetval->nodeTab[0], BAD_CAST "type"))) {
        if (!strcmp((char *)prop, "vnc")) {
            def->graphicsType = QEMUD_GRAPHICS_VNC;
            prop = xmlGetProp(obj->nodesetval->nodeTab[0], BAD_CAST "port");
            if (prop) {
                conv = NULL;
                def->vncPort = strtoll((const char*)prop, &conv, 10);
            } else {
                def->vncPort = -1;
            }
        } else if (!strcmp((char *)prop, "sdl")) {
            def->graphicsType = QEMUD_GRAPHICS_SDL;
        } else {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "Unsupported graphics type %s", prop);
            goto error;
        }
        xmlFree(prop);
    }
    xmlXPathFreeObject(obj);

    /* analysis of the disk devices */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/disk", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            struct qemud_vm_disk_def *disk;
            if (!(disk = qemudParseDiskXML(server, obj->nodesetval->nodeTab[i]))) {
                goto error;
            }
            def->ndisks++;
            disk->next = def->disks;
            def->disks = disk;
        }
    }
    xmlXPathFreeObject(obj);


    /* analysis of the network devices */
    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr >= 0)) {
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
            struct qemud_vm_net_def *net;
            if (!(net = qemudParseInterfaceXML(server, obj->nodesetval->nodeTab[i]))) {
                goto error;
            }
            def->nnets++;
            net->next = def->nets;
            def->nets = net;
        }
    }
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);

    return def;

 error:
    if (prop)
        free(prop);
    if (obj)
        xmlXPathFreeObject(obj);
    if (ctxt)
        xmlXPathFreeContext(ctxt);
    qemudFreeVMDef(def);
    return NULL;
}


static char *
qemudNetworkIfaceConnect(struct qemud_server *server,
                         struct qemud_vm *vm,
                         struct qemud_vm_net_def *net)
{
    struct qemud_network *network;
    const char *tapifname;
    char tapfdstr[4+3+32+7];
    char *retval = NULL;
    int err;
    int tapfd = -1;
    int *tapfds;

    if (!(network = qemudFindNetworkByName(server, net->dst.network.name))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "Network '%s' not found", net->dst.network.name);
        goto error;
    } else if (network->bridge[0] == '\0') {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "Network '%s' not active", net->dst.network.name);
        goto error;
    }

    if (net->dst.network.tapifname[0] == '\0' ||
        strchr(net->dst.network.tapifname, '%')) {
        tapifname = "vnet%d";
    } else {
        tapifname = net->dst.network.tapifname;
    }

    if ((err = brAddTap(server->brctl, network->bridge, tapifname,
                        &net->dst.network.tapifname[0], BR_IFNAME_MAXLEN, &tapfd))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "Failed to add tap interface '%s' to bridge '%s' : %s",
                         tapifname, network->bridge, strerror(err));
        goto error;
    }

    if ((err = iptablesAddPhysdevForward(server->iptables, net->dst.network.tapifname))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "Failed to add iptables rule to allow bridging from '%s' :%s",
                         net->dst.network.tapifname, strerror(err));
        goto error;
    }

    snprintf(tapfdstr, sizeof(tapfdstr), "tap,fd=%d,script=", tapfd);

    if (!(retval = strdup(tapfdstr)))
        goto no_memory;

    if (!(tapfds = realloc(vm->tapfds, sizeof(int) * (vm->ntapfds+2))))
        goto no_memory;

    vm->tapfds = tapfds;
    vm->tapfds[vm->ntapfds++] = tapfd;
    vm->tapfds[vm->ntapfds]   = -1;

    return retval;

 no_memory:
    iptablesRemovePhysdevForward(server->iptables, net->dst.network.tapifname);
    qemudReportError(server, VIR_ERR_NO_MEMORY, "tapfds");
 error:
    if (retval)
        free(retval);
    if (tapfd != -1)
        close(tapfd);
    return NULL;
}

/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 */
int qemudBuildCommandLine(struct qemud_server *server,
                          struct qemud_vm *vm,
                          char ***argv) {
    int len, n = -1, i;
    char memory[50];
    char vcpus[50];
    char boot[QEMUD_MAX_BOOT_DEVS+1];
    struct qemud_vm_disk_def *disk = vm->def->disks;
    struct qemud_vm_net_def *net = vm->def->nets;

    if (qemudExtractVersion(server) < 0)
        return -1;

    len = 1 + /* qemu */
        2 + /* machine type */
        (((server->qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU) &&
          (vm->def->virtType == QEMUD_VIRT_QEMU)) ? 1 : 0) + /* Disable kqemu */
        2 * vm->def->ndisks + /* disks*/
        (vm->def->nnets > 0 ? (4 * vm->def->nnets) : 2) + /* networks */
        2 + /* memory*/
        2 + /* cpus */
        2 + /* boot device */
        2 + /* monitor */
        (vm->def->features & QEMUD_FEATURE_ACPI ? 0 : 1) + /* acpi */
        (vm->def->os.kernel[0] ? 2 : 0) + /* kernel */
        (vm->def->os.initrd[0] ? 2 : 0) + /* initrd */
        (vm->def->os.cmdline[0] ? 2 : 0) + /* cmdline */
        (vm->def->graphicsType == QEMUD_GRAPHICS_VNC ? 2 :
         (vm->def->graphicsType == QEMUD_GRAPHICS_SDL ? 0 : 1)); /* graphics */

    sprintf(memory, "%d", vm->def->memory/1024);
    sprintf(vcpus, "%d", vm->def->vcpus);

    if (!(*argv = malloc(sizeof(char *) * (len+1))))
        goto no_memory;
    if (!((*argv)[++n] = strdup(vm->def->os.binary)))
        goto no_memory;
    if (!((*argv)[++n] = strdup("-M")))
        goto no_memory;
    if (!((*argv)[++n] = strdup(vm->def->os.machine)))
        goto no_memory;
    if ((server->qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU) && 
        (vm->def->virtType == QEMUD_VIRT_QEMU)) {
        if (!((*argv)[++n] = strdup("-no-kqemu")))
            goto no_memory;
    }
    if (!((*argv)[++n] = strdup("-m")))
        goto no_memory;
    if (!((*argv)[++n] = strdup(memory)))
        goto no_memory;
    if (!((*argv)[++n] = strdup("-smp")))
        goto no_memory;
    if (!((*argv)[++n] = strdup(vcpus)))
        goto no_memory;

    if (!((*argv)[++n] = strdup("-monitor")))
        goto no_memory;
    if (!((*argv)[++n] = strdup("pty")))
        goto no_memory;

    if (!(vm->def->features & QEMUD_FEATURE_ACPI)) {
        if (!((*argv)[++n] = strdup("-no-acpi")))
            goto no_memory;
    }

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
    if (!((*argv)[++n] = strdup("-boot")))
        goto no_memory;
    if (!((*argv)[++n] = strdup(boot)))
        goto no_memory;

    if (vm->def->os.kernel[0]) {
        if (!((*argv)[++n] = strdup("-kernel")))
            goto no_memory;
        if (!((*argv)[++n] = strdup(vm->def->os.kernel)))
            goto no_memory;
    }
    if (vm->def->os.initrd[0]) {
        if (!((*argv)[++n] = strdup("-initrd")))
            goto no_memory;
        if (!((*argv)[++n] = strdup(vm->def->os.initrd)))
            goto no_memory;
    }
    if (vm->def->os.cmdline[0]) {
        if (!((*argv)[++n] = strdup("-append")))
            goto no_memory;
        if (!((*argv)[++n] = strdup(vm->def->os.cmdline)))
            goto no_memory;
    }

    while (disk) {
        char dev[NAME_MAX];
        char file[PATH_MAX];
        if (!strcmp(disk->dst, "hdc") &&
            disk->device == QEMUD_DISK_CDROM)
            snprintf(dev, NAME_MAX, "-%s", "cdrom");
        else
            snprintf(dev, NAME_MAX, "-%s", disk->dst);
        snprintf(file, PATH_MAX, "%s", disk->src);

        if (!((*argv)[++n] = strdup(dev)))
            goto no_memory;
        if (!((*argv)[++n] = strdup(file)))
            goto no_memory;

        disk = disk->next;
    }

    if (!net) {
        if (!((*argv)[++n] = strdup("-net")))
            goto no_memory;
        if (!((*argv)[++n] = strdup("none")))
            goto no_memory;
    } else {
        while (net) {
            char nic[3+1+7+1+17+1];

            if (!net->mac[0] && !net->mac[1] && !net->mac[2] &&
                !net->mac[3] && !net->mac[4] && !net->mac[5]) {
                strncpy(nic, "nic", 4);
            } else {
                sprintf(nic, "nic,macaddr=%02x:%02x:%02x:%02x:%02x:%02x",
                        net->mac[0], net->mac[1],
                        net->mac[2], net->mac[3],
                        net->mac[4], net->mac[5]);
            }

            if (!((*argv)[++n] = strdup("-net")))
                goto no_memory;
            if (!((*argv)[++n] = strdup(nic)))
                goto no_memory;
            if (!((*argv)[++n] = strdup("-net")))
                goto no_memory;

            if (net->type != QEMUD_NET_NETWORK) {
                /* XXX don't hardcode user */
                if (!((*argv)[++n] = strdup("user")))
                    goto no_memory;
            } else {
                if (!((*argv)[++n] = qemudNetworkIfaceConnect(server, vm, net)))
                    goto error;
            }

            net = net->next;
        }
    }

    if (vm->def->graphicsType == QEMUD_GRAPHICS_VNC) {
        char port[10];
        int ret;
        ret = snprintf(port, sizeof(port),
                       ((server->qemuCmdFlags & QEMUD_CMD_FLAG_VNC_COLON) ?
                        ":%d" : "%d"),
                       vm->def->vncActivePort - 5900);
        if (ret < 0 || ret >= (int)sizeof(port))
            goto error;

        if (!((*argv)[++n] = strdup("-vnc")))
            goto no_memory;
        if (!((*argv)[++n] = strdup(port)))
            goto no_memory;
    } else if (vm->def->graphicsType == QEMUD_GRAPHICS_NONE) {
        if (!((*argv)[++n] = strdup("-nographic")))
            goto no_memory;
    } else {
        /* SDL is the default. no args needed */
    }

    (*argv)[++n] = NULL;

    return 0;

 no_memory:
    qemudReportError(server, VIR_ERR_NO_MEMORY, "argv");
 error:
    if (vm->tapfds) {
        for (i = 0; vm->tapfds[i] != -1; i++)
            close(vm->tapfds[i]);
        free(vm->tapfds);
        vm->tapfds = NULL;
        vm->ntapfds = 0;
    }
    if (argv) {
        for (i = 0 ; i < n ; i++)
            free((*argv)[i]);
        free(*argv);
    }
    return -1;
}


/* Save a guest's config data into a persistent file */
static int qemudSaveConfig(struct qemud_server *server,
                           struct qemud_vm *vm,
                           struct qemud_vm_def *def) {
    char *xml;
    int fd = -1, ret = -1;
    int towrite;

    if (!(xml = qemudGenerateXML(server, vm, def, 0)))
        return -1;

    if ((fd = open(vm->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot create config file %s: %s",
                         vm->configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (write(fd, xml, towrite) != towrite) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot write config file %s: %s",
                         vm->configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot save config file %s: %s",
                         vm->configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (fd != -1)
        close(fd);

    free(xml);

    return ret;
}

struct qemud_vm_def *
qemudParseVMDef(struct qemud_server *server,
                const char *xmlStr,
                const char *displayName) {
    xmlDocPtr xml;
    struct qemud_vm_def *def = NULL;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, displayName ? displayName : "domain.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        qemudReportError(server, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    def = qemudParseXML(server, xml);

    xmlFreeDoc(xml);

    return def;
}

struct qemud_vm *
qemudAssignVMDef(struct qemud_server *server,
                 struct qemud_vm_def *def)
{
    struct qemud_vm *vm = NULL;

    if ((vm = qemudFindVMByName(server, def->name))) {
        if (!qemudIsActiveVM(vm)) {
            qemudFreeVMDef(vm->def);
            vm->def = def;
        } else {
            if (vm->newDef)
                qemudFreeVMDef(vm->newDef);
            vm->newDef = def;
        }

        return vm;
    }

    if (!(vm = calloc(1, sizeof(struct qemud_vm)))) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "vm");
        return NULL;
    }

    vm->stdout = -1;
    vm->stderr = -1;
    vm->monitor = -1;
    vm->pid = -1;
    vm->id = -1;
    vm->def = def;
    vm->next = server->vms;

    server->vms = vm;
    server->ninactivevms++;

    return vm;
}

void
qemudRemoveInactiveVM(struct qemud_server *server,
                      struct qemud_vm *vm)
{
    struct qemud_vm *prev = NULL, *curr;

    curr = server->vms;
    while (curr != vm) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            server->vms = curr->next;

        server->ninactivevms--;
    }

    qemudFreeVM(vm);
}

int
qemudSaveVMDef(struct qemud_server *server,
               struct qemud_vm *vm,
               struct qemud_vm_def *def) {
    if (vm->configFile[0] == '\0') {
        int err;

        if ((err = qemudEnsureDir(server->configDir))) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot create config directory %s: %s",
                             server->configDir, strerror(err));
            return -1;
        }

        if (qemudMakeConfigPath(server->configDir, def->name, ".xml",
                                vm->configFile, PATH_MAX) < 0) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot construct config file path");
            return -1;
        }

        if (qemudMakeConfigPath(server->autostartDir, def->name, ".xml",
                                vm->autostartLink, PATH_MAX) < 0) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot construct autostart link path");
            vm->configFile[0] = '\0';
            return -1;
        }
    }

    return qemudSaveConfig(server, vm, def);
}

static int qemudSaveNetworkConfig(struct qemud_server *server,
                                  struct qemud_network *network,
                                  struct qemud_network_def *def) {
    char *xml;
    int fd, ret = -1;
    int towrite;
    int err;

    if (!(xml = qemudGenerateNetworkXML(server, network, def))) {
        return -1;
    }

    if ((err = qemudEnsureDir(server->networkConfigDir))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot create config directory %s: %s",
                         server->networkConfigDir, strerror(err));
        goto cleanup;
    }

    if ((fd = open(network->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot create config file %s: %s",
                         network->configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (write(fd, xml, towrite) != towrite) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot write config file %s",
                         network->configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                         "cannot save config file %s",
                         network->configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:

    free(xml);

    return ret;
}

void qemudFreeNetworkDef(struct qemud_network_def *def) {
    struct qemud_dhcp_range_def *range = def->ranges;
    while (range) {
        struct qemud_dhcp_range_def *next = range->next;
        free(range);
        range = next;
    }
    free(def);
}

void qemudFreeNetwork(struct qemud_network *network) {
    qemudFreeNetworkDef(network->def);
    if (network->newDef)
        qemudFreeNetworkDef(network->newDef);
    free(network);
}

static int qemudParseBridgeXML(struct qemud_server *server ATTRIBUTE_UNUSED,
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

static int qemudParseDhcpRangesXML(struct qemud_server *server,
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

        if (!(range = calloc(1, sizeof(struct qemud_dhcp_range_def)))) {
            qemudReportError(server, VIR_ERR_NO_MEMORY, "range");
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
            free(range);
        }

        if (start)
            xmlFree(start);
        if (end)
            xmlFree(end);

        cur = cur->next;
    }

    return 1;
}

static int qemudParseInetXML(struct qemud_server *server ATTRIBUTE_UNUSED,
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

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "dhcp") &&
            !qemudParseDhcpRangesXML(server, def, cur))
            return 0;
        cur = cur->next;
    }

    return 1;
}


static struct qemud_network_def *qemudParseNetworkXML(struct qemud_server *server,
                                                      xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    struct qemud_network_def *def;

    if (!(def = calloc(1, sizeof(struct qemud_network_def)))) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "network_def");
        return NULL;
    }

    /* Prepare parser / xpath context */
    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "network"))) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "incorrect root element");
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "xmlXPathContext");
        goto error;
    }


    /* Extract network name */
    obj = xmlXPathEval(BAD_CAST "string(/network/name[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        qemudReportError(server, VIR_ERR_NO_NAME, NULL);
        goto error;
    }
    if (strlen((const char *)obj->stringval) >= (QEMUD_MAX_NAME_LEN-1)) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "network name length too long");
        goto error;
    }
    strcpy(def->name, (const char *)obj->stringval);
    xmlXPathFreeObject(obj);


    /* Extract network uuid */
    obj = xmlXPathEval(BAD_CAST "string(/network/uuid[1])", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        /* XXX auto-generate a UUID */
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "missing uuid element");
        goto error;
    }
    if (qemudParseUUID((const char *)obj->stringval, def->uuid) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "%s", "malformed uuid element");
        goto error;
    }
    xmlXPathFreeObject(obj);

    /* Parse bridge information */
    obj = xmlXPathEval(BAD_CAST "/network/bridge[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
        if (!qemudParseBridgeXML(server, def, obj->nodesetval->nodeTab[0])) {
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    /* Parse IP information */
    obj = xmlXPathEval(BAD_CAST "/network/ip[1]", ctxt);
    if ((obj != NULL) && (obj->type == XPATH_NODESET) &&
        (obj->nodesetval != NULL) && (obj->nodesetval->nodeNr > 0)) {
        if (!qemudParseInetXML(server, def, obj->nodesetval->nodeTab[0])) {
            goto error;
        }
    }
    xmlXPathFreeObject(obj);

    xmlXPathFreeContext(ctxt);

    return def;

 error:
    /* XXX free all the stuff in the qemud_network struct, or leave it upto
       the caller ? */
    if (obj)
        xmlXPathFreeObject(obj);
    if (ctxt)
        xmlXPathFreeContext(ctxt);
    qemudFreeNetworkDef(def);
    return NULL;
}

struct qemud_network_def *
qemudParseNetworkDef(struct qemud_server *server,
                     const char *xmlStr,
                     const char *displayName) {
    xmlDocPtr xml;
    struct qemud_network_def *def;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, displayName ? displayName : "network.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        qemudReportError(server, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    def = qemudParseNetworkXML(server, xml);

    xmlFreeDoc(xml);

    return def;
}

struct qemud_network *
qemudAssignNetworkDef(struct qemud_server *server,
                      struct qemud_network_def *def) {
    struct qemud_network *network;

    if ((network = qemudFindNetworkByName(server, def->name))) {
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

    if (!(network = calloc(1, sizeof(struct qemud_network)))) {
        qemudReportError(server, VIR_ERR_NO_MEMORY, "network");
        return NULL;
    }

    network->def = def;
    network->next = server->networks;

    server->networks = network;
    server->ninactivenetworks++;

    return network;
}

void
qemudRemoveInactiveNetwork(struct qemud_server *server,
                           struct qemud_network *network)
{
    struct qemud_network *prev = NULL, *curr;

    curr = server->networks;
    while (curr != network) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            server->networks = curr->next;

        server->ninactivenetworks--;
    }

    qemudFreeNetwork(network);
}

int
qemudSaveNetworkDef(struct qemud_server *server,
                    struct qemud_network *network,
                    struct qemud_network_def *def) {

    if (network->configFile[0] == '\0') {
        int err;

        if ((err = qemudEnsureDir(server->networkConfigDir))) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot create config directory %s: %s",
                             server->networkConfigDir, strerror(err));
            return -1;
        }

        if (qemudMakeConfigPath(server->networkConfigDir, def->name, ".xml",
                                network->configFile, PATH_MAX) < 0) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot construct config file path");
            return -1;
        }

        if (qemudMakeConfigPath(server->networkAutostartDir, def->name, ".xml",
                                network->autostartLink, PATH_MAX) < 0) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot construct autostart link path");
            network->configFile[0] = '\0';
            return -1;
        }
    }

    return qemudSaveNetworkConfig(server, network, def);
}

static int
qemudReadFile(const char *path,
              char *buf,
              int maxlen) {
    FILE *fh;
    struct stat st;
    int ret = 0;

    if (!(fh = fopen(path, "r"))) {
        qemudLog(QEMUD_WARN, "Failed to open file '%s': %s",
                 path, strerror(errno));
        goto error;
    }

    if (fstat(fileno(fh), &st) < 0) {
        qemudLog(QEMUD_WARN, "Failed to stat file '%s': %s",
                 path, strerror(errno));
        goto error;
    }

    if (S_ISDIR(st.st_mode)) {
        qemudDebug("Ignoring directory '%s' - clearly not a config file", path);
        goto error;
    }

    if (st.st_size >= maxlen) {
        qemudLog(QEMUD_WARN, "File '%s' is too large", path);
        goto error;
    }

    if ((ret = fread(buf, st.st_size, 1, fh)) != 1) {
        qemudLog(QEMUD_WARN, "Failed to read config file '%s': %s",
                 path, strerror(errno));
        goto error;
    }

    buf[st.st_size] = '\0';

    ret = 1;

 error:
    if (fh)
        fclose(fh);

    return ret;
}

static int
compareFileToNameSuffix(const char *file,
                        const char *name,
                        const char *suffix) {
    int filelen = strlen(file);
    int namelen = strlen(name);
    int suffixlen = strlen(suffix);

    if (filelen == (namelen + suffixlen) &&
        !strncmp(file, name, namelen) &&
        !strncmp(file + namelen, suffix, suffixlen))
        return 1;
    else
        return 0;
}

static int
hasSuffix(const char *str,
          const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return 0;

    return strcmp(str + len - suffixlen, suffix) == 0;
}

static int
checkLinkPointsTo(const char *checkLink,
                  const char *checkDest)
{
    char dest[PATH_MAX];
    char real[PATH_MAX];
    char checkReal[PATH_MAX];
    int n;
    int passed = 0;

    /* read the link destination */
    if ((n = readlink(checkLink, dest, PATH_MAX)) < 0) {
        switch (errno) {
        case ENOENT:
        case ENOTDIR:
            break;

        case EINVAL:
            qemudLog(QEMUD_WARN, "Autostart file '%s' is not a symlink",
                     checkLink);
            break;

        default:
            qemudLog(QEMUD_WARN, "Failed to read autostart symlink '%s': %s",
                     checkLink, strerror(errno));
            break;
        }

        goto failed;
    } else if (n >= PATH_MAX) {
        qemudLog(QEMUD_WARN, "Symlink '%s' contents too long to fit in buffer",
                 checkLink);
        goto failed;
    }

    dest[n] = '\0';

    /* make absolute */
    if (dest[0] != '/') {
        char dir[PATH_MAX];
        char tmp[PATH_MAX];
        char *p;

        strncpy(dir, checkLink, PATH_MAX);
        dir[PATH_MAX] = '\0';

        if (!(p = strrchr(dir, '/'))) {
            qemudLog(QEMUD_WARN, "Symlink path '%s' is not absolute", checkLink);
            goto failed;
        }

        if (p == dir) /* handle unlikely root dir case */
            p++;

        *p = '\0';

        if (qemudMakeConfigPath(dir, dest, NULL, tmp, PATH_MAX) < 0) {
            qemudLog(QEMUD_WARN, "Path '%s/%s' is too long", dir, dest);
            goto failed;
        }

        strncpy(dest, tmp, PATH_MAX);
        dest[PATH_MAX] = '\0';
    }

    /* canonicalize both paths */
    if (!realpath(dest, real)) {
        qemudLog(QEMUD_WARN, "Failed to expand path '%s' :%s",
                 dest, strerror(errno));
        strncpy(real, dest, PATH_MAX);
        real[PATH_MAX] = '\0';
    }

    if (!realpath(checkDest, checkReal)) {
        qemudLog(QEMUD_WARN, "Failed to expand path '%s' :%s",
                 checkDest, strerror(errno));
        strncpy(checkReal, checkDest, PATH_MAX);
        checkReal[PATH_MAX] = '\0';
    }

    /* compare */
    if (strcmp(checkReal, real) != 0) {
        qemudLog(QEMUD_WARN, "Autostart link '%s' is not a symlink to '%s', ignoring",
                 checkLink, checkReal);
        goto failed;
    }

    passed = 1;

 failed:
    return passed;
}

static struct qemud_vm *
qemudLoadConfig(struct qemud_server *server,
                const char *file,
                const char *path,
                const char *xml,
                const char *autostartLink) {
    struct qemud_vm_def *def;
    struct qemud_vm *vm;

    if (!(def = qemudParseVMDef(server, xml, file))) {
        qemudLog(QEMUD_WARN, "Error parsing QEMU guest config '%s' : %s",
                 path, server->errorMessage);
        return NULL;
    }

    if (!compareFileToNameSuffix(file, def->name, ".xml")) {
        qemudLog(QEMUD_WARN, "QEMU guest config filename '%s' does not match guest name '%s'",
                 path, def->name);
        qemudFreeVMDef(def);
        return NULL;
    }

    if (!(vm = qemudAssignVMDef(server, def))) {
        qemudLog(QEMUD_WARN, "Failed to load QEMU guest config '%s': out of memory", path);
        qemudFreeVMDef(def);
        return NULL;
    }

    strncpy(vm->configFile, path, PATH_MAX);
    vm->configFile[PATH_MAX-1] = '\0';

    strncpy(vm->autostartLink, autostartLink, PATH_MAX);
    vm->autostartLink[PATH_MAX-1] = '\0';

    vm->autostart = checkLinkPointsTo(vm->autostartLink, vm->configFile);

    return vm;
}

static struct qemud_network *
qemudLoadNetworkConfig(struct qemud_server *server,
                       const char *file,
                       const char *path,
                       const char *xml,
                       const char *autostartLink) {
    struct qemud_network_def *def;
    struct qemud_network *network;

    if (!(def = qemudParseNetworkDef(server, xml, file))) {
        qemudLog(QEMUD_WARN, "Error parsing network config '%s' : %s",
                 path, server->errorMessage);
        return NULL;
    }

    if (!compareFileToNameSuffix(file, def->name, ".xml")) {
        qemudLog(QEMUD_WARN, "Network config filename '%s' does not match network name '%s'",
                 path, def->name);
        qemudFreeNetworkDef(def);
        return NULL;
    }

    if (!(network = qemudAssignNetworkDef(server, def))) {
        qemudLog(QEMUD_WARN, "Failed to load network config '%s': out of memory", path);
        qemudFreeNetworkDef(def);
        return NULL;
    }

    strncpy(network->configFile, path, PATH_MAX);
    network->configFile[PATH_MAX-1] = '\0';

    strncpy(network->autostartLink, autostartLink, PATH_MAX);
    network->autostartLink[PATH_MAX-1] = '\0';

    network->autostart = checkLinkPointsTo(network->autostartLink, network->configFile);

    return network;
}

static
int qemudScanConfigDir(struct qemud_server *server,
                       const char *configDir,
                       const char *autostartDir,
                       int isGuest) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        qemudLog(QEMUD_ERR, "Failed to open dir '%s': %s",
                 configDir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir))) {
        char xml[QEMUD_MAX_XML_LEN];
        char path[PATH_MAX];
        char autostartLink[PATH_MAX];

        if (entry->d_name[0] == '.')
            continue;

        if (!hasSuffix(entry->d_name, ".xml"))
            continue;

        if (qemudMakeConfigPath(configDir, entry->d_name, NULL, path, PATH_MAX) < 0) {
            qemudLog(QEMUD_WARN, "Config filename '%s/%s' is too long",
                     configDir, entry->d_name);
            continue;
        }

        if (qemudMakeConfigPath(autostartDir, entry->d_name, NULL, autostartLink, PATH_MAX) < 0) {
            qemudLog(QEMUD_WARN, "Autostart link path '%s/%s' is too long",
                     autostartDir, entry->d_name);
            continue;
        }

        if (!qemudReadFile(path, xml, QEMUD_MAX_XML_LEN))
            continue;

        if (isGuest)
            qemudLoadConfig(server, entry->d_name, path, xml, autostartLink);
        else
            qemudLoadNetworkConfig(server, entry->d_name, path, xml, autostartLink);
    }

    closedir(dir);
 
    return 0;
}

static
void qemudAutostartConfigs(struct qemud_server *server) {
    struct qemud_network *network;
    struct qemud_vm *vm;

    network = server->networks;
    while (network != NULL) {
        struct qemud_network *next = network->next;

        if (network->autostart &&
            !qemudIsActiveNetwork(network) &&
            qemudStartNetworkDaemon(server, network) < 0)
            qemudLog(QEMUD_ERR, "Failed to autostart network '%s'",
                     network->def->name);

        network = next;
    }

    vm = server->vms;
    while (vm != NULL) {
        struct qemud_vm *next = vm->next;

        if (vm->autostart &&
            !qemudIsActiveVM(vm) &&
            qemudStartVMDaemon(server, vm) < 0)
            qemudLog(QEMUD_ERR, "Failed to autostart VM '%s'",
                     vm->def->name);

        vm = next;
    }
}

/* Scan for all guest and network config files */
int qemudScanConfigs(struct qemud_server *server) {
    if (qemudScanConfigDir(server, server->configDir, server->autostartDir, 1) < 0)
        return -1;

    if (qemudScanConfigDir(server, server->networkConfigDir, server->networkAutostartDir, 0) < 0)
        return -1;

    qemudAutostartConfigs(server);

    return 0;
}

/* Simple grow-on-demand string buffer */
/* XXX re-factor to shared library */
struct qemudBuffer {
    char *data;
    int len;
    int used;
};

static
int qemudBufferAdd(struct qemudBuffer *buf, const char *str) {
    int need = strlen(str);
  
    if ((need+1) > (buf->len-buf->used)) {
        return -1;
    }
  
    memcpy(buf->data + buf->used, str, need+1);
    buf->used += need;

    return 0;
}


static
int qemudBufferPrintf(struct qemudBuffer *buf,
                      const char *format, ...) {
    int size, count;
    va_list locarg, argptr;

    if ((format == NULL) || (buf == NULL)) {
        return -1;
    }
    size = buf->len - buf->used - 1;
    va_start(argptr, format);
    va_copy(locarg, argptr);

    if ((count = vsnprintf(&buf->data[buf->used],
                           size,
                           format,
                           locarg)) >= size) {
        return -1;
    }
    va_end(locarg);
    buf->used += count;

    buf->data[buf->used] = '\0';
    return 0;
}

/* Generate an XML document describing the guest's configuration */
char *qemudGenerateXML(struct qemud_server *server,
                       struct qemud_vm *vm,
                       struct qemud_vm_def *def,
                       int live) {
    struct qemudBuffer buf;
    unsigned char *uuid;
    struct qemud_vm_disk_def *disk;
    struct qemud_vm_net_def *net;
    const char *type = NULL;
    int n;

    buf.len = QEMUD_MAX_XML_LEN;
    buf.used = 0;
    buf.data = malloc(buf.len);

    if (!buf.data)
        goto no_memory;

    switch (def->virtType) {
    case QEMUD_VIRT_QEMU:
        type = "qemu";
        break;
    case QEMUD_VIRT_KQEMU:
        type = "kqemu";
        break;
    case QEMUD_VIRT_KVM:
        type = "kvm";
        break;
    }
    if (!type) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "unexpected domain type %d", def->virtType);
        goto cleanup;
    }

    if (qemudIsActiveVM(vm) && live) {
        if (qemudBufferPrintf(&buf, "<domain type='%s' id='%d'>\n", type, vm->id) < 0)
            goto no_memory;
    } else {
        if (qemudBufferPrintf(&buf, "<domain type='%s'>\n", type) < 0)
            goto no_memory;
    }

    if (qemudBufferPrintf(&buf, "  <name>%s</name>\n", def->name) < 0)
        goto no_memory;

    uuid = def->uuid;
    if (qemudBufferPrintf(&buf, "  <uuid>%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x</uuid>\n",
                          uuid[0], uuid[1], uuid[2], uuid[3],
                          uuid[4], uuid[5], uuid[6], uuid[7],
                          uuid[8], uuid[9], uuid[10], uuid[11],
                          uuid[12], uuid[13], uuid[14], uuid[15]) < 0)
        goto no_memory;
    if (qemudBufferPrintf(&buf, "  <memory>%d</memory>\n", def->maxmem) < 0)
        goto no_memory;
    if (qemudBufferPrintf(&buf, "  <currentMemory>%d</currentMemory>\n", def->memory) < 0)
        goto no_memory;
    if (qemudBufferPrintf(&buf, "  <vcpu>%d</vcpu>\n", def->vcpus) < 0)
        goto no_memory;

    if (qemudBufferAdd(&buf, "  <os>\n") < 0)
        goto no_memory;

    if (def->virtType == QEMUD_VIRT_QEMU) {
        if (qemudBufferPrintf(&buf, "    <type arch='%s' machine='%s'>%s</type>\n",
                              def->os.arch, def->os.machine, def->os.type) < 0)
            goto no_memory;
    } else {
        if (qemudBufferPrintf(&buf, "    <type>%s</type>\n", def->os.type) < 0)
            goto no_memory;
    }

    if (def->os.kernel[0])
        if (qemudBufferPrintf(&buf, "    <kernel>%s</kernel>\n", def->os.kernel) < 0)
            goto no_memory;
    if (def->os.initrd[0])
        if (qemudBufferPrintf(&buf, "    <initrd>%s</initrd>\n", def->os.initrd) < 0)
            goto no_memory;
    if (def->os.cmdline[0])
        if (qemudBufferPrintf(&buf, "    <cmdline>%s</cmdline>\n", def->os.cmdline) < 0)
            goto no_memory;

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
            boottype = "net";
            break;
        }
        if (qemudBufferPrintf(&buf, "    <boot dev='%s'/>\n", boottype) < 0)
            goto no_memory;
    }

    if (qemudBufferAdd(&buf, "  </os>\n") < 0)
        goto no_memory;

    if (def->features & QEMUD_FEATURE_ACPI) {
        if (qemudBufferAdd(&buf, "  <features>\n") < 0)
            goto no_memory;
        if (qemudBufferAdd(&buf, "    <acpi/>\n") < 0)
            goto no_memory;
        if (qemudBufferAdd(&buf, "  </features>\n") < 0)
            goto no_memory;
    }


    if (qemudBufferAdd(&buf, "  <devices>\n") < 0)
        goto no_memory;

    if (qemudBufferPrintf(&buf, "    <emulator>%s</emulator>\n", def->os.binary) < 0)
        goto no_memory;

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
        if (qemudBufferPrintf(&buf, "    <disk type='%s' device='%s'>\n",
                              types[disk->type], devices[disk->device]) < 0)
            goto no_memory;

        if (qemudBufferPrintf(&buf, "      <source %s='%s'/>\n", typeAttrs[disk->type], disk->src) < 0)
            goto no_memory;

        if (qemudBufferPrintf(&buf, "      <target dev='%s'/>\n", disk->dst) < 0)
            goto no_memory;

        if (disk->readonly)
            if (qemudBufferAdd(&buf, "      <readonly/>\n") < 0)
                goto no_memory;

        if (qemudBufferPrintf(&buf, "    </disk>\n") < 0)
            goto no_memory;

        disk = disk->next;
    }

    net = def->nets;
    while (net) {
        const char *types[] = {
            "user",
            "tap",
            "server",
            "client",
            "mcast",
            "network",
            "vde",
        };
        if (qemudBufferPrintf(&buf, "    <interface type='%s'>\n",
                              types[net->type]) < 0)
            goto no_memory;

        if (net->mac[0] && net->mac[1] && net->mac[2] &&
            net->mac[3] && net->mac[4] && net->mac[5] &&
            qemudBufferPrintf(&buf, "      <mac address='%02x:%02x:%02x:%02x:%02x:%02x'/>\n",
                              net->mac[0], net->mac[1], net->mac[2],
                              net->mac[3], net->mac[4], net->mac[5]) < 0)
            goto no_memory;

        if (net->type == QEMUD_NET_NETWORK) {
            if (qemudBufferPrintf(&buf, "      <source network='%s'", net->dst.network.name) < 0)
                goto no_memory;

            if (net->dst.network.tapifname[0] != '\0' &&
                qemudBufferPrintf(&buf, " tapifname='%s'", net->dst.network.tapifname) < 0)
                goto no_memory;

            if (qemudBufferPrintf(&buf, "/>\n") < 0)
                goto no_memory;
        }

        if (qemudBufferPrintf(&buf, "    </interface>\n") < 0)
            goto no_memory;

        net = net->next;
    }

    switch (def->graphicsType) {
    case QEMUD_GRAPHICS_VNC:
        if (qemudBufferAdd(&buf, "    <graphics type='vnc'") < 0)
            goto no_memory;

        if (def->vncPort &&
            qemudBufferPrintf(&buf, " port='%d'",
                              qemudIsActiveVM(vm) && live ? def->vncActivePort : def->vncPort) < 0)
            goto no_memory;

        if (qemudBufferAdd(&buf, "/>\n") < 0)
            goto no_memory;
        break;

    case QEMUD_GRAPHICS_SDL:
        if (qemudBufferAdd(&buf, "    <graphics type='sdl'/>\n") < 0)
            goto no_memory;
        break;

    case QEMUD_GRAPHICS_NONE:
    default:
        break;
    }

    if (def->graphicsType == QEMUD_GRAPHICS_VNC) {
    }

    if (qemudBufferAdd(&buf, "  </devices>\n") < 0)
        goto no_memory;


    if (qemudBufferAdd(&buf, "</domain>\n") < 0)
        goto no_memory;

    return buf.data;

 no_memory:
    qemudReportError(server, VIR_ERR_NO_MEMORY, "xml");
 cleanup:
    if (buf.data)
        free(buf.data);
    return NULL;
}


char *qemudGenerateNetworkXML(struct qemud_server *server,
                              struct qemud_network *network ATTRIBUTE_UNUSED,
                              struct qemud_network_def *def) {
    struct qemudBuffer buf;
    unsigned char *uuid;

    buf.len = QEMUD_MAX_XML_LEN;
    buf.used = 0;
    buf.data = malloc(buf.len);

    if (!buf.data)
        goto no_memory;

    if (qemudBufferPrintf(&buf, "<network>\n") < 0)
        goto no_memory;

    if (qemudBufferPrintf(&buf, "  <name>%s</name>\n", def->name) < 0)
        goto no_memory;

    uuid = def->uuid;
    if (qemudBufferPrintf(&buf, "  <uuid>%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x</uuid>\n",
                          uuid[0], uuid[1], uuid[2], uuid[3],
                          uuid[4], uuid[5], uuid[6], uuid[7],
                          uuid[8], uuid[9], uuid[10], uuid[11],
                          uuid[12], uuid[13], uuid[14], uuid[15]) < 0)
        goto no_memory;

    if ((def->bridge != '\0' || def->disableSTP || def->forwardDelay) &&
        qemudBufferPrintf(&buf, "  <bridge name='%s' stp='%s' delay='%d' />\n",
                          def->bridge,
                          def->disableSTP ? "off" : "on",
                          def->forwardDelay) < 0)
        goto no_memory;

    if (def->ipAddress[0] || def->netmask[0]) {
        if (qemudBufferAdd(&buf, "  <ip") < 0)
            goto no_memory;

        if (def->ipAddress[0] &&
            qemudBufferPrintf(&buf, " address='%s'", def->ipAddress) < 0)
            goto no_memory;

        if (def->netmask[0] &&
            qemudBufferPrintf(&buf, " netmask='%s'", def->netmask) < 0)
            goto no_memory;

        if (qemudBufferAdd(&buf, ">\n") < 0)
            goto no_memory;

        if (def->ranges) {
            struct qemud_dhcp_range_def *range = def->ranges;
            if (qemudBufferAdd(&buf, "    <dhcp>\n") < 0)
                goto no_memory;
            while (range) {
                if (qemudBufferPrintf(&buf, "      <range start='%s' end='%s' />\n",
                                      range->start, range->end) < 0)
                    goto no_memory;
                range = range->next;
            }
            if (qemudBufferAdd(&buf, "    </dhcp>\n") < 0)
                goto no_memory;
        }

        if (qemudBufferAdd(&buf, "  </ip>\n") < 0)
            goto no_memory;
    }

    if (qemudBufferAdd(&buf, "</network>\n") < 0)
        goto no_memory;

    return buf.data;

 no_memory:
    qemudReportError(server, VIR_ERR_NO_MEMORY, "xml");
    if (buf.data)
        free(buf.data);
    return NULL;
}


int qemudDeleteConfig(struct qemud_server *server,
                      const char *configFile,
                      const char *name) {
    if (!configFile[0]) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "no config file for %s", name);
        return -1;
    }

    if (unlink(configFile) < 0) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "cannot remove config for %s", name);
        return -1;
    }

    return 0;
}


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
