/*
 * xm_internal.h: helper routines for dealing with inactive domains
 *
 * Copyright (C) 2006
 *
 *      Daniel Berrange <berrange@redhat.com>
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING.LIB in the main directory of this
 *  archive for more details.
 */

#include <dirent.h>
#include <time.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdint.h>
#include <xen/dom0_ops.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>


#include "xm_internal.h"
#include "xend_internal.h"
#include "conf.h"
#include "hash.h"
#include "internal.h"
#include "xml.h"

typedef struct xenXMConfCache *xenXMConfCachePtr;
typedef struct xenXMConfCache {
    time_t refreshedAt;
    char filename[PATH_MAX];
    virConfPtr conf;
} xenXMConfCache;

static char configDir[PATH_MAX];
static virHashTablePtr configCache = NULL;
static int nconnections = 0;
static time_t lastRefresh = 0;

#define XM_REFRESH_INTERVAL 10

#define XM_CONFIG_DIR "/etc/xen"
#define XM_EXAMPLE_PREFIX "xmexample"
#define XEND_CONFIG_FILE "xend-config.sxp"
#define XEND_PCI_CONFIG_PREFIX "xend-pci-"
#define QEMU_IF_SCRIPT "qemu-ifup"

static virDriver xenXMDriver = {
    VIR_DRV_XEN_XM,
    "XenXM",
    (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
    (DOM0_INTERFACE_VERSION & 0xFFFF),
    NULL, /* init */
    xenXMOpen, /* open */
    xenXMClose, /* close */
    xenXMGetType, /* type */
    NULL, /* version */
    NULL, /* nodeGetInfo */
    NULL, /* listDomains */
    NULL, /* numOfDomains */
    NULL, /* domainCreateLinux */
    NULL, /* domainLookupByID */
    xenXMDomainLookupByUUID, /* domainLookupByUUID */
    xenXMDomainLookupByName, /* domainLookupByName */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    NULL, /* domainDestroy */
    NULL, /* domainFree */
    NULL, /* domainGetName */
    NULL, /* domainGetID */
    NULL, /* domainGetUUID */
    NULL, /* domainGetOSType */
    xenXMDomainGetMaxMemory, /* domainGetMaxMemory */
    xenXMDomainSetMaxMemory, /* domainSetMaxMemory */
    xenXMDomainSetMemory, /* domainMaxMemory */
    xenXMDomainGetInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    xenXMDomainSetVcpus, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    xenXMDomainDumpXML, /* domainDumpXML */
    xenXMListDefinedDomains, /* listDefinedDomains */
    xenXMNumOfDefinedDomains, /* numOfDefinedDomains */
    xenXMDomainCreate, /* domainCreate */
    xenXMDomainDefineXML, /* domainDefineXML */
    xenXMDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
};

static void
xenXMError(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, VIR_FROM_XEND, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}

void xenXMRegister(void)
{
    char *envConfigDir;
    int safeMode = 0;
    virRegisterDriver(&xenXMDriver);

    /* Disable use of env variable if running setuid */
    if ((geteuid() != getuid()) ||
        (getegid() != getgid()))
        safeMode = 1;

    if (!safeMode &&
        (envConfigDir = getenv("LIBVIRT_XM_CONFIG_DIR")) != NULL) {
        strncpy(configDir, envConfigDir, PATH_MAX-1);
        configDir[PATH_MAX-1] = '\0';
    } else {
        strcpy(configDir, XM_CONFIG_DIR);
    }
}


/* Remove any configs which were not refreshed recently */
static int xenXMConfigReaper(const void *payload, const char *key ATTRIBUTE_UNUSED, const void *data) {
    time_t now = *(const time_t *)data;
    xenXMConfCachePtr entry = (xenXMConfCachePtr)payload;

    if (entry->refreshedAt != now)
        return (1);
    return (0);
}

/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetInt(virConfPtr conf, const char *name, long *value) {
    virConfValuePtr val;
    if (!value || !name || !conf)
        return (-1);

    if (!(val = virConfGetValue(conf, name))) {
        return (-1);
    }

    if (val->type == VIR_CONF_LONG) {
        *value = val->l;
    } else if (val->type == VIR_CONF_STRING) {
        char *ret;
        if (!val->str)
            return (-1);
        *value = strtol(val->str, &ret, 10);
        if (ret == val->str)
            return (-1);
    } else {
        return (-1);
    }
    return (0);
}


/* Convenience method to grab a string from the config file object */
static int xenXMConfigGetString(virConfPtr conf, const char *name, const char **value) {
    virConfValuePtr val;
    if (!value || !name || !conf)
        return (-1);
    *value = NULL;
    if (!(val = virConfGetValue(conf, name))) {
        return (-1);
    }
    if (val->type != VIR_CONF_STRING)
        return (-1);
    if (!val->str)
        return (-1);
    *value = val->str;
    return (0);
}

/* Convenience method to grab a string UUID from the config file object */
static int xenXMConfigGetUUID(virConfPtr conf, const char *name, unsigned char *uuid) {
    virConfValuePtr val;
    char *rawuuid = (char *)uuid;
    if (!uuid || !name || !conf)
        return (-1);
    if (!(val = virConfGetValue(conf, name))) {
        return (-1);
    }

    if (val->type != VIR_CONF_STRING)
        return (-1);
    if (!val->str)
        return (-1);

    if (!virParseUUID(&rawuuid, val->str))
        return (-1);

    return (0);
}

/* Generate a rnadom UUID - used if domain doesn't already
   have one in its config */
static void xenXMConfigGenerateUUID(unsigned char *uuid) {
    int i;
    for (i = 0 ; i < 16 ; i++) {
        uuid[i] = (unsigned char)(1 + (int) (256.0 * (rand() / (RAND_MAX + 1.0))));
    }
}

/* Ensure that a config object has a valid UUID in it,
   if it doesn't then (re-)generate one */
static int xenXMConfigEnsureUUID(virConfPtr conf) {
    unsigned char uuid[16];

    /* If there is no uuid...*/
    if (xenXMConfigGetUUID(conf, "uuid", uuid) < 0) {
        virConfValuePtr value;
        char uuidstr[37];

        value = malloc(sizeof(virConfValue));
        if (!value) {
            return (-1);
        }

        /* ... then generate one */
        xenXMConfigGenerateUUID(uuid);
        snprintf(uuidstr, 37,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x</uuid>\n",
                 uuid[0], uuid[1], uuid[2], uuid[3],
                 uuid[4], uuid[5], uuid[6], uuid[7],
                 uuid[8], uuid[9], uuid[10], uuid[11],
                 uuid[12], uuid[13], uuid[14], uuid[15]);
        uuidstr[36] = '\0';

        value->type = VIR_CONF_STRING;
        value->str = strdup(uuidstr);
        if (!value->str) {
            free(value);
            return (-1);
        }

        /* And stuff the UUID back into the config file */
        if (virConfSetValue(conf, "uuid", value) < 0)
            return (-1);
    }
    return (0);
}

/* Release memory associated with a cached config object */
static void xenXMConfigFree(void *payload, const char *key ATTRIBUTE_UNUSED) {
    xenXMConfCachePtr entry = (xenXMConfCachePtr)payload;
    virConfFree(entry->conf);
    free(entry);
}


/* This method is called by various methods to scan /etc/xen
   (or whatever directory was set by  LIBVIRT_XM_CONFIG_DIR
   environment variable) and process any domain configs. It
   has rate-limited so never rescans more frequently than
   once every X seconds */
static int xenXMConfigCacheRefresh(void) {
    DIR *dh;
    struct dirent *ent;
    time_t now = time(NULL);
    int ret = -1;

    if (now == ((time_t)-1)) {
        return (-1);
    }

    /* Rate limit re-scans */
    if ((now - lastRefresh) < XM_REFRESH_INTERVAL)
        return (0);

    lastRefresh = now;

    /* Process the files in the config dir */
    if (!(dh = opendir(configDir))) {
        return (-1);
    }

    while ((ent = readdir(dh))) {
        xenXMConfCachePtr entry;
        struct stat st;
        int newborn = 0;
        char path[PATH_MAX];

        /*
         * Skip a bunch of crufty files that clearly aren't config files
         */

        /* Like 'dot' files... */
        if (!strncmp(ent->d_name, ".", 1))
            continue;
        /* ...and the XenD server config file */
        if (!strncmp(ent->d_name, XEND_CONFIG_FILE, strlen(XEND_CONFIG_FILE)))
            continue;
        /* ...and random PCI config cruft */
        if (!strncmp(ent->d_name, XEND_PCI_CONFIG_PREFIX, strlen(XEND_PCI_CONFIG_PREFIX)))
            continue;
        /* ...and the example domain configs */
        if (!strncmp(ent->d_name, XM_EXAMPLE_PREFIX, strlen(XM_EXAMPLE_PREFIX)))
            continue;
        /* ...and the QEMU networking script */
        if (!strncmp(ent->d_name, QEMU_IF_SCRIPT, strlen(QEMU_IF_SCRIPT)))
            continue;

        /* ...and editor backups */
        if (ent->d_name[0] == '#')
            continue;
        if (ent->d_name[strlen(ent->d_name)-1] == '~')
            continue;

        /* Build the full file path */
        if ((strlen(configDir) + 1 + strlen(ent->d_name) + 1) > PATH_MAX)
            continue;
        strcpy(path, configDir);
        strcat(path, "/");
        strcat(path, ent->d_name);

        /* Skip anything which isn't a file (takes care of scripts/ subdir */
        if ((stat(path, &st) < 0) ||
            (!S_ISREG(st.st_mode))) {
            continue;
        }

        /* If we already have a matching entry and it is not
           modified, then carry on to next one*/
        if ((entry = virHashLookup(configCache, ent->d_name))) {
            if (entry->refreshedAt >= st.st_mtime) {
                entry->refreshedAt = now;
                continue;
            }
        }

        if (entry) { /* Existing entry which needs refresh */
            virConfFree(entry->conf);
            entry->conf = NULL;
        } else { /* Completely new entry */
            newborn = 1;
            if (!(entry = malloc(sizeof(xenXMConfCache)))) {
                goto cleanup;
            }
            memcpy(entry->filename, path, PATH_MAX);
        }
        entry->refreshedAt = now;

        if (!(entry->conf = virConfReadFile(entry->filename)) ||
            xenXMConfigEnsureUUID(entry->conf) < 0) {
            if (!newborn) {
                virHashRemoveEntry(configCache, ent->d_name, NULL);
            }
            free(entry);
            continue;
        }

        /* If its a completely new entry, it must be stuck into
           the cache (refresh'd entries are already registered) */
        if (newborn) {
            if (virHashAddEntry(configCache, ent->d_name, entry) < 0) {
                virConfFree(entry->conf);
                free(entry);
                goto cleanup;
            }
        }
    }

    /* Reap all entries which were not changed, by comparing
       their refresh timestamp - the timestamp should match
       'now' if they were refreshed. If timestamp doesn't match
       then the config is no longer on disk */
    virHashRemoveSet(configCache, xenXMConfigReaper, xenXMConfigFree, (const void*) &now);
    ret = 0;

 cleanup:
    if (dh)
        closedir(dh);

    return (ret);
}


/*
 * Open a 'connection' to the config file directory ;-)
 * We just create a hash table to store config files in.
 * We only support a single directory, so repeated calls
 * to open all end up using the same cache of files
 */
int xenXMOpen(virConnectPtr conn ATTRIBUTE_UNUSED, const char *name, int flags ATTRIBUTE_UNUSED) {
    if (name &&
        strcasecmp(name, "xen")) {
        return (-1);
    }

    if (nconnections == 0) {
        configCache = virHashCreate(50);
        if (!configCache)
            return (-1);
    }
    nconnections++;

    return (0);
}

/*
 * Free the config files in the cache if this is the
 * last connection
 */
int xenXMClose(virConnectPtr conn ATTRIBUTE_UNUSED) {
    if (!nconnections--) {
        virHashFree(configCache, xenXMConfigFree);
        configCache = NULL;
    }
    return (0);
}

/* 
 * Our backend type
 */
const char *xenXMGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return ("XenXM");
}

/*
 * Since these are all offline domains, we only return info about
 * VCPUs and memory. 
 */
int xenXMDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info) {
    xenXMConfCachePtr entry;
    long vcpus;
    long mem;
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return(-1);
    }

    if (domain->handle != -1)
        return (-1);

    if (!(entry = virHashLookup(configCache, domain->name)))
        return (-1);

    memset(info, 0, sizeof(virDomainInfo));
    if (xenXMConfigGetInt(entry->conf, "memory", &mem) < 0 ||
        mem < 0)
        info->memory = 64 * 1024;
    else
        info->memory = (unsigned long)mem * 1024;
    if (xenXMConfigGetInt(entry->conf, "maxmem", &mem) < 0 ||
        mem < 0)
        info->maxMem = info->memory;
    else
        info->maxMem = (unsigned long)mem * 1024;

    if (xenXMConfigGetInt(entry->conf, "vcpus", &vcpus) < 0 ||
        vcpus < 0)
        info->nrVirtCpu = 1;
    else
        info->nrVirtCpu = (unsigned short)vcpus;
    info->state = VIR_DOMAIN_SHUTOFF;
    info->cpuTime = 0;

    return (0);

}

/*
 * Turn a config record into a lump of XML describing the
 * domain, suitable for later feeding for virDomainCreateLinux
 */
char *xenXMDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED) {
    virBufferPtr buf;
    xenXMConfCachePtr entry;
    char *xml;
    const char *name;
    unsigned char uuid[16];
    const char *str;
    int hvm = 0;
    long val;
    virConfValuePtr list;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return(NULL);
    }
    if (domain->handle != -1)
        return (NULL);
    if (!(entry = virHashLookup(configCache, domain->name)))
        return (NULL);

    if (xenXMConfigGetString(entry->conf, "name", &name) < 0)
        return (NULL);
    if (xenXMConfigGetUUID(entry->conf, "uuid", uuid) < 0)
        return (NULL);

    buf = virBufferNew(4096);

    virBufferAdd(buf, "<domain type='xen'>\n", -1);
    virBufferVSprintf(buf, "  <name>%s</name>\n", name);
    virBufferVSprintf(buf,
                      "  <uuid>%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x</uuid>\n",
                      uuid[0], uuid[1], uuid[2], uuid[3],
                      uuid[4], uuid[5], uuid[6], uuid[7],
                      uuid[8], uuid[9], uuid[10], uuid[11],
                      uuid[12], uuid[13], uuid[14], uuid[15]);

    if ((xenXMConfigGetString(entry->conf, "builder", &str) == 0) &&
        !strcmp(str, "hvm"))
        hvm = 1;

    if (hvm) {
        virBufferAdd(buf, "  <os>\n", -1);
        virBufferAdd(buf, "    <type>hvm</type>\n", -1);
        if (xenXMConfigGetString(entry->conf, "kernel", &str) == 0)
            virBufferVSprintf(buf, "    <loader>%s</loader>\n", str);
        virBufferAdd(buf, "  </os>\n", -1);
    } else {

        if (xenXMConfigGetString(entry->conf, "bootloader", &str) == 0)
            virBufferVSprintf(buf, "  <bootloader>%s</bootloader>\n", str);
        if (xenXMConfigGetString(entry->conf, "kernel", &str) == 0) {
            virBufferAdd(buf, "  <os>\n", -1);
            virBufferAdd(buf, "    <type>linux</type>\n", -1);
            virBufferVSprintf(buf, "    <kernel>%s</kernel>\n", str);
            if (xenXMConfigGetString(entry->conf, "ramdisk", &str) == 0)
                virBufferVSprintf(buf, "    <initrd>%s</initrd>\n", str);
            if (xenXMConfigGetString(entry->conf, "extra", &str) == 0)
                virBufferVSprintf(buf, "    <cmdline>%s</cmdline>\n", str);
            virBufferAdd(buf, "  </os>\n", -1);
        }
    }

    if (xenXMConfigGetInt(entry->conf, "memory", &val) < 0)
        val = 64;
    virBufferVSprintf(buf, "  <memory>%ld</memory>\n", val * 1024);

    if (xenXMConfigGetInt(entry->conf, "vcpus", &val) < 0)
        val = 1;
    virBufferVSprintf(buf, "  <vcpu>%ld</vcpu>\n", val);



    if (xenXMConfigGetString(entry->conf, "on_poweroff", &str) < 0)
        str = "destroy";
    virBufferVSprintf(buf, "  <on_poweroff>%s</on_poweroff>\n", str);

    if (xenXMConfigGetString(entry->conf, "on_reboot", &str) < 0)
        str = "restart";
    virBufferVSprintf(buf, "  <on_reboot>%s</on_reboot>\n", str);

    if (xenXMConfigGetString(entry->conf, "on_crash", &str) < 0)
        str = "restart";
    virBufferVSprintf(buf, "  <on_crash>%s</on_crash>\n", str);


    if (hvm) {
        virBufferAdd(buf, "  <features>\n", -1);
        if (xenXMConfigGetInt(entry->conf, "pae", &val) == 0 &&
            val)
            virBufferAdd(buf, "    <pae/>\n", -1);
        if (xenXMConfigGetInt(entry->conf, "acpi", &val) == 0 &&
            val)
            virBufferAdd(buf, "    <acpi/>\n", -1);
        if (xenXMConfigGetInt(entry->conf, "apic", &val) == 0 &&
            val)
            virBufferAdd(buf, "    <apic/>\n", -1);
        virBufferAdd(buf, "  </features>\n", -1);
    }

    virBufferAdd(buf, "  <devices>\n", -1);

    if (hvm) {
        if (xenXMConfigGetString(entry->conf, "device_model", &str) == 0)
            virBufferVSprintf(buf, "    <emulator>%s</emulator>\n", str);
    }

    list = virConfGetValue(entry->conf, "disk");
    while (list && list->type == VIR_CONF_LIST) {
        virConfValuePtr el = list->list;
        int block = 0;
        char dev[NAME_MAX];
        char src[PATH_MAX];
        char drvName[NAME_MAX] = "";
        char drvType[NAME_MAX] = "";
        char *device;
        char *mode;
        char *path;

        if ((el== NULL) || (el->type != VIR_CONF_STRING) || (el->str == NULL))
            goto skipdisk;

        if (!(device = index(el->str, ',')) || device[0] == '\0')
            goto skipdisk;
        device++;
        if (!(mode = index(device, ',')) || mode[0] == '\0')
            goto skipdisk;
        mode++;

        if (!(path = index(el->str, ':')) || path[0] == '\0' || path > device)
            goto skipdisk;

        strncpy(drvName, el->str, (path-el->str));
        if (!strcmp(drvName, "tap")) {
            if (!(path = index(el->str+4, ':')) || path[0] == '\0' || path > device)
                goto skipdisk;

            strncpy(drvType, el->str+4, (path-(el->str+4)));
        }
        if ((device-path) > PATH_MAX)
            goto skipdisk;

        strncpy(src, path+1, (device-(path+1))-1);
        src[(device-(path+1))-1] = '\0';

        if (!strcmp(drvName, "phy")) {
            block = 1;
        }

        if ((mode-device-1) > (NAME_MAX-1)) {
            goto skipdisk;
        }
        strncpy(dev, device, (mode-device-1));
        dev[(mode-device-1)] = '\0';

        virBufferVSprintf(buf, "    <disk type='%s' device='disk'>\n", block ? "block" : "file");
        if (drvType[0])
            virBufferVSprintf(buf, "      <driver name='%s' type='%s'/>\n", drvName, drvType);
        else
            virBufferVSprintf(buf, "      <driver name='%s'/>\n", drvName);
        virBufferVSprintf(buf, "      <source %s='%s'/>\n", block ? "dev" : "file", src);
        virBufferVSprintf(buf, "      <target dev='%s'/>\n", dev);
        if (*mode == 'r')
            virBufferAdd(buf, "      <readonly/>\n", -1);
        virBufferAdd(buf, "    </disk>\n", -1);

    skipdisk:
        list = list->next;
    }

    list = virConfGetValue(entry->conf, "vif");
    while (list && list->type == VIR_CONF_LIST) {
        virConfValuePtr el = list->list;
        int type = -1;
        char script[PATH_MAX];
        char ip[16];
        char mac[18];
        char *key;

        mac[0] = '\0';
        script[0] = '\0';
        ip[0] = '\0';

        if ((el== NULL) || (el->type != VIR_CONF_STRING) || (el->str == NULL))
            goto skipnic;

        key = el->str;
        while (key) {
            char *data;
            char *nextkey = index(key, ',');

            if (!(data = index(key, '=')) || (data[0] == '\0'))
                goto skipnic;
            data++;

            if (!strncmp(key, "mac=", 4)) {
                int len = nextkey ? (nextkey - data) : 17;
                if (len > 17)
                    len = 17;
                strncpy(mac, data, len);
                mac[len] = '\0';
            } else if (!strncmp(key, "bridge=", 7)) {
                type = 1;
            } else if (!strncmp(key, "script=", 7)) {
                int len = nextkey ? (nextkey - data) : PATH_MAX-1;
                if (len > (PATH_MAX-1))
                    len = PATH_MAX-1;
                strncpy(script, data, len);
                script[len] = '\0';
            } else if (!strncmp(key, "ip=", 3)) {
                int len = nextkey ? (nextkey - data) : 15;
                if (len > 15)
                    len = 15;
                strncpy(ip, data, len);
                ip[len] = '\0';
            }

            while (nextkey && (nextkey[0] == ',' ||
                               nextkey[0] == ' ' ||
                               nextkey[0] == '\t'))
                nextkey++;
            key = nextkey;
        }

        /* XXX Forcing to pretend its a bridge */
        if (type == -1) {
            type = 1;
        }

        virBufferAdd(buf, "    <interface type='bridge'>\n", -1);
        if (mac[0])
            virBufferVSprintf(buf, "      <mac address='%s'/>\n", mac);
        if (script[0])
            virBufferVSprintf(buf, "      <script path='%s'/>\n", script);
        if (ip[0])
            virBufferVSprintf(buf, "      <ip address='%s'/>\n", ip);
        virBufferAdd(buf, "    </interface>\n", -1);

    skipnic:
        list = list->next;
    }

    if (xenXMConfigGetInt(entry->conf, "vnc", &val) == 0 && val) {
        long display;
        long unused = 1;
        if (xenXMConfigGetInt(entry->conf, "vncunused", &unused) < 0)
            unused = 1;
        if (xenXMConfigGetInt(entry->conf, "vncdisplay", &display) < 0)
            display = 0;

        if (unused) {
            virBufferAdd(buf, "    <graphics type='vnc' port='-1'/>\n", -1);
        } else {
            virBufferVSprintf(buf, "    <graphics type='vnc' port='%d'/>\n", (5900+display));
        }
    }
    if (xenXMConfigGetInt(entry->conf, "sdl", &val) == 0 && val) {
        virBufferAdd(buf, "    <graphics type='sdl'/>\n", -1);
    }

    if (hvm) {
        if (xenXMConfigGetString(entry->conf, "serial", &str) == 0 && !strcmp(str, "pty")) {
            virBufferAdd(buf, "    <console/>\n", -1);
        }
    }

    virBufferAdd(buf, "  </devices>\n", -1);

    virBufferAdd(buf, "</domain>\n", -1);

    xml = buf->content;
    buf->content = NULL;
    virBufferFree(buf);
    return (xml);
}


/*
 * Update amount of memory in the config file
 */
int xenXMDomainSetMemory(virDomainPtr domain, unsigned long memory) {
    xenXMConfCachePtr entry;
    virConfValuePtr value;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);
    if (domain->handle != -1)
        return (-1);

    if (!(entry = virHashLookup(configCache, domain->name)))
        return (-1);

    if (!(value = malloc(sizeof(virConfValue))))
        return (-1);

    value->type = VIR_CONF_LONG;
    value->l = (memory/1024);

    if (virConfSetValue(entry->conf, "memory", value) < 0)
        return (-1);

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (virConfWriteFile(entry->filename, entry->conf) < 0)
        return (-1);

    return (0);
}

/*
 * Update maximum memory limit in config
 */
int xenXMDomainSetMaxMemory(virDomainPtr domain, unsigned long memory) {
    xenXMConfCachePtr entry;
    virConfValuePtr value;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);
    if (domain->handle != -1)
        return (-1);

    if (!(entry = virHashLookup(configCache, domain->name)))
        return (-1);

    if (!(value = malloc(sizeof(virConfValue))))
        return (-1);

    value->type = VIR_CONF_LONG;
    value->l = (memory/1024);

    if (virConfSetValue(entry->conf, "maxmem", value) < 0)
        return (-1);

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (virConfWriteFile(entry->filename, entry->conf) < 0)
        return (-1);

    return (0);
}

/*
 * Get max memory limit from config
 */
unsigned long xenXMDomainGetMaxMemory(virDomainPtr domain) {
    xenXMConfCachePtr entry;
    long val;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->handle != -1)
        return (-1);

    if (!(entry = virHashLookup(configCache, domain->name)))
        return (-1);

    if (xenXMConfigGetInt(entry->conf, "maxmem", &val) < 0 ||
        val < 0)
        if (xenXMConfigGetInt(entry->conf, "memory", &val) < 0 ||
            val < 0)
            val = 64;

    return (val * 1024);
}

/*
 * Set the VCPU count in config
 */
int xenXMDomainSetVcpus(virDomainPtr domain, unsigned int vcpus) {
    xenXMConfCachePtr entry;
    virConfValuePtr value;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);
    if (domain->handle != -1)
        return (-1);

    if (!(entry = virHashLookup(configCache, domain->name)))
        return (-1);

    if (!(value = malloc(sizeof(virConfValue))))
        return (-1);

    value->type = VIR_CONF_LONG;
    value->l = vcpus;

    if (virConfSetValue(entry->conf, "vcpus", value) < 0)
        return (-1);

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (virConfWriteFile(entry->filename, entry->conf) < 0)
        return (-1);

    return (0);
}

/*
 * Find an inactive domain based on its name
 */
virDomainPtr xenXMDomainLookupByName(virConnectPtr conn, const char *domname) {
    xenXMConfCachePtr entry;
    virDomainPtr ret;
    unsigned char uuid[16];
    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (domname == NULL) {
        xenXMError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (xenXMConfigCacheRefresh() < 0)
        return (NULL);

    if (!(entry = virHashLookup(configCache, domname))) {
        return (NULL);
    }


    if (xenXMConfigGetUUID(entry->conf, "uuid", uuid) < 0) {
        return (NULL);
    }

    if (!(ret = virGetDomain(conn, domname, uuid))) {
        return (NULL);
    }
    ret->handle = -1;

    return (ret);
}


/*
 * Hash table iterator to search for a domain based on UUID
 */
static int xenXMDomainSearchForUUID(const void *payload, const char *name ATTRIBUTE_UNUSED, const void *data) {
    unsigned char uuid[16];
    const unsigned char *wantuuid = (const unsigned char *)data;
    const xenXMConfCachePtr entry = (const xenXMConfCachePtr)payload;

    if (xenXMConfigGetUUID(entry->conf, "uuid", uuid) < 0) {
        return (0);
    }

    if (!memcmp(uuid, wantuuid, 16))
        return (1);

    return (0);
}

/*
 * Find an inactive domain based on its UUID
 */
virDomainPtr xenXMDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid) {
    xenXMConfCachePtr entry;
    virDomainPtr ret;
    const char *domname;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        xenXMError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (xenXMConfigCacheRefresh() < 0)
        return (NULL);

    if (!(entry = virHashSearch(configCache, xenXMDomainSearchForUUID, (const void *)uuid))) {
        return (NULL);
    }

    if (xenXMConfigGetString(entry->conf, "name", &domname) < 0) {
        return (NULL);
    }

    if (!(ret = virGetDomain(conn, domname, uuid))) {
        return (NULL);
    }

    return (ret);
}


/*
 * Start a domain from an existing defined config file
 */
int xenXMDomainCreate(virDomainPtr domain) {
    char *xml;
    char *sexpr;
    int ret, xendConfigVersion;
    unsigned char uuid[16];

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }

    if (domain->handle != -1)
        return (-1);
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);

    if (!(xml = xenXMDomainDumpXML(domain, 0)))
        return (-1);

    if ((xendConfigVersion = xend_get_config_version(domain->conn)) < 0) {
        xenXMError(domain->conn, VIR_ERR_INTERNAL_ERROR, "cannot determine xend config version");
        return (-1);
    }

    if (!(sexpr = virDomainParseXMLDesc(xml, NULL, xendConfigVersion))) {
        free(xml);
        return (-1);
    }
    free(xml);

    ret = xenDaemonDomainCreateLinux(domain->conn, sexpr);
    free(sexpr);
    if (ret != 0) {
        fprintf(stderr, "Failed to create domain %s\n", domain->name);
        return (-1);
    }

    ret = xend_wait_for_devices(domain->conn, domain->name);
    if (ret != 0) {
        fprintf(stderr, "Failed to get devices for domain %s\n", domain->name);
        return (-1);
    }

    if ((ret = xenDaemonDomainLookupByName_ids(domain->conn, domain->name, uuid)) < 0) {
        return (-1);
    }
    domain->handle = ret;

    ret = xenDaemonDomainResume(domain);
    if (ret != 0) {
        fprintf(stderr, "Failed to resume new domain %s\n", domain->name);
        xenDaemonDomainDestroy(domain);
        domain->handle = -1;
        return (-1);
    }

    return (0);
}

/*
 * Convenience method to set an int config param
 * based on an XPath expression
 */
static
int xenXMConfigSetIntFromXPath(virConfPtr conf, xmlXPathContextPtr ctxt,
                               const char *setting, const char *xpath,
                               int allowMissing, long scale) {
    xmlXPathObjectPtr obj;
    virConfValuePtr value = NULL;
    long intval;
    char *strend;
    int ret = -1;

    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) && allowMissing)
        return (0);

    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0))
        goto error;

    intval = strtol((char *)obj->stringval, &strend, 10);
    if (strend == (char *)obj->stringval)
        goto error;

    if (!(value = malloc(sizeof(virConfValue))))
        goto error;

    value->type = VIR_CONF_LONG;
    value->next = NULL;
    if (scale > 0)
        value->l = intval * scale;
    else if (scale < 0)
        value->l = intval / (-1*scale);
    else
        value->l = intval;

    if (virConfSetValue(conf, setting, value) < 0)
        goto error;

    ret = 0;

 error:
    if (obj)
        xmlXPathFreeObject(obj);

    return (ret);
}

/*
 * Convenience method to set a string param
 * based on an XPath expression
 */
static
int xenXMConfigSetStringFromXPath(virConfPtr conf, xmlXPathContextPtr ctxt,
                                  const char *setting, const char *xpath,
                                  int allowMissing) {
    xmlXPathObjectPtr obj;
    virConfValuePtr value = NULL;
    int ret = -1;

    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) && allowMissing)
        return (0);

    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0))
        goto error;

    if (!(value = malloc(sizeof(virConfValue))))
        goto error;

    value->type = VIR_CONF_STRING;
    value->next = NULL;
    if (!(value->str = strdup((char*)obj->stringval)))
        goto error;

    if (virConfSetValue(conf, setting, value) < 0)
        goto error;

    ret = 0;

 error:
    if (obj)
        xmlXPathFreeObject(obj);

    return (ret);
}


/*
 * Create a config file for a domain, based on an XML
 * document describing its config
 */
virDomainPtr xenXMDomainDefineXML(virConnectPtr conn, const char *xml) {
    virDomainPtr ret;
    char filename[PATH_MAX];
    unsigned char uuid[16];
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlChar *prop = NULL;
    virConfPtr conf = NULL;
    virConfValuePtr value = NULL;
    xenXMConfCachePtr entry = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xml == NULL) {
        xenXMError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO)
        return (NULL);

    if (xenXMConfigCacheRefresh() < 0)
        return (NULL);

    doc = xmlReadDoc((const xmlChar *) xml, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        return (NULL);
    }
    node = xmlDocGetRootElement(doc);
    if ((node == NULL) || (!xmlStrEqual(node->name, BAD_CAST "domain")))
        goto error;

    prop = xmlGetProp(node, BAD_CAST "type");
    if (prop != NULL) {
        if (!xmlStrEqual(prop, BAD_CAST "xen")) {
            goto error;
        }
        xmlFree(prop);
        prop = NULL;
    }
    if (!(ctxt = xmlXPathNewContext(doc)))
        goto error;

    if (!(conf = virConfNew()))
        goto error;

    if (xenXMConfigSetStringFromXPath(conf, ctxt, "name", "string(/domain/name)", 0) < 0)
        goto error;

    if (xenXMConfigSetStringFromXPath(conf, ctxt, "uuid", "string(/domain/uuid)", 0) < 0)
        goto error;

    if (xenXMConfigSetIntFromXPath(conf, ctxt, "memory", "string(/domain/memory)", 0, -1024) < 0)
        goto error;

    if (xenXMConfigSetIntFromXPath(conf, ctxt, "vcpus", "string(/domain/vcpu)", 0, 0) < 0)
        goto error;

    if (xenXMConfigSetIntFromXPath(conf, ctxt, "pae", "string(count(/domain/features/pae))", 0, 0) < 0)
        goto error;

    if (xenXMConfigSetIntFromXPath(conf, ctxt, "acpi", "string(count(/domain/features/acpi))", 0, 0) < 0)
        goto error;

    if (xenXMConfigSetIntFromXPath(conf, ctxt, "apic", "string(count(/domain/features/apic))", 0, 0) < 0)
        goto error;


    if (xenXMConfigSetStringFromXPath(conf, ctxt, "on_poweroff", "string(/domain/on_poweroff)", 1) < 0)
        goto error;

    if (xenXMConfigSetStringFromXPath(conf, ctxt, "on_reboot", "string(/domain/on_reboot)", 1) < 0)
        goto error;

    if (xenXMConfigSetStringFromXPath(conf, ctxt, "on_crash", "string(/domain/on_crash)", 1) < 0)
        goto error;


    if (!(value = virConfGetValue(conf, "name")) || value->type != VIR_CONF_STRING || value->str == NULL)
        goto error;

    if (virHashLookup(configCache, value->str) != 0)
        goto error;

    if ((strlen(configDir) + 1 + strlen(value->str) + 1) > PATH_MAX)
        goto error;

    strcpy(filename, configDir);
    strcat(filename, "/");
    strcat(filename, value->str);

    if (virConfWriteFile(filename, conf) < 0)
        goto error;

    if (!(entry = malloc(sizeof(xenXMConfCache))))
        goto error;
    memset(entry, 0, sizeof(xenXMConfCache));

    if ((entry->refreshedAt = time(NULL)) == ((time_t)-1))
        goto error;

    memmove(entry->filename, filename, PATH_MAX);
    entry->conf = conf;

    if (xenXMConfigGetUUID(conf, "uuid", uuid) < 0)
        goto error;

    if (virHashAddEntry(configCache, value->str, entry) < 0)
        goto error;
    entry = NULL;

    if (!(ret = virGetDomain(conn, value->str, uuid)))
        goto error;
    ret->handle = -1;

    return (ret);

 error:
    if (entry)
        free(entry);
    if (conf)
        virConfFree(conf);
    if (prop != NULL)
        xmlFree(prop);
    if (obj != NULL)
        xmlXPathFreeObject(obj);
    if (ctxt != NULL)
        xmlXPathFreeContext(ctxt);
    if (doc != NULL)
        xmlFreeDoc(doc);
    return (NULL);
}

/*
 * Delete a domain from disk
 */
int xenXMDomainUndefine(virDomainPtr domain) {
    xenXMConfCachePtr entry;
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }

    if (domain->handle != -1)
        return (-1);
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);

    if (!(entry = virHashLookup(configCache, domain->name)))
        return (-1);

    if (unlink(entry->filename) < 0)
        return (-1);

    if (virHashRemoveEntry(configCache, domain->name, xenXMConfigFree) < 0)
        return (-1);

    return (0);
}

struct xenXMListIteratorContext {
    virConnectPtr conn;
    int max;
    int count;
    const char **names;
};

static void xenXMListIterator(const void *payload ATTRIBUTE_UNUSED, const char *name, const void *data) {
    struct xenXMListIteratorContext *ctx = (struct xenXMListIteratorContext *)data;
    virDomainPtr dom = NULL;

    if (ctx->count == ctx->max)
        return;

    dom = xenDaemonDomainLookupByName(ctx->conn, name);
    if (!dom) {
        ctx->names[ctx->count] = strdup(name);
        ctx->count++;
    } else {
        virDomainFree(dom);
    }
}


/*
 * List all defined domains, filtered to remove any which
 * are currently running
 */
int xenXMListDefinedDomains(virConnectPtr conn, const char **names, int maxnames) {
    struct xenXMListIteratorContext ctx;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (xenXMConfigCacheRefresh() < 0)
        return (-1);

    if (maxnames > virHashSize(configCache))
        maxnames = virHashSize(configCache);

    ctx.conn = conn;
    ctx.count = 0;
    ctx.max = maxnames;
    ctx.names = names;

    virHashForEach(configCache, xenXMListIterator, &ctx);
    return (ctx.count);
}

/*
 * Return the maximum number of defined domains - not filtered
 * based on number running
 */
int xenXMNumOfDefinedDomains(virConnectPtr conn) {
    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (xenXMConfigCacheRefresh() < 0)
        return (-1);

    return virHashSize(configCache);
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
