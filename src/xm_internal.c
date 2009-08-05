/*
 * xm_internal.h: helper routines for dealing with inactive domains
 *
 * Copyright (C) 2006-2007 Red Hat
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
 *
 */

#include <config.h>

#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <stdint.h>
#include <xen/dom0_ops.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "xm_internal.h"
#include "xen_unified.h"
#include "xend_internal.h"
#include "hash.h"
#include "buf.h"
#include "uuid.h"
#include "util.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_XENXM

#ifdef WITH_RHEL5_API
#define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 0
#define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF 2
#else
#define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 3
#define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF 3
#endif

/* The true Xen limit varies but so far is always way
   less than 1024, which is the Linux kernel limit according
   to sched.h, so we'll match that for now */
#define XEN_MAX_PHYSICAL_CPU 1024

static int xenXMConfigSetString(virConfPtr conf, const char *setting,
                                const char *str);
char * xenXMAutoAssignMac(void);
static int xenXMDomainAttachDevice(virDomainPtr domain, const char *xml);
static int xenXMDomainDetachDevice(virDomainPtr domain, const char *xml);

#define XM_REFRESH_INTERVAL 10

#define XM_CONFIG_DIR "/etc/xen"
#define XM_EXAMPLE_PREFIX "xmexample"
#define XEND_CONFIG_FILE "xend-config.sxp"
#define XEND_PCI_CONFIG_PREFIX "xend-pci-"
#define QEMU_IF_SCRIPT "qemu-ifup"
#define XM_XML_ERROR "Invalid xml"

struct xenUnifiedDriver xenXMDriver = {
    xenXMOpen, /* open */
    xenXMClose, /* close */
    NULL, /* version */
    NULL, /* hostname */
    NULL, /* nodeGetInfo */
    NULL, /* getCapabilities */
    NULL, /* listDomains */
    NULL, /* numOfDomains */
    NULL, /* domainCreateXML */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    NULL, /* domainDestroy */
    NULL, /* domainGetOSType */
    xenXMDomainGetMaxMemory, /* domainGetMaxMemory */
    xenXMDomainSetMaxMemory, /* domainSetMaxMemory */
    xenXMDomainSetMemory, /* domainMaxMemory */
    xenXMDomainGetInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    xenXMDomainSetVcpus, /* domainSetVcpus */
    xenXMDomainPinVcpu, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    xenXMListDefinedDomains, /* listDefinedDomains */
    xenXMNumOfDefinedDomains, /* numOfDefinedDomains */
    xenXMDomainCreate, /* domainCreate */
    xenXMDomainDefineXML, /* domainDefineXML */
    xenXMDomainUndefine, /* domainUndefine */
    xenXMDomainAttachDevice, /* domainAttachDevice */
    xenXMDomainDetachDevice, /* domainDetachDevice */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
};

#define xenXMError(conn, code, fmt...)                                       \
        virReportErrorHelper(conn, VIR_FROM_XENXM, code, __FILE__,         \
                               __FUNCTION__, __LINE__, fmt)

#ifndef WITH_XEN_INOTIFY
static int xenInotifyActive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
   return 0;
}
#else
static int xenInotifyActive(virConnectPtr conn)
{
   xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;
   return priv->inotifyWatch > 0;
}
#endif

/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetBool(virConnectPtr conn,
                              virConfPtr conf,
                              const char *name,
                              int *value,
                              int def) {
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_LONG) {
        *value = val->l ? 1 : 0;
    } else if (val->type == VIR_CONF_STRING) {
        if (!val->str) {
            *value = def;
        }
        *value = STREQ(val->str, "1") ? 1 : 0;
    } else {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was malformed"), name);
        return -1;
    }
    return 0;
}


/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetULong(virConnectPtr conn,
                               virConfPtr conf,
                               const char *name,
                               unsigned long *value,
                               int def) {
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_LONG) {
        *value = val->l;
    } else if (val->type == VIR_CONF_STRING) {
        char *ret;
        if (!val->str) {
            *value = def;
        }
        *value = strtol(val->str, &ret, 10);
        if (ret == val->str) {
            xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was malformed"), name);
            return -1;
        }
    } else {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was malformed"), name);
        return -1;
    }
    return 0;
}


/* Convenience method to grab a string from the config file object */
static int xenXMConfigGetString(virConnectPtr conn,
                                virConfPtr conf,
                                const char *name,
                                const char **value,
                                const char *def) {
    virConfValuePtr val;

    *value = NULL;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type != VIR_CONF_STRING) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was malformed"), name);
        return -1;
    }
    if (!val->str)
        *value = def;
    else
        *value = val->str;
    return 0;
}

static int xenXMConfigCopyStringInternal(virConnectPtr conn,
                                         virConfPtr conf,
                                         const char *name,
                                         char **value,
                                         int allowMissing) {
    virConfValuePtr val;

    *value = NULL;
    if (!(val = virConfGetValue(conf, name))) {
        if (allowMissing)
            return 0;
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was missing"), name);
        return -1;
    }

    if (val->type != VIR_CONF_STRING) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was not a string"), name);
        return -1;
    }
    if (!val->str) {
        if (allowMissing)
            return 0;
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was missing"), name);
        return -1;
    }

    if (!(*value = strdup(val->str))) {
        virReportOOMError(conn);
        return -1;
    }

    return 0;
}


static int xenXMConfigCopyString(virConnectPtr conn,
                                 virConfPtr conf,
                                 const char *name,
                                 char **value) {
    return xenXMConfigCopyStringInternal(conn, conf, name, value, 0);
}

static int xenXMConfigCopyStringOpt(virConnectPtr conn,
                                    virConfPtr conf,
                                    const char *name,
                                    char **value) {
    return xenXMConfigCopyStringInternal(conn, conf, name, value, 1);
}


/* Convenience method to grab a string UUID from the config file object */
static int xenXMConfigGetUUID(virConfPtr conf, const char *name, unsigned char *uuid) {
    virConfValuePtr val;
    if (!uuid || !name || !conf)
        return (-1);
    if (!(val = virConfGetValue(conf, name))) {
        return (-1);
    }

    if (val->type != VIR_CONF_STRING)
        return (-1);
    if (!val->str)
        return (-1);

    if (virUUIDParse(val->str, uuid) < 0)
        return (-1);

    return (0);
}


/* Release memory associated with a cached config object */
static void xenXMConfigFree(void *payload, const char *key ATTRIBUTE_UNUSED) {
    xenXMConfCachePtr entry = (xenXMConfCachePtr)payload;
    virDomainDefFree(entry->def);
    VIR_FREE(entry);
}

struct xenXMConfigReaperData {
    xenUnifiedPrivatePtr priv;
    time_t now;
};

/* Remove any configs which were not refreshed recently */
static int xenXMConfigReaper(const void *payload, const char *key ATTRIBUTE_UNUSED, const void *data) {
    const struct xenXMConfigReaperData *args = data;
    xenXMConfCachePtr entry = (xenXMConfCachePtr)payload;

    /* We're going to purge this config file, so check if it
       is currently mapped as owner of a named domain. */
    if (entry->refreshedAt != args->now) {
        const char *olddomname = entry->def->name;
        char *nameowner = (char *)virHashLookup(args->priv->nameConfigMap, olddomname);
        if (nameowner && STREQ(nameowner, key)) {
            virHashRemoveEntry(args->priv->nameConfigMap, olddomname, NULL);
        }
        return (1);
    }
    return (0);
}


static virDomainDefPtr
xenXMConfigReadFile(virConnectPtr conn, const char *filename) {
    virConfPtr conf;
    virDomainDefPtr def;

    if (!(conf = virConfReadFile(filename, 0)))
        return NULL;

    def = xenXMDomainConfigParse(conn, conf);
    virConfFree(conf);

    return def;
}

static int
xenXMConfigSaveFile(virConnectPtr conn, const char *filename, virDomainDefPtr def) {
    virConfPtr conf;
    int ret;

    if (!(conf = xenXMDomainConfigFormat(conn, def)))
        return -1;

    ret = virConfWriteFile(filename, conf);
    virConfFree(conf);
    return ret;
}


/*
 * Caller must hold the lock on 'conn->privateData' before
 * calling this funtion
 */
int
xenXMConfigCacheRemoveFile(virConnectPtr conn,
                           const char *filename)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;

    entry = virHashLookup(priv->configCache, filename);
    if (!entry) {
        DEBUG("No config entry for %s", filename);
        return 0;
    }

    virHashRemoveEntry(priv->nameConfigMap, entry->def->name, NULL);
    virHashRemoveEntry(priv->configCache, filename, xenXMConfigFree);
    DEBUG("Removed %s %s", entry->def->name, filename);
    return 0;
}


/*
 * Caller must hold the lock on 'conn->privateData' before
 * calling this funtion
 */
int
xenXMConfigCacheAddFile(virConnectPtr conn, const char *filename)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;
    struct stat st;
    int newborn = 0;
    time_t now = time(NULL);

    DEBUG("Adding file %s", filename);

    /* Get modified time */
    if ((stat(filename, &st) < 0)) {
        virReportSystemError(conn, errno,
                             _("cannot stat: %s"),
                             filename);
        return -1;
    }

    /* Ignore zero length files, because inotify fires before
       any content has actually been created */
    if (st.st_size == 0) {
        DEBUG("Ignoring zero length file %s", filename);
        return -1;
    }

    /* If we already have a matching entry and it is not
    modified, then carry on to next one*/
    if ((entry = virHashLookup(priv->configCache, filename))) {
        char *nameowner;

        if (entry->refreshedAt >= st.st_mtime) {
            entry->refreshedAt = now;
            /* return success if up-to-date */
            return 0;
        }

        /* If we currently own the name, then release it and
            re-acquire it later - just in case it was renamed */
        nameowner = (char *)virHashLookup(priv->nameConfigMap, entry->def->name);
        if (nameowner && STREQ(nameowner, filename)) {
            virHashRemoveEntry(priv->nameConfigMap, entry->def->name, NULL);
        }

        /* Clear existing config entry which needs refresh */
        virDomainDefFree(entry->def);
        entry->def = NULL;
    } else { /* Completely new entry */
        newborn = 1;
        if (VIR_ALLOC(entry) < 0) {
            virReportOOMError(conn);
            return -1;
        }
        memcpy(entry->filename, filename, PATH_MAX);
    }
    entry->refreshedAt = now;

    if (!(entry->def = xenXMConfigReadFile(conn, entry->filename))) {
        DEBUG("Failed to read %s", entry->filename);
        if (!newborn)
            virHashRemoveEntry(priv->configCache, filename, NULL);
        VIR_FREE(entry);
        return -1;
    }

    /* If its a completely new entry, it must be stuck into
        the cache (refresh'd entries are already registered) */
    if (newborn) {
        if (virHashAddEntry(priv->configCache, entry->filename, entry) < 0) {
            virDomainDefFree(entry->def);
            VIR_FREE(entry);
            xenXMError (conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("xenXMConfigCacheRefresh: virHashAddEntry"));
            return -1;
        }
    }

    /* See if we need to map this config file in as the primary owner
        * of the domain in question
        */
    if (!virHashLookup(priv->nameConfigMap, entry->def->name)) {
        if (virHashAddEntry(priv->nameConfigMap, entry->def->name, entry->filename) < 0) {
            virHashRemoveEntry(priv->configCache, filename, NULL);
            virDomainDefFree(entry->def);
            VIR_FREE(entry);
        }
    }
    DEBUG("Added config %s %s", entry->def->name, filename);

    return 0;
}

/* This method is called by various methods to scan /etc/xen
 * (or whatever directory was set by  LIBVIRT_XM_CONFIG_DIR
 * environment variable) and process any domain configs. It
 * has rate-limited so never rescans more frequently than
 * once every X seconds
 *
 * Caller must hold the lock on 'conn->privateData' before
 * calling this funtion
 */
int xenXMConfigCacheRefresh (virConnectPtr conn) {
    xenUnifiedPrivatePtr priv = conn->privateData;
    DIR *dh;
    struct dirent *ent;
    time_t now = time(NULL);
    int ret = -1;
    struct xenXMConfigReaperData args;

    if (now == ((time_t)-1)) {
        virReportSystemError(conn, errno,
                             "%s", _("cannot get time of day"));
        return (-1);
    }

    /* Rate limit re-scans */
    if ((now - priv->lastRefresh) < XM_REFRESH_INTERVAL)
        return (0);

    priv->lastRefresh = now;

    /* Process the files in the config dir */
    if (!(dh = opendir(priv->configDir))) {
        virReportSystemError(conn, errno,
                             _("cannot read directory %s"),
                             priv->configDir);
        return (-1);
    }

    while ((ent = readdir(dh))) {
        struct stat st;
        char path[PATH_MAX];

        /*
         * Skip a bunch of crufty files that clearly aren't config files
         */

        /* Like 'dot' files... */
        if (STRPREFIX(ent->d_name, "."))
            continue;
        /* ...and the XenD server config file */
        if (STRPREFIX(ent->d_name, XEND_CONFIG_FILE))
            continue;
        /* ...and random PCI config cruft */
        if (STRPREFIX(ent->d_name, XEND_PCI_CONFIG_PREFIX))
            continue;
        /* ...and the example domain configs */
        if (STRPREFIX(ent->d_name, XM_EXAMPLE_PREFIX))
            continue;
        /* ...and the QEMU networking script */
        if (STRPREFIX(ent->d_name, QEMU_IF_SCRIPT))
            continue;

        /* ...and editor backups */
        if (ent->d_name[0] == '#')
            continue;
        if (ent->d_name[strlen(ent->d_name)-1] == '~')
            continue;

        /* Build the full file path */
        if ((strlen(priv->configDir) + 1 + strlen(ent->d_name) + 1) > PATH_MAX)
            continue;
        strcpy(path, priv->configDir);
        strcat(path, "/");
        strcat(path, ent->d_name);

        /* Skip anything which isn't a file (takes care of scripts/ subdir */
        if ((stat(path, &st) < 0) ||
            (!S_ISREG(st.st_mode))) {
            continue;
        }

        /* If we already have a matching entry and it is not
           modified, then carry on to next one*/
        if (xenXMConfigCacheAddFile(conn, path) < 0) {
            /* Ignoring errors, since alot of stuff goes wrong in /etc/xen */
        }
    }

    /* Reap all entries which were not changed, by comparing
       their refresh timestamp - the timestamp should match
       'now' if they were refreshed. If timestamp doesn't match
       then the config is no longer on disk */
    args.now = now;
    args.priv = priv;
    virHashRemoveSet(priv->configCache, xenXMConfigReaper, xenXMConfigFree, &args);
    ret = 0;

    if (dh)
        closedir(dh);

    return (ret);
}


/*
 * The XM driver keeps a cache of config files as virDomainDefPtr
 * objects in the xenUnifiedPrivatePtr. Optionally inotify lets
 * us watch for changes (see separate driver), otherwise we poll
 * every few seconds
 */
virDrvOpenStatus
xenXMOpen (virConnectPtr conn,
           virConnectAuthPtr auth ATTRIBUTE_UNUSED,
           int flags ATTRIBUTE_UNUSED)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    priv->configDir = XM_CONFIG_DIR;

    priv->configCache = virHashCreate(50);
    if (!priv->configCache)
        return (-1);
    priv->nameConfigMap = virHashCreate(50);
    if (!priv->nameConfigMap) {
        virHashFree(priv->configCache, NULL);
        priv->configCache = NULL;
        return (-1);
    }
    /* Force the cache to be reloaded next time that
     * xenXMConfigCacheRefresh is called.
     */
    priv->lastRefresh = 0;

    return (0);
}

/*
 * Free the cached config files associated with this
 * connection
 */
int xenXMClose(virConnectPtr conn) {
    xenUnifiedPrivatePtr priv = conn->privateData;

    virHashFree(priv->nameConfigMap, NULL);
    virHashFree(priv->configCache, xenXMConfigFree);

    return (0);
}

/*
 * Since these are all offline domains, we only return info about
 * VCPUs and memory.
 */
int xenXMDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return(-1);
    }

    if (domain->id != -1)
        return (-1);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto error;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto error;

    memset(info, 0, sizeof(virDomainInfo));
    info->maxMem = entry->def->maxmem;
    info->memory = entry->def->memory;
    info->nrVirtCpu = entry->def->vcpus;
    info->state = VIR_DOMAIN_SHUTOFF;
    info->cpuTime = 0;

    xenUnifiedUnlock(priv);
    return (0);

error:
    xenUnifiedUnlock(priv);
    return -1;
}

#define MAX_VFB 1024
/*
 * Turn a config record into a lump of XML describing the
 * domain, suitable for later feeding for virDomainCreateXML
 */
virDomainDefPtr
xenXMDomainConfigParse(virConnectPtr conn, virConfPtr conf) {
    const char *str;
    int hvm = 0;
    int val;
    virConfValuePtr list;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainDiskDefPtr disk = NULL;
    virDomainNetDefPtr net = NULL;
    virDomainGraphicsDefPtr graphics = NULL;
    virDomainHostdevDefPtr hostdev = NULL;
    int i;
    const char *defaultArch, *defaultMachine;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;

    if (xenXMConfigCopyString(conn, conf, "name", &def->name) < 0)
        goto cleanup;
    if (xenXMConfigGetUUID(conf, "uuid", def->uuid) < 0)
        goto cleanup;


    if ((xenXMConfigGetString(conn, conf, "builder", &str, "linux") == 0) &&
        STREQ(str, "hvm"))
        hvm = 1;

    if (!(def->os.type = strdup(hvm ? "hvm" : "xen")))
        goto no_memory;

    defaultArch = virCapabilitiesDefaultGuestArch(priv->caps, def->os.type, virDomainVirtTypeToString(def->virtType));
    if (defaultArch == NULL) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("no supported architecture for os type '%s'"),
                   def->os.type);
        goto cleanup;
    }
    if (!(def->os.arch = strdup(defaultArch)))
        goto no_memory;

    defaultMachine = virCapabilitiesDefaultGuestMachine(priv->caps,
                                                        def->os.type,
                                                        def->os.arch);
    if (defaultMachine != NULL) {
        if (!(def->os.machine = strdup(defaultMachine)))
            goto no_memory;
    }

    if (hvm) {
        const char *boot;
        if (xenXMConfigCopyString(conn, conf, "kernel", &def->os.loader) < 0)
            goto cleanup;

        if (xenXMConfigGetString(conn, conf, "boot", &boot, "c") < 0)
            goto cleanup;

        for (i = 0 ; i < VIR_DOMAIN_BOOT_LAST && boot[i] ; i++) {
            switch (*boot) {
            case 'a':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_FLOPPY;
                break;
            case 'd':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_CDROM;
                break;
            case 'n':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_NET;
                break;
            case 'c':
            default:
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_DISK;
                break;
            }
            def->os.nBootDevs++;
        }
    } else {
        if (xenXMConfigCopyStringOpt(conn, conf, "bootloader", &def->os.bootloader) < 0)
            goto cleanup;
        if (xenXMConfigCopyStringOpt(conn, conf, "bootargs", &def->os.bootloaderArgs) < 0)
            goto cleanup;

        if (xenXMConfigCopyStringOpt(conn, conf, "kernel", &def->os.kernel) < 0)
            goto cleanup;
        if (xenXMConfigCopyStringOpt(conn, conf, "ramdisk", &def->os.initrd) < 0)
            goto cleanup;
        if (xenXMConfigCopyStringOpt(conn, conf, "extra", &def->os.cmdline) < 0)
            goto cleanup;
    }

    if (xenXMConfigGetULong(conn, conf, "memory", &def->memory, MIN_XEN_GUEST_SIZE * 2) < 0)
        goto cleanup;

    if (xenXMConfigGetULong(conn, conf, "maxmem", &def->maxmem, def->memory) < 0)
        goto cleanup;

    def->memory *= 1024;
    def->maxmem *= 1024;


    if (xenXMConfigGetULong(conn, conf, "vcpus", &def->vcpus, 1) < 0)
        goto cleanup;

    if (xenXMConfigGetString(conn, conf, "cpus", &str, NULL) < 0)
        goto cleanup;
    if (str) {
        def->cpumasklen = 4096;
        if (VIR_ALLOC_N(def->cpumask, def->cpumasklen) < 0)
            goto no_memory;

        if (virDomainCpuSetParse(conn, &str, 0,
                                 def->cpumask, def->cpumasklen) < 0)
            goto cleanup;
    }


    if (xenXMConfigGetString(conn, conf, "on_poweroff", &str, "destroy") < 0)
        goto cleanup;
    if ((def->onPoweroff = virDomainLifecycleTypeFromString(str)) < 0) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unexpected value %s for on_poweroff"), str);
        goto cleanup;
    }

    if (xenXMConfigGetString(conn, conf, "on_reboot", &str, "restart") < 0)
        goto cleanup;
    if ((def->onReboot = virDomainLifecycleTypeFromString(str)) < 0) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unexpected value %s for on_reboot"), str);
        goto cleanup;
    }

    if (xenXMConfigGetString(conn, conf, "on_crash", &str, "restart") < 0)
        goto cleanup;
    if ((def->onCrash = virDomainLifecycleTypeFromString(str)) < 0) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unexpected value %s for on_crash"), str);
        goto cleanup;
    }



    if (hvm) {
        if (xenXMConfigGetBool(conn, conf, "pae", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);
        if (xenXMConfigGetBool(conn, conf, "acpi", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_ACPI);
        if (xenXMConfigGetBool(conn, conf, "apic", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_APIC);
    }
    if (xenXMConfigGetBool(conn, conf, "localtime", &def->localtime, 0) < 0)
        goto cleanup;

    if (xenXMConfigCopyStringOpt(conn, conf, "device_model", &def->emulator) < 0)
        goto cleanup;

    list = virConfGetValue(conf, "disk");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char *head;
            char *offset;
            char *tmp;

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipdisk;
            head = list->str;

            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            /*
             * Disks have 3 components, SOURCE,DEST-DEVICE,MODE
             * eg, phy:/dev/HostVG/XenGuest1,xvda,w
             * The SOURCE is usually prefixed with a driver type,
             * and optionally driver sub-type
             * The DEST-DEVICE is optionally post-fixed with disk type
             */

            /* Extract the source file path*/
            if (!(offset = strchr(head, ',')) || offset[0] == '\0')
                goto skipdisk;
            if ((offset - head) >= (PATH_MAX-1))
                goto skipdisk;

            if (offset == head) {
                disk->src = NULL; /* No source file given, eg CDROM with no media */
            } else {
                if (VIR_ALLOC_N(disk->src, (offset - head) + 1) < 0)
                    goto no_memory;
                strncpy(disk->src, head, (offset - head));
                disk->src[(offset-head)] = '\0';
            }
            head = offset + 1;

            /* Remove legacy ioemu: junk */
            if (STRPREFIX(head, "ioemu:"))
                head = head + 6;

            /* Extract the dest device name */
            if (!(offset = strchr(head, ',')) || offset[0] == '\0')
                goto skipdisk;
            if (VIR_ALLOC_N(disk->dst, (offset - head) + 1) < 0)
                goto no_memory;
            strncpy(disk->dst, head, (offset - head));
            disk->dst[(offset-head)] = '\0';
            head = offset + 1;


            /* Extract source driver type */
            if (disk->src) {
                /* The main type  phy:, file:, tap: ... */
                if ((tmp = strchr(disk->src, ':')) != NULL) {
                    if (VIR_ALLOC_N(disk->driverName, (tmp - disk->src) + 1) < 0)
                        goto no_memory;
                    strncpy(disk->driverName, disk->src, (tmp - disk->src));
                    disk->driverName[tmp - disk->src] = '\0';

                    /* Strip the prefix we found off the source file name */
                    memmove(disk->src, disk->src+(tmp-disk->src)+1,
                            strlen(disk->src)-(tmp-disk->src));
                }

                /* And the sub-type for tap:XXX: type */
                if (disk->driverName &&
                    STREQ(disk->driverName, "tap")) {
                    if (!(tmp = strchr(disk->src, ':')))
                        goto skipdisk;
                    if (VIR_ALLOC_N(disk->driverType, (tmp - disk->src) + 1) < 0)
                        goto no_memory;
                    strncpy(disk->driverType, disk->src, (tmp - disk->src));
                    disk->driverType[tmp - disk->src] = '\0';

                    /* Strip the prefix we found off the source file name */
                    memmove(disk->src, disk->src+(tmp-disk->src)+1,
                            strlen(disk->src)-(tmp-disk->src));
                }
            }

            /* No source, or driver name, so fix to phy: */
            if (!disk->driverName &&
                !(disk->driverName = strdup("phy")))
                goto no_memory;


            /* phy: type indicates a block device */
            disk->type = STREQ(disk->driverName, "phy") ?
                VIR_DOMAIN_DISK_TYPE_BLOCK : VIR_DOMAIN_DISK_TYPE_FILE;

            /* Check for a :cdrom/:disk postfix */
            disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
            if ((tmp = strchr(disk->dst, ':')) != NULL) {
                if (STREQ(tmp, ":cdrom"))
                    disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                tmp[0] = '\0';
            }

            if (STRPREFIX(disk->dst, "xvd") || !hvm) {
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            } else if (STRPREFIX(disk->dst, "sd")) {
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            } else {
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            }

            if (STREQ(head, "r") ||
                STREQ(head, "ro"))
                disk->readonly = 1;
            else if ((STREQ(head, "w!")) ||
                     (STREQ(head, "!")))
                disk->shared = 1;

            /* Maintain list in sorted order according to target device name */
            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;
            def->disks[def->ndisks++] = disk;
            disk = NULL;

            skipdisk:
            list = list->next;
            virDomainDiskDefFree(disk);
        }
    }

    if (hvm && priv->xendConfigVersion == 1) {
        if (xenXMConfigGetString(conn, conf, "cdrom", &str, NULL) < 0)
            goto cleanup;
        if (str) {
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            if (!(disk->driverName = strdup("file")))
                goto no_memory;
            if (!(disk->src = strdup(str)))
                goto no_memory;
            if (!(disk->dst = strdup("hdc")))
                goto no_memory;
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            disk->readonly = 1;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;
            def->disks[def->ndisks++] = disk;
            disk = NULL;
        }
    }
    qsort(def->disks, def->ndisks, sizeof(*def->disks),
          virDomainDiskQSort);

    list = virConfGetValue(conf, "vif");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            int type = -1;
            char script[PATH_MAX];
            char model[10];
            char ip[16];
            char mac[18];
            char bridge[50];
            char vifname[50];
            char *key;

            bridge[0] = '\0';
            mac[0] = '\0';
            script[0] = '\0';
            ip[0] = '\0';
            model[0] = '\0';
            vifname[0] = '\0';

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipnic;

            key = list->str;
            while (key) {
                char *data;
                char *nextkey = strchr(key, ',');

                if (!(data = strchr(key, '=')) || (data[0] == '\0'))
                    goto skipnic;
                data++;

                if (STRPREFIX(key, "mac=")) {
                    int len = nextkey ? (nextkey - data) : 17;
                    if (len > 17)
                        len = 17;
                    strncpy(mac, data, len);
                    mac[len] = '\0';
                } else if (STRPREFIX(key, "bridge=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(bridge)-1;
                    type = 1;
                    if (len > (sizeof(bridge)-1))
                        len = sizeof(bridge)-1;
                    strncpy(bridge, data, len);
                    bridge[len] = '\0';
                } else if (STRPREFIX(key, "script=")) {
                    int len = nextkey ? (nextkey - data) : PATH_MAX-1;
                    if (len > (PATH_MAX-1))
                        len = PATH_MAX-1;
                    strncpy(script, data, len);
                    script[len] = '\0';
                } else if (STRPREFIX(key, "model=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(model)-1;
                    if (len > (sizeof(model)-1))
                        len = sizeof(model)-1;
                    strncpy(model, data, len);
                    model[len] = '\0';
                } else if (STRPREFIX(key, "vifname=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(vifname)-1;
                    if (len > (sizeof(vifname)-1))
                        len = sizeof(vifname)-1;
                    strncpy(vifname, data, len);
                    vifname[len] = '\0';
                } else if (STRPREFIX(key, "ip=")) {
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

            if (VIR_ALLOC(net) < 0)
                goto cleanup;

            if (mac[0]) {
                unsigned int rawmac[6];
                sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                       (unsigned int*)&rawmac[0],
                       (unsigned int*)&rawmac[1],
                       (unsigned int*)&rawmac[2],
                       (unsigned int*)&rawmac[3],
                       (unsigned int*)&rawmac[4],
                       (unsigned int*)&rawmac[5]);
                net->mac[0] = rawmac[0];
                net->mac[1] = rawmac[1];
                net->mac[2] = rawmac[2];
                net->mac[3] = rawmac[3];
                net->mac[4] = rawmac[4];
                net->mac[5] = rawmac[5];
            }

            if (bridge[0] || STREQ(script, "vif-bridge") ||
                STREQ(script, "vif-vnic")) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            }

            if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                if (bridge[0] &&
                    !(net->data.bridge.brname = strdup(bridge)))
                    goto no_memory;
                if (script[0] &&
                    !(net->data.bridge.script = strdup(script)))
                    goto no_memory;
                if (ip[0] &&
                    !(net->data.bridge.ipaddr = strdup(ip)))
                    goto no_memory;
            } else {
                if (script[0] &&
                    !(net->data.ethernet.script = strdup(script)))
                    goto no_memory;
                if (ip[0] &&
                    !(net->data.ethernet.ipaddr = strdup(ip)))
                    goto no_memory;
            }
            if (model[0] &&
                !(net->model = strdup(model)))
                goto no_memory;

            if (vifname[0] &&
                !(net->ifname = strdup(vifname)))
                goto no_memory;

            if (VIR_REALLOC_N(def->nets, def->nnets+1) < 0)
                goto no_memory;
            def->nets[def->nnets++] = net;
            net = NULL;

        skipnic:
            list = list->next;
            virDomainNetDefFree(net);
        }
    }

    list = virConfGetValue(conf, "pci");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char domain[5];
            char bus[3];
            char slot[3];
            char func[2];
            char *key, *nextkey;
            int domainID;
            int busID;
            int slotID;
            int funcID;

            domain[0] = bus[0] = slot[0] = func[0] = '\0';

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skippci;

            /* pci=['0000:00:1b.0','0000:00:13.0'] */
            key = list->str;
            if (!(key = list->str))
                goto skippci;
            if (!(nextkey = strchr(key, ':')))
                goto skippci;

            if ((nextkey - key) > (sizeof(domain)-1))
                goto skippci;

            strncpy(domain, key, sizeof(domain));
            domain[sizeof(domain)-1] = '\0';

            key = nextkey + 1;
            if (!(nextkey = strchr(key, ':')))
                goto skippci;

            strncpy(bus, key, sizeof(bus));
            bus[sizeof(bus)-1] = '\0';

            key = nextkey + 1;
            if (!(nextkey = strchr(key, '.')))
                goto skippci;

            strncpy(slot, key, sizeof(slot));
            slot[sizeof(slot)-1] = '\0';

            key = nextkey + 1;
            if (strlen(key) != 1)
                goto skippci;

            strncpy(func, key, sizeof(func));
            func[sizeof(func)-1] = '\0';

            if (virStrToLong_i(domain, NULL, 16, &domainID) < 0)
                goto skippci;
            if (virStrToLong_i(bus, NULL, 16, &busID) < 0)
                goto skippci;
            if (virStrToLong_i(slot, NULL, 16, &slotID) < 0)
                goto skippci;
            if (virStrToLong_i(func, NULL, 16, &funcID) < 0)
                goto skippci;

            if (VIR_ALLOC(hostdev) < 0)
                goto cleanup;

            hostdev->managed = 0;
            hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
            hostdev->source.subsys.u.pci.domain = domainID;
            hostdev->source.subsys.u.pci.bus = busID;
            hostdev->source.subsys.u.pci.slot = slotID;
            hostdev->source.subsys.u.pci.function = funcID;

            if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0)
                goto no_memory;
            def->hostdevs[def->nhostdevs++] = hostdev;
            hostdev = NULL;

        skippci:
            list = list->next;
        }
    }

    if (hvm) {
        if (xenXMConfigGetString(conn, conf, "usbdevice", &str, NULL) < 0)
            goto cleanup;
        if (str &&
            (STREQ(str, "tablet") ||
             STREQ(str, "mouse"))) {
            virDomainInputDefPtr input;
            if (VIR_ALLOC(input) < 0)
                goto no_memory;
            input->bus = VIR_DOMAIN_INPUT_BUS_USB;
            input->type = STREQ(str, "tablet") ?
                VIR_DOMAIN_INPUT_TYPE_TABLET :
                VIR_DOMAIN_INPUT_TYPE_MOUSE;
            if (VIR_ALLOC_N(def->inputs, 1) < 0) {
                virDomainInputDefFree(input);
                goto no_memory;
            }
            def->inputs[0] = input;
            def->ninputs = 1;
        }
    }

    /* HVM guests, or old PV guests use this config format */
    if (hvm || priv->xendConfigVersion < 3) {
        if (xenXMConfigGetBool(conn, conf, "vnc", &val, 0) < 0)
            goto cleanup;

        if (val) {
            if (VIR_ALLOC(graphics) < 0)
                goto no_memory;
            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
            if (xenXMConfigGetBool(conn, conf, "vncunused", &val, 1) < 0)
                goto cleanup;
            graphics->data.vnc.autoport = val ? 1 : 0;

            if (!graphics->data.vnc.autoport) {
                unsigned long vncdisplay;
                if (xenXMConfigGetULong(conn, conf, "vncdisplay", &vncdisplay, 0) < 0)
                    goto cleanup;
                graphics->data.vnc.port = (int)vncdisplay + 5900;
            }
            if (xenXMConfigCopyStringOpt(conn, conf, "vnclisten", &graphics->data.vnc.listenAddr) < 0)
                goto cleanup;
            if (xenXMConfigCopyStringOpt(conn, conf, "vncpasswd", &graphics->data.vnc.passwd) < 0)
                goto cleanup;
            if (xenXMConfigCopyStringOpt(conn, conf, "keymap", &graphics->data.vnc.keymap) < 0)
                goto cleanup;

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto no_memory;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        } else {
            if (xenXMConfigGetBool(conn, conf, "sdl", &val, 0) < 0)
                goto cleanup;
            if (val) {
                if (VIR_ALLOC(graphics) < 0)
                    goto no_memory;
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
                if (xenXMConfigCopyStringOpt(conn, conf, "display", &graphics->data.sdl.display) < 0)
                    goto cleanup;
                if (xenXMConfigCopyStringOpt(conn, conf, "xauthority", &graphics->data.sdl.xauth) < 0)
                    goto cleanup;
                if (VIR_ALLOC_N(def->graphics, 1) < 0)
                    goto no_memory;
                def->graphics[0] = graphics;
                def->ngraphics = 1;
                graphics = NULL;
            }
        }
    }

    if (!hvm && def->graphics == NULL) { /* New PV guests use this format */
        list = virConfGetValue(conf, "vfb");
        if (list && list->type == VIR_CONF_LIST &&
            list->list && list->list->type == VIR_CONF_STRING &&
            list->list->str) {
            char vfb[MAX_VFB];
            char *key = vfb;
            strncpy(vfb, list->list->str, MAX_VFB-1);
            vfb[MAX_VFB-1] = '\0';

            if (VIR_ALLOC(graphics) < 0)
                goto no_memory;

            if (strstr(key, "type=sdl"))
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
            else
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

            while (key) {
                char *data;
                char *nextkey = strchr(key, ',');
                char *end = nextkey;
                if (nextkey) {
                    *end = '\0';
                    nextkey++;
                }

                if (!(data = strchr(key, '=')) || (data[0] == '\0'))
                    break;
                data++;

                if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
                    if (STRPREFIX(key, "vncunused=")) {
                        if (STREQ(key + 10, "1"))
                            graphics->data.vnc.autoport = 1;
                    } else if (STRPREFIX(key, "vnclisten=")) {
                        if (!(graphics->data.vnc.listenAddr = strdup(key + 10)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "vncpasswd=")) {
                        if (!(graphics->data.vnc.passwd = strdup(key + 10)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "keymap=")) {
                        if (!(graphics->data.vnc.keymap = strdup(key + 7)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "vncdisplay=")) {
                        graphics->data.vnc.port = strtol(key+11, NULL, 10) + 5900;
                    }
                } else {
                    if (STRPREFIX(key, "display=")) {
                        if (!(graphics->data.sdl.display = strdup(key + 8)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "xauthority=")) {
                        if (!(graphics->data.sdl.xauth = strdup(key + 11)))
                            goto no_memory;
                    }
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }
            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto no_memory;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        }
    }

    if (hvm) {
        virDomainChrDefPtr chr = NULL;

        if (xenXMConfigGetString(conn, conf, "parallel", &str, NULL) < 0)
            goto cleanup;
        if (str && STRNEQ(str, "none") &&
            !(chr = xenDaemonParseSxprChar(conn, str, NULL)))
            goto cleanup;

        if (chr) {
            if (VIR_ALLOC_N(def->parallels, 1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            def->parallels[0] = chr;
            def->nparallels++;
            chr = NULL;
        }

        if (xenXMConfigGetString(conn, conf, "serial", &str, NULL) < 0)
            goto cleanup;
        if (str && STRNEQ(str, "none") &&
            !(chr = xenDaemonParseSxprChar(conn, str, NULL)))
            goto cleanup;

        if (chr) {
            if (VIR_ALLOC_N(def->serials, 1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            def->serials[0] = chr;
            def->nserials++;
        }
    } else {
        if (!(def->console = xenDaemonParseSxprChar(conn, "pty", NULL)))
            goto cleanup;
    }

    if (hvm) {
        if (xenXMConfigGetString(conn, conf, "soundhw", &str, NULL) < 0)
            goto cleanup;

        if (str &&
            xenDaemonParseSxprSound(conn, def, str) < 0)
            goto cleanup;
    }

    return def;

no_memory:
    virReportOOMError(conn);
    /* fallthrough */
  cleanup:
    virDomainGraphicsDefFree(graphics);
    virDomainNetDefFree(net);
    virDomainDiskDefFree(disk);
    virDomainDefFree(def);
    return NULL;
}


/*
 * Turn a config record into a lump of XML describing the
 * domain, suitable for later feeding for virDomainCreateXML
 */
char *xenXMDomainDumpXML(virDomainPtr domain, int flags) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    char *ret = NULL;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return(NULL);
    }
    if (domain->id != -1)
        return (NULL);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    ret = virDomainDefFormat(domain->conn, entry->def, flags);

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}


/*
 * Update amount of memory in the config file
 */
int xenXMDomainSetMemory(virDomainPtr domain, unsigned long memory) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);
    if (domain->id != -1)
        return (-1);
    if (memory < 1024 * MIN_XEN_GUEST_SIZE)
        return (-1);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    entry->def->memory = memory;
    if (entry->def->memory > entry->def->maxmem)
        entry->def->memory = entry->def->maxmem;

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(domain->conn, entry->filename, entry->def) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Update maximum memory limit in config
 */
int xenXMDomainSetMaxMemory(virDomainPtr domain, unsigned long memory) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);
    if (domain->id != -1)
        return (-1);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    entry->def->maxmem = memory;
    if (entry->def->memory > entry->def->maxmem)
        entry->def->memory = entry->def->maxmem;

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(domain->conn, entry->filename, entry->def) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Get max memory limit from config
 */
unsigned long xenXMDomainGetMaxMemory(virDomainPtr domain) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    unsigned long ret = 0;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (0);
    }
    if (domain->id != -1)
        return (0);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    ret = entry->def->maxmem;

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Set the VCPU count in config
 */
int xenXMDomainSetVcpus(virDomainPtr domain, unsigned int vcpus) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);
    if (domain->id != -1)
        return (-1);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    entry->def->vcpus = vcpus;

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(domain->conn, entry->filename, entry->def) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/**
 * xenXMDomainPinVcpu:
 * @domain: pointer to domain object
 * @vcpu: virtual CPU number (reserved)
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes)
 * @maplen: length of cpumap in bytes
 *
 * Set the vcpu affinity in config
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int xenXMDomainPinVcpu(virDomainPtr domain,
                       unsigned int vcpu ATTRIBUTE_UNUSED,
                       unsigned char *cpumap, int maplen)
{
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    virBuffer mapbuf = VIR_BUFFER_INITIALIZER;
    char *mapstr = NULL, *mapsave = NULL;
    int i, j, n, comma = 0;
    int ret = -1;
    char *cpuset = NULL;
    int maxcpu = XEN_MAX_PHYSICAL_CPU;

    if (domain == NULL || domain->conn == NULL || domain->name == NULL
        || cpumap == NULL || maplen < 1 || maplen > (int)sizeof(cpumap_t)) {
        xenXMError(domain ? domain->conn : NULL, VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        xenXMError (domain->conn, VIR_ERR_INVALID_ARG,
                    "%s", _("read only connection"));
        return -1;
    }
    if (domain->id != -1) {
        xenXMError (domain->conn, VIR_ERR_INVALID_ARG,
                    "%s", _("not inactive domain"));
        return -1;
    }

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name))) {
        xenXMError (domain->conn, VIR_ERR_INTERNAL_ERROR, "%s", _("virHashLookup"));
        goto cleanup;
    }
    if (!(entry = virHashLookup(priv->configCache, filename))) {
        xenXMError (domain->conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("can't retrieve config file for domain"));
        goto cleanup;
    }

    /* from bit map, build character string of mapped CPU numbers */
    for (i = 0; i < maplen; i++)
        for (j = 0; j < 8; j++)
            if ((cpumap[i] & (1 << j))) {
                n = i*8 + j;

                if (comma)
                    virBufferAddLit (&mapbuf, ",");
                comma = 1;

                virBufferVSprintf (&mapbuf, "%d", n);
            }

    if (virBufferError(&mapbuf)) {
        virReportOOMError(domain->conn);
        goto cleanup;
    }

    mapstr = virBufferContentAndReset(&mapbuf);
    mapsave = mapstr;

    if (VIR_ALLOC_N(cpuset, maxcpu) < 0) {
        virReportOOMError(domain->conn);
        goto cleanup;
    }
    if (virDomainCpuSetParse(domain->conn,
                             (const char **)&mapstr, 0,
                             cpuset, maxcpu) < 0)
        goto cleanup;

    VIR_FREE(entry->def->cpumask);
    entry->def->cpumask = cpuset;
    entry->def->cpumasklen = maxcpu;
    cpuset = NULL;

    if (xenXMConfigSaveFile(domain->conn, entry->filename, entry->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(mapsave);
    VIR_FREE(cpuset);
    xenUnifiedUnlock(priv);
    return (ret);
}

/*
 * Find an inactive domain based on its name
 */
virDomainPtr xenXMDomainLookupByName(virConnectPtr conn, const char *domname) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    virDomainPtr ret = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (domname == NULL) {
        xenXMError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    priv = conn->privateData;
    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh (conn) < 0)
        goto cleanup;

    if (!(filename = virHashLookup(priv->nameConfigMap, domname)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    if (!(ret = virGetDomain(conn, domname, entry->def->uuid)))
        goto cleanup;

    /* Ensure its marked inactive, because may be cached
       handle to a previously active domain */
    ret->id = -1;

cleanup:
    xenUnifiedUnlock(priv);
    return (ret);
}


/*
 * Hash table iterator to search for a domain based on UUID
 */
static int xenXMDomainSearchForUUID(const void *payload, const char *name ATTRIBUTE_UNUSED, const void *data) {
    const unsigned char *wantuuid = (const unsigned char *)data;
    const xenXMConfCachePtr entry = (const xenXMConfCachePtr)payload;

    if (!memcmp(entry->def->uuid, wantuuid, VIR_UUID_BUFLEN))
        return (1);

    return (0);
}

/*
 * Find an inactive domain based on its UUID
 */
virDomainPtr xenXMDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid) {
    xenUnifiedPrivatePtr priv;
    xenXMConfCachePtr entry;
    virDomainPtr ret = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        xenXMError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    priv = conn->privateData;
    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh (conn) < 0)
        goto cleanup;

    if (!(entry = virHashSearch(priv->configCache, xenXMDomainSearchForUUID, (const void *)uuid)))
        goto cleanup;

    if (!(ret = virGetDomain(conn, entry->def->name, uuid)))
        goto cleanup;

    /* Ensure its marked inactive, because may be cached
       handle to a previously active domain */
    ret->id = -1;

cleanup:
    xenUnifiedUnlock(priv);
    return (ret);
}


/*
 * Start a domain from an existing defined config file
 */
int xenXMDomainCreate(virDomainPtr domain) {
    char *sexpr;
    int ret = -1;
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id != -1)
        return (-1);

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto error;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto error;

    if (!(sexpr = xenDaemonFormatSxpr(domain->conn, entry->def, priv->xendConfigVersion)))
        goto error;

    ret = xenDaemonDomainCreateXML(domain->conn, sexpr);
    VIR_FREE(sexpr);
    if (ret != 0)
        goto error;

    if ((ret = xenDaemonDomainLookupByName_ids(domain->conn, domain->name,
                                               entry->def->uuid)) < 0)
        goto error;
    domain->id = ret;

    if ((ret = xend_wait_for_devices(domain->conn, domain->name)) < 0)
        goto error;

    if ((ret = xenDaemonDomainResume(domain)) < 0)
        goto error;

    xenUnifiedUnlock(priv);
    return (0);

 error:
    if (domain->id != -1) {
        xenDaemonDomainDestroy(domain);
        domain->id = -1;
    }
    xenUnifiedUnlock(priv);
    return (-1);
}


static
int xenXMConfigSetInt(virConfPtr conf, const char *setting, long l) {
    virConfValuePtr value = NULL;

    if (VIR_ALLOC(value) < 0)
        return -1;

    value->type = VIR_CONF_LONG;
    value->next = NULL;
    value->l = l;

    return virConfSetValue(conf, setting, value);
}


static
int xenXMConfigSetString(virConfPtr conf, const char *setting, const char *str) {
    virConfValuePtr value = NULL;

    if (VIR_ALLOC(value) < 0)
        return -1;

    value->type = VIR_CONF_STRING;
    value->next = NULL;
    if (!(value->str = strdup(str))) {
        VIR_FREE(value);
        return -1;
    }

    return virConfSetValue(conf, setting, value);
}


static int xenXMDomainConfigFormatDisk(virConnectPtr conn,
                                       virConfValuePtr list,
                                       virDomainDiskDefPtr disk,
                                       int hvm,
                                       int xendConfigVersion)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    char *str;

    if(disk->src) {
        if (disk->driverName) {
            virBufferVSprintf(&buf, "%s:", disk->driverName);
            if (STREQ(disk->driverName, "tap"))
                virBufferVSprintf(&buf, "%s:", disk->driverType ? disk->driverType : "aio");
        } else {
            virBufferVSprintf(&buf, "%s:",
                              disk->type == VIR_DOMAIN_DISK_TYPE_FILE ?
                              "file" : "phy");
        }
        virBufferVSprintf(&buf, "%s", disk->src);
    }
    virBufferAddLit(&buf, ",");
    if (hvm && xendConfigVersion == 1)
        virBufferAddLit(&buf, "ioemu:");

    virBufferVSprintf(&buf, "%s", disk->dst);
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&buf, ":cdrom");

    if (disk->readonly)
        virBufferAddLit(&buf, ",r");
    else if (disk->shared)
        virBufferAddLit(&buf, ",!");
    else
        virBufferAddLit(&buf, ",w");

    if (virBufferError(&buf)) {
        virReportOOMError(conn);
        return -1;
    }

    if (VIR_ALLOC(val) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;

    return 0;

cleanup:
    str = virBufferContentAndReset(&buf);
    VIR_FREE(str);
    return -1;
}

static int xenXMDomainConfigFormatNet(virConnectPtr conn,
                                      virConfValuePtr list,
                                      virDomainNetDefPtr net,
                                      int hvm)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    char *str;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    virBufferVSprintf(&buf, "mac=%02x:%02x:%02x:%02x:%02x:%02x",
                      net->mac[0], net->mac[1],
                      net->mac[2], net->mac[3],
                      net->mac[4], net->mac[5]);

    switch (net->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferVSprintf(&buf, ",bridge=%s", net->data.bridge.brname);
        if (net->data.bridge.ipaddr)
            virBufferVSprintf(&buf, ",ip=%s", net->data.bridge.ipaddr);
        virBufferVSprintf(&buf, ",script=%s", DEFAULT_VIF_SCRIPT);
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (net->data.ethernet.script)
            virBufferVSprintf(&buf, ",script=%s", net->data.ethernet.script);
        if (net->data.ethernet.ipaddr)
            virBufferVSprintf(&buf, ",ip=%s", net->data.ethernet.ipaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
    {
        virNetworkPtr network = virNetworkLookupByName(conn, net->data.network.name);
        char *bridge;
        if (!network) {
            xenXMError(conn, VIR_ERR_NO_NETWORK, "%s",
                       net->data.network.name);
            return -1;
        }
        bridge = virNetworkGetBridgeName(network);
        virNetworkFree(network);
        if (!bridge) {
            xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                       _("network %s is not active"),
                       net->data.network.name);
            return -1;
        }

        virBufferVSprintf(&buf, ",bridge=%s", bridge);
        virBufferVSprintf(&buf, ",script=%s", DEFAULT_VIF_SCRIPT);
    }
    break;

    default:
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unsupported network type %d"),
                   net->type);
        goto cleanup;
    }

    if (hvm && priv->xendConfigVersion <= XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU)
        virBufferAddLit(&buf, ",type=ioemu");

    if (net->model)
        virBufferVSprintf(&buf, ",model=%s",
                          net->model);

    if (net->ifname)
        virBufferVSprintf(&buf, ",vifname=%s",
                          net->ifname);

    if (VIR_ALLOC(val) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;

    return 0;

cleanup:
    str = virBufferContentAndReset(&buf);
    VIR_FREE(str);
    return -1;
}



static int
xenXMDomainConfigFormatPCI(virConnectPtr conn,
                           virConfPtr conf,
                           virDomainDefPtr def)
{

    virConfValuePtr pciVal = NULL;
    int hasPCI = 0;
    int i;

    for (i = 0 ; i < def->nhostdevs ; i++)
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            hasPCI = 1;

    if (!hasPCI)
        return 0;

    if (VIR_ALLOC(pciVal) < 0)
        return -1;

    pciVal->type = VIR_CONF_LIST;
    pciVal->list = NULL;

    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            virConfValuePtr val, tmp;
            char *buf;

            if (virAsprintf(&buf, "%04x:%02x:%02x.%x",
                            def->hostdevs[i]->source.subsys.u.pci.domain,
                            def->hostdevs[i]->source.subsys.u.pci.bus,
                            def->hostdevs[i]->source.subsys.u.pci.slot,
                            def->hostdevs[i]->source.subsys.u.pci.function) < 0)
                goto error;

            if (VIR_ALLOC(val) < 0) {
                VIR_FREE(buf);
                virReportOOMError(conn);
                goto error;
            }
            val->type = VIR_CONF_STRING;
            val->str = buf;
            tmp = pciVal->list;
            while (tmp && tmp->next)
                tmp = tmp->next;
            if (tmp)
                tmp->next = val;
            else
                pciVal->list = val;
        }
    }

    if (pciVal->list != NULL) {
        int ret = virConfSetValue(conf, "pci", pciVal);
        pciVal = NULL;
        if (ret < 0)
            return -1;
    }
    VIR_FREE(pciVal);

    return 0;

error:
    virConfFreeValue(pciVal);
    return -1;
}


virConfPtr xenXMDomainConfigFormat(virConnectPtr conn,
                                   virDomainDefPtr def) {
    virConfPtr conf = NULL;
    int hvm = 0, i;
    xenUnifiedPrivatePtr priv;
    char *cpus = NULL;
    const char *lifecycle;
    char uuid[VIR_UUID_STRING_BUFLEN];
    virConfValuePtr diskVal = NULL;
    virConfValuePtr netVal = NULL;

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (!(conf = virConfNew()))
        goto cleanup;


    if (xenXMConfigSetString(conf, "name", def->name) < 0)
        goto no_memory;

    virUUIDFormat(def->uuid, uuid);
    if (xenXMConfigSetString(conf, "uuid", uuid) < 0)
        goto no_memory;

    if (xenXMConfigSetInt(conf, "maxmem", def->maxmem / 1024) < 0)
        goto no_memory;

    if (xenXMConfigSetInt(conf, "memory", def->memory / 1024) < 0)
        goto no_memory;

    if (xenXMConfigSetInt(conf, "vcpus", def->vcpus) < 0)
        goto no_memory;

    if (def->cpumask &&
        !(cpus = virDomainCpuSetFormat(conn, def->cpumask, def->cpumasklen)) < 0)
        goto cleanup;

    if (cpus &&
        xenXMConfigSetString(conf, "cpus", cpus) < 0)
        goto no_memory;
    VIR_FREE(cpus);

    hvm = STREQ(def->os.type, "hvm") ? 1 : 0;

    if (hvm) {
        char boot[VIR_DOMAIN_BOOT_LAST+1];
        if (xenXMConfigSetString(conf, "builder", "hvm") < 0)
            goto no_memory;

        if (def->os.loader &&
            xenXMConfigSetString(conf, "kernel", def->os.loader) < 0)
            goto no_memory;

        for (i = 0 ; i < def->os.nBootDevs ; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case VIR_DOMAIN_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case VIR_DOMAIN_BOOT_NET:
                boot[i] = 'n';
                break;
            case VIR_DOMAIN_BOOT_DISK:
            default:
                boot[i] = 'c';
                break;
            }
        }
        if (!def->os.nBootDevs) {
            boot[0] = 'c';
            boot[1] = '\0';
        } else {
            boot[def->os.nBootDevs] = '\0';
        }

        if (xenXMConfigSetString(conf, "boot", boot) < 0)
            goto no_memory;

        if (xenXMConfigSetInt(conf, "pae",
                              (def->features &
                               (1 << VIR_DOMAIN_FEATURE_PAE)) ? 1 : 0) < 0)
            goto no_memory;

        if (xenXMConfigSetInt(conf, "acpi",
                              (def->features &
                               (1 << VIR_DOMAIN_FEATURE_ACPI)) ? 1 : 0) < 0)
            goto no_memory;

        if (xenXMConfigSetInt(conf, "apic",
                              (def->features &
                               (1 << VIR_DOMAIN_FEATURE_APIC)) ? 1 : 0) < 0)
            goto no_memory;


        if (xenXMConfigSetInt(conf, "localtime", def->localtime ? 1 : 0) < 0)
            goto no_memory;

        if (priv->xendConfigVersion == 1) {
            for (i = 0 ; i < def->ndisks ; i++) {
                if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
                    def->disks[i]->dst &&
                    STREQ(def->disks[i]->dst, "hdc") &&
                    def->disks[i]->src) {
                    if (xenXMConfigSetString(conf, "cdrom",
                                             def->disks[i]->src) < 0)
                        goto no_memory;
                    break;
                }
            }
        }

        /* XXX floppy disks */
    } else {
        if (def->os.bootloader &&
            xenXMConfigSetString(conf, "bootloader", def->os.bootloader) < 0)
            goto no_memory;
        if (def->os.bootloaderArgs &&
            xenXMConfigSetString(conf, "bootloader_args", def->os.bootloaderArgs) < 0)
            goto no_memory;
        if (def->os.kernel &&
            xenXMConfigSetString(conf, "kernel", def->os.kernel) < 0)
            goto no_memory;
        if (def->os.initrd &&
            xenXMConfigSetString(conf, "ramdisk", def->os.initrd) < 0)
            goto no_memory;
        if (def->os.cmdline &&
            xenXMConfigSetString(conf, "extra", def->os.cmdline) < 0)
            goto no_memory;

    }

    if (!(lifecycle = virDomainLifecycleTypeToString(def->onPoweroff))) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unexpected lifecycle action %d"), def->onPoweroff);
        goto cleanup;
    }
    if (xenXMConfigSetString(conf, "on_poweroff", lifecycle) < 0)
        goto no_memory;


    if (!(lifecycle = virDomainLifecycleTypeToString(def->onReboot))) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unexpected lifecycle action %d"), def->onReboot);
        goto cleanup;
    }
    if (xenXMConfigSetString(conf, "on_reboot", lifecycle) < 0)
        goto no_memory;


    if (!(lifecycle = virDomainLifecycleTypeToString(def->onCrash))) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   _("unexpected lifecycle action %d"), def->onCrash);
        goto cleanup;
    }
    if (xenXMConfigSetString(conf, "on_crash", lifecycle) < 0)
        goto no_memory;



    if (hvm) {
        if (def->emulator &&
            xenXMConfigSetString(conf, "device_model", def->emulator) < 0)
            goto no_memory;

        for (i = 0 ; i < def->ninputs ; i++) {
            if (def->inputs[i]->bus == VIR_DOMAIN_INPUT_BUS_USB) {
                if (xenXMConfigSetInt(conf, "usb", 1) < 0)
                    goto no_memory;
                if (xenXMConfigSetString(conf, "usbdevice",
                                         def->inputs[i]->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ?
                                         "mouse" : "tablet") < 0)
                    goto no_memory;
                break;
            }
        }
    }

    if (def->ngraphics == 1) {
        if (priv->xendConfigVersion < (hvm ? 4 : XEND_CONFIG_MIN_VERS_PVFB_NEWCONF)) {
            if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                if (xenXMConfigSetInt(conf, "sdl", 1) < 0)
                    goto no_memory;
                if (xenXMConfigSetInt(conf, "vnc", 0) < 0)
                    goto no_memory;
                if (def->graphics[0]->data.sdl.display &&
                    xenXMConfigSetString(conf, "display",
                                     def->graphics[0]->data.sdl.display) < 0)
                    goto no_memory;
                if (def->graphics[0]->data.sdl.xauth &&
                    xenXMConfigSetString(conf, "xauthority",
                                         def->graphics[0]->data.sdl.xauth) < 0)
                    goto no_memory;
            } else {
                if (xenXMConfigSetInt(conf, "sdl", 0) < 0)
                    goto no_memory;
                if (xenXMConfigSetInt(conf, "vnc", 1) < 0)
                    goto no_memory;
                if (xenXMConfigSetInt(conf, "vncunused",
                              def->graphics[0]->data.vnc.autoport ? 1 : 0) < 0)
                    goto no_memory;
                if (!def->graphics[0]->data.vnc.autoport &&
                    xenXMConfigSetInt(conf, "vncdisplay",
                                  def->graphics[0]->data.vnc.port - 5900) < 0)
                    goto no_memory;
                if (def->graphics[0]->data.vnc.listenAddr &&
                    xenXMConfigSetString(conf, "vnclisten",
                                    def->graphics[0]->data.vnc.listenAddr) < 0)
                    goto no_memory;
                if (def->graphics[0]->data.vnc.passwd &&
                    xenXMConfigSetString(conf, "vncpasswd",
                                        def->graphics[0]->data.vnc.passwd) < 0)
                    goto no_memory;
                if (def->graphics[0]->data.vnc.keymap &&
                    xenXMConfigSetString(conf, "keymap",
                                        def->graphics[0]->data.vnc.keymap) < 0)
                    goto no_memory;
            }
        } else {
            virConfValuePtr vfb, disp;
            char *vfbstr = NULL;
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                virBufferAddLit(&buf, "type=sdl");
                if (def->graphics[0]->data.sdl.display)
                    virBufferVSprintf(&buf, ",display=%s",
                                      def->graphics[0]->data.sdl.display);
                if (def->graphics[0]->data.sdl.xauth)
                    virBufferVSprintf(&buf, ",xauthority=%s",
                                      def->graphics[0]->data.sdl.xauth);
            } else {
                virBufferAddLit(&buf, "type=vnc");
                virBufferVSprintf(&buf, ",vncunused=%d",
                                  def->graphics[0]->data.vnc.autoport ? 1 : 0);
                if (!def->graphics[0]->data.vnc.autoport)
                    virBufferVSprintf(&buf, ",vncdisplay=%d",
                                      def->graphics[0]->data.vnc.port - 5900);
                if (def->graphics[0]->data.vnc.listenAddr)
                    virBufferVSprintf(&buf, ",vnclisten=%s",
                                      def->graphics[0]->data.vnc.listenAddr);
                if (def->graphics[0]->data.vnc.passwd)
                    virBufferVSprintf(&buf, ",vncpasswd=%s",
                                      def->graphics[0]->data.vnc.passwd);
                if (def->graphics[0]->data.vnc.keymap)
                    virBufferVSprintf(&buf, ",keymap=%s",
                                      def->graphics[0]->data.vnc.keymap);
            }
            if (virBufferError(&buf))
                goto no_memory;

            vfbstr = virBufferContentAndReset(&buf);

            if (VIR_ALLOC(vfb) < 0) {
                VIR_FREE(vfbstr);
                goto no_memory;
            }

            if (VIR_ALLOC(disp) < 0) {
                VIR_FREE(vfb);
                VIR_FREE(vfbstr);
                goto no_memory;
            }

            vfb->type = VIR_CONF_LIST;
            vfb->list = disp;
            disp->type = VIR_CONF_STRING;
            disp->str = vfbstr;

            if (virConfSetValue(conf, "vfb", vfb) < 0)
                goto no_memory;
        }
    }

    /* analyze of the devices */
    if (VIR_ALLOC(diskVal) < 0)
        goto no_memory;
    diskVal->type = VIR_CONF_LIST;
    diskVal->list = NULL;

    for (i = 0 ; i < def->ndisks ; i++) {
        if (priv->xendConfigVersion == 1 &&
            def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
            def->disks[i]->dst &&
            STREQ(def->disks[i]->dst, "hdc")) {
            continue;
        }
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            continue;

        if (xenXMDomainConfigFormatDisk(conn, diskVal, def->disks[i],
                                        hvm, priv->xendConfigVersion) < 0)
            goto cleanup;
    }
    if (diskVal->list != NULL) {
        int ret = virConfSetValue(conf, "disk", diskVal);
        diskVal = NULL;
        if (ret < 0)
            goto no_memory;
    }
    VIR_FREE(diskVal);

    if (VIR_ALLOC(netVal) < 0)
        goto no_memory;
    netVal->type = VIR_CONF_LIST;
    netVal->list = NULL;

    for (i = 0 ; i < def->nnets ; i++) {
        if (xenXMDomainConfigFormatNet(conn, netVal,
                                       def->nets[i],
                                       hvm) < 0)
            goto cleanup;
    }
    if (netVal->list != NULL) {
        int ret = virConfSetValue(conf, "vif", netVal);
        netVal = NULL;
        if (ret < 0)
            goto no_memory;
    }
    VIR_FREE(netVal);

    if (xenXMDomainConfigFormatPCI(conn, conf, def) < 0)
        goto cleanup;

    if (hvm) {
        if (def->nparallels) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str;
            int ret;

            ret = xenDaemonFormatSxprChr(conn, def->parallels[0], &buf);
            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenXMConfigSetString(conf, "parallel", str);
            VIR_FREE(str);
            if (ret < 0)
                goto no_memory;
        } else {
            if (xenXMConfigSetString(conf, "parallel", "none") < 0)
                goto no_memory;
        }

        if (def->nserials) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str;
            int ret;

            ret = xenDaemonFormatSxprChr(conn, def->serials[0], &buf);
            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenXMConfigSetString(conf, "serial", str);
            VIR_FREE(str);
            if (ret < 0)
                goto no_memory;
        } else {
            if (xenXMConfigSetString(conf, "serial", "none") < 0)
                goto no_memory;
        }


        if (def->sounds) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str = NULL;
            int ret = xenDaemonFormatSxprSound(conn,
                                               def,
                                               &buf);
            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenXMConfigSetString(conf, "soundhw", str);

            VIR_FREE(str);
            if (ret < 0)
                goto no_memory;
        }
    }

    return conf;

no_memory:
    virReportOOMError(conn);

cleanup:
    virConfFreeValue(diskVal);
    virConfFreeValue(netVal);
    VIR_FREE(cpus);
    if (conf)
        virConfFree(conf);
    return (NULL);
}

/*
 * Create a config file for a domain, based on an XML
 * document describing its config
 */
virDomainPtr xenXMDomainDefineXML(virConnectPtr conn, const char *xml) {
    virDomainPtr ret;
    virDomainPtr olddomain;
    char filename[PATH_MAX];
    const char * oldfilename;
    virDomainDefPtr def = NULL;
    xenXMConfCachePtr entry = NULL;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

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

    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh (conn) < 0) {
        xenUnifiedUnlock(priv);
        return (NULL);
    }

    if (!(def = virDomainDefParseString(conn, priv->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        xenUnifiedUnlock(priv);
        return (NULL);
    }

    if (virHashLookup(priv->nameConfigMap, def->name)) {
        /* domain exists, we will overwrite it */

        if (!(oldfilename = (char *)virHashLookup(priv->nameConfigMap, def->name))) {
            xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                       "%s", _("can't retrieve config filename for domain to overwrite"));
            goto error;
        }

        if (!(entry = virHashLookup(priv->configCache, oldfilename))) {
            xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                       "%s", _("can't retrieve config entry for domain to overwrite"));
            goto error;
        }

        /* XXX wtf.com is this line for - it appears to be amemory leak */
        if (!(olddomain = virGetDomain(conn, def->name, entry->def->uuid)))
            goto error;

        /* Remove the name -> filename mapping */
        if (virHashRemoveEntry(priv->nameConfigMap, def->name, NULL) < 0) {
            xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                       "%s", _("failed to remove old domain from config map"));
            goto error;
        }

        /* Remove the config record itself */
        if (virHashRemoveEntry(priv->configCache, oldfilename, xenXMConfigFree) < 0) {
            xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                       "%s", _("failed to remove old domain from config map"));
            goto error;
        }

        entry = NULL;
    }

    if ((strlen(priv->configDir) + 1 + strlen(def->name) + 1) > PATH_MAX) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("config file name is too long"));
        goto error;
    }

    strcpy(filename, priv->configDir);
    strcat(filename, "/");
    strcat(filename, def->name);

    if (xenXMConfigSaveFile(conn, filename, def) < 0)
        goto error;

    if (VIR_ALLOC(entry) < 0) {
        virReportOOMError(conn);
        goto error;
    }

    if ((entry->refreshedAt = time(NULL)) == ((time_t)-1)) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("unable to get current time"));
        goto error;
    }

    memmove(entry->filename, filename, PATH_MAX);
    entry->def = def;

    if (virHashAddEntry(priv->configCache, filename, entry) < 0) {
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("unable to store config file handle"));
        goto error;
    }

    if (virHashAddEntry(priv->nameConfigMap, def->name, entry->filename) < 0) {
        virHashRemoveEntry(priv->configCache, filename, NULL);
        xenXMError(conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("unable to store config file handle"));
        goto error;
    }

    ret = virGetDomain(conn, def->name, def->uuid);
    xenUnifiedUnlock(priv);
    return (ret);

 error:
    VIR_FREE(entry);
    virDomainDefFree(def);
    xenUnifiedUnlock(priv);
    return (NULL);
}

/*
 * Delete a domain from disk
 */
int xenXMDomainUndefine(virDomainPtr domain) {
    xenUnifiedPrivatePtr priv;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return (-1);
    }

    if (domain->id != -1)
        return (-1);
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    if (unlink(entry->filename) < 0)
        goto cleanup;

    /* Remove the name -> filename mapping */
    if (virHashRemoveEntry(priv->nameConfigMap, domain->name, NULL) < 0)
        goto cleanup;

    /* Remove the config record itself */
    if (virHashRemoveEntry(priv->configCache, entry->filename, xenXMConfigFree) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

struct xenXMListIteratorContext {
    virConnectPtr conn;
    int max;
    int count;
    char ** names;
};

static void xenXMListIterator(const void *payload ATTRIBUTE_UNUSED, const char *name, const void *data) {
    struct xenXMListIteratorContext *ctx = (struct xenXMListIteratorContext *)data;
    virDomainPtr dom = NULL;

    if (ctx->count == ctx->max)
        return;

    dom = xenDaemonLookupByName(ctx->conn, name);
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
int xenXMListDefinedDomains(virConnectPtr conn, char **const names, int maxnames) {
    xenUnifiedPrivatePtr priv;
    struct xenXMListIteratorContext ctx;
    int ret = -1;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    priv = conn->privateData;
    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh (conn) < 0)
        goto cleanup;

    if (maxnames > virHashSize(priv->configCache))
        maxnames = virHashSize(priv->configCache);

    ctx.conn = conn;
    ctx.count = 0;
    ctx.max = maxnames;
    ctx.names = names;

    virHashForEach(priv->nameConfigMap, xenXMListIterator, &ctx);
    ret = ctx.count;

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Return the maximum number of defined domains - not filtered
 * based on number running
 */
int xenXMNumOfDefinedDomains(virConnectPtr conn) {
    xenUnifiedPrivatePtr priv;
    int ret = -1;

    if (!VIR_IS_CONNECT(conn)) {
        xenXMError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    priv = conn->privateData;
    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh (conn) < 0)
        goto cleanup;

    ret = virHashSize(priv->nameConfigMap);

cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}


/**
 * xenXMDomainAttachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into config file.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenXMDomainAttachDevice(virDomainPtr domain, const char *xml) {
    const char *filename = NULL;
    xenXMConfCachePtr entry = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def;
    xenUnifiedPrivatePtr priv;

    if ((!domain) || (!domain->conn) || (!domain->name) || (!xml)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO)
        return -1;
    if (domain->id != -1)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;
    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;
    def = entry->def;

    if (!(dev = virDomainDeviceDefParse(domain->conn,
                                        priv->caps,
                                        entry->def,
                                        xml, VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    {
        if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
            virReportOOMError(domain->conn);
            goto cleanup;
        }
        def->disks[def->ndisks++] = dev->data.disk;
        dev->data.disk = NULL;
        qsort(def->disks, def->ndisks, sizeof(*def->disks),
              virDomainDiskQSort);
    }
    break;

    case VIR_DOMAIN_DEVICE_NET:
    {
        if (VIR_REALLOC_N(def->nets, def->nnets+1) < 0) {
            virReportOOMError(domain->conn);
            goto cleanup;
        }
        def->nets[def->nnets++] = dev->data.net;
        dev->data.net = NULL;
        break;
    }

    default:
        xenXMError(domain->conn, VIR_ERR_XML_ERROR,
                   "%s", _("unknown device"));
        goto cleanup;
    }

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(domain->conn, entry->filename, entry->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainDeviceDefFree(dev);
    xenUnifiedUnlock(priv);
    return ret;
}


/**
 * xenXMDomainDetachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 *
 * Destroy a virtual device attachment to backend.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenXMDomainDetachDevice(virDomainPtr domain, const char *xml) {
    const char *filename = NULL;
    xenXMConfCachePtr entry = NULL;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def;
    int ret = -1;
    int i;
    xenUnifiedPrivatePtr priv;

    if ((!domain) || (!domain->conn) || (!domain->name) || (!xml)) {
        xenXMError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                   __FUNCTION__);
        return -1;
    }


    if (domain->conn->flags & VIR_CONNECT_RO)
        return -1;
    if (domain->id != -1)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, domain->name)))
        goto cleanup;
    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;
    def = entry->def;

    if (!(dev = virDomainDeviceDefParse(domain->conn,
                                        priv->caps,
                                        entry->def,
                                        xml, VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    {
        for (i = 0 ; i < def->ndisks ; i++) {
            if (def->disks[i]->dst &&
                dev->data.disk->dst &&
                STREQ(def->disks[i]->dst, dev->data.disk->dst)) {
                virDomainDiskDefFree(def->disks[i]);
                if (i < (def->ndisks - 1))
                    memmove(def->disks + i,
                            def->disks + i + 1,
                            sizeof(*def->disks) *
                            (def->ndisks - (i + 1)));
                break;
            }
        }
        break;
    }

    case VIR_DOMAIN_DEVICE_NET:
    {
        for (i = 0 ; i < def->nnets ; i++) {
            if (!memcmp(def->nets[i]->mac,
                        dev->data.net->mac,
                        sizeof(def->nets[i]->mac))) {
                virDomainNetDefFree(def->nets[i]);
                if (i < (def->nnets - 1))
                    memmove(def->nets + i,
                            def->nets + i + 1,
                            sizeof(*def->nets) *
                            (def->nnets - (i + 1)));
                break;
            }
        }
        break;
    }
    default:
        xenXMError(domain->conn, VIR_ERR_XML_ERROR,
                   "%s", _("unknown device"));
        goto cleanup;
    }

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(domain->conn, entry->filename, entry->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainDeviceDefFree(dev);
    xenUnifiedUnlock(priv);
    return (ret);
}

int
xenXMDomainBlockPeek (virDomainPtr dom,
                      const char *path ATTRIBUTE_UNUSED,
                      unsigned long long offset ATTRIBUTE_UNUSED,
                      size_t size ATTRIBUTE_UNUSED,
                      void *buffer ATTRIBUTE_UNUSED)
{
    xenXMError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}


static char *xenXMAutostartLinkName(virDomainPtr dom)
{
    char *ret;
    virAsprintf(&ret, "/etc/xen/auto/%s", dom->name);
    return ret;
}

static char *xenXMDomainConfigName(virDomainPtr dom)
{
    char *ret;
    virAsprintf(&ret, "/etc/xen/%s", dom->name);
    return ret;
}

int xenXMDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    char *linkname = xenXMAutostartLinkName(dom);
    char *config = xenXMDomainConfigName(dom);
    int ret = -1;

    if (!linkname || !config) {
        virReportOOMError(dom->conn);
        goto cleanup;
    }

    *autostart = virFileLinkPointsTo(linkname, config);
    if (*autostart < 0) {
        virReportSystemError(dom->conn, errno,
                             _("cannot check link %s points to config %s"),
                             linkname, config);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(linkname);
    VIR_FREE(config);
    return ret;
}


int xenXMDomainSetAutostart(virDomainPtr dom, int autostart)
{
    char *linkname = xenXMAutostartLinkName(dom);
    char *config = xenXMDomainConfigName(dom);
    int ret = -1;

    if (!linkname || !config) {
        virReportOOMError(dom->conn);
        goto cleanup;
    }

    if (autostart) {
        if (symlink(config, linkname) < 0 &&
            errno != EEXIST) {
            virReportSystemError(dom->conn, errno,
                                 _("failed to create link %s to %s"),
                                 config, linkname);
            goto cleanup;
        }
    } else {
        if (unlink(linkname)  < 0 &&
            errno != ENOENT) {
            virReportSystemError(dom->conn, errno,
                                 _("failed to remove link %s"),
                                 linkname);
            goto cleanup;
        }
    }
    ret = 0;

cleanup:
    VIR_FREE(linkname);
    VIR_FREE(config);

    return ret;
}
