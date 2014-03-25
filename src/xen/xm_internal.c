/*
 * xm_internal.c: helper routines for dealing with inactive domains
 *
 * Copyright (C) 2006-2007, 2009-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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

#include "virerror.h"
#include "virfile.h"
#include "datatypes.h"
#include "xm_internal.h"
#include "xen_driver.h"
#include "xend_internal.h"
#include "xen_sxpr.h"
#include "xen_xm.h"
#include "virhash.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "viralloc.h"
#include "virlog.h"
#include "count-one-bits.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_XENXM

VIR_LOG_INIT("xen.xm_internal");

#ifdef WITH_RHEL5_API
# define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 0
# define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF 2
#else
# define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 3
# define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF 3
#endif

/* The true Xen limit varies but so far is always way
   less than 1024, which is the Linux kernel limit according
   to sched.h, so we'll match that for now */
#define XEN_MAX_PHYSICAL_CPU 1024

char * xenXMAutoAssignMac(void);

#define XM_REFRESH_INTERVAL 10

#define XM_CONFIG_DIR "/etc/xen"
#define XM_EXAMPLE_PREFIX "xmexample"
#define XEND_CONFIG_FILE "xend-config.sxp"
#define XEND_PCI_CONFIG_PREFIX "xend-pci-"
#define QEMU_IF_SCRIPT "qemu-ifup"
#define XM_XML_ERROR "Invalid xml"

#ifndef WITH_XEN_INOTIFY
static int xenInotifyActive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
   return 0;
}
#else
static int xenInotifyActive(virConnectPtr conn)
{
   xenUnifiedPrivatePtr priv = conn->privateData;
   return priv->inotifyWatch > 0;
}
#endif


/* Release memory associated with a cached config object */
static void xenXMConfigFree(void *payload, const void *key ATTRIBUTE_UNUSED)
{
    xenXMConfCachePtr entry = (xenXMConfCachePtr)payload;
    virDomainDefFree(entry->def);
    VIR_FREE(entry->filename);
    VIR_FREE(entry);
}

struct xenXMConfigReaperData {
    xenUnifiedPrivatePtr priv;
    time_t now;
};

/* Remove any configs which were not refreshed recently */
static int
xenXMConfigReaper(const void *payload,
                  const void *key ATTRIBUTE_UNUSED,
                  const void *data)
{
    const struct xenXMConfigReaperData *args = data;
    xenXMConfCachePtr entry = (xenXMConfCachePtr)payload;

    /* We're going to purge this config file, so check if it
       is currently mapped as owner of a named domain. */
    if (entry->refreshedAt != args->now) {
        const char *olddomname = entry->def->name;
        char *nameowner = (char *)virHashLookup(args->priv->nameConfigMap, olddomname);
        if (nameowner && STREQ(nameowner, key)) {
            virHashRemoveEntry(args->priv->nameConfigMap, olddomname);
        }
        return 1;
    }
    return 0;
}


static virDomainDefPtr
xenXMConfigReadFile(virConnectPtr conn, const char *filename)
{
    virConfPtr conf;
    virDomainDefPtr def;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (!(conf = virConfReadFile(filename, 0)))
        return NULL;

    def = xenParseXM(conf, priv->xendConfigVersion, priv->caps);
    virConfFree(conf);

    return def;
}

static int
xenXMConfigSaveFile(virConnectPtr conn,
                    const char *filename,
                    virDomainDefPtr def)
{
    virConfPtr conf;
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret;

    if (!(conf = xenFormatXM(conn, def, priv->xendConfigVersion)))
        return -1;

    ret = virConfWriteFile(filename, conf);
    virConfFree(conf);
    return ret;
}


/*
 * Caller must hold the lock on 'conn->privateData' before
 * calling this function
 */
int
xenXMConfigCacheRemoveFile(virConnectPtr conn, const char *filename)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;

    entry = virHashLookup(priv->configCache, filename);
    if (!entry) {
        VIR_DEBUG("No config entry for %s", filename);
        return 0;
    }

    virHashRemoveEntry(priv->nameConfigMap, entry->def->name);
    virHashRemoveEntry(priv->configCache, filename);
    VIR_DEBUG("Removed %s %s", entry->def->name, filename);
    return 0;
}


/*
 * Caller must hold the lock on 'conn->privateData' before
 * calling this function
 */
int
xenXMConfigCacheAddFile(virConnectPtr conn, const char *filename)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;
    struct stat st;
    int newborn = 0;
    time_t now = time(NULL);

    VIR_DEBUG("Adding file %s", filename);

    /* Get modified time */
    if ((stat(filename, &st) < 0)) {
        virReportSystemError(errno,
                             _("cannot stat: %s"),
                             filename);
        return -1;
    }

    /* Ignore zero length files, because inotify fires before
       any content has actually been created */
    if (st.st_size == 0) {
        VIR_DEBUG("Ignoring zero length file %s", filename);
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
            virHashRemoveEntry(priv->nameConfigMap, entry->def->name);
        }

        /* Clear existing config entry which needs refresh */
        virDomainDefFree(entry->def);
        entry->def = NULL;
    } else { /* Completely new entry */
        newborn = 1;
        if (VIR_ALLOC(entry) < 0)
            return -1;
        if (VIR_STRDUP(entry->filename, filename) < 0) {
            VIR_FREE(entry);
            return -1;
        }
    }
    entry->refreshedAt = now;

    if (!(entry->def = xenXMConfigReadFile(conn, entry->filename))) {
        VIR_DEBUG("Failed to read %s", entry->filename);
        if (!newborn)
            virHashSteal(priv->configCache, filename);
        VIR_FREE(entry->filename);
        VIR_FREE(entry);
        return -1;
    }

    /* If its a completely new entry, it must be stuck into
        the cache (refresh'd entries are already registered) */
    if (newborn) {
        if (virHashAddEntry(priv->configCache, entry->filename, entry) < 0) {
            virDomainDefFree(entry->def);
            VIR_FREE(entry->filename);
            VIR_FREE(entry);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("xenXMConfigCacheRefresh: virHashAddEntry"));
            return -1;
        }
    }

    /* See if we need to map this config file in as the primary owner
        * of the domain in question
        */
    if (!virHashLookup(priv->nameConfigMap, entry->def->name)) {
        if (virHashAddEntry(priv->nameConfigMap, entry->def->name,
                            entry->filename) < 0) {
            virHashSteal(priv->configCache, filename);
            virDomainDefFree(entry->def);
            VIR_FREE(entry->filename);
            VIR_FREE(entry);
        }
    }
    VIR_DEBUG("Added config %s %s", entry->def->name, filename);

    return 0;
}

/* This method is called by various methods to scan /etc/xen
 * (or whatever directory was set by  LIBVIRT_XM_CONFIG_DIR
 * environment variable) and process any domain configs. It
 * has rate-limited so never rescans more frequently than
 * once every X seconds
 *
 * Caller must hold the lock on 'conn->privateData' before
 * calling this function
 */
int
xenXMConfigCacheRefresh(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    DIR *dh;
    struct dirent *ent;
    time_t now = time(NULL);
    int ret = -1;
    struct xenXMConfigReaperData args;

    if (now == ((time_t)-1)) {
        virReportSystemError(errno,
                             "%s", _("cannot get time of day"));
        return -1;
    }

    /* Rate limit re-scans */
    if ((now - priv->lastRefresh) < XM_REFRESH_INTERVAL)
        return 0;

    priv->lastRefresh = now;

    /* Process the files in the config dir */
    if (!(dh = opendir(priv->configDir))) {
        virReportSystemError(errno,
                             _("cannot read directory %s"),
                             priv->configDir);
        return -1;
    }

    while ((ent = readdir(dh))) {
        struct stat st;
        char *path;

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
        if (!(path = virFileBuildPath(priv->configDir, ent->d_name, NULL))) {
            closedir(dh);
            return -1;
        }

        /* Skip anything which isn't a file (takes care of scripts/ subdir */
        if ((stat(path, &st) < 0) ||
            (!S_ISREG(st.st_mode))) {
            VIR_FREE(path);
            continue;
        }

        /* If we already have a matching entry and it is not
           modified, then carry on to next one*/
        if (xenXMConfigCacheAddFile(conn, path) < 0) {
            /* Ignoring errors, since a lot of stuff goes wrong in /etc/xen */
        }

        VIR_FREE(path);
    }

    /* Reap all entries which were not changed, by comparing
       their refresh timestamp - the timestamp should match
       'now' if they were refreshed. If timestamp doesn't match
       then the config is no longer on disk */
    args.now = now;
    args.priv = priv;
    virHashRemoveSet(priv->configCache, xenXMConfigReaper, &args);
    ret = 0;

    closedir(dh);

    return ret;
}


/*
 * The XM driver keeps a cache of config files as virDomainDefPtr
 * objects in the xenUnifiedPrivatePtr. Optionally inotify lets
 * us watch for changes (see separate driver), otherwise we poll
 * every few seconds
 */
int
xenXMOpen(virConnectPtr conn,
          virConnectAuthPtr auth ATTRIBUTE_UNUSED,
          unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, -1);

    priv->configDir = XM_CONFIG_DIR;

    priv->configCache = virHashCreate(50, xenXMConfigFree);
    if (!priv->configCache)
        return -1;
    priv->nameConfigMap = virHashCreate(50, NULL);
    if (!priv->nameConfigMap) {
        virHashFree(priv->configCache);
        priv->configCache = NULL;
        return -1;
    }
    /* Force the cache to be reloaded next time that
     * xenXMConfigCacheRefresh is called.
     */
    priv->lastRefresh = 0;

    return 0;
}

/*
 * Free the cached config files associated with this
 * connection
 */
int
xenXMClose(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    virHashFree(priv->nameConfigMap);
    virHashFree(priv->configCache);

    return 0;
}

/*
 * Since these are all offline domains, the state is always SHUTOFF.
 */
int
xenXMDomainGetState(virConnectPtr conn ATTRIBUTE_UNUSED,
                    virDomainDefPtr def ATTRIBUTE_UNUSED,
                    int *state,
                    int *reason)
{
    *state = VIR_DOMAIN_SHUTOFF;
    if (reason)
        *reason = 0;

    return 0;
}


/*
 * Since these are all offline domains, we only return info about
 * VCPUs and memory.
 */
int
xenXMDomainGetInfo(virConnectPtr conn,
                   virDomainDefPtr def,
                   virDomainInfoPtr info)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto error;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto error;

    memset(info, 0, sizeof(virDomainInfo));
    info->maxMem = entry->def->mem.max_balloon;
    info->memory = entry->def->mem.cur_balloon;
    info->nrVirtCpu = entry->def->vcpus;
    info->state = VIR_DOMAIN_SHUTOFF;
    info->cpuTime = 0;

    xenUnifiedUnlock(priv);
    return 0;

 error:
    xenUnifiedUnlock(priv);
    return -1;
}


/*
 * Turn a config record into a lump of XML describing the
 * domain, suitable for later feeding for virDomainCreateXML
 */
virDomainDefPtr
xenXMDomainGetXMLDesc(virConnectPtr conn,
                      virDomainDefPtr def)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    virDomainDefPtr ret = NULL;

    /* Flags checked by virDomainDefFormat */

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    ret = virDomainDefCopy(entry->def,
                           priv->caps,
                           priv->xmlopt,
                           false);

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}


/*
 * Update amount of memory in the config file
 */
int
xenXMDomainSetMemory(virConnectPtr conn,
                     virDomainDefPtr def,
                     unsigned long memory)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if (memory < 1024 * MIN_XEN_GUEST_SIZE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory %lu too small, min %lu"),
                       memory, (unsigned long)1024 * MIN_XEN_GUEST_SIZE);
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    entry->def->mem.cur_balloon = memory;
    if (entry->def->mem.cur_balloon > entry->def->mem.max_balloon)
        entry->def->mem.cur_balloon = entry->def->mem.max_balloon;

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(conn, entry->filename, entry->def) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Update maximum memory limit in config
 */
int
xenXMDomainSetMaxMemory(virConnectPtr conn,
                        virDomainDefPtr def,
                        unsigned long memory)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if (memory < 1024 * MIN_XEN_GUEST_SIZE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory %lu too small, min %lu"),
                       memory, (unsigned long)1024 * MIN_XEN_GUEST_SIZE);
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    entry->def->mem.max_balloon = memory;
    if (entry->def->mem.cur_balloon > entry->def->mem.max_balloon)
        entry->def->mem.cur_balloon = entry->def->mem.max_balloon;

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(conn, entry->filename, entry->def) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Get max memory limit from config
 */
unsigned long long
xenXMDomainGetMaxMemory(virConnectPtr conn,
                        virDomainDefPtr def)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    unsigned long long ret = 0;

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    ret = entry->def->mem.max_balloon;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * xenXMDomainSetVcpusFlags:
 * @conn: the connection object
 * @def: domain configuration
 * @nvcpus: number of vcpus
 * @flags: bitwise-ORd from virDomainVcpuFlags
 *
 * Change virtual CPUs allocation of domain according to flags.
 *
 * Returns 0 on success, -1 if an error message was issued
 */
int
xenXMDomainSetVcpusFlags(virConnectPtr conn,
                         virDomainDefPtr def,
                         unsigned int vcpus,
                         unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;
    int max;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (flags & VIR_DOMAIN_VCPU_LIVE) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    /* Hypervisor maximum. */
    if ((max = xenUnifiedConnectGetMaxVcpus(conn, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not determine max vcpus for the domain"));
        goto cleanup;
    }
    /* Can't specify a current larger than stored maximum; but
     * reducing maximum can silently reduce current.  */
    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM))
        max = entry->def->maxvcpus;
    if (vcpus > max) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable"
                         " vcpus for the domain: %d > %d"), vcpus, max);
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
        entry->def->maxvcpus = vcpus;
        if (entry->def->vcpus > vcpus)
            entry->def->vcpus = vcpus;
    } else {
        entry->def->vcpus = vcpus;
    }

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(conn, entry->filename, entry->def) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/**
 * xenXMDomainGetVcpusFlags:
 * @conn: the connection object
 * @def: domain configuration
 * @flags: bitwise-ORd from virDomainVcpuFlags
 *
 * Extract information about virtual CPUs of domain according to flags.
 *
 * Returns the number of vcpus on success, -1 if an error message was
 * issued
 */
int
xenXMDomainGetVcpusFlags(virConnectPtr conn,
                         virDomainDefPtr def,
                         unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (flags & VIR_DOMAIN_VCPU_LIVE) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("domain not active"));
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    ret = ((flags & VIR_DOMAIN_VCPU_MAXIMUM) ? entry->def->maxvcpus
           : entry->def->vcpus);

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/**
 * xenXMDomainPinVcpu:
 * @conn: the connection object
 * @def: domain configuration
 * @vcpu: virtual CPU number (reserved)
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes)
 * @maplen: length of cpumap in bytes
 *
 * Set the vcpu affinity in config
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int
xenXMDomainPinVcpu(virConnectPtr conn,
                   virDomainDefPtr def,
                   unsigned int vcpu ATTRIBUTE_UNUSED,
                   unsigned char *cpumap,
                   int maplen)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    if (maplen > (int)sizeof(cpumap_t)) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("virHashLookup"));
        goto cleanup;
    }
    if (!(entry = virHashLookup(priv->configCache, filename))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("can't retrieve config file for domain"));
        goto cleanup;
    }

    virBitmapFree(entry->def->cpumask);
    entry->def->cpumask = virBitmapNewData(cpumap, maplen);
    if (!entry->def->cpumask)
        goto cleanup;
    if (xenXMConfigSaveFile(conn, entry->filename, entry->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Find an inactive domain based on its name
 */
virDomainDefPtr
xenXMDomainLookupByName(virConnectPtr conn, const char *domname)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    virDomainDefPtr ret = NULL;

    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh(conn) < 0)
        goto cleanup;

    if (!(filename = virHashLookup(priv->nameConfigMap, domname)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    ret = virDomainDefNew(domname, entry->def->uuid, -1);

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}


/*
 * Hash table iterator to search for a domain based on UUID
 */
static int
xenXMDomainSearchForUUID(const void *payload,
                         const void *name ATTRIBUTE_UNUSED,
                         const void *data)
{
    const unsigned char *wantuuid = data;
    const xenXMConfCache *entry = payload;

    if (!memcmp(entry->def->uuid, wantuuid, VIR_UUID_BUFLEN))
        return 1;

    return 0;
}

/*
 * Find an inactive domain based on its UUID
 */
virDomainDefPtr
xenXMDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;
    virDomainDefPtr ret = NULL;

    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh(conn) < 0)
        goto cleanup;

    if (!(entry = virHashSearch(priv->configCache, xenXMDomainSearchForUUID, (const void *)uuid)))
        goto cleanup;

    ret = virDomainDefNew(entry->def->name, uuid, -1);

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}


/*
 * Start a domain from an existing defined config file
 */
int
xenXMDomainCreate(virConnectPtr conn,
                  virDomainDefPtr def)
{
    char *sexpr;
    int ret = -1;
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry = NULL;

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto error;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto error;

    if (!(sexpr = xenFormatSxpr(conn, entry->def, priv->xendConfigVersion)))
        goto error;

    ret = xenDaemonDomainCreateXML(conn, sexpr);
    VIR_FREE(sexpr);
    if (ret != 0)
        goto error;

    if ((ret = xenDaemonDomainLookupByName_ids(conn, def->name,
                                               entry->def->uuid)) < 0)
        goto error;
    def->id = ret;

    if (xend_wait_for_devices(conn, def->name) < 0)
        goto error;

    if (xenDaemonDomainResume(conn, entry->def) < 0)
        goto error;

    xenUnifiedUnlock(priv);
    return 0;

 error:
    if (def->id != -1 && entry) {
        xenDaemonDomainDestroy(conn, entry->def);
        def->id = -1;
    }
    xenUnifiedUnlock(priv);
    return -1;
}

/*
 * Create a config file for a domain, based on an XML
 * document describing its config
 */
int
xenXMDomainDefineXML(virConnectPtr conn, virDomainDefPtr def)
{
    char *filename = NULL;
    const char *oldfilename;
    virConfPtr conf = NULL;
    xenXMConfCachePtr entry = NULL;
    xenUnifiedPrivatePtr priv = conn->privateData;

    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh(conn) < 0) {
        xenUnifiedUnlock(priv);
        return -1;
    }

    if (!(conf = xenFormatXM(conn, def, priv->xendConfigVersion)))
        goto error;

    /*
     * check that if there is another domain defined with the same uuid
     * it has the same name
     */
    if ((entry = virHashSearch(priv->configCache, xenXMDomainSearchForUUID,
                               (const void *)&(def->uuid))) != NULL) {
        if ((entry->def != NULL) && (entry->def->name != NULL) &&
            (STRNEQ(def->name, entry->def->name))) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];

            virUUIDFormat(entry->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("domain '%s' is already defined with uuid %s"),
                           entry->def->name, uuidstr);
            entry = NULL;
            goto error;
        }
        entry = NULL;
    }

    if (virHashLookup(priv->nameConfigMap, def->name)) {
        /* domain exists, we will overwrite it */

        if (!(oldfilename = (char *)virHashLookup(priv->nameConfigMap, def->name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("can't retrieve config filename for domain to overwrite"));
            goto error;
        }

        if (!(entry = virHashLookup(priv->configCache, oldfilename))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("can't retrieve config entry for domain to overwrite"));
            goto error;
        }

        /* Remove the name -> filename mapping */
        if (virHashRemoveEntry(priv->nameConfigMap, def->name) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("failed to remove old domain from config map"));
            goto error;
        }

        /* Remove the config record itself */
        if (virHashRemoveEntry(priv->configCache, oldfilename) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("failed to remove old domain from config map"));
            goto error;
        }

        entry = NULL;
    }

    if (!(filename = virFileBuildPath(priv->configDir, def->name, NULL)))
        goto error;

    if (virConfWriteFile(filename, conf) < 0)
        goto error;

    if (VIR_ALLOC(entry) < 0)
        goto error;

    if ((entry->refreshedAt = time(NULL)) == ((time_t)-1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to get current time"));
        goto error;
    }

    if (VIR_STRDUP(entry->filename, filename) < 0)
        goto error;
    entry->def = def;

    if (virHashAddEntry(priv->configCache, filename, entry) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to store config file handle"));
        goto error;
    }

    if (virHashAddEntry(priv->nameConfigMap, def->name, entry->filename) < 0) {
        virHashSteal(priv->configCache, filename);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to store config file handle"));
        goto error;
    }

    xenUnifiedUnlock(priv);
    VIR_FREE(filename);
    return 0;

 error:
    VIR_FREE(filename);
    if (entry)
        VIR_FREE(entry->filename);
    VIR_FREE(entry);
    virConfFree(conf);
    xenUnifiedUnlock(priv);
    return -1;
}

/*
 * Delete a domain from disk
 */
int
xenXMDomainUndefine(virConnectPtr conn,
                    virDomainDefPtr def)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *filename;
    xenXMConfCachePtr entry;
    int ret = -1;

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, def->name)))
        goto cleanup;

    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;

    if (unlink(entry->filename) < 0)
        goto cleanup;

    /* Remove the name -> filename mapping */
    if (virHashRemoveEntry(priv->nameConfigMap, def->name) < 0)
        goto cleanup;

    /* Remove the config record itself */
    if (virHashRemoveEntry(priv->configCache, entry->filename) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

struct xenXMListIteratorContext {
    virConnectPtr conn;
    int oom;
    int max;
    int count;
    char ** names;
};

static void
xenXMListIterator(void *payload ATTRIBUTE_UNUSED,
                  const void *name,
                  void *data)
{
    struct xenXMListIteratorContext *ctx = data;
    virDomainDefPtr def = NULL;

    if (ctx->oom)
        return;

    if (ctx->count == ctx->max)
        return;

    def = xenDaemonLookupByName(ctx->conn, name);
    if (!def) {
        if (VIR_STRDUP(ctx->names[ctx->count], name) < 0)
            ctx->oom = 1;
        else
            ctx->count++;
    } else {
        virDomainDefFree(def);
    }
}


/*
 * List all defined domains, filtered to remove any which
 * are currently running
 */
int
xenXMListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    struct xenXMListIteratorContext ctx;
    size_t i;
    int ret = -1;

    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh(conn) < 0)
        goto cleanup;

    if (maxnames > virHashSize(priv->configCache))
        maxnames = virHashSize(priv->configCache);

    ctx.conn = conn;
    ctx.oom = 0;
    ctx.count = 0;
    ctx.max = maxnames;
    ctx.names = names;

    virHashForEach(priv->nameConfigMap, xenXMListIterator, &ctx);

    if (ctx.oom) {
        for (i = 0; i < ctx.count; i++)
            VIR_FREE(ctx.names[i]);
        goto cleanup;
    }

    ret = ctx.count;

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * Return the maximum number of defined domains - not filtered
 * based on number running
 */
int
xenXMNumOfDefinedDomains(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret = -1;

    xenUnifiedLock(priv);

    if (!xenInotifyActive(conn) && xenXMConfigCacheRefresh(conn) < 0)
        goto cleanup;

    ret = virHashSize(priv->nameConfigMap);

 cleanup:
    xenUnifiedUnlock(priv);
    return ret;
}


/**
 * xenXMDomainAttachDeviceFlags:
 * @conn: the connection object
 * @minidef: domain configuration
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into config file.
 * This driver only supports device allocation to
 * persisted config.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
xenXMDomainAttachDeviceFlags(virConnectPtr conn,
                             virDomainDefPtr minidef,
                             const char *xml,
                             unsigned int flags)
{
    const char *filename = NULL;
    xenXMConfCachePtr entry = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def;
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) ||
        (minidef->id != -1 && flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Xm driver only supports modifying persistent config"));
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, minidef->name)))
        goto cleanup;
    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;
    def = entry->def;

    if (!(dev = virDomainDeviceDefParse(xml, entry->def,
                                        priv->caps,
                                        priv->xmlopt,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    {
        if (virDomainDiskInsert(def, dev->data.disk) < 0)
            goto cleanup;
        dev->data.disk = NULL;
    }
    break;

    case VIR_DOMAIN_DEVICE_NET:
    {
        if (VIR_APPEND_ELEMENT(def->nets, def->nnets, dev->data.net) < 0)
            goto cleanup;
        break;
    }

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Xm driver only supports adding disk or network devices"));
        goto cleanup;
    }

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(conn, entry->filename, entry->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainDeviceDefFree(dev);
    xenUnifiedUnlock(priv);
    return ret;
}


/**
 * xenXMDomainDetachDeviceFlags:
 * @conn: the connection object
 * @minidef: domain configuration
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Destroy a virtual device attachment to backend.
 * This driver only supports device deallocation from
 * persisted config.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
xenXMDomainDetachDeviceFlags(virConnectPtr conn,
                             virDomainDefPtr minidef,
                             const char *xml,
                             unsigned int flags)
{
    const char *filename = NULL;
    xenXMConfCachePtr entry = NULL;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def;
    int ret = -1;
    size_t i;
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) ||
        (minidef->id != -1 && flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Xm driver only supports modifying persistent config"));
        return -1;
    }

    xenUnifiedLock(priv);

    if (!(filename = virHashLookup(priv->nameConfigMap, minidef->name)))
        goto cleanup;
    if (!(entry = virHashLookup(priv->configCache, filename)))
        goto cleanup;
    def = entry->def;

    if (!(dev = virDomainDeviceDefParse(xml, entry->def,
                                        priv->caps,
                                        priv->xmlopt,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    {
        for (i = 0; i < def->ndisks; i++) {
            if (def->disks[i]->dst &&
                dev->data.disk->dst &&
                STREQ(def->disks[i]->dst, dev->data.disk->dst)) {
                virDomainDiskDefFree(def->disks[i]);
                VIR_DELETE_ELEMENT(def->disks, i, def->ndisks);
                break;
            }
        }
        break;
    }

    case VIR_DOMAIN_DEVICE_NET:
    {
        for (i = 0; i < def->nnets; i++) {
            if (!virMacAddrCmp(&def->nets[i]->mac, &dev->data.net->mac)) {
                virDomainNetDefFree(def->nets[i]);
                VIR_DELETE_ELEMENT(def->nets, i, def->nnets);
                break;
            }
        }
        break;
    }
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("device type '%s' cannot be detached"),
                       virDomainDeviceTypeToString(dev->type));
        goto cleanup;
    }

    /* If this fails, should we try to undo our changes to the
     * in-memory representation of the config file. I say not!
     */
    if (xenXMConfigSaveFile(conn, entry->filename, entry->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainDeviceDefFree(dev);
    xenUnifiedUnlock(priv);
    return ret;
}

int
xenXMDomainBlockPeek(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virDomainDefPtr def ATTRIBUTE_UNUSED,
                     const char *path ATTRIBUTE_UNUSED,
                     unsigned long long offset ATTRIBUTE_UNUSED,
                     size_t size ATTRIBUTE_UNUSED,
                     void *buffer ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("block peeking not implemented"));
    return -1;
}


static char *
xenXMAutostartLinkName(virDomainDefPtr def)
{
    char *ret;
    if (virAsprintf(&ret, "/etc/xen/auto/%s", def->name) < 0)
        return NULL;
    return ret;
}

static char *
xenXMDomainConfigName(virDomainDefPtr def)
{
    char *ret;
    if (virAsprintf(&ret, "/etc/xen/%s", def->name) < 0)
        return NULL;
    return ret;
}

int
xenXMDomainGetAutostart(virDomainDefPtr def,
                        int *autostart)
{
    char *linkname = xenXMAutostartLinkName(def);
    char *config = xenXMDomainConfigName(def);
    int ret = -1;

    if (!linkname || !config)
        goto cleanup;

    *autostart = virFileLinkPointsTo(linkname, config);
    if (*autostart < 0) {
        virReportSystemError(errno,
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


int
xenXMDomainSetAutostart(virDomainDefPtr def,
                        int autostart)
{
    char *linkname = xenXMAutostartLinkName(def);
    char *config = xenXMDomainConfigName(def);
    int ret = -1;

    if (!linkname || !config)
        goto cleanup;

    if (autostart) {
        if (symlink(config, linkname) < 0 &&
            errno != EEXIST) {
            virReportSystemError(errno,
                                 _("failed to create link %s to %s"),
                                 config, linkname);
            goto cleanup;
        }
    } else {
        if (unlink(linkname)  < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
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
