/*
 * xen_inotify.c: Xen notification of xml file activity in the
 *                following dirs:
 *                /etc/xen
 *                /var/lib/xend/domains
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
 * Copyright (C) 2008 VirtualIron
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
 * Author: Ben Guthro
 */
#include <config.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "virerror.h"
#include "datatypes.h"
#include "driver.h"
#include "viralloc.h"
#include "xen_driver.h"
#include "virconf.h"
#include "domain_conf.h"
#include "xen_inotify.h"
#include "xend_internal.h"
#include "virlog.h"
#include "viruuid.h"
#include "virfile.h"
#include "virstring.h"
#include "xm_internal.h" /* for xenXMDomainConfigParse */

#define VIR_FROM_THIS VIR_FROM_XEN_INOTIFY

VIR_LOG_INIT("xen.xen_inotify");

static int
xenInotifyXenCacheLookup(virConnectPtr conn,
                         const char *filename,
                         char **name,
                         unsigned char *uuid)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;

    if (!(entry = virHashLookup(priv->configCache, filename))) {
        VIR_DEBUG("No config found for %s", filename);
        return -1;
    }

    memcpy(uuid, entry->def->uuid, VIR_UUID_BUFLEN);
    if (VIR_STRDUP(*name, entry->def->name) < 0) {
        VIR_DEBUG("Error getting dom from def");
        return -1;
    }
    return 0;
}

static int
xenInotifyXendDomainsDirLookup(virConnectPtr conn,
                               const char *filename,
                               char **name,
                               unsigned char *uuid)
{
    size_t i;
    virDomainDefPtr def;
    const char *uuid_str;
    unsigned char rawuuid[VIR_UUID_BUFLEN];
    xenUnifiedPrivatePtr priv = conn->privateData;

    /* xend is managing domains. we will get
    * a filename in the manner:
    * /var/lib/xend/domains/<uuid>/
    */
    uuid_str = filename + strlen(XEND_DOMAINS_DIR) + 1;

    if (virUUIDParse(uuid_str, rawuuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("parsing uuid %s"), uuid_str);
        return -1;
    }
    /* call directly into xend here, as driver may not yet
       be set during open while we are building our
       initial list of domains */
    VIR_DEBUG("Looking for dom with uuid: %s", uuid_str);

    if (!(def = xenDaemonLookupByUUID(conn, rawuuid))) {
        /* If we are here, the domain has gone away.
           search for, and create a domain from the stored
           list info */
        for (i = 0; i < priv->configInfoList->count; i++) {
            if (!memcmp(rawuuid, priv->configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN)) {
                if (VIR_STRDUP(*name, priv->configInfoList->doms[i]->name) < 0)
                    return -1;
                memcpy(uuid, priv->configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN);
                VIR_DEBUG("Found dom on list");
                return 0;
            }
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("finding dom on config list"));
        return -1;
    }

    if (VIR_STRDUP(*name, def->name) < 0) {
        virDomainDefFree(def);
        return -1;
    }
    memcpy(uuid, def->uuid, VIR_UUID_BUFLEN);
    virDomainDefFree(def);
    /* succeeded too find domain by uuid */
    return 0;
}

static int
xenInotifyDomainLookup(virConnectPtr conn,
                       const char *filename,
                       char **name,
                       unsigned char *uuid)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    if (priv->useXenConfigCache)
        return xenInotifyXenCacheLookup(conn, filename, name, uuid);
    else
        return xenInotifyXendDomainsDirLookup(conn, filename, name, uuid);
}

static virObjectEventPtr
xenInotifyDomainEventFromFile(virConnectPtr conn,
                              const char *filename,
                              int type,
                              int detail)
{
    virObjectEventPtr event;
    char *name = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (xenInotifyDomainLookup(conn, filename, &name, uuid) < 0)
        return NULL;

    event = virDomainEventLifecycleNew(-1, name, uuid, type, detail);
    VIR_FREE(name);
    return event;
}

static int
xenInotifyXendDomainsDirRemoveEntry(virConnectPtr conn, const char *fname)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *uuidstr = fname + strlen(XEND_DOMAINS_DIR) + 1;
    unsigned char uuid[VIR_UUID_BUFLEN];
    size_t i;

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("parsing uuid %s"), uuidstr);
        return -1;
    }

    /* match and remove on uuid */
    for (i = 0; i < priv->configInfoList->count; i++) {
        if (!memcmp(uuid, priv->configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN)) {
            VIR_FREE(priv->configInfoList->doms[i]->name);
            VIR_FREE(priv->configInfoList->doms[i]);

            VIR_DELETE_ELEMENT(priv->configInfoList->doms, i,
                               priv->configInfoList->count);
            return 0;
        }
    }
    return -1;
}

static int
xenInotifyXendDomainsDirAddEntry(virConnectPtr conn, const char *fname)
{
    char *name = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (xenInotifyDomainLookup(conn, fname, &name, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Error looking up domain"));
        return -1;
    }

    if (xenUnifiedAddDomainInfo(priv->configInfoList,
                                -1, name, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Error adding file to config cache"));
        VIR_FREE(name);
        return -1;
    }
    VIR_FREE(name);
    return 0;
}

static int
xenInotifyRemoveDomainConfigInfo(virConnectPtr conn, const char *fname)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    return priv->useXenConfigCache ?
        xenXMConfigCacheRemoveFile(conn, fname) :
        xenInotifyXendDomainsDirRemoveEntry(conn, fname);
}

static int
xenInotifyAddDomainConfigInfo(virConnectPtr conn, const char *fname)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    return priv->useXenConfigCache ?
        xenXMConfigCacheAddFile(conn, fname) :
        xenInotifyXendDomainsDirAddEntry(conn, fname);
}

static void
xenInotifyEvent(int watch ATTRIBUTE_UNUSED,
                int fd,
                int events ATTRIBUTE_UNUSED,
                void *data)
{
    char buf[1024];
    char fname[1024];
    struct inotify_event *e;
    int got;
    char *tmp, *name;
    virConnectPtr conn = data;
    xenUnifiedPrivatePtr priv = NULL;

    VIR_DEBUG("got inotify event");

    if (conn && conn->privateData) {
        priv = conn->privateData;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("conn, or private data is NULL"));
        return;
    }

    xenUnifiedLock(priv);

 reread:
    got = read(fd, buf, sizeof(buf));
    if (got == -1) {
        if (errno == EINTR)
            goto reread;
        goto cleanup;
    }

    tmp = buf;
    while (got) {
        if (got < sizeof(struct inotify_event))
            goto cleanup; /* bad */

        VIR_WARNINGS_NO_CAST_ALIGN
        e = (struct inotify_event *)tmp;
        VIR_WARNINGS_RESET

        tmp += sizeof(struct inotify_event);
        got -= sizeof(struct inotify_event);

        if (got < e->len)
            goto cleanup;

        tmp += e->len;
        got -= e->len;

        name = (char *)&(e->name);

        snprintf(fname, 1024, "%s/%s",
                 priv->configDir, name);

        if (e->mask & (IN_DELETE | IN_MOVED_FROM)) {
            virObjectEventPtr event =
                xenInotifyDomainEventFromFile(conn, fname,
                                              VIR_DOMAIN_EVENT_UNDEFINED,
                                              VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);
            if (event)
                xenUnifiedDomainEventDispatch(conn->privateData, event);
            else
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("looking up dom"));

            if (xenInotifyRemoveDomainConfigInfo(conn, fname) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Error adding file to config cache"));
                goto cleanup;
            }
        } else if (e->mask & (IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO)) {
            virObjectEventPtr event;
            if (xenInotifyAddDomainConfigInfo(conn, fname) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Error adding file to config cache"));
                goto cleanup;
            }

            event = xenInotifyDomainEventFromFile(conn, fname,
                                                  VIR_DOMAIN_EVENT_DEFINED,
                                                  VIR_DOMAIN_EVENT_DEFINED_ADDED);

            if (event)
                xenUnifiedDomainEventDispatch(conn->privateData, event);
            else
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("looking up dom"));

        }

    }

 cleanup:
    xenUnifiedUnlock(priv);
}

/**
 * xenInotifyOpen:
 * @conn: pointer to the connection block
 * @name: URL for the target, NULL for local
 * @flags: combination of virDrvOpenFlag(s)
 *
 * Connects and starts listening for inotify events
 *
 * Returns 0 or -1 in case of error.
 */
int
xenInotifyOpen(virConnectPtr conn,
               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
               unsigned int flags)
{
    DIR *dh;
    struct dirent *ent;
    char *path;
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, -1);

    if (priv->configDir) {
        priv->useXenConfigCache = 1;
    } else {
        /* /var/lib/xend/domains/<uuid>/config.sxp */
        priv->configDir = XEND_DOMAINS_DIR;
        priv->useXenConfigCache = 0;

        if (VIR_ALLOC(priv->configInfoList) < 0)
            return -1;

        /* populate initial list */
        if (!(dh = opendir(priv->configDir))) {
            virReportSystemError(errno,
                                 _("cannot open directory: %s"),
                                 priv->configDir);
            return -1;
        }
        while ((ent = readdir(dh))) {
            if (STRPREFIX(ent->d_name, "."))
                continue;

            /* Build the full file path */
            if (!(path = virFileBuildPath(priv->configDir, ent->d_name, NULL))) {
                closedir(dh);
                return -1;
            }

            if (xenInotifyAddDomainConfigInfo(conn, path) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Error adding file to config list"));
                closedir(dh);
                VIR_FREE(path);
                return -1;
            }

            VIR_FREE(path);
        }
        closedir(dh);
    }

    if ((priv->inotifyFD = inotify_init()) < 0) {
        virReportSystemError(errno,
                             "%s", _("initializing inotify"));
        return -1;
    }

    VIR_DEBUG("Adding a watch on %s", priv->configDir);
    if (inotify_add_watch(priv->inotifyFD,
                          priv->configDir,
                          IN_CREATE |
                          IN_CLOSE_WRITE | IN_DELETE |
                          IN_MOVED_TO | IN_MOVED_FROM) < 0) {
        virReportSystemError(errno,
                             _("adding watch on %s"),
                             priv->configDir);
        return -1;
    }

    VIR_DEBUG("Building initial config cache");
    if (priv->useXenConfigCache &&
        xenXMConfigCacheRefresh(conn) < 0) {
        VIR_DEBUG("Failed to enable XM config cache %s", conn->err.message);
        return -1;
    }

    VIR_DEBUG("Registering with event loop");
    /* Add the handle for monitoring */
    if ((priv->inotifyWatch = virEventAddHandle(priv->inotifyFD, VIR_EVENT_HANDLE_READABLE,
                                                xenInotifyEvent, conn, NULL)) < 0) {
        VIR_DEBUG("Failed to add inotify handle, disabling events");
    }

    return 0;
}

/**
 * xenInotifyClose:
 * @conn: pointer to the connection block
 *
 * Close and stop listening for inotify events
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
xenInotifyClose(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (priv->configInfoList)
        xenUnifiedDomainInfoListFree(priv->configInfoList);

    if (priv->inotifyWatch != -1)
        virEventRemoveHandle(priv->inotifyWatch);
    VIR_FORCE_CLOSE(priv->inotifyFD);

    return 0;
}
