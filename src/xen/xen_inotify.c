/*
 * xen_inofify.c: Xen notification of xml file activity in the
 *                following dirs:
 *                /etc/xen
 *                /var/lib/xend/domains
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Ben Guthro
 */
#include <config.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "driver.h"
#include "memory.h"
#include "xen_driver.h"
#include "conf.h"
#include "domain_conf.h"
#include "xen_inotify.h"
#include "xend_internal.h"
#include "logging.h"
#include "uuid.h"
#include "virfile.h"

#include "xm_internal.h" /* for xenXMDomainConfigParse */

#define VIR_FROM_THIS VIR_FROM_XEN_INOTIFY

#define virXenInotifyError(code, ...)                                   \
        virReportErrorHelper(VIR_FROM_XEN_INOTIFY, code, __FILE__,      \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

struct xenUnifiedDriver xenInotifyDriver = {
    .xenClose = xenInotifyClose,
};

static int
xenInotifyXenCacheLookup(virConnectPtr conn,
                         const char *filename,
                         char **name, unsigned char *uuid) {
    xenUnifiedPrivatePtr priv = conn->privateData;
    xenXMConfCachePtr entry;

    if (!(entry = virHashLookup(priv->configCache, filename))) {
        VIR_DEBUG("No config found for %s", filename);
        return -1;
    }

    *name = strdup(entry->def->name);
    memcpy(uuid, entry->def->uuid, VIR_UUID_BUFLEN);

    if (!*name) {
        VIR_DEBUG("Error getting dom from def");
        virReportOOMError();
        return -1;
    }
    return 0;
}

static int
xenInotifyXendDomainsDirLookup(virConnectPtr conn, const char *filename,
                               char **name, unsigned char *uuid) {
    int i;
    virDomainPtr dom;
    const char *uuid_str;
    unsigned char rawuuid[VIR_UUID_BUFLEN];
    xenUnifiedPrivatePtr priv = conn->privateData;

    /* xend is managing domains. we will get
    * a filename in the manner:
    * /var/lib/xend/domains/<uuid>/
    */
    uuid_str = filename + strlen(XEND_DOMAINS_DIR) + 1;

    if (virUUIDParse(uuid_str, rawuuid) < 0) {
        virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                           _("parsing uuid %s"), uuid_str);
        return -1;
    }
    /* call directly into xend here, as driver may not yet
       be set during open while we are building our
       initial list of domains */
    VIR_DEBUG("Looking for dom with uuid: %s", uuid_str);
    /* XXX Should not have to go via a virDomainPtr obj instance */
    if(!(dom = xenDaemonLookupByUUID(conn, rawuuid))) {
        /* If we are here, the domain has gone away.
           search for, and create a domain from the stored
           list info */
        for (i = 0 ; i < priv->configInfoList->count ; i++) {
            if (!memcmp(rawuuid, priv->configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN)) {
                *name = strdup(priv->configInfoList->doms[i]->name);
                if (!*name) {
                    virReportOOMError();
                    return -1;
                }
                memcpy(uuid, priv->configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN);
                VIR_DEBUG("Found dom on list");
                return 0;
            }
        }
        virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("finding dom on config list"));
        return -1;
    }

    if (!(*name = strdup(dom->name))) {
        virReportOOMError();
        return -1;
    }
    memcpy(uuid, dom->uuid, VIR_UUID_BUFLEN);
    virDomainFree(dom);
    /* succeeded too find domain by uuid */
    return 0;
}

static int
xenInotifyDomainLookup(virConnectPtr conn,
                       const char *filename,
                       char **name, unsigned char *uuid) {
    xenUnifiedPrivatePtr priv = conn->privateData;
    if (priv->useXenConfigCache)
        return xenInotifyXenCacheLookup(conn, filename, name, uuid);
    else
        return xenInotifyXendDomainsDirLookup(conn, filename, name, uuid);
}

static virDomainEventPtr
xenInotifyDomainEventFromFile(virConnectPtr conn,
                              const char *filename,
                              int type, int detail) {
    virDomainEventPtr event;
    char *name = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (xenInotifyDomainLookup(conn, filename, &name, uuid) < 0)
        return NULL;

    event = virDomainEventNew(-1, name, uuid, type, detail);
    VIR_FREE(name);
    return event;
}

static int
xenInotifyXendDomainsDirRemoveEntry(virConnectPtr conn,
                                    const char *fname) {
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *uuidstr = fname + strlen(XEND_DOMAINS_DIR) + 1;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int i;

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                           _("parsing uuid %s"), uuidstr);
        return -1;
    }

    /* match and remove on uuid */
    for (i = 0 ; i < priv->configInfoList->count ; i++) {
        if (!memcmp(uuid, priv->configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN)) {
            VIR_FREE(priv->configInfoList->doms[i]->name);
            VIR_FREE(priv->configInfoList->doms[i]);

            if (i < (priv->configInfoList->count - 1))
                memmove(priv->configInfoList->doms + i,
                        priv->configInfoList->doms + i + 1,
                        sizeof(*(priv->configInfoList->doms)) *
                                (priv->configInfoList->count - (i + 1)));

            if (VIR_REALLOC_N(priv->configInfoList->doms,
                              priv->configInfoList->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            priv->configInfoList->count--;
            return 0;
        }
    }
    return -1;
}

static int
xenInotifyXendDomainsDirAddEntry(virConnectPtr conn,
                                 const char *fname) {
    char *name = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (xenInotifyDomainLookup(conn, fname, &name, uuid) < 0) {
        virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Error looking up domain"));
        return -1;
    }

    if (xenUnifiedAddDomainInfo(priv->configInfoList,
                                -1, name, uuid) < 0) {
        virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Error adding file to config cache"));
        VIR_FREE(name);
        return -1;
    }
    VIR_FREE(name);
    return 0;
}

static int
xenInotifyRemoveDomainConfigInfo(virConnectPtr conn,
                                 const char *fname) {
    xenUnifiedPrivatePtr priv = conn->privateData;
    return priv->useXenConfigCache ?
        xenXMConfigCacheRemoveFile(conn, fname) :
        xenInotifyXendDomainsDirRemoveEntry(conn, fname);
}

static int
xenInotifyAddDomainConfigInfo(virConnectPtr conn,
                              const char *fname) {
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

    if( conn && conn->privateData ) {
        priv = conn->privateData;
    } else {
        virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
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

        e = (struct inotify_event *)tmp;
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
            virDomainEventPtr event =
                xenInotifyDomainEventFromFile(conn, fname,
                                              VIR_DOMAIN_EVENT_UNDEFINED,
                                              VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);
            if (event)
                xenUnifiedDomainEventDispatch(conn->privateData, event);
            else
                virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("looking up dom"));

            if (xenInotifyRemoveDomainConfigInfo(conn, fname) < 0 ) {
                virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Error adding file to config cache"));
                goto cleanup;
            }
        } else if (e->mask & ( IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO) ) {
            virDomainEventPtr event;
            if (xenInotifyAddDomainConfigInfo(conn, fname) < 0 ) {
                virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Error adding file to config cache"));
                goto cleanup;
            }

            event = xenInotifyDomainEventFromFile(conn, fname,
                                                  VIR_DOMAIN_EVENT_DEFINED,
                                                  VIR_DOMAIN_EVENT_DEFINED_ADDED);

            if (event)
                xenUnifiedDomainEventDispatch(conn->privateData, event);
            else
                virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
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
virDrvOpenStatus
xenInotifyOpen(virConnectPtr conn,
               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
               unsigned int flags)
{
    DIR *dh;
    struct dirent *ent;
    char *path;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (priv->configDir) {
        priv->useXenConfigCache = 1;
    } else {
        /* /var/lib/xend/domains/<uuid>/config.sxp */
        priv->configDir = XEND_DOMAINS_DIR;
        priv->useXenConfigCache = 0;

        if (VIR_ALLOC(priv->configInfoList) < 0) {
            virReportOOMError();
            return -1;
        }

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

            if (xenInotifyAddDomainConfigInfo(conn, path) < 0 ) {
                virXenInotifyError(VIR_ERR_INTERNAL_ERROR,
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
        xenXMConfigCacheRefresh (conn) < 0) {
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
