/*
 * xen_inofify.c: Xen notification of xml file activity in the
 *                following dirs:
 *                /etc/xen
 *                /var/lib/xend/domains
 *
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
#include "event.h"
#include "xen_unified.h"
#include "conf.h"
#include "domain_conf.h"
#include "xen_inotify.h"
#include "xend_internal.h"
#include "logging.h"
#include "uuid.h"

#include "xm_internal.h" /* for xenXMDomainConfigParse */

#define virXenInotifyError(conn, code, fmt...)                                 \
        virReportErrorHelper(NULL, VIR_FROM_XEN_INOTIFY, code, __FILE__,      \
                               __FUNCTION__, __LINE__, fmt)

#define LIBVIRTD_DOMAINS_DIR "/var/lib/xend/domains"
static const char *configDir        = NULL;
static int  useXenConfigCache = 0;
static xenUnifiedDomainInfoListPtr configInfoList = NULL;

struct xenUnifiedDriver xenInotifyDriver = {
    xenInotifyOpen, /* open */
    xenInotifyClose, /* close */
    NULL, /* version */
    NULL, /* hostname */
    NULL, /* URI */
    NULL, /* nodeGetInfo */
    NULL, /* getCapabilities */
    NULL, /* listDomains */
    NULL, /* numOfDomains */
    NULL, /* domainCreateLinux */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    NULL, /* domainDestroy */
    NULL, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    NULL, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    NULL, /* listDefinedDomains */
    NULL, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
};

static virDomainPtr
xenInotifyXenCacheLookup(virConnectPtr conn, const char *filename) {
    xenXMConfCachePtr entry;
    virDomainPtr dom;

    if (!(entry = virHashLookup(xenXMGetConfigCache(), filename))) {
        DEBUG("No config found for %s", filename);
        return NULL;
    }

    if(!(dom = virGetDomain(conn, entry->def->name,
                    (unsigned char*)entry->def->uuid))) {
        DEBUG0("Error getting dom from def");
        return NULL;
    }
    return dom;
}

static virDomainPtr
xenInotifyXendDomainsDirLookup(virConnectPtr conn, const char *filename) {
    int i;
    virDomainPtr dom;
    const char *uuid_str;
    unsigned char uuid[VIR_UUID_BUFLEN];

    /* xend is managing domains. we will get
    * a filename in the manner:
    * /var/lib/xend/domains/<uuid>/
    */
    uuid_str = filename + strlen(LIBVIRTD_DOMAINS_DIR) + 1;

    if (virUUIDParse(uuid_str, uuid) < 0) {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "parsing uuid %s", uuid_str);
        return (NULL);
    }
    /* call directly into xend here, as driver may not yet
       be set during open while we are building our
       initial list of domains */
    DEBUG("Looking for dom with uuid: %s", uuid_str);
    if(!(dom = xenDaemonLookupByUUID(conn, uuid))) {
        /* If we are here, the domain has gone away.
           search for, and create a domain from the stored
           list info */
        for (i=0; i<configInfoList->count; i++) {
            if (!memcmp(uuid, configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN)) {
                if(!(dom = virGetDomain(conn, configInfoList->doms[i]->name,
                                        configInfoList->doms[i]->uuid))) {
                    virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                                       "finding dom for %s", uuid_str);
                    return NULL;
                }
                DEBUG0("Found dom on list");
                return dom;
            }
        }
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                                       "%s", _("finding dom on config list"));
        return NULL;
    }

    /* succeeded too find domain by uuid */
    return dom;
}

static virDomainPtr
xenInotifyDomainLookup(virConnectPtr conn, const char *filename) {
    virDomainPtr dom;
    virDomainInfo info;

    dom = useXenConfigCache ? xenInotifyXenCacheLookup(conn, filename) :
                              xenInotifyXendDomainsDirLookup(conn, filename);

    if(dom) {
        if ( (useXenConfigCache ? xenXMDomainGetInfo(dom, &info) :
                                  xenDaemonDomainGetInfo(dom, &info)) < 0)
            dom->id = -1;
        else
            dom->id = (info.state == VIR_DOMAIN_SHUTOFF) ? -1 : dom->id;
        return dom;
    }
    return NULL;
}

static int
xenInotifyXendDomainsDirRemoveEntry(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    const char *fname) {
    const char *uuidstr = fname + strlen(LIBVIRTD_DOMAINS_DIR) + 1;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int i;

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "parsing uuid %s", uuidstr);
        return -1;
    }

    /* match and remove on uuid */
    for (i=0; i<configInfoList->count; i++) {
        if (!memcmp(uuid, configInfoList->doms[i]->uuid, VIR_UUID_BUFLEN)) {
            VIR_FREE(configInfoList->doms[i]->name);
            VIR_FREE(configInfoList->doms[i]);

            if (i < (configInfoList->count - 1))
                memmove(configInfoList->doms + i,
                        configInfoList->doms + i + 1,
                        sizeof(*(configInfoList->doms)) *
                                (configInfoList->count - (i + 1)));

            if (VIR_REALLOC_N(configInfoList->doms,
                              configInfoList->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            configInfoList->count--;
            return 0;
        }
    }
    return -1;
}

static int
xenInotifyXendDomainsDirAddEntry(virConnectPtr conn,
                                 const char *fname) {
    virDomainPtr dom = xenInotifyDomainLookup(conn, fname);
    if(!dom) {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Error looking up domain"));
        return -1;
    }

    if( xenUnifiedAddDomainInfo(configInfoList,
                                dom->id, dom->name, dom->uuid) < 0) {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Error adding file to config cache"));
        virUnrefDomain(dom);
        return -1;
    }
    virUnrefDomain(dom);
    return 0;
}

static int
xenInotifyRemoveDomainConfigInfo(virConnectPtr conn,
                                 const char *fname) {
    return useXenConfigCache ? xenXMConfigCacheRemoveFile(conn, fname) :
                               xenInotifyXendDomainsDirRemoveEntry(conn, fname);
}

static int
xenInotifyAddDomainConfigInfo(virConnectPtr conn,
                              const char *fname) {
    return useXenConfigCache ? xenXMConfigCacheAddFile(conn, fname) :
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
    virConnectPtr conn = (virConnectPtr) data;
    xenUnifiedPrivatePtr priv = NULL;
    virDomainPtr dom = NULL;

    DEBUG0("got inotify event");

    if( conn && conn->privateData ) {
        priv = conn->privateData;
    } else {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "%s", _("conn, or private data is NULL"));
        return;
    }

reread:
    got = read(fd, buf, sizeof(buf));
    if (got == -1) {
        if (errno == EINTR)
            goto reread;
        return;
    }

    tmp = buf;
    while (got) {
        if (got < sizeof(struct inotify_event))
            return; /* bad */

        e = (struct inotify_event *)tmp;
        tmp += sizeof(struct inotify_event);
        got -= sizeof(struct inotify_event);

        if (got < e->len)
            return;

        tmp += e->len;
        got -= e->len;

        name = (char *)&(e->name);

        snprintf(fname, 1024, "%s/%s", configDir, name);

        if (e->mask & (IN_DELETE | IN_MOVED_FROM)) {
            if (!(dom = xenInotifyDomainLookup(conn, fname))) {
                virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "%s", _("looking up dom"));
                continue;
            }

            xenUnifiedDomainEventDispatch(conn->privateData, dom,
                                          VIR_DOMAIN_EVENT_UNDEFINED,
                                          VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);


            if (xenInotifyRemoveDomainConfigInfo(conn, fname) < 0 ) {
                virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Error adding file to config cache"));
                return;
            }
        } else if (e->mask & ( IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO) ) {
            if (xenInotifyAddDomainConfigInfo(conn, fname) < 0 ) {
                virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Error adding file to config cache"));
                return;
            }

            if (!(dom = xenInotifyDomainLookup(conn, fname))) {
                virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "%s", _("looking up dom"));
                continue;
            }

            xenUnifiedDomainEventDispatch(conn->privateData, dom,
                                          VIR_DOMAIN_EVENT_DEFINED,
                                          VIR_DOMAIN_EVENT_DEFINED_ADDED);
        }

    }
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
xenInotifyOpen(virConnectPtr conn ATTRIBUTE_UNUSED,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             int flags ATTRIBUTE_UNUSED)
{
    DIR *dh;
    struct dirent *ent;
    char path[PATH_MAX];
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if(priv->xendConfigVersion <= 2) {
        /* /etc/xen */
        configDir = xenXMGetConfigDir();
        useXenConfigCache = 1;
    } else {
        /* /var/lib/xend/domains/<uuid>/config.sxp */
        configDir = LIBVIRTD_DOMAINS_DIR;
        useXenConfigCache = 0;

        if ( VIR_ALLOC(configInfoList ) < 0) {
            virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("failed to allocate configInfoList"));
            return -1;
        }

        /* populate initial list */
         if (!(dh = opendir(configDir))) {
            virXenInotifyError (NULL, VIR_ERR_INTERNAL_ERROR,
                                 "%s", strerror(errno));
            return -1;
        }
        while ((ent = readdir(dh))) {
            if (STRPREFIX(ent->d_name, "."))
                continue;

            /* Build the full file path */
            if ((strlen(configDir) + 1 + strlen(ent->d_name) + 1) > PATH_MAX)
                continue;
            strcpy(path, configDir);
            strcat(path, "/");
            strcat(path, ent->d_name);

            if (xenInotifyAddDomainConfigInfo(conn, path) < 0 ) {
                virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Error adding file to config list"));
                return -1;
            }
        }
        closedir(dh);
    }

    if ((priv->inotifyFD = inotify_init()) < 0) {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "%s", _("initializing inotify"));
        return -1;
    }

    DEBUG("Adding a watch on %s", configDir);
    if (inotify_add_watch(priv->inotifyFD,
                          configDir,
                          IN_CREATE |
                          IN_CLOSE_WRITE | IN_DELETE |
                          IN_MOVED_TO | IN_MOVED_FROM) < 0) {
        virXenInotifyError(NULL, VIR_ERR_INTERNAL_ERROR,
                           "adding watch on %s", _(configDir));
        return -1;
    }

    DEBUG0("Building initial config cache");
    if (useXenConfigCache &&
        xenXMConfigCacheRefresh (conn) < 0) {
        DEBUG("Failed to enable XM config cache %s", conn->err.message);
        return -1;
    }

    DEBUG0("Registering with event loop");
    /* Add the handle for monitoring */
    if ((priv->inotifyWatch = virEventAddHandle(priv->inotifyFD, VIR_EVENT_HANDLE_READABLE,
                                                xenInotifyEvent, conn, NULL)) < 0) {
        DEBUG0("Failed to add inotify handle, disabling events");
    }

    conn->refs++;
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
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if(configInfoList)
        xenUnifiedDomainInfoListFree(configInfoList);

    if (priv->inotifyWatch != -1)
        virEventRemoveHandle(priv->inotifyWatch);
    close(priv->inotifyFD);
    virUnrefConnect(conn);

    return 0;
}
