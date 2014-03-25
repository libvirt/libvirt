/*
 * xs_internal.c: access to Xen Store
 *
 * Copyright (C) 2006, 2009-2013 Red Hat, Inc.
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
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <stdint.h>

#include <xen/dom0_ops.h>
#include <xen/version.h>

#if HAVE_XENSTORE_H
# include <xenstore.h>
#else
# include <xs.h>
#endif

#include "virerror.h"
#include "datatypes.h"
#include "driver.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "xen_driver.h"
#include "xs_internal.h"
#include "xen_hypervisor.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_XEN

VIR_LOG_INIT("xen.xs_internal");

static void xenStoreWatchEvent(int watch, int fd, int events, void *data);
static void xenStoreWatchListFree(xenStoreWatchListPtr list);

/************************************************************************
 *									*
 *		Helper internal APIs					*
 *									*
 ************************************************************************/

/**
 * virDomainDoStoreQuery:
 * @conn: pointer to the hypervisor connection
 * @domid: id of the domain
 * @path: the relative path of the data in the store to retrieve
 *
 * Internal API querying the Xenstore for a string value.
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char *
virDomainDoStoreQuery(virConnectPtr conn, int domid, const char *path)
{
    char s[256];
    unsigned int len = 0;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (priv->xshandle == NULL)
        return NULL;

    snprintf(s, 255, "/local/domain/%d/%s", domid, path);
    s[255] = 0;

    return xs_read(priv->xshandle, 0, &s[0], &len);
}

/************************************************************************
 *									*
 *		Canonical internal APIs					*
 *									*
 ************************************************************************/
/**
 * xenStoreOpen:
 * @conn: pointer to the connection block
 * @name: URL for the target, NULL for local
 * @flags: combination of virDrvOpenFlag(s)
 *
 * Connects to the Xen hypervisor.
 *
 * Returns 0 or -1 in case of error.
 */
int
xenStoreOpen(virConnectPtr conn,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, -1);

    if (flags & VIR_CONNECT_RO)
        priv->xshandle = xs_daemon_open_readonly();
    else
        priv->xshandle = xs_daemon_open();

    if (priv->xshandle == NULL) {
        /*
         * not being able to connect via the socket as an unprivileged
         * user is rather normal, this should fallback to the proxy (or
         * remote) mechanism.
         */
        if (xenHavePrivilege()) {
            virReportError(VIR_ERR_NO_XEN,
                           "%s", _("failed to connect to Xen Store"));
        }
        return -1;
    }

    /* Init activeDomainList */
    if (VIR_ALLOC(priv->activeDomainList) < 0)
        return -1;

    /* Init watch list before filling in domInfoList,
       so we can know if it is the first time through
       when the callback fires */
    if (VIR_ALLOC(priv->xsWatchList) < 0)
        return -1;

    /* This will get called once at start */
    if (xenStoreAddWatch(conn, "@releaseDomain",
                         "releaseDomain", xenStoreDomainReleased, priv) < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("adding watch @releaseDomain"));
        return -1;
    }

    /* The initial call of this will fill domInfoList */
    if (xenStoreAddWatch(conn, "@introduceDomain",
                         "introduceDomain", xenStoreDomainIntroduced, priv) < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("adding watch @introduceDomain"));
        return -1;
    }

    /* Add an event handle */
    if ((priv->xsWatch = virEventAddHandle(xs_fileno(priv->xshandle),
                                           VIR_EVENT_HANDLE_READABLE,
                                           xenStoreWatchEvent,
                                           conn,
                                           NULL)) < 0)
        VIR_DEBUG("Failed to add event handle, disabling events");

    return 0;
}

/**
 * xenStoreClose:
 * @conn: pointer to the connection block
 *
 * Close the connection to the Xen hypervisor.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
xenStoreClose(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (xenStoreRemoveWatch(conn, "@introduceDomain", "introduceDomain") < 0) {
        VIR_DEBUG("Warning, could not remove @introduceDomain watch");
        /* not fatal */
    }

    if (xenStoreRemoveWatch(conn, "@releaseDomain", "releaseDomain") < 0) {
        VIR_DEBUG("Warning, could not remove @releaseDomain watch");
        /* not fatal */
    }

    xenStoreWatchListFree(priv->xsWatchList);
    priv->xsWatchList = NULL;
    xenUnifiedDomainInfoListFree(priv->activeDomainList);
    priv->activeDomainList = NULL;

    if (priv->xshandle == NULL)
        return -1;

    if (priv->xsWatch != -1)
        virEventRemoveHandle(priv->xsWatch);

    xs_daemon_close(priv->xshandle);
    priv->xshandle = NULL;

    return 0;
}

/**
 * xenStoreNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenStoreNumOfDomains(virConnectPtr conn)
{
    unsigned int num;
    char **idlist = NULL, *endptr;
    size_t i;
    int ret = -1, realnum = 0;
    long id;
    xenUnifiedPrivatePtr priv = conn->privateData;

    idlist = xs_directory(priv->xshandle, 0, "/local/domain", &num);
    if (idlist) {
        for (i = 0; i < num; i++) {
            id = strtol(idlist[i], &endptr, 10);
            if ((endptr == idlist[i]) || (*endptr != 0))
                goto out;

            /* Sometimes xenstore has stale domain IDs, so filter
               against the hypervisor's info */
            if (xenHypervisorHasDomain(conn, (int)id))
                realnum++;
        }
 out:
        VIR_FREE(idlist);
        ret = realnum;
    }
    return ret;
}

/**
 * xenStoreDoListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Internal API: collect the list of active domains, and store
 * their ID in @maxids. The driver lock must be held.
 *
 * Returns the number of domain found or -1 in case of error
 */
static int
xenStoreDoListDomains(virConnectPtr conn,
                      xenUnifiedPrivatePtr priv,
                      int *ids,
                      int maxids)
{
    char **idlist = NULL, *endptr;
    unsigned int num;
    size_t i;
    int ret = -1;
    long id;

    idlist = xs_directory(priv->xshandle, 0, "/local/domain", &num);
    if (idlist == NULL)
        goto out;

    for (ret = 0, i = 0; (i < num) && (ret < maxids); i++) {
        id = strtol(idlist[i], &endptr, 10);
        if ((endptr == idlist[i]) || (*endptr != 0))
            goto out;

        /* Sometimes xenstore has stale domain IDs, so filter
           against the hypervisor's info */
        if (xenHypervisorHasDomain(conn, (int)id))
            ids[ret++] = (int) id;
    }

 out:
    VIR_FREE(idlist);
    return ret;
}

/**
 * xenStoreListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their ID in @maxids
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenStoreListDomains(virConnectPtr conn, int *ids, int maxids)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret;

    xenUnifiedLock(priv);
    ret = xenStoreDoListDomains(conn, priv, ids, maxids);
    xenUnifiedUnlock(priv);

    return ret;
}


/**
 * xenStoreDomainGetVNCPort:
 * @conn: the hypervisor connection
 * @domid: id of the domain
 *
 * Return the port number on which the domain is listening for VNC
 * connections.
 *
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 *
 * Returns the port number, -1 in case of error
 */
int
xenStoreDomainGetVNCPort(virConnectPtr conn, int domid)
{
    char *tmp;
    int ret = -1;

    tmp = virDomainDoStoreQuery(conn, domid, "console/vnc-port");
    if (tmp != NULL) {
        char *end;
        ret = strtol(tmp, &end, 10);
        if (ret == 0 && end == tmp)
            ret = -1;
        VIR_FREE(tmp);
    }
    return ret;
}

/**
 * xenStoreDomainGetConsolePath:
 * @conn: the hypervisor connection
 * @domid: id of the domain
 *
 * Return the path to the pseudo TTY on which the guest domain's
 * serial console is attached.
 *
 * Returns the path to the serial console. It is the callers
 * responsibilty to free() the return string. Returns NULL
 * on error
 *
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
char *
xenStoreDomainGetConsolePath(virConnectPtr conn, int domid)
{
  return virDomainDoStoreQuery(conn, domid, "console/tty");
}

/**
 * xenStoreDomainGetSerailConsolePath:
 * @conn: the hypervisor connection
 * @domid: id of the domain
 *
 * Return the path to the pseudo TTY on which the guest domain's
 * serial console is attached.
 *
 * Returns the path to the serial console. It is the callers
 * responsibilty to free() the return string. Returns NULL
 * on error
 *
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
char *
xenStoreDomainGetSerialConsolePath(virConnectPtr conn, int domid)
{
    return virDomainDoStoreQuery(conn, domid, "serial/0/tty");
}


/*
 * xenStoreDomainGetNetworkID:
 * @conn: pointer to the connection.
 * @id: the domain id
 * @mac: the mac address
 *
 * Get the reference (i.e. the string number) for the device on that domain
 * which uses the given mac address
 *
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
char *
xenStoreDomainGetNetworkID(virConnectPtr conn, int id, const char *mac)
{
    char dir[80], path[128], **list = NULL, *val = NULL;
    unsigned int len, num;
    size_t i;
    char *ret = NULL;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (id < 0 || priv->xshandle == NULL || mac == NULL)
        return NULL;

    snprintf(dir, sizeof(dir), "/local/domain/0/backend/vif/%d", id);
    list = xs_directory(priv->xshandle, 0, dir, &num);
    if (list == NULL)
        return NULL;
    for (i = 0; i < num; i++) {
        snprintf(path, sizeof(path), "%s/%s/%s", dir, list[i], "mac");
        if ((val = xs_read(priv->xshandle, 0, path, &len)) == NULL)
            break;

        bool match = (virMacAddrCompare(val, mac) == 0);

        VIR_FREE(val);

        if (match) {
            ignore_value(VIR_STRDUP(ret, list[i]));
            break;
        }
    }

    VIR_FREE(list);
    return ret;
}

/*
 * xenStoreDomainGetDiskID:
 * @conn: pointer to the connection.
 * @id: the domain id
 * @dev: the virtual block device name
 *
 * Get the reference (i.e. the string number) for the device on that domain
 * which uses the given virtual block device name
 *
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
char *
xenStoreDomainGetDiskID(virConnectPtr conn, int id, const char *dev)
{
    char dir[80], path[128], **list = NULL, *val = NULL;
    unsigned int devlen, len, num;
    size_t i;
    char *ret = NULL;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (id < 0 || priv->xshandle == NULL || dev == NULL)
        return NULL;
    devlen = strlen(dev);
    if (devlen <= 0)
        return NULL;

    snprintf(dir, sizeof(dir), "/local/domain/0/backend/vbd/%d", id);
    list = xs_directory(priv->xshandle, 0, dir, &num);
    if (list != NULL) {
        for (i = 0; i < num; i++) {
            snprintf(path, sizeof(path), "%s/%s/%s", dir, list[i], "dev");
            val = xs_read(priv->xshandle, 0, path, &len);
            if (val == NULL)
                break;
            if ((devlen != len) || memcmp(val, dev, len)) {
                VIR_FREE(val);
            } else {
                ignore_value(VIR_STRDUP(ret, list[i]));

                VIR_FREE(val);
                VIR_FREE(list);
                return ret;
            }
        }
        VIR_FREE(list);
    }
    snprintf(dir, sizeof(dir), "/local/domain/0/backend/tap/%d", id);
    list = xs_directory(priv->xshandle, 0, dir, &num);
    if (list != NULL) {
        for (i = 0; i < num; i++) {
            snprintf(path, sizeof(path), "%s/%s/%s", dir, list[i], "dev");
            val = xs_read(priv->xshandle, 0, path, &len);
            if (val == NULL)
                break;
            if ((devlen != len) || memcmp(val, dev, len)) {
                VIR_FREE(val);
            } else {
                ignore_value(VIR_STRDUP(ret, list[i]));

                VIR_FREE(val);
                VIR_FREE(list);
                return ret;
            }
        }
        VIR_FREE(list);
    }
    return NULL;
}

/*
 * xenStoreDomainGetPCIID:
 * @conn: pointer to the connection.
 * @id: the domain id
 * @bdf: the PCI BDF
 *
 * Get the reference (i.e. the string number) for the device on that domain
 * which uses the given PCI address
 *
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
char *
xenStoreDomainGetPCIID(virConnectPtr conn, int id, const char *bdf)
{
    char dir[80], path[128], **list = NULL, *val = NULL;
    unsigned int len, num;
    size_t i;
    char *ret = NULL;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (id < 0 || priv->xshandle == NULL || bdf == NULL)
        return NULL;

    snprintf(dir, sizeof(dir), "/local/domain/0/backend/pci/%d", id);
    list = xs_directory(priv->xshandle, 0, dir, &num);
    if (list == NULL)
        return NULL;
    for (i = 0; i < num; i++) {
        snprintf(path, sizeof(path), "%s/%s/%s", dir, list[i], "dev-0");
        if ((val = xs_read(priv->xshandle, 0, path, &len)) == NULL)
            break;

        bool match = STREQ(val, bdf);

        VIR_FREE(val);

        if (match) {
            ignore_value(VIR_STRDUP(ret, list[i]));
            break;
        }
    }

    VIR_FREE(list);
    return ret;
}

/*
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
char *
xenStoreDomainGetName(virConnectPtr conn, int id)
{
    char prop[200];
    xenUnifiedPrivatePtr priv = conn->privateData;
    unsigned int len;

    if (priv->xshandle == NULL)
        return NULL;

    snprintf(prop, 199, "/local/domain/%d/name", id);
    prop[199] = 0;
    return xs_read(priv->xshandle, 0, prop, &len);
}

/*
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
int
xenStoreDomainGetUUID(virConnectPtr conn, int id, unsigned char *uuid)
{
    char prop[200];
    xenUnifiedPrivatePtr priv = conn->privateData;
    unsigned int len;
    char *uuidstr;
    int ret = 0;

    if (priv->xshandle == NULL)
        return -1;

    snprintf(prop, 199, "/local/domain/%d/vm", id);
    prop[199] = 0;
    /* This will return something like
     * /vm/00000000-0000-0000-0000-000000000000[-*] */
    uuidstr = xs_read(priv->xshandle, 0, prop, &len);
    /* Strip optional version suffix when VM was renamed */
    if (len > 40) /* strlen('/vm/') + VIR_UUID_STRING_BUFLEN - sizeof('\0') */
        uuidstr[40] = '\0';

    /* remove "/vm/" */
    ret = virUUIDParse(uuidstr + 4, uuid);

    VIR_FREE(uuidstr);

    return ret;
}

static void
xenStoreWatchListFree(xenStoreWatchListPtr list)
{
    size_t i;
    for (i = 0; i < list->count; i++) {
        VIR_FREE(list->watches[i]->path);
        VIR_FREE(list->watches[i]->token);
        VIR_FREE(list->watches[i]);
    }
    VIR_FREE(list);
}

/*
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
int
xenStoreAddWatch(virConnectPtr conn,
                 const char *path,
                 const char *token,
                 xenStoreWatchCallback cb,
                 void *opaque)
{
    xenStoreWatchPtr watch = NULL;
    int n;
    xenStoreWatchListPtr list;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (priv->xshandle == NULL)
        return -1;

    list = priv->xsWatchList;
    if (!list)
        return -1;

    /* check if we already have this callback on our list */
    for (n = 0; n < list->count; n++) {
        if (STREQ(list->watches[n]->path, path) &&
            STREQ(list->watches[n]->token, token)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("watch already tracked"));
            return -1;
        }
    }

    if (VIR_ALLOC(watch) < 0)
        goto error;

    watch->cb = cb;
    watch->opaque = opaque;
    if (VIR_STRDUP(watch->path, path) < 0 ||
        VIR_STRDUP(watch->token, token) < 0)
        goto error;

    if (VIR_APPEND_ELEMENT_COPY(list->watches, list->count, watch) < 0)
        goto error;

    return xs_watch(priv->xshandle, watch->path, watch->token);

 error:
    if (watch) {
        VIR_FREE(watch->path);
        VIR_FREE(watch->token);
        VIR_FREE(watch);
    }
    return -1;
}

/*
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
int
xenStoreRemoveWatch(virConnectPtr conn, const char *path, const char *token)
{
    size_t i;
    xenStoreWatchListPtr list;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (priv->xshandle == NULL)
        return -1;

    list = priv->xsWatchList;
    if (!list)
        return -1;

    for (i = 0; i < list->count; i++) {
        if (STREQ(list->watches[i]->path, path) &&
            STREQ(list->watches[i]->token, token)) {

            if (!xs_unwatch(priv->xshandle,
                       list->watches[i]->path,
                       list->watches[i]->token))
            {
                VIR_DEBUG("WARNING: Could not remove watch");
                /* Not fatal, continue */
            }

            VIR_FREE(list->watches[i]->path);
            VIR_FREE(list->watches[i]->token);
            VIR_FREE(list->watches[i]);

            VIR_DELETE_ELEMENT(list->watches, i, list->count);
            return 0;
        }
    }
    return -1;
}

static xenStoreWatchPtr
xenStoreFindWatch(xenStoreWatchListPtr list,
                  const char *path,
                  const char *token)
{
    size_t i;
    for (i = 0; i < list->count; i++)
        if (STREQ(path, list->watches[i]->path) &&
            STREQ(token, list->watches[i]->token))
            return list->watches[i];

    return NULL;
}

static void
xenStoreWatchEvent(int watch ATTRIBUTE_UNUSED,
                   int fd ATTRIBUTE_UNUSED,
                   int events, void *data)
{
    char		 **event;
    char		 *path;
    char		 *token;
    unsigned int	 stringCount;
    xenStoreWatchPtr     sw;

    virConnectPtr        conn = data;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (!priv) return;

    /* only set a watch on read and write events */
    if (events & (VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP)) return;

    xenUnifiedLock(priv);

    if (!priv->xshandle)
        goto cleanup;

    event = xs_read_watch(priv->xshandle, &stringCount);
    if (!event)
        goto cleanup;

    path  = event[XS_WATCH_PATH];
    token = event[XS_WATCH_TOKEN];

    sw = xenStoreFindWatch(priv->xsWatchList, path, token);
    if (sw)
        sw->cb(conn, path, token, sw->opaque);
    VIR_FREE(event);

 cleanup:
    xenUnifiedUnlock(priv);
}


/*
 * The domain callback for the @introduceDomain watch
 *
 * The lock on 'priv' is held when calling this
 */
int
xenStoreDomainIntroduced(virConnectPtr conn,
                         const char *path ATTRIBUTE_UNUSED,
                         const char *token ATTRIBUTE_UNUSED,
                         void *opaque)
{
    size_t i, j;
    int found, missing = 0, retries = 20;
    int new_domain_cnt;
    int *new_domids;
    int nread;

    xenUnifiedPrivatePtr priv = opaque;

 retry:
    new_domain_cnt = xenStoreNumOfDomains(conn);
    if (new_domain_cnt < 0)
        return -1;

    if (VIR_ALLOC_N(new_domids, new_domain_cnt) < 0)
        return -1;
    nread = xenStoreDoListDomains(conn, priv, new_domids, new_domain_cnt);
    if (nread != new_domain_cnt) {
        /* mismatch. retry this read */
        VIR_FREE(new_domids);
        goto retry;
    }

    missing = 0;
    for (i = 0; i < new_domain_cnt; i++) {
        found = 0;
        for (j = 0; j < priv->activeDomainList->count; j++) {
            if (priv->activeDomainList->doms[j]->id == new_domids[i]) {
                found = 1;
                break;
            }
        }

        if (!found) {
            virObjectEventPtr event;
            char *name;
            unsigned char uuid[VIR_UUID_BUFLEN];

            if (!(name = xenStoreDomainGetName(conn, new_domids[i]))) {
                missing = 1;
                continue;
            }
            if (xenStoreDomainGetUUID(conn, new_domids[i], uuid) < 0) {
                missing = 1;
                VIR_FREE(name);
                continue;
            }

            event = virDomainEventLifecycleNew(new_domids[i], name, uuid,
                                               VIR_DOMAIN_EVENT_STARTED,
                                               VIR_DOMAIN_EVENT_STARTED_BOOTED);
            if (event)
                xenUnifiedDomainEventDispatch(priv, event);

            /* Add to the list */
            xenUnifiedAddDomainInfo(priv->activeDomainList,
                                    new_domids[i], name, uuid);

            VIR_FREE(name);
        }
    }
    VIR_FREE(new_domids);

    if (missing && retries--) {
        VIR_DEBUG("Some domains were missing, trying again");
        usleep(100 * 1000);
        goto retry;
    }
    return 0;
}

/*
 * The domain callback for the @destroyDomain watch
 *
 * The lock on 'priv' is held when calling this
 */
int
xenStoreDomainReleased(virConnectPtr conn,
                       const char *path  ATTRIBUTE_UNUSED,
                       const char *token ATTRIBUTE_UNUSED,
                       void *opaque)
{
    size_t i, j;
    int found, removed, retries = 20;
    int new_domain_cnt;
    int *new_domids;
    int nread;

    xenUnifiedPrivatePtr priv = opaque;

    if (!priv->activeDomainList->count) return 0;

 retry:
    new_domain_cnt = xenStoreNumOfDomains(conn);
    if (new_domain_cnt < 0)
        return -1;

    if (VIR_ALLOC_N(new_domids, new_domain_cnt) < 0)
        return -1;
    nread = xenStoreDoListDomains(conn, priv, new_domids, new_domain_cnt);
    if (nread != new_domain_cnt) {
        /* mismatch. retry this read */
        VIR_FREE(new_domids);
        goto retry;
    }

    removed = 0;
    for (j = 0; j < priv->activeDomainList->count; j++) {
        found = 0;
        for (i = 0; i < new_domain_cnt; i++) {
            if (priv->activeDomainList->doms[j]->id == new_domids[i]) {
                found = 1;
                break;
            }
        }

        if (!found) {
            virObjectEventPtr event =
                virDomainEventLifecycleNew(-1,
                                           priv->activeDomainList->doms[j]->name,
                                           priv->activeDomainList->doms[j]->uuid,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
            if (event)
                xenUnifiedDomainEventDispatch(priv, event);

            /* Remove from the list */
            xenUnifiedRemoveDomainInfo(priv->activeDomainList,
                                       priv->activeDomainList->doms[j]->id,
                                       priv->activeDomainList->doms[j]->name,
                                       priv->activeDomainList->doms[j]->uuid);

            removed = 1;
        }
    }

    VIR_FREE(new_domids);

    if (!removed && retries--) {
        VIR_DEBUG("No domains removed, retrying");
        usleep(100 * 1000);
        goto retry;
    }
    return 0;
}
