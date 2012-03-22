/*
 * xs_internal.c: access to Xen Store
 *
 * Copyright (C) 2006, 2009-2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
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

#include <xs.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "driver.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "xen_driver.h"
#include "xs_internal.h"
#include "xen_hypervisor.h"

#define VIR_FROM_THIS VIR_FROM_XEN

static char *xenStoreDomainGetOSType(virDomainPtr domain);
static void xenStoreWatchEvent(int watch, int fd, int events, void *data);
static void xenStoreWatchListFree(xenStoreWatchListPtr list);

struct xenUnifiedDriver xenStoreDriver = {
    .xenClose = xenStoreClose,
    .xenDomainShutdown = xenStoreDomainShutdown,
    .xenDomainReboot = xenStoreDomainReboot,
    .xenDomainGetOSType = xenStoreDomainGetOSType,
    .xenDomainGetMaxMemory = xenStoreDomainGetMaxMemory,
    .xenDomainSetMemory = xenStoreDomainSetMemory,
    .xenDomainGetInfo = xenStoreGetDomainInfo,
};

#define virXenStoreError(code, ...)                                  \
        virReportErrorHelper(VIR_FROM_XENSTORE, code, __FILE__,      \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

/************************************************************************
 *									*
 *		Helper internal APIs					*
 *									*
 ************************************************************************/
/**
 * virConnectDoStoreList:
 * @conn: pointer to the hypervisor connection
 * @path: the absolute path of the directory in the store to list
 * @nb: OUT pointer to the number of items found
 *
 * Internal API querying the Xenstore for a list
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char **
virConnectDoStoreList(virConnectPtr conn, const char *path,
                      unsigned int *nb)
{
    xenUnifiedPrivatePtr priv;

    if (conn == NULL)
        return NULL;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL || path == NULL || nb == NULL)
        return NULL;

    return xs_directory (priv->xshandle, 0, path, nb);
}

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
    xenUnifiedPrivatePtr priv;

    if (!conn)
        return NULL;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;

    snprintf(s, 255, "/local/domain/%d/%s", domid, path);
    s[255] = 0;

    return xs_read(priv->xshandle, 0, &s[0], &len);
}

/**
 * virDomainDoStoreWrite:
 * @domain: a domain object
 * @path: the relative path of the data in the store to retrieve
 *
 * Internal API setting up a string value in the Xenstore
 * Requires write access to the XenStore
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virDomainDoStoreWrite(virDomainPtr domain, const char *path,
                      const char *value)
{
    char s[256];
    xenUnifiedPrivatePtr priv;
    int ret = -1;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xshandle == NULL)
        return -1;
    if (domain->conn->flags & VIR_CONNECT_RO)
        return -1;

    snprintf(s, 255, "/local/domain/%d/%s", domain->id, path);
    s[255] = 0;

    if (xs_write(priv->xshandle, 0, &s[0], value, strlen(value)))
        ret = 0;

    return ret;
}

/**
 * virDomainGetVM:
 * @domain: a domain object
 *
 * Internal API extracting a xenstore vm path.
 *
 * Returns the new string or NULL in case of error
 */
static char *
virDomainGetVM(virDomainPtr domain)
{
    char *vm;
    char query[200];
    unsigned int len;
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return NULL;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;

    snprintf(query, 199, "/local/domain/%d/vm", virDomainGetID(domain));
    query[199] = 0;

    vm = xs_read(priv->xshandle, 0, &query[0], &len);

    return vm;
}

/**
 * virDomainGetVMInfo:
 * @domain: a domain object
 * @vm: the xenstore vm path
 * @name: the value's path
 *
 * Internal API extracting one information the device used
 * by the domain from xensttore
 *
 * Returns the new string or NULL in case of error
 */
static char *
virDomainGetVMInfo(virDomainPtr domain, const char *vm, const char *name)
{
    char s[256];
    char *ret = NULL;
    unsigned int len = 0;
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return NULL;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;

    snprintf(s, 255, "%s/%s", vm, name);
    s[255] = 0;

    ret = xs_read(priv->xshandle, 0, &s[0], &len);

    return ret;
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
virDrvOpenStatus
xenStoreOpen(virConnectPtr conn,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             unsigned int flags)
{
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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
            virXenStoreError(VIR_ERR_NO_XEN,
                             "%s", _("failed to connect to Xen Store"));
        }
        return -1;
    }

    /* Init activeDomainList */
    if (VIR_ALLOC(priv->activeDomainList) < 0) {
        virReportOOMError();
        return -1;
    }

    /* Init watch list before filling in domInfoList,
       so we can know if it is the first time through
       when the callback fires */
    if (VIR_ALLOC(priv->xsWatchList) < 0) {
        virReportOOMError();
        return -1;
    }

    /* This will get called once at start */
    if ( xenStoreAddWatch(conn, "@releaseDomain",
                     "releaseDomain", xenStoreDomainReleased, priv) < 0 )
    {
        virXenStoreError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("adding watch @releaseDomain"));
        return -1;
    }

    /* The initial call of this will fill domInfoList */
    if( xenStoreAddWatch(conn, "@introduceDomain",
                     "introduceDomain", xenStoreDomainIntroduced, priv) < 0 )
    {
        virXenStoreError(VIR_ERR_INTERNAL_ERROR,
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
    xenUnifiedPrivatePtr priv;

    if (conn == NULL) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;

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
 * xenStoreGetDomainInfo:
 * @domain: pointer to the domain block
 * @info: the place where information should be stored
 *
 * Do a hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenStoreGetDomainInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    char *tmp, **tmp2;
    unsigned int nb_vcpus;
    char request[200];
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return -1;

    if ((domain == NULL) || (domain->conn == NULL) || (info == NULL)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xshandle == NULL)
        return -1;

    if (domain->id == -1)
        return -1;

    tmp = virDomainDoStoreQuery(domain->conn, domain->id, "running");
    if (tmp != NULL) {
        if (tmp[0] == '1')
            info->state = VIR_DOMAIN_RUNNING;
        VIR_FREE(tmp);
    } else {
        info->state = VIR_DOMAIN_NOSTATE;
    }
    tmp = virDomainDoStoreQuery(domain->conn, domain->id, "memory/target");
    if (tmp != NULL) {
        info->memory = atol(tmp);
        info->maxMem = atol(tmp);
        VIR_FREE(tmp);
    } else {
        info->memory = 0;
        info->maxMem = 0;
    }
#if 0
    /* doesn't seems to work */
    tmp = virDomainDoStoreQuery(domain->conn, domain->id, "cpu_time");
    if (tmp != NULL) {
        info->cpuTime = atol(tmp);
        VIR_FREE(tmp);
    } else {
        info->cpuTime = 0;
    }
#endif
    snprintf(request, 199, "/local/domain/%d/cpu", domain->id);
    request[199] = 0;
    tmp2 = virConnectDoStoreList(domain->conn, request, &nb_vcpus);
    if (tmp2 != NULL) {
        info->nrVirtCpu = nb_vcpus;
        VIR_FREE(tmp2);
    }
    return 0;
}

/**
 * xenStoreDomainGetState:
 * @domain: pointer to the domain block
 * @state: returned domain's state
 * @reason: returned state reason
 * @flags: additional flags, 0 for now
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenStoreDomainGetState(virDomainPtr domain,
                       int *state,
                       int *reason,
                       unsigned int flags)
{
    char *running;

    virCheckFlags(0, -1);

    if (domain->id == -1)
        return -1;

    running = virDomainDoStoreQuery(domain->conn, domain->id, "running");

    if (running && *running == '1')
        *state = VIR_DOMAIN_RUNNING;
    else
        *state = VIR_DOMAIN_NOSTATE;
    if (reason)
        *reason = 0;

    VIR_FREE(running);

    return 0;
}

/**
 * xenStoreDomainSetMemory:
 * @domain: pointer to the domain block
 * @memory: the max memory size in kilobytes.
 *
 * Change the maximum amount of memory allowed in the xen store
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenStoreDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    int ret;
    char value[20];

    if ((domain == NULL) || (domain->conn == NULL) ||
        (memory < 1024 * MIN_XEN_GUEST_SIZE)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }
    if (domain->id == -1)
        return -1;
    if ((domain->id == 0) && (memory < (2 * MIN_XEN_GUEST_SIZE * 1024)))
        return -1;
    snprintf(value, 19, "%lu", memory);
    value[19] = 0;
    ret = virDomainDoStoreWrite(domain, "memory/target", &value[0]);
    if (ret < 0)
        return -1;
    return 0;
}

/**
 * xenStoreDomainGetMaxMemory:
 * @domain: pointer to the domain block
 *
 * Ask the xenstore for the maximum memory allowed for a domain
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long long
xenStoreDomainGetMaxMemory(virDomainPtr domain)
{
    char *tmp;
    unsigned long long ret = 0;
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return ret;
    if (domain->id == -1)
        return 0;

    priv = domain->conn->privateData;
    xenUnifiedLock(priv);
    tmp = virDomainDoStoreQuery(domain->conn, domain->id, "memory/target");
    if (tmp != NULL) {
        ret = atol(tmp);
        VIR_FREE(tmp);
    }
    xenUnifiedUnlock(priv);
    return ret;
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
    int i, ret = -1, realnum = 0;
    long id;
    xenUnifiedPrivatePtr priv;

    if (conn == NULL) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

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
        VIR_FREE (idlist);
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
xenStoreDoListDomains(virConnectPtr conn, xenUnifiedPrivatePtr priv, int *ids, int maxids)
{
    char **idlist = NULL, *endptr;
    unsigned int num, i;
    int ret = -1;
    long id;

    if (priv->xshandle == NULL)
        goto out;

    idlist = xs_directory (priv->xshandle, 0, "/local/domain", &num);
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
    VIR_FREE (idlist);
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
    xenUnifiedPrivatePtr priv;
    int ret;

    if ((conn == NULL) || (ids == NULL)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    xenUnifiedLock(priv);
    ret = xenStoreDoListDomains(conn, priv, ids, maxids);
    xenUnifiedUnlock(priv);

    return ret;
}

/**
 * xenStoreLookupByName:
 * @conn: A xend instance
 * @name: The name of the domain
 *
 * Try to lookup a domain on the Xen Store based on its name.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenStoreLookupByName(virConnectPtr conn, const char *name)
{
    virDomainPtr ret = NULL;
    unsigned int num, i, len;
    long id = -1;
    char **idlist = NULL, *endptr;
    char prop[200], *tmp;
    int found = 0;
    struct xend_domain *xenddomain = NULL;
    xenUnifiedPrivatePtr priv;

    if ((conn == NULL) || (name == NULL)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;

    idlist = xs_directory(priv->xshandle, 0, "/local/domain", &num);
    if (idlist == NULL)
        goto done;

    for (i = 0; i < num; i++) {
        id = strtol(idlist[i], &endptr, 10);
        if ((endptr == idlist[i]) || (*endptr != 0)) {
            goto done;
        }
#if 0
        if (virConnectCheckStoreID(conn, (int) id) < 0)
            continue;
#endif
        snprintf(prop, 199, "/local/domain/%s/name", idlist[i]);
        prop[199] = 0;
        tmp = xs_read(priv->xshandle, 0, prop, &len);
        if (tmp != NULL) {
            found = STREQ (name, tmp);
            VIR_FREE(tmp);
            if (found)
                break;
        }
    }
    if (!found)
        goto done;

    ret = virGetDomain(conn, name, NULL);
    if (ret == NULL)
        goto done;

    ret->id = id;

done:
    VIR_FREE(xenddomain);
    VIR_FREE(idlist);

    return ret;
}

/**
 * xenStoreDomainShutdown:
 * @domain: pointer to the Domain block
 *
 * Shutdown the domain, the OS is requested to properly shutdown
 * and the domain may ignore it.  It will return immediately
 * after queuing the request.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenStoreDomainShutdown(virDomainPtr domain)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }
    if (domain->id == -1 || domain->id == 0)
        return -1;
    /*
     * this is very hackish, the domU kernel probes for a special
     * node in the xenstore and launch the shutdown command if found.
     */
    priv = domain->conn->privateData;
    xenUnifiedLock(priv);
    ret = virDomainDoStoreWrite(domain, "control/shutdown", "poweroff");
    xenUnifiedUnlock(priv);
    return ret;
}

/**
 * xenStoreDomainReboot:
 * @domain: pointer to the Domain block
 * @flags: extra flags for the reboot operation, not used yet
 *
 * Reboot the domain, the OS is requested to properly shutdown
 * and reboot but the domain may ignore it.  It will return immediately
 * after queuing the request.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenStoreDomainReboot(virDomainPtr domain, unsigned int flags)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    virCheckFlags(0, -1);

    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }
    if (domain->id == -1 || domain->id == 0)
        return -1;
    /*
     * this is very hackish, the domU kernel probes for a special
     * node in the xenstore and launch the shutdown command if found.
     */
    priv = domain->conn->privateData;
    xenUnifiedLock(priv);
    ret = virDomainDoStoreWrite(domain, "control/shutdown", "reboot");
    xenUnifiedUnlock(priv);
    return ret;
}

/*
 * xenStoreDomainGetOSType:
 * @domain: a domain object
 *
 * Get the type of domain operation system.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
static char *
xenStoreDomainGetOSType(virDomainPtr domain) {
    char *vm, *str = NULL;

    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenStoreError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }

    vm = virDomainGetVM(domain);
    if (vm) {
        xenUnifiedPrivatePtr priv = domain->conn->privateData;
        xenUnifiedLock(priv);
        str = virDomainGetVMInfo(domain, vm, "image/ostype");
        xenUnifiedUnlock(priv);
        VIR_FREE(vm);
    }

    return str;
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
int             xenStoreDomainGetVNCPort(virConnectPtr conn, int domid) {
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
char *          xenStoreDomainGetConsolePath(virConnectPtr conn, int domid) {
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
char * xenStoreDomainGetSerialConsolePath(virConnectPtr conn, int domid) {
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
xenStoreDomainGetNetworkID(virConnectPtr conn, int id, const char *mac) {
    char dir[80], path[128], **list = NULL, *val = NULL;
    unsigned int len, i, num;
    char *ret = NULL;
    xenUnifiedPrivatePtr priv;

    if (id < 0)
        return NULL;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;
    if (mac == NULL)
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
            ret = strdup(list[i]);

            if (ret == NULL)
                virReportOOMError();

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
xenStoreDomainGetDiskID(virConnectPtr conn, int id, const char *dev) {
    char dir[80], path[128], **list = NULL, *val = NULL;
    unsigned int devlen, len, i, num;
    char *ret = NULL;
    xenUnifiedPrivatePtr priv;

    if (id < 0)
        return NULL;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;
    if (dev == NULL)
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
                VIR_FREE (val);
            } else {
                ret = strdup(list[i]);

                if (ret == NULL)
                    virReportOOMError();

                VIR_FREE (val);
                VIR_FREE (list);
                return ret;
            }
        }
        VIR_FREE (list);
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
                VIR_FREE (val);
            } else {
                ret = strdup(list[i]);

                if (ret == NULL)
                    virReportOOMError();

                VIR_FREE (val);
                VIR_FREE (list);
                return ret;
            }
        }
        VIR_FREE (list);
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
    unsigned int len, i, num;
    char *ret = NULL;
    xenUnifiedPrivatePtr priv;

    if (id < 0)
        return NULL;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL)
        return NULL;
    if (bdf == NULL)
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
            ret = strdup(list[i]);
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
char *xenStoreDomainGetName(virConnectPtr conn,
                            int id) {
    char prop[200];
    xenUnifiedPrivatePtr priv;
    unsigned int len;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
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
int xenStoreDomainGetUUID(virConnectPtr conn,
                          int id,
                          unsigned char *uuid) {
    char prop[200];
    xenUnifiedPrivatePtr priv;
    unsigned int len;
    char *uuidstr;
    int ret = 0;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->xshandle == NULL)
        return -1;

    snprintf(prop, 199, "/local/domain/%d/vm", id);
    prop[199] = 0;
    /* This will return something like
     * /vm/00000000-0000-0000-0000-000000000000 */
    uuidstr = xs_read(priv->xshandle, 0, prop, &len);

    /* remove "/vm/" */
    ret = virUUIDParse(uuidstr + 4, uuid);

    VIR_FREE(uuidstr);

    return ret;
}

static void
xenStoreWatchListFree(xenStoreWatchListPtr list)
{
    int i;
    for (i=0; i<list->count; i++) {
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
int xenStoreAddWatch(virConnectPtr conn,
                     const char *path,
                     const char *token,
                     xenStoreWatchCallback cb,
                     void *opaque)
{
    xenStoreWatchPtr watch = NULL;
    int n;
    xenStoreWatchListPtr list;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (priv->xshandle == NULL)
        return -1;

    list = priv->xsWatchList;
    if(!list)
        return -1;

    /* check if we already have this callback on our list */
    for (n=0; n < list->count; n++) {
        if( STREQ(list->watches[n]->path, path) &&
            STREQ(list->watches[n]->token, token)) {
            virXenStoreError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("watch already tracked"));
            return -1;
        }
    }

    if (VIR_ALLOC(watch) < 0)
        goto no_memory;

    watch->path   = strdup(path);
    watch->token  = strdup(token);
    watch->cb     = cb;
    watch->opaque = opaque;

    if (watch->path == NULL || watch->token == NULL) {
        goto no_memory;
    }

    /* Make space on list */
    n = list->count;
    if (VIR_REALLOC_N(list->watches, n + 1) < 0) {
        goto no_memory;
    }

    list->watches[n] = watch;
    list->count++;

    return xs_watch(priv->xshandle, watch->path, watch->token);

  no_memory:
    if (watch) {
        VIR_FREE(watch->path);
        VIR_FREE(watch->token);
        VIR_FREE(watch);
    }

    virReportOOMError();

    return -1;
}

/*
 * The caller must hold the lock on the privateData
 * associated with the 'conn' parameter.
 */
int xenStoreRemoveWatch(virConnectPtr conn,
                        const char *path,
                        const char *token)
{
    int i;
    xenStoreWatchListPtr list;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (priv->xshandle == NULL)
        return -1;

    list = priv->xsWatchList;
    if(!list)
        return -1;

    for (i = 0 ; i < list->count ; i++) {
        if( STREQ(list->watches[i]->path, path) &&
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

            if (i < (list->count - 1))
                memmove(list->watches + i,
                        list->watches + i + 1,
                        sizeof(*(list->watches)) *
                                (list->count - (i + 1)));

            if (VIR_REALLOC_N(list->watches,
                              list->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            list->count--;
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
    int i;
    for (i = 0 ; i < list->count ; i++)
        if( STREQ(path, list->watches[i]->path) &&
            STREQ(token, list->watches[i]->token) )
            return list->watches[i];

    return NULL;
}

static void
xenStoreWatchEvent(int watch ATTRIBUTE_UNUSED,
                   int fd ATTRIBUTE_UNUSED,
                   int events,
                   void *data)
{
    char		 **event;
    char		 *path;
    char		 *token;
    unsigned int	 stringCount;
    xenStoreWatchPtr     sw;

    virConnectPtr        conn = data;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if(!priv) return;

    /* only set a watch on read and write events */
    if (events & (VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP)) return;

    xenUnifiedLock(priv);

    if(!priv->xshandle)
        goto cleanup;

    event = xs_read_watch(priv->xshandle, &stringCount);
    if (!event)
        goto cleanup;

    path  = event[XS_WATCH_PATH];
    token = event[XS_WATCH_TOKEN];

    sw = xenStoreFindWatch(priv->xsWatchList, path, token);
    if( sw )
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
int xenStoreDomainIntroduced(virConnectPtr conn,
                             const char *path ATTRIBUTE_UNUSED,
                             const char *token ATTRIBUTE_UNUSED,
                             void *opaque)
{
    int i, j, found, missing = 0, retries = 20;
    int new_domain_cnt;
    int *new_domids;
    int nread;

    xenUnifiedPrivatePtr priv = opaque;

retry:
    new_domain_cnt = xenStoreNumOfDomains(conn);
    if (new_domain_cnt < 0)
        return -1;

    if( VIR_ALLOC_N(new_domids,new_domain_cnt) < 0 ) {
        virReportOOMError();
        return -1;
    }
    nread = xenStoreDoListDomains(conn, priv, new_domids, new_domain_cnt);
    if (nread != new_domain_cnt) {
        /* mismatch. retry this read */
        VIR_FREE(new_domids);
        goto retry;
    }

    missing = 0;
    for (i=0 ; i < new_domain_cnt ; i++) {
        found = 0;
        for (j = 0 ; j < priv->activeDomainList->count ; j++) {
            if (priv->activeDomainList->doms[j]->id == new_domids[i]) {
                found = 1;
                break;
            }
        }

        if (!found) {
            virDomainEventPtr event;
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

            event = virDomainEventNew(new_domids[i], name, uuid,
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
int xenStoreDomainReleased(virConnectPtr conn,
                            const char *path  ATTRIBUTE_UNUSED,
                            const char *token ATTRIBUTE_UNUSED,
                            void *opaque)
{
    int i, j, found, removed, retries = 20;
    int new_domain_cnt;
    int *new_domids;
    int nread;

    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) opaque;

    if(!priv->activeDomainList->count) return 0;

retry:
    new_domain_cnt = xenStoreNumOfDomains(conn);
    if (new_domain_cnt < 0)
        return -1;

    if( VIR_ALLOC_N(new_domids,new_domain_cnt) < 0 ) {
        virReportOOMError();
        return -1;
    }
    nread = xenStoreDoListDomains(conn, priv, new_domids, new_domain_cnt);
    if (nread != new_domain_cnt) {
        /* mismatch. retry this read */
        VIR_FREE(new_domids);
        goto retry;
    }

    removed = 0;
    for (j=0 ; j < priv->activeDomainList->count ; j++) {
        found = 0;
        for (i=0 ; i < new_domain_cnt ; i++) {
            if (priv->activeDomainList->doms[j]->id == new_domids[i]) {
                found = 1;
                break;
            }
        }

        if (!found) {
            virDomainEventPtr event =
                virDomainEventNew(-1,
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
