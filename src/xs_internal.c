/*
 * xs_internal.c: access to Xen Store
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

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
#include <xen/xen.h>

#include <xs.h>

#include "internal.h"
#include "driver.h"
#include "xs_internal.h"
#include "xen_internal.h" /* for xenHypervisorCheckID */

#define XEN_HYPERVISOR_SOCKET "/proc/xen/privcmd"

#ifndef PROXY
static virDriver xenStoreDriver = {
    VIR_DRV_XEN_STORE,
    "XenStore",
    (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
    (DOM0_INTERFACE_VERSION & 0xFFFF),
    NULL, /* init */
    xenStoreOpen, /* open */
    xenStoreClose, /* close */
    NULL, /* type */
    NULL, /* version */
    NULL, /* nodeGetInfo */
    xenStoreListDomains, /* listDomains */
    NULL, /* numOfDomains */
    NULL, /* domainCreateLinux */
    NULL, /* domainLookupByID */
    NULL, /* domainLookupByUUID */
    xenStoreDomainLookupByName, /* domainLookupByName */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    xenStoreDomainShutdown, /* domainShutdown */
    xenStoreDomainReboot, /* domainReboot */
    NULL, /* domainDestroy */
    NULL, /* domainFree */
    NULL, /* domainGetName */
    NULL, /* domainGetID */
    NULL, /* domainGetUUID */
    NULL, /* domainGetOSType */
    xenStoreDomainGetMaxMemory, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    xenStoreDomainSetMemory, /* domainSetMemory */
    xenStoreGetDomainInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainDumpXML */
    NULL, /* listDefinedDomains */
    NULL, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
};

/**
 * xenStoreRegister:
 *
 * Registers the xenStore driver
 */
void xenStoreRegister(void)
{
    virRegisterDriver(&xenStoreDriver);
}
#endif /* ! PROXY */

/**
 * virXenStoreError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the xend store interface
 */
static void
virXenStoreError(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, VIR_FROM_XENSTORE, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}

/************************************************************************
 *									*
 *		Helper internal APIs					*
 *									*
 ************************************************************************/
#ifndef PROXY
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
    if ((conn == NULL) || (conn->xshandle == NULL) || (path == NULL) ||
        (nb == NULL))
        return (NULL);

    return xs_directory(conn->xshandle, 0, path, nb);
}
#endif /* ! PROXY */

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

    if (!conn || conn->xshandle == NULL)
        return (NULL);

    snprintf(s, 255, "/local/domain/%d/%s", domid, path);
    s[255] = 0;

    return xs_read(conn->xshandle, 0, &s[0], &len);
}

#ifndef PROXY
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

    int ret = -1;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (-1);
    if (domain->conn->xshandle == NULL)
        return (-1);
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);

    snprintf(s, 255, "/local/domain/%d/%s", domain->handle, path);
    s[255] = 0;

    if (xs_write(domain->conn->xshandle, 0, &s[0], value, strlen(value)))
        ret = 0;

    return (ret);
}

/**
 * virDomainGetVM:
 * @domain: a domain object
 *
 * Internal API extracting a xenstore vm path.
 *
 * Returns the new string or NULL in case of error
 */
char *
virDomainGetVM(virDomainPtr domain)
{
    char *vm;
    char query[200];
    unsigned int len;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (NULL);
    if (domain->conn->xshandle == NULL)
        return (NULL);

    snprintf(query, 199, "/local/domain/%d/vm", virDomainGetID(domain));
    query[199] = 0;

    vm = xs_read(domain->conn->xshandle, 0, &query[0], &len);

    return (vm);
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
char *
virDomainGetVMInfo(virDomainPtr domain, const char *vm, const char *name)
{
    char s[256];
    char *ret = NULL;
    unsigned int len = 0;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (NULL);
    if (domain->conn->xshandle == NULL)
        return (NULL);

    snprintf(s, 255, "%s/%s", vm, name);
    s[255] = 0;

    ret = xs_read(domain->conn->xshandle, 0, &s[0], &len);

    return (ret);
}

#if 0
/**
 * virConnectCheckStoreID:
 * @conn: pointer to the hypervisor connection
 * @id: the id number as returned from Xenstore
 *
 * the xenstore sometimes list non-running domains, double check
 * from the hypervisor if we have direct access
 *
 * Returns -1 if the check failed, 0 if successful or not possible to check
 */
static int
virConnectCheckStoreID(virConnectPtr conn, int id)
{
    if (conn->handle >= 0) {
        int tmp;

        tmp = xenHypervisorCheckID(conn, id);
        if (tmp < 0)
            return (-1);
    }
    return (0);
}
#endif
#endif /* ! PROXY */

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
xenStoreOpen(virConnectPtr conn, const char *name, int flags)
{
    if ((name != NULL) && (strcasecmp(name, "xen")))
        return(-1);

#ifdef PROXY
    conn->xshandle = xs_daemon_open_readonly();
#else
    if (flags & VIR_DRV_OPEN_RO)
	conn->xshandle = xs_daemon_open_readonly();
    else
	conn->xshandle = xs_daemon_open();
#endif /* ! PROXY */

    if (conn->xshandle == NULL) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
            virXenStoreError(conn, VIR_ERR_NO_XEN, 
	                     _("failed to connect to Xen Store"));
        return (-1);
    }
    return (0);
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
    if (conn == NULL) {
        virXenStoreError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return(-1);
    }
    if (conn->xshandle == NULL)
	return(-1);

    xs_daemon_close(conn->xshandle);
    return (0);
}

#ifndef PROXY
/**
 * xenStoreGetDomainInfo:
 * @domain: pointer to the domain block
 * @info: the place where information should be stored
 *
 * Do an hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenStoreGetDomainInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    char *tmp, **tmp2;
    unsigned int nb_vcpus;
    char request[200];

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (-1);

    if ((domain == NULL) || (domain->conn == NULL) || (info == NULL)) {
        virXenStoreError(domain ? domain->conn : NULL, VIR_ERR_INVALID_ARG,
	                 __FUNCTION__);
	return(-1);
    }
    if (domain->conn->xshandle == NULL)
        return(-1);

    tmp = virDomainDoStoreQuery(domain->conn, domain->handle, "running");
    if (tmp != NULL) {
        if (tmp[0] == '1')
            info->state = VIR_DOMAIN_RUNNING;
        free(tmp);
    } else {
        info->state = VIR_DOMAIN_NONE;
    }
    tmp = virDomainDoStoreQuery(domain->conn, domain->handle, "memory/target");
    if (tmp != NULL) {
        info->memory = atol(tmp);
        info->maxMem = atol(tmp);
        free(tmp);
    } else {
        info->memory = 0;
        info->maxMem = 0;
    }
#if 0
    /* doesn't seems to work */
    tmp = virDomainDoStoreQuery(domain->conn, domain->handle, "cpu_time");
    if (tmp != NULL) {
        info->cpuTime = atol(tmp);
        free(tmp);
    } else {
        info->cpuTime = 0;
    }
#endif
    snprintf(request, 199, "/local/domain/%d/cpu", domain->handle);
    request[199] = 0;
    tmp2 = virConnectDoStoreList(domain->conn, request, &nb_vcpus);
    if (tmp2 != NULL) {
        info->nrVirtCpu = nb_vcpus;
        free(tmp2);
    }
    return (0);
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

    if ((domain == NULL) || (domain->conn == NULL) || (memory < 4096)) {
        virXenStoreError(domain ? domain->conn : NULL, VIR_ERR_INVALID_ARG,
	                 __FUNCTION__);
	return(-1);
    }
    snprintf(value, 19, "%lu", memory);
    value[19] = 0;
    ret = virDomainDoStoreWrite(domain, "memory/target", &value[0]);
    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenStoreDomainGetMaxMemory:
 * @domain: pointer to the domain block
 *
 * Ask the xenstore for the maximum memory allowed for a domain
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
xenStoreDomainGetMaxMemory(virDomainPtr domain)
{
    char *tmp;
    unsigned long ret = 0;

    if (!VIR_IS_CONNECTED_DOMAIN(domain))
        return (ret);

    tmp = virDomainDoStoreQuery(domain->conn, domain->handle, "memory/target");
    if (tmp != NULL) {
	ret = (unsigned long) atol(tmp);
	free(tmp);
    }
    return(ret);
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
    char **idlist;
    int ret = -1;

    if ((conn == NULL) || (conn->xshandle == NULL)) {
        virXenStoreError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return(-1);
    }
    idlist = xs_directory(conn->xshandle, 0, "/local/domain", &num);
    if (idlist) {
        free(idlist);
	ret = num;
    }
    return(ret);
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
    char **idlist = NULL, *endptr;
    unsigned int num, i;
    int ret;
    long id;

    if ((conn == NULL) || (ids == NULL)) {
        virXenStoreError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return(-1);
    }
    if (conn->xshandle == NULL)
        return(-1);

    idlist = xs_directory(conn->xshandle, 0, "/local/domain", &num);
    if (idlist == NULL)
	return(-1);

    for (ret = 0, i = 0; (i < num) && (ret < maxids); i++) {
	id = strtol(idlist[i], &endptr, 10);
	if ((endptr == idlist[i]) || (*endptr != 0)) {
	    ret = -1;
	    break;
	}
#if 0
	if (virConnectCheckStoreID(conn, (int) id) < 0)
	    continue;
#endif
	ids[ret++] = (int) id;
    }
    return(ret);
}

/**
 * xenStoreDomainLookupByName:
 * @conn: A xend instance
 * @name: The name of the domain
 *
 * Try to lookup a domain on the Xen Store based on its name.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenStoreDomainLookupByName(virConnectPtr conn, const char *name)
{
    virDomainPtr ret = NULL;
    unsigned int num, i, len;
    long id = -1;
    char **idlist = NULL, *endptr;
    char prop[200], *tmp, *path = NULL;
    int found = 0;
    struct xend_domain *xenddomain = NULL;

    if ((conn == NULL) || (name == NULL)) {
        virXenStoreError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return(NULL);
    }
    if (conn->xshandle == NULL)
        return(NULL);

    idlist = xs_directory(conn->xshandle, 0, "/local/domain", &num);
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
	tmp = xs_read(conn->xshandle, 0, prop, &len);
	if (tmp != NULL) {
	    found = !strcmp(name, tmp);
	    free(tmp);
	    if (found)
		break;
	}
    }
    path = xs_get_domain_path(conn->xshandle, (unsigned int) id);

    if (!found)
        return(NULL);

    ret = virGetDomain(conn, name, NULL);
    if (ret == NULL) {
        virXenStoreError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
	if (path != NULL)
	    free(path);
	goto done;
    }
    ret->handle = id;
    ret->path = path;

done:
    if (xenddomain != NULL)
	free(xenddomain);
    if (idlist != NULL)
	free(idlist);

    return(ret);
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
    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenStoreError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	                 __FUNCTION__);
        return(-1);
    }
    /*
     * this is very hackish, the domU kernel probes for a special 
     * node in the xenstore and launch the shutdown command if found.
     */
    return(virDomainDoStoreWrite(domain, "control/shutdown", "halt"));
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
xenStoreDomainReboot(virDomainPtr domain, unsigned int flags ATTRIBUTE_UNUSED)
{
    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenStoreError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	                 __FUNCTION__);
        return(-1);
    }
    /*
     * this is very hackish, the domU kernel probes for a special 
     * node in the xenstore and launch the shutdown command if found.
     */
    return(virDomainDoStoreWrite(domain, "control/shutdown", "reboot"));
}
#endif /* ! PROXY */

/**
 * xenStoreDomainGetVNCPort:
 * @conn: the hypervisor connection
 * @domid: id of the domain
 *
 * Return the port number on which the domain is listening for VNC
 * connections. 
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
        free(tmp);
    }
    return(ret);
}

/**
 * xenStoreDomainGetConsolePath:
 * @conn: the hypervisor connection
 * @domid: id of the domain
 *
 * Return the path to the psuedo TTY on which the guest domain's
 * serial console is attached.
 *
 * Returns the path to the serial console. It is the callers
 * responsibilty to free() the return string. Returns NULL
 * on error
 */
char *          xenStoreDomainGetConsolePath(virConnectPtr conn, int domid) {
  return virDomainDoStoreQuery(conn, domid, "console/tty");
}
