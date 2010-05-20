/*
 * proxy_client.c: client side of the communication with the libvirt proxy.
 *
 * Copyright (C) 2006, 2008, 2009, 2010 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <string.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "driver.h"
#include "proxy_internal.h"
#include "util.h"
#include "xen_driver.h"
#include "memory.h"

#define STANDALONE

#define VIR_FROM_THIS VIR_FROM_PROXY

static int xenProxyClose(virConnectPtr conn);
static virDrvOpenStatus xenProxyOpen(virConnectPtr conn, virConnectAuthPtr auth, int flags);
static int xenProxyGetVersion(virConnectPtr conn, unsigned long *hvVer);
static int xenProxyNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);
static char *xenProxyGetCapabilities(virConnectPtr conn);
static unsigned long xenProxyDomainGetMaxMemory(virDomainPtr domain);
static int xenProxyDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info);
static char *xenProxyDomainGetOSType(virDomainPtr domain);

struct xenUnifiedDriver xenProxyDriver = {
    xenProxyOpen, /* open */
    xenProxyClose, /* close */
    xenProxyGetVersion, /* version */
    NULL, /* hostname */
    xenProxyNodeGetInfo, /* nodeGetInfo */
    xenProxyGetCapabilities, /* getCapabilities */
    xenProxyListDomains, /* listDomains */
    xenProxyNumOfDomains, /* numOfDomains */
    NULL, /* domainCreateXML */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    NULL, /* domainDestroy */
    xenProxyDomainGetOSType, /* domainGetOSType */
    xenProxyDomainGetMaxMemory, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    xenProxyDomainGetInfo, /* domainGetInfo */
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
    NULL, /* domainAttachDeviceFlags */
    NULL, /* domainDetachDeviceFlags */
    NULL, /* domainUpdateDeviceFlags */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
};


/************************************************************************
 *									*
 *			Error handling					*
 *									*
 ************************************************************************/

#define virProxyError(code, ...)                                           \
        virReportErrorHelper(NULL, VIR_FROM_PROXY, code, __FILE__,         \
                               __FUNCTION__, __LINE__, __VA_ARGS__)

/************************************************************************
 *									*
 *	Automatic startup of the proxy server if it is not running	*
 *									*
 ************************************************************************/
/**
 * virProxyFindServerPath:
 *
 * Tries to find the path to the gam_server binary.
 *
 * Returns path on success or NULL in case of error.
 */
static const char *
virProxyFindServerPath(void)
{
    static const char *serverPaths[] = {
        BINDIR "/libvirt_proxy",
        "/usr/bin/libvirt_proxy_dbg",
        NULL
    };
    int i;
    const char *debugProxy = getenv("LIBVIRT_DEBUG_PROXY");

    if (debugProxy)
        return(debugProxy);

    for (i = 0; serverPaths[i]; i++) {
        if (access(serverPaths[i], X_OK | R_OK) == 0) {
            return serverPaths[i];
        }
    }
    return NULL;
}

/**
 * virProxyForkServer:
 *
 * Forks and try to launch the proxy server processing the requests for
 * libvirt when communicating with Xen.
 *
 * Returns 0 in case of success or -1 in case of detected error.
 */
static int
virProxyForkServer(void)
{
    const char *proxyPath = virProxyFindServerPath();
    pid_t pid;
    const char *proxyarg[2];

    if (!proxyPath) {
        VIR_WARN0("failed to find libvirt_proxy");
        return(-1);
    }

    VIR_DEBUG("Asking to launch %s", proxyPath);

    proxyarg[0] = proxyPath;
    proxyarg[1] = NULL;

    if (virExecDaemonize(proxyarg, NULL, NULL,
                         &pid, -1, NULL, NULL, 0,
                         NULL, NULL, NULL) < 0)
        VIR_ERROR0(_("Failed to fork libvirt_proxy"));

    return (0);
}

/************************************************************************
 *									*
 *		Processing of client sockets				*
 *									*
 ************************************************************************/

/**
 * virProxyOpenClientSocket:
 * @path: the filename for the socket
 *
 * try to connect to the socket open by libvirt_proxy
 *
 * Returns the associated file descriptor or -1 in case of failure
 */
static int
virProxyOpenClientSocket(const char *path) {
    int fd;
    struct sockaddr_un addr;
    int trials = 0;

retry:
    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return(-1);
    }

    /*
     * Abstract socket do not hit the filesystem, way more secure and
     * guaranteed to be atomic
     */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    if (virStrcpy(&addr.sun_path[1], path, sizeof(addr.sun_path) - 1) == NULL) {
        close(fd);
        return -1;
    }

    /*
     * now bind the socket to that address and listen on it
     */
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        if (trials < 3) {
            if (virProxyForkServer() < 0)
                return(-1);
            trials++;
            usleep(5000 * trials * trials);
            goto retry;
        }
        return (-1);
    }

    DEBUG("connected to unix socket %s via %d", path, fd);

    return (fd);
}

/**
 * virProxyCloseSocket:
 * @priv: the Xen proxy data
 *
 * Close the socket from that client. The caller must
 * hold the lock on 'priv' before calling
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
virProxyCloseSocket(xenUnifiedPrivatePtr priv) {
    int ret;

    if (priv->proxy < 0)
        return(-1);

    ret = close(priv->proxy);
    if (ret != 0)
        VIR_WARN("Failed to close socket %d", priv->proxy);
    else
        VIR_DEBUG("Closed socket %d", priv->proxy);
    priv->proxy = -1;
    return(ret);
}

/**
 * virProxyReadClientSocket:
 * @fd: the socket
 * @buffer: the target memory area
 * @len: the length in bytes
 *
 * Process a read from a client socket
 *
 * Returns the number of byte read or -1 in case of error.
 */
static int
virProxyReadClientSocket(int fd, char *buffer, int len) {
    int ret;

    if ((fd < 0) || (buffer == NULL) || (len < 0))
        return(-1);

retry:
    ret = read(fd, buffer, len);
    if (ret < 0) {
        if (errno == EINTR) {
            VIR_DEBUG("read socket %d interrupted", fd);
            goto retry;
        }
        VIR_WARN("Failed to read socket %d", fd);
        return(-1);
    }

    VIR_DEBUG("read %d bytes from socket %d",
              ret, fd);
    return(ret);
}

/**
 * virProxyWriteClientSocket:
 * @fd: the socket
 * @data: the data
 * @len: the length of data in bytes
 *
 * Process a read from a client socket
 */
static int
virProxyWriteClientSocket(int fd, const char *data, int len) {
    int ret;

    if ((fd < 0) || (data == NULL) || (len < 0))
        return(-1);

    ret = safewrite(fd, data, len);
    if (ret < 0) {
        VIR_WARN("Failed to write to socket %d", fd);
        return(-1);
    }
    VIR_DEBUG("wrote %d bytes to socket %d",
              len, fd);

    return(0);
}

/************************************************************************
 *									*
 *			Proxy commands processing			*
 *									*
 ************************************************************************/

/**
 * xenProxyClose:
 * @conn: pointer to the hypervisor connection
 *
 * Shutdown the Xen proxy communication layer
 */
static int
xenProxyClose(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv;

    if (conn == NULL) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (!priv) {
        virProxyError(VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        return -1;
    }

    xenUnifiedLock(priv);
    virProxyCloseSocket (priv);
    xenUnifiedUnlock(priv);

    return 0;
}

static int ATTRIBUTE_NONNULL(2)
xenProxyCommand(virConnectPtr conn, virProxyPacketPtr request,
                virProxyFullPacketPtr answer, int quiet) {
    static int serial = 0;
    int ret;
    virProxyPacketPtr res = NULL;
    xenUnifiedPrivatePtr priv;

    if (conn == NULL) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (!priv) {
        virProxyError(VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        return -1;
    }

    xenUnifiedLock(priv);

    /* Fail silently. */
    if (priv->proxy == -1)
        goto error;

    /*
     * normal communication serial numbers are in 0..4095
     */
    ++serial;
    if (serial >= 4096)
        serial = 0;
    request->version = PROXY_PROTO_VERSION;
    request->serial = serial;
    ret  = virProxyWriteClientSocket(priv->proxy, (const char *) request,
                                     request->len);
    if (ret < 0) {
        if (!quiet)
            virReportSystemError(errno, "%s",
                                 _("failed to write proxy request"));
        goto error;
    }
retry:
    if (answer == NULL) {
        /* read in situ */
        ret  = virProxyReadClientSocket(priv->proxy, (char *) request,
                                        sizeof(virProxyPacket));
        if (ret < 0) {
            if (!quiet)
                virReportSystemError(errno, "%s",
                                     _("failed to read proxy reply"));
            goto error;
        }
        if (ret != sizeof(virProxyPacket)) {
            virProxyError(VIR_ERR_INTERNAL_ERROR,
                          _("Communication error with proxy: got %d bytes of %d"),
                          ret, (int) sizeof(virProxyPacket));
            goto error;
        }
        res = request;
        if (res->len != sizeof(virProxyPacket)) {
            virProxyError(VIR_ERR_INTERNAL_ERROR,
                          _("Communication error with proxy: expected %d bytes got %d"),
                          (int) sizeof(virProxyPacket), res->len);
            goto error;
        }
    } else {
        /* read in packet provided */
        ret  = virProxyReadClientSocket(priv->proxy, (char *) answer,
                                        sizeof(virProxyPacket));
        if (ret < 0) {
            if (!quiet)
                virReportSystemError(errno, "%s",
                                     _("failed to read proxy reply"));
            goto error;
        }
        if (ret != sizeof(virProxyPacket)) {
            virProxyError(VIR_ERR_INTERNAL_ERROR,
                          _("Communication error with proxy: got %d bytes of %d"),
                          ret, (int) sizeof(virProxyPacket));
            goto error;
        }
        res = (virProxyPacketPtr) answer;
        if ((res->len < sizeof(virProxyPacket)) ||
            (res->len > sizeof(virProxyFullPacket))) {
            virProxyError(VIR_ERR_INTERNAL_ERROR,
                          _("Communication error with proxy: got %d bytes packet"),
                          res->len);
            goto error;
        }
        if (res->len > sizeof(virProxyPacket)) {
            ret  = virProxyReadClientSocket(priv->proxy,
                                   (char *) &(answer->extra.arg[0]),
                                            res->len - ret);
            if (ret != (int) (res->len - sizeof(virProxyPacket))) {
                virProxyError(VIR_ERR_INTERNAL_ERROR,
                              _("Communication error with proxy: got %d bytes of %d"),
                              ret, (int) sizeof(virProxyPacket));
                goto error;
            }
        }
    }
    /*
     * do more checks on the incoming packet.
     */
    if ((res->version != PROXY_PROTO_VERSION) ||
        (res->len < sizeof(virProxyPacket))) {
        virProxyError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("Communication error with proxy: malformed packet"));
        goto error;
    }
    if (res->serial != serial) {
        VIR_WARN("got asynchronous packet number %d", res->serial);
        goto retry;
    }

    xenUnifiedUnlock(priv);
    return 0;

error:
    virProxyCloseSocket(priv);
    xenUnifiedUnlock(priv);
    return -1;
}

/**
 * xenProxyOpen:
 * @conn: pointer to the hypervisor connection
 * @name: URL for the target, NULL for local
 * @flags: combination of virDrvOpenFlag(s)
 *
 * Try to initialize the Xen proxy communication layer
 * This can be opened only for a read-only kind of access
 *
 * Returns 0 in case of success, and -1 in case of failure
 */
virDrvOpenStatus
xenProxyOpen(virConnectPtr conn,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             int flags)
{
    virProxyPacket req;
    int ret;
    int fd;
    xenUnifiedPrivatePtr priv;

    if (!(flags & VIR_CONNECT_RO))
        return(-1);

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    priv->proxy = -1;

    fd = virProxyOpenClientSocket(PROXY_SOCKET_PATH);
    if (fd < 0) {
            virProxyError(VIR_ERR_NO_XEN, PROXY_SOCKET_PATH);
        return(-1);
    }
    priv->proxy = fd;

    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_NONE;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 1);
    if ((ret < 0) || (req.command != VIR_PROXY_NONE)) {
        virProxyError(VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        return(-1);
    }
    return(0);
}

/************************************************************************
 *									*
 *			Driver entry points				*
 *									*
 ************************************************************************/

/**
 * xenProxyGetVersion:
 * @conn: pointer to the Xen Daemon block
 * @hvVer: return value for the version of the running hypervisor (OUT)
 *
 * Get the version level of the Hypervisor running.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
static int
xenProxyGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    virProxyPacket req;
    int ret;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (hvVer == NULL) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_VERSION;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 0);
    if (ret < 0) {
        return(-1);
    }
    *hvVer = req.data.larg;
    return(0);
}

/**
 * xenProxyListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their ID in @maxids
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenProxyListDomains(virConnectPtr conn, int *ids, int maxids)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;
    int nb;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if ((ids == NULL) || (maxids <= 0)) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_LIST;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        return(-1);
    }
    nb = ans.data.arg;
    if ((nb > 1020) || (nb <= 0) ||
        (ans.len <= sizeof(virProxyPacket)) ||
        (ans.len > sizeof(virProxyFullPacket))) {
        virProxyError(VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        return(-1);
    }
    if (nb > maxids)
        nb = maxids;
    memmove(ids, &ans.extra.arg[0], nb * sizeof(int));

    return(nb);
}

/**
 * xenProxyNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenProxyNumOfDomains(virConnectPtr conn)
{
    virProxyPacket req;
    int ret;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_NUM_DOMAIN;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 0);
    if (ret < 0) {
        return(-1);
    }
    return(req.data.arg);
}


/**
 * xenProxyDomainGetDomMaxMemory:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Ask the Xen Daemon for the maximum memory allowed for a domain
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
static unsigned long
xenProxyDomainGetDomMaxMemory(virConnectPtr conn, int id)
{
    virProxyPacket req;
    int ret;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (0);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_MAX_MEMORY;
    req.data.arg = id;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 0);
    if (ret < 0) {
        return(0);
    }
    return(req.data.larg);
}

/**
 * xenProxyDomainGetMaxMemory:
 * @domain: pointer to the domain block
 *
 * Ask the Xen Daemon for the maximum memory allowed for a domain
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
static unsigned long
xenProxyDomainGetMaxMemory(virDomainPtr domain)
{
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virProxyError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }
    if (domain->id < 0)
        return (0);
    return(xenProxyDomainGetDomMaxMemory(domain->conn, domain->id));
}

/**
 * xenProxyDomainGetInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainInfo structure allocated by the user
 *
 * This method looks up information about a domain and update the
 * information block provided.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
xenProxyDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virProxyError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->id < 0)
        return (-1);
    if (info == NULL) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_DOMAIN_INFO;
    req.data.arg = domain->id;
    req.len = sizeof(req);
    ret = xenProxyCommand(domain->conn, &req, &ans, 0);
    if (ret < 0) {
        return(-1);
    }
    if (ans.len != sizeof(virProxyPacket) + sizeof(virDomainInfo)) {
        virProxyError(VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        return (-1);
    }
    memmove(info, &ans.extra.dinfo, sizeof(virDomainInfo));

    return(0);
}

/**
 * xenProxyLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenProxyLookupByID(virConnectPtr conn, int id)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    unsigned char uuid[VIR_UUID_BUFLEN];
    const char *name;
    int ret;
    virDomainPtr res;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (id < 0) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_LOOKUP_ID;
    req.data.arg = id;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        return(NULL);
    }
    if (ans.data.arg == -1) {
        return(NULL);
    }
    memcpy(uuid, &ans.extra.str[0], VIR_UUID_BUFLEN);
    name = &ans.extra.str[VIR_UUID_BUFLEN];
    res = virGetDomain(conn, name, uuid);
        if (res) res->id = id;
    return(res);
}

/**
 * xenProxyLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the domain
 *
 * Try to lookup a domain on xend based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenProxyLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virProxyFullPacket req;
    const char *name;
    int ret;
    virDomainPtr res;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    memset(&req, 0, sizeof(virProxyPacket));
    req.command = VIR_PROXY_LOOKUP_UUID;
    req.len = sizeof(virProxyPacket) + VIR_UUID_BUFLEN;
    memcpy(&req.extra.str[0], uuid, VIR_UUID_BUFLEN);

    ret = xenProxyCommand(conn, (virProxyPacketPtr) &req, &req, 0);
    if (ret < 0) {
        return(NULL);
    }
    if (req.data.arg == -1) {
        return(NULL);
    }
    name = &req.extra.str[0];
    res = virGetDomain(conn, name, uuid);
        if (res) res->id = req.data.arg;
    return(res);
}

/**
 * xenProxyLookupByName:
 * @conn: A xend instance
 * @name: The name of the domain
 *
 * This method looks up information about a domain based on its name
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenProxyLookupByName(virConnectPtr conn, const char *name)
{
    virProxyFullPacket req;
    int ret, len;
    virDomainPtr res;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    len = strlen(name);
    if (len > 1000) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    memset(&req, 0, sizeof(virProxyPacket));
    req.command = VIR_PROXY_LOOKUP_NAME;
    req.len = sizeof(virProxyPacket) + len + 1;
    strcpy(&req.extra.str[0], name);
    ret = xenProxyCommand(conn, (virProxyPacketPtr) &req, &req, 0);
    if (ret < 0) {
        return(NULL);
    }
    if (req.data.arg == -1) {
        return(NULL);
    }
    res = virGetDomain(conn, name, (const unsigned char *)&req.extra.str[0]);
        if (res) res->id = req.data.arg;
    return(res);
}

/**
 * xenProxyNodeGetInfo:
 * @conn: pointer to the Xen Daemon block
 * @info: pointer to a virNodeInfo structure allocated by the user
 *
 * Extract hardware information about the node.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
xenProxyNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info) {
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virProxyError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_NODE_INFO;
    req.data.arg = 0;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        return(-1);
    }
    if (ans.data.arg == -1) {
        return(-1);
    }
    if (ans.len != sizeof(virProxyPacket) + sizeof(virNodeInfo)) {
        return(-1);
    }
    memcpy(info, &ans.extra.ninfo, sizeof(virNodeInfo));
    return(0);
}

/**
 * xenProxyGetCapabilities:
 * @conn: pointer to the Xen Daemon block
 *
 * Extract capabilities of the hypervisor.
 *
 * Returns capabilities in case of success (freed by caller)
 * and NULL in case of failure.
 */
static char *
xenProxyGetCapabilities (virConnectPtr conn)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret, xmllen;
    char *xml;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_GET_CAPABILITIES;
    req.data.arg = 0;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        return NULL;
    }
    if (ans.data.arg == -1)
        return NULL;
    if (ans.len <= sizeof(virProxyPacket)
        || ans.len > sizeof (ans) - sizeof(virProxyPacket)) {
        virProxyError(VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        return NULL;
    }

    xmllen = ans.len - sizeof (virProxyPacket);
    if (VIR_ALLOC_N(xml, xmllen+1) < 0) {
        virReportOOMError();
        return NULL;
    }
    memcpy (xml, ans.extra.str, xmllen);
    xml[xmllen] = '\0';

    return xml;
}

/**
 * xenProxyDomainDumpXML:
 * @domain: a domain object
 * @flags: xml generation flags
 *
 * This method generates an XML description of a domain.
 *
 * Returns the XML document on success, NULL otherwise.
 */
char *
xenProxyDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;
    int xmllen;
    char *xml;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virProxyError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    if (domain->id < 0)
        return (NULL);
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_DOMAIN_XML;
    req.data.arg = domain->id;
    req.len = sizeof(req);
    ret = xenProxyCommand(domain->conn, &req, &ans, 0);
    if (ret < 0) {
        return(NULL);
    }
    if (ans.len <= sizeof(virProxyPacket)
        || ans.len > sizeof (ans) - sizeof(virProxyPacket)) {
        virProxyError(VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        return (NULL);
    }
    xmllen = ans.len - sizeof(virProxyPacket);
    if (VIR_ALLOC_N(xml, xmllen+1) < 0) {
        virReportOOMError();
        return NULL;
    }
    memcpy(xml, &ans.extra.dinfo, xmllen);
    xml[xmllen] = '\0';

    return(xml);
}

/**
 * xenProxyDomainGetOSType:
 * @domain: a domain object
 *
 * Get the type of domain operation system.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
static char *
xenProxyDomainGetOSType(virDomainPtr domain)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;
    int oslen;
    char *ostype;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virProxyError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_DOMAIN_OSTYPE;
    req.data.arg = domain->id;
    req.len = sizeof(req);
    ret = xenProxyCommand(domain->conn, &req, &ans, 0);
    if (ret < 0) {
        return(NULL);
    }
    if ((ans.len == sizeof(virProxyPacket)) && (ans.data.arg < 0)) {
        virRaiseError (domain->conn, NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_OPERATION_FAILED, VIR_ERR_ERROR, NULL, NULL,
                       NULL, 0, 0, "%s", _("Cannot get domain details"));
        return(NULL);
    }

    if (ans.len <= sizeof(virProxyPacket)
        || ans.len > sizeof (ans) - sizeof(virProxyPacket)) {
        virProxyError(VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        return (NULL);
    }
    oslen = ans.len - sizeof(virProxyPacket);
    if (VIR_ALLOC_N(ostype, oslen+1) < 0) {
        virReportOOMError();
        return NULL;
    }
    memcpy(ostype, &ans.extra.dinfo, oslen);
    ostype[oslen] = '\0';

    return(ostype);
}
