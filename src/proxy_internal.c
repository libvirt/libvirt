/*
 * proxy_client.c: client side of the communication with the libvirt proxy.
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

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
#include "internal.h"
#include "driver.h"
#include "proxy_internal.h"

#define STANDALONE

static int debug = 0;

static int xenProxyClose(virConnectPtr conn);
static int xenProxyOpen(virConnectPtr conn, const char *name, int flags);
static int xenProxyGetVersion(virConnectPtr conn, unsigned long *hvVer);
static int xenProxyNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);
static int xenProxyListDomains(virConnectPtr conn, int *ids, int maxids);
static int xenProxyNumOfDomains(virConnectPtr conn);
static virDomainPtr xenProxyLookupByID(virConnectPtr conn, int id);
static virDomainPtr xenProxyLookupByUUID(virConnectPtr conn,
					 const unsigned char *uuid);
static virDomainPtr xenProxyDomainLookupByName(virConnectPtr conn,
					       const char *domname);
static unsigned long xenProxyDomainGetMaxMemory(virDomainPtr domain);
static int xenProxyDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info);
static char *xenProxyDomainDumpXML(virDomainPtr domain, int flags);

static virDriver xenProxyDriver = {
    VIR_DRV_XEN_PROXY,
    "XenProxy",
    0,
    NULL, /* init */
    xenProxyOpen, /* open */
    xenProxyClose, /* close */
    NULL, /* type */
    xenProxyGetVersion, /* version */
    xenProxyNodeGetInfo, /* nodeGetInfo */
    xenProxyListDomains, /* listDomains */
    xenProxyNumOfDomains, /* numOfDomains */
    NULL, /* domainCreateLinux */
    xenProxyLookupByID, /* domainLookupByID */
    xenProxyLookupByUUID, /* domainLookupByUUID */
    xenProxyDomainLookupByName, /* domainLookupByName */
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
    xenProxyDomainGetMaxMemory, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    xenProxyDomainGetInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    xenProxyDomainDumpXML, /* domainDumpXML */
    NULL, /* listDefinedDomains */
    NULL, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
};

/**
 * xenProxyRegister:
 *
 * Registers the xenHypervisor driver
 */
void xenProxyRegister(void)
{
    virRegisterDriver(&xenProxyDriver);
}
/************************************************************************
 *									*
 *			Error handling					*
 *									*
 ************************************************************************/

/**
 * virProxyError:
 * @conn: the connection if available
 * @error: the error noumber
 * @info: extra information string
 *
 * Handle an error at the xend daemon interface
 */
static void
virProxyError(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, VIR_FROM_PROXY, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}

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
    int ret, pid, status;

    if (!proxyPath) {
        fprintf(stderr, "failed to find libvirt_proxy\n");
	return(-1);
    }

    if (debug)
        fprintf(stderr, "Asking to launch %s\n", proxyPath);

    /* Become a daemon */
    pid = fork();
    if (pid == 0) {
        long open_max;
	long i;

        /* don't hold open fd opened from the client of the library */
	open_max = sysconf (_SC_OPEN_MAX);
	for (i = 0; i < open_max; i++)
	    fcntl (i, F_SETFD, FD_CLOEXEC);

        setsid();
        if (fork() == 0) {
            execl(proxyPath, proxyPath, NULL);
            fprintf(stderr, _("failed to exec %s\n"), proxyPath);
        }
        /*
         * calling exit() generate troubles for termination handlers
         */
        _exit(0);
    }

    /*
     * do a waitpid on the intermediate process to avoid zombies.
     */
retry_wait:
    ret = waitpid(pid, &status, 0);
    if (ret < 0) {
        if (errno == EINTR)
            goto retry_wait;
    }

    return (0);
}

/************************************************************************
 *									*
 *		Processing of client sockets				*
 *									*
 ************************************************************************/

/**
 * virProxyOpenClientSocket:
 * @path: the fileame for the socket
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
     * garanteed to be atomic
     */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(&addr.sun_path[1], path, (sizeof(addr) - 4) - 2);

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

    if (debug > 0)
        fprintf(stderr, "connected to unix socket %s via %d\n", path, fd);

    return (fd);
}

/**
 * virProxyCloseClientSocket:
 * @fd: the file descriptor for the socket
 *
 * Close the socket from that client
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
virProxyCloseClientSocket(int fd) {
    int ret;

    if (fd < 0)
        return(-1);

    ret = close(fd);
    if (ret != 0)
        fprintf(stderr, _("Failed to close socket %d\n"), fd);
    else if (debug > 0)
	fprintf(stderr, "Closed socket %d\n", fd);
    return(ret);
}

/**
 * virProxyReadClientSocket:
 * @fd: the socket 
 * @buffer: the target memory area
 * @len: the lenght in bytes
 * @quiet: quiet access
 *
 * Process a read from a client socket
 *
 * Returns the number of byte read or -1 in case of error.
 */
static int
virProxyReadClientSocket(int fd, char *buffer, int len, int quiet) {
    int ret;

    if ((fd < 0) || (buffer == NULL) || (len < 0))
        return(-1);

retry:
    ret = read(fd, buffer, len);
    if (ret < 0) {
        if (errno == EINTR) {
	    if (debug > 0)
	        fprintf(stderr, "read socket %d interrupted\n", fd);
	    goto retry;
	}
	if (!quiet)
            fprintf(stderr, _("Failed to read socket %d\n"), fd);
	return(-1);
    }

    if (debug)
	fprintf(stderr, "read %d bytes from socket %d\n",
		ret, fd);
    return(ret);
}

/**
 * virProxyWriteClientSocket:
 * @fd: the socket 
 * @data: the data
 * @len: the lenght of data in bytes
 *
 * Process a read from a client socket
 */
static int
virProxyWriteClientSocket(int fd, const char *data, int len) {
    int ret;

    if ((fd < 0) || (data == NULL) || (len < 0))
        return(-1);

retry:
    ret = write(fd, data, len);
    if (ret < 0) {
        if (errno == EINTR) {
	    if (debug > 0)
	        fprintf(stderr, "write socket %d, %d bytes interrupted\n",
		        fd, len);
	    goto retry;
	}
        fprintf(stderr, _("Failed to write to socket %d\n"), fd);
	return(-1);
    }
    if (debug)
	fprintf(stderr, "wrote %d bytes to socket %d\n",
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
xenProxyClose(virConnectPtr conn) {
    if ((conn == NULL) || (conn->proxy < 0))
        return(-1);
    virProxyCloseClientSocket(conn->proxy);
    conn->proxy = -1;
    return (0);
}

static int 
xenProxyCommand(virConnectPtr conn, virProxyPacketPtr request,
                virProxyFullPacketPtr answer, int quiet) {
    static int serial = 0;
    int ret;
    virProxyPacketPtr res = NULL;

    if ((conn == NULL) || (conn->proxy < 0))
        return(-1);

    /*
     * normal communication serial numbers are in 0..4095
     */
    ++serial;
    if (serial >= 4096)
        serial = 0;
    request->version = PROXY_PROTO_VERSION;
    request->serial = serial;
    ret  = virProxyWriteClientSocket(conn->proxy, (const char *) request,
                                     request->len);
    if (ret < 0)
        return(-1);
retry:
    if (answer == NULL) {
        /* read in situ */
	ret  = virProxyReadClientSocket(conn->proxy, (char *) request,
	                                sizeof(virProxyPacket), quiet);
	if (ret < 0)
	    return(-1);
	if (ret != sizeof(virProxyPacket)) {
	    fprintf(stderr,
		    _("Communication error with proxy: got %d bytes of %d\n"),
		    ret, (int) sizeof(virProxyPacket));
	    xenProxyClose(conn);
	    return(-1);
	}
	res = request;
	if (res->len != sizeof(virProxyPacket)) {
	    fprintf(stderr,
		    _("Communication error with proxy: expected %d bytes got %d\n"),
		    (int) sizeof(virProxyPacket), res->len);
	    xenProxyClose(conn);
	    return(-1);
	}
    } else {
        /* read in packet provided */
        ret  = virProxyReadClientSocket(conn->proxy, (char *) answer,
	                                sizeof(virProxyPacket), quiet);
	if (ret < 0)
	    return(-1);
	if (ret != sizeof(virProxyPacket)) {
	    fprintf(stderr,
		    _("Communication error with proxy: got %d bytes of %d\n"),
		    ret, (int) sizeof(virProxyPacket));
	    xenProxyClose(conn);
	    return(-1);
	}
	res = (virProxyPacketPtr) answer;
	if ((res->len < sizeof(virProxyPacket)) ||
	    (res->len > sizeof(virProxyFullPacket))) {
	    fprintf(stderr,
		    _("Communication error with proxy: got %d bytes packet\n"),
		    res->len);
	    xenProxyClose(conn);
	    return(-1);
	}
	if (res->len > sizeof(virProxyPacket)) {
	    ret  = virProxyReadClientSocket(conn->proxy,
	                           (char *) &(answer->extra.arg[0]),
	                                    res->len - ret, quiet);
	    if (ret != (int) (res->len - sizeof(virProxyPacket))) {
		fprintf(stderr,
			_("Communication error with proxy: got %d bytes of %d\n"),
			ret, (int) sizeof(virProxyPacket));
		xenProxyClose(conn);
		return(-1);
	    }
	}
    }
    /*
     * do more checks on the incoming packet.
     */
    if ((res == NULL) || (res->version != PROXY_PROTO_VERSION) ||
        (res->len < sizeof(virProxyPacket))) {
	fprintf(stderr,
		_("Communication error with proxy: malformed packet\n"));
	xenProxyClose(conn);
	return(-1);
    }
    if (res->serial != serial) {
        TODO /* Asynchronous communication */
	fprintf(stderr, _("got asynchronous packet number %d\n"), res->serial);
        goto retry;
    }
    return(0);
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
int
xenProxyOpen(virConnectPtr conn, const char *name, int flags)
{
    virProxyPacket req;
    int ret;
    int fd;
    
    if ((name != NULL) && (strcasecmp(name, "xen")))
        return(-1);
    if (!(flags & VIR_DRV_OPEN_RO))
        return(-1);
        
    conn->proxy = -1;
    fd = virProxyOpenClientSocket(PROXY_SOCKET_PATH);
    if (fd < 0) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
	    virProxyError(conn, VIR_ERR_NO_XEN, PROXY_SOCKET_PATH);
	return(-1);
    }
    conn->proxy = fd;

    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_NONE;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 1);
    if ((ret < 0) || (req.command != VIR_PROXY_NONE)) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
	    virProxyError(conn, VIR_ERR_OPERATION_FAILED, __FUNCTION__);
        xenProxyClose(conn);
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
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (hvVer == NULL) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_VERSION;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 0);
    if (ret < 0) {
        xenProxyClose(conn);
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
static int
xenProxyListDomains(virConnectPtr conn, int *ids, int maxids)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;
    int nb;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if ((ids == NULL) || (maxids <= 0)) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_LIST;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        xenProxyClose(conn);
	return(-1);
    }
    nb = ans.data.arg;
    if ((nb > 1020) || (nb <= 0) ||
        (ans.len <= sizeof(virProxyPacket)) ||
	(ans.len > sizeof(virProxyFullPacket))) {
        virProxyError(conn, VIR_ERR_OPERATION_FAILED, __FUNCTION__);
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
static int
xenProxyNumOfDomains(virConnectPtr conn)
{
    virProxyPacket req;
    int ret;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_NUM_DOMAIN;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 0);
    if (ret < 0) {
        xenProxyClose(conn);
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
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_MAX_MEMORY;
    req.data.arg = id;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, NULL, 0);
    if (ret < 0) {
        xenProxyClose(conn);
	return(-1);
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
	if (domain == NULL)
	    virProxyError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
	else
	    virProxyError(domain->conn, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }
    return(xenProxyDomainGetDomMaxMemory(domain->conn, domain->handle));
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
	if (domain == NULL)
	    virProxyError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
	else
	    virProxyError(domain->conn, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }
    if (info == NULL) {
        virProxyError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_DOMAIN_INFO;
    req.data.arg = domain->handle;
    req.len = sizeof(req);
    ret = xenProxyCommand(domain->conn, &req, &ans, 0);
    if (ret < 0) {
        xenProxyClose(domain->conn);
	return(-1);
    }
    if (ans.len != sizeof(virProxyPacket) + sizeof(virDomainInfo)) {
        virProxyError(domain->conn, VIR_ERR_OPERATION_FAILED, __FUNCTION__);
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
static virDomainPtr
xenProxyLookupByID(virConnectPtr conn, int id)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    unsigned char uuid[16];
    const char *name;
    int ret;
    virDomainPtr res;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (id < 0) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (NULL);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_LOOKUP_ID;
    req.data.arg = id;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        xenProxyClose(conn);
	return(NULL);
    }
    if (ans.data.arg == -1) {
	return(NULL);
    }
    memcpy(uuid, &ans.extra.str[0], 16);
    name = &ans.extra.str[16];
    res = virGetDomain(conn, name, uuid);

    if (res == NULL)
        virProxyError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
    else
	res->handle = id;
    
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
static virDomainPtr
xenProxyLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virProxyFullPacket req;
    const char *name;
    int ret;
    virDomainPtr res;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (NULL);
    }
    memset(&req, 0, sizeof(virProxyPacket));
    req.command = VIR_PROXY_LOOKUP_UUID;
    req.len = sizeof(virProxyPacket) + 16;
    ret = xenProxyCommand(conn, (virProxyPacketPtr) &req, &req, 0);
    if (ret < 0) {
        xenProxyClose(conn);
	return(NULL);
    }
    if (req.data.arg == -1) {
	return(NULL);
    }
    name = &req.extra.str[0];
    res = virGetDomain(conn, name, uuid);

    if (res == NULL)
        virProxyError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
    else
	res->handle = req.data.arg;
    
    return(res);
}

/**
 * xenProxyDomainLookupByName:
 * @conn: A xend instance
 * @name: The name of the domain
 *
 * This method looks up information about a domain based on its name
 *
 * Returns a new domain object or NULL in case of failure
 */
static virDomainPtr
xenProxyDomainLookupByName(virConnectPtr conn, const char *name)
{
    virProxyFullPacket req;
    int ret, len;
    virDomainPtr res;

    if (!VIR_IS_CONNECT(conn)) {
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (NULL);
    }
    len = strlen(name);
    if (len > 1000) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (NULL);
    }
    memset(&req, 0, sizeof(virProxyPacket));
    req.command = VIR_PROXY_LOOKUP_NAME;
    req.len = sizeof(virProxyPacket) + len + 1;
    strcpy(&req.extra.str[0], name);
    ret = xenProxyCommand(conn, (virProxyPacketPtr) &req, &req, 0);
    if (ret < 0) {
        xenProxyClose(conn);
	return(NULL);
    }
    if (req.data.arg == -1) {
	return(NULL);
    }
    res = virGetDomain(conn, name, (const unsigned char *)&req.extra.str[0]);

    if (res == NULL)
        virProxyError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
    else
	res->handle = req.data.arg;
    
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
        virProxyError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virProxyError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return (-1);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_NODE_INFO;
    req.data.arg = 0;
    req.len = sizeof(req);
    ret = xenProxyCommand(conn, &req, &ans, 0);
    if (ret < 0) {
        xenProxyClose(conn);
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
 * xenProxyDomainDumpXML:
 * @domain: a domain object
 * @flags: xml generation flags
 *
 * This method generates an XML description of a domain.
 *
 * Returns the XML document on success, NULL otherwise. 
 */
static char *
xenProxyDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED)
{
    virProxyPacket req;
    virProxyFullPacket ans;
    int ret;
    int xmllen;
    char *xml;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
	if (domain == NULL)
	    virProxyError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
	else
	    virProxyError(domain->conn, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    memset(&req, 0, sizeof(req));
    req.command = VIR_PROXY_DOMAIN_XML;
    req.data.arg = domain->handle;
    req.len = sizeof(req);
    ret = xenProxyCommand(domain->conn, &req, &ans, 0);
    if (ret < 0) {
        xenProxyClose(domain->conn);
	return(NULL);
    }
    if (ans.len <= sizeof(virProxyPacket)) {
        virProxyError(domain->conn, VIR_ERR_OPERATION_FAILED, __FUNCTION__);
	return (NULL);
    }
    xmllen = ans.len - sizeof(virProxyPacket);
    if (!(xml = malloc(xmllen+1))) {
      return NULL;
    }
    memmove(xml, &ans.extra.dinfo, xmllen);
    xml[xmllen] = '\0';

    return(xml);
}
