/*
 * qemu_internal.c: A backend for managing QEMU machines
 *
 * Copyright (C) 2006-2007 Red Hat, Inc.
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
 */

#ifdef WITH_QEMU
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <limits.h>
#include <paths.h>

#include "internal.h"
#include "qemu_internal.h"
#include "xml.h"
#include "protocol.h"

/**
 * qemuPrivatePtr:
 *
 * Per-connection private data.
 */
struct _qemuPrivate {
    int qemud_fd;               /* Connection to libvirt qemu daemon. */
};
struct _qemuNetworkPrivate {
    int qemud_fd;
    int shared;
};
typedef struct _qemuPrivate *qemuPrivatePtr;
typedef struct _qemuNetworkPrivate *qemuNetworkPrivatePtr;

static void
qemuError(virConnectPtr con,
           virDomainPtr dom,
           virErrorNumber error,
           const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(con, dom, NULL, VIR_FROM_QEMU, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info, 0);
}

static void qemuPacketError(virConnectPtr con,
                             virDomainPtr dom,
                             struct qemud_packet *pkt) {
    if (!pkt) {
        qemuError(con, dom, VIR_ERR_INTERNAL_ERROR, "Malformed data packet");
        return;
    }
    if (pkt->header.type == QEMUD_PKT_FAILURE) {
        /* Paranoia in case remote side didn't terminate it */
        if (pkt->data.failureReply.message[0])
            pkt->data.failureReply.message[QEMUD_MAX_ERROR_LEN-1] = '\0';

        qemuError(con,
                   dom,
                   pkt->data.failureReply.code,
                   pkt->data.failureReply.message[0] ?
                   pkt->data.failureReply.message : NULL);
    } else {
        qemuError(con, dom, VIR_ERR_INTERNAL_ERROR, "Incorrect reply type");
    }
}


/**
 * qemuFindServerPath:
 *
 * Tries to find the path to the qemu binary.
 * 
 * Returns path on success or NULL in case of error.
 */
static const char *
qemuFindServerPath(void)
{
    static const char *serverPaths[] = {
        SBINDIR "/libvirt_qemud",
        SBINDIR "/libvirt_qemud_dbg",
        NULL
    };
    int i;
    const char *debugQemu = getenv("LIBVIRT_QEMU_SERVER");

    if (debugQemu)
        return(debugQemu);

    for (i = 0; serverPaths[i]; i++) {
        if (access(serverPaths[i], X_OK | R_OK) == 0) {
            return serverPaths[i];
        }
    }
    return NULL;
}


/**
 * qemuForkServer:
 *
 * Forks and try to launch the qemu server
 *
 * Returns 0 in case of success or -1 in case of detected error.
 */
static int
qemuForkServer(void)
{
    const char *proxyPath = qemuFindServerPath();
    int ret, pid, status;

    if (!proxyPath) {
        fprintf(stderr, "failed to find qemu\n");
        return(-1);
    }

    /* Become a daemon */
    pid = fork();
    if (pid == 0) {
        int stdinfd = -1;
        int stdoutfd = -1;
        int i, open_max;
        if ((stdinfd = open(_PATH_DEVNULL, O_RDONLY)) < 0)
            goto cleanup;
        if ((stdoutfd = open(_PATH_DEVNULL, O_WRONLY)) < 0)
            goto cleanup;
        if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
            goto cleanup;
        if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
            goto cleanup;
        if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
            goto cleanup;
        if (close(stdinfd) < 0)
            goto cleanup;
        stdinfd = -1;
        if (close(stdoutfd) < 0)
            goto cleanup;
        stdoutfd = -1;

        open_max = sysconf (_SC_OPEN_MAX);
        for (i = 0; i < open_max; i++)
            if (i != STDIN_FILENO &&
                i != STDOUT_FILENO &&
                i != STDERR_FILENO)
                close(i);

        setsid();
        if (fork() == 0) {
            /* Run daemon in auto-shutdown mode, so it goes away when
               no longer needed by an active guest, or client */
            execl(proxyPath, proxyPath, "--timeout", "30", NULL);
            fprintf(stderr, "failed to exec %s\n", proxyPath);
        }
        /*
         * calling exit() generate troubles for termination handlers
         */
        _exit(0);

    cleanup:
        if (stdoutfd != -1)
            close(stdoutfd);
        if (stdinfd != -1)
            close(stdinfd);
        _exit(-1);
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

/**
 * qemuOpenClientUNIX:
 * @path: the fileame for the socket
 *
 * try to connect to the socket open by qemu
 *
 * Returns the associated file descriptor or -1 in case of failure
 */
static int
qemuOpenClientUNIX(virConnectPtr conn ATTRIBUTE_UNUSED,
                   const char *path, int autostart) {
    int fd;
    struct sockaddr_un addr;
    int trials = 0;

 retry:
    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return VIR_DRV_OPEN_ERROR;
    }

    /*
     * Abstract socket do not hit the filesystem, way more secure and
     * garanteed to be atomic
     */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (addr.sun_path[0] == '@')
        addr.sun_path[0] = '\0';

    /*
     * now bind the socket to that address and listen on it
     */
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        if (autostart && trials < 3) {
            if (qemuForkServer() < 0)
                return(-1);
            trials++;
            usleep(5000 * trials * trials);
            goto retry;
        }
        return VIR_DRV_OPEN_ERROR;
    }

    return fd;
}


/* Takes a single request packet, does a blocking send on it.
 * then blocks until the complete reply has come back, or
 * connection closes.
 */
static int qemuProcessRequest(virConnectPtr conn,
                              int qemud_fd,
                              virDomainPtr dom,
                              struct qemud_packet *req,
                              struct qemud_packet *reply) {
    char *out = (char *)req;
    int outDone = 0;
    int outLeft = sizeof(struct qemud_packet_header) + req->header.dataSize;
    char *in = (char *)reply;
    int inGot = 0;
    int inLeft = sizeof(struct qemud_packet_header);

    /* printf("Send request %d\n", req->header.type); */

    /* Block sending entire outgoing packet */
    while (outLeft) {
        int got = write(qemud_fd, out+outDone, outLeft);
        if (got < 0) {
            return -1;
        }
        outDone += got;
        outLeft -= got;
    }

    /* Block waiting for header to come back */
    while (inLeft) {
        int done = read(qemud_fd, in+inGot, inLeft);
        if (done <= 0) {
            return -1;
        }
        inGot += done;
        inLeft -= done;
    }

    /* Validate header isn't bogus (bigger than
       maximum defined packet size) */
    if (reply->header.dataSize > sizeof(union qemud_packet_data)) {
        /*
        printf("Got type %ds body %d (max %ld)\n",
               reply->header.type,
               reply->header.dataSize,
               sizeof(union qemud_packet_data));
        printf("%ld == %ld + %ld\n",
               sizeof(struct qemud_packet),
               sizeof(struct qemud_packet_header),
               sizeof(union qemud_packet_data));
        */
        qemuPacketError(conn, dom, NULL);
        return -1;
    }

    /* Now block reading in body */
    inLeft = reply->header.dataSize;
    while (inLeft) {
        int done = read(qemud_fd, in+inGot, inLeft);
        if (done <= 0) {
            return -1;
        }
        inGot += done;
        inLeft -= done;
    }

    if (reply->header.type != req->header.type) {
        qemuPacketError(conn, dom, reply);
        return -1;
    }

    return 0;
}


/*
 * Open a connection to the libvirt QEMU daemon
 */
static int qemuOpenConnection(virConnectPtr conn, xmlURIPtr uri, int readonly) {
    char path[PATH_MAX];
    int autostart = 0;

    if (uri->server != NULL) {
        return VIR_DRV_OPEN_ERROR;
    }

    if (!strcmp(uri->path, "/system")) {
        if (readonly) {
            if (snprintf(path, sizeof(path), "%s/run/libvirt/qemud-sock-ro", LOCAL_STATE_DIR) >= (int)sizeof(path)) {
                return VIR_DRV_OPEN_ERROR;
            }
        } else {
            if (snprintf(path, sizeof(path), "%s/run/libvirt/qemud-sock", LOCAL_STATE_DIR) >= (int)sizeof(path)) {
                return VIR_DRV_OPEN_ERROR;
            }
        }
    } else if (!strcmp(uri->path, "/session")) {
        struct passwd *pw;
        int uid;

        if ((uid = geteuid()) < 0) {
            return VIR_DRV_OPEN_ERROR;
        }

        if (!(pw = getpwuid(uid)))
            return VIR_DRV_OPEN_ERROR;

        if (snprintf(path, sizeof(path), "@%s/.libvirt/qemud-sock", pw->pw_dir) == sizeof(path)) {
            return VIR_DRV_OPEN_ERROR;
        }
        autostart = 1;
    }
    return qemuOpenClientUNIX(conn, path, autostart);
}


/*
 * Open a connection to the QEMU manager
 */
static int qemuOpen(virConnectPtr conn,
                    const char *name,
                    int flags){
    xmlURIPtr uri;
    qemuPrivatePtr priv;
    int ret;

    if (!name) {
        return VIR_DRV_OPEN_DECLINED;
    }

    uri = xmlParseURI(name);
    if (uri == NULL) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
            qemuError(conn, NULL, VIR_ERR_NO_SUPPORT, name);
        return VIR_DRV_OPEN_DECLINED;
    }

    if (!uri->scheme ||
        strcmp(uri->scheme, "qemu") ||
        !uri->path) {
        xmlFreeURI(uri);
        return VIR_DRV_OPEN_DECLINED;
    }

    /* Create per-connection private data. */
    priv = conn->privateData = malloc (sizeof *priv);
    if (!priv) {
        qemuError (conn, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return VIR_DRV_OPEN_ERROR;
    }

    ret = qemuOpenConnection(conn, uri, flags & VIR_DRV_OPEN_RO ? 1 : 0);
    xmlFreeURI(uri);

    if (ret < 0) {
        free (priv);
        conn->privateData = NULL;
        return VIR_DRV_OPEN_ERROR;
    }

    priv->qemud_fd = ret;

    return VIR_DRV_OPEN_SUCCESS;
}


static int
qemuClose (virConnectPtr conn)
{
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (priv->qemud_fd != -1) {
        close (priv->qemud_fd);
        priv->qemud_fd = -1;
    }

    free (priv);
    conn->privateData = NULL;

    return 0;
}


static int qemuGetVersion(virConnectPtr conn,
                          unsigned long *hvVer) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_GET_VERSION;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    *hvVer = reply.data.getVersionReply.version;
    return 0;
}


static int qemuNodeGetInfo(virConnectPtr conn,
                           virNodeInfoPtr info) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_GET_NODEINFO;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    info->cores = reply.data.getNodeInfoReply.cores;
    info->threads = reply.data.getNodeInfoReply.threads;
    info->sockets = reply.data.getNodeInfoReply.sockets;
    info->nodes = reply.data.getNodeInfoReply.nodes;
    strncpy(info->model, reply.data.getNodeInfoReply.model, sizeof(info->model));
    info->mhz = reply.data.getNodeInfoReply.mhz;
    info->cpus = reply.data.getNodeInfoReply.cpus;
    info->memory = reply.data.getNodeInfoReply.memory;
    return 0;
}


static char *
qemuGetCapabilities (virConnectPtr conn)
{
    struct qemud_packet req, reply;
    char *xml;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    /* Punt the request across to the daemon, because the daemon
     * has tables describing available architectures.
     */
    req.header.type = QEMUD_PKT_GET_CAPABILITIES;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.getCapabilitiesReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    xml = strdup (reply.data.getCapabilitiesReply.xml);
    if (!xml) {
        qemuError (conn, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    return xml;
}

static int qemuNumOfDomains(virConnectPtr conn) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_NUM_DOMAINS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.numDomainsReply.numDomains;
}


static int qemuListDomains(virConnectPtr conn,
                           int *ids,
                           int maxids) {
    struct qemud_packet req, reply;
    int i, nDomains;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_LIST_DOMAINS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nDomains = reply.data.listDomainsReply.numDomains;
    if (nDomains > maxids)
        nDomains = maxids;

    for (i = 0 ; i < nDomains ; i++) {
        ids[i] = reply.data.listDomainsReply.domains[i];
    }

    return nDomains;
}


static virDomainPtr
qemuDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    struct qemud_packet req, reply;
    virDomainPtr dom;
    int len = strlen(xmlDesc);
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.header.type = QEMUD_PKT_DOMAIN_CREATE;
    req.header.dataSize = sizeof(req.data.domainCreateRequest);
    strcpy(req.data.domainCreateRequest.xml, xmlDesc);
    req.data.domainCreateRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.domainCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.domainCreateReply.name,
                             reply.data.domainCreateReply.uuid)))
        return NULL;

    dom->id = reply.data.domainCreateReply.id;
    return dom;
}


static virDomainPtr qemuLookupDomainByID(virConnectPtr conn,
                                         int id) {
    struct qemud_packet req, reply;
    virDomainPtr dom;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_LOOKUP_BY_ID;
    req.header.dataSize = sizeof(req.data.domainLookupByIDRequest);
    req.data.domainLookupByIDRequest.id = id;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.domainLookupByIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.domainLookupByIDReply.name,
                             reply.data.domainLookupByIDReply.uuid)))
        return NULL;

    dom->id = id;
    return dom;
}


static virDomainPtr qemuLookupDomainByUUID(virConnectPtr conn,
                                           const unsigned char *uuid) {
    struct qemud_packet req, reply;
    virDomainPtr dom;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_LOOKUP_BY_UUID;
    req.header.dataSize = sizeof(req.data.domainLookupByUUIDRequest);
    memmove(req.data.domainLookupByUUIDRequest.uuid, uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.domainLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.domainLookupByUUIDReply.name,
                             uuid)))
        return NULL;

    dom->id = reply.data.domainLookupByUUIDReply.id;
    return dom;
}


static virDomainPtr qemuLookupDomainByName(virConnectPtr conn,
                                           const char *name) {
    struct qemud_packet req, reply;
    virDomainPtr dom;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (strlen(name) > (QEMUD_MAX_NAME_LEN-1))
        return NULL;

    req.header.type = QEMUD_PKT_DOMAIN_LOOKUP_BY_NAME;
    req.header.dataSize = sizeof(req.data.domainLookupByNameRequest);
    strcpy(req.data.domainLookupByNameRequest.name, name);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    if (!(dom = virGetDomain(conn,
                             name,
                             reply.data.domainLookupByNameReply.uuid)))
        return NULL;

    dom->id = reply.data.domainLookupByNameReply.id;
    return dom;
}

static int qemuDestroyDomain(virDomainPtr domain) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_DESTROY;
    req.header.dataSize = sizeof(req.data.domainDestroyRequest);
    req.data.domainDestroyRequest.id = domain->id;

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static char *qemuDomainGetOSType(virDomainPtr domain ATTRIBUTE_UNUSED) {
    char *type = strdup("hvm");

    if (!type) {
        qemuError (domain->conn, domain, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return NULL;
    }

    return type;
}

static int qemuShutdownDomain(virDomainPtr domain) {
    return qemuDestroyDomain(domain);
}

static int qemuResumeDomain(virDomainPtr domain) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_RESUME;
    req.header.dataSize = sizeof(req.data.domainResumeRequest);
    req.data.domainResumeRequest.id = domain->id;

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuPauseDomain(virDomainPtr domain) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_SUSPEND;
    req.header.dataSize = sizeof(req.data.domainSuspendRequest);
    req.data.domainSuspendRequest.id = domain->id;

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuGetDomainInfo(virDomainPtr domain,
                             virDomainInfoPtr info) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_GET_INFO;
    req.header.dataSize = sizeof(req.data.domainGetInfoRequest);
    memmove(req.data.domainGetInfoRequest.uuid, domain->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    memset(info, 0, sizeof(virDomainInfo));
    switch (reply.data.domainGetInfoReply.runstate) {
    case QEMUD_STATE_RUNNING:
        info->state = VIR_DOMAIN_RUNNING;
        break;

    case QEMUD_STATE_PAUSED:
        info->state = VIR_DOMAIN_PAUSED;
        break;

    case QEMUD_STATE_STOPPED:
        info->state = VIR_DOMAIN_SHUTOFF;
        break;

    default:
        return -1;
    }
    info->maxMem = reply.data.domainGetInfoReply.maxmem;
    info->memory = reply.data.domainGetInfoReply.memory;
    info->nrVirtCpu = reply.data.domainGetInfoReply.nrVirtCpu;
    info->cpuTime = reply.data.domainGetInfoReply.cpuTime;

    return 0;
}

static char *qemuDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.header.type = QEMUD_PKT_DUMP_XML;
    req.header.dataSize = sizeof(req.data.domainDumpXMLRequest);
    memmove(req.data.domainDumpXMLRequest.uuid, domain->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.domainDumpXMLReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    return strdup(reply.data.domainDumpXMLReply.xml);
}

static int qemuSaveDomain(virDomainPtr domain ATTRIBUTE_UNUSED, const char *file ATTRIBUTE_UNUSED) {
    return -1;
}

static int qemuRestoreDomain(virConnectPtr conn ATTRIBUTE_UNUSED, const char *file ATTRIBUTE_UNUSED) {
    return -1;
}


static int qemuNumOfDefinedDomains(virConnectPtr conn) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_NUM_DEFINED_DOMAINS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.numDefinedDomainsReply.numDomains;
}

static int qemuListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames){
    struct qemud_packet req, reply;
    int i, nDomains;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.header.type = QEMUD_PKT_LIST_DEFINED_DOMAINS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nDomains = reply.data.listDefinedDomainsReply.numDomains;
    if (nDomains > maxnames)
        nDomains = maxnames;

    for (i = 0 ; i < nDomains ; i++) {
        reply.data.listDefinedDomainsReply.domains[i][QEMUD_MAX_NAME_LEN-1] = '\0';
        names[i] = strdup(reply.data.listDefinedDomainsReply.domains[i]);
    }

    return nDomains;
}

static int qemuDomainCreate(virDomainPtr dom) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_START;
    req.header.dataSize = sizeof(req.data.domainStartRequest);
    memcpy(req.data.domainStartRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    dom->id = reply.data.domainStartReply.id;

    return 0;
}

static virDomainPtr qemuDomainDefineXML(virConnectPtr conn, const char *xml) {
    struct qemud_packet req, reply;
    virDomainPtr dom;
    int len = strlen(xml);
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.header.type = QEMUD_PKT_DOMAIN_DEFINE;
    req.header.dataSize = sizeof(req.data.domainDefineRequest);
    strcpy(req.data.domainDefineRequest.xml, xml);
    req.data.domainDefineRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.domainDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.domainDefineReply.name,
                             reply.data.domainDefineReply.uuid)))
        return NULL;

    dom->id = -1;
    return dom;
}

static int qemuUndefine(virDomainPtr dom) {
    struct qemud_packet req, reply;
    int ret = 0;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_UNDEFINE;
    req.header.dataSize = sizeof(req.data.domainUndefineRequest);
    memcpy(req.data.domainUndefineRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    if (virFreeDomain(dom->conn, dom) < 0)
        ret = -1;

    return ret;
}

static int qemuDomainGetAutostart(virDomainPtr dom,
                                  int *autostart) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_GET_AUTOSTART;
    req.header.dataSize = sizeof(req.data.domainGetAutostartRequest);
    memmove(req.data.domainGetAutostartRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    *autostart = reply.data.domainGetAutostartReply.autostart;

    return 0;
}

static int qemuDomainSetAutostart(virDomainPtr dom,
                                  int autostart) {
    struct qemud_packet req, reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.header.type = QEMUD_PKT_DOMAIN_SET_AUTOSTART;
    req.header.dataSize = sizeof(req.data.domainSetAutostartRequest);
    req.data.domainSetAutostartRequest.autostart = (autostart != 0);
    memmove(req.data.domainSetAutostartRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuNetworkOpen(virConnectPtr conn,
                           const char *name ATTRIBUTE_UNUSED,
                           int flags) {
    qemuNetworkPrivatePtr netpriv = NULL;

    if (!(netpriv = malloc(sizeof(struct _qemuNetworkPrivate)))) {
        qemuError (conn, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!strcmp(conn->driver->name, "QEMU")) {
        /* QEMU driver is active - just re-use existing connection */
        qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;
        netpriv->qemud_fd = priv->qemud_fd;
        netpriv->shared = 1;
        conn->networkPrivateData = netpriv;
        return 0;
    } else {
        /* Non-QEMU driver is active - open a new connection */
        const char *drvname = geteuid() == 0 ? "qemu:///system" : "qemu://session";
        xmlURIPtr uri = xmlParseURI(drvname);
        int ret = qemuOpenConnection(conn, uri, flags & VIR_DRV_OPEN_RO ? 1 : 0);
        xmlFreeURI(uri);

        if (ret < 0) {
            free(netpriv);
            return ret;
        } else {
            netpriv->qemud_fd = ret;
            netpriv->shared = 0;
            conn->networkPrivateData = netpriv;
            return 0;
        }
    }
}

static int
qemuNetworkClose (virConnectPtr conn)
{
    qemuNetworkPrivatePtr netpriv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (!netpriv->shared)
        close(netpriv->qemud_fd);
    free(netpriv);
    conn->networkPrivateData = NULL;

    return 0;
}

static int qemuNumOfNetworks(virConnectPtr conn) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NUM_NETWORKS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.numNetworksReply.numNetworks;
}

static int qemuListNetworks(virConnectPtr conn,
                            char **const names,
                            int maxnames) {
    struct qemud_packet req, reply;
    int i, nNetworks;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.header.type = QEMUD_PKT_LIST_NETWORKS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nNetworks = reply.data.listNetworksReply.numNetworks;
    if (nNetworks > maxnames)
        return -1;

    for (i = 0 ; i < nNetworks ; i++) {
        reply.data.listNetworksReply.networks[i][QEMUD_MAX_NAME_LEN-1] = '\0';
        names[i] = strdup(reply.data.listNetworksReply.networks[i]);
    }

    return nNetworks;
}

static int qemuNumOfDefinedNetworks(virConnectPtr conn) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NUM_DEFINED_NETWORKS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.numDefinedNetworksReply.numNetworks;
}

static int qemuListDefinedNetworks(virConnectPtr conn,
                                   char **const names,
                                   int maxnames) {
    struct qemud_packet req, reply;
    int i, nNetworks;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.header.type = QEMUD_PKT_LIST_DEFINED_NETWORKS;
    req.header.dataSize = 0;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nNetworks = reply.data.listDefinedNetworksReply.numNetworks;
    if (nNetworks > maxnames)
        return -1;

    for (i = 0 ; i < nNetworks ; i++) {
        reply.data.listDefinedNetworksReply.networks[i][QEMUD_MAX_NAME_LEN-1] = '\0';
        names[i] = strdup(reply.data.listDefinedNetworksReply.networks[i]);
    }

    return nNetworks;
}

static virNetworkPtr qemuNetworkLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid) {
    struct qemud_packet req, reply;
    virNetworkPtr network;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_LOOKUP_BY_UUID;
    req.header.dataSize = sizeof(req.data.networkLookupByUUIDRequest);
    memmove(req.data.networkLookupByUUIDRequest.uuid, uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.networkLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(network = virGetNetwork(conn,
                                  reply.data.networkLookupByUUIDReply.name,
                                  uuid)))
        return NULL;

    return network;
}

static virNetworkPtr qemuNetworkLookupByName(virConnectPtr conn,
                                             const char *name) {
    struct qemud_packet req, reply;
    virNetworkPtr network;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (strlen(name) > (QEMUD_MAX_NAME_LEN-1))
        return NULL;

    req.header.type = QEMUD_PKT_NETWORK_LOOKUP_BY_NAME;
    req.header.dataSize = sizeof(req.data.networkLookupByNameRequest);
    strcpy(req.data.networkLookupByNameRequest.name, name);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    if (!(network = virGetNetwork(conn,
                                  name,
                                  reply.data.networkLookupByNameReply.uuid)))
        return NULL;

    return network;
}

static virNetworkPtr qemuNetworkCreateXML(virConnectPtr conn,
                                          const char *xmlDesc) {
    struct qemud_packet req, reply;
    virNetworkPtr network;
    int len = strlen(xmlDesc);
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.header.type = QEMUD_PKT_NETWORK_CREATE;
    req.header.dataSize = sizeof(req.data.networkCreateRequest);
    strcpy(req.data.networkCreateRequest.xml, xmlDesc);
    req.data.networkCreateRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.networkCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(network = virGetNetwork(conn,
                                  reply.data.networkCreateReply.name,
                                  reply.data.networkCreateReply.uuid)))
        return NULL;

    return network;
}


static virNetworkPtr qemuNetworkDefineXML(virConnectPtr conn,
                                          const char *xml) {
    struct qemud_packet req, reply;
    virNetworkPtr network;
    int len = strlen(xml);
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.header.type = QEMUD_PKT_NETWORK_DEFINE;
    req.header.dataSize = sizeof(req.data.networkDefineRequest);
    strcpy(req.data.networkDefineRequest.xml, xml);
    req.data.networkDefineRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.networkDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(network = virGetNetwork(conn,
                                  reply.data.networkDefineReply.name,
                                  reply.data.networkDefineReply.uuid)))
        return NULL;

    return network;
}

static int qemuNetworkUndefine(virNetworkPtr network) {
    struct qemud_packet req, reply;
    int ret = 0;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_UNDEFINE;
    req.header.dataSize = sizeof(req.data.networkUndefineRequest);
    memcpy(req.data.networkUndefineRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    if (virFreeNetwork(network->conn, network) < 0)
        ret = -1;

    return ret;
}

static int qemuNetworkCreate(virNetworkPtr network) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_START;
    req.header.dataSize = sizeof(req.data.networkStartRequest);
    memcpy(req.data.networkStartRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuNetworkDestroy(virNetworkPtr network) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_DESTROY;
    req.header.dataSize = sizeof(req.data.networkDestroyRequest);
    memcpy(req.data.networkDestroyRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static char * qemuNetworkDumpXML(virNetworkPtr network, int flags ATTRIBUTE_UNUSED) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_DUMP_XML;
    req.header.dataSize = sizeof(req.data.networkDumpXMLRequest);
    memmove(req.data.networkDumpXMLRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.networkDumpXMLReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    return strdup(reply.data.networkDumpXMLReply.xml);
}

static char * qemuNetworkGetBridgeName(virNetworkPtr network) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_GET_BRIDGE_NAME;
    req.header.dataSize = sizeof(req.data.networkGetBridgeNameRequest);
    memmove(req.data.networkGetBridgeNameRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.networkGetBridgeNameReply.ifname[QEMUD_MAX_IFNAME_LEN-1] = '\0';

    return strdup(reply.data.networkGetBridgeNameReply.ifname);
}

static int qemuNetworkGetAutostart(virNetworkPtr network,
                                   int *autostart) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_GET_AUTOSTART;
    req.header.dataSize = sizeof(req.data.networkGetAutostartRequest);
    memmove(req.data.networkGetAutostartRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    *autostart = reply.data.networkGetAutostartReply.autostart;

    return 0;
}

static int qemuNetworkSetAutostart(virNetworkPtr network,
                                   int autostart) {
    struct qemud_packet req, reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.header.type = QEMUD_PKT_NETWORK_SET_AUTOSTART;
    req.header.dataSize = sizeof(req.data.networkSetAutostartRequest);
    req.data.networkSetAutostartRequest.autostart = (autostart != 0);
    memmove(req.data.networkSetAutostartRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static virDriver qemuDriver = {
    VIR_DRV_QEMU,
    "QEMU",
    LIBVIR_VERSION_NUMBER,
    qemuOpen, /* open */
    qemuClose, /* close */
    NULL, /* type */
    qemuGetVersion, /* version */
    NULL, /* getMaxVcpus */
    qemuNodeGetInfo, /* nodeGetInfo */
    qemuGetCapabilities, /* getCapabilities */
    qemuListDomains, /* listDomains */
    qemuNumOfDomains, /* numOfDomains */
    qemuDomainCreateLinux, /* domainCreateLinux */
    qemuLookupDomainByID, /* domainLookupByID */
    qemuLookupDomainByUUID, /* domainLookupByUUID */
    qemuLookupDomainByName, /* domainLookupByName */
    qemuPauseDomain, /* domainSuspend */
    qemuResumeDomain, /* domainResume */
    qemuShutdownDomain, /* domainShutdown */
    NULL, /* domainReboot */
    qemuDestroyDomain, /* domainDestroy */
    qemuDomainGetOSType, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    qemuGetDomainInfo, /* domainGetInfo */
    qemuSaveDomain, /* domainSave */
    qemuRestoreDomain, /* domainRestore */
    NULL, /* domainCoreDump */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    qemuDomainDumpXML, /* domainDumpXML */
    qemuListDefinedDomains, /* listDomains */
    qemuNumOfDefinedDomains, /* numOfDomains */
    qemuDomainCreate, /* domainCreate */
    qemuDomainDefineXML, /* domainDefineXML */
    qemuUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    qemuDomainGetAutostart, /* domainGetAutostart */
    qemuDomainSetAutostart, /* domainSetAutostart */
};

static virNetworkDriver qemuNetworkDriver = {
    qemuNetworkOpen, /* open */
    qemuNetworkClose, /* close */
    qemuNumOfNetworks, /* numOfNetworks */
    qemuListNetworks, /* listNetworks */
    qemuNumOfDefinedNetworks, /* numOfDefinedNetworks */
    qemuListDefinedNetworks, /* listDefinedNetworks */
    qemuNetworkLookupByUUID, /* networkLookupByUUID */
    qemuNetworkLookupByName, /* networkLookupByName */
    qemuNetworkCreateXML , /* networkCreateXML */
    qemuNetworkDefineXML , /* networkDefineXML */
    qemuNetworkUndefine, /* networkUndefine */
    qemuNetworkCreate, /* networkCreate */
    qemuNetworkDestroy, /* networkDestroy */
    qemuNetworkDumpXML, /* networkDumpXML */
    qemuNetworkGetBridgeName, /* networkGetBridgeName */
    qemuNetworkGetAutostart, /* networkGetAutostart */
    qemuNetworkSetAutostart, /* networkSetAutostart */
};

/**
 * qemuRegister:
 *
 * Registers QEmu/KVM in libvirt driver system
 */
int
qemuRegister (void)
{
    if (virRegisterDriver(&qemuDriver) == -1)
        return -1;
    if (virRegisterNetworkDriver(&qemuNetworkDriver) == -1)
        return -1;

    return 0;
}
#endif /* WITH_QEMU */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
