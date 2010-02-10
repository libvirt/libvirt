/*
 * proxy_svr.c: root suid proxy server for Xen access to APIs with no
 *              side effects from unauthenticated clients.
 *
 * Copyright (C) 2006, 2007, 2008, 2009 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>
#include <stdio.h>

#ifdef WITH_XEN

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <locale.h>

#include "internal.h"
#include "datatypes.h"
#include "proxy_internal.h"
#include "util.h"
#include "xen_hypervisor.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "xen_driver.h"

static int fdServer = -1;
static int debug = 0;
static int persist = 0;
static int done = 0;

#define MAX_CLIENT 64

static int nbClients = 0; /* client 0 is the unix listen socket */
static struct pollfd pollInfos[MAX_CLIENT + 1];

static virConnect conninfos;
static virConnectPtr conn = &conninfos;

static unsigned long xenVersion = 0;

/************************************************************************
 *									*
 *	Interfaces with the Xen hypervisor				*
 *									*
 ************************************************************************/

/**
 * proxyInitXen:
 *
 * Initialize the communication layer with Xen
 *
 * Returns 0 or -1 in case of error
 */
static int
proxyInitXen(void) {
    int ret;
    unsigned long xenVersion2;
    xenUnifiedPrivatePtr priv;

    /* Allocate per-connection private data. */
    priv = malloc (sizeof *priv);
    if (!priv) {
        fprintf(stderr, "Failed to allocate private data\n");
        return(-1);
    }
    conn->privateData = priv;

    priv->handle = -1;
    priv->xendConfigVersion = -1;
    priv->xshandle = NULL;
    priv->proxy = -1;

    ret = xenHypervisorOpen(conn, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to open Xen hypervisor\n");
        return(-1);
    } else {
        ret = xenHypervisorGetVersion(conn, &xenVersion);
        if (ret != 0) {
            fprintf(stderr, "Failed to get Xen hypervisor version\n");
            return(-1);
        }
    }
    ret = xenDaemonOpen_unix(conn, "/var/lib/xend/xend-socket");
    if (ret < 0) {
        fprintf(stderr, "Failed to connect to Xen daemon\n");
        return(-1);
    }
    ret = xenStoreOpen(conn, NULL, VIR_CONNECT_RO);
    if (ret < 0) {
        fprintf(stderr, "Failed to open XenStore connection");
        return (-1);
    }
    ret = xenDaemonGetVersion(conn, &xenVersion2);
    if (ret != 0) {
        fprintf(stderr, "Failed to get Xen daemon version\n");
        return(-1);
    }
    if (debug)
        fprintf(stderr, "Connected to hypervisor %lu and daemon %lu\n",
                xenVersion, xenVersion2);
    if (xenVersion2 > xenVersion)
        xenVersion = xenVersion2;
    return(0);
}

/************************************************************************
 *									*
 *	Processing of the unix socket to listen for clients		*
 *									*
 ************************************************************************/

/**
 * proxyCloseUnixSocket:
 *
 * close the unix socket
 *
 * Returns 0 or -1 in case of error
 */
static int
proxyCloseUnixSocket(void) {
    int ret;

    if (fdServer < 0)
        return(0);

    ret = close(fdServer);
    if (debug > 0)
        fprintf(stderr, "closing unix socket %d: %d\n", fdServer, ret);
    fdServer = -1;
    pollInfos[0].fd = -1;
    return(ret);
}

/**
 * proxyListenUnixSocket:
 * @path: the filename for the socket
 *
 * create a new abstract socket based on that path and listen on it
 *
 * Returns the associated file descriptor or -1 in case of failure
 */
static int
proxyListenUnixSocket(const char *path) {
    int fd;
    struct sockaddr_un addr;

    if (fdServer >= 0)
        return(fdServer);

    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Failed to create unix socket");
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
        fprintf(stderr, "Path %s too long to fit into destination\n", path);
        close(fd);
        return -1;
    }

    /*
     * now bind the socket to that address and listen on it
     */
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to bind to socket %s\n", path);
        close(fd);
        return (-1);
    }
    if (listen(fd, 30 /* backlog */ ) < 0) {
        fprintf(stderr, "Failed to listen to socket %s\n", path);
        close(fd);
        return (-1);
    }

    if (debug > 0)
        fprintf(stderr, "opened and bound unix socket %d\n", fd);

    fdServer = fd;
    pollInfos[0].fd = fd;
    pollInfos[0].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    return (fd);
}

/**
 * proxyAcceptClientSocket:
 *
 * Process a request to the unix socket
 *
 * Returns the filedescriptor of the new client or -1 in case of error
 */
static int
proxyAcceptClientSocket(void) {
    int client;
    socklen_t client_addrlen;
    struct sockaddr client_addr;

retry:
    client_addrlen = sizeof(client_addr);
    client = accept(pollInfos[0].fd, &client_addr, &client_addrlen);
    if (client < 0) {
        if (errno == EINTR) {
            if (debug > 0)
                fprintf(stderr, "accept connection on socket %d interrupted\n",
                        pollInfos[0].fd);
            goto retry;
        }
        fprintf(stderr, "Failed to accept incoming connection on socket %d\n",
                pollInfos[0].fd);
        done = 1;
        return(-1);
    }

    if (nbClients >= MAX_CLIENT) {
        fprintf(stderr, "Too many client registered\n");
        close(client);
        return(-1);
    }
    nbClients++;
    pollInfos[nbClients].fd = client;
    pollInfos[nbClients].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    if (debug > 0)
        fprintf(stderr, "accept connection on socket %d for client %d\n",
                client, nbClients);
    return(client);
}

/************************************************************************
 *									*
 *		Processing of client sockets				*
 *									*
 ************************************************************************/

/**
 * proxyCloseClientSocket:
 * @nr: client number
 *
 * Close the socket from that client, and recompact the pollInfo array
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
proxyCloseClientSocket(int nr) {
    int ret;

    ret = close(pollInfos[nr].fd);
    if (ret != 0)
        fprintf(stderr, "Failed to close socket %d from client %d\n",
                pollInfos[nr].fd, nr);
    else if (debug > 0)
        fprintf(stderr, "Closed socket %d from client %d\n",
                pollInfos[nr].fd, nr);
    if (nr < nbClients) {
        memmove(&pollInfos[nr], &pollInfos[nr + 1],
                (nbClients - nr) * sizeof(pollInfos[0]));
    }
    nbClients--;
    return(ret);
}

/**
 * proxyCloseClientSockets:
 *
 * Close all the sockets from the clients
 */
static void
proxyCloseClientSockets(void) {
    int i, ret;

    for (i = 1;i <= nbClients;i++) {
        ret = close(pollInfos[i].fd);
        if (ret != 0)
            fprintf(stderr, "Failed to close socket %d from client %d\n",
                    pollInfos[i].fd, i);
        else if (debug > 0)
            fprintf(stderr, "Closed socket %d from client %d\n",
                    pollInfos[i].fd, i);
    }
    nbClients = 0;
}

/**
 * proxyWriteClientSocket:
 * @nr: the client number
 * @req: pointer to the packet
 *
 * Send back a packet to the client. If it seems write would be blocking
 * then try to disconnect from it.
 *
 * Return 0 in case of success and -1 in case of error.
 */
static int
proxyWriteClientSocket(int nr, virProxyPacketPtr req) {
    int ret;

    if ((nr <= 0) || (nr > nbClients) || (req == NULL) ||
        (req->len < sizeof(virProxyPacket)) ||
        (req->len > sizeof(virProxyFullPacket)) ||
        (pollInfos[nr].fd < 0)) {
        fprintf(stderr, "write to client %d in error", nr);
        proxyCloseClientSocket(nr);
        return(-1);
    }

    ret = safewrite(pollInfos[nr].fd, (char *) req, req->len);
    if (ret < 0) {
        fprintf(stderr, "write %d bytes to socket %d from client %d failed\n",
                req->len, pollInfos[nr].fd, nr);
        proxyCloseClientSocket(nr);
        return(-1);
    }
    if (ret == 0) {
        if (debug)
            fprintf(stderr, "end of stream from client %d on socket %d\n",
                    nr, pollInfos[nr].fd);
        proxyCloseClientSocket(nr);
        return(-1);
    }

    if (ret != req->len) {
        fprintf(stderr, "write %d of %d bytes to socket %d from client %d\n",
                ret, req->len, pollInfos[nr].fd, nr);
        proxyCloseClientSocket(nr);
        return(-1);
    }
    if (debug)
        fprintf(stderr, "wrote %d bytes to client %d on socket %d\n",
                ret, nr, pollInfos[nr].fd);

    return(0);
}
/**
 * proxyReadClientSocket:
 * @nr: the client number
 *
 * Process a read from a client socket
 */
static int
proxyReadClientSocket(int nr) {
    virDomainDefPtr def;
    union {
        virProxyFullPacket full_request;
        virProxyPacket request;
    } r;
    virProxyPacketPtr req = &r.request;
    int ret;
    char *xml, *ostype;

retry:
    ret = read(pollInfos[nr].fd, req, sizeof(virProxyPacket));
    if (ret < 0) {
        if (errno == EINTR) {
            if (debug > 0)
                fprintf(stderr, "read socket %d from client %d interrupted\n",
                        pollInfos[nr].fd, nr);
            goto retry;
        }
        fprintf(stderr, "Failed to read socket %d from client %d\n",
                pollInfos[nr].fd, nr);
        proxyCloseClientSocket(nr);
        return(-1);
    }
    if (ret == 0) {
        if (debug)
            fprintf(stderr, "end of stream from client %d on socket %d\n",
                    nr, pollInfos[nr].fd);
        proxyCloseClientSocket(nr);
        return(-1);
    }

    if (debug)
        fprintf(stderr, "read %d bytes from client %d on socket %d\n",
                ret, nr, pollInfos[nr].fd);

    if ((ret != sizeof(virProxyPacket)) ||
        (req->version != PROXY_PROTO_VERSION) ||
        (req->len < sizeof(virProxyPacket)) ||
        (req->len > sizeof(virProxyFullPacket)))
        goto comm_error;


    if (debug)
        fprintf(stderr, "Got command %d from client %d\n", req->command, nr);

    /*
     * complete reading the packet.
     * TODO: we should detect when blocking and abort connection if this happen
     */
    if (req->len > ret) {
        int total, extra;
        char *base = (char *) &r;

        total = ret;
        while (total < req->len) {
            extra = req->len - total;
retry2:
            ret = read(pollInfos[nr].fd, base + total, extra);
            if (ret < 0) {
                if (errno == EINTR) {
                    if (debug > 0)
                        fprintf(stderr,
                                "read socket %d from client %d interrupted\n",
                                pollInfos[nr].fd, nr);
                    goto retry2;
                }
                fprintf(stderr, "Failed to read socket %d from client %d\n",
                        pollInfos[nr].fd, nr);
                proxyCloseClientSocket(nr);
                return(-1);
            }
            if (ret == 0) {
                if (debug)
                    fprintf(stderr,
                            "end of stream from client %d on socket %d\n",
                            nr, pollInfos[nr].fd);
                proxyCloseClientSocket(nr);
                return(-1);
            }
            total += ret;
        }
    }
    switch (req->command) {
        case VIR_PROXY_NONE:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;
            break;
        case VIR_PROXY_VERSION:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;
            req->data.larg = xenVersion;
            break;
        case VIR_PROXY_LIST: {
            int maxids;

            if (req->len != sizeof(virProxyPacket))
                goto comm_error;
            maxids = sizeof(r.full_request.extra.arg) / sizeof(int);
            ret = xenHypervisorListDomains(conn, &r.full_request.extra.arg[0],
                                           maxids);
            if (ret < 0) {
                req->len = sizeof(virProxyPacket);
                req->data.arg = 0;
            } else {
                req->len = sizeof(virProxyPacket) + ret * sizeof(int);
                req->data.arg = ret;
            }
            break;
        }
        case VIR_PROXY_NUM_DOMAIN:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;
            req->data.arg = xenHypervisorNumOfDomains(conn);
            break;
        case VIR_PROXY_MAX_MEMORY:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;
            req->data.larg = xenHypervisorGetDomMaxMemory(conn, req->data.arg);
            break;
        case VIR_PROXY_DOMAIN_INFO:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;
            memset(&r.full_request.extra.dinfo, 0, sizeof(virDomainInfo));
            ret = xenHypervisorGetDomInfo(conn, req->data.arg,
                                          &r.full_request.extra.dinfo);
            if (ret < 0) {
                req->data.arg = -1;
            } else {
                req->len += sizeof(virDomainInfo);
            }
            break;
        case VIR_PROXY_LOOKUP_ID: {
            char *name = NULL;
            unsigned char uuid[VIR_UUID_BUFLEN];
            int len;

            if (req->len != sizeof(virProxyPacket))
                goto comm_error;

            if (xenDaemonDomainLookupByID(conn, req->data.arg, &name, uuid) < 0) {
                req->data.arg = -1;
            } else {
                len = strlen(name);
                if (len > 1000) {
                    len = 1000;
                    name[1000] = 0;
                }
                req->len += VIR_UUID_BUFLEN + len + 1;
                memcpy(&r.full_request.extra.str[0], uuid, VIR_UUID_BUFLEN);
                strcpy(&r.full_request.extra.str[VIR_UUID_BUFLEN], name);
            }
        free(name);
            break;
        }
        case VIR_PROXY_LOOKUP_UUID: {
            char **names;
            char **tmp;
            int ident, len;
            char *name = NULL;
            unsigned char uuid[VIR_UUID_BUFLEN];

            if (req->len != sizeof(virProxyPacket) + VIR_UUID_BUFLEN)
                goto comm_error;

            /*
             * Xend API forces to collect the full domain list by names, and
             * then query each of them until the id is found
             */
            names = xenDaemonListDomainsOld(conn);
            tmp = names;

            if (names != NULL) {
               while (*tmp != NULL) {
                  ident = xenDaemonDomainLookupByName_ids(conn, *tmp, &uuid[0]);
                  if (!memcmp(uuid, &r.full_request.extra.str[0], VIR_UUID_BUFLEN)) {
                     name = *tmp;
                     break;
                  }
                  tmp++;
               }
            }
            if (name == NULL) {
                /* not found */
                req->data.arg = -1;
                req->len = sizeof(virProxyPacket);
            } else {
                len = strlen(name);
                if (len > 1000) {
                    len = 1000;
                    name[1000] = 0;
                }
                req->len = sizeof(virProxyPacket) + len + 1;
                strcpy(&r.full_request.extra.str[0], name);
                req->data.arg = ident;
            }
            free(names);
            break;
        }
        case VIR_PROXY_LOOKUP_NAME: {
            int ident;
            unsigned char uuid[VIR_UUID_BUFLEN];

            if (req->len > sizeof(virProxyPacket) + 1000)
                goto comm_error;

            ident = xenDaemonDomainLookupByName_ids(conn,
                                            &r.full_request.extra.str[0], &uuid[0]);
            if (ident < 0) {
                /* not found */
                req->data.arg = -1;
                req->len = sizeof(virProxyPacket);
            } else {
                req->len = sizeof(virProxyPacket) + VIR_UUID_BUFLEN;
                memcpy(&r.full_request.extra.str[0], uuid, VIR_UUID_BUFLEN);
                req->data.arg = ident;
            }
            break;
        }
        case VIR_PROXY_NODE_INFO:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;

            /*
             * Hum, could we expect those information to be unmutable and
             * cache them ? Since it's probably an unfrequent call better
             * not make assumption and do the xend RPC each call.
             */
            ret = xenDaemonNodeGetInfo(conn, &r.full_request.extra.ninfo);
            if (ret < 0) {
                req->data.arg = -1;
                req->len = sizeof(virProxyPacket);
            } else {
                req->data.arg = 0;
                req->len = sizeof(virProxyPacket) + sizeof(virNodeInfo);
            }
            break;

        case VIR_PROXY_GET_CAPABILITIES:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;

        xml = xenHypervisorGetCapabilities (conn);
        if (!xml) {
            req->data.arg = -1;
            req->len = sizeof (virProxyPacket);
        } else {
            int xmllen = strlen (xml);
            if (xmllen > (int) sizeof (r.full_request.extra.str)) {
                req->data.arg = -2;
                req->len = sizeof (virProxyPacket);
            } else {
                req->data.arg = 0;
                memmove (r.full_request.extra.str, xml, xmllen);
                req->len = sizeof (virProxyPacket) + xmllen;
            }
            free (xml);
        }
        break;

        case VIR_PROXY_DOMAIN_XML:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;

            /*
             * Ideally we should get the CPUs used by the domain
             * but that information is really node specific and it
             * rather hard to get from that code path. So proxy
             * users won't see CPU pinning (last NULL arg)
             */
            def = xenDaemonDomainFetch(conn, r.full_request.data.arg, NULL, NULL);
            if (!def) {
                req->data.arg = -1;
                req->len = sizeof(virProxyPacket);
            } else {
                xml = virDomainDefFormat(def, 0);
                if (!xml) {
                    req->data.arg = -1;
                    req->len = sizeof(virProxyPacket);
                } else {
                    int xmllen = strlen(xml);
                    if (xmllen > (int) sizeof(r.full_request.extra.str)) {
                        req->data.arg = -2;
                        req->len = sizeof(virProxyPacket);
                    } else {
                        req->data.arg = 0;
                        memmove(&r.full_request.extra.str[0], xml, xmllen);
                        req->len = sizeof(virProxyPacket) + xmllen;
                    }
                    free(xml);
                }
            }
            virDomainDefFree(def);
            break;
        case VIR_PROXY_DOMAIN_OSTYPE:
            if (req->len != sizeof(virProxyPacket))
                goto comm_error;

            ostype = xenStoreDomainGetOSTypeID(conn, r.full_request.data.arg);
            if (!ostype) {
                req->data.arg = -1;
                req->len = sizeof(virProxyPacket);
            } else {
                int ostypelen = strlen(ostype);
                if (ostypelen > (int) sizeof(r.full_request.extra.str)) {
                    req->data.arg = -2;
                    req->len = sizeof(virProxyPacket);
                } else {
                    req->data.arg = 0;
                    memmove(&r.full_request.extra.str[0], ostype, ostypelen);
                    req->len = sizeof(virProxyPacket) + ostypelen;
                }
                free(ostype);
            }
            break;
        default:
            goto comm_error;
    }
    ret = proxyWriteClientSocket(nr, req);
    return(ret);

comm_error:
    fprintf(stderr,
            "Communication error with client %d: malformed packet\n", nr);
    proxyCloseClientSocket(nr);
    return(-1);
}

/************************************************************************
 *									*
 *		Main loop processing					*
 *									*
 ************************************************************************/

/**
 * proxyProcessRequests:
 *
 * process requests and timers
 */
static void
proxyProcessRequests(void) {
    int exit_timeout = 30;
    int ret, i;

    while (!done) {
        /*
         * wait for requests, with a one second timeout
         */
        ret = poll(&pollInfos[0], nbClients + 1, 1000);
        if (ret == 0) { /* timeout */
            if ((nbClients == 0) && (persist == 0)) {
                exit_timeout--;
                if (exit_timeout == 0) {
                    done = 1;
                    if (debug > 0) {
                        fprintf(stderr, "Exiting after 30s without clients\n");
                    }
                }
            } else
                exit_timeout = 30;
            if (debug > 1)
                fprintf(stderr, "poll timeout\n");
            continue;
        } else if (ret < 0) {
            if (errno == EINTR) {
                if (debug > 0)
                    fprintf(stderr, "poll syscall interrupted\n");
                    continue;
            }
            fprintf(stderr, "poll syscall failed\n");
            break;
        }
        /*
         * there have been I/O to process
         */
        exit_timeout = 30;
        if (pollInfos[0].revents != 0) {
            if (pollInfos[0].revents & POLLIN) {
                proxyAcceptClientSocket();
            } else {
                fprintf(stderr, "Got an error %d on incoming socket %d\n",
                        pollInfos[0].revents, pollInfos[0].fd);
                break;
            }
        }

        /*
         * process the clients in reverse order since on error or disconnect
         * pollInfos is compacted to remove the given client.
         */
        for (i = nbClients;i > 0;i--) {
            if (pollInfos[i].revents & POLLIN) {
                proxyReadClientSocket(i);
            } else if (pollInfos[i].revents != 0) {
                fprintf(stderr, "Got an error %d on client %d socket %d\n",
                        pollInfos[i].revents, i, pollInfos[i].fd);
                proxyCloseClientSocket(i);
            }
        }

    }
}

/**
 * proxyMainLoop:
 *
 * main loop for the proxy, continually try to keep the unix socket
 * open, serve client requests, and process timing events.
 */

static void
proxyMainLoop(void) {
    while (! done) {
        if (proxyListenUnixSocket(PROXY_SOCKET_PATH) < 0)
            break;
        proxyProcessRequests();
    }
    proxyCloseClientSockets();
}

/**
 * usage:
 *
 * dump on stdout information about the program
 */
static void
usage(const char *progname) {
    printf("Usage: %s [-v] [-v]\n", progname);
    printf("    option -v increase the verbosity level for debugging\n");
    printf("This is a proxy for xen services used by libvirt to offer\n");
    printf("safe and fast status information on the Xen virtualization.\n");
    printf("This need not be run manually it's started automatically.\n");
}

/**
 * main:
 *
 * Check that we are running with root privileges, initialize the
 * connections to the daemon and or hypervisor, and then run the main loop
 */
int main(int argc, char **argv) {
    int i;

    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        return -1;
    }
    if (!bindtextdomain(GETTEXT_PACKAGE, LOCALEBASEDIR)) {
        perror("bindtextdomain");
        return -1;
    }
    if (!textdomain(GETTEXT_PACKAGE)) {
        perror("textdomain");
        return -1;
    }

    for (i = 1; i < argc; i++) {
         if (STREQ(argv[i], "-v")) {
             debug++;
         } else if (STREQ(argv[i], "-no-timeout")) {
             persist = 1;
         } else {
             usage(argv[0]);
             exit(EXIT_FAILURE);
         }
    }


    if (geteuid() != 0) {
        fprintf(stderr, "%s must be run as root or suid\n", argv[0]);
        /* exit(EXIT_FAILURE); */
    }

    /*
     * setup a connection block
     */
    memset(conn, 0, sizeof(conninfos));
    conn->magic = VIR_CONNECT_MAGIC;

    /*
     * very fist thing, use the socket as an exclusive lock, this then
     * allow to do timed exits, avoiding constant CPU usage in case of
     * failure.
     */
    if (proxyListenUnixSocket(PROXY_SOCKET_PATH) < 0)
        exit(EXIT_SUCCESS);
    if (proxyInitXen() == 0)
        proxyMainLoop();
    sleep(1);
    proxyCloseUnixSocket();
    exit(EXIT_SUCCESS);
}

#else /* WITHOUT_XEN */

int main(void) {
    fprintf(stderr, "libvirt was compiled without Xen support\n");
    exit(EXIT_FAILURE);
}

#endif /* WITH_XEN */
