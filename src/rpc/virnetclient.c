/*
 * virnetclient.c: generic network RPC client
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 */

#include <config.h>

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "virnetclient.h"
#include "virnetsocket.h"
#include "virkeepalive.h"
#include "viralloc.h"
#include "virthread.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"
#include "virerror.h"
#include "virprobe.h"
#include "vireventglibwatch.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netclient");

typedef struct _virNetClientCall virNetClientCall;

enum {
    VIR_NET_CLIENT_MODE_WAIT_TX,
    VIR_NET_CLIENT_MODE_WAIT_RX,
    VIR_NET_CLIENT_MODE_COMPLETE,
};

VIR_ENUM_IMPL(virNetClientProxy,
              VIR_NET_CLIENT_PROXY_LAST,
              "auto", "netcat", "native");

struct _virNetClientCall {
    int mode;

    virNetMessage *msg;
    bool expectReply;
    bool nonBlock;
    bool haveThread;

    virCond cond;

    virNetClientCall *next;
};


struct _virNetClient {
    virObjectLockable parent;

    virNetSocket *sock;
    bool asyncIO;

    virNetTLSSession *tls;
    char *hostname;

    virNetClientProgram **programs;
    size_t nprograms;

    /* For incoming message packets */
    virNetMessage msg;

#if WITH_SASL
    virNetSASLSession *sasl;
#endif

    GMainLoop *eventLoop;
    GMainContext *eventCtx;

    /*
     * List of calls currently waiting for dispatch
     * The calls should all have threads waiting for
     * them, except possibly the first call in the list
     * which might be a partially sent non-blocking call.
     */
    virNetClientCall *waitDispatch;
    /* True if a thread holds the buck */
    bool haveTheBuck;

    size_t nstreams;
    virNetClientStream **streams;

    virKeepAlive *keepalive;
    bool wantClose;
    int closeReason;
    virErrorPtr error;

    virNetClientCloseFunc closeCb;
    void *closeOpaque;
    virFreeCallback closeFf;
};


static virClass *virNetClientClass;
static void virNetClientDispose(void *obj);

static int virNetClientOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetClient, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetClient);

static void virNetClientIOEventLoopPassTheBuck(virNetClient *client,
                                               virNetClientCall *thiscall);
static int virNetClientQueueNonBlocking(virNetClient *client,
                                        virNetMessage *msg);
static void virNetClientCloseInternal(virNetClient *client,
                                      int reason);


void virNetClientSetCloseCallback(virNetClient *client,
                                  virNetClientCloseFunc cb,
                                  void *opaque,
                                  virFreeCallback ff)
{
    virObjectLock(client);
    client->closeCb = cb;
    client->closeOpaque = opaque;
    client->closeFf = ff;
    virObjectUnlock(client);
}


static void virNetClientIncomingEvent(virNetSocket *sock,
                                      int events,
                                      void *opaque);

/* Append a call to the end of the list */
static void virNetClientCallQueue(virNetClientCall **head,
                                  virNetClientCall *call)
{
    virNetClientCall *tmp = *head;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = call;
    else
        *head = call;
    call->next = NULL;
}

#if 0
/* Obtain a call from the head of the list */
static virNetClientCall *virNetClientCallServe(virNetClientCall **head)
{
    virNetClientCall *tmp = *head;
    if (tmp)
        *head = tmp->next;
    else
        *head = NULL;
    tmp->next = NULL;
    return tmp;
}
#endif

/* Remove a call from anywhere in the list */
static void virNetClientCallRemove(virNetClientCall **head,
                                   virNetClientCall *call)
{
    virNetClientCall *tmp = *head;
    virNetClientCall *prev = NULL;
    while (tmp) {
        if (tmp == call) {
            if (prev)
                prev->next = g_steal_pointer(&tmp->next);
            else
                *head = g_steal_pointer(&tmp->next);
            return;
        }
        prev = tmp;
        tmp = tmp->next;
    }
}

/* Predicate returns true if matches */
typedef bool (*virNetClientCallPredicate)(virNetClientCall *call, void *opaque);

/* Remove a list of calls from the list based on a predicate */
static void virNetClientCallRemovePredicate(virNetClientCall **head,
                                            virNetClientCallPredicate pred,
                                            void *opaque)
{
    virNetClientCall *tmp = *head;
    virNetClientCall *prev = NULL;
    while (tmp) {
        virNetClientCall *next = tmp->next;
        tmp->next = NULL; /* Temp unlink */
        if (pred(tmp, opaque)) {
            if (prev)
                prev->next = next;
            else
                *head = next;
        } else {
            tmp->next = next; /* Reverse temp unlink */
            prev = tmp;
        }
        tmp = next;
    }
}

/* Returns true if the predicate matches at least one call in the list */
static bool virNetClientCallMatchPredicate(virNetClientCall *head,
                                           virNetClientCallPredicate pred,
                                           void *opaque)
{
    virNetClientCall *tmp = head;
    while (tmp) {
        if (pred(tmp, opaque))
            return true;
        tmp = tmp->next;
    }
    return false;
}


bool
virNetClientKeepAliveIsSupported(virNetClient *client)
{
    bool supported;

    virObjectLock(client);
    supported = !!client->keepalive;
    virObjectUnlock(client);

    return supported;
}

int
virNetClientKeepAliveStart(virNetClient *client,
                           int interval,
                           unsigned int count)
{
    int ret;

    virObjectLock(client);
    ret = virKeepAliveStart(client->keepalive, interval, count);
    virObjectUnlock(client);

    return ret;
}

void
virNetClientKeepAliveStop(virNetClient *client)
{
    virObjectLock(client);
    virKeepAliveStop(client->keepalive);
    virObjectUnlock(client);
}

static void
virNetClientKeepAliveDeadCB(void *opaque)
{
    virNetClientCloseInternal(opaque, VIR_CONNECT_CLOSE_REASON_KEEPALIVE);
}

static int
virNetClientKeepAliveSendCB(void *opaque,
                            virNetMessage *msg)
{
    int ret;

    ret = virNetClientSendNonBlock(opaque, msg);
    if (ret != -1 && ret != 1)
        virNetMessageFree(msg);
    return ret;
}

static virNetClient *virNetClientNew(virNetSocket *sock,
                                       const char *hostname)
{
    virNetClient *client = NULL;

    if (virNetClientInitialize() < 0)
        goto error;

    if (!(client = virObjectLockableNew(virNetClientClass)))
        goto error;

    client->sock = g_steal_pointer(&sock);

    client->eventCtx = g_main_context_new();
    client->eventLoop = g_main_loop_new(client->eventCtx, FALSE);

    client->hostname = g_strdup(hostname);

    PROBE(RPC_CLIENT_NEW,
          "client=%p sock=%p",
          client, client->sock);
    return client;

 error:
    virObjectUnref(client);
    virObjectUnref(sock);
    return NULL;
}

/*
 * Check whether the specified SSH key exists.
 *
 * Return -1 on error, 0 if it does not exist, and 1 if it does exist.
 */
static int
virNetClientCheckKeyExists(const char *homedir,
                           const char *name,
                           char **retPath)
{
    char *path;

    path = g_strdup_printf("%s/.ssh/%s", homedir, name);

    if (!(virFileExists(path))) {
        VIR_FREE(path);
        return 0;
    }

    *retPath = path;
    return 1;
}

/*
 * Detect the default SSH key, if existing.
 *
 * Return -1 on error, 0 if it does not exist, and 1 if it does exist.
 */
static int
virNetClientFindDefaultSshKey(const char *homedir, char **retPath)
{
    size_t i;

    const char *keys[] = { "identity", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa" };

    for (i = 0; i < G_N_ELEMENTS(keys); ++i) {
        int ret = virNetClientCheckKeyExists(homedir, keys[i], retPath);
        if (ret != 0)
            return ret;
    }

    return 0;
}


virNetClient *virNetClientNewUNIX(const char *path,
                                  const char *spawnDaemonPath)
{
    virNetSocket *sock;

    if (virNetSocketNewConnectUNIX(path, spawnDaemonPath, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}


virNetClient *virNetClientNewTCP(const char *nodename,
                                   const char *service,
                                   int family)
{
    virNetSocket *sock;

    if (virNetSocketNewConnectTCP(nodename, service,
                                  family,
                                  &sock) < 0)
        return NULL;

    return virNetClientNew(sock, nodename);
}


/*
 * The SSH Server uses shell to spawn the command we give
 * it.  Our command then invokes shell again. Thus we need
 * to apply two levels of escaping, so that commands with
 * whitespace in their path get correctly interpreted.
 */
static char *
virNetClientDoubleEscapeShell(const char *str)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *tmp = NULL;

    virBufferEscapeShell(&buf, str);

    tmp = virBufferContentAndReset(&buf);

    virBufferEscapeShell(&buf, tmp);

    return virBufferContentAndReset(&buf);
}

char *
virNetClientSSHHelperCommand(virNetClientProxy proxy,
                             const char *netcatPath,
                             const char *socketPath,
                             const char *driverURI,
                             bool readonly)
{
    g_autofree char *netcatPathSafe = virNetClientDoubleEscapeShell(netcatPath ? netcatPath : "nc");
    g_autofree char *driverURISafe = virNetClientDoubleEscapeShell(driverURI);
    g_autofree char *nccmd = NULL;
    g_autofree char *helpercmd = NULL;

    /* If user gave a 'netcat' path in the URI, we must
     * assume they want the legacy 'nc' based proxy, not
     * our new virt-ssh-helper
     */
    if (proxy == VIR_NET_CLIENT_PROXY_AUTO &&
        netcatPath != NULL) {
        proxy = VIR_NET_CLIENT_PROXY_NETCAT;
    }

    nccmd = g_strdup_printf(
        "if '%s' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
            "ARG=-q0;"
        "else "
            "ARG=;"
        "fi;"
        "'%s' $ARG -U %s",
        netcatPathSafe, netcatPathSafe, socketPath);

    helpercmd = g_strdup_printf("virt-ssh-helper%s'%s'",
                                readonly ? " -r " : " ",
                                driverURISafe);

    switch (proxy) {
    case VIR_NET_CLIENT_PROXY_AUTO:
        return g_strdup_printf("sh -c 'which virt-ssh-helper 1>/dev/null 2>&1; "
                               "if test $? = 0; then "
                               "    %s; "
                               "else"
                               "    %s; "
                               "fi'", helpercmd, nccmd);

    case VIR_NET_CLIENT_PROXY_NETCAT:
        return g_strdup_printf("sh -c '%s'", nccmd);

    case VIR_NET_CLIENT_PROXY_NATIVE:
        if (netcatPath) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("netcat path not valid with native proxy mode"));
            return NULL;
        }
        return g_strdup_printf("sh -c '%s'", helpercmd);

    case VIR_NET_CLIENT_PROXY_LAST:
    default:
        virReportEnumRangeError(virNetClientProxy, proxy);
        return NULL;
    }
}


#define DEFAULT_VALUE(VAR, VAL) \
    if (!VAR) \
        VAR = VAL;

virNetClient *virNetClientNewSSH(const char *nodename,
                                   const char *service,
                                   const char *binary,
                                   const char *username,
                                   bool noTTY,
                                   bool noVerify,
                                   const char *keyfile,
                                   virNetClientProxy proxy,
                                   const char *netcatPath,
                                   const char *socketPath,
                                   const char *driverURI,
                                   bool readonly)
{
    virNetSocket *sock;
    g_autofree char *command = NULL;

    if (!(command = virNetClientSSHHelperCommand(proxy, netcatPath, socketPath,
                                                 driverURI, readonly)))
        return NULL;

    if (virNetSocketNewConnectSSH(nodename, service, binary, username, noTTY,
                                  noVerify, keyfile, command, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}

virNetClient *virNetClientNewLibSSH2(const char *host,
                                       const char *port,
                                       int family,
                                       const char *username,
                                       const char *privkeyPath,
                                       const char *knownHostsPath,
                                       const char *knownHostsVerify,
                                       const char *authMethods,
                                       virNetClientProxy proxy,
                                       const char *netcatPath,
                                       const char *socketPath,
                                       const char *driverURI,
                                       bool readonly,
                                       virConnectAuthPtr authPtr,
                                       virURI *uri)
{
    virNetSocket *sock = NULL;
    g_autofree char *command = NULL;
    g_autofree char *homedir = NULL;
    g_autofree char *confdir = NULL;
    g_autofree char *knownhosts = NULL;
    g_autofree char *privkey = NULL;

    /* Use default paths for known hosts an public keys if not provided */
    if (knownHostsPath) {
        knownhosts = g_strdup(knownHostsPath);
    } else {
        confdir = virGetUserConfigDirectory();
        knownhosts = g_strdup_printf("%s/known_hosts", confdir);
    }

    if (privkeyPath) {
        privkey = g_strdup(privkeyPath);
    } else {
        homedir = virGetUserDirectory();
        if (virNetClientFindDefaultSshKey(homedir, &privkey) < 0)
            return NULL;
    }

    if (!authMethods) {
        if (privkey)
            authMethods = "agent,privkey,password,keyboard-interactive";
        else
            authMethods = "agent,password,keyboard-interactive";
    }

    DEFAULT_VALUE(host, "localhost");
    DEFAULT_VALUE(port, "22");
    DEFAULT_VALUE(username, "root");
    DEFAULT_VALUE(knownHostsVerify, "normal");

    if (!(command = virNetClientSSHHelperCommand(proxy, netcatPath, socketPath,
                                                 driverURI, readonly)))
        return NULL;

    if (virNetSocketNewConnectLibSSH2(host, port,
                                      family,
                                      username, privkey,
                                      knownhosts, knownHostsVerify, authMethods,
                                      command, authPtr, uri, &sock) != 0)
        return NULL;

   return virNetClientNew(sock, NULL);
}

virNetClient *virNetClientNewLibssh(const char *host,
                                      const char *port,
                                      int family,
                                      const char *username,
                                      const char *privkeyPath,
                                      const char *knownHostsPath,
                                      const char *knownHostsVerify,
                                      const char *authMethods,
                                      virNetClientProxy proxy,
                                      const char *netcatPath,
                                      const char *socketPath,
                                      const char *driverURI,
                                      bool readonly,
                                      virConnectAuthPtr authPtr,
                                      virURI *uri)
{
    virNetSocket *sock = NULL;
    g_autofree char *command = NULL;
    g_autofree char *homedir = NULL;
    g_autofree char *confdir = NULL;
    g_autofree char *knownhosts = NULL;
    g_autofree char *privkey = NULL;

    /* Use default paths for known hosts an public keys if not provided */
    if (knownHostsPath) {
        knownhosts = g_strdup(knownHostsPath);
    } else {
        confdir = virGetUserConfigDirectory();
        knownhosts = g_strdup_printf("%s/known_hosts", confdir);
    }

    if (privkeyPath) {
        privkey = g_strdup(privkeyPath);
    } else {
        homedir = virGetUserDirectory();
        if (virNetClientFindDefaultSshKey(homedir, &privkey) < 0)
            return NULL;
    }

    if (!authMethods) {
        if (privkey)
            authMethods = "agent,privkey,password,keyboard-interactive";
        else
            authMethods = "agent,password,keyboard-interactive";
    }

    DEFAULT_VALUE(host, "localhost");
    DEFAULT_VALUE(port, "22");
    DEFAULT_VALUE(username, "root");
    DEFAULT_VALUE(knownHostsVerify, "normal");

    if (!(command = virNetClientSSHHelperCommand(proxy, netcatPath, socketPath,
                                                 driverURI, readonly)))
        return NULL;

    if (virNetSocketNewConnectLibssh(host, port,
                                     family,
                                     username, privkey,
                                     knownhosts, knownHostsVerify, authMethods,
                                     command, authPtr, uri, &sock) != 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}
#undef DEFAULT_VALUE

virNetClient *virNetClientNewExternal(const char **cmdargv)
{
    virNetSocket *sock;

    if (virNetSocketNewConnectExternal(cmdargv, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}


int virNetClientRegisterAsyncIO(virNetClient *client)
{
    if (client->asyncIO)
        return 0;

    /* Set up a callback to listen on the socket data */
    virObjectRef(client);
    if (virNetSocketAddIOCallback(client->sock,
                                  VIR_EVENT_HANDLE_READABLE,
                                  virNetClientIncomingEvent,
                                  client,
                                  virObjectUnref) < 0) {
        virObjectUnref(client);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to register async IO callback"));
        return -1;
    }

    client->asyncIO = true;
    return 0;
}


int virNetClientRegisterKeepAlive(virNetClient *client)
{
    virKeepAlive *ka;

    if (client->keepalive)
        return 0;

    if (!client->asyncIO) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Unable to enable keepalives without async IO support"));
        return -1;
    }

    /* Keepalive protocol consists of async messages so it can only be used
     * if the client supports them */
    if (!(ka = virKeepAliveNew(-1, 0, client,
                               virNetClientKeepAliveSendCB,
                               virNetClientKeepAliveDeadCB,
                               virObjectUnref)))
        return -1;

    /* keepalive object has a reference to client */
    virObjectRef(client);

    client->keepalive = ka;
    return 0;
}


int virNetClientGetFD(virNetClient *client)
{
    int fd;
    virObjectLock(client);
    fd = virNetSocketGetFD(client->sock);
    virObjectUnlock(client);
    return fd;
}


int virNetClientDupFD(virNetClient *client, bool cloexec)
{
    int fd;
    virObjectLock(client);
    fd = virNetSocketDupFD(client->sock, cloexec);
    virObjectUnlock(client);
    return fd;
}


bool virNetClientHasPassFD(virNetClient *client)
{
    bool hasPassFD;
    virObjectLock(client);
    hasPassFD = virNetSocketHasPassFD(client->sock);
    virObjectUnlock(client);
    return hasPassFD;
}


void virNetClientDispose(void *obj)
{
    virNetClient *client = obj;
    size_t i;

    PROBE(RPC_CLIENT_DISPOSE,
          "client=%p", client);

    if (client->closeFf)
        client->closeFf(client->closeOpaque);

    for (i = 0; i < client->nprograms; i++)
        virObjectUnref(client->programs[i]);
    g_free(client->programs);

    g_main_loop_unref(client->eventLoop);
    g_main_context_unref(client->eventCtx);

    g_free(client->hostname);

    if (client->sock)
        virNetSocketRemoveIOCallback(client->sock);
    virObjectUnref(client->sock);
    virObjectUnref(client->tls);
#if WITH_SASL
    virObjectUnref(client->sasl);
#endif

    virNetMessageClear(&client->msg);
}


static void
virNetClientMarkClose(virNetClient *client,
                      int reason)
{
    VIR_DEBUG("client=%p, reason=%d", client, reason);

    if (client->sock)
        virNetSocketRemoveIOCallback(client->sock);

    /* Don't override reason that's already set. */
    if (!client->wantClose) {
        if (!client->error)
            client->error = virSaveLastError();
        client->wantClose = true;
        client->closeReason = reason;
    }
}


static void
virNetClientCloseLocked(virNetClient *client)
{
    virKeepAlive *ka;

    VIR_DEBUG("client=%p, sock=%p, reason=%d", client, client->sock, client->closeReason);

    if (!client->sock)
        return;

    g_clear_pointer(&client->sock, virObjectUnref);
    g_clear_pointer(&client->tls, virObjectUnref);
#if WITH_SASL
    g_clear_pointer(&client->sasl, virObjectUnref);
#endif
    ka = g_steal_pointer(&client->keepalive);
    client->wantClose = false;

    g_clear_pointer(&client->error, virFreeError);

    if (ka || client->closeCb) {
        virNetClientCloseFunc closeCb = client->closeCb;
        void *closeOpaque = client->closeOpaque;
        int closeReason = client->closeReason;
        virObjectRef(client);
        virObjectUnlock(client);

        if (ka) {
            virKeepAliveStop(ka);
            virObjectUnref(ka);
        }
        if (closeCb)
            closeCb(client, closeReason, closeOpaque);

        virObjectLock(client);
        virObjectUnref(client);
    }
}


static void virNetClientCloseInternal(virNetClient *client,
                                      int reason)
{
    VIR_DEBUG("client=%p wantclose=%d", client, client ? client->wantClose : false);

    if (!client)
        return;

    if (!client->sock ||
        client->wantClose)
        return;

    virObjectLock(client);

    virNetClientMarkClose(client, reason);

    /* If there is a thread polling for data on the socket, wake the thread up
     * otherwise try to pass the buck to a possibly waiting thread. If no
     * thread is waiting, virNetClientIOEventLoopPassTheBuck will clean the
     * queue and close the client because we set client->wantClose.
     */
    if (client->haveTheBuck) {
        g_main_loop_quit(client->eventLoop);
    } else {
        virNetClientIOEventLoopPassTheBuck(client, NULL);
    }

    virObjectUnlock(client);
}


void virNetClientClose(virNetClient *client)
{
    virNetClientCloseInternal(client, VIR_CONNECT_CLOSE_REASON_CLIENT);
}


#if WITH_SASL
void virNetClientSetSASLSession(virNetClient *client,
                                virNetSASLSession *sasl)
{
    virObjectLock(client);
    client->sasl = virObjectRef(sasl);
    virNetSocketSetSASLSession(client->sock, client->sasl);
    virObjectUnlock(client);
}
#endif


static gboolean
virNetClientIOEventTLS(int fd,
                       GIOCondition ev,
                       gpointer opaque);

static gboolean
virNetClientTLSHandshake(virNetClient *client)
{
    g_autoptr(GSource) G_GNUC_UNUSED source = NULL;
    GIOCondition ev;
    int ret;

    ret = virNetTLSSessionHandshake(client->tls);

    if (ret <= 0)
        return FALSE;

    if (virNetTLSSessionGetHandshakeStatus(client->tls) ==
        VIR_NET_TLS_HANDSHAKE_RECVING)
        ev = G_IO_IN;
    else
        ev = G_IO_OUT;

    source = virEventGLibAddSocketWatch(virNetSocketGetFD(client->sock),
                                        ev,
                                        client->eventCtx,
                                        virNetClientIOEventTLS, client, NULL);

    return TRUE;
}


static gboolean
virNetClientIOEventTLS(int fd G_GNUC_UNUSED,
                       GIOCondition ev G_GNUC_UNUSED,
                       gpointer opaque)
{
    virNetClient *client = opaque;

    if (!virNetClientTLSHandshake(client))
        g_main_loop_quit(client->eventLoop);

    return G_SOURCE_REMOVE;
}


static gboolean
virNetClientIOEventTLSConfirm(int fd G_GNUC_UNUSED,
                              GIOCondition ev G_GNUC_UNUSED,
                              gpointer opaque)
{
    virNetClient *client = opaque;

    g_main_loop_quit(client->eventLoop);

    return G_SOURCE_REMOVE;
}


int virNetClientSetTLSSession(virNetClient *client,
                              virNetTLSContext *tls)
{
    int ret;
    char buf[1];
    int len;
    g_autoptr(GSource) G_GNUC_UNUSED source = NULL;

#ifndef WIN32
    sigset_t oldmask, blockedsigs;

    sigemptyset(&blockedsigs);
# ifdef SIGWINCH
    sigaddset(&blockedsigs, SIGWINCH);
# endif
# ifdef SIGCHLD
    sigaddset(&blockedsigs, SIGCHLD);
# endif
    sigaddset(&blockedsigs, SIGPIPE);
#endif /* !WIN32 */

    virObjectLock(client);

    if (!(client->tls = virNetTLSSessionNew(tls,
                                            client->hostname)))
        goto error;

    virNetSocketSetTLSSession(client->sock, client->tls);

    virResetLastError();
    if (virNetClientTLSHandshake(client)) {
#ifndef WIN32
        /* Block SIGWINCH from interrupting poll in curses programs,
         * then restore the original signal mask again immediately
         * after the call (RHBZ#567931).  Same for SIGCHLD and SIGPIPE
         * at the suggestion of Paolo Bonzini and Daniel Berrange.
         */
        ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));
#endif /* !WIN32 */

        g_main_loop_run(client->eventLoop);

#ifndef WIN32
        ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));
#endif /* !WIN32 */
    }

    if (virGetLastErrorCode() != VIR_ERR_OK)
        goto error;

    ret = virNetTLSContextCheckCertificate(tls, client->tls);

    if (ret < 0)
        goto error;

    /* At this point, the server is verifying _our_ certificate, IP address,
     * etc.  If we make the grade, it will send us a '\1' byte.
     */

    source = virEventGLibAddSocketWatch(virNetSocketGetFD(client->sock),
                                        G_IO_IN,
                                        client->eventCtx,
                                        virNetClientIOEventTLSConfirm, client, NULL);

#ifndef WIN32
    /* Block SIGWINCH from interrupting poll in curses programs */
    ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));
#endif /* !WIN32 */

    g_main_loop_run(client->eventLoop);

#ifndef WIN32
    ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));
#endif /* !WIN32 */

    len = virNetTLSSessionRead(client->tls, buf, 1);
    if (len < 0 && errno != ENOMSG) {
        virReportSystemError(errno, "%s",
                             _("Unable to read TLS confirmation"));
        goto error;
    }
    if (len != 1 || buf[0] != '\1') {
        virReportError(VIR_ERR_RPC, "%s",
                       _("server verification (of our certificate or IP address) failed"));
        goto error;
    }

    virObjectUnlock(client);
    return 0;

 error:
    g_clear_pointer(&client->tls, virObjectUnref);
    virObjectUnlock(client);
    return -1;
}

bool virNetClientIsEncrypted(virNetClient *client)
{
    bool ret = false;
    virObjectLock(client);
    if (client->tls)
        ret = true;
#if WITH_SASL
    if (client->sasl)
        ret = true;
#endif
    virObjectUnlock(client);
    return ret;
}


bool virNetClientIsOpen(virNetClient *client)
{
    bool ret;

    if (!client)
        return false;

    virObjectLock(client);
    ret = client->sock && !client->wantClose;
    virObjectUnlock(client);
    return ret;
}


int virNetClientAddProgram(virNetClient *client,
                           virNetClientProgram *prog)
{
    virObjectLock(client);

    VIR_EXPAND_N(client->programs, client->nprograms, 1);
    client->programs[client->nprograms-1] = virObjectRef(prog);

    virObjectUnlock(client);
    return 0;
}


int virNetClientAddStream(virNetClient *client,
                          virNetClientStream *st)
{
    virObjectLock(client);

    VIR_EXPAND_N(client->streams, client->nstreams, 1);
    client->streams[client->nstreams-1] = virObjectRef(st);

    virObjectUnlock(client);
    return 0;
}


void virNetClientRemoveStream(virNetClient *client,
                              virNetClientStream *st)
{
    size_t i;

    virObjectLock(client);

    for (i = 0; i < client->nstreams; i++) {
        if (client->streams[i] == st)
            break;
    }
    if (i == client->nstreams)
        goto cleanup;

    VIR_DELETE_ELEMENT(client->streams, i, client->nstreams);
    virObjectUnref(st);

 cleanup:
    virObjectUnlock(client);
}


const char *virNetClientLocalAddrStringSASL(virNetClient *client)
{
    return virNetSocketLocalAddrStringSASL(client->sock);
}

const char *virNetClientRemoteAddrStringSASL(virNetClient *client)
{
    return virNetSocketRemoteAddrStringSASL(client->sock);
}

int virNetClientGetTLSKeySize(virNetClient *client)
{
    int ret = 0;
    virObjectLock(client);
    if (client->tls)
        ret = virNetTLSSessionGetKeySize(client->tls);
    virObjectUnlock(client);
    return ret;
}

static int
virNetClientCallDispatchReply(virNetClient *client)
{
    virNetClientCall *thecall;

    /* Ok, definitely got an RPC reply now find
       out which waiting call is associated with it */
    thecall = client->waitDispatch;
    while (thecall &&
           !(thecall->msg->header.prog == client->msg.header.prog &&
             thecall->msg->header.vers == client->msg.header.vers &&
             thecall->msg->header.serial == client->msg.header.serial))
        thecall = thecall->next;

    if (!thecall) {
        virReportError(VIR_ERR_RPC,
                       _("no call waiting for reply with prog %1$d vers %2$d serial %3$d"),
                       client->msg.header.prog, client->msg.header.vers, client->msg.header.serial);
        return -1;
    }

    VIR_REALLOC_N(thecall->msg->buffer, client->msg.bufferLength);

    memcpy(thecall->msg->buffer, client->msg.buffer, client->msg.bufferLength);
    memcpy(&thecall->msg->header, &client->msg.header, sizeof(client->msg.header));
    thecall->msg->bufferLength = client->msg.bufferLength;
    thecall->msg->bufferOffset = client->msg.bufferOffset;

    thecall->msg->nfds = client->msg.nfds;
    thecall->msg->fds = g_steal_pointer(&client->msg.fds);
    client->msg.nfds = 0;

    thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;

    return 0;
}

static int virNetClientCallDispatchMessage(virNetClient *client)
{
    size_t i;
    virNetClientProgram *prog = NULL;

    for (i = 0; i < client->nprograms; i++) {
        if (virNetClientProgramMatches(client->programs[i],
                                       &client->msg)) {
            prog = client->programs[i];
            break;
        }
    }
    if (!prog) {
        VIR_DEBUG("No program found for event with prog=%d vers=%d",
                  client->msg.header.prog, client->msg.header.vers);
        return -1;
    }

    virNetClientProgramDispatch(prog, client, &client->msg);

    return 0;
}

static void virNetClientCallCompleteAllWaitingReply(virNetClient *client)
{
    virNetClientCall *call;

    for (call = client->waitDispatch; call; call = call->next) {
        if (call->msg->header.prog == client->msg.header.prog &&
            call->msg->header.vers == client->msg.header.vers &&
            call->msg->header.serial == client->msg.header.serial &&
            call->expectReply)
            call->mode = VIR_NET_CLIENT_MODE_COMPLETE;
    }
}

static int virNetClientCallDispatchStream(virNetClient *client)
{
    size_t i;
    virNetClientStream *st = NULL;
    virNetClientCall *thecall;

    /* First identify what stream this packet is directed at */
    for (i = 0; i < client->nstreams; i++) {
        if (virNetClientStreamMatches(client->streams[i],
                                      &client->msg)) {
            st = client->streams[i];
            break;
        }
    }
    if (!st) {
        VIR_DEBUG("No stream found for packet with prog=%d vers=%d serial=%u proc=%u",
                  client->msg.header.prog, client->msg.header.vers,
                  client->msg.header.serial, client->msg.header.proc);
        /* Don't return -1, because we expect to see further stream packets
         * after we've shut it down sometimes */
        return 0;
    }


    /* Status is either
     *   - VIR_NET_OK - no payload for streams
     *   - VIR_NET_ERROR - followed by a remote_error struct
     *   - VIR_NET_CONTINUE - followed by a raw data packet
     */
    switch (client->msg.header.status) {
    case VIR_NET_CONTINUE: {
        if (virNetClientStreamQueuePacket(st, &client->msg) < 0)
            return -1;

        /* Find oldest dummy message waiting for incoming data. */
        for (thecall = client->waitDispatch; thecall; thecall = thecall->next) {
            if (thecall->msg->header.prog == client->msg.header.prog &&
                thecall->msg->header.vers == client->msg.header.vers &&
                thecall->msg->header.serial == client->msg.header.serial &&
                thecall->expectReply &&
                thecall->msg->header.status == VIR_NET_CONTINUE)
                break;
        }

        if (thecall) {
            VIR_DEBUG("Got a new incoming stream data");
            thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;
        }
        return 0;
    }

    case VIR_NET_OK:
        /* Find oldest abort/finish message. */
        for (thecall = client->waitDispatch; thecall; thecall = thecall->next) {
            if (thecall->msg->header.prog == client->msg.header.prog &&
                thecall->msg->header.vers == client->msg.header.vers &&
                thecall->msg->header.serial == client->msg.header.serial &&
                thecall->expectReply &&
                thecall->msg->header.status != VIR_NET_CONTINUE)
                break;
        }

        if (!thecall) {
            VIR_DEBUG("Got unexpected async stream finish confirmation");
            return -1;
        }

        VIR_DEBUG("Got a synchronous abort/finish confirm");

        virNetClientStreamSetClosed(st,
                                    thecall->msg->header.status == VIR_NET_OK ?
                                        VIR_NET_CLIENT_STREAM_CLOSED_FINISHED :
                                        VIR_NET_CLIENT_STREAM_CLOSED_ABORTED);

        virNetClientCallCompleteAllWaitingReply(client);
        return 0;

    case VIR_NET_ERROR:
        /* No call, so queue the error against the stream */
        if (virNetClientStreamSetError(st, &client->msg) < 0)
            return -1;

        virNetClientCallCompleteAllWaitingReply(client);
        return 0;

    default:
        VIR_WARN("Stream with unexpected serial=%d, proc=%d, status=%d",
                 client->msg.header.serial, client->msg.header.proc,
                 client->msg.header.status);
        return -1;
    }

    return 0;
}


static int
virNetClientCallDispatch(virNetClient *client)
{
    virNetMessage *response = NULL;

    PROBE(RPC_CLIENT_MSG_RX,
          "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
          client, client->msg.bufferLength,
          client->msg.header.prog, client->msg.header.vers, client->msg.header.proc,
          client->msg.header.type, client->msg.header.status, client->msg.header.serial);

    if (virKeepAliveCheckMessage(client->keepalive, &client->msg, &response)) {
        if (response &&
            virNetClientQueueNonBlocking(client, response) < 0) {
            VIR_WARN("Could not queue keepalive response");
            virNetMessageFree(response);
        }
        return 0;
    }

    switch (client->msg.header.type) {
    case VIR_NET_REPLY: /* Normal RPC replies */
    case VIR_NET_REPLY_WITH_FDS: /* Normal RPC replies with FDs */
        return virNetClientCallDispatchReply(client);

    case VIR_NET_MESSAGE: /* Async notifications */
        return virNetClientCallDispatchMessage(client);

    case VIR_NET_STREAM: /* Stream protocol */
    case VIR_NET_STREAM_HOLE: /* Sparse stream protocol */
        return virNetClientCallDispatchStream(client);

    case VIR_NET_CALL:
    case VIR_NET_CALL_WITH_FDS:
    default:
        virReportError(VIR_ERR_RPC,
                       _("got unexpected RPC call prog %1$d vers %2$d proc %3$d type %4$d"),
                       client->msg.header.prog, client->msg.header.vers,
                       client->msg.header.proc, client->msg.header.type);
        return -1;
    }
}


static ssize_t
virNetClientIOWriteMessage(virNetClient *client,
                           virNetClientCall *thecall)
{
    ssize_t ret = 0;

    if (thecall->msg->bufferOffset < thecall->msg->bufferLength) {
        ret = virNetSocketWrite(client->sock,
                                thecall->msg->buffer + thecall->msg->bufferOffset,
                                thecall->msg->bufferLength - thecall->msg->bufferOffset);
        if (ret <= 0)
            return ret;

        thecall->msg->bufferOffset += ret;
    }

    if (thecall->msg->bufferOffset == thecall->msg->bufferLength) {
        size_t i;
        for (i = thecall->msg->donefds; i < thecall->msg->nfds; i++) {
            int rv;
            if ((rv = virNetSocketSendFD(client->sock, thecall->msg->fds[i])) < 0)
                return -1;
            if (rv == 0) /* Blocking */
                return 0;
            thecall->msg->donefds++;
        }
        virNetMessageClearPayload(thecall->msg);
        if (thecall->expectReply)
            thecall->mode = VIR_NET_CLIENT_MODE_WAIT_RX;
        else
            thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;
    }

    return ret;
}


static ssize_t
virNetClientIOHandleOutput(virNetClient *client)
{
    virNetClientCall *thecall = client->waitDispatch;

    while (thecall &&
           thecall->mode != VIR_NET_CLIENT_MODE_WAIT_TX)
        thecall = thecall->next;

    if (!thecall)
        return 0; /* This can happen if another thread raced with us and
                   * completed the call between the time this thread woke
                   * up from poll()ing and the time we locked the client
                   */

    while (thecall) {
        ssize_t ret = virNetClientIOWriteMessage(client, thecall);
        if (ret < 0)
            return ret;

        if (thecall->mode == VIR_NET_CLIENT_MODE_WAIT_TX)
            return 0; /* Blocking write, to back to event loop */

        thecall = thecall->next;
    }

    return 0; /* No more calls to send, all done */
}

static ssize_t
virNetClientIOReadMessage(virNetClient *client)
{
    size_t wantData;
    ssize_t ret;

    /* Start by reading length word */
    if (client->msg.bufferLength == 0) {
        client->msg.bufferLength = 4;
        client->msg.buffer = g_new0(char, client->msg.bufferLength);
    }

    wantData = client->msg.bufferLength - client->msg.bufferOffset;

    ret = virNetSocketRead(client->sock,
                           client->msg.buffer + client->msg.bufferOffset,
                           wantData);
    if (ret <= 0)
        return ret;

    client->msg.bufferOffset += ret;

    return ret;
}


static ssize_t
virNetClientIOHandleInput(virNetClient *client)
{
    /* Read as much data as is available, until we get
     * EAGAIN
     */
    for (;;) {
        ssize_t ret;

        if (client->msg.nfds == 0) {
            ret = virNetClientIOReadMessage(client);

            if (ret < 0)
                return -1;
            if (ret == 0)
                return 0;  /* Blocking on read */
        }

        /* Check for completion of our goal */
        if (client->msg.bufferOffset == client->msg.bufferLength) {
            if (client->msg.bufferOffset == 4) {
                ret = virNetMessageDecodeLength(&client->msg);
                if (ret < 0)
                    return -1;

                /*
                 * We'll carry on around the loop to immediately
                 * process the message body, because it has probably
                 * already arrived. Worst case, we'll get EAGAIN on
                 * next iteration.
                 */
            } else {
                if (virNetMessageDecodeHeader(&client->msg) < 0)
                    return -1;

                if (client->msg.header.type == VIR_NET_REPLY_WITH_FDS) {
                    size_t i;

                    if (virNetMessageDecodeNumFDs(&client->msg) < 0)
                        return -1;

                    for (i = client->msg.donefds; i < client->msg.nfds; i++) {
                        int rv;
                        if ((rv = virNetSocketRecvFD(client->sock, &(client->msg.fds[i]))) < 0)
                            return -1;
                        if (rv == 0) /* Blocking */
                            break;
                        client->msg.donefds++;
                    }

                    if (client->msg.donefds < client->msg.nfds) {
                        /* Because DecodeHeader/NumFDs reset bufferOffset, we
                         * put it back to what it was, so everything works
                         * again next time we run this method
                         */
                        client->msg.bufferOffset = client->msg.bufferLength;
                        return 0; /* Blocking on more fds */
                    }
                }

                ret = virNetClientCallDispatch(client);
                virNetMessageClear(&client->msg);
                /*
                 * We've completed one call, but we don't want to
                 * spin around the loop forever if there are many
                 * incoming async events, or replies for other
                 * thread's RPC calls. We want to get out & let
                 * any other thread take over as soon as we've
                 * got our reply. When SASL is active though, we
                 * may have read more data off the wire than we
                 * initially wanted & cached it in memory. In this
                 * case, poll() would not detect that there is more
                 * ready todo.
                 *
                 * So if SASL is active *and* some SASL data is
                 * already cached, then we'll process that now,
                 * before returning.
                 */
                if (ret == 0 &&
                    virNetSocketHasCachedData(client->sock))
                    continue;
                return ret;
            }
        }
    }
}


static bool virNetClientIOEventLoopPollEvents(virNetClientCall *call,
                                              void *opaque)
{
    GIOCondition *ev = opaque;

    if (call->mode == VIR_NET_CLIENT_MODE_WAIT_RX)
        *ev |= G_IO_IN;
    if (call->mode == VIR_NET_CLIENT_MODE_WAIT_TX)
        *ev |= G_IO_OUT;

    return false;
}


static bool virNetClientIOEventLoopRemoveDone(virNetClientCall *call,
                                              void *opaque)
{
    virNetClientCall *thiscall = opaque;

    if (call == thiscall)
        return false;

    if (call->mode != VIR_NET_CLIENT_MODE_COMPLETE)
        return false;

    /*
     * ...if the call being removed from the list
     * still has a thread, then wake that thread up,
     * otherwise free the call. The latter should
     * only happen for calls without replies.
     *
     * ...the threads won't actually wakeup until
     * we release our mutex a short while
     * later...
     */
    if (call->haveThread) {
        VIR_DEBUG("Waking up sleep %p", call);
        virCondSignal(&call->cond);
    } else {
        VIR_DEBUG("Removing completed call %p", call);
        if (call->expectReply)
            VIR_WARN("Got a call expecting a reply but without a waiting thread");
        virCondDestroy(&call->cond);
        virNetMessageFree(call->msg);
        VIR_FREE(call);
    }

    return true;
}


static void
virNetClientIODetachNonBlocking(virNetClientCall *call)
{
    VIR_DEBUG("Keeping unfinished non-blocking call %p in the queue", call);
    call->haveThread = false;
}


static bool
virNetClientIOEventLoopRemoveAll(virNetClientCall *call,
                                 void *opaque)
{
    virNetClientCall *thiscall = opaque;

    if (call == thiscall)
        return false;

    VIR_DEBUG("Removing call %p", call);
    virCondDestroy(&call->cond);
    virNetMessageFree(call->msg);
    VIR_FREE(call);
    return true;
}


static void
virNetClientIOEventLoopPassTheBuck(virNetClient *client,
                                   virNetClientCall *thiscall)
{
    virNetClientCall *tmp = client->waitDispatch;

    VIR_DEBUG("Giving up the buck %p", thiscall);

    /* See if someone else is still waiting
     * and if so, then pass the buck ! */
    while (tmp) {
        if (tmp != thiscall && tmp->haveThread) {
            VIR_DEBUG("Passing the buck to %p", tmp);
            virCondSignal(&tmp->cond);
            return;
        }
        tmp = tmp->next;
    }
    client->haveTheBuck = false;

    VIR_DEBUG("No thread to pass the buck to");
    if (client->wantClose) {
        virNetClientCloseLocked(client);
        virNetClientCallRemovePredicate(&client->waitDispatch,
                                        virNetClientIOEventLoopRemoveAll,
                                        thiscall);
    }
}


struct virNetClientIOEventData {
    virNetClient *client;
    GIOCondition rev;
};

static gboolean
virNetClientIOEventFD(int fd G_GNUC_UNUSED,
                      GIOCondition ev,
                      gpointer opaque)
{
    struct virNetClientIOEventData *data = opaque;
    data->rev = ev;
    g_main_loop_quit(data->client->eventLoop);
    return G_SOURCE_REMOVE;
}


/*
 * Process all calls pending dispatch/receive until we
 * get a reply to our own call. Then quit and pass the buck
 * to someone else.
 *
 * Returns 1 if the call was queued and will be completed later (only
 * for nonBlock == true), 0 if the call was completed and -1 on error.
 */
static int virNetClientIOEventLoop(virNetClient *client,
                                   virNetClientCall *thiscall)
{
    bool error = false;
    int closeReason;

    for (;;) {
#ifndef WIN32
        sigset_t oldmask, blockedsigs;
#endif /* !WIN32 */
        int timeout = -1;
        virNetMessage *msg = NULL;
        g_autoptr(GSource) G_GNUC_UNUSED source = NULL;
        GIOCondition ev = 0;
        struct virNetClientIOEventData data = {
            .client = client,
            .rev = 0,
        };

        /* If we have existing SASL decoded data we don't want to sleep in
         * the poll(), just check if any other FDs are also ready.
         * If the connection is going to be closed, we don't want to sleep in
         * poll() either.
         */
        if (virNetSocketHasCachedData(client->sock) || client->wantClose)
            timeout = 0;

        /* If we are non-blocking, then we don't want to sleep in poll() */
        if (thiscall->nonBlock)
            timeout = 0;

        /* Limit timeout so that we can send keepalive request in time */
        if (timeout == -1)
            timeout = virKeepAliveTimeout(client->keepalive);

        /* Calculate poll events for calls */
        virNetClientCallMatchPredicate(client->waitDispatch,
                                       virNetClientIOEventLoopPollEvents,
                                       &ev);

        /* We have to be prepared to receive stream data
         * regardless of whether any of the calls waiting
         * for dispatch are for streams.
         */
        if (client->nstreams)
            ev |= G_IO_IN;

        source = virEventGLibAddSocketWatch(virNetSocketGetFD(client->sock),
                                            ev,
                                            client->eventCtx,
                                            virNetClientIOEventFD, &data, NULL);

        /* Release lock while poll'ing so other threads
         * can stuff themselves on the queue */
        virObjectUnlock(client);

#ifndef WIN32
        /* Block SIGWINCH from interrupting poll in curses programs,
         * then restore the original signal mask again immediately
         * after the call (RHBZ#567931).  Same for SIGCHLD and SIGPIPE
         * at the suggestion of Paolo Bonzini and Daniel Berrange.
         */
        sigemptyset(&blockedsigs);
# ifdef SIGWINCH
        sigaddset(&blockedsigs, SIGWINCH);
# endif
# ifdef SIGCHLD
        sigaddset(&blockedsigs, SIGCHLD);
# endif
        sigaddset(&blockedsigs, SIGPIPE);

        ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));
#endif /* !WIN32 */

        g_main_loop_run(client->eventLoop);

#ifndef WIN32
        ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));
#endif /* !WIN32 */

        virObjectLock(client);

        if (virKeepAliveTrigger(client->keepalive, &msg)) {
            virNetClientMarkClose(client, VIR_CONNECT_CLOSE_REASON_KEEPALIVE);
        } else if (msg && virNetClientQueueNonBlocking(client, msg) < 0) {
            VIR_WARN("Could not queue keepalive request");
            virNetMessageFree(msg);
        }

        /* If we have existing SASL decoded data, pretend
         * the socket became readable so we consume it
         */
        if (virNetSocketHasCachedData(client->sock))
            data.rev |= G_IO_IN;

        /* If wantClose flag is set, pretend there was an error on the socket,
         * but still read and process any data we received so far.
         */
        if (client->wantClose)
            error = true;

        if (data.rev & G_IO_HUP)
            closeReason = VIR_CONNECT_CLOSE_REASON_EOF;
        else
            closeReason = VIR_CONNECT_CLOSE_REASON_ERROR;

        if (data.rev & G_IO_OUT) {
            if (virNetClientIOHandleOutput(client) < 0) {
                virNetClientMarkClose(client, closeReason);
                error = true;
                /* Fall through to process any pending data. */
            }
        }

        if (data.rev & G_IO_IN) {
            if (virNetClientIOHandleInput(client) < 0) {
                virNetClientMarkClose(client, closeReason);
                error = true;
                /* Fall through to process any pending data. */
            }
        }

        /* Iterate through waiting calls and if any are
         * complete, remove them from the dispatch list.
         */
        virNetClientCallRemovePredicate(&client->waitDispatch,
                                        virNetClientIOEventLoopRemoveDone,
                                        thiscall);

        /* Now see if *we* are done */
        if (thiscall->mode == VIR_NET_CLIENT_MODE_COMPLETE) {
            virNetClientCallRemove(&client->waitDispatch, thiscall);
            virNetClientIOEventLoopPassTheBuck(client, thiscall);
            return 0;
        }

        /* We're not done, but we're non-blocking; keep the call queued */
        if (thiscall->nonBlock) {
            virNetClientIODetachNonBlocking(thiscall);
            virNetClientIOEventLoopPassTheBuck(client, thiscall);
            return 1;
        }

        if (error)
            goto error;

        if (data.rev & G_IO_HUP) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("received hangup event on socket"));
            virNetClientMarkClose(client, closeReason);
            goto error;
        }
        if (data.rev & G_IO_ERR) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("received error event on socket"));
            virNetClientMarkClose(client, closeReason);
            goto error;
        }
    }

 error:
    if (client->error) {
        VIR_DEBUG("error on socket: %s", client->error->message);
        virSetError(client->error);
    }
    virNetClientCallRemove(&client->waitDispatch, thiscall);
    virNetClientIOEventLoopPassTheBuck(client, thiscall);
    return -1;
}


static bool
virNetClientIOUpdateEvents(virNetClientCall *call,
                           void *opaque)
{
    int *events = opaque;

    if (call->mode == VIR_NET_CLIENT_MODE_WAIT_TX)
        *events |= VIR_EVENT_HANDLE_WRITABLE;

    return false;
}


static void virNetClientIOUpdateCallback(virNetClient *client,
                                         bool enableCallback)
{
    int events = 0;

    if (client->wantClose)
        return;

    if (enableCallback) {
        events |= VIR_EVENT_HANDLE_READABLE;
        virNetClientCallMatchPredicate(client->waitDispatch,
                                       virNetClientIOUpdateEvents,
                                       &events);
    }

    virNetSocketUpdateIOCallback(client->sock, events);
}


/*
 * This function sends a message to remote server and awaits a reply
 *
 * NB. This does not free the args structure (not desirable, since you
 * often want this allocated on the stack or else it contains strings
 * which come from the user).  It does however free any intermediate
 * results, eg. the error structure if there is one.
 *
 * NB(2). Make sure to initialize ret variable to { 0 } before calling,
 * else Bad things will happen in the XDR code.
 *
 * NB(3) You must have the client lock before calling this
 *
 * NB(4) This is very complicated. Multiple threads are allowed to
 * use the client for RPC at the same time. Obviously only one of
 * them can. So if someone's using the socket, other threads are put
 * to sleep on condition variables. The existing thread may completely
 * send & receive their RPC call/reply while they're asleep. Or it
 * may only get around to dealing with sending the call. Or it may
 * get around to neither. So upon waking up from slumber, the other
 * thread may or may not have more work todo.
 *
 * We call this dance  'passing the buck'
 *
 *      https://en.wikipedia.org/wiki/Passing_the_buck
 *
 *   "Buck passing or passing the buck is the action of transferring
 *    responsibility or blame unto another person. It is also used as
 *    a strategy in power politics when the actions of one country/
 *    nation are blamed on another, providing an opportunity for war."
 *
 * NB(5) If the 'thiscall' has the 'nonBlock' flag set, the caller
 * must *NOT* free it, if this returns '1' (ie partial send).
 *
 * NB(6) The following input states are valid if *no* threads
 *       are currently executing this method
 *
 *   - waitDispatch == NULL,
 *   - waitDispatch != NULL, waitDispatch.nonBlock == true
 *
 * The following input states are valid, if n threads are currently
 * executing
 *
 *   - waitDispatch != NULL
 *   - 0 or 1  waitDispatch.nonBlock == false, without any threads
 *   - 0 or more waitDispatch.nonBlock == false, with threads
 *
 * The following output states are valid when all threads are done
 *
 *   - waitDispatch == NULL,
 *   - waitDispatch != NULL, waitDispatch.nonBlock == true
 *
 * NB(7) Don't Panic!
 *
 * Returns 1 if the call was queued and will be completed later (only
 * for nonBlock == true), 0 if the call was completed and -1 on error.
 */
static int virNetClientIO(virNetClient *client,
                          virNetClientCall *thiscall)
{
    int rv = -1;

    VIR_DEBUG("Outgoing message prog=%u version=%u serial=%u proc=%d type=%d length=%zu dispatch=%p",
              thiscall->msg->header.prog,
              thiscall->msg->header.vers,
              thiscall->msg->header.serial,
              thiscall->msg->header.proc,
              thiscall->msg->header.type,
              thiscall->msg->bufferLength,
              client->waitDispatch);

    /* Stick ourselves on the end of the wait queue */
    virNetClientCallQueue(&client->waitDispatch, thiscall);

    /* Check to see if another thread is dispatching */
    if (client->haveTheBuck) {
        /* Force other thread to wakeup from poll */
        g_main_loop_quit(client->eventLoop);

        /* If we are non-blocking, detach the thread and keep the call in the
         * queue. */
        if (thiscall->nonBlock) {
            virNetClientIODetachNonBlocking(thiscall);
            rv = 1;
            goto cleanup;
        }

        VIR_DEBUG("Going to sleep head=%p call=%p",
                  client->waitDispatch, thiscall);
        /* Go to sleep while other thread is working... */
        if (virCondWait(&thiscall->cond, &client->parent.lock) < 0) {
            virNetClientCallRemove(&client->waitDispatch, thiscall);
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to wait on condition"));
            return -1;
        }

        VIR_DEBUG("Woken up from sleep head=%p call=%p",
                  client->waitDispatch, thiscall);
        /* Three reasons we can be woken up
         *  1. Other thread has got our reply ready for us
         *  2. Other thread is all done, and it is our turn to
         *     be the dispatcher to finish waiting for
         *     our reply
         */
        if (thiscall->mode == VIR_NET_CLIENT_MODE_COMPLETE) {
            rv = 0;
            /*
             * We avoided catching the buck and our reply is ready !
             * We've already had 'thiscall' removed from the list
             * so just need to (maybe) handle errors & free it
             */
            goto cleanup;
        }

        /* Grr, someone passed the buck to us ... */
    } else {
        client->haveTheBuck = true;
    }

    VIR_DEBUG("We have the buck head=%p call=%p",
              client->waitDispatch, thiscall);

    /*
     * The buck stops here!
     *
     * At this point we're about to own the dispatch
     * process...
     */

    /*
     * Avoid needless wake-ups of the event loop in the
     * case where this call is being made from a different
     * thread than the event loop. These wake-ups would
     * cause the event loop thread to be blocked on the
     * mutex for the duration of the call
     */
    virNetClientIOUpdateCallback(client, false);

    rv = virNetClientIOEventLoop(client, thiscall);

    if (client->sock)
        virNetClientIOUpdateCallback(client, true);

 cleanup:
    VIR_DEBUG("All done with our call head=%p call=%p rv=%d",
              client->waitDispatch, thiscall, rv);
    return rv;
}


void virNetClientIncomingEvent(virNetSocket *sock,
                               int events,
                               void *opaque)
{
    virNetClient *client = opaque;
    int closeReason;

    virObjectLock(client);

    VIR_DEBUG("client=%p wantclose=%d", client, client ? client->wantClose : false);

    if (!client->sock)
        goto done;

    if (client->haveTheBuck || client->wantClose)
        goto done;

    VIR_DEBUG("Event fired %p %d", sock, events);

    if (events & VIR_EVENT_HANDLE_HANGUP)
        closeReason = VIR_CONNECT_CLOSE_REASON_EOF;
    else
        closeReason = VIR_CONNECT_CLOSE_REASON_ERROR;

    if (events & VIR_EVENT_HANDLE_WRITABLE) {
        if (virNetClientIOHandleOutput(client) < 0)
            virNetClientMarkClose(client, closeReason);
    }

    if (events & VIR_EVENT_HANDLE_READABLE) {
        if (virNetClientIOHandleInput(client) < 0)
            virNetClientMarkClose(client, closeReason);
    }

    if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR)) {
        VIR_DEBUG("VIR_EVENT_HANDLE_HANGUP or "
                  "VIR_EVENT_HANDLE_ERROR encountered");
        virNetClientMarkClose(client, closeReason);
        goto done;
    }

    /* Remove completed calls or signal their threads. */
    virNetClientCallRemovePredicate(&client->waitDispatch,
                                    virNetClientIOEventLoopRemoveDone,
                                    NULL);
    virNetClientIOUpdateCallback(client, true);

 done:
    if (client->wantClose && !client->haveTheBuck) {
        virNetClientCloseLocked(client);
        virNetClientCallRemovePredicate(&client->waitDispatch,
                                        virNetClientIOEventLoopRemoveAll,
                                        NULL);
    }
    virObjectUnlock(client);
}


static virNetClientCall *
virNetClientCallNew(virNetMessage *msg,
                    bool expectReply,
                    bool nonBlock)
{
    virNetClientCall *call = NULL;

    if (expectReply &&
        (msg->bufferLength != 0) &&
        (msg->header.status == VIR_NET_CONTINUE)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Attempt to send an asynchronous message with a synchronous reply"));
        goto error;
    }

    if (expectReply && nonBlock) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Attempt to send a non-blocking message with a synchronous reply"));
        goto error;
    }

    call = g_new0(virNetClientCall, 1);

    if (virCondInit(&call->cond) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize condition variable"));
        goto error;
    }

    msg->donefds = 0;
    if (msg->bufferLength)
        call->mode = VIR_NET_CLIENT_MODE_WAIT_TX;
    else
        call->mode = VIR_NET_CLIENT_MODE_WAIT_RX;
    call->msg = msg;
    call->expectReply = expectReply;
    call->nonBlock = nonBlock;

    VIR_DEBUG("New call %p: msg=%p, expectReply=%d, nonBlock=%d",
              call, msg, expectReply, nonBlock);

    return call;

 error:
    VIR_FREE(call);
    return NULL;
}


static int
virNetClientQueueNonBlocking(virNetClient *client,
                             virNetMessage *msg)
{
    virNetClientCall *call;

    PROBE(RPC_CLIENT_MSG_TX_QUEUE,
          "client=%p len=%zu prog=%u vers=%u proc=%u"
          " type=%u status=%u serial=%u",
          client, msg->bufferLength,
          msg->header.prog, msg->header.vers, msg->header.proc,
          msg->header.type, msg->header.status, msg->header.serial);

    if (!(call = virNetClientCallNew(msg, false, true)))
        return -1;

    virNetClientCallQueue(&client->waitDispatch, call);
    return 0;
}


/*
 * Returns 1 if the call was queued and will be completed later (only
 * for nonBlock == true), 0 if the call was completed and -1 on error.
 */
static int virNetClientSendInternal(virNetClient *client,
                                    virNetMessage *msg,
                                    bool expectReply,
                                    bool nonBlock)
{
    virNetClientCall *call;
    int ret = -1;

    PROBE(RPC_CLIENT_MSG_TX_QUEUE,
          "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
          client, msg->bufferLength,
          msg->header.prog, msg->header.vers, msg->header.proc,
          msg->header.type, msg->header.status, msg->header.serial);

    if (!client->sock || client->wantClose) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("client socket is closed"));
        return -1;
    }

    if (!(call = virNetClientCallNew(msg, expectReply, nonBlock)))
        return -1;

    call->haveThread = true;
    ret = virNetClientIO(client, call);

    /* If queued, the call will be finished and freed later by another thread;
     * we're done. */
    if (ret == 1)
        return 1;

    virCondDestroy(&call->cond);
    VIR_FREE(call);
    return ret;
}


/*
 * @msg: a message allocated on heap or stack
 *
 * Send a message synchronously, and wait for the reply synchronously
 *
 * The caller is responsible for free'ing @msg if it was allocated
 * on the heap
 *
 * Returns 0 on success, -1 on failure
 */
int virNetClientSendWithReply(virNetClient *client,
                              virNetMessage *msg)
{
    int ret;
    virObjectLock(client);
    ret = virNetClientSendInternal(client, msg, true, false);
    virObjectUnlock(client);
    if (ret < 0)
        return -1;
    return 0;
}


/*
 * @msg: a message allocated on the heap.
 *
 * Send a message asynchronously, without any reply
 *
 * The caller is responsible for free'ing @msg, *except* if
 * this method returns 1.
 *
 * Returns 1 if the message was queued and will be completed later (only
 * for nonBlock == true), 0 if the message was completed and -1 on error.
 */
int virNetClientSendNonBlock(virNetClient *client,
                             virNetMessage *msg)
{
    int ret;
    virObjectLock(client);
    ret = virNetClientSendInternal(client, msg, false, true);
    virObjectUnlock(client);
    return ret;
}

/*
 * @msg: a message allocated on heap or stack
 *
 * Send a message synchronously, and wait for the reply synchronously if
 * message is dummy (just to wait for incoming data) or abort/finish message.
 *
 * The caller is responsible for free'ing @msg if it was allocated
 * on the heap
 *
 * Returns 0 on success, -1 on failure
 */
int virNetClientSendStream(virNetClient *client,
                           virNetMessage *msg,
                           virNetClientStream *st)
{
    int ret = -1;
    bool expectReply = !msg->bufferLength ||
                       msg->header.status != VIR_NET_CONTINUE;

    virObjectLock(client);

    if (virNetClientStreamCheckState(st) < 0)
        goto cleanup;

    /* Check for EOF only if we are going to wait for incoming data */
    if (!msg->bufferLength && virNetClientStreamEOF(st)) {
        ret = 0;
        goto cleanup;
    }

    if (virNetClientSendInternal(client, msg, expectReply, false) < 0)
        goto cleanup;

    if (expectReply && virNetClientStreamCheckSendStatus(st, msg) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnlock(client);

    return ret;
}
