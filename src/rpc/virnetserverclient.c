/*
 * virnetserverclient.c: generic network RPC server client
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "internal.h"
#if WITH_SASL
# include <sasl/sasl.h>
#endif

#include "virnetserver.h"
#include "virnetserverclient.h"

#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virthread.h"
#include "virkeepalive.h"
#include "virprobe.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netserverclient");

/* Allow for filtering of incoming messages to a custom
 * dispatch processing queue, instead of the workers.
 * This allows for certain types of messages to be handled
 * strictly "in order"
 */

typedef struct _virNetServerClientFilter virNetServerClientFilter;
struct _virNetServerClientFilter {
    int id;
    virNetServerClientFilterFunc func;
    void *opaque;

    virNetServerClientFilter *next;
};


struct _virNetServerClient
{
    virObjectLockable parent;

    unsigned long long id;
    bool wantClose;
    bool delayedClose;
    virNetSocket *sock;
    int auth;
    bool auth_pending;
    bool readonly;
    virNetTLSContext *tlsCtxt;
    virNetTLSSession *tls;
#if WITH_SASL
    virNetSASLSession *sasl;
#endif
    int sockTimer; /* Timer to be fired upon cached data,
                    * so we jump out from poll() immediately */


    virIdentity *identity;

    /* Connection timestamp, i.e. when a client connected to the daemon (UTC).
     * For old clients restored by post-exec-restart, which did not have this
     * attribute, value of 0 (epoch time) is used to indicate we have no
     * information about their connection time.
     */
    long long conn_time;

    /* Count of messages in the 'tx' queue,
     * and the server worker pool queue
     * ie RPC calls in progress. Does not count
     * async events which are not used for
     * throttling calculations */
    size_t nrequests;
    size_t nrequests_max;
    /* True if we've warned about nrequests hittin
     * the server limit already */
    bool nrequests_warning;
    /* Zero or one messages being received. Zero if
     * nrequests >= max_clients and throttling */
    virNetMessage *rx;
    /* Zero or many messages waiting for transmit
     * back to client, including async events */
    virNetMessage *tx;

    /* Filters to capture messages that would otherwise
     * end up on the 'dx' queue */
    virNetServerClientFilter *filters;
    int nextFilterID;

    virNetServerClientDispatchFunc dispatchFunc;
    void *dispatchOpaque;

    void *privateData;
    virFreeCallback privateDataFreeFunc;
    virNetServerClientPrivPreExecRestart privateDataPreExecRestart;
    virNetServerClientCloseFunc privateDataCloseFunc;

    virKeepAlive *keepalive;
};


static virClass *virNetServerClientClass;
static void virNetServerClientDispose(void *obj);

static int virNetServerClientOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetServerClient, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServerClient);


static void virNetServerClientDispatchEvent(virNetSocket *sock, int events, void *opaque);
static void virNetServerClientUpdateEvent(virNetServerClient *client);
static virNetMessage *virNetServerClientDispatchRead(virNetServerClient *client);
static int virNetServerClientSendMessageLocked(virNetServerClient *client,
                                               virNetMessage *msg);

/*
 * @client: a locked client object
 */
static int
virNetServerClientCalculateHandleMode(virNetServerClient *client)
{
    int mode = 0;


    VIR_DEBUG("tls=%p hs=%d, rx=%p tx=%p",
              client->tls,
              client->tls ? virNetTLSSessionGetHandshakeStatus(client->tls) : -1,
              client->rx,
              client->tx);
    if (!client->sock || client->wantClose)
        return 0;

    if (client->tls) {
        switch (virNetTLSSessionGetHandshakeStatus(client->tls)) {
        case VIR_NET_TLS_HANDSHAKE_RECVING:
            mode |= VIR_EVENT_HANDLE_READABLE;
            break;
        case VIR_NET_TLS_HANDSHAKE_SENDING:
            mode |= VIR_EVENT_HANDLE_WRITABLE;
            break;
        default:
        case VIR_NET_TLS_HANDSHAKE_COMPLETE:
            if (client->rx)
                mode |= VIR_EVENT_HANDLE_READABLE;
            if (client->tx)
                mode |= VIR_EVENT_HANDLE_WRITABLE;
        }
    } else {
        /* If there is a message on the rx queue, and
         * we're not in middle of a delayedClose, then
         * we're wanting more input */
        if (client->rx && !client->delayedClose)
            mode |= VIR_EVENT_HANDLE_READABLE;

        /* If there are one or more messages to send back to client,
           then monitor for writability on socket */
        if (client->tx)
            mode |= VIR_EVENT_HANDLE_WRITABLE;
    }
    VIR_DEBUG("mode=0%o", mode);
    return mode;
}

/*
 * @server: a locked or unlocked server object
 * @client: a locked client object
 */
static int virNetServerClientRegisterEvent(virNetServerClient *client)
{
    int mode = virNetServerClientCalculateHandleMode(client);

    if (!client->sock)
        return -1;

    virObjectRef(client);
    VIR_DEBUG("Registering client event callback %d", mode);
    if (virNetSocketAddIOCallback(client->sock,
                                  mode,
                                  virNetServerClientDispatchEvent,
                                  client,
                                  virObjectUnref) < 0) {
        virObjectUnref(client);
        return -1;
    }

    return 0;
}

/*
 * @client: a locked client object
 */
static void virNetServerClientUpdateEvent(virNetServerClient *client)
{
    int mode;

    if (!client->sock)
        return;

    mode = virNetServerClientCalculateHandleMode(client);

    virNetSocketUpdateIOCallback(client->sock, mode);

    if (client->rx && virNetSocketHasCachedData(client->sock))
        virEventUpdateTimeout(client->sockTimer, 0);
}


int virNetServerClientAddFilter(virNetServerClient *client,
                                virNetServerClientFilterFunc func,
                                void *opaque)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    virNetServerClientFilter *filter;
    virNetServerClientFilter **place;

    filter = g_new0(virNetServerClientFilter, 1);

    filter->id = client->nextFilterID++;
    filter->func = func;
    filter->opaque = opaque;

    place = &client->filters;
    while (*place)
        place = &(*place)->next;
    *place = filter;

    return filter->id;
}

void virNetServerClientRemoveFilter(virNetServerClient *client,
                                    int filterID)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    virNetServerClientFilter *tmp;
    virNetServerClientFilter *prev;

    prev = NULL;
    tmp = client->filters;
    while (tmp) {
        if (tmp->id == filterID) {
            if (prev)
                prev->next = tmp->next;
            else
                client->filters = tmp->next;

            VIR_FREE(tmp);
            break;
        }
        prev = tmp;
        tmp = tmp->next;
    }
}


/* Check the client's access. */
static int
virNetServerClientCheckAccess(virNetServerClient *client)
{
    virNetMessage *confirm;

    /* Verify client certificate. */
    if (virNetTLSContextCheckCertificate(client->tlsCtxt, client->tls) < 0)
        return -1;

    if (client->tx) {
        VIR_DEBUG("client had unexpected data pending tx after access check");
        return -1;
    }

    if (!(confirm = virNetMessageNew(false)))
        return -1;

    /* Checks have succeeded.  Write a '\1' byte back to the client to
     * indicate this (otherwise the socket is abruptly closed).
     * (NB. The '\1' byte is sent in an encrypted record).
     */
    confirm->bufferLength = 1;
    confirm->buffer = g_new0(char, confirm->bufferLength);
    confirm->bufferOffset = 0;
    confirm->buffer[0] = '\1';

    client->tx = confirm;

    return 0;
}


static void virNetServerClientDispatchMessage(virNetServerClient *client,
                                              virNetMessage *msg)
{
    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        if (!client->dispatchFunc) {
            virNetMessageFree(msg);
            client->wantClose = true;
            return;
        }
    }

    /* Accessing 'client' is safe, because virNetServerClientSetDispatcher
     * only permits setting 'dispatchFunc' once, so if non-NULL, it will
     * never change again
     */
    client->dispatchFunc(client, msg, client->dispatchOpaque);
}


static void virNetServerClientSockTimerFunc(int timer,
                                            void *opaque)
{
    virNetServerClient *client = opaque;
    virNetMessage *msg = NULL;

    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        virEventUpdateTimeout(timer, -1);
        /* Although client->rx != NULL when this timer is enabled, it might have
         * changed since the client was unlocked in the meantime. */
        if (client->rx)
            msg = virNetServerClientDispatchRead(client);
    }

    if (msg)
        virNetServerClientDispatchMessage(client, msg);
}


/**
 * virNetServerClientAuthMethodImpliesAuthenticated:
 * @auth: authentication method to check
 *
 * Check if the passed authentication method implies that a client is
 * automatically authenticated.
 *
 * Returns true if @auth implies that a client is automatically
 * authenticated, otherwise false.
 */
static bool
virNetServerClientAuthMethodImpliesAuthenticated(int auth)
{
    return auth == VIR_NET_SERVER_SERVICE_AUTH_NONE;
}


static virNetServerClient *
virNetServerClientNewInternal(unsigned long long id,
                              virNetSocket *sock,
                              int auth,
                              bool auth_pending,
                              virNetTLSContext *tls,
                              bool readonly,
                              size_t nrequests_max,
                              long long timestamp)
{
    virNetServerClient *client;

    if (virNetServerClientInitialize() < 0)
        return NULL;

    if (!(client = virObjectLockableNew(virNetServerClientClass)))
        return NULL;

    client->id = id;
    client->sock = virObjectRef(sock);
    client->auth = auth;
    client->auth_pending = auth_pending;
    client->readonly = readonly;
    client->tlsCtxt = virObjectRef(tls);
    client->nrequests_max = nrequests_max;
    client->conn_time = timestamp;

    client->sockTimer = virEventAddTimeout(-1, virNetServerClientSockTimerFunc,
                                           client, NULL);
    if (client->sockTimer < 0)
        goto error;

    /* Prepare one for packet receive */
    if (!(client->rx = virNetMessageNew(true)))
        goto error;
    client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
    client->rx->buffer = g_new0(char, client->rx->bufferLength);
    client->nrequests = 1;

    PROBE(RPC_SERVER_CLIENT_NEW,
          "client=%p sock=%p",
          client, client->sock);

    return client;

 error:
    virObjectUnref(client);
    return NULL;
}


virNetServerClient *virNetServerClientNew(unsigned long long id,
                                          virNetSocket *sock,
                                          int auth,
                                          bool readonly,
                                          size_t nrequests_max,
                                          virNetTLSContext *tls,
                                          virNetServerClientPrivNew privNew,
                                          virNetServerClientPrivPreExecRestart privPreExecRestart,
                                          virFreeCallback privFree,
                                          void *privOpaque)
{
    virNetServerClient *client;
    time_t now;
    bool auth_pending = !virNetServerClientAuthMethodImpliesAuthenticated(auth);

    VIR_DEBUG("sock=%p auth=%d tls=%p", sock, auth, tls);

    if ((now = time(NULL)) == (time_t)-1) {
        virReportSystemError(errno, "%s", _("failed to get current time"));
        return NULL;
    }

    if (!(client = virNetServerClientNewInternal(id, sock, auth, auth_pending,
                                                 tls, readonly, nrequests_max,
                                                 now)))
        return NULL;

    if (!(client->privateData = privNew(client, privOpaque))) {
        virObjectUnref(client);
        return NULL;
    }
    client->privateDataFreeFunc = privFree;
    client->privateDataPreExecRestart = privPreExecRestart;

    return client;
}


virNetServerClient *virNetServerClientNewPostExecRestart(virNetServer *srv,
                                                         virJSONValue *object,
                                                         virNetServerClientPrivNewPostExecRestart privNew,
                                                         virNetServerClientPrivPreExecRestart privPreExecRestart,
                                                         virFreeCallback privFree,
                                                         void *privOpaque)
{
    virJSONValue *child;
    virNetServerClient *client = NULL;
    virNetSocket *sock;
    int auth;
    bool readonly, auth_pending;
    unsigned int nrequests_max;
    unsigned long long id;
    long long timestamp;

    if (virJSONValueObjectGetNumberInt(object, "auth", &auth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing auth field in JSON state document"));
        return NULL;
    }

    if (!virJSONValueObjectHasKey(object, "auth_pending")) {
        auth_pending = !virNetServerClientAuthMethodImpliesAuthenticated(auth);
    } else {
        if (virJSONValueObjectGetBoolean(object, "auth_pending", &auth_pending) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed auth_pending field in JSON state document"));
            return NULL;
        }

        /* If the used authentication method implies that the new
         * client is automatically authenticated, the authentication
         * cannot be pending */
        if (auth_pending && virNetServerClientAuthMethodImpliesAuthenticated(auth)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid auth_pending and auth combination in JSON state document"));
            return NULL;
        }
    }

    if (virJSONValueObjectGetBoolean(object, "readonly", &readonly) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing readonly field in JSON state document"));
        return NULL;
    }
    if (virJSONValueObjectGetNumberUint(object, "nrequests_max",
                                        &nrequests_max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing nrequests_client_max field in JSON state document"));
        return NULL;
    }

    if (!(child = virJSONValueObjectGet(object, "sock"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing sock field in JSON state document"));
        return NULL;
    }

    if (!virJSONValueObjectHasKey(object, "id")) {
        /* no ID found in, a new one must be generated */
        id = virNetServerNextClientID(srv);
    } else {
        if (virJSONValueObjectGetNumberUlong(object, "id", &id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed id field in JSON state document"));
            return NULL;
        }
    }

    if (!virJSONValueObjectHasKey(object, "conn_time")) {
        timestamp = 0;
    } else {
        if (virJSONValueObjectGetNumberLong(object, "conn_time", &timestamp) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed conn_time field in JSON state document"));
            return NULL;
        }
    }

    if (!(sock = virNetSocketNewPostExecRestart(child))) {
        virObjectUnref(sock);
        return NULL;
    }

    if (!(client = virNetServerClientNewInternal(id,
                                                 sock,
                                                 auth,
                                                 auth_pending,
                                                 NULL,
                                                 readonly,
                                                 nrequests_max,
                                                 timestamp))) {
        virObjectUnref(sock);
        return NULL;
    }
    virObjectUnref(sock);

    if (!(child = virJSONValueObjectGet(object, "privateData"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing privateData field in JSON state document"));
        goto error;
    }

    if (!(client->privateData = privNew(client, child, privOpaque)))
        goto error;

    client->privateDataFreeFunc = privFree;
    client->privateDataPreExecRestart = privPreExecRestart;


    return client;

 error:
    virObjectUnref(client);
    return NULL;
}


virJSONValue *virNetServerClientPreExecRestart(virNetServerClient *client)
{
    g_autoptr(virJSONValue) object = virJSONValueNewObject();
    g_autoptr(virJSONValue) sock = NULL;
    g_autoptr(virJSONValue) priv = NULL;
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (virJSONValueObjectAppendNumberUlong(object, "id", client->id) < 0)
        return NULL;
    if (virJSONValueObjectAppendNumberInt(object, "auth", client->auth) < 0)
        return NULL;
    if (virJSONValueObjectAppendBoolean(object, "auth_pending", client->auth_pending) < 0)
        return NULL;
    if (virJSONValueObjectAppendBoolean(object, "readonly", client->readonly) < 0)
        return NULL;
    if (virJSONValueObjectAppendNumberUint(object, "nrequests_max", client->nrequests_max) < 0)
        return NULL;

    if (client->conn_time &&
        virJSONValueObjectAppendNumberLong(object, "conn_time",
                                           client->conn_time) < 0)
        return NULL;

    if (!(sock = virNetSocketPreExecRestart(client->sock)))
        return NULL;

    if (virJSONValueObjectAppend(object, "sock", &sock) < 0)
        return NULL;

    if (!(priv = client->privateDataPreExecRestart(client, client->privateData)))
        return NULL;

    if (virJSONValueObjectAppend(object, "privateData", &priv) < 0)
        return NULL;

    return g_steal_pointer(&object);
}


int virNetServerClientGetAuth(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return client->auth;
}


void
virNetServerClientSetAuthLocked(virNetServerClient *client,
                                int auth)
{
    client->auth = auth;
}


bool virNetServerClientGetReadonly(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return client->readonly;
}


void
virNetServerClientSetReadonly(virNetServerClient *client,
                              bool readonly)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    client->readonly = readonly;
}


unsigned long long virNetServerClientGetID(virNetServerClient *client)
{
    return client->id;
}

long long virNetServerClientGetTimestamp(virNetServerClient *client)
{
    return client->conn_time;
}

bool virNetServerClientHasTLSSession(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return !!client->tls;
}


virNetTLSSession *virNetServerClientGetTLSSession(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return client->tls;
}

int virNetServerClientGetTLSKeySize(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (!client->tls)
        return 0;

    return virNetTLSSessionGetKeySize(client->tls);
}

int virNetServerClientGetFD(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (!client->sock)
        return -1;

    return virNetSocketGetFD(client->sock);
}


bool virNetServerClientIsLocal(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (!client->sock)
        return false;

    return virNetSocketIsLocal(client->sock);
}


int virNetServerClientGetUNIXIdentity(virNetServerClient *client,
                                      uid_t *uid, gid_t *gid, pid_t *pid,
                                      unsigned long long *timestamp)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (!client->sock)
        return -1;

    return virNetSocketGetUNIXIdentity(client->sock, uid, gid, pid, timestamp);
}


static virIdentity *
virNetServerClientCreateIdentity(virNetServerClient *client)
{
    g_autofree char *username = NULL;
    g_autofree char *groupname = NULL;
    g_autofree char *seccontext = NULL;
    g_autoptr(virIdentity) ret = virIdentityNew();

    if (client->sock && virNetSocketIsLocal(client->sock)) {
        gid_t gid;
        uid_t uid;
        pid_t pid;
        unsigned long long timestamp;
        if (virNetSocketGetUNIXIdentity(client->sock,
                                        &uid, &gid, &pid,
                                        &timestamp) < 0)
            return NULL;

        if (!(username = virGetUserName(uid)))
            return NULL;
        if (virIdentitySetUserName(ret, username) < 0)
            return NULL;
        if (virIdentitySetUNIXUserID(ret, uid) < 0)
            return NULL;

        if (!(groupname = virGetGroupName(gid)))
            return NULL;
        if (virIdentitySetGroupName(ret, groupname) < 0)
            return NULL;
        if (virIdentitySetUNIXGroupID(ret, gid) < 0)
            return NULL;

        if (virIdentitySetProcessID(ret, pid) < 0)
            return NULL;
        if (virIdentitySetProcessTime(ret, timestamp) < 0)
            return NULL;
    }

#if WITH_SASL
    if (client->sasl) {
        const char *identity = virNetSASLSessionGetIdentity(client->sasl);
        if (virIdentitySetSASLUserName(ret, identity) < 0)
            return NULL;
    }
#endif

    if (client->tls) {
        const char *identity = virNetTLSSessionGetX509DName(client->tls);
        if (virIdentitySetX509DName(ret, identity) < 0)
            return NULL;
    }

    if (client->sock &&
        virNetSocketGetSELinuxContext(client->sock, &seccontext) < 0)
        return NULL;
    if (seccontext &&
        virIdentitySetSELinuxContext(ret, seccontext) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


virIdentity *virNetServerClientGetIdentity(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (!client->identity)
        client->identity = virNetServerClientCreateIdentity(client);

    if (!client->identity)
        return NULL;

    return g_object_ref(client->identity);
}


void virNetServerClientSetIdentity(virNetServerClient *client,
                                   virIdentity *identity)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    g_clear_object(&client->identity);
    client->identity = identity;
    if (client->identity)
        g_object_ref(client->identity);
}


int virNetServerClientGetSELinuxContext(virNetServerClient *client,
                                        char **context)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    *context = NULL;

    if (!client->sock)
        return 0;

    return virNetSocketGetSELinuxContext(client->sock, context);
}


bool virNetServerClientIsSecure(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    if (client->tls)
        return true;

#if WITH_SASL
    if (client->sasl)
        return true;
#endif

    if (client->sock && virNetSocketIsLocal(client->sock))
        return true;

    return false;
}


#if WITH_SASL
void virNetServerClientSetSASLSession(virNetServerClient *client,
                                      virNetSASLSession *sasl)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    /* We don't set the sasl session on the socket here
     * because we need to send out the auth confirmation
     * in the clear. Only once we complete the next 'tx'
     * operation do we switch to SASL mode
     */
    client->sasl = virObjectRef(sasl);
}


virNetSASLSession *virNetServerClientGetSASLSession(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return client->sasl;
}

bool virNetServerClientHasSASLSession(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return !!client->sasl;
}
#endif


void *virNetServerClientGetPrivateData(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return client->privateData;
}


void virNetServerClientSetCloseHook(virNetServerClient *client,
                                    virNetServerClientCloseFunc cf)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    client->privateDataCloseFunc = cf;
}


void virNetServerClientSetDispatcher(virNetServerClient *client,
                                     virNetServerClientDispatchFunc func,
                                     void *opaque)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    /* Only set dispatcher if not already set, to avoid race
     * with dispatch code that runs without locks held
     */
    if (!client->dispatchFunc) {
        client->dispatchFunc = func;
        client->dispatchOpaque = opaque;
    }
}


const char *virNetServerClientLocalAddrStringSASL(virNetServerClient *client)
{
    if (!client->sock)
        return NULL;
    return virNetSocketLocalAddrStringSASL(client->sock);
}


const char *virNetServerClientRemoteAddrStringSASL(virNetServerClient *client)
{
    if (!client->sock)
        return NULL;
    return virNetSocketRemoteAddrStringSASL(client->sock);
}

const char *virNetServerClientRemoteAddrStringURI(virNetServerClient *client)
{
    if (!client->sock)
        return NULL;
    return virNetSocketRemoteAddrStringURI(client->sock);
}

void virNetServerClientDispose(void *obj)
{
    virNetServerClient *client = obj;

    PROBE(RPC_SERVER_CLIENT_DISPOSE,
          "client=%p", client);

    if (client->rx)
        virNetMessageFree(client->rx);
    if (client->privateData)
        client->privateDataFreeFunc(client->privateData);

    g_clear_object(&client->identity);

#if WITH_SASL
    virObjectUnref(client->sasl);
#endif
    if (client->sockTimer > 0)
        virEventRemoveTimeout(client->sockTimer);
    virObjectUnref(client->tls);
    virObjectUnref(client->tlsCtxt);
    virObjectUnref(client->sock);
}


/*
 *
 * We don't free stuff here, merely disconnect the client's
 * network socket & resources.
 *
 * Full free of the client is done later in a safe point
 * where it can be guaranteed it is no longer in use
 */
void
virNetServerClientCloseLocked(virNetServerClient *client)
{
    virNetServerClientCloseFunc cf;
    virKeepAlive *ka;

    VIR_DEBUG("client=%p", client);
    if (!client->sock)
        return;

    if (client->keepalive) {
        virKeepAliveStop(client->keepalive);
        ka = g_steal_pointer(&client->keepalive);
        virObjectRef(client);
        virObjectUnlock(client);
        virObjectUnref(ka);
        virObjectLock(client);
        virObjectUnref(client);
    }

    if (client->privateDataCloseFunc) {
        cf = client->privateDataCloseFunc;
        virObjectRef(client);
        virObjectUnlock(client);
        (cf)(client);
        virObjectLock(client);
        virObjectUnref(client);
    }

    /* Do now, even though we don't close the socket
     * until end, to ensure we don't get invoked
     * again due to tls shutdown */
    if (client->sock)
        virNetSocketRemoveIOCallback(client->sock);

    if (client->tls) {
        g_clear_pointer(&client->tls, virObjectUnref);
    }
    client->wantClose = true;

    while (client->rx) {
        virNetMessage *msg
            = virNetMessageQueueServe(&client->rx);
        virNetMessageFree(msg);
    }
    while (client->tx) {
        virNetMessage *msg
            = virNetMessageQueueServe(&client->tx);
        virNetMessageFree(msg);
    }

    if (client->sock) {
        g_clear_pointer(&client->sock, virObjectUnref);
    }
}


void
virNetServerClientClose(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    virNetServerClientCloseLocked(client);
}


bool
virNetServerClientIsClosedLocked(virNetServerClient *client)
{
    return client->sock == NULL;
}


void virNetServerClientDelayedClose(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    client->delayedClose = true;
}

void virNetServerClientImmediateClose(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    client->wantClose = true;
}


bool
virNetServerClientWantCloseLocked(virNetServerClient *client)
{
    return client->wantClose;
}


int virNetServerClientInit(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    int ret = -1;

    if (!client->tlsCtxt) {
        /* Plain socket, so prepare to read first message */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
        return 0;
    }

    if (!(client->tls = virNetTLSSessionNew(client->tlsCtxt, NULL)))
        goto error;

    virNetSocketSetTLSSession(client->sock, client->tls);

    /* Begin the TLS handshake. */
    VIR_WITH_OBJECT_LOCK_GUARD(client->tlsCtxt) {
        ret = virNetTLSSessionHandshake(client->tls);
    }

    if (ret == 0) {
        /* Unlikely, but ...  Next step is to check the certificate. */
        if (virNetServerClientCheckAccess(client) < 0)
            goto error;

        /* Handshake & cert check OK,  so prepare to read first message */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
    } else if (ret > 0) {
        /* Most likely, need to do more handshake data */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
    } else {
        goto error;
    }

    return 0;

 error:
    client->wantClose = true;
    return -1;
}



/*
 * Read data into buffer using wire decoding (plain or TLS)
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t virNetServerClientRead(virNetServerClient *client)
{
    ssize_t ret;

    if (client->rx->bufferLength <= client->rx->bufferOffset) {
        virReportError(VIR_ERR_RPC,
                       _("unexpected zero/negative length request %1$lld"),
                       (long long int)(client->rx->bufferLength - client->rx->bufferOffset));
        client->wantClose = true;
        return -1;
    }

    ret = virNetSocketRead(client->sock,
                           client->rx->buffer + client->rx->bufferOffset,
                           client->rx->bufferLength - client->rx->bufferOffset);

    if (ret <= 0)
        return ret;

    client->rx->bufferOffset += ret;
    return ret;
}


/*
 * Read data until we get a complete message to process.
 * If a complete message is available, it will be returned
 * from this method, for dispatch by the caller.
 *
 * Returns a complete message for dispatch, or NULL if none is
 * yet available, or an error occurred. On error, the wantClose
 * flag will be set.
 */
static virNetMessage *virNetServerClientDispatchRead(virNetServerClient *client)
{
 readmore:
    if (client->rx->nfds == 0) {
        if (virNetServerClientRead(client) < 0) {
            client->wantClose = true;
            return NULL; /* Error */
        }
    }

    if (client->rx->bufferOffset < client->rx->bufferLength)
        return NULL; /* Still not read enough */

    /* Either done with length word header */
    if (client->rx->bufferLength == VIR_NET_MESSAGE_LEN_MAX) {
        if (virNetMessageDecodeLength(client->rx) < 0) {
            client->wantClose = true;
            return NULL;
        }

        virNetServerClientUpdateEvent(client);

        /* Try and read payload immediately instead of going back
           into poll() because chances are the data is already
           waiting for us */
        goto readmore;
    } else {
        /* Grab the completed message */
        virNetMessage *msg = client->rx;
        virNetMessage *response = NULL;
        virNetServerClientFilter *filter;
        size_t i;

        /* Decode the header so we can use it for routing decisions */
        if (virNetMessageDecodeHeader(msg) < 0) {
            virNetMessageQueueServe(&client->rx);
            virNetMessageFree(msg);
            client->wantClose = true;
            return NULL;
        }

        /* Now figure out if we need to read more data to get some
         * file descriptors */
        if (msg->header.type == VIR_NET_CALL_WITH_FDS) {
            if (virNetMessageDecodeNumFDs(msg) < 0) {
                virNetMessageQueueServe(&client->rx);
                virNetMessageFree(msg);
                client->wantClose = true;
                return NULL; /* Error */
            }

            /* Try getting the file descriptors (may fail if blocking) */
            for (i = msg->donefds; i < msg->nfds; i++) {
                int rv;
                if ((rv = virNetSocketRecvFD(client->sock, &(msg->fds[i]))) < 0) {
                    virNetMessageQueueServe(&client->rx);
                    virNetMessageFree(msg);
                    client->wantClose = true;
                    return NULL;
                }
                if (rv == 0) /* Blocking */
                    break;
                msg->donefds++;
            }

            /* Need to poll() until FDs arrive */
            if (msg->donefds < msg->nfds) {
                /* Because DecodeHeader/NumFDs reset bufferOffset, we
                 * put it back to what it was, so everything works
                 * again next time we run this method
                 */
                client->rx->bufferOffset = client->rx->bufferLength;
                return NULL;
            }
        }

        /* Definitely finished reading, so remove from queue */
        virNetMessageQueueServe(&client->rx);
        PROBE(RPC_SERVER_CLIENT_MSG_RX,
              "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
              client, msg->bufferLength,
              msg->header.prog, msg->header.vers, msg->header.proc,
              msg->header.type, msg->header.status, msg->header.serial);

        if (virKeepAliveCheckMessage(client->keepalive, msg, &response)) {
            g_clear_pointer(&msg, virNetMessageFree);
            client->nrequests--;

            if (response &&
                virNetServerClientSendMessageLocked(client, response) < 0)
                virNetMessageFree(response);
        }

        /* Maybe send off for queue against a filter */
        if (msg) {
            filter = client->filters;
            while (filter) {
                int ret = filter->func(client, msg, filter->opaque);
                if (ret < 0) {
                    g_clear_pointer(&msg, virNetMessageFree);
                    client->wantClose = true;
                    break;
                }
                if (ret > 0) {
                    msg = NULL;
                    break;
                }

                filter = filter->next;
            }
        }

        /* Possibly need to create another receive buffer */
        if (client->nrequests < client->nrequests_max) {
            client->rx = virNetMessageNew(true);
            client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
            client->rx->buffer = g_new0(char, client->rx->bufferLength);
            client->nrequests++;
        } else if (!client->nrequests_warning &&
                   client->nrequests_max > 1) {
            client->nrequests_warning = true;
            VIR_WARN("Client hit max requests limit %zd. This may result "
                     "in keep-alive timeouts. Consider tuning the "
                     "max_client_requests server parameter", client->nrequests);
        }
        virNetServerClientUpdateEvent(client);

        return msg;
    }
}


/*
 * Send client->tx using no encoding
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t virNetServerClientWrite(virNetServerClient *client)
{
    ssize_t ret;

    if (client->tx->bufferLength < client->tx->bufferOffset) {
        virReportError(VIR_ERR_RPC,
                       _("unexpected zero/negative length request %1$lld"),
                       (long long int)(client->tx->bufferLength - client->tx->bufferOffset));
        client->wantClose = true;
        return -1;
    }

    if (client->tx->bufferLength == client->tx->bufferOffset)
        return 1;

    ret = virNetSocketWrite(client->sock,
                            client->tx->buffer + client->tx->bufferOffset,
                            client->tx->bufferLength - client->tx->bufferOffset);
    if (ret <= 0)
        return ret; /* -1 error, 0 = egain */

    client->tx->bufferOffset += ret;
    return ret;
}


/*
 * Process all queued client->tx messages until
 * we would block on I/O
 */
static void
virNetServerClientDispatchWrite(virNetServerClient *client)
{
    while (client->tx) {
        if (client->tx->bufferOffset < client->tx->bufferLength) {
            ssize_t ret;
            ret = virNetServerClientWrite(client);
            if (ret < 0) {
                client->wantClose = true;
                return;
            }
            if (ret == 0)
                return; /* Would block on write EAGAIN */
        }

        if (client->tx->bufferOffset == client->tx->bufferLength) {
            virNetMessage *msg;
            size_t i;

            for (i = client->tx->donefds; i < client->tx->nfds; i++) {
                int rv;
                if ((rv = virNetSocketSendFD(client->sock, client->tx->fds[i])) < 0) {
                    client->wantClose = true;
                    return;
                }
                if (rv == 0) /* Blocking */
                    return;
                client->tx->donefds++;
            }

#if WITH_SASL
            /* Completed this 'tx' operation, so now read for all
             * future rx/tx to be under a SASL SSF layer
             */
            if (client->sasl) {
                virNetSocketSetSASLSession(client->sock, client->sasl);
                g_clear_pointer(&client->sasl, virObjectUnref);
            }
#endif

            /* Get finished msg from head of tx queue */
            msg = virNetMessageQueueServe(&client->tx);

            if (msg->tracked) {
                client->nrequests--;
                /* See if the recv queue is currently throttled */
                if (!client->rx &&
                    client->nrequests < client->nrequests_max) {
                    /* Ready to recv more messages */
                    virNetMessageClear(msg);
                    msg->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
                    msg->buffer = g_new0(char, msg->bufferLength);
                    client->rx = g_steal_pointer(&msg);
                    client->nrequests++;
                }
            }

            virNetMessageFree(msg);

            virNetServerClientUpdateEvent(client);

            if (client->delayedClose)
                client->wantClose = true;
         }
    }
}


static void
virNetServerClientDispatchHandshake(virNetServerClient *client)
{
    int ret = -1;

    /* Continue the handshake. */
    VIR_WITH_OBJECT_LOCK_GUARD(client->tlsCtxt) {
        ret = virNetTLSSessionHandshake(client->tls);
    }

    if (ret == 0) {
        /* Finished.  Next step is to check the certificate. */
        if (virNetServerClientCheckAccess(client) < 0)
            client->wantClose = true;
        else
            virNetServerClientUpdateEvent(client);
    } else if (ret > 0) {
        /* Carry on waiting for more handshake. Update
           the events just in case handshake data flow
           direction has changed */
        virNetServerClientUpdateEvent(client);
    } else {
        /* Fatal error in handshake */
        client->wantClose = true;
    }
}


static void
virNetServerClientDispatchEvent(virNetSocket *sock, int events, void *opaque)
{
    virNetServerClient *client = opaque;
    virNetMessage *msg = NULL;

    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        if (client->sock != sock) {
            virNetSocketRemoveIOCallback(sock);
            return;
        }

        if (events & (VIR_EVENT_HANDLE_WRITABLE | VIR_EVENT_HANDLE_READABLE)) {
            if (client->tls &&
                virNetTLSSessionGetHandshakeStatus(client->tls) !=
                VIR_NET_TLS_HANDSHAKE_COMPLETE) {
                virNetServerClientDispatchHandshake(client);
            } else {
                if (events & VIR_EVENT_HANDLE_WRITABLE)
                    virNetServerClientDispatchWrite(client);
                if ((events & VIR_EVENT_HANDLE_READABLE) && client->rx)
                    msg = virNetServerClientDispatchRead(client);
            }
        }

        /* NB, will get HANGUP + READABLE at same time upon disconnect */
        if (events & (VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP))
            client->wantClose = true;
    }

    if (msg)
        virNetServerClientDispatchMessage(client, msg);
}


static int
virNetServerClientSendMessageLocked(virNetServerClient *client,
                                    virNetMessage *msg)
{
    int ret = -1;
    VIR_DEBUG("msg=%p proc=%d len=%zu offset=%zu",
              msg, msg->header.proc,
              msg->bufferLength, msg->bufferOffset);

    msg->donefds = 0;
    if (client->sock && !client->wantClose) {
        PROBE(RPC_SERVER_CLIENT_MSG_TX_QUEUE,
              "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
              client, msg->bufferLength,
              msg->header.prog, msg->header.vers, msg->header.proc,
              msg->header.type, msg->header.status, msg->header.serial);
        virNetMessageQueuePush(&client->tx, msg);

        virNetServerClientUpdateEvent(client);
        ret = 0;
    }

    return ret;
}

int virNetServerClientSendMessage(virNetServerClient *client,
                                  virNetMessage *msg)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return virNetServerClientSendMessageLocked(client, msg);
}


bool
virNetServerClientIsAuthenticated(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return virNetServerClientAuthMethodImpliesAuthenticated(client->auth);
}


/* The caller must hold the lock for @client */
void
virNetServerClientSetAuthPendingLocked(virNetServerClient *client,
                                       bool auth_pending)
{
    client->auth_pending = auth_pending;
}


/* The caller must hold the lock for @client */
bool
virNetServerClientIsAuthPendingLocked(virNetServerClient *client)
{
    return client->auth_pending;
}


static void
virNetServerClientKeepAliveDeadCB(void *opaque)
{
    virNetServerClientImmediateClose(opaque);
}

static int
virNetServerClientKeepAliveSendCB(void *opaque,
                                  virNetMessage *msg)
{
    return virNetServerClientSendMessage(opaque, msg);
}


int
virNetServerClientInitKeepAlive(virNetServerClient *client,
                                int interval,
                                unsigned int count)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    virKeepAlive *ka;

    if (!(ka = virKeepAliveNew(interval, count, client,
                               virNetServerClientKeepAliveSendCB,
                               virNetServerClientKeepAliveDeadCB,
                               virObjectUnref)))
        return -1;

    /* keepalive object has a reference to client */
    virObjectRef(client);

    client->keepalive = ka;
    return 0;
}

int
virNetServerClientStartKeepAlive(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    /* The connection might have been closed before we got here and thus the
     * keepalive object could have been removed too.
     */
    if (!client->keepalive) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        return -1;
    }

    return virKeepAliveStart(client->keepalive, 0, 0);
}

int
virNetServerClientGetTransport(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    int ret = -1;

    if (client->sock && virNetSocketIsLocal(client->sock))
        ret = VIR_CLIENT_TRANS_UNIX;
    else
        ret = VIR_CLIENT_TRANS_TCP;

    if (client->tls)
        ret = VIR_CLIENT_TRANS_TLS;

    return ret;
}

int
virNetServerClientGetInfo(virNetServerClient *client,
                          bool *readonly, char **sock_addr,
                          virIdentity **identity)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    const char *addr;

    *readonly = client->readonly;

    if (!(addr = virNetServerClientRemoteAddrStringURI(client))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No network socket associated with client"));
        return -1;
    }

    *sock_addr = g_strdup(addr);

    if (!client->identity) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No identity information available for client"));
        return -1;
    }

    *identity = g_object_ref(client->identity);
    return 0;
}


/**
 * virNetServerClientSetQuietEOF:
 *
 * Don't report errors for protocols that close connection by hangup of the
 * socket rather than calling an API to close it.
 */
void
virNetServerClientSetQuietEOF(virNetServerClient *client)
{
    virNetSocketSetQuietEOF(client->sock);
}
