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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "internal.h"
#if WITH_SASL
# include <sasl/sasl.h>
#endif

#include "virnetserverclient.h"

#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virthread.h"
#include "virkeepalive.h"
#include "virprobe.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netserverclient");

/* Allow for filtering of incoming messages to a custom
 * dispatch processing queue, instead of the workers.
 * This allows for certain types of messages to be handled
 * strictly "in order"
 */

typedef struct _virNetServerClientFilter virNetServerClientFilter;
typedef virNetServerClientFilter *virNetServerClientFilterPtr;

struct _virNetServerClientFilter {
    int id;
    virNetServerClientFilterFunc func;
    void *opaque;

    virNetServerClientFilterPtr next;
};


struct _virNetServerClient
{
    virObjectLockable parent;

    bool wantClose;
    bool delayedClose;
    virNetSocketPtr sock;
    int auth;
    bool readonly;
#if WITH_GNUTLS
    virNetTLSContextPtr tlsCtxt;
    virNetTLSSessionPtr tls;
#endif
#if WITH_SASL
    virNetSASLSessionPtr sasl;
#endif
    int sockTimer; /* Timer to be fired upon cached data,
                    * so we jump out from poll() immediately */


    virIdentityPtr identity;

    /* Count of messages in the 'tx' queue,
     * and the server worker pool queue
     * ie RPC calls in progress. Does not count
     * async events which are not used for
     * throttling calculations */
    size_t nrequests;
    size_t nrequests_max;
    /* Zero or one messages being received. Zero if
     * nrequests >= max_clients and throttling */
    virNetMessagePtr rx;
    /* Zero or many messages waiting for transmit
     * back to client, including async events */
    virNetMessagePtr tx;

    /* Filters to capture messages that would otherwise
     * end up on the 'dx' queue */
    virNetServerClientFilterPtr filters;
    int nextFilterID;

    virNetServerClientDispatchFunc dispatchFunc;
    void *dispatchOpaque;

    void *privateData;
    virFreeCallback privateDataFreeFunc;
    virNetServerClientPrivPreExecRestart privateDataPreExecRestart;
    virNetServerClientCloseFunc privateDataCloseFunc;

    virKeepAlivePtr keepalive;
};


static virClassPtr virNetServerClientClass;
static void virNetServerClientDispose(void *obj);

static int virNetServerClientOnceInit(void)
{
    if (!(virNetServerClientClass = virClassNew(virClassForObjectLockable(),
                                                "virNetServerClient",
                                                sizeof(virNetServerClient),
                                                virNetServerClientDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServerClient)


static void virNetServerClientDispatchEvent(virNetSocketPtr sock, int events, void *opaque);
static void virNetServerClientUpdateEvent(virNetServerClientPtr client);
static void virNetServerClientDispatchRead(virNetServerClientPtr client);
static int virNetServerClientSendMessageLocked(virNetServerClientPtr client,
                                               virNetMessagePtr msg);

/*
 * @client: a locked client object
 */
static int
virNetServerClientCalculateHandleMode(virNetServerClientPtr client)
{
    int mode = 0;


    VIR_DEBUG("tls=%p hs=%d, rx=%p tx=%p",
#ifdef WITH_GNUTLS
              client->tls,
              client->tls ? virNetTLSSessionGetHandshakeStatus(client->tls) : -1,
#else
              NULL, -1,
#endif
              client->rx,
              client->tx);
    if (!client->sock || client->wantClose)
        return 0;

#if WITH_GNUTLS
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
#endif
        /* If there is a message on the rx queue, and
         * we're not in middle of a delayedClose, then
         * we're wanting more input */
        if (client->rx && !client->delayedClose)
            mode |= VIR_EVENT_HANDLE_READABLE;

        /* If there are one or more messages to send back to client,
           then monitor for writability on socket */
        if (client->tx)
            mode |= VIR_EVENT_HANDLE_WRITABLE;
#if WITH_GNUTLS
    }
#endif
    VIR_DEBUG("mode=%o", mode);
    return mode;
}

/*
 * @server: a locked or unlocked server object
 * @client: a locked client object
 */
static int virNetServerClientRegisterEvent(virNetServerClientPtr client)
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
                                  virObjectFreeCallback) < 0) {
        virObjectUnref(client);
        return -1;
    }

    return 0;
}

/*
 * @client: a locked client object
 */
static void virNetServerClientUpdateEvent(virNetServerClientPtr client)
{
    int mode;

    if (!client->sock)
        return;

    mode = virNetServerClientCalculateHandleMode(client);

    virNetSocketUpdateIOCallback(client->sock, mode);

    if (client->rx && virNetSocketHasCachedData(client->sock))
        virEventUpdateTimeout(client->sockTimer, 0);
}


int virNetServerClientAddFilter(virNetServerClientPtr client,
                                virNetServerClientFilterFunc func,
                                void *opaque)
{
    virNetServerClientFilterPtr filter;
    virNetServerClientFilterPtr *place;
    int ret;

    if (VIR_ALLOC(filter) < 0)
        return -1;

    virObjectLock(client);

    filter->id = client->nextFilterID++;
    filter->func = func;
    filter->opaque = opaque;

    place = &client->filters;
    while (*place)
        place = &(*place)->next;
    *place = filter;

    ret = filter->id;

    virObjectUnlock(client);

    return ret;
}

void virNetServerClientRemoveFilter(virNetServerClientPtr client,
                                    int filterID)
{
    virNetServerClientFilterPtr tmp, prev;

    virObjectLock(client);

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

    virObjectUnlock(client);
}


#ifdef WITH_GNUTLS
/* Check the client's access. */
static int
virNetServerClientCheckAccess(virNetServerClientPtr client)
{
    virNetMessagePtr confirm;

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
    if (VIR_ALLOC_N(confirm->buffer, confirm->bufferLength) < 0) {
        virNetMessageFree(confirm);
        return -1;
    }
    confirm->bufferOffset = 0;
    confirm->buffer[0] = '\1';

    client->tx = confirm;

    return 0;
}
#endif


static void virNetServerClientSockTimerFunc(int timer,
                                            void *opaque)
{
    virNetServerClientPtr client = opaque;
    virObjectLock(client);
    virEventUpdateTimeout(timer, -1);
    /* Although client->rx != NULL when this timer is enabled, it might have
     * changed since the client was unlocked in the meantime. */
    if (client->rx)
        virNetServerClientDispatchRead(client);
    virObjectUnlock(client);
}


static virNetServerClientPtr
virNetServerClientNewInternal(virNetSocketPtr sock,
                              int auth,
#ifdef WITH_GNUTLS
                              virNetTLSContextPtr tls,
#endif
                              bool readonly,
                              size_t nrequests_max)
{
    virNetServerClientPtr client;

    if (virNetServerClientInitialize() < 0)
        return NULL;

    if (!(client = virObjectLockableNew(virNetServerClientClass)))
        return NULL;

    client->sock = virObjectRef(sock);
    client->auth = auth;
    client->readonly = readonly;
#ifdef WITH_GNUTLS
    client->tlsCtxt = virObjectRef(tls);
#endif
    client->nrequests_max = nrequests_max;

    client->sockTimer = virEventAddTimeout(-1, virNetServerClientSockTimerFunc,
                                           client, NULL);
    if (client->sockTimer < 0)
        goto error;

    /* Prepare one for packet receive */
    if (!(client->rx = virNetMessageNew(true)))
        goto error;
    client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
    if (VIR_ALLOC_N(client->rx->buffer, client->rx->bufferLength) < 0)
        goto error;
    client->nrequests = 1;

    PROBE(RPC_SERVER_CLIENT_NEW,
          "client=%p sock=%p",
          client, client->sock);

    return client;

 error:
    virObjectUnref(client);
    return NULL;
}


virNetServerClientPtr virNetServerClientNew(virNetSocketPtr sock,
                                            int auth,
                                            bool readonly,
                                            size_t nrequests_max,
#ifdef WITH_GNUTLS
                                            virNetTLSContextPtr tls,
#endif
                                            virNetServerClientPrivNew privNew,
                                            virNetServerClientPrivPreExecRestart privPreExecRestart,
                                            virFreeCallback privFree,
                                            void *privOpaque)
{
    virNetServerClientPtr client;

    VIR_DEBUG("sock=%p auth=%d tls=%p", sock, auth,
#ifdef WITH_GNUTLS
              tls
#else
              NULL
#endif
        );

    if (!(client = virNetServerClientNewInternal(sock, auth,
#ifdef WITH_GNUTLS
                                                 tls,
#endif
                                                 readonly, nrequests_max)))
        return NULL;

    if (privNew) {
        if (!(client->privateData = privNew(client, privOpaque))) {
            virObjectUnref(client);
            return NULL;
        }
        client->privateDataFreeFunc = privFree;
        client->privateDataPreExecRestart = privPreExecRestart;
    }

    return client;
}


virNetServerClientPtr virNetServerClientNewPostExecRestart(virJSONValuePtr object,
                                                           virNetServerClientPrivNewPostExecRestart privNew,
                                                           virNetServerClientPrivPreExecRestart privPreExecRestart,
                                                           virFreeCallback privFree,
                                                           void *privOpaque)
{
    virJSONValuePtr child;
    virNetServerClientPtr client = NULL;
    virNetSocketPtr sock;
    int auth;
    bool readonly;
    unsigned int nrequests_max;

    if (virJSONValueObjectGetNumberInt(object, "auth", &auth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing auth field in JSON state document"));
        return NULL;
    }
    if (virJSONValueObjectGetBoolean(object, "readonly", &readonly) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing readonly field in JSON state document"));
        return NULL;
    }
    if (virJSONValueObjectGetNumberUint(object, "nrequests_max",
                                        (unsigned int *)&nrequests_max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing nrequests_client_max field in JSON state document"));
        return NULL;
    }

    if (!(child = virJSONValueObjectGet(object, "sock"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing sock field in JSON state document"));
        return NULL;
    }

    if (!(sock = virNetSocketNewPostExecRestart(child))) {
        virObjectUnref(sock);
        return NULL;
    }

    if (!(client = virNetServerClientNewInternal(sock,
                                                 auth,
#ifdef WITH_GNUTLS
                                                 NULL,
#endif
                                                 readonly,
                                                 nrequests_max))) {
        virObjectUnref(sock);
        return NULL;
    }
    virObjectUnref(sock);

    if (privNew) {
        if (!(child = virJSONValueObjectGet(object, "privateData"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing privateData field in JSON state document"));
            goto error;
        }
        if (!(client->privateData = privNew(client, child, privOpaque))) {
            goto error;
        }
        client->privateDataFreeFunc = privFree;
        client->privateDataPreExecRestart = privPreExecRestart;
    }


    return client;

 error:
    virObjectUnref(client);
    return NULL;
}


virJSONValuePtr virNetServerClientPreExecRestart(virNetServerClientPtr client)
{
    virJSONValuePtr object = virJSONValueNewObject();
    virJSONValuePtr child;

    if (!object)
        return NULL;

    virObjectLock(client);

    if (virJSONValueObjectAppendNumberInt(object, "auth", client->auth) < 0)
        goto error;
    if (virJSONValueObjectAppendBoolean(object, "readonly", client->readonly) < 0)
        goto error;
    if (virJSONValueObjectAppendNumberUint(object, "nrequests_max", client->nrequests_max) < 0)
        goto error;

    if (!(child = virNetSocketPreExecRestart(client->sock)))
        goto error;

    if (virJSONValueObjectAppend(object, "sock", child) < 0) {
        virJSONValueFree(child);
        goto error;
    }

    if (client->privateData && client->privateDataPreExecRestart &&
        !(child = client->privateDataPreExecRestart(client, client->privateData)))
        goto error;

    if (virJSONValueObjectAppend(object, "privateData", child) < 0) {
        virJSONValueFree(child);
        goto error;
    }

    virObjectUnlock(client);
    return object;

 error:
    virObjectUnlock(client);
    virJSONValueFree(object);
    return NULL;
}


int virNetServerClientGetAuth(virNetServerClientPtr client)
{
    int auth;
    virObjectLock(client);
    auth = client->auth;
    virObjectUnlock(client);
    return auth;
}

void virNetServerClientSetAuth(virNetServerClientPtr client, int auth)
{
    virObjectLock(client);
    client->auth = auth;
    virObjectUnlock(client);
}

bool virNetServerClientGetReadonly(virNetServerClientPtr client)
{
    bool readonly;
    virObjectLock(client);
    readonly = client->readonly;
    virObjectUnlock(client);
    return readonly;
}


#ifdef WITH_GNUTLS
bool virNetServerClientHasTLSSession(virNetServerClientPtr client)
{
    bool has;
    virObjectLock(client);
    has = client->tls ? true : false;
    virObjectUnlock(client);
    return has;
}


virNetTLSSessionPtr virNetServerClientGetTLSSession(virNetServerClientPtr client)
{
    virNetTLSSessionPtr tls;
    virObjectLock(client);
    tls = client->tls;
    virObjectUnlock(client);
    return tls;
}

int virNetServerClientGetTLSKeySize(virNetServerClientPtr client)
{
    int size = 0;
    virObjectLock(client);
    if (client->tls)
        size = virNetTLSSessionGetKeySize(client->tls);
    virObjectUnlock(client);
    return size;
}
#endif

int virNetServerClientGetFD(virNetServerClientPtr client)
{
    int fd = -1;
    virObjectLock(client);
    if (client->sock)
        fd = virNetSocketGetFD(client->sock);
    virObjectUnlock(client);
    return fd;
}


bool virNetServerClientIsLocal(virNetServerClientPtr client)
{
    bool local = false;
    virObjectLock(client);
    if (client->sock)
        local = virNetSocketIsLocal(client->sock);
    virObjectUnlock(client);
    return local;
}


int virNetServerClientGetUNIXIdentity(virNetServerClientPtr client,
                                      uid_t *uid, gid_t *gid, pid_t *pid,
                                      unsigned long long *timestamp)
{
    int ret = -1;
    virObjectLock(client);
    if (client->sock)
        ret = virNetSocketGetUNIXIdentity(client->sock,
                                          uid, gid, pid,
                                          timestamp);
    virObjectUnlock(client);
    return ret;
}


static virIdentityPtr
virNetServerClientCreateIdentity(virNetServerClientPtr client)
{
    char *processid = NULL;
    char *processtime = NULL;
    char *username = NULL;
    char *userid = NULL;
    char *groupname = NULL;
    char *groupid = NULL;
#if WITH_SASL
    char *saslname = NULL;
#endif
#if WITH_GNUTLS
    char *x509dname = NULL;
#endif
    char *seccontext = NULL;
    virIdentityPtr ret = NULL;

    if (client->sock && virNetSocketIsLocal(client->sock)) {
        gid_t gid;
        uid_t uid;
        pid_t pid;
        unsigned long long timestamp;
        if (virNetSocketGetUNIXIdentity(client->sock,
                                        &uid, &gid, &pid,
                                        &timestamp) < 0)
            goto cleanup;

        if (!(username = virGetUserName(uid)))
            goto cleanup;
        if (virAsprintf(&userid, "%d", (int)uid) < 0)
            goto cleanup;
        if (!(groupname = virGetGroupName(gid)))
            goto cleanup;
        if (virAsprintf(&groupid, "%d", (int)gid) < 0)
            goto cleanup;
        if (virAsprintf(&processid, "%llu",
                        (unsigned long long)pid) < 0)
            goto cleanup;
        if (virAsprintf(&processtime, "%llu",
                        timestamp) < 0)
            goto cleanup;
    }

#if WITH_SASL
    if (client->sasl) {
        const char *identity = virNetSASLSessionGetIdentity(client->sasl);
        if (VIR_STRDUP(saslname, identity) < 0)
            goto cleanup;
    }
#endif

#if WITH_GNUTLS
    if (client->tls) {
        const char *identity = virNetTLSSessionGetX509DName(client->tls);
        if (VIR_STRDUP(x509dname, identity) < 0)
            goto cleanup;
    }
#endif

    if (client->sock &&
        virNetSocketGetSELinuxContext(client->sock, &seccontext) < 0)
        goto cleanup;

    if (!(ret = virIdentityNew()))
        goto cleanup;

    if (username &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_USER_NAME,
                           username) < 0)
        goto error;
    if (userid &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_USER_ID,
                           userid) < 0)
        goto error;
    if (groupname &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
                           groupname) < 0)
        goto error;
    if (groupid &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_GROUP_ID,
                           groupid) < 0)
        goto error;
    if (processid &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_PROCESS_ID,
                           processid) < 0)
        goto error;
    if (processtime &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_UNIX_PROCESS_TIME,
                           processtime) < 0)
        goto error;
#if WITH_SASL
    if (saslname &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_SASL_USER_NAME,
                           saslname) < 0)
        goto error;
#endif
#if WITH_GNUTLS
    if (x509dname &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_X509_DISTINGUISHED_NAME,
                           x509dname) < 0)
        goto error;
#endif
    if (seccontext &&
        virIdentitySetAttr(ret,
                           VIR_IDENTITY_ATTR_SELINUX_CONTEXT,
                           seccontext) < 0)
        goto error;

 cleanup:
    VIR_FREE(username);
    VIR_FREE(userid);
    VIR_FREE(groupname);
    VIR_FREE(groupid);
    VIR_FREE(processid);
    VIR_FREE(processtime);
    VIR_FREE(seccontext);
#if WITH_SASL
    VIR_FREE(saslname);
#endif
#if WITH_GNUTLS
    VIR_FREE(x509dname);
#endif
    return ret;

 error:
    virObjectUnref(ret);
    ret = NULL;
    goto cleanup;
}


virIdentityPtr virNetServerClientGetIdentity(virNetServerClientPtr client)
{
    virIdentityPtr ret = NULL;
    virObjectLock(client);
    if (!client->identity)
        client->identity = virNetServerClientCreateIdentity(client);
    if (client->identity)
        ret = virObjectRef(client->identity);
    virObjectUnlock(client);
    return ret;
}


int virNetServerClientGetSELinuxContext(virNetServerClientPtr client,
                                        char **context)
{
    int ret = 0;
    *context = NULL;
    virObjectLock(client);
    if (client->sock)
        ret = virNetSocketGetSELinuxContext(client->sock, context);
    virObjectUnlock(client);
    return ret;
}


bool virNetServerClientIsSecure(virNetServerClientPtr client)
{
    bool secure = false;
    virObjectLock(client);
#if WITH_GNUTLS
    if (client->tls)
        secure = true;
#endif
#if WITH_SASL
    if (client->sasl)
        secure = true;
#endif
    if (client->sock && virNetSocketIsLocal(client->sock))
        secure = true;
    virObjectUnlock(client);
    return secure;
}


#if WITH_SASL
void virNetServerClientSetSASLSession(virNetServerClientPtr client,
                                      virNetSASLSessionPtr sasl)
{
    /* We don't set the sasl session on the socket here
     * because we need to send out the auth confirmation
     * in the clear. Only once we complete the next 'tx'
     * operation do we switch to SASL mode
     */
    virObjectLock(client);
    client->sasl = virObjectRef(sasl);
    virObjectUnlock(client);
}


virNetSASLSessionPtr virNetServerClientGetSASLSession(virNetServerClientPtr client)
{
    virNetSASLSessionPtr sasl;
    virObjectLock(client);
    sasl = client->sasl;
    virObjectUnlock(client);
    return sasl;
}
#endif


void *virNetServerClientGetPrivateData(virNetServerClientPtr client)
{
    void *data;
    virObjectLock(client);
    data = client->privateData;
    virObjectUnlock(client);
    return data;
}


void virNetServerClientSetCloseHook(virNetServerClientPtr client,
                                    virNetServerClientCloseFunc cf)
{
    virObjectLock(client);
    client->privateDataCloseFunc = cf;
    virObjectUnlock(client);
}


void virNetServerClientSetDispatcher(virNetServerClientPtr client,
                                     virNetServerClientDispatchFunc func,
                                     void *opaque)
{
    virObjectLock(client);
    client->dispatchFunc = func;
    client->dispatchOpaque = opaque;
    virObjectUnlock(client);
}


const char *virNetServerClientLocalAddrString(virNetServerClientPtr client)
{
    if (!client->sock)
        return NULL;
    return virNetSocketLocalAddrString(client->sock);
}


const char *virNetServerClientRemoteAddrString(virNetServerClientPtr client)
{
    if (!client->sock)
        return NULL;
    return virNetSocketRemoteAddrString(client->sock);
}


void virNetServerClientDispose(void *obj)
{
    virNetServerClientPtr client = obj;

    PROBE(RPC_SERVER_CLIENT_DISPOSE,
          "client=%p", client);

    virObjectUnref(client->identity);

    if (client->privateData &&
        client->privateDataFreeFunc)
        client->privateDataFreeFunc(client->privateData);

#if WITH_SASL
    virObjectUnref(client->sasl);
#endif
    if (client->sockTimer > 0)
        virEventRemoveTimeout(client->sockTimer);
#if WITH_GNUTLS
    virObjectUnref(client->tls);
    virObjectUnref(client->tlsCtxt);
#endif
    virObjectUnref(client->sock);
    virObjectUnlock(client);
}


/*
 *
 * We don't free stuff here, merely disconnect the client's
 * network socket & resources.
 *
 * Full free of the client is done later in a safe point
 * where it can be guaranteed it is no longer in use
 */
void virNetServerClientClose(virNetServerClientPtr client)
{
    virNetServerClientCloseFunc cf;
    virKeepAlivePtr ka;

    virObjectLock(client);
    VIR_DEBUG("client=%p", client);
    if (!client->sock) {
        virObjectUnlock(client);
        return;
    }

    if (client->keepalive) {
        virKeepAliveStop(client->keepalive);
        ka = client->keepalive;
        client->keepalive = NULL;
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

#if WITH_GNUTLS
    if (client->tls) {
        virObjectUnref(client->tls);
        client->tls = NULL;
    }
#endif
    client->wantClose = true;

    while (client->rx) {
        virNetMessagePtr msg
            = virNetMessageQueueServe(&client->rx);
        virNetMessageFree(msg);
    }
    while (client->tx) {
        virNetMessagePtr msg
            = virNetMessageQueueServe(&client->tx);
        virNetMessageFree(msg);
    }

    if (client->sock) {
        virObjectUnref(client->sock);
        client->sock = NULL;
    }

    virObjectUnlock(client);
}


bool virNetServerClientIsClosed(virNetServerClientPtr client)
{
    bool closed;
    virObjectLock(client);
    closed = client->sock == NULL ? true : false;
    virObjectUnlock(client);
    return closed;
}

void virNetServerClientDelayedClose(virNetServerClientPtr client)
{
    virObjectLock(client);
    client->delayedClose = true;
    virObjectUnlock(client);
}

void virNetServerClientImmediateClose(virNetServerClientPtr client)
{
    virObjectLock(client);
    client->wantClose = true;
    virObjectUnlock(client);
}

bool virNetServerClientWantClose(virNetServerClientPtr client)
{
    bool wantClose;
    virObjectLock(client);
    wantClose = client->wantClose;
    virObjectUnlock(client);
    return wantClose;
}


int virNetServerClientInit(virNetServerClientPtr client)
{
    virObjectLock(client);

#if WITH_GNUTLS
    if (!client->tlsCtxt) {
#endif
        /* Plain socket, so prepare to read first message */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
#if WITH_GNUTLS
    } else {
        int ret;

        if (!(client->tls = virNetTLSSessionNew(client->tlsCtxt,
                                                NULL)))
            goto error;

        virNetSocketSetTLSSession(client->sock,
                                  client->tls);

        /* Begin the TLS handshake. */
        ret = virNetTLSSessionHandshake(client->tls);
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
    }
#endif

    virObjectUnlock(client);
    return 0;

 error:
    client->wantClose = true;
    virObjectUnlock(client);
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
static ssize_t virNetServerClientRead(virNetServerClientPtr client)
{
    ssize_t ret;

    if (client->rx->bufferLength <= client->rx->bufferOffset) {
        virReportError(VIR_ERR_RPC,
                       _("unexpected zero/negative length request %lld"),
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
 * Read data until we get a complete message to process
 */
static void virNetServerClientDispatchRead(virNetServerClientPtr client)
{
 readmore:
    if (client->rx->nfds == 0) {
        if (virNetServerClientRead(client) < 0) {
            client->wantClose = true;
            return; /* Error */
        }
    }

    if (client->rx->bufferOffset < client->rx->bufferLength)
        return; /* Still not read enough */

    /* Either done with length word header */
    if (client->rx->bufferLength == VIR_NET_MESSAGE_LEN_MAX) {
        if (virNetMessageDecodeLength(client->rx) < 0) {
            client->wantClose = true;
            return;
        }

        virNetServerClientUpdateEvent(client);

        /* Try and read payload immediately instead of going back
           into poll() because chances are the data is already
           waiting for us */
        goto readmore;
    } else {
        /* Grab the completed message */
        virNetMessagePtr msg = client->rx;
        virNetMessagePtr response = NULL;
        virNetServerClientFilterPtr filter;
        size_t i;

        /* Decode the header so we can use it for routing decisions */
        if (virNetMessageDecodeHeader(msg) < 0) {
            virNetMessageQueueServe(&client->rx);
            virNetMessageFree(msg);
            client->wantClose = true;
            return;
        }

        /* Now figure out if we need to read more data to get some
         * file descriptors */
        if (msg->header.type == VIR_NET_CALL_WITH_FDS &&
            virNetMessageDecodeNumFDs(msg) < 0) {
            virNetMessageQueueServe(&client->rx);
            virNetMessageFree(msg);
            client->wantClose = true;
            return; /* Error */
        }

        /* Try getting the file descriptors (may fail if blocking) */
        for (i = msg->donefds; i < msg->nfds; i++) {
            int rv;
            if ((rv = virNetSocketRecvFD(client->sock, &(msg->fds[i]))) < 0) {
                virNetMessageQueueServe(&client->rx);
                virNetMessageFree(msg);
                client->wantClose = true;
                return;
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
            return;
        }

        /* Definitely finished reading, so remove from queue */
        virNetMessageQueueServe(&client->rx);
        PROBE(RPC_SERVER_CLIENT_MSG_RX,
              "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
              client, msg->bufferLength,
              msg->header.prog, msg->header.vers, msg->header.proc,
              msg->header.type, msg->header.status, msg->header.serial);

        if (virKeepAliveCheckMessage(client->keepalive, msg, &response)) {
            virNetMessageFree(msg);
            client->nrequests--;
            msg = NULL;

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
                    virNetMessageFree(msg);
                    msg = NULL;
                    if (ret < 0)
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

        /* Send off to for normal dispatch to workers */
        if (msg) {
            virObjectRef(client);
            if (!client->dispatchFunc ||
                client->dispatchFunc(client, msg, client->dispatchOpaque) < 0) {
                virNetMessageFree(msg);
                client->wantClose = true;
                virObjectUnref(client);
                return;
            }
        }

        /* Possibly need to create another receive buffer */
        if (client->nrequests < client->nrequests_max) {
            if (!(client->rx = virNetMessageNew(true))) {
                client->wantClose = true;
            } else {
                client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
                if (VIR_ALLOC_N(client->rx->buffer,
                                client->rx->bufferLength) < 0) {
                    client->wantClose = true;
                } else {
                    client->nrequests++;
                }
            }
        }
        virNetServerClientUpdateEvent(client);
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
static ssize_t virNetServerClientWrite(virNetServerClientPtr client)
{
    ssize_t ret;

    if (client->tx->bufferLength < client->tx->bufferOffset) {
        virReportError(VIR_ERR_RPC,
                       _("unexpected zero/negative length request %lld"),
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
virNetServerClientDispatchWrite(virNetServerClientPtr client)
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
            virNetMessagePtr msg;
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
                virObjectUnref(client->sasl);
                client->sasl = NULL;
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
                    if (VIR_ALLOC_N(msg->buffer, msg->bufferLength) < 0) {
                        virNetMessageFree(msg);
                        return;
                    }
                    client->rx = msg;
                    msg = NULL;
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


#if WITH_GNUTLS
static void
virNetServerClientDispatchHandshake(virNetServerClientPtr client)
{
    int ret;
    /* Continue the handshake. */
    ret = virNetTLSSessionHandshake(client->tls);
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
#endif

static void
virNetServerClientDispatchEvent(virNetSocketPtr sock, int events, void *opaque)
{
    virNetServerClientPtr client = opaque;

    virObjectLock(client);

    if (client->sock != sock) {
        virNetSocketRemoveIOCallback(sock);
        virObjectUnlock(client);
        return;
    }

    if (events & (VIR_EVENT_HANDLE_WRITABLE |
                  VIR_EVENT_HANDLE_READABLE)) {
#if WITH_GNUTLS
        if (client->tls &&
            virNetTLSSessionGetHandshakeStatus(client->tls) !=
            VIR_NET_TLS_HANDSHAKE_COMPLETE) {
            virNetServerClientDispatchHandshake(client);
        } else {
#endif
            if (events & VIR_EVENT_HANDLE_WRITABLE)
                virNetServerClientDispatchWrite(client);
            if (events & VIR_EVENT_HANDLE_READABLE &&
                client->rx)
                virNetServerClientDispatchRead(client);
#if WITH_GNUTLS
        }
#endif
    }

    /* NB, will get HANGUP + READABLE at same time upon
     * disconnect */
    if (events & (VIR_EVENT_HANDLE_ERROR |
                  VIR_EVENT_HANDLE_HANGUP))
        client->wantClose = true;

    virObjectUnlock(client);
}


static int
virNetServerClientSendMessageLocked(virNetServerClientPtr client,
                                    virNetMessagePtr msg)
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

int virNetServerClientSendMessage(virNetServerClientPtr client,
                                  virNetMessagePtr msg)
{
    int ret;

    virObjectLock(client);
    ret = virNetServerClientSendMessageLocked(client, msg);
    virObjectUnlock(client);

    return ret;
}


bool virNetServerClientNeedAuth(virNetServerClientPtr client)
{
    bool need = false;
    virObjectLock(client);
    if (client->auth)
        need = true;
    virObjectUnlock(client);
    return need;
}


static void
virNetServerClientKeepAliveDeadCB(void *opaque)
{
    virNetServerClientImmediateClose(opaque);
}

static int
virNetServerClientKeepAliveSendCB(void *opaque,
                                  virNetMessagePtr msg)
{
    return virNetServerClientSendMessage(opaque, msg);
}


int
virNetServerClientInitKeepAlive(virNetServerClientPtr client,
                                int interval,
                                unsigned int count)
{
    virKeepAlivePtr ka;
    int ret = -1;

    virObjectLock(client);

    if (!(ka = virKeepAliveNew(interval, count, client,
                               virNetServerClientKeepAliveSendCB,
                               virNetServerClientKeepAliveDeadCB,
                               virObjectFreeCallback)))
        goto cleanup;
    /* keepalive object has a reference to client */
    virObjectRef(client);

    client->keepalive = ka;

 cleanup:
    virObjectUnlock(client);

    return ret;
}

int
virNetServerClientStartKeepAlive(virNetServerClientPtr client)
{
    int ret = -1;

    virObjectLock(client);

    /* The connection might have been closed before we got here and thus the
     * keepalive object could have been removed too.
     */
    if (!client->keepalive) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("connection not open"));
        goto cleanup;
    }

    ret = virKeepAliveStart(client->keepalive, 0, 0);

 cleanup:
    virObjectUnlock(client);
    return ret;
}
