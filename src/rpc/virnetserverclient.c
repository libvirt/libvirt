/*
 * virnetserverclient.c: generic network RPC server client
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#include <config.h>

#if HAVE_SASL
# include <sasl/sasl.h>
#endif

#include "virnetserverclient.h"

#include "logging.h"
#include "virterror_internal.h"
#include "memory.h"
#include "threads.h"
#include "virkeepalive.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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
    int refs;
    bool wantClose;
    bool delayedClose;
    virMutex lock;
    virNetSocketPtr sock;
    int auth;
    bool readonly;
    char *identity;
    virNetTLSContextPtr tlsCtxt;
    virNetTLSSessionPtr tls;
#if HAVE_SASL
    virNetSASLSessionPtr sasl;
#endif
    int sockTimer; /* Timer to be fired upon cached data,
                    * so we jump out from poll() immediately */

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
    virNetServerClientFreeFunc privateDataFreeFunc;
    virNetServerClientCloseFunc privateDataCloseFunc;

    virKeepAlivePtr keepalive;
    int keepaliveFilter;
};


static void virNetServerClientDispatchEvent(virNetSocketPtr sock, int events, void *opaque);
static void virNetServerClientUpdateEvent(virNetServerClientPtr client);
static void virNetServerClientDispatchRead(virNetServerClientPtr client);

static void virNetServerClientLock(virNetServerClientPtr client)
{
    virMutexLock(&client->lock);
}

static void virNetServerClientUnlock(virNetServerClientPtr client)
{
    virMutexUnlock(&client->lock);
}


/*
 * @client: a locked client object
 */
static int
virNetServerClientCalculateHandleMode(virNetServerClientPtr client) {
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
        /* If there is a message on the rx queue then
         * we're wanting more input */
        if (client->rx)
            mode |= VIR_EVENT_HANDLE_READABLE;

        /* If there are one or more messages to send back to client,
           then monitor for writability on socket */
        if (client->tx)
            mode |= VIR_EVENT_HANDLE_WRITABLE;
    }
    VIR_DEBUG("mode=%o", mode);
    return mode;
}

static void virNetServerClientEventFree(void *opaque)
{
    virNetServerClientPtr client = opaque;

    virNetServerClientFree(client);
}

/*
 * @server: a locked or unlocked server object
 * @client: a locked client object
 */
static int virNetServerClientRegisterEvent(virNetServerClientPtr client)
{
    int mode = virNetServerClientCalculateHandleMode(client);

    client->refs++;
    VIR_DEBUG("Registering client event callback %d", mode);
    if (!client->sock ||
        virNetSocketAddIOCallback(client->sock,
                                  mode,
                                  virNetServerClientDispatchEvent,
                                  client,
                                  virNetServerClientEventFree) < 0) {
        client->refs--;
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


static int
virNetServerClientAddFilterLocked(virNetServerClientPtr client,
                                  virNetServerClientFilterFunc func,
                                  void *opaque)
{
    virNetServerClientFilterPtr filter;
    virNetServerClientFilterPtr *place;
    int ret = -1;

    if (VIR_ALLOC(filter) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    filter->id = client->nextFilterID++;
    filter->func = func;
    filter->opaque = opaque;

    place = &client->filters;
    while (*place)
        place = &(*place)->next;
    *place = filter;

    ret = filter->id;

cleanup:
    return ret;
}

int virNetServerClientAddFilter(virNetServerClientPtr client,
                                virNetServerClientFilterFunc func,
                                void *opaque)
{
    int ret;

    virNetServerClientLock(client);
    ret = virNetServerClientAddFilterLocked(client, func, opaque);
    virNetServerClientUnlock(client);
    return ret;
}

static void
virNetServerClientRemoveFilterLocked(virNetServerClientPtr client,
                                     int filterID)
{
    virNetServerClientFilterPtr tmp, prev;

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

void virNetServerClientRemoveFilter(virNetServerClientPtr client,
                                    int filterID)
{
    virNetServerClientLock(client);
    virNetServerClientRemoveFilterLocked(client, filterID);
    virNetServerClientUnlock(client);
}


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
    confirm->bufferOffset = 0;
    confirm->buffer[0] = '\1';

    client->tx = confirm;

    return 0;
}

static void virNetServerClientSockTimerFunc(int timer,
                                            void *opaque)
{
    virNetServerClientPtr client = opaque;
    virNetServerClientLock(client);
    virEventUpdateTimeout(timer, -1);
    /* Although client->rx != NULL when this timer is enabled, it might have
     * changed since the client was unlocked in the meantime. */
    if (client->rx)
        virNetServerClientDispatchRead(client);
    virNetServerClientUnlock(client);
}


virNetServerClientPtr virNetServerClientNew(virNetSocketPtr sock,
                                            int auth,
                                            bool readonly,
                                            size_t nrequests_max,
                                            virNetTLSContextPtr tls)
{
    virNetServerClientPtr client;

    VIR_DEBUG("sock=%p auth=%d tls=%p", sock, auth, tls);

    if (VIR_ALLOC(client) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&client->lock) < 0)
        goto error;

    client->refs = 1;
    client->sock = sock;
    client->auth = auth;
    client->readonly = readonly;
    client->tlsCtxt = tls;
    client->nrequests_max = nrequests_max;
    client->keepaliveFilter = -1;

    client->sockTimer = virEventAddTimeout(-1, virNetServerClientSockTimerFunc,
                                           client, NULL);
    if (client->sockTimer < 0)
        goto error;

    if (tls)
        virNetTLSContextRef(tls);

    /* Prepare one for packet receive */
    if (!(client->rx = virNetMessageNew(true)))
        goto error;
    client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
    client->nrequests = 1;

    PROBE(RPC_SERVER_CLIENT_NEW,
          "client=%p refs=%d sock=%p",
          client, client->refs, client->sock);

    return client;

error:
    /* XXX ref counting is better than this */
    client->sock = NULL; /* Caller owns 'sock' upon failure */
    virNetServerClientFree(client);
    return NULL;
}

void virNetServerClientRef(virNetServerClientPtr client)
{
    virNetServerClientLock(client);
    client->refs++;
    PROBE(RPC_SERVER_CLIENT_REF,
          "client=%p refs=%d",
          client, client->refs);
    virNetServerClientUnlock(client);
}


int virNetServerClientGetAuth(virNetServerClientPtr client)
{
    int auth;
    virNetServerClientLock(client);
    auth = client->auth;
    virNetServerClientUnlock(client);
    return auth;
}

bool virNetServerClientGetReadonly(virNetServerClientPtr client)
{
    bool readonly;
    virNetServerClientLock(client);
    readonly = client->readonly;
    virNetServerClientUnlock(client);
    return readonly;
}


bool virNetServerClientHasTLSSession(virNetServerClientPtr client)
{
    bool has;
    virNetServerClientLock(client);
    has = client->tls ? true : false;
    virNetServerClientUnlock(client);
    return has;
}

int virNetServerClientGetTLSKeySize(virNetServerClientPtr client)
{
    int size = 0;
    virNetServerClientLock(client);
    if (client->tls)
        size = virNetTLSSessionGetKeySize(client->tls);
    virNetServerClientUnlock(client);
    return size;
}

int virNetServerClientGetFD(virNetServerClientPtr client)
{
    int fd = -1;
    virNetServerClientLock(client);
    if (client->sock)
        fd = virNetSocketGetFD(client->sock);
    virNetServerClientUnlock(client);
    return fd;
}

int virNetServerClientGetUNIXIdentity(virNetServerClientPtr client,
                                      uid_t *uid, gid_t *gid, pid_t *pid)
{
    int ret = -1;
    virNetServerClientLock(client);
    if (client->sock)
        ret = virNetSocketGetUNIXIdentity(client->sock, uid, gid, pid);
    virNetServerClientUnlock(client);
    return ret;
}

bool virNetServerClientIsSecure(virNetServerClientPtr client)
{
    bool secure = false;
    virNetServerClientLock(client);
    if (client->tls)
        secure = true;
#if HAVE_SASL
    if (client->sasl)
        secure = true;
#endif
    if (client->sock && virNetSocketIsLocal(client->sock))
        secure = true;
    virNetServerClientUnlock(client);
    return secure;
}


#if HAVE_SASL
void virNetServerClientSetSASLSession(virNetServerClientPtr client,
                                      virNetSASLSessionPtr sasl)
{
    /* We don't set the sasl session on the socket here
     * because we need to send out the auth confirmation
     * in the clear. Only once we complete the next 'tx'
     * operation do we switch to SASL mode
     */
    virNetServerClientLock(client);
    client->sasl = sasl;
    virNetSASLSessionRef(sasl);
    virNetServerClientUnlock(client);
}
#endif


int virNetServerClientSetIdentity(virNetServerClientPtr client,
                                  const char *identity)
{
    int ret = -1;
    virNetServerClientLock(client);
    if (!(client->identity = strdup(identity))) {
        virReportOOMError();
        goto error;
    }
    ret = 0;

error:
    virNetServerClientUnlock(client);
    return ret;
}

const char *virNetServerClientGetIdentity(virNetServerClientPtr client)
{
    const char *identity;
    virNetServerClientLock(client);
    identity = client->identity;
    virNetServerClientLock(client);
    return identity;
}

void virNetServerClientSetPrivateData(virNetServerClientPtr client,
                                      void *opaque,
                                      virNetServerClientFreeFunc ff)
{
    virNetServerClientLock(client);

    if (client->privateData &&
        client->privateDataFreeFunc)
        client->privateDataFreeFunc(client->privateData);

    client->privateData = opaque;
    client->privateDataFreeFunc = ff;

    virNetServerClientUnlock(client);
}


void *virNetServerClientGetPrivateData(virNetServerClientPtr client)
{
    void *data;
    virNetServerClientLock(client);
    data = client->privateData;
    virNetServerClientUnlock(client);
    return data;
}


void virNetServerClientSetCloseHook(virNetServerClientPtr client,
                                    virNetServerClientCloseFunc cf)
{
    virNetServerClientLock(client);
    client->privateDataCloseFunc = cf;
    virNetServerClientUnlock(client);
}


void virNetServerClientSetDispatcher(virNetServerClientPtr client,
                                     virNetServerClientDispatchFunc func,
                                     void *opaque)
{
    virNetServerClientLock(client);
    client->dispatchFunc = func;
    client->dispatchOpaque = opaque;
    virNetServerClientUnlock(client);
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


void virNetServerClientFree(virNetServerClientPtr client)
{
    if (!client)
        return;

    virNetServerClientLock(client);
    PROBE(RPC_SERVER_CLIENT_FREE,
          "client=%p refs=%d",
          client, client->refs);

    client->refs--;
    if (client->refs > 0) {
        virNetServerClientUnlock(client);
        return;
    }

    if (client->privateData &&
        client->privateDataFreeFunc)
        client->privateDataFreeFunc(client->privateData);

    VIR_FREE(client->identity);
#if HAVE_SASL
    virNetSASLSessionFree(client->sasl);
#endif
    if (client->sockTimer > 0)
        virEventRemoveTimeout(client->sockTimer);
    virNetTLSSessionFree(client->tls);
    virNetTLSContextFree(client->tlsCtxt);
    virNetSocketFree(client->sock);
    virNetServerClientUnlock(client);
    virMutexDestroy(&client->lock);
    VIR_FREE(client);
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

    virNetServerClientLock(client);
    VIR_DEBUG("client=%p refs=%d", client, client->refs);
    if (!client->sock) {
        virNetServerClientUnlock(client);
        return;
    }

    if (client->keepaliveFilter >= 0)
        virNetServerClientRemoveFilterLocked(client, client->keepaliveFilter);

    if (client->keepalive) {
        virKeepAliveStop(client->keepalive);
        ka = client->keepalive;
        client->keepalive = NULL;
        client->refs++;
        virNetServerClientUnlock(client);
        virKeepAliveFree(ka);
        virNetServerClientLock(client);
        client->refs--;
    }

    if (client->privateDataCloseFunc) {
        cf = client->privateDataCloseFunc;
        client->refs++;
        virNetServerClientUnlock(client);
        (cf)(client);
        virNetServerClientLock(client);
        client->refs--;
    }

    /* Do now, even though we don't close the socket
     * until end, to ensure we don't get invoked
     * again due to tls shutdown */
    if (client->sock)
        virNetSocketRemoveIOCallback(client->sock);

    if (client->tls) {
        virNetTLSSessionFree(client->tls);
        client->tls = NULL;
    }
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
        virNetSocketFree(client->sock);
        client->sock = NULL;
    }

    virNetServerClientUnlock(client);
}


bool virNetServerClientIsClosed(virNetServerClientPtr client)
{
    bool closed;
    virNetServerClientLock(client);
    closed = client->sock == NULL ? true : false;
    virNetServerClientUnlock(client);
    return closed;
}

void virNetServerClientDelayedClose(virNetServerClientPtr client)
{
    virNetServerClientLock(client);
    client->delayedClose = true;
    virNetServerClientUnlock(client);
}

void virNetServerClientImmediateClose(virNetServerClientPtr client)
{
    virNetServerClientLock(client);
    client->wantClose = true;
    virNetServerClientUnlock(client);
}

bool virNetServerClientWantClose(virNetServerClientPtr client)
{
    bool wantClose;
    virNetServerClientLock(client);
    wantClose = client->wantClose;
    virNetServerClientUnlock(client);
    return wantClose;
}


int virNetServerClientInit(virNetServerClientPtr client)
{
    virNetServerClientLock(client);

    if (!client->tlsCtxt) {
        /* Plain socket, so prepare to read first message */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
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

    virNetServerClientUnlock(client);
    return 0;

error:
    client->wantClose = true;
    virNetServerClientUnlock(client);
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
        virNetError(VIR_ERR_RPC,
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
        virNetServerClientFilterPtr filter;
        size_t i;

        /* Decode the header so we can use it for routing decisions */
        if (virNetMessageDecodeHeader(msg) < 0) {
            virNetMessageFree(msg);
            client->wantClose = true;
            return;
        }

        /* Now figure out if we need to read more data to get some
         * file descriptors */
        if (msg->header.type == VIR_NET_CALL_WITH_FDS &&
            virNetMessageDecodeNumFDs(msg) < 0) {
            virNetMessageFree(msg);
            client->wantClose = true;
            return; /* Error */
        }

        /* Try getting the file descriptors (may fail if blocking) */
        for (i = msg->donefds ; i < msg->nfds ; i++) {
            int rv;
            if ((rv = virNetSocketRecvFD(client->sock, &(msg->fds[i]))) < 0) {
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

        /* Maybe send off for queue against a filter */
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

        /* Send off to for normal dispatch to workers */
        if (msg) {
            client->refs++;
            if (!client->dispatchFunc ||
                client->dispatchFunc(client, msg, client->dispatchOpaque) < 0) {
                virNetMessageFree(msg);
                client->wantClose = true;
                client->refs--;
                return;
            }
        }

        /* Possibly need to create another receive buffer */
        if (client->nrequests < client->nrequests_max) {
            if (!(client->rx = virNetMessageNew(true))) {
                client->wantClose = true;
            } else {
                client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
                client->nrequests++;
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
        virNetError(VIR_ERR_RPC,
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

            for (i = client->tx->donefds ; i < client->tx->nfds ; i++) {
                int rv;
                if ((rv = virNetSocketSendFD(client->sock, client->tx->fds[i])) < 0) {
                    client->wantClose = true;
                    return;
                }
                if (rv == 0) /* Blocking */
                    return;
                client->tx->donefds++;
            }

#if HAVE_SASL
            /* Completed this 'tx' operation, so now read for all
             * future rx/tx to be under a SASL SSF layer
             */
            if (client->sasl) {
                virNetSocketSetSASLSession(client->sock, client->sasl);
                virNetSASLSessionFree(client->sasl);
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
                    client->rx = msg;
                    client->rx->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
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
        virNetServerClientUpdateEvent (client);
    } else {
        /* Fatal error in handshake */
        client->wantClose = true;
    }
}

static void
virNetServerClientDispatchEvent(virNetSocketPtr sock, int events, void *opaque)
{
    virNetServerClientPtr client = opaque;

    virNetServerClientLock(client);

    if (client->sock != sock) {
        virNetSocketRemoveIOCallback(sock);
        virNetServerClientUnlock(client);
        return;
    }

    if (events & (VIR_EVENT_HANDLE_WRITABLE |
                  VIR_EVENT_HANDLE_READABLE)) {
        if (client->tls &&
            virNetTLSSessionGetHandshakeStatus(client->tls) !=
            VIR_NET_TLS_HANDSHAKE_COMPLETE) {
            virNetServerClientDispatchHandshake(client);
        } else {
            if (events & VIR_EVENT_HANDLE_WRITABLE)
                virNetServerClientDispatchWrite(client);
            if (events & VIR_EVENT_HANDLE_READABLE &&
                client->rx)
                virNetServerClientDispatchRead(client);
        }
    }

    /* NB, will get HANGUP + READABLE at same time upon
     * disconnect */
    if (events & (VIR_EVENT_HANDLE_ERROR |
                  VIR_EVENT_HANDLE_HANGUP))
        client->wantClose = true;

    virNetServerClientUnlock(client);
}


int virNetServerClientSendMessage(virNetServerClientPtr client,
                                  virNetMessagePtr msg)
{
    int ret = -1;
    VIR_DEBUG("msg=%p proc=%d len=%zu offset=%zu",
              msg, msg->header.proc,
              msg->bufferLength, msg->bufferOffset);

    virNetServerClientLock(client);

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

    virNetServerClientUnlock(client);

    return ret;
}


bool virNetServerClientNeedAuth(virNetServerClientPtr client)
{
    bool need = false;
    virNetServerClientLock(client);
    if (client->auth && !client->identity)
        need = true;
    virNetServerClientUnlock(client);
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

static void
virNetServerClientFreeCB(void *opaque)
{
    virNetServerClientFree(opaque);
}

static int
virNetServerClientKeepAliveFilter(virNetServerClientPtr client,
                                  virNetMessagePtr msg,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    if (virKeepAliveCheckMessage(client->keepalive, msg)) {
        virNetMessageFree(msg);
        client->nrequests--;
        return 1;
    }

    return 0;
}

int
virNetServerClientInitKeepAlive(virNetServerClientPtr client,
                                int interval,
                                unsigned int count)
{
    virKeepAlivePtr ka;
    int ret = -1;

    virNetServerClientLock(client);

    if (!(ka = virKeepAliveNew(interval, count, client,
                               virNetServerClientKeepAliveSendCB,
                               virNetServerClientKeepAliveDeadCB,
                               virNetServerClientFreeCB)))
        goto cleanup;
    /* keepalive object has a reference to client */
    client->refs++;

    client->keepaliveFilter =
        virNetServerClientAddFilterLocked(client,
                                          virNetServerClientKeepAliveFilter,
                                          NULL);
    if (client->keepaliveFilter < 0)
        goto cleanup;

    client->keepalive = ka;
    ka = NULL;

cleanup:
    virNetServerClientUnlock(client);
    if (ka)
        virKeepAliveStop(ka);
    virKeepAliveFree(ka);

    return ret;
}

int
virNetServerClientStartKeepAlive(virNetServerClientPtr client)
{
    int ret;
    virNetServerClientLock(client);
    ret = virKeepAliveStart(client->keepalive, 0, 0);
    virNetServerClientUnlock(client);
    return ret;
}
