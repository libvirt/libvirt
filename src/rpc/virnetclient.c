/*
 * virnetclient.c: generic network RPC client
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>

#include "virnetclient.h"
#include "virnetsocket.h"
#include "virkeepalive.h"
#include "memory.h"
#include "threads.h"
#include "virfile.h"
#include "logging.h"
#include "util.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

typedef struct _virNetClientCall virNetClientCall;
typedef virNetClientCall *virNetClientCallPtr;

enum {
    VIR_NET_CLIENT_MODE_WAIT_TX,
    VIR_NET_CLIENT_MODE_WAIT_RX,
    VIR_NET_CLIENT_MODE_COMPLETE,
};

struct _virNetClientCall {
    int mode;

    virNetMessagePtr msg;
    bool expectReply;
    bool nonBlock;
    bool haveThread;
    bool sentSomeData;

    virCond cond;

    virNetClientCallPtr next;
};


struct _virNetClient {
    int refs;

    virMutex lock;

    virNetSocketPtr sock;

    virNetTLSSessionPtr tls;
    char *hostname;

    virNetClientProgramPtr *programs;
    size_t nprograms;

    /* For incoming message packets */
    virNetMessage msg;

#if HAVE_SASL
    virNetSASLSessionPtr sasl;
#endif

    /* Self-pipe to wakeup threads waiting in poll() */
    int wakeupSendFD;
    int wakeupReadFD;

    /*
     * List of calls currently waiting for dispatch
     * The calls should all have threads waiting for
     * them, except possibly the first call in the list
     * which might be a partially sent non-blocking call.
     */
    virNetClientCallPtr waitDispatch;
    /* True if a thread holds the buck */
    bool haveTheBuck;

    size_t nstreams;
    virNetClientStreamPtr *streams;

    virKeepAlivePtr keepalive;
    bool wantClose;
};


static void virNetClientLock(virNetClientPtr client)
{
    virMutexLock(&client->lock);
}


static void virNetClientUnlock(virNetClientPtr client)
{
    virMutexUnlock(&client->lock);
}


static void virNetClientIncomingEvent(virNetSocketPtr sock,
                                      int events,
                                      void *opaque);

/* Append a call to the end of the list */
static void virNetClientCallQueue(virNetClientCallPtr *head,
                                  virNetClientCallPtr call)
{
    virNetClientCallPtr tmp = *head;
    while (tmp && tmp->next) {
        tmp = tmp->next;
    }
    if (tmp)
        tmp->next = call;
    else
        *head = call;
    call->next = NULL;
}

#if 0
/* Obtain a call from the head of the list */
static virNetClientCallPtr virNetClientCallServe(virNetClientCallPtr *head)
{
    virNetClientCallPtr tmp = *head;
    if (tmp)
        *head = tmp->next;
    else
        *head = NULL;
    tmp->next = NULL;
    return tmp;
}
#endif

/* Remove a call from anywhere in the list */
static void virNetClientCallRemove(virNetClientCallPtr *head,
                                   virNetClientCallPtr call)
{
    virNetClientCallPtr tmp = *head;
    virNetClientCallPtr prev = NULL;
    while (tmp) {
        if (tmp == call) {
            if (prev)
                prev->next = tmp->next;
            else
                *head = tmp->next;
            tmp->next = NULL;
            return;
        }
        prev = tmp;
        tmp = tmp->next;
    }
}

/* Predicate returns true if matches */
typedef bool (*virNetClientCallPredicate)(virNetClientCallPtr call, void *opaque);

/* Remove a list of calls from the list based on a predicate */
static void virNetClientCallRemovePredicate(virNetClientCallPtr *head,
                                            virNetClientCallPredicate pred,
                                            void *opaque)
{
    virNetClientCallPtr tmp = *head;
    virNetClientCallPtr prev = NULL;
    while (tmp) {
        virNetClientCallPtr next = tmp->next;
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
static bool virNetClientCallMatchPredicate(virNetClientCallPtr head,
                                           virNetClientCallPredicate pred,
                                           void *opaque)
{
    virNetClientCallPtr tmp = head;
    while (tmp) {
        if (pred(tmp, opaque)) {
            return true;
        }
        tmp = tmp->next;
    }
    return false;
}


static void virNetClientEventFree(void *opaque)
{
    virNetClientPtr client = opaque;

    virNetClientFree(client);
}

bool
virNetClientKeepAliveIsSupported(virNetClientPtr client)
{
    bool supported;

    virNetClientLock(client);
    supported = !!client->keepalive;
    virNetClientUnlock(client);

    return supported;
}

int
virNetClientKeepAliveStart(virNetClientPtr client,
                           int interval,
                           unsigned int count)
{
    int ret;

    virNetClientLock(client);
    ret = virKeepAliveStart(client->keepalive, interval, count);
    virNetClientUnlock(client);

    return ret;
}

static void
virNetClientKeepAliveDeadCB(void *opaque)
{
    virNetClientClose(opaque);
}

static int
virNetClientKeepAliveSendCB(void *opaque,
                            virNetMessagePtr msg)
{
    int ret;

    ret = virNetClientSendNonBlock(opaque, msg);
    if (ret != -1 && ret != 1)
        virNetMessageFree(msg);
    return ret;
}

static virNetClientPtr virNetClientNew(virNetSocketPtr sock,
                                       const char *hostname)
{
    virNetClientPtr client = NULL;
    int wakeupFD[2] = { -1, -1 };
    virKeepAlivePtr ka = NULL;

    if (pipe2(wakeupFD, O_CLOEXEC) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to make pipe"));
        goto error;
    }

    if (VIR_ALLOC(client) < 0)
        goto no_memory;

    client->refs = 1;

    if (virMutexInit(&client->lock) < 0)
        goto error;

    client->sock = sock;
    client->wakeupReadFD = wakeupFD[0];
    client->wakeupSendFD = wakeupFD[1];
    wakeupFD[0] = wakeupFD[1] = -1;

    if (hostname &&
        !(client->hostname = strdup(hostname)))
        goto no_memory;

    /* Set up a callback to listen on the socket data */
    client->refs++;
    if (virNetSocketAddIOCallback(client->sock,
                                  VIR_EVENT_HANDLE_READABLE,
                                  virNetClientIncomingEvent,
                                  client,
                                  virNetClientEventFree) < 0) {
        client->refs--;
        VIR_DEBUG("Failed to add event watch, disabling events and support for"
                  " keepalive messages");
    } else {
        /* Keepalive protocol consists of async messages so it can only be used
         * if the client supports them */
        if (!(ka = virKeepAliveNew(-1, 0, client,
                                   virNetClientKeepAliveSendCB,
                                   virNetClientKeepAliveDeadCB,
                                   virNetClientEventFree)))
            goto error;
        /* keepalive object has a reference to client */
        client->refs++;
    }

    client->keepalive = ka;
    PROBE(RPC_CLIENT_NEW,
          "client=%p refs=%d sock=%p",
          client, client->refs, client->sock);
    return client;

no_memory:
    virReportOOMError();
error:
    VIR_FORCE_CLOSE(wakeupFD[0]);
    VIR_FORCE_CLOSE(wakeupFD[1]);
    if (ka) {
        virKeepAliveStop(ka);
        virKeepAliveFree(ka);
    }
    virNetClientFree(client);
    return NULL;
}


virNetClientPtr virNetClientNewUNIX(const char *path,
                                    bool spawnDaemon,
                                    const char *binary)
{
    virNetSocketPtr sock;

    if (virNetSocketNewConnectUNIX(path, spawnDaemon, binary, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}


virNetClientPtr virNetClientNewTCP(const char *nodename,
                                   const char *service)
{
    virNetSocketPtr sock;

    if (virNetSocketNewConnectTCP(nodename, service, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, nodename);
}

virNetClientPtr virNetClientNewSSH(const char *nodename,
                                   const char *service,
                                   const char *binary,
                                   const char *username,
                                   bool noTTY,
                                   bool noVerify,
                                   const char *netcat,
                                   const char *keyfile,
                                   const char *path)
{
    virNetSocketPtr sock;

    if (virNetSocketNewConnectSSH(nodename, service, binary, username, noTTY,
                                  noVerify, netcat, keyfile, path, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}

virNetClientPtr virNetClientNewExternal(const char **cmdargv)
{
    virNetSocketPtr sock;

    if (virNetSocketNewConnectExternal(cmdargv, &sock) < 0)
        return NULL;

    return virNetClientNew(sock, NULL);
}


void virNetClientRef(virNetClientPtr client)
{
    virNetClientLock(client);
    client->refs++;
    PROBE(RPC_CLIENT_REF,
          "client=%p refs=%d",
          client, client->refs);
    virNetClientUnlock(client);
}


int virNetClientGetFD(virNetClientPtr client)
{
    int fd;
    virNetClientLock(client);
    fd = virNetSocketGetFD(client->sock);
    virNetClientUnlock(client);
    return fd;
}


int virNetClientDupFD(virNetClientPtr client, bool cloexec)
{
    int fd;
    virNetClientLock(client);
    fd = virNetSocketDupFD(client->sock, cloexec);
    virNetClientUnlock(client);
    return fd;
}


bool virNetClientHasPassFD(virNetClientPtr client)
{
    bool hasPassFD;
    virNetClientLock(client);
    hasPassFD = virNetSocketHasPassFD(client->sock);
    virNetClientUnlock(client);
    return hasPassFD;
}


void virNetClientFree(virNetClientPtr client)
{
    int i;

    if (!client)
        return;

    virNetClientLock(client);
    PROBE(RPC_CLIENT_FREE,
          "client=%p refs=%d",
          client, client->refs);
    client->refs--;
    if (client->refs > 0) {
        virNetClientUnlock(client);
        return;
    }

    for (i = 0 ; i < client->nprograms ; i++)
        virNetClientProgramFree(client->programs[i]);
    VIR_FREE(client->programs);

    VIR_FORCE_CLOSE(client->wakeupSendFD);
    VIR_FORCE_CLOSE(client->wakeupReadFD);

    VIR_FREE(client->hostname);

    if (client->sock)
        virNetSocketRemoveIOCallback(client->sock);
    virNetSocketFree(client->sock);
    virNetTLSSessionFree(client->tls);
#if HAVE_SASL
    virNetSASLSessionFree(client->sasl);
#endif
    virNetClientUnlock(client);
    virMutexDestroy(&client->lock);

    VIR_FREE(client);
}


static void
virNetClientCloseLocked(virNetClientPtr client)
{
    virKeepAlivePtr ka;

    VIR_DEBUG("client=%p, sock=%p", client, client->sock);

    if (!client->sock)
        return;

    virNetSocketRemoveIOCallback(client->sock);
    virNetSocketFree(client->sock);
    client->sock = NULL;
    virNetTLSSessionFree(client->tls);
    client->tls = NULL;
#if HAVE_SASL
    virNetSASLSessionFree(client->sasl);
    client->sasl = NULL;
#endif
    ka = client->keepalive;
    client->keepalive = NULL;
    client->wantClose = false;

    if (ka) {
        client->refs++;
        virNetClientUnlock(client);

        virKeepAliveStop(ka);
        virKeepAliveFree(ka);

        virNetClientLock(client);
        client->refs--;
    }
}

void virNetClientClose(virNetClientPtr client)
{
    VIR_DEBUG("client=%p", client);

    if (!client)
        return;

    virNetClientLock(client);

    /* If there is a thread polling for data on the socket, set wantClose flag
     * and wake the thread up or just immediately close the socket when no-one
     * is polling on it.
     */
    if (client->waitDispatch) {
        char ignore = 1;
        size_t len = sizeof(ignore);

        client->wantClose = true;
        if (safewrite(client->wakeupSendFD, &ignore, len) != len)
            VIR_ERROR(_("failed to wake up polling thread"));
    } else {
        virNetClientCloseLocked(client);
    }

    virNetClientUnlock(client);
}


#if HAVE_SASL
void virNetClientSetSASLSession(virNetClientPtr client,
                                virNetSASLSessionPtr sasl)
{
    virNetClientLock(client);
    client->sasl = sasl;
    virNetSASLSessionRef(sasl);
    virNetSocketSetSASLSession(client->sock, client->sasl);
    virNetClientUnlock(client);
}
#endif


int virNetClientSetTLSSession(virNetClientPtr client,
                              virNetTLSContextPtr tls)
{
    int ret;
    char buf[1];
    int len;
    struct pollfd fds[1];
    sigset_t oldmask, blockedsigs;

    sigemptyset (&blockedsigs);
#ifdef SIGWINCH
    sigaddset (&blockedsigs, SIGWINCH);
#endif
#ifdef SIGCHLD
    sigaddset (&blockedsigs, SIGCHLD);
#endif
    sigaddset (&blockedsigs, SIGPIPE);

    virNetClientLock(client);

    if (!(client->tls = virNetTLSSessionNew(tls,
                                            client->hostname)))
        goto error;

    virNetSocketSetTLSSession(client->sock, client->tls);

    for (;;) {
        ret = virNetTLSSessionHandshake(client->tls);

        if (ret < 0)
            goto error;
        if (ret == 0)
            break;

        fds[0].fd = virNetSocketGetFD(client->sock);
        fds[0].revents = 0;
        if (virNetTLSSessionGetHandshakeStatus(client->tls) ==
            VIR_NET_TLS_HANDSHAKE_RECVING)
            fds[0].events = POLLIN;
        else
            fds[0].events = POLLOUT;

        /* Block SIGWINCH from interrupting poll in curses programs,
         * then restore the original signal mask again immediately
         * after the call (RHBZ#567931).  Same for SIGCHLD and SIGPIPE
         * at the suggestion of Paolo Bonzini and Daniel Berrange.
         */
        ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));

    repoll:
        ret = poll(fds, ARRAY_CARDINALITY(fds), -1);
        if (ret < 0 && errno == EAGAIN)
            goto repoll;

        ignore_value(pthread_sigmask(SIG_BLOCK, &oldmask, NULL));
    }

    ret = virNetTLSContextCheckCertificate(tls, client->tls);

    if (ret < 0)
        goto error;

    /* At this point, the server is verifying _our_ certificate, IP address,
     * etc.  If we make the grade, it will send us a '\1' byte.
     */

    fds[0].fd = virNetSocketGetFD(client->sock);
    fds[0].revents = 0;
    fds[0].events = POLLIN;

    /* Block SIGWINCH from interrupting poll in curses programs */
    ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));

    repoll2:
    ret = poll(fds, ARRAY_CARDINALITY(fds), -1);
    if (ret < 0 && errno == EAGAIN)
        goto repoll2;

    ignore_value(pthread_sigmask(SIG_BLOCK, &oldmask, NULL));

    len = virNetTLSSessionRead(client->tls, buf, 1);
    if (len < 0 && errno != ENOMSG) {
        virReportSystemError(errno, "%s",
                             _("Unable to read TLS confirmation"));
        goto error;
    }
    if (len != 1 || buf[0] != '\1') {
        virNetError(VIR_ERR_RPC, "%s",
                    _("server verification (of our certificate or IP "
                      "address) failed"));
        goto error;
    }

    virNetClientUnlock(client);
    return 0;

error:
    virNetTLSSessionFree(client->tls);
    client->tls = NULL;
    virNetClientUnlock(client);
    return -1;
}

bool virNetClientIsEncrypted(virNetClientPtr client)
{
    bool ret = false;
    virNetClientLock(client);
    if (client->tls)
        ret = true;
#if HAVE_SASL
    if (client->sasl)
        ret = true;
#endif
    virNetClientUnlock(client);
    return ret;
}


bool virNetClientIsOpen(virNetClientPtr client)
{
    bool ret;

    if (!client)
        return false;

    virNetClientLock(client);
    ret = client->sock && !client->wantClose;
    virNetClientUnlock(client);
    return ret;
}


int virNetClientAddProgram(virNetClientPtr client,
                           virNetClientProgramPtr prog)
{
    virNetClientLock(client);

    if (VIR_EXPAND_N(client->programs, client->nprograms, 1) < 0)
        goto no_memory;

    client->programs[client->nprograms-1] = prog;
    virNetClientProgramRef(prog);

    virNetClientUnlock(client);
    return 0;

no_memory:
    virReportOOMError();
    virNetClientUnlock(client);
    return -1;
}


int virNetClientAddStream(virNetClientPtr client,
                          virNetClientStreamPtr st)
{
    virNetClientLock(client);

    if (VIR_EXPAND_N(client->streams, client->nstreams, 1) < 0)
        goto no_memory;

    client->streams[client->nstreams-1] = st;
    virNetClientStreamRef(st);

    virNetClientUnlock(client);
    return 0;

no_memory:
    virReportOOMError();
    virNetClientUnlock(client);
    return -1;
}


void virNetClientRemoveStream(virNetClientPtr client,
                              virNetClientStreamPtr st)
{
    virNetClientLock(client);
    size_t i;
    for (i = 0 ; i < client->nstreams ; i++) {
        if (client->streams[i] == st)
            break;
    }
    if (i == client->nstreams)
        goto cleanup;

    if (client->nstreams > 1) {
        memmove(client->streams + i,
                client->streams + i + 1,
                sizeof(*client->streams) *
                (client->nstreams - (i + 1)));
        VIR_SHRINK_N(client->streams, client->nstreams, 1);
    } else {
        VIR_FREE(client->streams);
        client->nstreams = 0;
    }
    virNetClientStreamFree(st);

cleanup:
    virNetClientUnlock(client);
}


const char *virNetClientLocalAddrString(virNetClientPtr client)
{
    return virNetSocketLocalAddrString(client->sock);
}

const char *virNetClientRemoteAddrString(virNetClientPtr client)
{
    return virNetSocketRemoteAddrString(client->sock);
}

int virNetClientGetTLSKeySize(virNetClientPtr client)
{
    int ret = 0;
    virNetClientLock(client);
    if (client->tls)
        ret = virNetTLSSessionGetKeySize(client->tls);
    virNetClientUnlock(client);
    return ret;
}

static int
virNetClientCallDispatchReply(virNetClientPtr client)
{
    virNetClientCallPtr thecall;

    /* Ok, definitely got an RPC reply now find
       out which waiting call is associated with it */
    thecall = client->waitDispatch;
    while (thecall &&
           !(thecall->msg->header.prog == client->msg.header.prog &&
             thecall->msg->header.vers == client->msg.header.vers &&
             thecall->msg->header.serial == client->msg.header.serial))
        thecall = thecall->next;

    if (!thecall) {
        virNetError(VIR_ERR_RPC,
                    _("no call waiting for reply with prog %d vers %d serial %d"),
                    client->msg.header.prog, client->msg.header.vers, client->msg.header.serial);
        return -1;
    }

    memcpy(thecall->msg->buffer, client->msg.buffer, sizeof(client->msg.buffer));
    memcpy(&thecall->msg->header, &client->msg.header, sizeof(client->msg.header));
    thecall->msg->bufferLength = client->msg.bufferLength;
    thecall->msg->bufferOffset = client->msg.bufferOffset;

    thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;

    return 0;
}

static int virNetClientCallDispatchMessage(virNetClientPtr client)
{
    size_t i;
    virNetClientProgramPtr prog = NULL;

    for (i = 0 ; i < client->nprograms ; i++) {
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

static int virNetClientCallDispatchStream(virNetClientPtr client)
{
    size_t i;
    virNetClientStreamPtr st = NULL;
    virNetClientCallPtr thecall;

    /* First identify what stream this packet is directed at */
    for (i = 0 ; i < client->nstreams ; i++) {
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

    /* Finish/Abort are synchronous, so also see if there's an
     * (optional) call waiting for this stream packet */
    thecall = client->waitDispatch;
    while (thecall &&
           !(thecall->msg->header.prog == client->msg.header.prog &&
             thecall->msg->header.vers == client->msg.header.vers &&
             thecall->msg->header.serial == client->msg.header.serial))
        thecall = thecall->next;

    VIR_DEBUG("Found call %p", thecall);

    /* Status is either
     *   - REMOTE_OK - no payload for streams
     *   - REMOTE_ERROR - followed by a remote_error struct
     *   - REMOTE_CONTINUE - followed by a raw data packet
     */
    switch (client->msg.header.status) {
    case VIR_NET_CONTINUE: {
        if (virNetClientStreamQueuePacket(st, &client->msg) < 0)
            return -1;

        if (thecall && thecall->expectReply) {
            if (thecall->msg->header.status == VIR_NET_CONTINUE) {
                VIR_DEBUG("Got a synchronous confirm");
                thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;
            } else {
                VIR_DEBUG("Not completing call with status %d", thecall->msg->header.status);
            }
        }
        return 0;
    }

    case VIR_NET_OK:
        if (thecall && thecall->expectReply) {
            VIR_DEBUG("Got a synchronous confirm");
            thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;
        } else {
            VIR_DEBUG("Got unexpected async stream finish confirmation");
            return -1;
        }
        return 0;

    case VIR_NET_ERROR:
        /* No call, so queue the error against the stream */
        if (virNetClientStreamSetError(st, &client->msg) < 0)
            return -1;

        if (thecall && thecall->expectReply) {
            VIR_DEBUG("Got a synchronous error");
            /* Raise error now, so that this call will see it immediately */
            if (!virNetClientStreamRaiseError(st))
                VIR_DEBUG("unable to raise synchronous error");
            thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;
        }
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
virNetClientCallDispatch(virNetClientPtr client)
{
    PROBE(RPC_CLIENT_MSG_RX,
          "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
          client, client->msg.bufferLength,
          client->msg.header.prog, client->msg.header.vers, client->msg.header.proc,
          client->msg.header.type, client->msg.header.status, client->msg.header.serial);

    if (virKeepAliveCheckMessage(client->keepalive, &client->msg))
        return 0;

    switch (client->msg.header.type) {
    case VIR_NET_REPLY: /* Normal RPC replies */
    case VIR_NET_REPLY_WITH_FDS: /* Normal RPC replies with FDs */
        return virNetClientCallDispatchReply(client);

    case VIR_NET_MESSAGE: /* Async notifications */
        return virNetClientCallDispatchMessage(client);

    case VIR_NET_STREAM: /* Stream protocol */
        return virNetClientCallDispatchStream(client);

    default:
        virNetError(VIR_ERR_RPC,
                    _("got unexpected RPC call prog %d vers %d proc %d type %d"),
                    client->msg.header.prog, client->msg.header.vers,
                    client->msg.header.proc, client->msg.header.type);
        return -1;
    }
}


static ssize_t
virNetClientIOWriteMessage(virNetClientPtr client,
                           virNetClientCallPtr thecall)
{
    ssize_t ret = 0;

    if (thecall->msg->bufferOffset < thecall->msg->bufferLength) {
        ret = virNetSocketWrite(client->sock,
                                thecall->msg->buffer + thecall->msg->bufferOffset,
                                thecall->msg->bufferLength - thecall->msg->bufferOffset);
        if (ret > 0 || virNetSocketHasPendingData(client->sock))
            thecall->sentSomeData = true;
        if (ret <= 0)
            return ret;

        thecall->msg->bufferOffset += ret;
    }

    if (thecall->msg->bufferOffset == thecall->msg->bufferLength) {
        size_t i;
        for (i = thecall->msg->donefds ; i < thecall->msg->nfds ; i++) {
            int rv;
            if ((rv = virNetSocketSendFD(client->sock, thecall->msg->fds[i])) < 0)
                return -1;
            if (rv == 0) /* Blocking */
                return 0;
            thecall->msg->donefds++;
        }
        thecall->msg->donefds = 0;
        thecall->msg->bufferOffset = thecall->msg->bufferLength = 0;
        if (thecall->expectReply)
            thecall->mode = VIR_NET_CLIENT_MODE_WAIT_RX;
        else
            thecall->mode = VIR_NET_CLIENT_MODE_COMPLETE;
    }

    return ret;
}


static ssize_t
virNetClientIOHandleOutput(virNetClientPtr client)
{
    virNetClientCallPtr thecall = client->waitDispatch;

    while (thecall &&
           thecall->mode != VIR_NET_CLIENT_MODE_WAIT_TX)
        thecall = thecall->next;

    if (!thecall)
        return -1; /* Shouldn't happen, but you never know... */

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
virNetClientIOReadMessage(virNetClientPtr client)
{
    size_t wantData;
    ssize_t ret;

    /* Start by reading length word */
    if (client->msg.bufferLength == 0)
        client->msg.bufferLength = 4;

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
virNetClientIOHandleInput(virNetClientPtr client)
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

                    for (i = client->msg.donefds ; i < client->msg.nfds ; i++) {
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
                client->msg.bufferOffset = client->msg.bufferLength = 0;
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


static bool virNetClientIOEventLoopPollEvents(virNetClientCallPtr call,
                                              void *opaque)
{
    struct pollfd *fd = opaque;

    if (call->mode == VIR_NET_CLIENT_MODE_WAIT_RX)
        fd->events |= POLLIN;
    if (call->mode == VIR_NET_CLIENT_MODE_WAIT_TX)
        fd->events |= POLLOUT;

    return false;
}


static bool virNetClientIOEventLoopRemoveDone(virNetClientCallPtr call,
                                              void *opaque)
{
    virNetClientCallPtr thiscall = opaque;

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
        ignore_value(virCondDestroy(&call->cond));
        VIR_FREE(call->msg);
        VIR_FREE(call);
    }

    return true;
}


static bool virNetClientIOEventLoopRemoveNonBlocking(virNetClientCallPtr call,
                                                     void *opaque)
{
    virNetClientCallPtr thiscall = opaque;

    if (call == thiscall)
        return false;

    if (!call->nonBlock)
        return false;

    if (call->sentSomeData) {
        /*
         * If some data has been sent we must keep it in the list,
         * but still wakeup any thread
         */
        if (call->haveThread) {
            VIR_DEBUG("Waking up sleep %p", call);
            virCondSignal(&call->cond);
        } else {
            VIR_DEBUG("Keeping unfinished call %p in the list", call);
        }
        return false;
    } else {
        /*
         * If no data has been sent, we can remove it from the list.
         * Wakup any thread, otherwise free the caller ourselves
         */
        if (call->haveThread) {
            VIR_DEBUG("Waking up sleep %p", call);
            virCondSignal(&call->cond);
        } else {
            VIR_DEBUG("Removing call %p", call);
            if (call->expectReply)
                VIR_WARN("Got a call expecting a reply but without a waiting thread");
            ignore_value(virCondDestroy(&call->cond));
            VIR_FREE(call->msg);
            VIR_FREE(call);
        }
        return true;
    }
}


static void
virNetClientIOEventLoopRemoveAll(virNetClientPtr client,
                                 virNetClientCallPtr thiscall)
{
    if (!client->waitDispatch)
        return;

    if (client->waitDispatch == thiscall) {
        /* just pretend nothing was sent and the caller will free the call */
        thiscall->sentSomeData = false;
    } else {
        virNetClientCallPtr call = client->waitDispatch;
        virNetClientCallRemove(&client->waitDispatch, call);
        ignore_value(virCondDestroy(&call->cond));
        VIR_FREE(call->msg);
        VIR_FREE(call);
    }
}


static void virNetClientIOEventLoopPassTheBuck(virNetClientPtr client, virNetClientCallPtr thiscall)
{
    VIR_DEBUG("Giving up the buck %p", thiscall);
    virNetClientCallPtr tmp = client->waitDispatch;
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
        virNetClientIOEventLoopRemoveAll(client, thiscall);
    }
}


static bool virNetClientIOEventLoopWantNonBlock(virNetClientCallPtr call, void *opaque ATTRIBUTE_UNUSED)
{
    return call->nonBlock;
}

/*
 * Process all calls pending dispatch/receive until we
 * get a reply to our own call. Then quit and pass the buck
 * to someone else.
 *
 * Returns 2 if fully sent, 1 if partially sent (only for nonBlock==true),
 * 0 if nothing sent (only for nonBlock==true) and -1 on error
 */
static int virNetClientIOEventLoop(virNetClientPtr client,
                                   virNetClientCallPtr thiscall)
{
    struct pollfd fds[2];
    int ret;

    fds[0].fd = virNetSocketGetFD(client->sock);
    fds[1].fd = client->wakeupReadFD;

    for (;;) {
        char ignore;
        sigset_t oldmask, blockedsigs;
        int timeout = -1;

        /* If we have existing SASL decoded data we don't want to sleep in
         * the poll(), just check if any other FDs are also ready.
         * If the connection is going to be closed, we don't want to sleep in
         * poll() either.
         */
        if (virNetSocketHasCachedData(client->sock) || client->wantClose)
            timeout = 0;

        /* If there are any non-blocking calls in the queue,
         * then we don't want to sleep in poll()
         */
        if (virNetClientCallMatchPredicate(client->waitDispatch,
                                           virNetClientIOEventLoopWantNonBlock,
                                           NULL))
            timeout = 0;

        fds[0].events = fds[0].revents = 0;
        fds[1].events = fds[1].revents = 0;

        fds[1].events = POLLIN;

        /* Calculate poll events for calls */
        virNetClientCallMatchPredicate(client->waitDispatch,
                                       virNetClientIOEventLoopPollEvents,
                                       &fds[0]);

        /* We have to be prepared to receive stream data
         * regardless of whether any of the calls waiting
         * for dispatch are for streams.
         */
        if (client->nstreams)
            fds[0].events |= POLLIN;

        /* Release lock while poll'ing so other threads
         * can stuff themselves on the queue */
        virNetClientUnlock(client);

        /* Block SIGWINCH from interrupting poll in curses programs,
         * then restore the original signal mask again immediately
         * after the call (RHBZ#567931).  Same for SIGCHLD and SIGPIPE
         * at the suggestion of Paolo Bonzini and Daniel Berrange.
         */
        sigemptyset (&blockedsigs);
#ifdef SIGWINCH
        sigaddset (&blockedsigs, SIGWINCH);
#endif
#ifdef SIGCHLD
        sigaddset (&blockedsigs, SIGCHLD);
#endif
        sigaddset (&blockedsigs, SIGPIPE);
        ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));

    repoll:
        ret = poll(fds, ARRAY_CARDINALITY(fds), timeout);
        if (ret < 0 && errno == EAGAIN)
            goto repoll;

        ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));

        virNetClientLock(client);

        /* If we have existing SASL decoded data, pretend
         * the socket became readable so we consume it
         */
        if (virNetSocketHasCachedData(client->sock)) {
            fds[0].revents |= POLLIN;
        }

        /* If wantClose flag is set, pretend there was an error on the socket
         */
        if (client->wantClose)
            fds[0].revents = POLLERR;

        if (fds[1].revents) {
            VIR_DEBUG("Woken up from poll by other thread");
            if (saferead(client->wakeupReadFD, &ignore, sizeof(ignore)) != sizeof(ignore)) {
                virReportSystemError(errno, "%s",
                                     _("read on wakeup fd failed"));
                goto error;
            }

            /* If we were woken up because a new non-blocking call was queued,
             * we need to re-poll to check if we can send it.
             */
            if (virNetClientCallMatchPredicate(client->waitDispatch,
                                               virNetClientIOEventLoopWantNonBlock,
                                               NULL)) {
                VIR_DEBUG("New non-blocking call arrived; repolling");
                continue;
            }
        }

        if (ret < 0) {
            /* XXX what's this dubious errno check doing ? */
            if (errno == EWOULDBLOCK)
                continue;
            virReportSystemError(errno,
                                 "%s", _("poll on socket failed"));
            goto error;
        }

        if (fds[0].revents & POLLOUT) {
            if (virNetClientIOHandleOutput(client) < 0)
                goto error;
        }

        if (fds[0].revents & POLLIN) {
            if (virNetClientIOHandleInput(client) < 0)
                goto error;
        }

        /* Iterate through waiting calls and if any are
         * complete, remove them from the dispatch list..
         */
        virNetClientCallRemovePredicate(&client->waitDispatch,
                                        virNetClientIOEventLoopRemoveDone,
                                        thiscall);

        /* Iterate through waiting calls and if any are
         * non-blocking, remove them from the dispatch list...
         */
        virNetClientCallRemovePredicate(&client->waitDispatch,
                                        virNetClientIOEventLoopRemoveNonBlocking,
                                        thiscall);

        /* Now see if *we* are done */
        if (thiscall->mode == VIR_NET_CLIENT_MODE_COMPLETE) {
            virNetClientCallRemove(&client->waitDispatch, thiscall);
            virNetClientIOEventLoopPassTheBuck(client, thiscall);
            return 2;
        }

        /* We're not done, but we're non-blocking */
        if (thiscall->nonBlock) {
            virNetClientIOEventLoopPassTheBuck(client, thiscall);
            if (thiscall->sentSomeData) {
                return 1;
            } else {
                virNetClientCallRemove(&client->waitDispatch, thiscall);
                return 0;
            }
        }

        if (fds[0].revents & (POLLHUP | POLLERR)) {
            virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("received hangup / error event on socket"));
            goto error;
        }
    }


error:
    virNetClientCallRemove(&client->waitDispatch, thiscall);
    virNetClientIOEventLoopPassTheBuck(client, thiscall);
    return -1;
}


static void virNetClientIOUpdateCallback(virNetClientPtr client,
                                         bool enableCallback)
{
    int events = 0;
    if (enableCallback)
        events |= VIR_EVENT_HANDLE_READABLE;

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
 * NB(2). Make sure to memset (&ret, 0, sizeof(ret)) before calling,
 * else Bad Things will happen in the XDR code.
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
 *      http://en.wikipedia.org/wiki/Passing_the_buck
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
 * Returns 2 if fully sent, 1 if partially sent (only for nonBlock==true),
 * 0 if nothing sent (only for nonBlock==true) and -1 on error
 */
static int virNetClientIO(virNetClientPtr client,
                          virNetClientCallPtr thiscall)
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
        char ignore = 1;

        /* Force other thread to wakeup from poll */
        if (safewrite(client->wakeupSendFD, &ignore, sizeof(ignore)) != sizeof(ignore)) {
            virNetClientCallRemove(&client->waitDispatch, thiscall);
            virReportSystemError(errno, "%s",
                                 _("failed to wake up polling thread"));
            return -1;
        }

        VIR_DEBUG("Going to sleep %p %p", client->waitDispatch, thiscall);
        /* Go to sleep while other thread is working... */
        if (virCondWait(&thiscall->cond, &client->lock) < 0) {
            virNetClientCallRemove(&client->waitDispatch, thiscall);
            virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to wait on condition"));
            return -1;
        }

        VIR_DEBUG("Wokeup from sleep %p %p", client->waitDispatch, thiscall);
        /* Three reasons we can be woken up
         *  1. Other thread has got our reply ready for us
         *  2. Other thread is all done, and it is our turn to
         *     be the dispatcher to finish waiting for
         *     our reply
         *  3. I/O was expected to block
         */
        if (thiscall->mode == VIR_NET_CLIENT_MODE_COMPLETE) {
            rv = 2;
            /*
             * We avoided catching the buck and our reply is ready !
             * We've already had 'thiscall' removed from the list
             * so just need to (maybe) handle errors & free it
             */
            goto cleanup;
        }

        /* If we're non-blocking, get outta here */
        if (thiscall->nonBlock) {
            if (thiscall->sentSomeData)
                rv = 1; /* In progress */
            else
                rv = 0; /* none at all */
            goto cleanup;
        }

        /* Grr, someone passed the buck onto us ... */
    } else {
        client->haveTheBuck = true;
    }

    VIR_DEBUG("We have the buck %p %p", client->waitDispatch, thiscall);

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

    virResetLastError();
    rv = virNetClientIOEventLoop(client, thiscall);

    if (client->sock)
        virNetClientIOUpdateCallback(client, true);

    if (rv == 0 &&
        virGetLastError())
        rv = -1;

cleanup:
    VIR_DEBUG("All done with our call %p %p %d", client->waitDispatch, thiscall, rv);
    return rv;
}


void virNetClientIncomingEvent(virNetSocketPtr sock,
                               int events,
                               void *opaque)
{
    virNetClientPtr client = opaque;

    virNetClientLock(client);

    if (!client->sock)
        goto done;

    /* This should be impossible, but it doesn't hurt to check */
    if (client->haveTheBuck || client->wantClose)
        goto done;

    VIR_DEBUG("Event fired %p %d", sock, events);

    if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR)) {
        VIR_DEBUG("%s : VIR_EVENT_HANDLE_HANGUP or "
                  "VIR_EVENT_HANDLE_ERROR encountered", __FUNCTION__);
        virNetSocketRemoveIOCallback(sock);
        goto done;
    }

    if (virNetClientIOHandleInput(client) < 0) {
        VIR_WARN("Something went wrong during async message processing");
        virNetSocketRemoveIOCallback(sock);
    }

done:
    virNetClientUnlock(client);
}


/*
 * Returns 2 if fully sent, 1 if partially sent (only for nonBlock==true),
 * 0 if nothing sent (only for nonBlock==true) and -1 on error
 */
static int virNetClientSendInternal(virNetClientPtr client,
                                    virNetMessagePtr msg,
                                    bool expectReply,
                                    bool nonBlock)
{
    virNetClientCallPtr call;
    int ret = -1;

    PROBE(RPC_CLIENT_MSG_TX_QUEUE,
          "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
          client, msg->bufferLength,
          msg->header.prog, msg->header.vers, msg->header.proc,
          msg->header.type, msg->header.status, msg->header.serial);

    if (expectReply &&
        (msg->bufferLength != 0) &&
        (msg->header.status == VIR_NET_CONTINUE)) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Attempt to send an asynchronous message with a synchronous reply"));
        return -1;
    }

    if (expectReply && nonBlock) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Attempt to send a non-blocking message with a synchronous reply"));
        return -1;
    }

    if (VIR_ALLOC(call) < 0) {
        virReportOOMError();
        return -1;
    }

    if (!client->sock || client->wantClose) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("client socket is closed"));
        goto cleanup;
    }

    if (virCondInit(&call->cond) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot initialize condition variable"));
        goto cleanup;
    }

    msg->donefds = 0;
    if (msg->bufferLength)
        call->mode = VIR_NET_CLIENT_MODE_WAIT_TX;
    else
        call->mode = VIR_NET_CLIENT_MODE_WAIT_RX;
    call->msg = msg;
    call->expectReply = expectReply;
    call->nonBlock = nonBlock;
    call->haveThread = true;

    ret = virNetClientIO(client, call);

    /* If partially sent, then the call is still on the dispatch queue */
    if (ret == 1) {
        call->haveThread = false;
    } else {
        ignore_value(virCondDestroy(&call->cond));
    }

cleanup:
    if (ret != 1)
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
int virNetClientSendWithReply(virNetClientPtr client,
                              virNetMessagePtr msg)
{
    int ret;
    virNetClientLock(client);
    ret = virNetClientSendInternal(client, msg, true, false);
    virNetClientUnlock(client);
    if (ret < 0)
        return -1;
    return 0;
}


/*
 * @msg: a message allocated on heap or stack
 *
 * Send a message synchronously, without any reply
 *
 * The caller is responsible for free'ing @msg if it was allocated
 * on the heap
 *
 * Returns 0 on success, -1 on failure
 */
int virNetClientSendNoReply(virNetClientPtr client,
                            virNetMessagePtr msg)
{
    int ret;
    virNetClientLock(client);
    ret = virNetClientSendInternal(client, msg, false, false);
    virNetClientUnlock(client);
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
 * Returns 2 on full send, 1 on partial send, 0 on no send, -1 on error
 */
int virNetClientSendNonBlock(virNetClientPtr client,
                             virNetMessagePtr msg)
{
    int ret;
    virNetClientLock(client);
    ret = virNetClientSendInternal(client, msg, false, true);
    virNetClientUnlock(client);
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
int virNetClientSendWithReplyStream(virNetClientPtr client,
                                    virNetMessagePtr msg,
                                    virNetClientStreamPtr st)
{
    int ret;
    virNetClientLock(client);
    /* Other thread might have already received
     * stream EOF so we don't want sent anything.
     * Server won't respond anyway.
     */
    if (virNetClientStreamEOF(st)) {
        virNetClientUnlock(client);
        return 0;
    }

    ret = virNetClientSendInternal(client, msg, true, false);
    virNetClientUnlock(client);
    if (ret < 0)
        return -1;
    return 0;
}
