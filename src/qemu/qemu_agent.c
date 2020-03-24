/*
 * qemu_agent.c: interaction with QEMU guest agent
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

#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <gio/gio.h>

#include "qemu_agent.h"
#include "qemu_domain.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virjson.h"
#include "virfile.h"
#include "virprocess.h"
#include "virtime.h"
#include "virobject.h"
#include "virstring.h"
#include "virenum.h"
#include "virsocket.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_agent");

#define LINE_ENDING "\n"

#define DEBUG_IO 0
#define DEBUG_RAW_IO 0

/* We read from QEMU until seeing a \r\n pair to indicate a
 * completed reply or event. To avoid memory denial-of-service
 * though, we must have a size limit on amount of data we
 * buffer. 10 MB is large enough that it ought to cope with
 * normal QEMU replies, and small enough that we're not
 * consuming unreasonable mem.
 */
#define QEMU_AGENT_MAX_RESPONSE (10 * 1024 * 1024)

/* When you are the first to uncomment this,
 * don't forget to uncomment the corresponding
 * part in qemuAgentIOProcessEvent as well.
 *
static struct {
    const char *type;
    void (*handler)(qemuAgentPtr agent, virJSONValuePtr data);
} eventHandlers[] = {
};
*/

typedef struct _qemuAgentMessage qemuAgentMessage;
typedef qemuAgentMessage *qemuAgentMessagePtr;

struct _qemuAgentMessage {
    char *txBuffer;
    int txOffset;
    int txLength;

    /* Used by the JSON agent to hold reply / error */
    char *rxBuffer;
    int rxLength;
    void *rxObject;

    /* True if rxBuffer / rxObject are ready, or a
     * fatal error occurred on the agent channel
     */
    bool finished;
    /* true for sync command */
    bool sync;
    /* id of the issued sync comand */
    unsigned long long id;
    bool first;
};


struct _qemuAgent {
    virObjectLockable parent;

    virCond notify;

    int fd;

    GMainContext *context;
    GSocket *socket;
    GSource *watch;

    bool running;
    bool singleSync;
    bool inSync;

    virDomainObjPtr vm;

    qemuAgentCallbacksPtr cb;

    /* If there's a command being processed this will be
     * non-NULL */
    qemuAgentMessagePtr msg;

    /* Buffer incoming data ready for agent
     * code to process & find message boundaries */
    size_t bufferOffset;
    size_t bufferLength;
    char *buffer;

    /* If anything went wrong, this will be fed back
     * the next agent msg */
    virError lastError;

    /* Some guest agent commands don't return anything
     * but fire up an event on qemu agent instead.
     * Take that as indication of successful completion */
    qemuAgentEvent await_event;
    int timeout;
};

static virClassPtr qemuAgentClass;
static void qemuAgentDispose(void *obj);

static int qemuAgentOnceInit(void)
{
    if (!VIR_CLASS_NEW(qemuAgent, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(qemuAgent);


#if DEBUG_RAW_IO
static char *
qemuAgentEscapeNonPrintable(const char *text)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\\')
            virBufferAddLit(&buf, "\\\\");
        else if (g_ascii_isprint(text[i]) || text[i] == '\n' ||
                 (text[i] == '\r' && text[i+1] == '\n'))
            virBufferAddChar(&buf, text[i]);
        else
            virBufferAsprintf(&buf, "\\x%02x", text[i]);
    }
    return virBufferContentAndReset(&buf);
}
#endif


static void qemuAgentDispose(void *obj)
{
    qemuAgentPtr agent = obj;
    VIR_DEBUG("agent=%p", agent);
    if (agent->cb && agent->cb->destroy)
        (agent->cb->destroy)(agent, agent->vm);
    virCondDestroy(&agent->notify);
    VIR_FREE(agent->buffer);
    g_main_context_unref(agent->context);
    virResetError(&agent->lastError);
}

static int
qemuAgentOpenUnix(const char *socketpath)
{
    struct sockaddr_un addr;
    int agentfd;
    int ret = -1;

    if ((agentfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    if (virSetCloseExec(agentfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set agent "
                               "close-on-exec flag"));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, socketpath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Socket path %s too big for destination"), socketpath);
        goto error;
    }

    ret = connect(agentfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to connect to agent socket"));
        goto error;
    }

    return agentfd;

 error:
    VIR_FORCE_CLOSE(agentfd);
    return -1;
}


static int
qemuAgentIOProcessEvent(qemuAgentPtr agent,
                        virJSONValuePtr obj)
{
    const char *type;
    VIR_DEBUG("agent=%p obj=%p", agent, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }

/*
    for (i = 0; i < G_N_ELEMENTS(eventHandlers); i++) {
        if (STREQ(eventHandlers[i].type, type)) {
            virJSONValuePtr data = virJSONValueObjectGet(obj, "data");
            VIR_DEBUG("handle %s handler=%p data=%p", type,
                      eventHandlers[i].handler, data);
            (eventHandlers[i].handler)(agent, data);
            break;
        }
    }
*/
    return 0;
}

static int
qemuAgentIOProcessLine(qemuAgentPtr agent,
                       const char *line,
                       qemuAgentMessagePtr msg)
{
    virJSONValuePtr obj = NULL;
    int ret = -1;

    VIR_DEBUG("Line [%s]", line);

    if (!(obj = virJSONValueFromString(line))) {
        /* receiving garbage on first sync is regular situation */
        if (msg && msg->sync && msg->first) {
            VIR_DEBUG("Received garbage on sync");
            msg->finished = 1;
            return 0;
        }

        goto cleanup;
    }

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parsed JSON reply '%s' isn't an object"), line);
        goto cleanup;
    }

    if (virJSONValueObjectHasKey(obj, "QMP") == 1) {
        ret = 0;
    } else if (virJSONValueObjectHasKey(obj, "event") == 1) {
        ret = qemuAgentIOProcessEvent(agent, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") == 1 ||
               virJSONValueObjectHasKey(obj, "return") == 1) {
        if (msg) {
            if (msg->sync) {
                unsigned long long id;

                if (virJSONValueObjectGetNumberUlong(obj, "return", &id) < 0) {
                    VIR_DEBUG("Ignoring delayed reply on sync");
                    ret = 0;
                    goto cleanup;
                }

                VIR_DEBUG("Guest returned ID: %llu", id);

                if (msg->id != id) {
                    VIR_DEBUG("Guest agent returned ID: %llu instead of %llu",
                              id, msg->id);
                    ret = 0;
                    goto cleanup;
                }
            }
            msg->rxObject = obj;
            msg->finished = 1;
            obj = NULL;
        } else {
            /* we are out of sync */
            VIR_DEBUG("Ignoring delayed reply");
        }
        ret = 0;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown JSON reply '%s'"), line);
    }

 cleanup:
    virJSONValueFree(obj);
    return ret;
}

static int qemuAgentIOProcessData(qemuAgentPtr agent,
                                  char *data,
                                  size_t len,
                                  qemuAgentMessagePtr msg)
{
    int used = 0;
    size_t i = 0;
#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuAgentEscapeNonPrintable(data);
    VIR_ERROR(_("[%s]"), str1);
    VIR_FREE(str1);
# else
    VIR_DEBUG("Data %zu bytes [%s]", len, data);
# endif
#endif

    while (used < len) {
        char *nl = strstr(data + used, LINE_ENDING);

        if (nl) {
            int got = nl - (data + used);
            for (i = 0; i < strlen(LINE_ENDING); i++)
                data[used + got + i] = '\0';
            if (qemuAgentIOProcessLine(agent, data + used, msg) < 0)
                return -1;
            used += got + strlen(LINE_ENDING);
        } else {
            break;
        }
    }

    VIR_DEBUG("Total used %d bytes out of %zd available in buffer", used, len);
    return used;
}

/* This method processes data that has been received
 * from the agent. Looking for async events and
 * replies/errors.
 */
static int
qemuAgentIOProcess(qemuAgentPtr agent)
{
    int len;
    qemuAgentMessagePtr msg = NULL;

    /* See if there's a message ready for reply; that is,
     * one that has completed writing all its data.
     */
    if (agent->msg && agent->msg->txOffset == agent->msg->txLength)
        msg = agent->msg;

#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuAgentEscapeNonPrintable(msg ? msg->txBuffer : "");
    char *str2 = qemuAgentEscapeNonPrintable(agent->buffer);
    VIR_ERROR(_("Process %zu %p %p [[[%s]]][[[%s]]]"),
              agent->bufferOffset, agent->msg, msg, str1, str2);
    VIR_FREE(str1);
    VIR_FREE(str2);
# else
    VIR_DEBUG("Process %zu", agent->bufferOffset);
# endif
#endif

    len = qemuAgentIOProcessData(agent,
                                 agent->buffer, agent->bufferOffset,
                                 msg);

    if (len < 0)
        return -1;

    if (len < agent->bufferOffset) {
        memmove(agent->buffer, agent->buffer + len, agent->bufferOffset - len);
        agent->bufferOffset -= len;
    } else {
        VIR_FREE(agent->buffer);
        agent->bufferOffset = agent->bufferLength = 0;
    }
#if DEBUG_IO
    VIR_DEBUG("Process done %zu used %d", agent->bufferOffset, len);
#endif
    if (msg && msg->finished)
        virCondBroadcast(&agent->notify);
    return len;
}


/*
 * Called when the agent is able to write data
 * Call this function while holding the agent lock.
 */
static int
qemuAgentIOWrite(qemuAgentPtr agent)
{
    int done;

    /* If no active message, or fully transmitted, then no-op */
    if (!agent->msg || agent->msg->txOffset == agent->msg->txLength)
        return 0;

    done = safewrite(agent->fd,
                     agent->msg->txBuffer + agent->msg->txOffset,
                     agent->msg->txLength - agent->msg->txOffset);

    if (done < 0) {
        if (errno == EAGAIN)
            return 0;

        virReportSystemError(errno, "%s",
                             _("Unable to write to agent"));
        return -1;
    }
    agent->msg->txOffset += done;
    return done;
}

/*
 * Called when the agent has incoming data to read
 * Call this function while holding the agent lock.
 *
 * Returns -1 on error, or number of bytes read
 */
static int
qemuAgentIORead(qemuAgentPtr agent)
{
    size_t avail = agent->bufferLength - agent->bufferOffset;
    int ret = 0;

    if (avail < 1024) {
        if (agent->bufferLength >= QEMU_AGENT_MAX_RESPONSE) {
            virReportSystemError(ERANGE,
                                 _("No complete agent response found in %d bytes"),
                                 QEMU_AGENT_MAX_RESPONSE);
            return -1;
        }
        if (VIR_REALLOC_N(agent->buffer,
                          agent->bufferLength + 1024) < 0)
            return -1;
        agent->bufferLength += 1024;
        avail += 1024;
    }

    /* Read as much as we can get into our buffer,
       until we block on EAGAIN, or hit EOF */
    while (avail > 1) {
        int got;
        got = read(agent->fd,
                   agent->buffer + agent->bufferOffset,
                   avail - 1);
        if (got < 0) {
            if (errno == EAGAIN)
                break;
            virReportSystemError(errno, "%s",
                                 _("Unable to read from agent"));
            ret = -1;
            break;
        }
        if (got == 0)
            break;

        ret += got;
        avail -= got;
        agent->bufferOffset += got;
        agent->buffer[agent->bufferOffset] = '\0';
    }

#if DEBUG_IO
    VIR_DEBUG("Now read %zu bytes of data", agent->bufferOffset);
#endif

    return ret;
}


static gboolean
qemuAgentIO(GSocket *socket,
            GIOCondition cond,
            gpointer opaque);


static void
qemuAgentRegister(qemuAgentPtr agent)
{
    GIOCondition cond = 0;

    if (agent->lastError.code == VIR_ERR_OK) {
        cond |= G_IO_IN;

        if (agent->msg && agent->msg->txOffset < agent->msg->txLength)
            cond |= G_IO_OUT;
    }

    agent->watch = g_socket_create_source(agent->socket,
                                        cond,
                                        NULL);

    virObjectRef(agent);
    g_source_set_callback(agent->watch,
                          (GSourceFunc)qemuAgentIO,
                          agent,
                          (GDestroyNotify)virObjectUnref);

    g_source_attach(agent->watch,
                    agent->context);
}


static void
qemuAgentUnregister(qemuAgentPtr agent)
{
    if (agent->watch) {
        g_source_destroy(agent->watch);
        g_source_unref(agent->watch);
        agent->watch = NULL;
    }
}


static void qemuAgentUpdateWatch(qemuAgentPtr agent)
{
    qemuAgentUnregister(agent);
    if (agent->socket)
        qemuAgentRegister(agent);
}


static gboolean
qemuAgentIO(GSocket *socket G_GNUC_UNUSED,
            GIOCondition cond,
            gpointer opaque)
{
    qemuAgentPtr agent = opaque;
    bool error = false;
    bool eof = false;

    virObjectRef(agent);
    /* lock access to the agent and protect fd */
    virObjectLock(agent);
#if DEBUG_IO
    VIR_DEBUG("Agent %p I/O on watch %d socket %p cond %d", agent, agent->socket, cond);
#endif

    if (agent->fd == -1 || !agent->watch) {
        virObjectUnlock(agent);
        virObjectUnref(agent);
        return G_SOURCE_REMOVE;
    }

    if (agent->lastError.code != VIR_ERR_OK) {
        if (cond & (G_IO_HUP | G_IO_ERR))
            eof = true;
        error = true;
    } else {
        if (cond & G_IO_OUT) {
            if (qemuAgentIOWrite(agent) < 0)
                error = true;
        }

        if (!error &&
            cond & G_IO_IN) {
            int got = qemuAgentIORead(agent);
            if (got < 0) {
                error = true;
            } else if (got == 0) {
                eof = true;
            } else {
                /* Ignore hangup/error cond if we read some data, to
                 * give time for that data to be consumed */
                cond = 0;

                if (qemuAgentIOProcess(agent) < 0)
                    error = true;
            }
        }

        if (!error &&
            cond & G_IO_HUP) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("End of file from agent socket"));
            eof = true;
        }

        if (!error && !eof &&
            cond & G_IO_ERR) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid file descriptor while waiting for agent"));
            eof = true;
        }
    }

    if (error || eof) {
        if (agent->lastError.code != VIR_ERR_OK) {
            /* Already have an error, so clear any new error */
            virResetLastError();
        } else {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Error while processing agent IO"));
            virCopyLastError(&agent->lastError);
            virResetLastError();
        }

        VIR_DEBUG("Error on agent %s", NULLSTR(agent->lastError.message));
        /* If IO process resulted in an error & we have a message,
         * then wakeup that waiter */
        if (agent->msg && !agent->msg->finished) {
            agent->msg->finished = 1;
            virCondSignal(&agent->notify);
        }
    }

    qemuAgentUpdateWatch(agent);

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObjPtr mutex next */
    if (eof) {
        void (*eofNotify)(qemuAgentPtr, virDomainObjPtr)
            = agent->cb->eofNotify;
        virDomainObjPtr vm = agent->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&agent->notify);
        virObjectUnlock(agent);
        virObjectUnref(agent);
        VIR_DEBUG("Triggering EOF callback");
        (eofNotify)(agent, vm);
    } else if (error) {
        void (*errorNotify)(qemuAgentPtr, virDomainObjPtr)
            = agent->cb->errorNotify;
        virDomainObjPtr vm = agent->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&agent->notify);
        virObjectUnlock(agent);
        virObjectUnref(agent);
        VIR_DEBUG("Triggering error callback");
        (errorNotify)(agent, vm);
    } else {
        virObjectUnlock(agent);
        virObjectUnref(agent);
    }

    return G_SOURCE_REMOVE;
}


qemuAgentPtr
qemuAgentOpen(virDomainObjPtr vm,
              const virDomainChrSourceDef *config,
              GMainContext *context,
              qemuAgentCallbacksPtr cb,
              bool singleSync)
{
    qemuAgentPtr agent;
    g_autoptr(GError) gerr = NULL;

    if (!cb || !cb->eofNotify) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("EOF notify callback must be supplied"));
        return NULL;
    }

    if (qemuAgentInitialize() < 0)
        return NULL;

    if (!(agent = virObjectLockableNew(qemuAgentClass)))
        return NULL;

    agent->timeout = QEMU_DOMAIN_PRIVATE(vm)->agentTimeout;
    agent->fd = -1;
    if (virCondInit(&agent->notify) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot initialize agent condition"));
        virObjectUnref(agent);
        return NULL;
    }
    agent->vm = vm;
    agent->cb = cb;
    agent->singleSync = singleSync;

    if (config->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to handle agent type: %s"),
                       virDomainChrTypeToString(config->type));
        goto cleanup;
    }

    agent->fd = qemuAgentOpenUnix(config->data.nix.path);
    if (agent->fd == -1)
        goto cleanup;

    agent->context = g_main_context_ref(context);

    agent->socket = g_socket_new_from_fd(agent->fd, &gerr);
    if (!agent->socket) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to create socket object: %s"),
                       gerr->message);
        goto cleanup;
    }

    qemuAgentRegister(agent);

    agent->running = true;
    VIR_DEBUG("New agent %p fd=%d", agent, agent->fd);

    return agent;

 cleanup:
    /* We don't want the 'destroy' callback invoked during
     * cleanup from construction failure, because that can
     * give a double-unref on virDomainObjPtr in the caller,
     * so kill the callbacks now.
     */
    agent->cb = NULL;
    qemuAgentClose(agent);
    return NULL;
}


static void
qemuAgentNotifyCloseLocked(qemuAgentPtr agent)
{
    if (agent) {
        agent->running = false;

        /* If there is somebody waiting for a message
         * wake him up. No message will arrive anyway. */
        if (agent->msg && !agent->msg->finished) {
            agent->msg->finished = 1;
            virCondSignal(&agent->notify);
        }
    }
}


void
qemuAgentNotifyClose(qemuAgentPtr agent)
{
    if (!agent)
        return;

    VIR_DEBUG("agent=%p", agent);

    virObjectLock(agent);
    qemuAgentNotifyCloseLocked(agent);
    virObjectUnlock(agent);
}


void qemuAgentClose(qemuAgentPtr agent)
{
    if (!agent)
        return;

    VIR_DEBUG("agent=%p", agent);

    virObjectLock(agent);

    if (agent->socket) {
        qemuAgentUnregister(agent);
        g_object_unref(agent->socket);
        agent->socket = NULL;
        agent->fd = -1;
    }

    qemuAgentNotifyCloseLocked(agent);
    virObjectUnlock(agent);

    virObjectUnref(agent);
}

#define QEMU_AGENT_WAIT_TIME 5

/**
 * qemuAgentSend:
 * @agent: agent object
 * @msg: Message
 * @seconds: number of seconds to wait for the result, it can be either
 *           -2, -1, 0 or positive.
 *
 * Send @msg to agent @agent. If @seconds is equal to
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK(-2), this function will block forever
 * waiting for the result. The value of
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT(-1) means use default timeout value
 * and VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT(0) makes this function return
 * immediately without waiting. Any positive value means the number of seconds
 * to wait for the result.
 *
 * Returns: 0 on success,
 *          -2 on timeout,
 *          -1 otherwise
 */
static int qemuAgentSend(qemuAgentPtr agent,
                         qemuAgentMessagePtr msg,
                         int seconds)
{
    int ret = -1;
    unsigned long long then = 0;

    /* Check whether qemu quit unexpectedly */
    if (agent->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s",
                  NULLSTR(agent->lastError.message));
        virSetError(&agent->lastError);
        return -1;
    }

    if (seconds > VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) {
        unsigned long long now;
        if (virTimeMillisNow(&now) < 0)
            return -1;
        if (seconds == VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT)
            seconds = QEMU_AGENT_WAIT_TIME;
        then = now + seconds * 1000ull;
    }

    agent->msg = msg;
    qemuAgentUpdateWatch(agent);

    while (!agent->msg->finished) {
        if ((then && virCondWaitUntil(&agent->notify, &agent->parent.lock, then) < 0) ||
            (!then && virCondWait(&agent->notify, &agent->parent.lock) < 0)) {
            if (errno == ETIMEDOUT) {
                virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                               _("Guest agent not available for now"));
                ret = -2;
            } else {
                virReportSystemError(errno, "%s",
                                     _("Unable to wait on agent socket "
                                       "condition"));
            }
            agent->inSync = false;
            goto cleanup;
        }
    }

    if (agent->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Send command resulted in error %s",
                  NULLSTR(agent->lastError.message));
        virSetError(&agent->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    agent->msg = NULL;
    qemuAgentUpdateWatch(agent);

    return ret;
}


/**
 * qemuAgentGuestSync:
 * @agent: agent object
 *
 * Send guest-sync with unique ID
 * and wait for reply. If we get one, check if
 * received ID is equal to given.
 *
 * Returns: 0 on success,
 *          -1 otherwise
 */
static int
qemuAgentGuestSync(qemuAgentPtr agent)
{
    int ret = -1;
    int send_ret;
    unsigned long long id;
    qemuAgentMessage sync_msg;
    int timeout = VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT;

    if (agent->singleSync && agent->inSync)
        return 0;

    /* if user specified a custom agent timeout that is lower than the
     * default timeout, use the shorter timeout instead */
    if ((agent->timeout >= 0) && (agent->timeout < QEMU_AGENT_WAIT_TIME))
        timeout = agent->timeout;

    memset(&sync_msg, 0, sizeof(sync_msg));
    /* set only on first sync */
    sync_msg.first = true;

 retry:
    if (virTimeMillisNow(&id) < 0)
        return -1;

    sync_msg.txBuffer = g_strdup_printf("{\"execute\":\"guest-sync\", "
                                        "\"arguments\":{\"id\":%llu}}\n", id);

    sync_msg.txLength = strlen(sync_msg.txBuffer);
    sync_msg.sync = true;
    sync_msg.id = id;

    VIR_DEBUG("Sending guest-sync command with ID: %llu", id);

    send_ret = qemuAgentSend(agent, &sync_msg, timeout);

    VIR_DEBUG("qemuAgentSend returned: %d", send_ret);

    if (send_ret < 0)
        goto cleanup;

    if (!sync_msg.rxObject) {
        if (sync_msg.first) {
            VIR_FREE(sync_msg.txBuffer);
            memset(&sync_msg, 0, sizeof(sync_msg));
            goto retry;
        } else {
            if (agent->running)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing agent reply object"));
            else
                virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                               _("Guest agent disappeared while executing command"));
            goto cleanup;
        }
    }

    if (agent->singleSync)
        agent->inSync = true;

    ret = 0;

 cleanup:
    virJSONValueFree(sync_msg.rxObject);
    VIR_FREE(sync_msg.txBuffer);
    return ret;
}

static const char *
qemuAgentStringifyErrorClass(const char *klass)
{
    if (STREQ_NULLABLE(klass, "BufferOverrun"))
        return "Buffer overrun";
    else if (STREQ_NULLABLE(klass, "CommandDisabled"))
        return "The command has been disabled for this instance";
    else if (STREQ_NULLABLE(klass, "CommandNotFound"))
        return "The command has not been found";
    else if (STREQ_NULLABLE(klass, "FdNotFound"))
        return "File descriptor not found";
    else if (STREQ_NULLABLE(klass, "InvalidParameter"))
        return "Invalid parameter";
    else if (STREQ_NULLABLE(klass, "InvalidParameterType"))
        return "Invalid parameter type";
    else if (STREQ_NULLABLE(klass, "InvalidParameterValue"))
        return "Invalid parameter value";
    else if (STREQ_NULLABLE(klass, "OpenFileFailed"))
        return "Cannot open file";
    else if (STREQ_NULLABLE(klass, "QgaCommandFailed"))
        return "Guest agent command failed";
    else if (STREQ_NULLABLE(klass, "QMPBadInputObjectMember"))
        return "Bad QMP input object member";
    else if (STREQ_NULLABLE(klass, "QMPExtraInputObjectMember"))
        return "Unexpected extra object member";
    else if (STREQ_NULLABLE(klass, "UndefinedError"))
        return "An undefined error has occurred";
    else if (STREQ_NULLABLE(klass, "Unsupported"))
        return "this feature or command is not currently supported";
    else if (klass)
        return klass;
    else
        return "unknown QEMU command error";
}

/* Checks whether the agent reply msg is an error caused by an unsupported
 * command.
 *
 * Returns true when reply is CommandNotFound or CommandDisabled
 *         false otherwise
 */
static bool
qemuAgentErrorCommandUnsupported(virJSONValuePtr reply)
{
    const char *klass;
    virJSONValuePtr error;

    if (!reply)
        return false;

    error = virJSONValueObjectGet(reply, "error");

    if (!error)
        return false;

    klass = virJSONValueObjectGetString(error, "class");
    return STREQ_NULLABLE(klass, "CommandNotFound") ||
        STREQ_NULLABLE(klass, "CommandDisabled");
}

/* Ignoring OOM in this method, since we're already reporting
 * a more important error
 *
 * XXX see qerror.h for different klasses & fill out useful params
 */
static const char *
qemuAgentStringifyError(virJSONValuePtr error)
{
    const char *klass = virJSONValueObjectGetString(error, "class");
    const char *detail = virJSONValueObjectGetString(error, "desc");

    /* The QMP 'desc' field is usually sufficient for our generic
     * error reporting needs. However, if not present, translate
     * the class into something readable.
     */
    if (!detail)
        detail = qemuAgentStringifyErrorClass(klass);

    return detail;
}

static const char *
qemuAgentCommandName(virJSONValuePtr cmd)
{
    const char *name = virJSONValueObjectGetString(cmd, "execute");
    if (name)
        return name;
    else
        return "<unknown>";
}

static int
qemuAgentCheckError(virJSONValuePtr cmd,
                    virJSONValuePtr reply)
{
    if (virJSONValueObjectHasKey(reply, "error")) {
        virJSONValuePtr error = virJSONValueObjectGet(reply, "error");
        char *cmdstr = virJSONValueToString(cmd, false);
        char *replystr = virJSONValueToString(reply, false);

        /* Log the full JSON formatted command & error */
        VIR_DEBUG("unable to execute QEMU agent command %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));

        /* Only send the user the command name + friendly error */
        if (!error)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU agent command '%s'"),
                           qemuAgentCommandName(cmd));
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU agent command '%s': %s"),
                           qemuAgentCommandName(cmd),
                           qemuAgentStringifyError(error));

        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    } else if (!virJSONValueObjectHasKey(reply, "return")) {
        char *cmdstr = virJSONValueToString(cmd, false);
        char *replystr = virJSONValueToString(reply, false);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to execute QEMU agent command '%s'"),
                       qemuAgentCommandName(cmd));
        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    }
    return 0;
}

static int
qemuAgentCommand(qemuAgentPtr agent,
                 virJSONValuePtr cmd,
                 virJSONValuePtr *reply,
                 int seconds)
{
    int ret = -1;
    qemuAgentMessage msg;
    char *cmdstr = NULL;
    int await_event = agent->await_event;

    *reply = NULL;
    memset(&msg, 0, sizeof(msg));

    if (!agent->running) {
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("Guest agent disappeared while executing command"));
        goto cleanup;
    }

    if (qemuAgentGuestSync(agent) < 0)
        goto cleanup;

    if (!(cmdstr = virJSONValueToString(cmd, false)))
        goto cleanup;
    msg.txBuffer = g_strdup_printf("%s" LINE_ENDING, cmdstr);
    msg.txLength = strlen(msg.txBuffer);

    VIR_DEBUG("Send command '%s' for write, seconds = %d", cmdstr, seconds);

    ret = qemuAgentSend(agent, &msg, seconds);

    VIR_DEBUG("Receive command reply ret=%d rxObject=%p",
              ret, msg.rxObject);

    if (ret < 0)
        goto cleanup;

    /* If we haven't obtained any reply but we wait for an
     * event, then don't report this as error */
    if (!msg.rxObject) {
        if (!await_event) {
            if (agent->running) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing agent reply object"));
            } else {
                virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                               _("Guest agent disappeared while executing command"));
            }
            ret = -1;
        }
        goto cleanup;
    }

    *reply = msg.rxObject;
    ret = qemuAgentCheckError(cmd, *reply);

 cleanup:
    VIR_FREE(cmdstr);
    VIR_FREE(msg.txBuffer);
    agent->await_event = QEMU_AGENT_EVENT_NONE;

    return ret;
}

static virJSONValuePtr G_GNUC_NULL_TERMINATED
qemuAgentMakeCommand(const char *cmdname,
                     ...)
{
    virJSONValuePtr obj = virJSONValueNewObject();
    virJSONValuePtr jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (virJSONValueObjectAppendString(obj, "execute", cmdname) < 0)
        goto error;

    if (virJSONValueObjectCreateVArgs(&jargs, args) < 0)
        goto error;

    if (jargs &&
        virJSONValueObjectAppend(obj, "arguments", jargs) < 0)
        goto error;

    va_end(args);

    return obj;

 error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
    return NULL;
}

static virJSONValuePtr
qemuAgentMakeStringsArray(const char **strings, unsigned int len)
{
    size_t i;
    virJSONValuePtr ret = virJSONValueNewArray(), str;

    for (i = 0; i < len; i++) {
        str = virJSONValueNewString(strings[i]);
        if (!str)
            goto error;

        if (virJSONValueArrayAppend(ret, str) < 0) {
            virJSONValueFree(str);
            goto error;
        }
    }
    return ret;

 error:
    virJSONValueFree(ret);
    return NULL;
}

void qemuAgentNotifyEvent(qemuAgentPtr agent,
                          qemuAgentEvent event)
{
    virObjectLock(agent);

    VIR_DEBUG("agent=%p event=%d await_event=%d", agent, event, agent->await_event);
    if (agent->await_event == event) {
        agent->await_event = QEMU_AGENT_EVENT_NONE;
        /* somebody waiting for this event, wake him up. */
        if (agent->msg && !agent->msg->finished) {
            agent->msg->finished = 1;
            virCondSignal(&agent->notify);
        }
    }

    virObjectUnlock(agent);
}

VIR_ENUM_DECL(qemuAgentShutdownMode);

VIR_ENUM_IMPL(qemuAgentShutdownMode,
              QEMU_AGENT_SHUTDOWN_LAST,
              "powerdown", "reboot", "halt",
);

int qemuAgentShutdown(qemuAgentPtr agent,
                      qemuAgentShutdownMode mode)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-shutdown",
                               "s:mode", qemuAgentShutdownModeTypeToString(mode),
                               NULL);
    if (!cmd)
        return -1;

    if (mode == QEMU_AGENT_SHUTDOWN_REBOOT)
        agent->await_event = QEMU_AGENT_EVENT_RESET;
    else
        agent->await_event = QEMU_AGENT_EVENT_SHUTDOWN;
    ret = qemuAgentCommand(agent, cmd, &reply,
                           VIR_DOMAIN_QEMU_AGENT_COMMAND_SHUTDOWN);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentFSFreeze:
 * @agent: agent object
 * @mountpoints: Array of mountpoint paths to be frozen, or NULL for all
 * @nmountpoints: Number of mountpoints to be frozen, or 0 for all
 *
 * Issue guest-fsfreeze-freeze command to guest agent,
 * which freezes file systems mounted on specified mountpoints
 * (or all file systems when @mountpoints is NULL), and returns
 * number of frozen file systems on success.
 *
 * Returns: number of file system frozen on success,
 *          -1 on error.
 */
int qemuAgentFSFreeze(qemuAgentPtr agent, const char **mountpoints,
                      unsigned int nmountpoints)
{
    int ret = -1;
    virJSONValuePtr cmd, arg = NULL;
    virJSONValuePtr reply = NULL;

    if (mountpoints && nmountpoints) {
        arg = qemuAgentMakeStringsArray(mountpoints, nmountpoints);
        if (!arg)
            return -1;

        cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze-list",
                                   "a:mountpoints", &arg, NULL);
    } else {
        cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze", NULL);
    }

    if (!cmd)
        goto cleanup;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
    }

 cleanup:
    virJSONValueFree(arg);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentFSThaw:
 * @agent: agent object
 *
 * Issue guest-fsfreeze-thaw command to guest agent,
 * which unfreezes all mounted file systems and returns
 * number of thawed file systems on success.
 *
 * Returns: number of file system thawed on success,
 *          -1 on error.
 */
int qemuAgentFSThaw(qemuAgentPtr agent)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fsfreeze-thaw", NULL);

    if (!cmd)
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

VIR_ENUM_DECL(qemuAgentSuspendMode);

VIR_ENUM_IMPL(qemuAgentSuspendMode,
              VIR_NODE_SUSPEND_TARGET_LAST,
              "guest-suspend-ram",
              "guest-suspend-disk",
              "guest-suspend-hybrid",
);

int
qemuAgentSuspend(qemuAgentPtr agent,
                 unsigned int target)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand(qemuAgentSuspendModeTypeToString(target),
                               NULL);
    if (!cmd)
        return -1;

    agent->await_event = QEMU_AGENT_EVENT_SUSPEND;
    ret = qemuAgentCommand(agent, cmd, &reply, agent->timeout);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuAgentArbitraryCommand(qemuAgentPtr agent,
                          const char *cmd_str,
                          char **result,
                          int timeout)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

    *result = NULL;
    if (timeout < VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("guest agent timeout '%d' is "
                         "less than the minimum '%d'"),
                       timeout, VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN);
        goto cleanup;
    }

    if (!(cmd = virJSONValueFromString(cmd_str)))
        goto cleanup;

    if ((ret = qemuAgentCommand(agent, cmd, &reply, timeout)) < 0)
        goto cleanup;

    if (!(*result = virJSONValueToString(reply, false)))
        ret = -1;


 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuAgentFSTrim(qemuAgentPtr agent,
                unsigned long long minimum)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fstrim",
                               "U:minimum", minimum,
                               NULL);
    if (!cmd)
        return ret;

    ret = qemuAgentCommand(agent, cmd, &reply, agent->timeout);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuAgentGetVCPUs(qemuAgentPtr agent,
                  qemuAgentCPUInfoPtr *info)
{
    int ret = -1;
    size_t i;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data = NULL;
    size_t ndata;

    if (!(cmd = qemuAgentMakeCommand("guest-get-vcpus", NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-vcpus reply was missing return data"));
        goto cleanup;
    }

    if (!virJSONValueIsArray(data)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed guest-get-vcpus data array"));
        goto cleanup;
    }

    ndata = virJSONValueArraySize(data);

    if (VIR_ALLOC_N(*info, ndata) < 0)
        goto cleanup;

    for (i = 0; i < ndata; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        qemuAgentCPUInfoPtr in = *info + i;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("array element missing in guest-get-vcpus return "
                             "value"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUint(entry, "logical-id", &in->id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'logical-id' missing in reply of guest-get-vcpus"));
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(entry, "online", &in->online) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'online' missing in reply of guest-get-vcpus"));
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(entry, "can-offline",
                                         &in->offlinable) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'can-offline' missing in reply of guest-get-vcpus"));
            goto cleanup;
        }
    }

    ret = ndata;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/* returns the value provided by the guest agent or -1 on internal error */
static int
qemuAgentSetVCPUsCommand(qemuAgentPtr agent,
                         qemuAgentCPUInfoPtr info,
                         size_t ninfo,
                         int *nmodified)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr cpus = NULL;
    virJSONValuePtr cpu = NULL;
    size_t i;

    *nmodified = 0;

    /* create the key data array */
    cpus = virJSONValueNewArray();

    for (i = 0; i < ninfo; i++) {
        qemuAgentCPUInfoPtr in = &info[i];

        /* don't set state for cpus that were not touched */
        if (!in->modified)
            continue;

        (*nmodified)++;

        /* create single cpu object */
        cpu = virJSONValueNewObject();

        if (virJSONValueObjectAppendNumberInt(cpu, "logical-id", in->id) < 0)
            goto cleanup;

        if (virJSONValueObjectAppendBoolean(cpu, "online", in->online) < 0)
            goto cleanup;

        if (virJSONValueArrayAppend(cpus, cpu) < 0)
            goto cleanup;

        cpu = NULL;
    }

    if (*nmodified == 0) {
        ret = 0;
        goto cleanup;
    }

    if (!(cmd = qemuAgentMakeCommand("guest-set-vcpus",
                                     "a:vcpus", &cpus,
                                     NULL)))
        goto cleanup;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    /* All negative values are invalid. Return of 0 is bogus since we wouldn't
     * call the guest agent so that 0 cpus would be set successfully. Reporting
     * more successfully set vcpus that we've asked for is invalid. */
    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0 ||
        ret <= 0 || ret > *nmodified) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest agent returned malformed or invalid return value"));
        ret = -1;
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virJSONValueFree(cpu);
    virJSONValueFree(cpus);
    return ret;
}


/**
 * Set the VCPU state using guest agent.
 *
 * Attempts to set the guest agent state for all cpus or until a proper error is
 * reported by the guest agent. This may require multiple calls.
 *
 * Returns -1 on error, 0 on success.
 */
int
qemuAgentSetVCPUs(qemuAgentPtr agent,
                  qemuAgentCPUInfoPtr info,
                  size_t ninfo)
{
    int rv;
    int nmodified;
    size_t i;

    do {
        if ((rv = qemuAgentSetVCPUsCommand(agent, info, ninfo, &nmodified)) < 0)
            return -1;

        /* all vcpus were set successfully */
        if (rv == nmodified)
            return 0;

        /* un-mark vcpus that were already set */
        for (i = 0; i < ninfo && rv > 0; i++) {
            if (!info[i].modified)
                continue;

            info[i].modified = false;
            rv--;
        }
    } while (1);

    return 0;
}


/* modify the cpu info structure to set the correct amount of cpus */
int
qemuAgentUpdateCPUInfo(unsigned int nvcpus,
                       qemuAgentCPUInfoPtr cpuinfo,
                       int ncpuinfo)
{
    size_t i;
    int nonline = 0;
    int nofflinable = 0;
    ssize_t cpu0 = -1;

    /* count the active and offlinable cpus */
    for (i = 0; i < ncpuinfo; i++) {
        if (cpuinfo[i].id == 0)
            cpu0 = i;

        if (cpuinfo[i].online)
            nonline++;

        if (cpuinfo[i].offlinable && cpuinfo[i].online)
            nofflinable++;

        /* This shouldn't happen, but we can't trust the guest agent */
        if (!cpuinfo[i].online && !cpuinfo[i].offlinable) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid data provided by guest agent"));
            return -1;
        }
    }

    /* CPU0 was made offlinable in linux a while ago, but certain parts (suspend
     * to ram) of the kernel still don't cope well with that. Make sure that if
     * all remaining vCPUs are offlinable, vCPU0 will not be selected to be
     * offlined automatically */
    if (nofflinable == nonline && cpu0 >= 0 && cpuinfo[cpu0].online) {
        cpuinfo[cpu0].offlinable = false;
        nofflinable--;
    }

    /* the guest agent reported less cpus than requested */
    if (nvcpus > ncpuinfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest agent reports less cpu than requested"));
        return -1;
    }

    /* not enough offlinable CPUs to support the request */
    if (nvcpus < nonline - nofflinable) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Cannot offline enough CPUs"));
        return -1;
    }

    for (i = 0; i < ncpuinfo; i++) {
        if (nvcpus < nonline) {
            /* unplug */
            if (cpuinfo[i].offlinable && cpuinfo[i].online) {
                cpuinfo[i].online = false;
                cpuinfo[i].modified = true;
                nonline--;
            }
        } else if (nvcpus > nonline) {
            /* plug */
            if (!cpuinfo[i].online) {
                cpuinfo[i].online = true;
                cpuinfo[i].modified = true;
                nonline++;
            }
        } else {
            /* done */
            break;
        }
    }

    return 0;
}


int
qemuAgentGetHostname(qemuAgentPtr agent,
                     char **hostname)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data = NULL;
    const char *result = NULL;

    cmd = qemuAgentMakeCommand("guest-get-host-name",
                               NULL);

    if (!cmd)
        return ret;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0) {
        if (qemuAgentErrorCommandUnsupported(reply))
            ret = -2;
        goto cleanup;
    }

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        goto cleanup;
    }

    if (!(result = virJSONValueObjectGetString(data, "host-name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'host-name' missing in guest-get-host-name reply"));
        goto cleanup;
    }

    *hostname = g_strdup(result);

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuAgentGetTime(qemuAgentPtr agent,
                 long long *seconds,
                 unsigned int *nseconds)
{
    int ret = -1;
    unsigned long long json_time;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-get-time",
                               NULL);
    if (!cmd)
        return ret;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberUlong(reply, "return", &json_time) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        goto cleanup;
    }

    /* guest agent returns time in nanoseconds,
     * we need it in seconds here */
    *seconds = json_time / 1000000000LL;
    *nseconds = json_time % 1000000000LL;
    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/**
 * qemuAgentSetTime:
 * @setTime: time to set
 * @sync: let guest agent to read domain's RTC (@setTime is ignored)
 */
int
qemuAgentSetTime(qemuAgentPtr agent,
                long long seconds,
                unsigned int nseconds,
                bool rtcSync)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (rtcSync) {
        cmd = qemuAgentMakeCommand("guest-set-time", NULL);
    } else {
        /* guest agent expect time with nanosecond granularity.
         * Impressing. */
        long long json_time;

        /* Check if we overflow. For some reason qemu doesn't handle unsigned
         * long long on the agent well as it silently truncates numbers to
         * signed long long. Therefore we must check overflow against LLONG_MAX
         * not ULLONG_MAX. */
        if (seconds > LLONG_MAX / 1000000000LL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Time '%lld' is too big for guest agent"),
                           seconds);
            return ret;
        }

        json_time = seconds * 1000000000LL;
        json_time += nseconds;
        cmd = qemuAgentMakeCommand("guest-set-time",
                                   "I:time", json_time,
                                   NULL);
    }

    if (!cmd)
        return ret;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

static void
qemuAgentDiskInfoFree(qemuAgentDiskInfoPtr info)
{
    if (!info)
        return;

    g_free(info->serial);
    g_free(info->bus_type);
    g_free(info->devnode);
    g_free(info);
}

void
qemuAgentFSInfoFree(qemuAgentFSInfoPtr info)
{
    size_t i;

    if (!info)
        return;

    g_free(info->mountpoint);
    g_free(info->name);
    g_free(info->fstype);

    for (i = 0; i < info->ndisks; i++)
        qemuAgentDiskInfoFree(info->disks[i]);
    g_free(info->disks);

    g_free(info);
}

static int
qemuAgentGetFSInfoFillDisks(virJSONValuePtr jsondisks,
                            qemuAgentFSInfoPtr fsinfo)
{
    size_t ndisks;
    size_t i;

    if (!virJSONValueIsArray(jsondisks)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed guest-get-fsinfo 'disk' data array"));
        return -1;
    }

    ndisks = virJSONValueArraySize(jsondisks);

    if (ndisks)
        fsinfo->disks = g_new0(qemuAgentDiskInfoPtr, ndisks);
    fsinfo->ndisks = ndisks;

    for (i = 0; i < fsinfo->ndisks; i++) {
        virJSONValuePtr jsondisk = virJSONValueArrayGet(jsondisks, i);
        virJSONValuePtr pci;
        qemuAgentDiskInfoPtr disk;
        const char *val;

        if (!jsondisk) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("array element '%zd' of '%zd' missing in "
                             "guest-get-fsinfo 'disk' data"),
                           i, fsinfo->ndisks);
            return -1;
        }

        fsinfo->disks[i] = g_new0(qemuAgentDiskInfo, 1);
        disk = fsinfo->disks[i];

        if ((val = virJSONValueObjectGetString(jsondisk, "bus-type")))
            disk->bus_type = g_strdup(val);

        if ((val = virJSONValueObjectGetString(jsondisk, "serial")))
            disk->serial = g_strdup(val);

        if ((val = virJSONValueObjectGetString(jsondisk, "dev")))
            disk->devnode = g_strdup(val);

#define GET_DISK_ADDR(jsonObject, var, name) \
        do { \
            if (virJSONValueObjectGetNumberUint(jsonObject, name, var) < 0) { \
                virReportError(VIR_ERR_INTERNAL_ERROR, \
                               _("'%s' missing in guest-get-fsinfo " \
                                 "'disk' data"), name); \
                return -1; \
            } \
        } while (0)

        GET_DISK_ADDR(jsondisk, &disk->bus, "bus");
        GET_DISK_ADDR(jsondisk, &disk->target, "target");
        GET_DISK_ADDR(jsondisk, &disk->unit, "unit");

        if (!(pci = virJSONValueObjectGet(jsondisk, "pci-controller"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'pci-controller' missing in guest-get-fsinfo "
                             "'disk' data"));
            return -1;
        }

        GET_DISK_ADDR(pci, &disk->pci_controller.domain, "domain");
        GET_DISK_ADDR(pci, &disk->pci_controller.bus, "bus");
        GET_DISK_ADDR(pci, &disk->pci_controller.slot, "slot");
        GET_DISK_ADDR(pci, &disk->pci_controller.function, "function");
#undef GET_DISK_ADDR
    }

    return 0;
}

/* Returns: number of entries in '@info' on success
 *          -2 when agent command is not supported by the agent
 *          -1 otherwise
 */
int
qemuAgentGetFSInfo(qemuAgentPtr agent,
                   qemuAgentFSInfoPtr **info)
{
    size_t i;
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValuePtr data;
    size_t ndata = 0;
    qemuAgentFSInfoPtr *info_ret = NULL;

    cmd = qemuAgentMakeCommand("guest-get-fsinfo", NULL);
    if (!cmd)
        return ret;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0) {
        if (qemuAgentErrorCommandUnsupported(reply))
            ret = -2;
        goto cleanup;
    }

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-fsinfo reply was missing return data"));
        goto cleanup;
    }

    if (!virJSONValueIsArray(data)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed guest-get-fsinfo data array"));
        goto cleanup;
    }

    ndata = virJSONValueArraySize(data);
    if (ndata == 0) {
        ret = 0;
        *info = NULL;
        goto cleanup;
    }
    info_ret = g_new0(qemuAgentFSInfoPtr, ndata);

    for (i = 0; i < ndata; i++) {
        /* Reverse the order to arrange in mount order */
        virJSONValuePtr entry = virJSONValueArrayGet(data, ndata - 1 - i);
        virJSONValuePtr disk;
        unsigned long long bytes_val;
        const char *result = NULL;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("array element '%zd' of '%zd' missing in "
                             "guest-get-fsinfo return data"),
                           i, ndata);
            goto cleanup;
        }

        info_ret[i] = g_new0(qemuAgentFSInfo, 1);

        if (!(result = virJSONValueObjectGetString(entry, "mountpoint"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'mountpoint' missing in reply of "
                             "guest-get-fsinfo"));
            goto cleanup;
        }

        info_ret[i]->mountpoint = g_strdup(result);

        if (!(result = virJSONValueObjectGetString(entry, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'name' missing in reply of guest-get-fsinfo"));
            goto cleanup;
        }

        info_ret[i]->name = g_strdup(result);

        if (!(result = virJSONValueObjectGetString(entry, "type"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'type' missing in reply of guest-get-fsinfo"));
            goto cleanup;
        }

        info_ret[i]->fstype = g_strdup(result);


        /* 'used-bytes' and 'total-bytes' were added in qemu-ga 3.0 */
        if (virJSONValueObjectHasKey(entry, "used-bytes")) {
            if (virJSONValueObjectGetNumberUlong(entry, "used-bytes",
                                                 &bytes_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Error getting 'used-bytes' in reply of guest-get-fsinfo"));
                goto cleanup;
            }
            info_ret[i]->used_bytes = bytes_val;
        } else {
            info_ret[i]->used_bytes = -1;
        }

        if (virJSONValueObjectHasKey(entry, "total-bytes")) {
            if (virJSONValueObjectGetNumberUlong(entry, "total-bytes",
                                                 &bytes_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Error getting 'total-bytes' in reply of guest-get-fsinfo"));
                goto cleanup;
            }
            info_ret[i]->total_bytes = bytes_val;
        } else {
            info_ret[i]->total_bytes = -1;
        }

        if (!(disk = virJSONValueObjectGet(entry, "disk"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'disk' missing in reply of guest-get-fsinfo"));
            goto cleanup;
        }

        if (qemuAgentGetFSInfoFillDisks(disk, info_ret[i]) < 0)
            goto cleanup;
    }

    *info = g_steal_pointer(&info_ret);
    ret = ndata;

 cleanup:
    if (info_ret) {
        for (i = 0; i < ndata; i++)
            qemuAgentFSInfoFree(info_ret[i]);
        g_free(info_ret);
    }
    return ret;
}

/*
 * qemuAgentGetInterfaces:
 * @agent: agent object
 * @ifaces: pointer to an array of pointers pointing to interface objects
 *
 * Issue guest-network-get-interfaces to guest agent, which returns a
 * list of interfaces of a running domain along with their IP and MAC
 * addresses.
 *
 * Returns: number of interfaces on success, -1 on error.
 */
int
qemuAgentGetInterfaces(qemuAgentPtr agent,
                       virDomainInterfacePtr **ifaces)
{
    int ret = -1;
    size_t i, j;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr ret_array = NULL;
    size_t ifaces_count = 0;
    size_t addrs_count = 0;
    virDomainInterfacePtr *ifaces_ret = NULL;
    virHashTablePtr ifaces_store = NULL;
    char **ifname = NULL;

    /* Hash table to handle the interface alias */
    if (!(ifaces_store = virHashCreate(ifaces_count, NULL))) {
        virHashFree(ifaces_store);
        return -1;
    }

    if (!(cmd = qemuAgentMakeCommand("guest-network-get-interfaces", NULL)))
        goto cleanup;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        goto cleanup;

    if (!(ret_array = virJSONValueObjectGet(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't provide 'return' field"));
        goto cleanup;
    }

    if (!virJSONValueIsArray(ret_array)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't return an array of interfaces"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(ret_array); i++) {
        virJSONValuePtr tmp_iface = virJSONValueArrayGet(ret_array, i);
        virJSONValuePtr ip_addr_arr = NULL;
        const char *hwaddr, *ifname_s, *name = NULL;
        virDomainInterfacePtr iface = NULL;

        /* Shouldn't happen but doesn't hurt to check neither */
        if (!tmp_iface) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu agent reply missing interface entry in array"));
            goto error;
        }

        /* interface name is required to be presented */
        name = virJSONValueObjectGetString(tmp_iface, "name");
        if (!name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu agent didn't provide 'name' field"));
            goto error;
        }

        /* Handle interface alias (<ifname>:<alias>) */
        ifname = virStringSplit(name, ":", 2);
        ifname_s = ifname[0];

        iface = virHashLookup(ifaces_store, ifname_s);

        /* If the hash table doesn't contain this iface, add it */
        if (!iface) {
            if (VIR_EXPAND_N(ifaces_ret, ifaces_count, 1) < 0)
                goto error;

            if (VIR_ALLOC(ifaces_ret[ifaces_count - 1]) < 0)
                goto error;

            if (virHashAddEntry(ifaces_store, ifname_s,
                                ifaces_ret[ifaces_count - 1]) < 0)
                goto error;

            iface = ifaces_ret[ifaces_count - 1];
            iface->naddrs = 0;

            iface->name = g_strdup(ifname_s);

            hwaddr = virJSONValueObjectGetString(tmp_iface, "hardware-address");
            iface->hwaddr = g_strdup(hwaddr);
        }

        /* Has to be freed for each interface. */
        virStringListFree(ifname);

        /* as well as IP address which - moreover -
         * can be presented multiple times */
        ip_addr_arr = virJSONValueObjectGet(tmp_iface, "ip-addresses");
        if (!ip_addr_arr)
            continue;

        if (!virJSONValueIsArray(ip_addr_arr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed ip-addresses array"));
            goto error;
        }

        /* If current iface already exists, continue with the count */
        addrs_count = iface->naddrs;

        for (j = 0; j < virJSONValueArraySize(ip_addr_arr); j++) {
            const char *type, *addr;
            virJSONValuePtr ip_addr_obj = virJSONValueArrayGet(ip_addr_arr, j);
            virDomainIPAddressPtr ip_addr;

            if (VIR_EXPAND_N(iface->addrs, addrs_count, 1)  < 0)
                goto error;

            ip_addr = &iface->addrs[addrs_count - 1];

            /* Shouldn't happen but doesn't hurt to check neither */
            if (!ip_addr_obj) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("qemu agent reply missing IP addr in array"));
                goto error;
            }

            type = virJSONValueObjectGetString(ip_addr_obj, "ip-address-type");
            if (!type) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("qemu agent didn't provide 'ip-address-type'"
                                 " field for interface '%s'"), name);
                goto error;
            } else if (STREQ(type, "ipv4")) {
                ip_addr->type = VIR_IP_ADDR_TYPE_IPV4;
            } else if (STREQ(type, "ipv6")) {
                ip_addr->type = VIR_IP_ADDR_TYPE_IPV6;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown ip address type '%s'"),
                               type);
                goto error;
            }

            addr = virJSONValueObjectGetString(ip_addr_obj, "ip-address");
            if (!addr) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("qemu agent didn't provide 'ip-address'"
                                 " field for interface '%s'"), name);
                goto error;
            }
            ip_addr->addr = g_strdup(addr);

            if (virJSONValueObjectGetNumberUint(ip_addr_obj, "prefix",
                                                &ip_addr->prefix) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed 'prefix' field"));
                goto error;
            }
        }

        iface->naddrs = addrs_count;
    }

    *ifaces = g_steal_pointer(&ifaces_ret);
    ret = ifaces_count;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virHashFree(ifaces_store);
    return ret;

 error:
    if (ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces_ret[i]);
    }
    VIR_FREE(ifaces_ret);
    virStringListFree(ifname);

    goto cleanup;
}


int
qemuAgentSetUserPassword(qemuAgentPtr agent,
                         const char *user,
                         const char *password,
                         bool crypted)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autofree char *password64 = NULL;

    password64 = g_base64_encode((unsigned char *)password,
                                 strlen(password));

    if (!(cmd = qemuAgentMakeCommand("guest-set-user-password",
                                     "b:crypted", crypted,
                                     "s:username", user,
                                     "s:password", password64,
                                     NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    return 0;
}

/* Returns: 0 on success
 *          -2 when agent command is not supported by the agent
 *          -1 otherwise
 */
int
qemuAgentGetUsers(qemuAgentPtr agent,
                  virTypedParameterPtr *params,
                  int *nparams,
                  int *maxparams)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValuePtr data = NULL;
    size_t ndata;
    size_t i;

    if (!(cmd = qemuAgentMakeCommand("guest-get-users", NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0) {
        if (qemuAgentErrorCommandUnsupported(reply))
            return -2;
        return -1;
    }

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-users reply was missing return data"));
        return -1;
    }

    if (!virJSONValueIsArray(data)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed guest-get-users data array"));
        return -1;
    }

    ndata = virJSONValueArraySize(data);

    if (virTypedParamsAddUInt(params, nparams, maxparams,
                              "user.count", ndata) < 0)
        return -1;

    for (i = 0; i < ndata; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        char param_name[VIR_TYPED_PARAM_FIELD_LENGTH];
        const char *strvalue;
        double logintime;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("array element missing in guest-get-users return "
                             "value"));
            return -1;
        }

        if (!(strvalue = virJSONValueObjectGetString(entry, "user"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'user' missing in reply of guest-get-users"));
            return -1;
        }

        g_snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH, "user.%zu.name", i);
        if (virTypedParamsAddString(params, nparams, maxparams,
                                    param_name, strvalue) < 0)
            return -1;

        /* 'domain' is only present for windows guests */
        if ((strvalue = virJSONValueObjectGetString(entry, "domain"))) {
            g_snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
                       "user.%zu.domain", i);
            if (virTypedParamsAddString(params, nparams, maxparams,
                                        param_name, strvalue) < 0)
                return -1;
        }

        if (virJSONValueObjectGetNumberDouble(entry, "login-time", &logintime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'login-time' missing in reply of guest-get-users"));
            return -1;
        }
        g_snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
                   "user.%zu.login-time", i);
        if (virTypedParamsAddULLong(params, nparams, maxparams,
                                    param_name, logintime * 1000) < 0)
            return -1;
    }

    return ndata;
}

/* Returns: 0 on success
 *          -2 when agent command is not supported by the agent
 *          -1 otherwise
 */
int
qemuAgentGetOSInfo(qemuAgentPtr agent,
                   virTypedParameterPtr *params,
                   int *nparams,
                   int *maxparams)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValuePtr data = NULL;

    if (!(cmd = qemuAgentMakeCommand("guest-get-osinfo", NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0) {
        if (qemuAgentErrorCommandUnsupported(reply))
            return -2;
        return -1;
    }

    if (!(data = virJSONValueObjectGetObject(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-osinfo reply was missing return data"));
        return -1;
    }

#define OSINFO_ADD_PARAM(agent_string_, param_string_) \
    do { \
        const char *result; \
        if ((result = virJSONValueObjectGetString(data, agent_string_))) { \
            if (virTypedParamsAddString(params, nparams, maxparams, \
                                        param_string_, result) < 0) { \
                return -1; \
            } \
        } \
    } while (0)
    OSINFO_ADD_PARAM("id", "os.id");
    OSINFO_ADD_PARAM("name", "os.name");
    OSINFO_ADD_PARAM("pretty-name", "os.pretty-name");
    OSINFO_ADD_PARAM("version", "os.version");
    OSINFO_ADD_PARAM("version-id", "os.version-id");
    OSINFO_ADD_PARAM("machine", "os.machine");
    OSINFO_ADD_PARAM("variant", "os.variant");
    OSINFO_ADD_PARAM("variant-id", "os.variant-id");
    OSINFO_ADD_PARAM("kernel-release", "os.kernel-release");
    OSINFO_ADD_PARAM("kernel-version", "os.kernel-version");

    return 0;
}

/* Returns: 0 on success
 *          -2 when agent command is not supported by the agent
 *          -1 otherwise
 */
int
qemuAgentGetTimezone(qemuAgentPtr agent,
                     virTypedParameterPtr *params,
                     int *nparams,
                     int *maxparams)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValuePtr data = NULL;
    const char *name;
    int offset;

    if (!(cmd = qemuAgentMakeCommand("guest-get-timezone", NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0) {
        if (qemuAgentErrorCommandUnsupported(reply))
            return -2;
        return -1;
    }

    if (!(data = virJSONValueObjectGetObject(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-timezone reply was missing return data"));
        return -1;
    }

    if ((name = virJSONValueObjectGetString(data, "zone")) &&
        virTypedParamsAddString(params, nparams, maxparams,
                                "timezone.name", name) < 0)
        return -1;

    if ((virJSONValueObjectGetNumberInt(data, "offset", &offset)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'offset' missing in reply of guest-get-timezone"));
        return -1;
    }

    if (virTypedParamsAddInt(params, nparams, maxparams,
                             "timezone.offset", offset) < 0)
        return -1;

    return 0;
}

/* qemuAgentSetResponseTimeout:
 * @agent: agent object
 * @timeout: number of seconds to wait for agent response
 *
 * The agent object must be locked prior to calling this function.
 */
void
qemuAgentSetResponseTimeout(qemuAgentPtr agent,
                            int timeout)
{
    agent->timeout = timeout;
}
