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
#include "virtime.h"
#include "virobject.h"
#include "virstring.h"
#include "virenum.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_agent");

#define LINE_ENDING "\n"

/* We read from QEMU until seeing a \r\n pair to indicate a
 * completed reply or event. To avoid memory denial-of-service
 * though, we must have a size limit on amount of data we
 * buffer. 10 MB is large enough that it ought to cope with
 * normal QEMU replies, and small enough that we're not
 * consuming unreasonable mem.
 */
#define QEMU_AGENT_MAX_RESPONSE (10 * 1024 * 1024)

typedef struct _qemuAgentMessage qemuAgentMessage;
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
    /* id of the issued sync command */
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
    bool inSync;

    virDomainObj *vm;

    qemuAgentCallbacks *cb;

    /* If there's a command being processed this will be
     * non-NULL */
    qemuAgentMessage *msg;

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

static virClass *qemuAgentClass;
static void qemuAgentDispose(void *obj);

static int qemuAgentOnceInit(void)
{
    if (!VIR_CLASS_NEW(qemuAgent, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(qemuAgent);



static void qemuAgentDispose(void *obj)
{
    qemuAgent *agent = obj;

    VIR_DEBUG("agent=%p", agent);

    if (agent->vm)
        virObjectUnref(agent->vm);
    virCondDestroy(&agent->notify);
    g_free(agent->buffer);
    g_main_context_unref(agent->context);
    virResetError(&agent->lastError);
}

static int
qemuAgentOpenUnix(const char *socketpath)
{
    struct sockaddr_un addr = { 0 };
    int agentfd;

    if ((agentfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    if (virSetCloseExec(agentfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set agent close-on-exec flag"));
        goto error;
    }

    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, socketpath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Socket path %1$s too big for destination"), socketpath);
        goto error;
    }

    if (connect(agentfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
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
qemuAgentIOProcessEvent(qemuAgent *agent,
                        virJSONValue *obj)
{
    const char *type;
    VIR_DEBUG("agent=%p obj=%p", agent, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int
qemuAgentIOProcessLine(qemuAgent *agent,
                       const char *line,
                       qemuAgentMessage *msg)
{
    g_autoptr(virJSONValue) obj = NULL;

    VIR_DEBUG("Line [%s]", line);

    if (!(obj = virJSONValueFromString(line))) {
        /* receiving garbage on first sync is regular situation */
        if (msg && msg->sync && msg->first) {
            VIR_DEBUG("Received garbage on sync");
            msg->finished = true;
            return 0;
        }

        return -1;
    }

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parsed JSON reply '%1$s' isn't an object"), line);
        return -1;
    }

    if (virJSONValueObjectHasKey(obj, "QMP")) {
        return 0;
    } else if (virJSONValueObjectHasKey(obj, "event")) {
        return qemuAgentIOProcessEvent(agent, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") ||
               virJSONValueObjectHasKey(obj, "return")) {
        if (msg) {
            if (msg->sync) {
                unsigned long long id;

                if (virJSONValueObjectGetNumberUlong(obj, "return", &id) < 0) {
                    VIR_DEBUG("Ignoring delayed reply on sync");
                    return 0;
                }

                VIR_DEBUG("Guest returned ID: %llu", id);

                if (msg->id != id) {
                    VIR_DEBUG("Guest agent returned ID: %llu instead of %llu",
                              id, msg->id);
                    return 0;
                }
            }
            msg->rxObject = g_steal_pointer(&obj);
            msg->finished = true;
        } else {
            /* we are out of sync */
            VIR_DEBUG("Ignoring delayed reply");
        }

        return 0;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unknown JSON reply '%1$s'"), line);
    return -1;
}

static int qemuAgentIOProcessData(qemuAgent *agent,
                                  char *data,
                                  size_t len,
                                  qemuAgentMessage *msg)
{
    int used = 0;
    size_t i = 0;

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
qemuAgentIOProcess(qemuAgent *agent)
{
    int len;
    qemuAgentMessage *msg = NULL;

    /* See if there's a message ready for reply; that is,
     * one that has completed writing all its data.
     */
    if (agent->msg && agent->msg->txOffset == agent->msg->txLength)
        msg = agent->msg;

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
    if (msg && msg->finished)
        virCondBroadcast(&agent->notify);
    return len;
}


/*
 * Called when the agent is able to write data
 * Call this function while holding the agent lock.
 */
static int
qemuAgentIOWrite(qemuAgent *agent)
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
qemuAgentIORead(qemuAgent *agent)
{
    size_t avail = agent->bufferLength - agent->bufferOffset;
    int ret = 0;

    if (avail < 1024) {
        if (agent->bufferLength >= QEMU_AGENT_MAX_RESPONSE) {
            virReportSystemError(ERANGE,
                                 _("No complete agent response found in %1$d bytes"),
                                 QEMU_AGENT_MAX_RESPONSE);
            return -1;
        }
        VIR_REALLOC_N(agent->buffer, agent->bufferLength + 1024);
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

    return ret;
}


static gboolean
qemuAgentIO(GSocket *socket,
            GIOCondition cond,
            gpointer opaque);


static void
qemuAgentRegister(qemuAgent *agent)
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
qemuAgentUnregister(qemuAgent *agent)
{
    if (agent->watch) {
        g_source_destroy(agent->watch);
        vir_g_source_unref(agent->watch, agent->context);
        agent->watch = NULL;
    }
}


static void qemuAgentUpdateWatch(qemuAgent *agent)
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
    qemuAgent *agent = opaque;
    bool error = false;
    bool eof = false;

    virObjectRef(agent);
    /* lock access to the agent and protect fd */
    virObjectLock(agent);

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
            agent->msg->finished = true;
            virCondSignal(&agent->notify);
        }
    }

    qemuAgentUpdateWatch(agent);

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObj *mutex next */
    if (eof) {
        void (*eofNotify)(qemuAgent *, virDomainObj *)
            = agent->cb->eofNotify;
        virDomainObj *vm = agent->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&agent->notify);
        virObjectUnlock(agent);
        virObjectUnref(agent);
        VIR_DEBUG("Triggering EOF callback");
        (eofNotify)(agent, vm);
    } else if (error) {
        void (*errorNotify)(qemuAgent *, virDomainObj *)
            = agent->cb->errorNotify;
        virDomainObj *vm = agent->vm;

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


qemuAgent *
qemuAgentOpen(virDomainObj *vm,
              const virDomainChrSourceDef *config,
              GMainContext *context,
              qemuAgentCallbacks *cb)
{
    qemuAgent *agent;
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
    agent->vm = virObjectRef(vm);
    agent->cb = cb;

    if (config->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to handle agent type: %1$s"),
                       virDomainChrTypeToString(config->type));
        goto cleanup;
    }

    virObjectUnlock(vm);
    agent->fd = qemuAgentOpenUnix(config->data.nix.path);
    virObjectLock(vm);

    if (agent->fd == -1)
        goto cleanup;

    agent->context = g_main_context_ref(context);

    agent->socket = g_socket_new_from_fd(agent->fd, &gerr);
    if (!agent->socket) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to create socket object: %1$s"),
                       gerr->message);
        goto cleanup;
    }

    qemuAgentRegister(agent);

    agent->running = true;
    VIR_DEBUG("New agent %p fd=%d", agent, agent->fd);

    return agent;

 cleanup:
    qemuAgentClose(agent);
    return NULL;
}


static void
qemuAgentNotifyCloseLocked(qemuAgent *agent)
{
    if (agent) {
        agent->running = false;

        /* If there is somebody waiting for a message
         * wake him up. No message will arrive anyway. */
        if (agent->msg && !agent->msg->finished) {
            agent->msg->finished = true;
            virCondSignal(&agent->notify);
        }
    }
}


void
qemuAgentNotifyClose(qemuAgent *agent)
{
    if (!agent)
        return;

    VIR_DEBUG("agent=%p", agent);

    VIR_WITH_OBJECT_LOCK_GUARD(agent) {
        qemuAgentNotifyCloseLocked(agent);
    }
}


void qemuAgentClose(qemuAgent *agent)
{
    if (!agent)
        return;

    VIR_DEBUG("agent=%p", agent);

    VIR_WITH_OBJECT_LOCK_GUARD(agent) {
        if (agent->socket) {
            qemuAgentUnregister(agent);
            g_clear_pointer(&agent->socket, g_object_unref);
            agent->fd = -1;
        }

        qemuAgentNotifyCloseLocked(agent);
    }

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
static int qemuAgentSend(qemuAgent *agent,
                         qemuAgentMessage *msg,
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
                                     _("Unable to wait on agent socket condition"));
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
 * qemuAgentGuestSyncSend:
 * @agent: agent object
 * @timeout: timeout for the command
 * @first: true when this is the first invocation to drain possible leftovers
 *         from the pipe
 *
 * Sends a sync request to the guest agent.
 * Returns: -1 on error
 *           0 on successful send, but when no reply was received
 *           1 when a reply was received
 */
static int
qemuAgentGuestSyncSend(qemuAgent *agent,
                       int timeout,
                       bool first)
{
    g_autofree char *txMsg = NULL;
    g_autoptr(virJSONValue) rxObj = NULL;
    unsigned long long id;
    qemuAgentMessage sync_msg = { 0 };
    int rc;

    if (virTimeMillisNow(&id) < 0)
        return -1;

    txMsg = g_strdup_printf("{\"execute\":\"guest-sync\", "
                             "\"arguments\":{\"id\":%llu}}\n", id);

    sync_msg.txBuffer = txMsg;
    sync_msg.txLength = strlen(txMsg);
    sync_msg.sync = true;
    sync_msg.id = id;
    sync_msg.first = first;

    VIR_DEBUG("Sending guest-sync command with ID: %llu", id);

    rc = qemuAgentSend(agent, &sync_msg, timeout);
    rxObj = g_steal_pointer(&sync_msg.rxObject);

    VIR_DEBUG("qemuAgentSend returned: %d", rc);

    if (rc < 0)
        return -1;

    if (rxObj)
        return 1;

    return 0;
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
qemuAgentGuestSync(qemuAgent *agent)
{
    int timeout = VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT;
    int rc;

    if (agent->inSync)
        return 0;

    /* if user specified a custom agent timeout that is lower than the
     * default timeout, use the shorter timeout instead */
    if ((agent->timeout >= 0) && (agent->timeout < QEMU_AGENT_WAIT_TIME))
        timeout = agent->timeout;

    if ((rc = qemuAgentGuestSyncSend(agent, timeout, true)) < 0)
        return -1;

    /* successfully sync'd */
    if (rc == 1) {
        agent->inSync = true;
        return 0;
    }

    /* send another sync */
    if ((rc = qemuAgentGuestSyncSend(agent, timeout, false)) < 0)
        return -1;

    /* successfully sync'd */
    if (rc == 1) {
        agent->inSync = true;
        return 0;
    }

    if (agent->running)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing agent reply object"));
    else
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("Guest agent disappeared while executing command"));

    return -1;
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

/* Ignoring OOM in this method, since we're already reporting
 * a more important error
 *
 * XXX see qerror.h for different klasses & fill out useful params
 */
static const char *
qemuAgentStringifyError(virJSONValue *error)
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
qemuAgentCommandName(virJSONValue *cmd)
{
    const char *name = virJSONValueObjectGetString(cmd, "execute");
    if (name)
        return name;
    return "<unknown>";
}

static int
qemuAgentCheckError(virJSONValue *cmd,
                    virJSONValue *reply,
                    bool report_unsupported)
{
    if (virJSONValueObjectHasKey(reply, "error")) {
        virJSONValue *error = virJSONValueObjectGet(reply, "error");
        g_autofree char *cmdstr = virJSONValueToString(cmd, false);
        g_autofree char *replystr = virJSONValueToString(reply, false);

        /* Log the full JSON formatted command & error */
        VIR_DEBUG("unable to execute QEMU agent command %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));

        /* Only send the user the command name + friendly error */
        if (!error) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU agent command '%1$s'"),
                           qemuAgentCommandName(cmd));
            return -1;
        }

        if (!report_unsupported) {
            const char *klass = virJSONValueObjectGetString(error, "class");

            if (STREQ_NULLABLE(klass, "CommandNotFound") ||
                STREQ_NULLABLE(klass, "CommandDisabled"))
                return -2;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to execute QEMU agent command '%1$s': %2$s"),
                       qemuAgentCommandName(cmd),
                       qemuAgentStringifyError(error));

        return -1;
    }
    if (!virJSONValueObjectHasKey(reply, "return")) {
        g_autofree char *cmdstr = virJSONValueToString(cmd, false);
        g_autofree char *replystr = virJSONValueToString(reply, false);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to execute QEMU agent command '%1$s'"),
                       qemuAgentCommandName(cmd));
        return -1;
    }
    return 0;
}

static int
qemuAgentCommandFull(qemuAgent *agent,
                     virJSONValue *cmd,
                     virJSONValue **reply,
                     int seconds,
                     bool report_unsupported)
{
    int ret = -1;
    qemuAgentMessage msg = { 0 };
    g_autofree char *cmdstr = NULL;
    int await_event = agent->await_event;

    *reply = NULL;

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
    ret = qemuAgentCheckError(cmd, *reply, report_unsupported);

 cleanup:
    VIR_FREE(msg.txBuffer);
    agent->await_event = QEMU_AGENT_EVENT_NONE;

    return ret;
}

static int
qemuAgentCommand(qemuAgent *agent,
                 virJSONValue *cmd,
                 virJSONValue **reply,
                 int seconds)
{
    return qemuAgentCommandFull(agent, cmd, reply, seconds, true);
}

static virJSONValue *G_GNUC_NULL_TERMINATED
qemuAgentMakeCommand(const char *cmdname,
                     ...)
{
    g_autoptr(virJSONValue) obj = NULL;
    g_autoptr(virJSONValue) jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (virJSONValueObjectAddVArgs(&jargs, args) < 0) {
        va_end(args);
        return NULL;
    }

    va_end(args);

    if (virJSONValueObjectAdd(&obj,
                              "s:execute", cmdname,
                              "A:arguments", &jargs,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&obj);
}

static virJSONValue *
qemuAgentMakeStringsArray(const char **strings, unsigned int len)
{
    size_t i;
    g_autoptr(virJSONValue) ret = virJSONValueNewArray();

    for (i = 0; i < len; i++) {
        if (virJSONValueArrayAppendString(ret, strings[i]) < 0)
            return NULL;
    }

    return g_steal_pointer(&ret);
}

void qemuAgentNotifyEvent(qemuAgent *agent,
                          qemuAgentEvent event)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(agent);

    VIR_DEBUG("agent=%p event=%d await_event=%d", agent, event, agent->await_event);
    if (agent->await_event == event) {
        agent->await_event = QEMU_AGENT_EVENT_NONE;
        /* somebody waiting for this event, wake him up. */
        if (agent->msg && !agent->msg->finished) {
            agent->msg->finished = true;
            virCondSignal(&agent->notify);
        }
    }
}

VIR_ENUM_DECL(qemuAgentShutdownMode);

VIR_ENUM_IMPL(qemuAgentShutdownMode,
              QEMU_AGENT_SHUTDOWN_LAST,
              "powerdown", "reboot", "halt",
);

int qemuAgentShutdown(qemuAgent *agent,
                      qemuAgentShutdownMode mode)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuAgentMakeCommand("guest-shutdown",
                               "s:mode", qemuAgentShutdownModeTypeToString(mode),
                               NULL);
    if (!cmd)
        return -1;

    if (mode == QEMU_AGENT_SHUTDOWN_REBOOT)
        agent->await_event = QEMU_AGENT_EVENT_RESET;
    else
        agent->await_event = QEMU_AGENT_EVENT_SHUTDOWN;

    return qemuAgentCommand(agent, cmd, &reply,
                            VIR_DOMAIN_QEMU_AGENT_COMMAND_SHUTDOWN);
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
int qemuAgentFSFreeze(qemuAgent *agent, const char **mountpoints,
                      unsigned int nmountpoints)
{
    int nfrozen = 0;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (mountpoints && nmountpoints) {
        g_autoptr(virJSONValue) arg = qemuAgentMakeStringsArray(mountpoints, nmountpoints);
        if (!arg)
            return -1;

        cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze-list",
                                   "a:mountpoints", &arg, NULL);
    } else {
        cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze", NULL);
    }

    if (!cmd)
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    if (virJSONValueObjectGetNumberInt(reply, "return", &nfrozen) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        return -1;
    }

    return nfrozen;
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
int qemuAgentFSThaw(qemuAgent *agent)
{
    int nthawed = 0;
    g_autoptr(virJSONValue) cmd = qemuAgentMakeCommand("guest-fsfreeze-thaw", NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    if (virJSONValueObjectGetNumberInt(reply, "return", &nthawed) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        return -1;
    }

    return nthawed;
}

VIR_ENUM_DECL(qemuAgentSuspendMode);

VIR_ENUM_IMPL(qemuAgentSuspendMode,
              VIR_NODE_SUSPEND_TARGET_LAST,
              "guest-suspend-ram",
              "guest-suspend-disk",
              "guest-suspend-hybrid",
);

int
qemuAgentSuspend(qemuAgent *agent,
                 unsigned int target)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuAgentMakeCommand(qemuAgentSuspendModeTypeToString(target),
                               NULL);
    if (!cmd)
        return -1;

    agent->await_event = QEMU_AGENT_EVENT_SUSPEND;

    return qemuAgentCommand(agent, cmd, &reply, agent->timeout);
}

int
qemuAgentArbitraryCommand(qemuAgent *agent,
                          const char *cmd_str,
                          char **result,
                          int timeout)
{
    int rc;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    *result = NULL;
    if (timeout < VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("guest agent timeout '%1$d' is less than the minimum '%2$d'"),
                       timeout, VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN);
        return -1;
    }

    if (!(cmd = virJSONValueFromString(cmd_str)))
        return -1;

    if ((rc = qemuAgentCommand(agent, cmd, &reply, timeout)) < 0)
        return rc;

    if (!(*result = virJSONValueToString(reply, false)))
        return -1;

    return rc;
}

int
qemuAgentFSTrim(qemuAgent *agent,
                unsigned long long minimum)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fstrim",
                               "U:minimum", minimum,
                               NULL);
    if (!cmd)
        return -1;

    return qemuAgentCommand(agent, cmd, &reply, agent->timeout);
}

int
qemuAgentGetVCPUs(qemuAgent *agent,
                  qemuAgentCPUInfo **info)
{
    size_t i;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    size_t ndata;

    if (!(cmd = qemuAgentMakeCommand("guest-get-vcpus", NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-vcpus reply was missing return data"));
        return -1;
    }

    ndata = virJSONValueArraySize(data);

    *info = g_new0(qemuAgentCPUInfo, ndata);

    for (i = 0; i < ndata; i++) {
        virJSONValue *entry = virJSONValueArrayGet(data, i);
        qemuAgentCPUInfo *in = *info + i;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("array element missing in guest-get-vcpus return value"));
            return -1;
        }

        if (virJSONValueObjectGetNumberUint(entry, "logical-id", &in->id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'logical-id' missing in reply of guest-get-vcpus"));
            return -1;
        }

        if (virJSONValueObjectGetBoolean(entry, "online", &in->online) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'online' missing in reply of guest-get-vcpus"));
            return -1;
        }

        in->offlinable = false;
        ignore_value(virJSONValueObjectGetBoolean(entry, "can-offline", &in->offlinable));
    }

    return ndata;
}


/* returns the value provided by the guest agent or -1 on internal error */
static int
qemuAgentSetVCPUsCommand(qemuAgent *agent,
                         qemuAgentCPUInfo *info,
                         size_t ninfo,
                         int *nmodified)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) cpus = virJSONValueNewArray();
    size_t i;
    int ret;

    *nmodified = 0;

    for (i = 0; i < ninfo; i++) {
        qemuAgentCPUInfo *in = &info[i];
        g_autoptr(virJSONValue) cpu = virJSONValueNewObject();

        /* don't set state for cpus that were not touched */
        if (!in->modified)
            continue;

        (*nmodified)++;

        if (virJSONValueObjectAppendNumberInt(cpu, "logical-id", in->id) < 0)
            return -1;

        if (virJSONValueObjectAppendBoolean(cpu, "online", in->online) < 0)
            return -1;

        if (virJSONValueArrayAppend(cpus, &cpu) < 0)
            return -1;
    }

    if (*nmodified == 0)
        return 0;

    if (!(cmd = qemuAgentMakeCommand("guest-set-vcpus",
                                     "a:vcpus", &cpus,
                                     NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    /* All negative values are invalid. Return of 0 is bogus since we wouldn't
     * call the guest agent so that 0 cpus would be set successfully. Reporting
     * more successfully set vcpus that we've asked for is invalid. */
    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0 ||
        ret <= 0 || ret > *nmodified) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest agent returned malformed or invalid return value"));
        return -1;
    }

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
qemuAgentSetVCPUs(qemuAgent *agent,
                  qemuAgentCPUInfo *info,
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
                       qemuAgentCPUInfo *cpuinfo,
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


/**
 * qemuAgentGetHostname:
 *
 * Gets the guest hostname using the guest agent.
 *
 * Returns 0 on success and fills @hostname. On error -1 is returned with an
 * error reported and if '@report_unsupported' is false -2 is returned if the
 * guest agent does not support the command without reporting an error
 */
int
qemuAgentGetHostname(qemuAgent *agent,
                     char **hostname,
                     bool report_unsupported)
{
    g_autoptr(virJSONValue) cmd = qemuAgentMakeCommand("guest-get-host-name", NULL);
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    const char *result = NULL;
    int rc;

    if (!cmd)
        return -1;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        return -1;
    }

    if (!(result = virJSONValueObjectGetString(data, "host-name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'host-name' missing in guest-get-host-name reply"));
        return -1;
    }

    *hostname = g_strdup(result);

    return 0;
}


int
qemuAgentGetTime(qemuAgent *agent,
                 long long *seconds,
                 unsigned int *nseconds)
{
    unsigned long long json_time;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuAgentMakeCommand("guest-get-time",
                               NULL);
    if (!cmd)
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    if (virJSONValueObjectGetNumberUlong(reply, "return", &json_time) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        return -1;
    }

    /* guest agent returns time in nanoseconds,
     * we need it in seconds here */
    *seconds = json_time / 1000000000LL;
    *nseconds = json_time % 1000000000LL;
    return 0;
}


/**
 * qemuAgentSetTime:
 * @setTime: time to set
 * @sync: let guest agent to read domain's RTC (@setTime is ignored)
 */
int
qemuAgentSetTime(qemuAgent *agent,
                long long seconds,
                unsigned int nseconds,
                bool rtcSync)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

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
                           _("Time '%1$lld' is too big for guest agent"),
                           seconds);
            return -1;
        }

        json_time = seconds * 1000000000LL;
        json_time += nseconds;
        cmd = qemuAgentMakeCommand("guest-set-time",
                                   "I:time", json_time,
                                   NULL);
    }

    if (!cmd)
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    return 0;
}

void
qemuAgentDiskAddressFree(qemuAgentDiskAddress *info)
{
    if (!info)
        return;

    g_free(info->serial);
    g_free(info->bus_type);
    g_free(info->devnode);
    g_free(info->ccw_addr);
    g_free(info);
}


void
qemuAgentDiskInfoFree(qemuAgentDiskInfo *info)
{
    if (!info)
        return;

    g_free(info->name);
    g_strfreev(info->dependencies);
    qemuAgentDiskAddressFree(info->address);
    g_free(info->alias);
    g_free(info);
}


void
qemuAgentFSInfoFree(qemuAgentFSInfo *info)
{
    size_t i;

    if (!info)
        return;

    g_free(info->mountpoint);
    g_free(info->name);
    g_free(info->fstype);

    for (i = 0; i < info->ndisks; i++)
        qemuAgentDiskAddressFree(info->disks[i]);
    g_free(info->disks);

    g_free(info);
}


static qemuAgentDiskAddress *
qemuAgentGetDiskAddress(virJSONValue *json)
{
    virJSONValue *pci;
    virJSONValue *ccw;
    g_autoptr(qemuAgentDiskAddress) addr = NULL;

    addr = g_new0(qemuAgentDiskAddress, 1);
    addr->bus_type = g_strdup(virJSONValueObjectGetString(json, "bus-type"));
    addr->serial = g_strdup(virJSONValueObjectGetString(json, "serial"));
    addr->devnode = g_strdup(virJSONValueObjectGetString(json, "dev"));

#define GET_DISK_ADDR(jsonObject, var, name) \
    do { \
        if (virJSONValueObjectGetNumberUint(jsonObject, name, var) < 0) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           _("'%1$s' missing"), name); \
            return NULL; \
        } \
    } while (0)

    GET_DISK_ADDR(json, &addr->bus, "bus");
    GET_DISK_ADDR(json, &addr->target, "target");
    GET_DISK_ADDR(json, &addr->unit, "unit");

    if (!(pci = virJSONValueObjectGet(json, "pci-controller"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'pci-controller' missing"));
        return NULL;
    }

    GET_DISK_ADDR(pci, &addr->pci_controller.domain, "domain");
    GET_DISK_ADDR(pci, &addr->pci_controller.bus, "bus");
    GET_DISK_ADDR(pci, &addr->pci_controller.slot, "slot");
    GET_DISK_ADDR(pci, &addr->pci_controller.function, "function");

    if ((ccw = virJSONValueObjectGet(json, "ccw-address"))) {
        g_autofree virCCWDeviceAddress *ccw_addr = NULL;

        ccw_addr = g_new0(virCCWDeviceAddress, 1);

        GET_DISK_ADDR(ccw, &ccw_addr->cssid, "cssid");
        if (ccw_addr->cssid == 0)  /* Guest CSSID 0 is 0xfe on host */
            ccw_addr->cssid = 0xfe;
        GET_DISK_ADDR(ccw, &ccw_addr->ssid, "ssid");
        GET_DISK_ADDR(ccw, &ccw_addr->devno, "devno");

        addr->ccw_addr = g_steal_pointer(&ccw_addr);
    }
#undef GET_DISK_ADDR

    return g_steal_pointer(&addr);
}


static int
qemuAgentGetFSInfoFillDisks(virJSONValue *jsondisks,
                            qemuAgentFSInfo *fsinfo)
{
    size_t ndisks;
    size_t i;

    ndisks = virJSONValueArraySize(jsondisks);

    if (ndisks)
        fsinfo->disks = g_new0(qemuAgentDiskAddress *, ndisks);
    fsinfo->ndisks = ndisks;

    for (i = 0; i < fsinfo->ndisks; i++) {
        virJSONValue *jsondisk = virJSONValueArrayGet(jsondisks, i);

        if (!jsondisk) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("array element '%1$zd' of '%2$zd' missing in guest-get-fsinfo 'disk' data"),
                           i, fsinfo->ndisks);
            return -1;
        }

        if (!(fsinfo->disks[i] = qemuAgentGetDiskAddress(jsondisk)))
            return -1;
    }

    return 0;
}

/* Returns: number of entries in '@info' on success
 *          -2 when agent command is not supported by the agent and
 *             'report_unsupported' is false (libvirt error is not reported)
 *          -1 otherwise (libvirt error is reported)
 */
int
qemuAgentGetFSInfo(qemuAgent *agent,
                   qemuAgentFSInfo ***info,
                   bool report_unsupported)
{
    size_t i;
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    size_t ndata = 0;
    qemuAgentFSInfo **info_ret = NULL;
    int rc;

    cmd = qemuAgentMakeCommand("guest-get-fsinfo", NULL);
    if (!cmd)
        return ret;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-fsinfo reply was missing or not an array"));
        goto cleanup;
    }

    ndata = virJSONValueArraySize(data);
    if (ndata == 0) {
        ret = 0;
        *info = NULL;
        goto cleanup;
    }
    info_ret = g_new0(qemuAgentFSInfo *, ndata);

    for (i = 0; i < ndata; i++) {
        /* Reverse the order to arrange in mount order */
        virJSONValue *entry = virJSONValueArrayGet(data, ndata - 1 - i);
        virJSONValue *disk;
        unsigned long long bytes_val;
        const char *result = NULL;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("array element '%1$zd' of '%2$zd' missing in guest-get-fsinfo return data"),
                           i, ndata);
            goto cleanup;
        }

        info_ret[i] = g_new0(qemuAgentFSInfo, 1);

        if (!(result = virJSONValueObjectGetString(entry, "mountpoint"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'mountpoint' missing in reply of guest-get-fsinfo"));
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

        if (!(disk = virJSONValueObjectGetArray(entry, "disk"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'disk' missing or not an array in reply of guest-get-fsinfo"));
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


static int
qemuAgentGetInterfaceOneAddress(virDomainIPAddressPtr ip_addr,
                                virJSONValue *ip_addr_obj,
                                const char *name)
{
    const char *type, *addr;

    type = virJSONValueObjectGetString(ip_addr_obj, "ip-address-type");
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu agent didn't provide 'ip-address-type' field for interface '%1$s'"),
                       name);
        return -1;
    }

    if (STRNEQ(type, "ipv4") && STRNEQ(type, "ipv6")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown ip address type '%1$s'"),
                       type);
        return -1;
    }

    addr = virJSONValueObjectGetString(ip_addr_obj, "ip-address");
    if (!addr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu agent didn't provide 'ip-address' field for interface '%1$s'"),
                       name);
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(ip_addr_obj, "prefix",
                                        &ip_addr->prefix) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed 'prefix' field"));
        return -1;
    }

    if (STREQ(type, "ipv4"))
        ip_addr->type = VIR_IP_ADDR_TYPE_IPV4;
    else
        ip_addr->type = VIR_IP_ADDR_TYPE_IPV6;

    ip_addr->addr = g_strdup(addr);
    return 0;
}


/**
 * qemuAgentGetInterfaceAddresses:
 * @ifaces_ret: the array to put/update the interface in
 * @ifaces_count: the number of interfaces in that array
 * @ifaces_store: hash table into @ifaces_ret by interface name
 * @iface_obj: one item from the JSON array of interfaces
 *
 * This function processes @iface_obj (which represents
 * information about a single interface) and adds the information
 * into the ifaces_ret array.
 *
 * If we're processing an interface alias, the suffix is stripped
 * and information is appended to the entry found via the @ifaces_store
 * hash table.
 *
 * Otherwise, the next free position in @ifaces_ret is used,
 * its address added to @ifaces_store, and @ifaces_count incremented.
 */
static int
qemuAgentGetInterfaceAddresses(virDomainInterfacePtr **ifaces_ret,
                               size_t *ifaces_count,
                               GHashTable *ifaces_store,
                               virJSONValue *iface_obj)
{
    virJSONValue *ip_addr_arr = NULL;
    const char *hwaddr, *name = NULL;
    virDomainInterfacePtr iface = NULL;
    g_autofree char *ifname = NULL;
    size_t addrs_count = 0;
    size_t j;

    /* interface name is required to be presented */
    name = virJSONValueObjectGetString(iface_obj, "name");
    if (!name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't provide 'name' field"));
        return -1;
    }

    /* Handle interface alias (<ifname>:<alias>) */
    ifname = g_strdelimit(g_strdup(name), ":", '\0');

    iface = virHashLookup(ifaces_store, ifname);

    /* If the hash table doesn't contain this iface, add it */
    if (!iface) {
        VIR_EXPAND_N(*ifaces_ret, *ifaces_count, 1);

        iface = g_new0(virDomainInterface, 1);
        (*ifaces_ret)[*ifaces_count - 1] = iface;

        if (virHashAddEntry(ifaces_store, ifname, iface) < 0)
            return -1;

        iface->naddrs = 0;
        iface->name = g_strdup(ifname);

        hwaddr = virJSONValueObjectGetString(iface_obj, "hardware-address");
        iface->hwaddr = g_strdup(hwaddr);
    }

    /* as well as IP address which - moreover -
     * can be presented multiple times */
    if (!(ip_addr_arr = virJSONValueObjectGetArray(iface_obj, "ip-addresses")))
        return 0;

    /* If current iface already exists, continue with the count */
    addrs_count = iface->naddrs;

    VIR_EXPAND_N(iface->addrs, addrs_count, virJSONValueArraySize(ip_addr_arr));

    for (j = 0; j < virJSONValueArraySize(ip_addr_arr); j++) {
        virJSONValue *ip_addr_obj = virJSONValueArrayGet(ip_addr_arr, j);
        virDomainIPAddressPtr ip_addr = iface->addrs + iface->naddrs;
        iface->naddrs++;

        if (qemuAgentGetInterfaceOneAddress(ip_addr, ip_addr_obj, name) < 0)
            return -1;
    }

    return 0;
}


static int
qemuAgentGetAllInterfaceAddresses(virDomainInterfacePtr **ifaces_ret,
                                  virJSONValue *ret_array)
{
    g_autoptr(GHashTable) ifaces_store = NULL;
    size_t ifaces_count = 0;
    size_t i;

    *ifaces_ret = NULL;
    /* Hash table to handle the interface alias */
    ifaces_store = virHashNew(NULL);

    for (i = 0; i < virJSONValueArraySize(ret_array); i++) {
        virJSONValue *iface_obj = virJSONValueArrayGet(ret_array, i);

        if (qemuAgentGetInterfaceAddresses(ifaces_ret, &ifaces_count,
                                           ifaces_store, iface_obj) < 0)
            goto error;
    }

    return ifaces_count;

 error:
    if (*ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree((*ifaces_ret)[i]);
    }
    VIR_FREE(*ifaces_ret);
    return -1;
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
qemuAgentGetInterfaces(qemuAgent *agent,
                       virDomainInterfacePtr **ifaces,
                       bool report_unsupported)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *ret_array = NULL;
    int rc;

    if (!(cmd = qemuAgentMakeCommand("guest-network-get-interfaces", NULL)))
        return -1;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

    if (!(ret_array = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't return an array of interfaces"));
        return -1;
    }

    return qemuAgentGetAllInterfaceAddresses(ifaces, ret_array);
}


int
qemuAgentSetUserPassword(qemuAgent *agent,
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
 *          -2 when agent command is not supported by the agent and
 *             'report_unsupported' is false (libvirt error is not reported)
 *          -1 otherwise (libvirt error is reported)
 */
int
qemuAgentGetUsers(qemuAgent *agent,
                  virTypedParameterPtr *params,
                  int *nparams,
                  int *maxparams,
                  bool report_unsupported)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    size_t ndata;
    size_t i;
    int rc;

    if (!(cmd = qemuAgentMakeCommand("guest-get-users", NULL)))
        return -1;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-users reply was missing return data"));
        return -1;
    }

    ndata = virJSONValueArraySize(data);

    if (virTypedParamsAddUInt(params, nparams, maxparams,
                              "user.count", ndata) < 0)
        return -1;

    for (i = 0; i < ndata; i++) {
        virJSONValue *entry = virJSONValueArrayGet(data, i);
        char param_name[VIR_TYPED_PARAM_FIELD_LENGTH];
        const char *strvalue;
        double logintime;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("array element missing in guest-get-users return value"));
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

    return 0;
}

/* Returns: 0 on success
 *          -2 when agent command is not supported by the agent and
 *             'report_unsupported' is false (libvirt error is not reported)
 *          -1 otherwise (libvirt error is reported)
 */
int
qemuAgentGetOSInfo(qemuAgent *agent,
                   virTypedParameterPtr *params,
                   int *nparams,
                   int *maxparams,
                   bool report_unsupported)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    int rc;

    if (!(cmd = qemuAgentMakeCommand("guest-get-osinfo", NULL)))
        return -1;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

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
 *          -2 when agent command is not supported by the agent and
 *             'report_unsupported' is false (libvirt error is not reported)
 *          -1 otherwise (libvirt error is reported)
 */
int
qemuAgentGetTimezone(qemuAgent *agent,
                     virTypedParameterPtr *params,
                     int *nparams,
                     int *maxparams,
                     bool report_unsupported)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    const char *name;
    int offset;
    int rc;

    if (!(cmd = qemuAgentMakeCommand("guest-get-timezone", NULL)))
        return -1;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

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
qemuAgentSetResponseTimeout(qemuAgent *agent,
                            int timeout)
{
    agent->timeout = timeout;
}

/**
 * qemuAgentSSHGetAuthorizedKeys:
 * @agent: agent object
 * @user: user to get authorized keys for
 * @keys: Array of authorized keys
 *
 * Fetch the public keys from @user's $HOME/.ssh/authorized_keys.
 *
 * Returns: number of keys returned on success,
 *          -1 otherwise (error is reported)
 */
int
qemuAgentSSHGetAuthorizedKeys(qemuAgent *agent,
                              const char *user,
                              char ***keys)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    virJSONValue *arr = NULL;

    if (!(cmd = qemuAgentMakeCommand("guest-ssh-get-authorized-keys",
                                     "s:username", user,
                                     NULL)))
        return -1;

    if (qemuAgentCommand(agent, cmd, &reply, agent->timeout) < 0)
        return -1;

    if (!(data = virJSONValueObjectGetObject(reply, "return")) ||
        !(arr = virJSONValueObjectGetArray(data, "keys"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't return an array of keys"));
        return -1;
    }

    if (!(*keys = virJSONValueArrayToStringList(arr)))
        return -1;

    return g_strv_length(*keys);
}


/**
 * qemuAgentSSHAddAuthorizedKeys:
 * @agent: agent object
 * @user: user to add authorized keys for
 * @keys: Array of authorized keys
 * @nkeys: number of items in @keys array
 * @reset: whether to truncate authorized keys file before writing
 *
 * Append SSH @keys into the @user's authorized keys file. If
 * @reset is true then the file is truncated before write and
 * thus contains only newly added @keys.
 *
 * Returns: 0 on success,
 *          -1 otherwise (error is reported)
 */
int
qemuAgentSSHAddAuthorizedKeys(qemuAgent *agent,
                              const char *user,
                              const char **keys,
                              size_t nkeys,
                              bool reset)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) jkeys = NULL;

    jkeys = qemuAgentMakeStringsArray(keys, nkeys);
    if (jkeys == NULL)
        return -1;

    if (!(cmd = qemuAgentMakeCommand("guest-ssh-add-authorized-keys",
                                     "s:username", user,
                                     "a:keys", &jkeys,
                                     "b:reset", reset,
                                     NULL)))
        return -1;

    return qemuAgentCommand(agent, cmd, &reply, agent->timeout);
}


/**
 * qemuAgentSSHRemoveAuthorizedKeys:
 * @agent: agent object
 * @user: user to remove authorized keys for
 * @keys: Array of authorized keys
 * @nkeys: number of items in @keys array
 *
 * Remove SSH @keys from the @user's authorized keys file. It's
 * not considered an error when trying to remove a non-existent
 * key.
 *
 * Returns: 0 on success,
 *          -1 otherwise (error is reported)
 */
int
qemuAgentSSHRemoveAuthorizedKeys(qemuAgent *agent,
                                 const char *user,
                                 const char **keys,
                                 size_t nkeys)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) jkeys = NULL;

    jkeys = qemuAgentMakeStringsArray(keys, nkeys);
    if (jkeys == NULL)
        return -1;

    if (!(cmd = qemuAgentMakeCommand("guest-ssh-remove-authorized-keys",
                                     "s:username", user,
                                     "a:keys", &jkeys,
                                     NULL)))
        return -1;

    return qemuAgentCommand(agent, cmd, &reply, agent->timeout);
}


int qemuAgentGetDisks(qemuAgent *agent,
                      qemuAgentDiskInfo ***disks,
                      bool report_unsupported)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    size_t ndata;
    size_t i;
    int rc;

    if (!(cmd = qemuAgentMakeCommand("guest-get-disks", NULL)))
        return -1;

    if ((rc = qemuAgentCommandFull(agent, cmd, &reply, agent->timeout,
                                   report_unsupported)) < 0)
        return rc;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't return an array of disks"));
        return -1;
    }

    ndata = virJSONValueArraySize(data);

    *disks = g_new0(qemuAgentDiskInfo *, ndata);

    for (i = 0; i < ndata; i++) {
        virJSONValue *addr;
        virJSONValue *entry = virJSONValueArrayGet(data, i);
        virJSONValue *dependencies;
        qemuAgentDiskInfo *disk;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("array element missing in guest-get-disks return value"));
            goto error;
        }

        disk = g_new0(qemuAgentDiskInfo, 1);
        (*disks)[i] = disk;

        disk->name = g_strdup(virJSONValueObjectGetString(entry, "name"));
        if (!disk->name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'name' missing in reply of guest-get-disks"));
            goto error;
        }

        if (virJSONValueObjectGetBoolean(entry, "partition", &disk->partition) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'partition' missing in reply of guest-get-disks"));
            goto error;
        }

        if ((dependencies = virJSONValueObjectGetArray(entry, "dependencies"))) {
            if (!(disk->dependencies = virJSONValueArrayToStringList(dependencies)))
                goto error;
        }

        disk->alias = g_strdup(virJSONValueObjectGetString(entry, "alias"));
        addr = virJSONValueObjectGetObject(entry, "address");
        if (addr) {
            disk->address = qemuAgentGetDiskAddress(addr);
            if (!disk->address)
                goto error;
        }
    }

    return ndata;

 error:
    for (i = 0; i < ndata; i++) {
        qemuAgentDiskInfoFree((*disks)[i]);
    }
    g_free(*disks);
    return -1;
}
