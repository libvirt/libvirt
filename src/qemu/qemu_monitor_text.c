/*
 * qemu_monitor_text.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>

#include "qemu_monitor_text.h"
#include "qemu_conf.h"
#include "c-ctype.h"
#include "memory.h"
#include "logging.h"
#include "driver.h"
#include "datatypes.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

/* Throw away any data available on the monitor
 * This is done before executing a command, in order
 * to allow re-synchronization if something went badly
 * wrong in the past. it also deals with problem of
 * QEMU *sometimes* re-printing its initial greeting
 * when we reconnect to the monitor after restarts.
 */
static void
qemuMonitorDiscardPendingData(virDomainObjPtr vm) {
    char buf[1024];
    int ret = 0;

    /* Monitor is non-blocking, so just loop till we
     * get -1 or 0. Don't bother with detecting
     * errors, since we'll deal with that better later */
    do {
        ret = read(vm->monitor, buf, sizeof (buf)-1);
    } while (ret > 0);
}

static int
qemudMonitorSendUnix(const virDomainObjPtr vm,
                     const char *cmd,
                     size_t cmdlen,
                     int scm_fd)
{
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t ret;

    memset(&msg, 0, sizeof(msg));

    iov[0].iov_base = (void *)cmd;
    iov[0].iov_len = cmdlen;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if (scm_fd != -1) {
        char control[CMSG_SPACE(sizeof(int))];
        struct cmsghdr *cmsg;

        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), &scm_fd, sizeof(int));
    }

    do {
        ret = sendmsg(vm->monitor, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    return ret == cmdlen ? 0 : -1;
}

static int
qemudMonitorSend(const virDomainObjPtr vm,
                 const char *cmd,
                 int scm_fd)
{
    char *full;
    size_t len;
    int ret = -1;

    if (virAsprintf(&full, "%s\r", cmd) < 0)
        return -1;

    len = strlen(full);

    switch (vm->monitor_chr->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (qemudMonitorSendUnix(vm, full, len, scm_fd) < 0)
            goto out;
        break;
    default:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (safewrite(vm->monitor, full, len) != len)
            goto out;
        break;
    }

    ret = 0;
out:
    VIR_FREE(full);
    return ret;
}

int
qemudMonitorCommandWithHandler(const virDomainObjPtr vm,
                               const char *cmd,
                               const char *extraPrompt,
                               qemudMonitorExtraPromptHandler extraHandler,
                               void *handlerData,
                               int scm_fd,
                               char **reply) {
    int size = 0;
    char *buf = NULL;

    /* Should never happen, but just in case, protect
     * against null monitor (ocurrs when VM is inactive) */
    if (!vm->monitor_chr)
        return -1;

    qemuMonitorDiscardPendingData(vm);

    VIR_DEBUG("Send '%s'", cmd);
    if (qemudMonitorSend(vm, cmd, scm_fd) < 0)
        return -1;

    *reply = NULL;

    for (;;) {
        struct pollfd fd = { vm->monitor, POLLIN | POLLERR | POLLHUP, 0 };
        char *tmp;

        /* Read all the data QEMU has sent thus far */
        for (;;) {
            char data[1024];
            int got = read(vm->monitor, data, sizeof(data));

            if (got == 0)
                goto error;
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN)
                    break;
                goto error;
            }
            if (VIR_REALLOC_N(buf, size+got+1) < 0)
                goto error;

            memmove(buf+size, data, got);
            buf[size+got] = '\0';
            size += got;
        }

        /* Look for QEMU prompt to indicate completion */
        if (buf) {
            char *foundPrompt;

            if (extraPrompt &&
                (foundPrompt = strstr(buf, extraPrompt)) != NULL) {
                char *promptEnd;

                if (extraHandler(vm, buf, foundPrompt, handlerData) < 0)
                    return -1;
                /* Discard output so far, necessary to detect whether
                   extraPrompt appears again.  We don't need the output between
                   original command and this prompt anyway. */
                promptEnd = foundPrompt + strlen(extraPrompt);
                memmove(buf, promptEnd, strlen(promptEnd)+1);
                size -= promptEnd - buf;
            } else if ((tmp = strstr(buf, QEMU_CMD_PROMPT)) != NULL) {
                char *commptr = NULL, *nlptr = NULL;
                /* Preserve the newline */
                tmp[1] = '\0';

                /* The monitor doesn't dump clean output after we have written to
                 * it. Every character we write dumps a bunch of useless stuff,
                 * so the result looks like "cXcoXcomXcommXcommaXcommanXcommand"
                 * Try to throw away everything before the first full command
                 * occurence, and inbetween the command and the newline starting
                 * the response
                 */
                if ((commptr = strstr(buf, cmd))) {
                    memmove(buf, commptr, strlen(commptr)+1);
                    if ((nlptr = strchr(buf, '\n')))
                        memmove(buf+strlen(cmd), nlptr, strlen(nlptr)+1);
                }

                break;
            }
        }
    pollagain:
        /* Need to wait for more data */
        if (poll(&fd, 1, -1) < 0) {
            if (errno == EINTR)
                goto pollagain;
            goto error;
        }
    }
    *reply = buf;
    return 0;

 error:
    VIR_FREE(buf);
    return -1;
}

struct extraHandlerData
{
    const char *reply;
    bool first;
};

static int
qemudMonitorCommandSimpleExtraHandler(const virDomainObjPtr vm,
                                      const char *buf ATTRIBUTE_UNUSED,
                                      const char *prompt ATTRIBUTE_UNUSED,
                                      void *data_)
{
    struct extraHandlerData *data = data_;

    if (!data->first)
        return 0;
    if (qemudMonitorSend(vm, data->reply, -1) < 0)
        return -1;
    data->first = false;
    return 0;
}

int
qemudMonitorCommandExtra(const virDomainObjPtr vm,
                         const char *cmd,
                         const char *extra,
                         const char *extraPrompt,
                         int scm_fd,
                         char **reply) {
    struct extraHandlerData data;

    data.reply = extra;
    data.first = true;
    return qemudMonitorCommandWithHandler(vm, cmd, extraPrompt,
                                          qemudMonitorCommandSimpleExtraHandler,
                                          &data, scm_fd, reply);
}

int
qemudMonitorCommandWithFd(const virDomainObjPtr vm,
                          const char *cmd,
                          int scm_fd,
                          char **reply) {
    return qemudMonitorCommandExtra(vm, cmd, NULL, NULL, scm_fd, reply);
}

int
qemudMonitorCommand(const virDomainObjPtr vm,
                    const char *cmd,
                    char **reply) {
    return qemudMonitorCommandWithFd(vm, cmd, -1, reply);
}



static virStorageEncryptionPtr
findDomainDiskEncryption(virConnectPtr conn, virDomainObjPtr vm,
                         const char *path)
{
    bool seen_volume;
    int i;

    seen_volume = false;
    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk;

        disk = vm->def->disks[i];
        if (disk->src != NULL && STREQ(disk->src, path)) {
            seen_volume = true;
            if (disk->encryption != NULL)
                return disk->encryption;
        }
    }
    if (seen_volume)
        qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("missing <encryption> for volume %s"), path);
    else
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected passphrase request for volume %s"),
                         path);
    return NULL;
}

static char *
findVolumeQcowPassphrase(virConnectPtr conn, virDomainObjPtr vm,
                         const char *path, size_t *passphrase_len)
{
    virStorageEncryptionPtr enc;
    virSecretPtr secret;
    char *passphrase;
    unsigned char *data;
    size_t size;

    if (conn->secretDriver == NULL ||
        conn->secretDriver->lookupByUUID == NULL ||
        conn->secretDriver->getValue == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT, "%s",
                         _("secret storage not supported"));
        return NULL;
    }

    enc = findDomainDiskEncryption(conn, vm, path);
    if (enc == NULL)
        return NULL;

    if (enc->format != VIR_STORAGE_ENCRYPTION_FORMAT_QCOW ||
        enc->nsecrets != 1 ||
        enc->secrets[0]->type !=
        VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("invalid <encryption> for volume %s"), path);
        return NULL;
    }

    secret = conn->secretDriver->lookupByUUID(conn,
                                              enc->secrets[0]->uuid);
    if (secret == NULL)
        return NULL;
    data = conn->secretDriver->getValue(secret, &size,
                                        VIR_SECRET_GET_VALUE_INTERNAL_CALL);
    virUnrefSecret(secret);
    if (data == NULL)
        return NULL;

    if (memchr(data, '\0', size) != NULL) {
        memset(data, 0, size);
        VIR_FREE(data);
        qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_SECRET,
                         _("format='qcow' passphrase for %s must not contain a "
                           "'\\0'"), path);
        return NULL;
    }

    if (VIR_ALLOC_N(passphrase, size + 1) < 0) {
        memset(data, 0, size);
        VIR_FREE(data);
        virReportOOMError(conn);
        return NULL;
    }
    memcpy(passphrase, data, size);
    passphrase[size] = '\0';

    memset(data, 0, size);
    VIR_FREE(data);

    *passphrase_len = size;
    return passphrase;
}

static int
qemudMonitorSendVolumePassphrase(const virDomainObjPtr vm,
                                 const char *buf,
                                 const char *prompt,
                                 void *data)
{
    virConnectPtr conn = data;
    char *passphrase, *path;
    const char *prompt_path;
    size_t path_len, passphrase_len = 0;
    int res;

    /* The complete prompt looks like this:
           ide0-hd0 (/path/to/volume) is encrypted.
           Password:
       "prompt" starts with ") is encrypted".  Extract /path/to/volume. */
    for (prompt_path = prompt; prompt_path > buf && prompt_path[-1] != '(';
         prompt_path--)
        ;
    if (prompt_path == buf)
        return -1;
    path_len = prompt - prompt_path;
    if (VIR_ALLOC_N(path, path_len + 1) < 0)
        return -1;
    memcpy(path, prompt_path, path_len);
    path[path_len] = '\0';

    passphrase = findVolumeQcowPassphrase(conn, vm, path, &passphrase_len);
    VIR_FREE(path);
    if (passphrase == NULL)
        return -1;

    res = qemudMonitorSend(vm, passphrase, -1);

    memset(passphrase, 0, passphrase_len);
    VIR_FREE(passphrase);

    return res;
}

int
qemuMonitorStartCPUs(virConnectPtr conn,
                     const virDomainObjPtr vm) {
    char *reply;

    if (qemudMonitorCommandWithHandler(vm, "cont", ") is encrypted.",
                                       qemudMonitorSendVolumePassphrase, conn,
                                       -1, &reply) < 0)
        return -1;
    qemudDebug ("%s: cont reply: %s", vm->def->name, info);
    VIR_FREE(reply);
    return 0;
}


int
qemuMonitorStopCPUs(const virDomainObjPtr vm) {
    char *info;

    if (qemudMonitorCommand(vm, "stop", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot stop CPU execution"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}


int qemuMonitorSystemPowerdown(const virDomainObjPtr vm) {
    char *info;

    if (qemudMonitorCommand(vm, "system_powerdown", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("system shutdown operation failed"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}


int qemuMonitorGetCPUInfo(const virDomainObjPtr vm,
                          int **pids)
{
    char *qemucpus = NULL;
    char *line;
    int lastVcpu = -1;
    pid_t *cpupids = NULL;
    size_t ncpupids = 0;

    if (qemudMonitorCommand(vm, "info cpus", &qemucpus) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot run monitor command to fetch CPU thread info"));
        return -1;
    }

    /*
     * This is the gross format we're about to parse :-{
     *
     * (qemu) info cpus
     * * CPU #0: pc=0x00000000000f0c4a thread_id=30019
     *   CPU #1: pc=0x00000000fffffff0 thread_id=30020
     *   CPU #2: pc=0x00000000fffffff0 thread_id=30021
     *
     */
    line = qemucpus;
    do {
        char *offset = strchr(line, '#');
        char *end = NULL;
        int vcpu = 0, tid = 0;

        /* See if we're all done */
        if (offset == NULL)
            break;

        /* Extract VCPU number */
        if (virStrToLong_i(offset + 1, &end, 10, &vcpu) < 0)
            goto error;

        if (end == NULL || *end != ':')
            goto error;

        /* Extract host Thread ID */
        if ((offset = strstr(line, "thread_id=")) == NULL)
            goto error;

        if (virStrToLong_i(offset + strlen("thread_id="), &end, 10, &tid) < 0)
            goto error;
        if (end == NULL || !c_isspace(*end))
            goto error;

        if (vcpu != (lastVcpu + 1))
            goto error;

        if (VIR_REALLOC_N(cpupids, ncpupids+1) < 0)
            goto error;

        cpupids[ncpupids++] = tid;
        lastVcpu = vcpu;

        /* Skip to next data line */
        line = strchr(offset, '\r');
        if (line == NULL)
            line = strchr(offset, '\n');
    } while (line != NULL);

    /* Validate we got data for all VCPUs we expected */
    VIR_FREE(qemucpus);
    *pids = cpupids;
    return ncpupids;

error:
    VIR_FREE(qemucpus);
    VIR_FREE(cpupids);

    /* Returning 0 to indicate non-fatal failure, since
     * older QEMU does not have VCPU<->PID mapping and
     * we don't want to fail on that
     */
    return 0;
}



/* The reply from QEMU contains 'ballon: actual=421' where value is in MB */
#define BALLOON_PREFIX "balloon: actual="

/*
 * Returns: 0 if balloon not supported, +1 if balloon query worked
 * or -1 on failure
 */
int qemuMonitorGetBalloonInfo(const virDomainObjPtr vm,
                              unsigned long *currmem)
{
    char *reply = NULL;
    int ret = -1;
    char *offset;

    if (qemudMonitorCommand(vm, "info balloon", &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("could not query memory balloon allocation"));
        return -1;
    }

    DEBUG ("%s: balloon reply: '%s'", vm->def->name, reply);
    if ((offset = strstr(reply, BALLOON_PREFIX)) != NULL) {
        unsigned int memMB;
        char *end;
        offset += strlen(BALLOON_PREFIX);
        if (virStrToLong_ui(offset, &end, 10, &memMB) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             _("could not parse memory balloon allocation from '%s'"), reply);
            goto cleanup;
        }
        *currmem = memMB * 1024;
        ret = 1;
    } else {
        /* We don't raise an error here, since its to be expected that
         * many QEMU's don't support ballooning
         */
        ret = 0;
    }

cleanup:
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorSetVNCPassword(const virDomainObjPtr vm,
                              const char *password)
{
    char *info = NULL;
    if (qemudMonitorCommandExtra(vm, "change vnc password",
                                 password,
                                 QEMU_PASSWD_PROMPT,
                                 -1, &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("setting VNC password failed"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}

/*
 * Returns: 0 if balloon not supported, +1 if balloon adjust worked
 * or -1 on failure
 */
int qemuMonitorSetBalloon(const virDomainObjPtr vm,
                          unsigned long newmem)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    /*
     * 'newmem' is in KB, QEMU monitor works in MB, and we all wish
     * we just worked in bytes with unsigned long long everywhere.
     */
    if (virAsprintf(&cmd, "balloon %lu", (newmem / 1024)) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemudMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("could not balloon memory allocation"));
        VIR_FREE(cmd);
        return -1;
    }
    VIR_FREE(cmd);

    /* If the command failed qemu prints: 'unknown command'
     * No message is printed on success it seems */
    DEBUG ("%s: balloon reply: %s", vm->def->name,  reply);
    if (strstr(reply, "\nunknown command:")) {
        /* Don't set error - it is expected memory balloon fails on many qemu */
        ret = 0;
    } else {
        ret = 1;
    }

    VIR_FREE(reply);
    return ret;
}

