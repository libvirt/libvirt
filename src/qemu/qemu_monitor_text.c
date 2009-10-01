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
#include <string.h>

#include "qemu_monitor_text.h"
#include "qemu_conf.h"
#include "c-ctype.h"
#include "memory.h"
#include "logging.h"
#include "driver.h"
#include "datatypes.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define QEMU_CMD_PROMPT "\n(qemu) "
#define QEMU_PASSWD_PROMPT "Password: "

/* Return -1 for error, 0 for success */
typedef int qemuMonitorExtraPromptHandler(const virDomainObjPtr vm,
                                          const char *buf,
                                          const char *prompt,
                                          void *data);


static char *qemuMonitorEscape(const char *in, int shell)
{
    int len = 0;
    int i, j;
    char *out;

    /* To pass through the QEMU monitor, we need to use escape
       sequences: \r, \n, \", \\

       To pass through both QEMU + the shell, we need to escape
       the single character ' as the five characters '\\''
    */

    for (i = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
        case '\n':
        case '"':
        case '\\':
            len += 2;
            break;
        case '\'':
            if (shell)
                len += 5;
            else
                len += 1;
            break;
        default:
            len += 1;
            break;
        }
    }

    if (VIR_ALLOC_N(out, len + 1) < 0)
        return NULL;

    for (i = j = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
            out[j++] = '\\';
            out[j++] = 'r';
            break;
        case '\n':
            out[j++] = '\\';
            out[j++] = 'n';
            break;
        case '"':
        case '\\':
            out[j++] = '\\';
            out[j++] = in[i];
            break;
        case '\'':
            if (shell) {
                out[j++] = '\'';
                out[j++] = '\\';
                out[j++] = '\\';
                out[j++] = '\'';
                out[j++] = '\'';
            } else {
                out[j++] = in[i];
            }
            break;
        default:
            out[j++] = in[i];
            break;
        }
    }
    out[j] = '\0';

    return out;
}

static char *qemuMonitorEscapeArg(const char *in)
{
    return qemuMonitorEscape(in, 0);
}

static char *qemuMonitorEscapeShell(const char *in)
{
    return qemuMonitorEscape(in, 1);
}

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
qemuMonitorSendUnix(const virDomainObjPtr vm,
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
qemuMonitorSend(const virDomainObjPtr vm,
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
        if (qemuMonitorSendUnix(vm, full, len, scm_fd) < 0)
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

static int
qemuMonitorCommandWithHandler(const virDomainObjPtr vm,
                              const char *cmd,
                              const char *extraPrompt,
                              qemuMonitorExtraPromptHandler extraHandler,
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

    VIR_DEBUG("cmd='%s' extraPrompt='%s'", cmd, NULLSTR(extraPrompt));
    if (qemuMonitorSend(vm, cmd, scm_fd) < 0)
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

                DEBUG("prompt='%s' handler=%p", extraPrompt, extraHandler);
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
    DEBUG("reply='%s'", buf);
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
qemuMonitorCommandSimpleExtraHandler(const virDomainObjPtr vm,
                                     const char *buf ATTRIBUTE_UNUSED,
                                     const char *prompt ATTRIBUTE_UNUSED,
                                     void *data_)
{
    struct extraHandlerData *data = data_;

    if (!data->first)
        return 0;
    if (qemuMonitorSend(vm, data->reply, -1) < 0)
        return -1;
    data->first = false;
    return 0;
}

static int
qemuMonitorCommandExtra(const virDomainObjPtr vm,
                         const char *cmd,
                         const char *extra,
                         const char *extraPrompt,
                         int scm_fd,
                         char **reply) {
    struct extraHandlerData data;

    data.reply = extra;
    data.first = true;
    return qemuMonitorCommandWithHandler(vm, cmd, extraPrompt,
                                         qemuMonitorCommandSimpleExtraHandler,
                                         &data, scm_fd, reply);
}

static int
qemuMonitorCommandWithFd(const virDomainObjPtr vm,
                          const char *cmd,
                          int scm_fd,
                          char **reply) {
    return qemuMonitorCommandExtra(vm, cmd, NULL, NULL, scm_fd, reply);
}

static int
qemuMonitorCommand(const virDomainObjPtr vm,
                    const char *cmd,
                    char **reply) {
    return qemuMonitorCommandWithFd(vm, cmd, -1, reply);
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
qemuMonitorSendVolumePassphrase(const virDomainObjPtr vm,
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

    res = qemuMonitorSend(vm, passphrase, -1);

    memset(passphrase, 0, passphrase_len);
    VIR_FREE(passphrase);

    return res;
}

int
qemuMonitorStartCPUs(virConnectPtr conn,
                     const virDomainObjPtr vm) {
    char *reply;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    if (qemuMonitorCommandWithHandler(vm, "cont", ") is encrypted.",
                                      qemuMonitorSendVolumePassphrase, conn,
                                      -1, &reply) < 0)
        return -1;

    VIR_FREE(reply);
    return 0;
}


int
qemuMonitorStopCPUs(const virDomainObjPtr vm) {
    char *info;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    if (qemuMonitorCommand(vm, "stop", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot stop CPU execution"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}


int qemuMonitorSystemPowerdown(const virDomainObjPtr vm) {
    char *info;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    if (qemuMonitorCommand(vm, "system_powerdown", &info) < 0) {
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

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    if (qemuMonitorCommand(vm, "info cpus", &qemucpus) < 0) {
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

        DEBUG("vcpu=%d pid=%d", vcpu, tid);
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

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    if (qemuMonitorCommand(vm, "info balloon", &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("could not query memory balloon allocation"));
        return -1;
    }

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


int qemuMonitorGetBlockStatsInfo(const virDomainObjPtr vm,
                                 const char *devname,
                                 long long *rd_req,
                                 long long *rd_bytes,
                                 long long *wr_req,
                                 long long *wr_bytes,
                                 long long *errs)
{
    char *info = NULL;
    int ret = -1;
    char *dummy;
    const char *p, *eol;
    int devnamelen = strlen(devname);

    DEBUG("vm=%p, pid=%d, id=%d, name=%s dev=%s",
          vm, vm->pid, vm->def->id, vm->def->name, devname);

    if (qemuMonitorCommand (vm, "info blockstats", &info) < 0) {
        qemudReportError (NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("'info blockstats' command failed"));
        goto cleanup;
    }

    /* If the command isn't supported then qemu prints the supported
     * info commands, so the output starts "info ".  Since this is
     * unlikely to be the name of a block device, we can use this
     * to detect if qemu supports the command.
     */
    if (strstr(info, "\ninfo ")) {
        qemudReportError (NULL, NULL, NULL, VIR_ERR_NO_SUPPORT,
                          "%s",
                          _("'info blockstats' not supported by this qemu"));
        goto cleanup;
    }

    *rd_req = -1;
    *rd_bytes = -1;
    *wr_req = -1;
    *wr_bytes = -1;
    *errs = -1;

    /* The output format for both qemu & KVM is:
     *   blockdevice: rd_bytes=% wr_bytes=% rd_operations=% wr_operations=%
     *   (repeated for each block device)
     * where '%' is a 64 bit number.
     */
    p = info;

    while (*p) {
        if (STREQLEN (p, devname, devnamelen)
            && p[devnamelen] == ':' && p[devnamelen+1] == ' ') {

            eol = strchr (p, '\n');
            if (!eol)
                eol = p + strlen (p);

            p += devnamelen+2;         /* Skip to first label. */

            while (*p) {
                if (STRPREFIX (p, "rd_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, rd_bytes) == -1)
                        DEBUG ("%s: error reading rd_bytes: %s",
                               vm->def->name, p);
                } else if (STRPREFIX (p, "wr_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, wr_bytes) == -1)
                        DEBUG ("%s: error reading wr_bytes: %s",
                               vm->def->name, p);
                } else if (STRPREFIX (p, "rd_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, rd_req) == -1)
                        DEBUG ("%s: error reading rd_req: %s",
                               vm->def->name, p);
                } else if (STRPREFIX (p, "wr_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, wr_req) == -1)
                        DEBUG ("%s: error reading wr_req: %s",
                               vm->def->name, p);
                } else
                    DEBUG ("%s: unknown block stat near %s", vm->def->name, p);

                /* Skip to next label. */
                p = strchr (p, ' ');
                if (!p || p >= eol) break;
                p++;
            }
            ret = 0;
            goto cleanup;
        }

        /* Skip to next line. */
        p = strchr (p, '\n');
        if (!p) break;
        p++;
    }

    /* If we reach here then the device was not found. */
    qemudReportError (NULL, NULL, NULL, VIR_ERR_INVALID_ARG,
                      _("no stats found for device %s"), devname);

 cleanup:
    VIR_FREE(info);
    return ret;
}


int qemuMonitorSetVNCPassword(const virDomainObjPtr vm,
                              const char *password)
{
    char *info = NULL;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    if (qemuMonitorCommandExtra(vm, "change vnc password",
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

    DEBUG("vm=%p, pid=%d, id=%d, name=%s newmem=%lu",
          vm, vm->pid, vm->def->id, vm->def->name, newmem);

    /*
     * 'newmem' is in KB, QEMU monitor works in MB, and we all wish
     * we just worked in bytes with unsigned long long everywhere.
     */
    if (virAsprintf(&cmd, "balloon %lu", (newmem / 1024)) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("could not balloon memory allocation"));
        VIR_FREE(cmd);
        return -1;
    }
    VIR_FREE(cmd);

    /* If the command failed qemu prints: 'unknown command'
     * No message is printed on success it seems */
    if (strstr(reply, "\nunknown command:")) {
        /* Don't set error - it is expected memory balloon fails on many qemu */
        ret = 0;
    } else {
        ret = 1;
    }

    VIR_FREE(reply);
    return ret;
}

int qemuMonitorEjectMedia(const virDomainObjPtr vm,
                          const char *devname)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s devname=%s",
          vm, vm->pid, vm->def->id, vm->def->name, devname);

    if (virAsprintf(&cmd, "eject %s", devname) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("could not eject media on %s"), devname);
        goto cleanup;
    }

    /* If the command failed qemu prints:
     * device not found, device is locked ...
     * No message is printed on success it seems */
    if (strstr(reply, "\ndevice ")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("could not eject media on %s: %s"), devname, reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}


int qemuMonitorChangeMedia(const virDomainObjPtr vm,
                           const char *devname,
                           const char *newmedia)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safepath = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s devname=%s newmedia=%s",
          vm, vm->pid, vm->def->id, vm->def->name, devname, newmedia);

    if (!(safepath = qemuMonitorEscapeArg(newmedia))) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (virAsprintf(&cmd, "change %s \"%s\"", devname, safepath) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("could not eject media on %s"), devname);
        goto cleanup;
    }

    /* If the command failed qemu prints:
     * device not found, device is locked ...
     * No message is printed on success it seems */
    if (strstr(reply, "\ndevice ")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("could not eject media on %s: %s"), devname, reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    VIR_FREE(safepath);
    return ret;
}

static int qemuMonitorSaveMemory(const virDomainObjPtr vm,
                                 const char *cmdtype,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safepath = NULL;
    int ret = -1;

    if (!(safepath = qemuMonitorEscapeArg(path))) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (virAsprintf(&cmd, "%s %llu %zi \"%s\"", cmdtype, offset, length, safepath) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("could save memory region to '%s'"), path);
        goto cleanup;
    }

    /* XXX what is printed on failure ? */

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safepath);
    return ret;
}


int qemuMonitorSaveVirtualMemory(const virDomainObjPtr vm,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path)
{
    DEBUG("vm=%p, pid=%d, id=%d, name=%s offset=%llu length=%zu path=%s",
          vm, vm->pid, vm->def->id, vm->def->name, offset, length, path);

    return qemuMonitorSaveMemory(vm, "memsave", offset, length, path);
}

int qemuMonitorSavePhysicalMemory(const virDomainObjPtr vm,
                                  unsigned long long offset,
                                  size_t length,
                                  const char *path)
{
    DEBUG("vm=%p, pid=%d, id=%d, name=%s offset=%llu length=%zu path=%s",
          vm, vm->pid, vm->def->id, vm->def->name, offset, length, path);

    return qemuMonitorSaveMemory(vm, "pmemsave", offset, length, path);
}


int qemuMonitorSetMigrationSpeed(const virDomainObjPtr vm,
                                 unsigned long bandwidth)
{
    char *cmd = NULL;
    char *info = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s bandwidth=%lu",
          vm, vm->pid, vm->def->id, vm->def->name, bandwidth);

    if (virAsprintf(&cmd, "migrate_set_speed %lum", bandwidth) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("could restrict migration speed"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(info);
    VIR_FREE(cmd);
    return ret;
}


#define MIGRATION_PREFIX "Migration status: "
#define MIGRATION_TRANSFER_PREFIX "transferred ram: "
#define MIGRATION_REMAINING_PREFIX "remaining ram: "
#define MIGRATION_TOTAL_PREFIX "total ram: "

VIR_ENUM_DECL(qemuMonitorMigrationStatus)
VIR_ENUM_IMPL(qemuMonitorMigrationStatus,
              QEMU_MONITOR_MIGRATION_STATUS_LAST,
              "inactive", "active", "completed", "failed", "cancelled")

int qemuMonitorGetMigrationStatus(const virDomainObjPtr vm,
                                  int *status,
                                  unsigned long long *transferred,
                                  unsigned long long *remaining,
                                  unsigned long long *total) {
    char *reply;
    char *tmp;
    char *end;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s", vm, vm->pid, vm->def->id, vm->def->name);

    *status = QEMU_MONITOR_MIGRATION_STATUS_INACTIVE;
    *transferred = 0;
    *remaining = 0;
    *total = 0;

    if (qemuMonitorCommand(vm, "info migrate", &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot query migration status"));
        return -1;
    }

    if ((tmp = strstr(reply, MIGRATION_PREFIX)) != NULL) {
        tmp += strlen(MIGRATION_PREFIX);
        end = strchr(tmp, '\r');
        *end = '\0';

        if ((*status = qemuMonitorMigrationStatusTypeFromString(tmp)) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected migration status in %s"), reply);
            goto cleanup;
        }

        if (*status == QEMU_MONITOR_MIGRATION_STATUS_ACTIVE) {
            tmp = end + 1;

            if (!(tmp = strstr(tmp, MIGRATION_TRANSFER_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_TRANSFER_PREFIX);

            if (virStrToLong_ull(tmp, NULL, 10, transferred) < 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse migration data transferred statistic %s"), tmp);
                goto cleanup;
            }
            *transferred *= 1024;

            if (!(tmp = strstr(tmp, MIGRATION_REMAINING_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_REMAINING_PREFIX);

            if (virStrToLong_ull(tmp, NULL, 10, remaining) < 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse migration data remaining statistic %s"), tmp);
                goto cleanup;
            }
            *remaining *= 1024;

            if (!(tmp = strstr(tmp, MIGRATION_TOTAL_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_TOTAL_PREFIX);

            if (virStrToLong_ull(tmp, NULL, 10, total) < 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse migration data total statistic %s"), tmp);
                goto cleanup;
            }
            *total *= 1024;

        }
    }

done:
    ret = 0;

cleanup:
    VIR_FREE(reply);
    return ret;
}


static int qemuMonitorMigrate(const virDomainObjPtr vm,
                              int background,
                              const char *dest)
{
    char *cmd = NULL;
    char *info = NULL;
    int ret = -1;
    char *safedest = qemuMonitorEscapeArg(dest);
    const char *extra;

    if (!safedest) {
        virReportOOMError(NULL);
        return -1;
    }

    if (background)
        extra = "-d ";
    else
        extra = " ";

    if (virAsprintf(&cmd, "migrate %s\"%s\"", extra, safedest) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unable to start migration to %s"), dest);
        goto cleanup;
    }

    /* Now check for "fail" in the output string */
    if (strstr(info, "fail") != NULL) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("migration to '%s' failed: %s"), dest, info);
        goto cleanup;
    }
    /* If the command isn't supported then qemu prints:
     * unknown command: migrate" */
    if (strstr(info, "unknown command:")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         _("migration to '%s' not supported by this qemu: %s"), dest, info);
        goto cleanup;
    }


    ret = 0;

cleanup:
    VIR_FREE(safedest);
    VIR_FREE(info);
    VIR_FREE(cmd);
    return ret;
}

int qemuMonitorMigrateToHost(const virDomainObjPtr vm,
                             int background,
                             const char *hostname,
                             int port)
{
    char *uri = NULL;
    int ret;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s hostname=%s port=%d",
          vm, vm->pid, vm->def->id, vm->def->name, hostname, port);

    if (virAsprintf(&uri, "tcp:%s:%d", hostname, port) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorMigrate(vm, background, uri);

    VIR_FREE(uri);

    return ret;
}


int qemuMonitorMigrateToCommand(const virDomainObjPtr vm,
                                int background,
                                const char * const *argv,
                                const char *target)
{
    char *argstr;
    char *dest = NULL;
    int ret = -1;
    char *safe_target = NULL;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s argv=%p target=%s",
          vm, vm->pid, vm->def->id, vm->def->name, argv, target);

    argstr = virArgvToString(argv);
    if (!argstr) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    /* Migrate to file */
    safe_target = qemuMonitorEscapeShell(target);
    if (!safe_target) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (virAsprintf(&dest, "exec:%s >>%s 2>/dev/null", argstr, safe_target) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    ret = qemuMonitorMigrate(vm, background, dest);

cleanup:
    VIR_FREE(safe_target);
    VIR_FREE(argstr);
    VIR_FREE(dest);
    return ret;
}

int qemuMonitorMigrateToUnix(const virDomainObjPtr vm,
                             int background,
                             const char *unixfile)
{
    char *dest = NULL;
    int ret = -1;

    if (virAsprintf(&dest, "unix:%s", unixfile) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorMigrate(vm, background, dest);

    VIR_FREE(dest);

    return ret;
}

int qemuMonitorMigrateCancel(const virDomainObjPtr vm)
{
    char *info = NULL;

    if (qemuMonitorCommand(vm, "migrate cancel", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot run monitor command to cancel migration"));
        return -1;
    }
    VIR_FREE(info);

    return 0;
}

int qemuMonitorAddUSBDisk(const virDomainObjPtr vm,
                          const char *path)
{
    char *cmd = NULL;
    char *safepath;
    int ret = -1;
    char *info = NULL;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s path=%s",
          vm, vm->pid, vm->def->id, vm->def->name, path);

    safepath = qemuMonitorEscapeArg(path);
    if (!safepath) {
        virReportOOMError(NULL);
        return -1;
    }

    if (virAsprintf(&cmd, "usb_add disk:%s", safepath) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot run monitor command to add usb disk"));
        goto cleanup;
    }

    /* If the command failed qemu prints:
     * Could not add ... */
    if (strstr(info, "Could not add ")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("unable to add USB disk %s: %s"), path, info);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(safepath);
    return ret;
}


static int qemuMonitorAddUSBDevice(const virDomainObjPtr vm,
                                   const char *addr)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "usb_add %s", addr) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach usb device"));
        goto cleanup;
    }

    /* If the command failed qemu prints:
     * Could not add ... */
    if (strstr(reply, "Could not add ")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("adding usb device failed"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorAddUSBDeviceExact(const virDomainObjPtr vm,
                                 int bus,
                                 int dev)
{
    int ret;
    char *addr;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s bus=%d dev=%d",
          vm, vm->pid, vm->def->id, vm->def->name, bus, dev);

    if (virAsprintf(&addr, "host:%.3d.%.3d", bus, dev) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorAddUSBDevice(vm, addr);

    VIR_FREE(addr);
    return ret;
}

int qemuMonitorAddUSBDeviceMatch(const virDomainObjPtr vm,
                                 int vendor,
                                 int product)
{
    int ret;
    char *addr;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s vendor=%d product=%d",
          vm, vm->pid, vm->def->id, vm->def->name, vendor, product);

    if (virAsprintf(&addr, "host:%.4x:%.4x", vendor, product) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorAddUSBDevice(vm, addr);

    VIR_FREE(addr);
    return ret;
}


static int
qemuMonitorParsePciAddReply(virDomainObjPtr vm,
                            const char *reply,
                            unsigned *domain,
                            unsigned *bus,
                            unsigned *slot)
{
    char *s, *e;

    DEBUG("%s: pci_add reply: %s", vm->def->name, reply);

    /* If the command succeeds qemu prints:
     * OK bus 0, slot XXX...
     * or
     * OK domain 0, bus 0, slot XXX
     */
    if (!(s = strstr(reply, "OK ")))
        return -1;

    s += 3;

    if (STRPREFIX(s, "domain ")) {
        s += strlen("domain ");

        if (virStrToLong_ui(s, &e, 10, domain) == -1) {
            VIR_WARN(_("Unable to parse domain number '%s'\n"), s);
            return -1;
        }

        if (!STRPREFIX(e, ", ")) {
            VIR_WARN(_("Expected ', ' parsing pci_add reply '%s'\n"), s);
            return -1;
        }
        s = e + 2;
    }

    if (!STRPREFIX(s, "bus ")) {
        VIR_WARN(_("Expected 'bus ' parsing pci_add reply '%s'\n"), s);
        return -1;
    }
    s += strlen("bus ");

    if (virStrToLong_ui(s, &e, 10, bus) == -1) {
        VIR_WARN(_("Unable to parse bus number '%s'\n"), s);
        return -1;
    }

    if (!STRPREFIX(e, ", ")) {
        VIR_WARN(_("Expected ', ' parsing pci_add reply '%s'\n"), s);
        return -1;
    }
    s = e + 2;

    if (!STRPREFIX(s, "slot ")) {
        VIR_WARN(_("Expected 'slot ' parsing pci_add reply '%s'\n"), s);
        return -1;
    }
    s += strlen("slot ");

    if (virStrToLong_ui(s, &e, 10, slot) == -1) {
        VIR_WARN(_("Unable to parse slot number '%s'\n"), s);
        return -1;
    }

    return 0;
}


int qemuMonitorAddPCIHostDevice(const virDomainObjPtr vm,
                                unsigned hostDomain ATTRIBUTE_UNUSED,
                                unsigned hostBus,
                                unsigned hostSlot,
                                unsigned hostFunction,
                                unsigned *guestDomain,
                                unsigned *guestBus,
                                unsigned *guestSlot)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s domain=%d bus=%d slot=%d function=%d",
          vm, vm->pid, vm->def->id, vm->def->name,
          hostDomain, hostBus, hostSlot, hostFunction);

    *guestDomain = *guestBus = *guestSlot = 0;

    /* XXX hostDomain */
    if (virAsprintf(&cmd, "pci_add pci_addr=auto host host=%.2x:%.2x.%.1x",
                    hostBus, hostSlot, hostFunction) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach host pci device"));
        goto cleanup;
    }

    if (strstr(reply, "invalid type: host")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_SUPPORT, "%s",
                         _("PCI device assignment is not supported by this version of qemu"));
        goto cleanup;
    }

    if (qemuMonitorParsePciAddReply(vm, reply,
                                    guestDomain,
                                    guestBus,
                                    guestSlot) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("parsing pci_add reply failed: %s"), reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorAddPCIDisk(const virDomainObjPtr vm,
                          const char *path,
                          const char *bus,
                          unsigned *guestDomain,
                          unsigned *guestBus,
                          unsigned *guestSlot) {
    char *cmd = NULL;
    char *reply = NULL;
    char *safe_path = NULL;
    int tryOldSyntax = 0;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s path=%s bus=%s",
          vm, vm->pid, vm->def->id, vm->def->name, path, bus);

    safe_path = qemuMonitorEscapeArg(path);
    if (!safe_path) {
        virReportOOMError(NULL);
        return -1;
    }

try_command:
    if (virAsprintf(&cmd, "pci_add %s storage file=%s,if=%s",
                    (tryOldSyntax ? "0": "pci_addr=auto"), safe_path, bus) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("cannot attach %s disk %s"), bus, path);
        goto cleanup;
    }

    if (qemuMonitorParsePciAddReply(vm, reply,
                                    guestDomain, guestBus, guestSlot) < 0) {
        if (!tryOldSyntax && strstr(reply, "invalid char in expression")) {
            VIR_FREE(reply);
            VIR_FREE(cmd);
            tryOldSyntax = 1;
            goto try_command;
        }

        qemudReportError (NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          _("adding %s disk failed %s: %s"), bus, path, reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(safe_path);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorAddPCINetwork(const virDomainObjPtr vm,
                             const char *nicstr,
                             unsigned *guestDomain,
                             unsigned *guestBus,
                             unsigned *guestSlot)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s nicstr=%s",
          vm, vm->pid, vm->def->id, vm->def->name, nicstr);

    if (virAsprintf(&cmd, "pci_add pci_addr=auto nic %s", nicstr) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to add NIC with '%s'"), cmd);
        goto cleanup;
    }

    if (qemuMonitorParsePciAddReply(vm, reply,
                                    guestDomain, guestBus, guestSlot) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("parsing pci_add reply failed: %s"), reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}


int qemuMonitorRemovePCIDevice(const virDomainObjPtr vm,
                               unsigned guestDomain,
                               unsigned guestBus,
                               unsigned guestSlot)
{
    char *cmd = NULL;
    char *reply = NULL;
    int tryOldSyntax = 0;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s domain=%d bus=%d slot=%d",
          vm, vm->pid, vm->def->id, vm->def->name, guestDomain, guestBus, guestSlot);

try_command:
    if (tryOldSyntax) {
        if (virAsprintf(&cmd, "pci_del 0 %.2x", guestSlot) < 0) {
            virReportOOMError(NULL);
            goto cleanup;
        }
    } else {
        if (virAsprintf(&cmd, "pci_del pci_addr=%.4x:%.2x:%.2x",
                        guestDomain, guestBus, guestSlot) < 0) {
            virReportOOMError(NULL);
            goto cleanup;
        }
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to remove PCI device"));
        goto cleanup;
    }

    /* Syntax changed when KVM merged PCI hotplug upstream to QEMU,
     * so check for an error message from old KVM indicating the
     * need to try the old syntax */
    if (!tryOldSyntax &&
        strstr(reply, "extraneous characters")) {
        tryOldSyntax = 1;
        VIR_FREE(reply);
        VIR_FREE(cmd);
        goto try_command;
    }
    /* If the command fails due to a wrong slot qemu prints: invalid slot,
     * nothing is printed on success */
    if (strstr(reply, "invalid slot") ||
        strstr(reply, "Invalid pci address")) {
        qemudReportError (NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          _("failed to detach PCI device, invalid address %.4x:%.2x:%.2x: %s"),
                          guestDomain, guestBus, guestSlot, reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorSendFileHandle(const virDomainObjPtr vm,
                              const char *fdname,
                              int fd)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s fdname=%s fd=%d",
          vm, vm->pid, vm->def->id, vm->def->name, fdname, fd);

    if (virAsprintf(&cmd, "getfd %s", fdname) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommandWithFd(vm, cmd, fd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to pass fd to qemu with '%s'"), cmd);
        goto cleanup;
    }

    /* If the command isn't supported then qemu prints:
     * unknown command: getfd" */
    if (strstr(reply, "unknown command:")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         _("qemu does not support sending of file handles: %s"),
                         reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorCloseFileHandle(const virDomainObjPtr vm,
                               const char *fdname)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s fdname=%s",
          vm, vm->pid, vm->def->id, vm->def->name, fdname);

    if (virAsprintf(&cmd, "closefd %s", fdname) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to close fd in qemu with '%s'"), cmd);
        goto cleanup;
    }

    /* If the command isn't supported then qemu prints:
     * unknown command: getfd" */
    if (strstr(reply, "unknown command:")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         _("qemu does not support closing of file handles: %s"),
                         reply);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorAddHostNetwork(const virDomainObjPtr vm,
                              const char *netstr)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s netstr=%s",
          vm, vm->pid, vm->def->id, vm->def->name, netstr);

    if (virAsprintf(&cmd, "host_net_add %s", netstr) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to close fd in qemu with '%s'"), cmd);
        goto cleanup;
    }

    /* XXX error messages here ? */

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorRemoveHostNetwork(const virDomainObjPtr vm,
                                 int vlan,
                                 const char *netname)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    DEBUG("vm=%p, pid=%d, id=%d, name=%s netname=%s",
          vm, vm->pid, vm->def->id, vm->def->name, netname);

    if (virAsprintf(&cmd, "host_net_remove %d %s", vlan, netname) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(vm, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to remove host metnwork in qemu with '%s'"), cmd);
        goto cleanup;
    }

    /* XXX error messages here ? */

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}
