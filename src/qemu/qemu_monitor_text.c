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
typedef int qemuMonitorExtraPromptHandler(qemuMonitorPtr mon,
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

/* When connecting to a monitor, QEMU will print a greeting like
 *
 * QEMU 0.11.0 monitor - type 'help' for more information
 *
 * Don't expect the version number bit to be stable :-)
 */
#define GREETING_PREFIX "QEMU "
#define GREETING_POSTFIX "type 'help' for more information\r\n(qemu) "
#define BASIC_PROMPT "(qemu) "
#define PASSWORD_PROMPT "Password:"
#define DISK_ENCRYPTION_PREFIX "("
#define DISK_ENCRYPTION_POSTFIX ") is encrypted."
#define LINE_ENDING "\r\n"

int qemuMonitorTextIOProcess(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                             const char *data,
                             size_t len,
                             qemuMonitorMessagePtr msg)
{
    int used = 0;

    /* Check for & discard greeting */
    if (STRPREFIX(data, GREETING_PREFIX)) {
        const char *offset = strstr(data, GREETING_POSTFIX);

        /* We see the greeting prefix, but not postfix, so pretend we've
           not consumed anything. We'll restart when more data arrives. */
        if (!offset) {
            VIR_DEBUG0("Partial greeting seen, getting out & waiting for more");
            return 0;
        }

        used = offset - data + strlen(GREETING_POSTFIX);

        VIR_DEBUG0("Discarded monitor greeting");
    }

    /* Don't print raw data in debug because its full of control chars */
    /*VIR_DEBUG("Process data %d byts of data [%s]", len - used, data + used);*/
    VIR_DEBUG("Process data %d byts of data", (int)(len - used));

    /* Look for a non-zero reply followed by prompt */
    if (msg && !msg->finished) {
        const char *end;

        /* We might get a prompt for a password */
        end = strstr(data + used, PASSWORD_PROMPT);
        if (end) {
            VIR_DEBUG("Woooo passwowrd [%s]", data + used);
            if (msg->passwordHandler) {
                size_t consumed;
                /* Try and handle the prompt */
                if (msg->passwordHandler(mon, msg,
                                         data + used,
                                         len - used,
                                         msg->passwordOpaque) < 0)
                    return -1;

                /* Skip over prompt now */
                consumed = (end + strlen(PASSWORD_PROMPT))
                    - (data + used);
                used += consumed;
            } else {
                errno = EACCES;
                return -1;
            }
        }

        /* We use the arrival of BASIC_PROMPT to detect when we've got a
         * complete reply available from a command */
        end = strstr(data + used, BASIC_PROMPT);
        if (end) {
            /* QEMU echos the command back to us, full of control
             * character junk that we don't want. Fortunately this
             * is all terminated by LINE_ENDING, so we can easily
             * skip over the control character junk */
            const char *start = strstr(data + used, LINE_ENDING);
            if (!start)
                start = data + used;
            else
                start += strlen(LINE_ENDING);
            int want = end - start;

            /* Annoyingly some commands may not have any reply data
             * at all upon success, but since we've detected the
             * BASIC_PROMPT we can reasonably reliably cope */
            if (want) {
                if (VIR_REALLOC_N(msg->rxBuffer,
                                  msg->rxLength + want + 1) < 0)
                    return -1;
                memcpy(msg->rxBuffer + msg->rxLength, start, want);
                msg->rxLength += want;
                msg->rxBuffer[msg->rxLength] = '\0';
                VIR_DEBUG("Finished %d byte reply [%s]", want, msg->rxBuffer);
            } else {
                VIR_DEBUG0("Finished 0 byte reply");
            }
            msg->finished = 1;
            used += end - (data + used);
            used += strlen(BASIC_PROMPT);
        }
    }

    VIR_DEBUG("Total used %d", used);
    return used;
}

static int
qemuMonitorCommandWithHandler(qemuMonitorPtr mon,
                              const char *cmd,
                              qemuMonitorPasswordHandler passwordHandler,
                              void *passwordOpaque,
                              int scm_fd,
                              char **reply) {
    int ret;
    qemuMonitorMessage msg;

    *reply = NULL;

    memset(&msg, 0, sizeof msg);

    if (virAsprintf(&msg.txBuffer, "%s\r", cmd) < 0) {
        virReportOOMError(NULL);
        return -1;
    }
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;
    msg.passwordHandler = passwordHandler;
    msg.passwordOpaque = passwordOpaque;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmd, scm_fd);

    ret = qemuMonitorSend(mon, &msg);

    VIR_DEBUG("Receive command reply ret=%d errno=%d %d bytes '%s'",
              ret, msg.lastErrno, msg.rxLength, msg.rxBuffer);

    /* Just in case buffer had some passwords in */
    memset(msg.txBuffer, 0, msg.txLength);
    VIR_FREE(msg.txBuffer);

    /* To make life safer for callers, already ensure there's at least an empty string */
    if (msg.rxBuffer) {
        *reply = msg.rxBuffer;
    } else {
        *reply = strdup("");
        if (!*reply) {
            virReportOOMError(NULL);
            return -1;
        }
    }

    if (ret < 0)
        virReportSystemError(NULL, msg.lastErrno,
                             _("cannot send monitor command '%s'"), cmd);

    return ret;
}

static int
qemuMonitorCommandWithFd(qemuMonitorPtr mon,
                          const char *cmd,
                          int scm_fd,
                          char **reply) {
    return qemuMonitorCommandWithHandler(mon, cmd, NULL, NULL, scm_fd, reply);
}

static int
qemuMonitorCommand(qemuMonitorPtr mon,
                    const char *cmd,
                    char **reply) {
    return qemuMonitorCommandWithFd(mon, cmd, -1, reply);
}


static int
qemuMonitorSendDiskPassphrase(qemuMonitorPtr mon,
                              qemuMonitorMessagePtr msg,
                              const char *data,
                              size_t len ATTRIBUTE_UNUSED,
                              void *opaque)
{
    virConnectPtr conn = opaque;
    char *path;
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    int res;
    const char *pathStart;
    const char *pathEnd;

    /*
     * For disk passwords:
     *
     *    ide0-hd0 (/path/to/volume) is encrypted.
     *    Password:
     *
     */
    pathStart = strstr(data, DISK_ENCRYPTION_PREFIX);
    pathEnd = strstr(data, DISK_ENCRYPTION_POSTFIX);
    if (!pathStart || !pathEnd || pathStart >= pathEnd) {
        errno = -EINVAL;
        return -1;
    }

    /* Extra the path */
    pathStart += strlen(DISK_ENCRYPTION_PREFIX);
    path = strndup(pathStart, pathEnd - pathStart);
    if (!path) {
        errno = ENOMEM;
        return -1;
    }

    /* Fetch the disk password if possible */
    res = qemuMonitorGetDiskSecret(mon,
                                   conn,
                                   path,
                                   &passphrase,
                                   &passphrase_len);
    VIR_FREE(path);
    if (res < 0)
        return -1;

    /* Enlarge transmit buffer to allow for the extra data
     * to be sent back */
    if (VIR_REALLOC_N(msg->txBuffer,
                      msg->txLength + passphrase_len + 1 + 1) < 0) {
        memset(passphrase, 0, passphrase_len);
        VIR_FREE(passphrase);
        errno = ENOMEM;
        return -1;
    }

    /* Queue the password for sending */
    memcpy(msg->txBuffer + msg->txLength,
           passphrase, passphrase_len);
    msg->txLength += passphrase_len;
    msg->txBuffer[msg->txLength] = '\r';
    msg->txLength++;
    msg->txBuffer[msg->txLength] = '\0';

    memset(passphrase, 0, passphrase_len);
    VIR_FREE(passphrase);

    return 0;
}

int
qemuMonitorTextStartCPUs(qemuMonitorPtr mon,
                         virConnectPtr conn) {
    char *reply;

    if (qemuMonitorCommandWithHandler(mon, "cont",
                                      qemuMonitorSendDiskPassphrase,
                                      conn,
                                      -1, &reply) < 0)
        return -1;

    VIR_FREE(reply);
    return 0;
}


int
qemuMonitorTextStopCPUs(qemuMonitorPtr mon) {
    char *info;

    if (qemuMonitorCommand(mon, "stop", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot stop CPU execution"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}


int qemuMonitorTextSystemPowerdown(qemuMonitorPtr mon) {
    char *info;

    if (qemuMonitorCommand(mon, "system_powerdown", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("system shutdown operation failed"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}


int qemuMonitorTextGetCPUInfo(qemuMonitorPtr mon,
                              int **pids)
{
    char *qemucpus = NULL;
    char *line;
    int lastVcpu = -1;
    pid_t *cpupids = NULL;
    size_t ncpupids = 0;

    if (qemuMonitorCommand(mon, "info cpus", &qemucpus) < 0) {
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
int qemuMonitorTextGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long *currmem)
{
    char *reply = NULL;
    int ret = -1;
    char *offset;

    if (qemuMonitorCommand(mon, "info balloon", &reply) < 0) {
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


int qemuMonitorTextGetBlockStatsInfo(qemuMonitorPtr mon,
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

    if (qemuMonitorCommand (mon, "info blockstats", &info) < 0) {
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
                        DEBUG ("error reading rd_bytes: %s", p);
                } else if (STRPREFIX (p, "wr_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, wr_bytes) == -1)
                        DEBUG ("error reading wr_bytes: %s", p);
                } else if (STRPREFIX (p, "rd_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, rd_req) == -1)
                        DEBUG ("error reading rd_req: %s", p);
                } else if (STRPREFIX (p, "wr_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, wr_req) == -1)
                        DEBUG ("error reading wr_req: %s", p);
                } else
                    DEBUG ("unknown block stat near %s", p);

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


static int
qemuMonitorSendVNCPassphrase(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                             qemuMonitorMessagePtr msg,
                             const char *data ATTRIBUTE_UNUSED,
                             size_t len ATTRIBUTE_UNUSED,
                             void *opaque)
{
    char *passphrase = opaque;
    size_t passphrase_len = strlen(passphrase);

    /* Enlarge transmit buffer to allow for the extra data
     * to be sent back */
    if (VIR_REALLOC_N(msg->txBuffer,
                      msg->txLength + passphrase_len + 1 + 1) < 0) {
        errno = ENOMEM;
        return -1;
    }

    /* Queue the password for sending */
    memcpy(msg->txBuffer + msg->txLength,
           passphrase, passphrase_len);
    msg->txLength += passphrase_len;
    msg->txBuffer[msg->txLength] = '\r';
    msg->txLength++;
    msg->txBuffer[msg->txLength] = '\0';

    return 0;
}

int qemuMonitorTextSetVNCPassword(qemuMonitorPtr mon,
                                  const char *password)
{
    char *info = NULL;

    if (qemuMonitorCommandWithHandler(mon, "change vnc password",
                                      qemuMonitorSendVNCPassphrase,
                                      (char *)password,
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
int qemuMonitorTextSetBalloon(qemuMonitorPtr mon,
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

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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

int qemuMonitorTextEjectMedia(qemuMonitorPtr mon,
                              const char *devname)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "eject %s", devname) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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


int qemuMonitorTextChangeMedia(qemuMonitorPtr mon,
                               const char *devname,
                               const char *newmedia)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safepath = NULL;
    int ret = -1;

    if (!(safepath = qemuMonitorEscapeArg(newmedia))) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (virAsprintf(&cmd, "change %s \"%s\"", devname, safepath) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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

static int qemuMonitorTextSaveMemory(qemuMonitorPtr mon,
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

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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


int qemuMonitorTextSaveVirtualMemory(qemuMonitorPtr mon,
                                     unsigned long long offset,
                                     size_t length,
                                     const char *path)
{
    return qemuMonitorTextSaveMemory(mon, "memsave", offset, length, path);
}

int qemuMonitorTextSavePhysicalMemory(qemuMonitorPtr mon,
                                      unsigned long long offset,
                                      size_t length,
                                      const char *path)
{
    return qemuMonitorTextSaveMemory(mon, "pmemsave", offset, length, path);
}


int qemuMonitorTextSetMigrationSpeed(qemuMonitorPtr mon,
                                     unsigned long bandwidth)
{
    char *cmd = NULL;
    char *info = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "migrate_set_speed %lum", bandwidth) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(mon, cmd, &info) < 0) {
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

int qemuMonitorTextGetMigrationStatus(qemuMonitorPtr mon,
                                      int *status,
                                      unsigned long long *transferred,
                                      unsigned long long *remaining,
                                      unsigned long long *total) {
    char *reply;
    char *tmp;
    char *end;
    int ret = -1;

    *status = QEMU_MONITOR_MIGRATION_STATUS_INACTIVE;
    *transferred = 0;
    *remaining = 0;
    *total = 0;

    if (qemuMonitorCommand(mon, "info migrate", &reply) < 0) {
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


static int qemuMonitorTextMigrate(qemuMonitorPtr mon,
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

    if (qemuMonitorCommand(mon, cmd, &info) < 0) {
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

int qemuMonitorTextMigrateToHost(qemuMonitorPtr mon,
                                 int background,
                                 const char *hostname,
                                 int port)
{
    char *uri = NULL;
    int ret;

    if (virAsprintf(&uri, "tcp:%s:%d", hostname, port) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorTextMigrate(mon, background, uri);

    VIR_FREE(uri);

    return ret;
}


int qemuMonitorTextMigrateToCommand(qemuMonitorPtr mon,
                                    int background,
                                    const char * const *argv,
                                    const char *target)
{
    char *argstr;
    char *dest = NULL;
    int ret = -1;
    char *safe_target = NULL;

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

    ret = qemuMonitorTextMigrate(mon, background, dest);

cleanup:
    VIR_FREE(safe_target);
    VIR_FREE(argstr);
    VIR_FREE(dest);
    return ret;
}

int qemuMonitorTextMigrateToUnix(qemuMonitorPtr mon,
                             int background,
                             const char *unixfile)
{
    char *dest = NULL;
    int ret = -1;

    if (virAsprintf(&dest, "unix:%s", unixfile) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorTextMigrate(mon, background, dest);

    VIR_FREE(dest);

    return ret;
}

int qemuMonitorTextMigrateCancel(qemuMonitorPtr mon)
{
    char *info = NULL;

    if (qemuMonitorCommand(mon, "migrate cancel", &info) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot run monitor command to cancel migration"));
        return -1;
    }
    VIR_FREE(info);

    return 0;
}

int qemuMonitorTextAddUSBDisk(qemuMonitorPtr mon,
                              const char *path)
{
    char *cmd = NULL;
    char *safepath;
    int ret = -1;
    char *info = NULL;

    safepath = qemuMonitorEscapeArg(path);
    if (!safepath) {
        virReportOOMError(NULL);
        return -1;
    }

    if (virAsprintf(&cmd, "usb_add disk:%s", safepath) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(mon, cmd, &info) < 0) {
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


static int qemuMonitorTextAddUSBDevice(qemuMonitorPtr mon,
                                       const char *addr)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "usb_add %s", addr) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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


int qemuMonitorTextAddUSBDeviceExact(qemuMonitorPtr mon,
                                     int bus,
                                     int dev)
{
    int ret;
    char *addr;

    if (virAsprintf(&addr, "host:%.3d.%.3d", bus, dev) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorTextAddUSBDevice(mon, addr);

    VIR_FREE(addr);
    return ret;
}

int qemuMonitorTextAddUSBDeviceMatch(qemuMonitorPtr mon,
                                     int vendor,
                                     int product)
{
    int ret;
    char *addr;

    if (virAsprintf(&addr, "host:%.4x:%.4x", vendor, product) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorTextAddUSBDevice(mon, addr);

    VIR_FREE(addr);
    return ret;
}


static int
qemuMonitorTextParsePciAddReply(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                const char *reply,
                                unsigned *domain,
                                unsigned *bus,
                                unsigned *slot)
{
    char *s, *e;

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


int qemuMonitorTextAddPCIHostDevice(qemuMonitorPtr mon,
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

    *guestDomain = *guestBus = *guestSlot = 0;

    /* XXX hostDomain */
    if (virAsprintf(&cmd, "pci_add pci_addr=auto host host=%.2x:%.2x.%.1x",
                    hostBus, hostSlot, hostFunction) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach host pci device"));
        goto cleanup;
    }

    if (strstr(reply, "invalid type: host")) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_SUPPORT, "%s",
                         _("PCI device assignment is not supported by this version of qemu"));
        goto cleanup;
    }

    if (qemuMonitorTextParsePciAddReply(mon, reply,
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


int qemuMonitorTextAddPCIDisk(qemuMonitorPtr mon,
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

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("cannot attach %s disk %s"), bus, path);
        goto cleanup;
    }

    if (qemuMonitorTextParsePciAddReply(mon, reply,
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


int qemuMonitorTextAddPCINetwork(qemuMonitorPtr mon,
                                 const char *nicstr,
                                 unsigned *guestDomain,
                                 unsigned *guestBus,
                                 unsigned *guestSlot)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "pci_add pci_addr=auto nic %s", nicstr) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to add NIC with '%s'"), cmd);
        goto cleanup;
    }

    if (qemuMonitorTextParsePciAddReply(mon, reply,
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


int qemuMonitorTextRemovePCIDevice(qemuMonitorPtr mon,
                                   unsigned guestDomain,
                                   unsigned guestBus,
                                   unsigned guestSlot)
{
    char *cmd = NULL;
    char *reply = NULL;
    int tryOldSyntax = 0;
    int ret = -1;

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

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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


int qemuMonitorTextSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "getfd %s", fdname) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommandWithFd(mon, cmd, fd, &reply) < 0) {
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


int qemuMonitorTextCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "closefd %s", fdname) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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


int qemuMonitorTextAddHostNetwork(qemuMonitorPtr mon,
                                  const char *netstr)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "host_net_add %s", netstr) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
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


int qemuMonitorTextRemoveHostNetwork(qemuMonitorPtr mon,
                                     int vlan,
                                     const char *netname)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "host_net_remove %d %s", vlan, netname) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    if (qemuMonitorCommand(mon, cmd, &reply) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to remove host network in qemu with '%s'"), cmd);
        goto cleanup;
    }

    /* XXX error messages here ? */

    ret = 0;

cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}
