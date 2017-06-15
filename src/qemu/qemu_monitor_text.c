/*
 * qemu_monitor_text.c: interaction with QEMU monitor console
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>

#include "qemu_monitor_text.h"
#include "qemu_alias.h"
#include "c-ctype.h"
#include "c-strcasestr.h"
#include "viralloc.h"
#include "virlog.h"
#include "driver.h"
#include "datatypes.h"
#include "virerror.h"
#include "virbuffer.h"
#include "virprobe.h"
#include "virstring.h"

#ifdef WITH_DTRACE_PROBES
# include "libvirt_qemu_probes.h"
#endif

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor_text");

#define DEBUG_IO 0

/* Return -1 for error, 0 for success */
typedef int qemuMonitorExtraPromptHandler(qemuMonitorPtr mon,
                                          const char *buf,
                                          const char *prompt,
                                          void *data);


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
                             size_t len ATTRIBUTE_UNUSED,
                             qemuMonitorMessagePtr msg)
{
    int used = 0;

    /* Check for & discard greeting */
    if (STRPREFIX(data, GREETING_PREFIX)) {
        const char *offset = strstr(data, GREETING_POSTFIX);

        /* We see the greeting prefix, but not postfix, so pretend we've
           not consumed anything. We'll restart when more data arrives. */
        if (!offset) {
#if DEBUG_IO
            VIR_DEBUG("Partial greeting seen, getting out & waiting for more");
#endif
            return 0;
        }

        used = offset - data + strlen(GREETING_POSTFIX);

#if DEBUG_IO
        VIR_DEBUG("Discarded monitor greeting");
#endif
    }

    /* Don't print raw data in debug because its full of control chars */
    /*VIR_DEBUG("Process data %d byts of data [%s]", len - used, data + used);*/
#if DEBUG_IO
    VIR_DEBUG("Process data %d byts of data", (int)(len - used));
#endif

    /* Look for a non-zero reply followed by prompt */
    if (msg && !msg->finished) {
        char *start = NULL;
        char *end = NULL;
        char *skip;

        /* If we're here, we've already sent the command. We now
         * strip the trailing '\r' because it makes the matching
         * code that follows a little easier ie we can just strstr()
         * for the original command
         */
        if (msg->txLength > 0) {
            char *tmp;
            if ((tmp = strchr(msg->txBuffer, '\r')))
                *tmp = '\0';
        }

        /* QEMU echos the command back to us, full of control
         * character junk that we don't want. We have to skip
         * over this junk by looking for the first complete
         * repetition of our command. Then we can look for
         * the prompt that is supposed to follow
         *
         * NB, we can't optimize by immediately looking for
         * LINE_ENDING, because QEMU 0.10 has bad problems
         * when initially connecting where it might write a
         * prompt in the wrong place. So we must not look
         * for LINE_ENDING, or BASIC_PROMPT until we've
         * seen our original command echod.
         */
        skip = strstr(data + used, msg->txBuffer);

        /* After the junk we should have a line ending... */
        if (skip)
            start = strstr(skip + strlen(msg->txBuffer), LINE_ENDING);

        /* ... then our command reply data, following by a (qemu) prompt */
        if (start) {
            char *passwd;
            start += strlen(LINE_ENDING);

            /* We might get a prompt for a password before the (qemu) prompt */
            passwd = strstr(start, PASSWORD_PROMPT);
            if (passwd) {
#if DEBUG_IO
                VIR_DEBUG("Seen a password prompt [%s]", data + used);
#endif
                if (msg->passwordHandler) {
                    size_t i;
                    /* Try and handle the prompt. The handler is required
                     * to report a normal libvirt error */
                    if (msg->passwordHandler(mon, msg,
                                             start,
                                             passwd - start + strlen(PASSWORD_PROMPT),
                                             msg->passwordOpaque) < 0)
                        return -1;

                    /* Blank out the password prompt so we don't re-trigger
                     * if we have to go back to sleep for more I/O */
                    for (i = 0; i < strlen(PASSWORD_PROMPT); i++)
                        start[i] = ' ';

                    /* Handled, so skip forward over password prompt */
                    start = passwd;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Password request seen, but no handler available"));
                    return -1;
                }
            }

            end = strstr(start, BASIC_PROMPT);
        }

        if (start && end) {
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
#if DEBUG_IO
                VIR_DEBUG("Finished %d byte reply [%s]", want, msg->rxBuffer);
            } else {
                VIR_DEBUG("Finished 0 byte reply");
#endif
            }
            PROBE(QEMU_MONITOR_RECV_REPLY,
                  "mon=%p reply=%s",
                  mon, msg->rxBuffer);
            msg->finished = 1;
            used += end - (data + used);
            used += strlen(BASIC_PROMPT);
        }
    }

#if DEBUG_IO
    VIR_DEBUG("Total used %d", used);
#endif
    return used;
}

static int
qemuMonitorTextCommandWithHandler(qemuMonitorPtr mon,
                                  const char *cmd,
                                  qemuMonitorPasswordHandler passwordHandler,
                                  void *passwordOpaque,
                                  int scm_fd,
                                  char **reply)
{
    int ret;
    qemuMonitorMessage msg;

    *reply = NULL;

    memset(&msg, 0, sizeof(msg));

    if (virAsprintf(&msg.txBuffer, "%s\r", cmd) < 0)
        return -1;
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;
    msg.passwordHandler = passwordHandler;
    msg.passwordOpaque = passwordOpaque;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmd, scm_fd);

    ret = qemuMonitorSend(mon, &msg);

    VIR_DEBUG("Receive command reply ret=%d rxLength=%d rxBuffer='%s'",
              ret, msg.rxLength, msg.rxBuffer);

    /* Just in case buffer had some passwords in */
    memset(msg.txBuffer, 0, msg.txLength);
    VIR_FREE(msg.txBuffer);

    if (ret >= 0) {
        /* To make life safer for callers, already ensure there's at least an empty string */
        if (msg.rxBuffer) {
            *reply = msg.rxBuffer;
        } else {
            if (VIR_STRDUP(*reply, "") < 0)
                return -1;
        }
    }

    return ret;
}

int
qemuMonitorTextCommandWithFd(qemuMonitorPtr mon,
                             const char *cmd,
                             int scm_fd,
                             char **reply)
{
    return qemuMonitorTextCommandWithHandler(mon, cmd, NULL, NULL,
                                             scm_fd, reply);
}

/* Check monitor output for evidence that the command was not recognized.
 * For 'info' commands, qemu returns help text.  For other commands, qemu
 * returns 'unknown command:'.
 */
static int
qemuMonitorTextCommandNotFound(const char *cmd, const char *reply)
{
    if (STRPREFIX(cmd, "info ")) {
        if (strstr(reply, "info version"))
            return 1;
    } else {
        if (strstr(reply, "unknown command:"))
            return 1;
    }

    return 0;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to extract disk path from %s"),
                       data);
        return -1;
    }

    /* Extra the path */
    pathStart += strlen(DISK_ENCRYPTION_PREFIX);
    if (VIR_STRNDUP(path, pathStart, pathEnd - pathStart) < 0)
        return -1;

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
                         virConnectPtr conn)
{
    char *reply;

    if (qemuMonitorTextCommandWithHandler(mon, "cont",
                                          qemuMonitorSendDiskPassphrase,
                                          conn,
                                          -1, &reply) < 0)
        return -1;

    VIR_FREE(reply);
    return 0;
}


int
qemuMonitorTextStopCPUs(qemuMonitorPtr mon)
{
    char *info;
    int ret;

    ret = qemuMonitorHMPCommand(mon, "stop", &info);
    VIR_FREE(info);
    return ret;
}


int
qemuMonitorTextGetStatus(qemuMonitorPtr mon,
                         bool *running,
                         virDomainPausedReason *reason)
{
    char *reply;
    int ret = -1;

    if (reason)
        *reason = VIR_DOMAIN_PAUSED_UNKNOWN;

    if (qemuMonitorHMPCommand(mon, "info status", &reply) < 0)
        return -1;

    if (strstr(reply, "running")) {
        *running = true;
    } else if (strstr(reply, "paused")) {
        char *status;

        if ((status = strchr(reply, '('))) {
            char *end = strchr(status, ')');
            if (end)
                *end = '\0';
            else
                status = NULL;
        }
        if (!status)
            VIR_DEBUG("info status was missing status details");
        else if (reason)
            *reason = qemuMonitorVMStatusToPausedReason(status);
        *running = false;
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("unexpected reply from info status: %s"), reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorTextSystemPowerdown(qemuMonitorPtr mon)
{
    char *info;
    int ret;

    ret = qemuMonitorHMPCommand(mon, "system_powerdown", &info);

    VIR_FREE(info);
    return ret;
}

int
qemuMonitorTextSetLink(qemuMonitorPtr mon,
                       const char *name,
                       virDomainNetInterfaceLinkState state)
{
    char *info = NULL;
    char *cmd = NULL;
    const char *st_str = NULL;

    /* determine state */
    if (state == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN)
        st_str = "off";
    else
        st_str = "on";

    if (virAsprintf(&cmd, "set_link %s %s", name, st_str) < 0)
        goto error;
    if (qemuMonitorHMPCommand(mon, cmd, &info) < 0)
        goto error;

    /* check if set_link command is supported */
    if (strstr(info, "\nunknown ")) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       "%s",
                       _("\'set_link\' not supported by this qemu"));
        goto error;
    }

    /* check if qemu didn't reject device name */
    if (strstr(info, "\nDevice ")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("device name rejected"));
        goto error;
    }

    VIR_FREE(info);
    VIR_FREE(cmd);
    return 0;

 error:
    VIR_FREE(info);
    VIR_FREE(cmd);

    return -1;
}

int qemuMonitorTextSystemReset(qemuMonitorPtr mon)
{
    char *info;
    int ret;

    ret = qemuMonitorHMPCommand(mon, "system_reset", &info);

    VIR_FREE(info);
    return ret;
}


int
qemuMonitorTextQueryCPUs(qemuMonitorPtr mon,
                         struct qemuMonitorQueryCpusEntry **entries,
                         size_t *nentries)
{
    char *qemucpus = NULL;
    char *line;
    struct qemuMonitorQueryCpusEntry *cpus = NULL;
    size_t ncpus = 0;
    struct qemuMonitorQueryCpusEntry cpu = {0};
    int ret = -2; /* -2 denotes a non-fatal error to get the data */

    if (qemuMonitorHMPCommand(mon, "info cpus", &qemucpus) < 0)
        return -1;

    /*
     * This is the gross format we're about to parse :-{
     *
     * (qemu) info cpus
     * * CPU #0: pc=0x00000000000f0c4a thread_id=30019
     *   CPU #1: pc=0x00000000fffffff0 thread_id=30020
     *   CPU #2: pc=0x00000000fffffff0 (halted) thread_id=30021
     *
     */
    line = qemucpus;
    do {
        char *offset = NULL;
        char *end = NULL;
        int cpuid = -1;
        int tid = 0;

        /* extract cpu number */
        if ((offset = strstr(line, "#")) == NULL)
            goto cleanup;

        if (virStrToLong_i(offset + strlen("#"), &end, 10, &cpuid) < 0)
            goto cleanup;
        if (end == NULL || *end != ':')
            goto cleanup;

        /* Extract host Thread ID */
        if ((offset = strstr(line, "thread_id=")) == NULL)
            goto cleanup;

        if (virStrToLong_i(offset + strlen("thread_id="), &end, 10, &tid) < 0)
            goto cleanup;
        if (end == NULL || !c_isspace(*end))
            goto cleanup;

        cpu.qemu_id = cpuid;
        cpu.tid = tid;

        if (VIR_APPEND_ELEMENT_COPY(cpus, ncpus, cpu) < 0) {
            ret = -1;
            goto cleanup;
        }

        VIR_DEBUG("tid=%d", tid);

        /* Skip to next data line */
        line = strchr(offset, '\r');
        if (line == NULL)
            line = strchr(offset, '\n');
    } while (line != NULL);

    VIR_STEAL_PTR(*entries, cpus);
    *nentries = ncpus;
    ret = 0;

 cleanup:
    qemuMonitorQueryCpusFree(cpus, ncpus);
    VIR_FREE(qemucpus);
    return ret;
}


int qemuMonitorTextGetVirtType(qemuMonitorPtr mon,
                               virDomainVirtType *virtType)
{
    char *reply = NULL;

    *virtType = VIR_DOMAIN_VIRT_QEMU;

    if (qemuMonitorHMPCommand(mon, "info kvm", &reply) < 0)
        return -1;

    if (strstr(reply, "enabled"))
        *virtType = VIR_DOMAIN_VIRT_KVM;

    VIR_FREE(reply);
    return 0;
}


static int parseMemoryStat(char **text, unsigned int tag,
                           const char *search, virDomainMemoryStatPtr mstat)
{
    char *dummy;
    unsigned long long value;

    if (STRPREFIX(*text, search)) {
        *text += strlen(search);
        if (virStrToLong_ull(*text, &dummy, 10, &value)) {
            VIR_DEBUG("error reading %s: %s", search, *text);
            return 0;
        }

        switch (tag) {
            /* Convert megabytes to kilobytes for libvirt */
            case VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON:
                value <<= 10;
                break;
            /* Convert bytes to kilobytes for libvirt */
            case VIR_DOMAIN_MEMORY_STAT_SWAP_IN:
            case VIR_DOMAIN_MEMORY_STAT_SWAP_OUT:
            case VIR_DOMAIN_MEMORY_STAT_UNUSED:
            case VIR_DOMAIN_MEMORY_STAT_AVAILABLE:
                value >>= 10;
        }
        mstat->tag = tag;
        mstat->val = value;
        return 1;
    }
    return 0;
}

/* The reply from the 'info balloon' command may contain additional memory
 * statistics in the form: 'actual=<val> [,<tag>=<val>]*'
 */
static int qemuMonitorParseBalloonInfo(char *text,
                                       virDomainMemoryStatPtr stats,
                                       unsigned int nr_stats)
{
    char *p = text;
    unsigned int nr_stats_found = 0;

    /* Since "actual=" always comes first in the returned string,
     * and sometime we only care about the value of "actual", such
     * as qemuMonitorGetBalloonInfo, we parse it outside of the
     * loop.
     */
    if (parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON,
                        "actual=", &stats[nr_stats_found]) == 1) {
        nr_stats_found++;
    }

    while (*p && nr_stats_found < nr_stats) {
        if (parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_SWAP_IN,
                            ",mem_swapped_in=", &stats[nr_stats_found]) ||
            parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_SWAP_OUT,
                            ",mem_swapped_out=", &stats[nr_stats_found]) ||
            parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT,
                            ",major_page_faults=", &stats[nr_stats_found]) ||
            parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT,
                            ",minor_page_faults=", &stats[nr_stats_found]) ||
            parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_UNUSED,
                            ",free_mem=", &stats[nr_stats_found]) ||
            parseMemoryStat(&p, VIR_DOMAIN_MEMORY_STAT_AVAILABLE,
                            ",total_mem=", &stats[nr_stats_found]))
            nr_stats_found++;

        /* Skip to the next label.  When *p is ',' the last match attempt
         * failed so try to match the next ','.
         */
        if (*p == ',')
            p++;
        p = strchr(p, ',');
        if (!p) break;
    }
    return nr_stats_found;
}


/* The reply from QEMU contains 'ballon: actual=421' where value is in MB */
#define BALLOON_PREFIX "balloon: "

int
qemuMonitorTextGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long long *currmem)
{
    char *reply = NULL;
    int ret = -1;
    char *offset;

    if (qemuMonitorHMPCommand(mon, "info balloon", &reply) < 0)
        return -1;

    if ((offset = strstr(reply, BALLOON_PREFIX)) != NULL) {
        offset += strlen(BALLOON_PREFIX);
        virDomainMemoryStatStruct stats[1];

        if (qemuMonitorParseBalloonInfo(offset, stats, 1) == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected balloon information '%s'"), reply);
            goto cleanup;
        }

        if (stats[0].tag != VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected balloon information '%s'"), reply);
            goto cleanup;
        }

        *currmem = stats[0].val;
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

int qemuMonitorTextGetMemoryStats(qemuMonitorPtr mon,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats)
{
    char *reply = NULL;
    int ret = 0;
    char *offset;

    if (qemuMonitorHMPCommand(mon, "info balloon", &reply) < 0)
        return -1;

    if ((offset = strstr(reply, BALLOON_PREFIX)) != NULL) {
        offset += strlen(BALLOON_PREFIX);
        ret = qemuMonitorParseBalloonInfo(offset, stats, nr_stats);
    }

    VIR_FREE(reply);
    return ret;
}


int qemuMonitorTextGetBlockInfo(qemuMonitorPtr mon,
                                virHashTablePtr table)
{
    struct qemuDomainDiskInfo *info = NULL;
    char *reply = NULL;
    int ret = -1;
    char *dummy;
    char *p, *eol;
    char *dev;
    int tmp;

    if (qemuMonitorHMPCommand(mon, "info block", &reply) < 0)
        goto cleanup;

    if (strstr(reply, "\ninfo ")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s",
                       _("info block not supported by this qemu"));
        goto cleanup;
    }

    /* The output looks like this:
     * drive-ide0-0-0: removable=0 file=<path> ro=0 drv=raw encrypted=0
     * drive-ide0-1-0: removable=1 locked=0 file=<path> ro=1 drv=raw encrypted=0
     */
    p = reply;

    while (*p) {
        p = (char *)qemuAliasDiskDriveSkipPrefix(p);

        eol = strchr(p, '\n');
        if (!eol)
            eol = p + strlen(p) - 1;

        dev = p;
        p = strchr(p, ':');
        if (p && p < eol && *(p + 1) == ' ') {
            if (VIR_ALLOC(info) < 0)
                goto cleanup;

            *p = '\0';
            p += 2;

            while (p < eol) {
                if (STRPREFIX(p, "removable=")) {
                    p += strlen("removable=");
                    if (virStrToLong_i(p, &dummy, 10, &tmp) == -1)
                        VIR_DEBUG("error reading removable: %s", p);
                    else
                        info->removable = (tmp != 0);
                } else if (STRPREFIX(p, "locked=")) {
                    p += strlen("locked=");
                    if (virStrToLong_i(p, &dummy, 10, &tmp) == -1)
                        VIR_DEBUG("error reading locked: %s", p);
                    else
                        info->locked = (tmp != 0);
                } else if (STRPREFIX(p, "tray-open=")) {
                    p += strlen("tray-open=");
                    if (virStrToLong_i(p, &dummy, 10, &tmp) == -1)
                        VIR_DEBUG("error reading tray-open: %s", p);
                    else
                        info->tray_open = (tmp != 0);
                } else if (STRPREFIX(p, "io-status=")) {
                    char *end;
                    char c;

                    p += strlen("io-status=");
                    end = strchr(p, ' ');
                    if (!end || end > eol)
                        end = eol;

                    c = *end;
                    *end = '\0';
                    info->io_status = qemuMonitorBlockIOStatusToError(p);
                    *end = c;
                    if (info->io_status < 0)
                        goto cleanup;
                } else {
                    /* ignore because we don't parse all options */
                }

                /* skip to next label */
                p = strchr(p, ' ');
                if (!p)
                    break;
                p++;
            }

            if (virHashAddEntry(table, dev, info) < 0)
                goto cleanup;
            else
                info = NULL;
        }

        /* skip to the next line */
        p = eol + 1;
    }

    ret = 0;

 cleanup:
    VIR_FREE(info);
    VIR_FREE(reply);
    return ret;
}


int
qemuMonitorTextGetAllBlockStatsInfo(qemuMonitorPtr mon,
                                    virHashTablePtr hash)
{
    qemuBlockStatsPtr stats = NULL;
    char *info = NULL;
    const char *dev_name;
    char **lines = NULL;
    char **values = NULL;
    char *line;
    char *value;
    char *key;
    size_t i;
    size_t j;
    int ret = -1;
    int nstats;
    int maxstats = 0;

    if (qemuMonitorHMPCommand(mon, "info blockstats", &info) < 0)
        goto cleanup;

    /* If the command isn't supported then qemu prints the supported info
     * commands, so the output starts "info ".  Since this is unlikely to be
     * the name of a block device, we can use this to detect if qemu supports
     * the command. */
    if (strstr(info, "\ninfo ")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("'info blockstats' not supported by this qemu"));
        goto cleanup;
    }

    /* The output format for both qemu & KVM is:
     *   blockdevice: rd_bytes=% wr_bytes=% rd_operations=% wr_operations=%
     *   (repeated for each block device)
     * where '%' is a 64 bit number.
     */
    if (!(lines = virStringSplit(info, "\n", 0)))
        goto cleanup;

    for (i = 0; lines[i] && *lines[i]; i++) {
        line = lines[i];

        if (VIR_ALLOC(stats) < 0)
            goto cleanup;

        /* set the entries to -1, the JSON monitor enforces them, but it would
         * be overly complex to achieve this here */
        stats->rd_req = -1;
        stats->rd_bytes = -1;
        stats->wr_req = -1;
        stats->wr_bytes = -1;
        stats->rd_total_times = -1;
        stats->wr_total_times = -1;
        stats->flush_req = -1;
        stats->flush_total_times = -1;

        /* extract device name and make sure that it's followed by
         * a colon and space */
        dev_name = line;
        if (!(line = strchr(line, ':')) || line[1] != ' ') {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("info blockstats reply was malformed"));
            goto cleanup;
        }

        *line = '\0';
        line += 2;

        dev_name = qemuAliasDiskDriveSkipPrefix(dev_name);

        if (!(values = virStringSplit(line, " ", 0)))
            goto cleanup;

        nstats = 0;

        for (j = 0; values[j] && *values[j]; j++) {
            key = values[j];

            if (!(value = strchr(key, '='))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("info blockstats entry was malformed"));
                goto cleanup;
            }

            *value = '\0';
            value++;

#define QEMU_MONITOR_TEXT_READ_BLOCK_STAT(NAME, VAR)                           \
            if (STREQ(key, NAME)) {                                            \
                nstats++;                                                      \
                if (virStrToLong_ll(value, NULL, 10, &VAR) < 0) {              \
                    virReportError(VIR_ERR_INTERNAL_ERROR,                     \
                                   _("'info blockstats' contains malformed "   \
                                     "parameter '%s' value '%s'"), NAME, value);\
                    goto cleanup;                                              \
                }                                                              \
                continue;                                                      \
            }

            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("rd_bytes", stats->rd_bytes);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("wr_bytes", stats->wr_bytes);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("rd_operations", stats->rd_req);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("wr_operations", stats->wr_req);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("rd_total_time_ns", stats->rd_total_times);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("wr_total_time_ns", stats->wr_total_times);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("flush_operations", stats->flush_req);
            QEMU_MONITOR_TEXT_READ_BLOCK_STAT("flush_total_time_ns", stats->flush_total_times);
#undef QEMU_MONITOR_TEXT_READ_BLOCK_STAT

            /* log if we get statistic element different from the above */
            VIR_DEBUG("unknown block stat field '%s'", key);
        }

        if (nstats > maxstats)
            maxstats = nstats;

        if (virHashAddEntry(hash, dev_name, stats) < 0)
            goto cleanup;
        stats = NULL;

        virStringListFree(values);
        values = NULL;
    }

    ret = maxstats;

 cleanup:
    virStringListFree(lines);
    virStringListFree(values);
    VIR_FREE(stats);
    VIR_FREE(info);
    return ret;
}

/* Return 0 on success, -1 on failure, or -2 if not supported.  Size
 * is in bytes. */
int qemuMonitorTextBlockResize(qemuMonitorPtr mon,
                               const char *device,
                               unsigned long long size)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "block_resize %s %lluB", device, size) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
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
                      msg->txLength + passphrase_len + 1 + 1) < 0)
        return -1;

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

    if (qemuMonitorTextCommandWithHandler(mon, "change vnc password",
                                          qemuMonitorSendVNCPassphrase,
                                          (char *)password,
                                          -1, &info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("setting VNC password failed"));
        return -1;
    }
    VIR_FREE(info);
    return 0;
}

/* Returns -1 on error, -2 if not supported */
int qemuMonitorTextSetPassword(qemuMonitorPtr mon,
                               const char *protocol,
                               const char *password,
                               const char *action_if_connected)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "set_password %s \"%s\" %s",
                    protocol, password, action_if_connected) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}

/* Returns -1 on error, -2 if not supported */
int qemuMonitorTextExpirePassword(qemuMonitorPtr mon,
                                  const char *protocol,
                                  const char *expire_time)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "expire_password %s %s",
                    protocol, expire_time) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}


int
qemuMonitorTextSetBalloon(qemuMonitorPtr mon,
                          unsigned long long newmem)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    /*
     * 'newmem' is in KB, QEMU monitor works in MB, and we all wish
     * we just worked in bytes with unsigned long long everywhere.
     */
    if (virAsprintf(&cmd, "balloon %llu", VIR_DIV_UP(newmem, 1024)) < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0) {
        VIR_FREE(cmd);
        return -1;
    }
    VIR_FREE(cmd);

    /* If the command failed qemu prints: 'unknown command'
     * No message is printed on success it seems */
    if (strstr(reply, "unknown command:")) {
        /* Don't set error - it is expected memory balloon fails on many qemu */
        ret = 0;
    } else {
        ret = 1;
    }

    VIR_FREE(reply);
    return ret;
}


int qemuMonitorTextSetCPU(qemuMonitorPtr mon, int cpu, bool online)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "cpu_set %d %s", cpu, online ? "online" : "offline") < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* If the command failed qemu prints: 'unknown command'
     * No message is printed on success it seems */
    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot change vcpu count of this domain"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);

    return ret;
}


/**
 * Run HMP command to eject a media from ejectable device.
 *
 * Returns:
 *      -1 on error
 *      0 on success
 */
int qemuMonitorTextEjectMedia(qemuMonitorPtr mon,
                              const char *dev_name,
                              bool force)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "eject %s%s", force ? "-f " : "", dev_name) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* If the command failed qemu prints:
     * device not found, device is locked ...
     * No message is printed on success it seems */
    if (c_strcasestr(reply, "device ")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("could not eject media on %s: %s"), dev_name, reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}


int qemuMonitorTextChangeMedia(qemuMonitorPtr mon,
                               const char *dev_name,
                               const char *newmedia,
                               const char *format ATTRIBUTE_UNUSED)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safepath = NULL;
    int ret = -1;

    if (!(safepath = qemuMonitorEscapeArg(newmedia)))
        goto cleanup;

    if (virAsprintf(&cmd, "change %s \"%s\"", dev_name, safepath) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* If the command failed qemu prints:
     * device not found, device is locked ...
     * No message is printed on success it seems */
    if (c_strcasestr(reply, "device ")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("could not change media on %s: %s"), dev_name, reply);
        goto cleanup;
    }

    /* Could not open message indicates bad filename */
    if (strstr(reply, "Could not open ")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("could not change media on %s: %s"), dev_name, reply);
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

    if (!(safepath = qemuMonitorEscapeArg(path)))
        goto cleanup;

    if (virAsprintf(&cmd, "%s %llu %zi \"%s\"", cmdtype, offset, length, safepath) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

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

    if (virAsprintf(&cmd, "migrate_set_speed %lum", bandwidth) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &info) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(info);
    VIR_FREE(cmd);
    return ret;
}


int qemuMonitorTextSetMigrationDowntime(qemuMonitorPtr mon,
                                        unsigned long long downtime)
{
    char *cmd = NULL;
    char *info = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "migrate_set_downtime %llums", downtime) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &info) < 0)
        goto cleanup;

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
#define MIGRATION_DISK_TRANSFER_PREFIX "transferred disk: "
#define MIGRATION_DISK_REMAINING_PREFIX "remaining disk: "
#define MIGRATION_DISK_TOTAL_PREFIX "total disk: "

int qemuMonitorTextGetMigrationStats(qemuMonitorPtr mon,
                                     qemuMonitorMigrationStatsPtr stats)
{
    char *reply;
    char *tmp;
    char *end;
    int ret = -1;

    memset(stats, 0, sizeof(*stats));

    if (qemuMonitorHMPCommand(mon, "info migrate", &reply) < 0)
        return -1;

    if ((tmp = strstr(reply, MIGRATION_PREFIX)) != NULL) {
        tmp += strlen(MIGRATION_PREFIX);
        end = strchr(tmp, '\r');
        if (end == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected migration status in %s"), reply);
            goto cleanup;
        }
        *end = '\0';

        stats->status = qemuMonitorMigrationStatusTypeFromString(tmp);
        if (stats->status < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected migration status in %s"), reply);
            goto cleanup;
        }

        if (stats->status == QEMU_MONITOR_MIGRATION_STATUS_ACTIVE) {
            tmp = end + 1;

            if (!(tmp = strstr(tmp, MIGRATION_TRANSFER_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_TRANSFER_PREFIX);

            if (virStrToLong_ull(tmp, &end, 10,
                                 &stats->ram_transferred) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse migration data transferred "
                                 "statistic %s"), tmp);
                goto cleanup;
            }
            stats->ram_transferred *= 1024;
            tmp = end;

            if (!(tmp = strstr(tmp, MIGRATION_REMAINING_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_REMAINING_PREFIX);

            if (virStrToLong_ull(tmp, &end, 10, &stats->ram_remaining) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse migration data remaining "
                                 "statistic %s"), tmp);
                goto cleanup;
            }
            stats->ram_remaining *= 1024;
            tmp = end;

            if (!(tmp = strstr(tmp, MIGRATION_TOTAL_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_TOTAL_PREFIX);

            if (virStrToLong_ull(tmp, &end, 10, &stats->ram_total) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse migration data total "
                                 "statistic %s"), tmp);
                goto cleanup;
            }
            stats->ram_total *= 1024;
            tmp = end;

            /*
             * Check for Optional Disk Migration stats
             */
            if (!(tmp = strstr(tmp, MIGRATION_DISK_TRANSFER_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_DISK_TRANSFER_PREFIX);

            if (virStrToLong_ull(tmp, &end, 10,
                                 &stats->disk_transferred) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse disk migration data "
                                 "transferred statistic %s"), tmp);
                goto cleanup;
            }
            stats->disk_transferred *= 1024;
            tmp = end;

            if (!(tmp = strstr(tmp, MIGRATION_DISK_REMAINING_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_DISK_REMAINING_PREFIX);

            if (virStrToLong_ull(tmp, &end, 10, &stats->disk_remaining) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse disk migration data remaining "
                                 "statistic %s"), tmp);
                goto cleanup;
            }
            stats->disk_remaining *= 1024;
            tmp = end;

            if (!(tmp = strstr(tmp, MIGRATION_DISK_TOTAL_PREFIX)))
                goto done;
            tmp += strlen(MIGRATION_DISK_TOTAL_PREFIX);

            if (virStrToLong_ull(tmp, &end, 10, &stats->disk_total) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse disk migration data total "
                                 "statistic %s"), tmp);
                goto cleanup;
            }
            stats->disk_total *= 1024;
        }
    }

 done:
    ret = 0;

 cleanup:
    VIR_FREE(reply);
    if (ret < 0)
        memset(stats, 0, sizeof(*stats));
    return ret;
}


int qemuMonitorTextMigrate(qemuMonitorPtr mon,
                           unsigned int flags,
                           const char *dest)
{
    char *cmd = NULL;
    char *info = NULL;
    int ret = -1;
    char *safedest = qemuMonitorEscapeArg(dest);
    virBuffer extra = VIR_BUFFER_INITIALIZER;
    char *extrastr = NULL;

    if (!safedest)
        return -1;

    if (flags & QEMU_MONITOR_MIGRATE_BACKGROUND)
        virBufferAddLit(&extra, " -d");
    if (flags & QEMU_MONITOR_MIGRATE_NON_SHARED_DISK)
        virBufferAddLit(&extra, " -b");
    if (flags & QEMU_MONITOR_MIGRATE_NON_SHARED_INC)
        virBufferAddLit(&extra, " -i");
    if (virBufferCheckError(&extra) < 0)
        goto cleanup;

    extrastr = virBufferContentAndReset(&extra);
    if (virAsprintf(&cmd, "migrate %s\"%s\"", extrastr ? extrastr : "",
                    safedest) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &info) < 0)
        goto cleanup;

    /* Now check for "fail" in the output string */
    if (strstr(info, "fail") != NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("migration to '%s' failed: %s"), dest, info);
        goto cleanup;
    }
    /* If the command isn't supported then qemu prints:
     * unknown command: migrate" */
    if (strstr(info, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("migration to '%s' not supported by this qemu: %s"), dest, info);
        goto cleanup;
    }


    ret = 0;

 cleanup:
    VIR_FREE(extrastr);
    VIR_FREE(safedest);
    VIR_FREE(info);
    VIR_FREE(cmd);
    return ret;
}

int qemuMonitorTextMigrateCancel(qemuMonitorPtr mon)
{
    char *info = NULL;
    int ret;

    ret = qemuMonitorHMPCommand(mon, "migrate_cancel", &info);

    VIR_FREE(info);
    return ret;
}


int qemuMonitorTextGraphicsRelocate(qemuMonitorPtr mon,
                                    int type,
                                    const char *hostname,
                                    int port,
                                    int tlsPort,
                                    const char *tlsSubject)
{
    char *cmd;
    char *info = NULL;

    if (virAsprintf(&cmd, "client_migrate_info %s %s %d %d %s",
                    type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE ? "spice" : "vnc",
                    hostname, port, tlsPort, tlsSubject ? tlsSubject : "") < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &info) < 0) {
        VIR_FREE(cmd);
        return -1;
    }
    VIR_FREE(cmd);
    VIR_FREE(info);

    return 0;
}


int qemuMonitorTextSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "getfd %s", fdname) < 0)
        return -1;

    if (qemuMonitorHMPCommandWithFd(mon, cmd, fd, &reply) < 0)
        goto cleanup;

    /* If the command isn't supported then qemu prints:
     * unknown command: getfd" */
    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("qemu does not support sending of file handles: %s"),
                       reply);
        goto cleanup;
    }

    if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to send file handle '%s': %s"),
                        fdname, reply);
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

    if (virAsprintf(&cmd, "closefd %s", fdname) < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* If the command isn't supported then qemu prints:
     * unknown command: getfd" */
    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
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

    if (virAsprintf(&cmd, "host_net_add %s", netstr) < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to add host net: %s"),
                       reply);
        goto cleanup;
    }

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

    if (virAsprintf(&cmd, "host_net_remove %d %s", vlan, netname) < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* XXX error messages here ? */

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorTextAddNetdev(qemuMonitorPtr mon,
                             const char *netdevstr)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "netdev_add %s", netdevstr) < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* XXX error messages here ? */

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorTextRemoveNetdev(qemuMonitorPtr mon,
                                const char *alias)
{
    char *cmd;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "netdev_del %s", alias) < 0)
        return -1;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* XXX error messages here ? */

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


/* Parse the output of "info chardev" and return a hash of pty paths.
 *
 * Output is:
 * foo: filename=pty:/dev/pts/7
 * monitor: filename=stdio
 * serial0: filename=vc
 * parallel0: filename=vc
 *
 * Non-pty lines are ignored. In the above example, key is 'foo', value is
 * '/dev/pty/7'. The hash will contain only a single value.
 */

int qemuMonitorTextGetChardevInfo(qemuMonitorPtr mon,
                                  virHashTablePtr info)
{
    char *reply = NULL;
    qemuMonitorChardevInfoPtr entry = NULL;
    int ret = -1;

    if (qemuMonitorHMPCommand(mon, "info chardev", &reply) < 0)
        return -1;

    char *pos;                          /* The current start of searching */
    char *next = reply;                 /* The start of the next line */
    char *eol;                   /* The character which ends the current line */
    char *end = reply + strlen(reply);  /* The end of the reply string */

    while (next) {
        pos = next;

        /* Split the output into lines */
        eol = memchr(pos, '\n', end - pos);
        if (eol == NULL) {
            eol = end;
            next = NULL;
        } else {
            next = eol + 1;
        }

        /* Ignore all whitespace immediately before eol */
        while (eol > pos && c_isspace(*(eol-1)))
            eol -= 1;

        /* Look for 'filename=pty:' */
#define NEEDLE "filename=pty:"
        char *needle = memmem(pos, eol - pos, NEEDLE, strlen(NEEDLE));

        /* If it's not there we can ignore this line */
        if (!needle)
            continue;

        /* id is everything from the beginning of the line to the ':'
         * find ':' and turn it into a terminator */
        char *colon = memchr(pos, ':', needle - pos);
        if (colon == NULL)
            continue;
        *colon = '\0';
        char *id = pos;

        /* Path is everything after needle to the end of the line */
        *eol = '\0';

        if (VIR_ALLOC(entry) < 0)
            goto cleanup;

        if (VIR_STRDUP(entry->ptyPath, needle + strlen(NEEDLE)) < 0)
            goto cleanup;

        if (virHashAddEntry(info, id, entry) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to save chardev path '%s'"),
                           entry->ptyPath);
            VIR_FREE(entry->ptyPath);
            goto cleanup;
        }

        entry = NULL;
#undef NEEDLE
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(entry);
    return ret;
}


int qemuMonitorTextDelDevice(qemuMonitorPtr mon,
                             const char *devalias)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safedev;
    int ret = -1;

    if (!(safedev = qemuMonitorEscapeArg(devalias)))
        goto cleanup;

    if (virAsprintf(&cmd, "device_del %s", safedev) < 0)
        goto cleanup;

    VIR_DEBUG("TextDelDevice devalias=%s", devalias);
    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("detaching %s device failed: %s"), devalias, reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safedev);
    return ret;
}


int qemuMonitorTextAddDevice(qemuMonitorPtr mon,
                             const char *devicestr)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safedev;
    int ret = -1;

    if (!(safedev = qemuMonitorEscapeArg(devicestr)))
        goto cleanup;

    if (virAsprintf(&cmd, "device_add %s", safedev) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* If the host device is hotpluged first time, qemu will output
     * husb: using %s file-system with %s if the command succeeds.
     */
    if (STRPREFIX(reply, "husb: using")) {
        ret = 0;
        goto cleanup;
    }

    /* Otherwise, if the command succeeds, no output is sent. So
     * any non-empty string shows an error */
    if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("adding %s device failed: %s"), devicestr, reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safedev);
    return ret;
}


int qemuMonitorTextAddDrive(qemuMonitorPtr mon,
                            const char *drivestr)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safe_str;

    safe_str = qemuMonitorEscapeArg(drivestr);
    if (!safe_str)
        return -1;

    /* 'dummy' here is just a placeholder since there is no PCI
     * address required when attaching drives to a controller */
    if (virAsprintf(&cmd, "drive_add dummy %s", safe_str) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("drive hotplug is not supported"));
        goto cleanup;
    }

    if (strstr(reply, "could not open disk image")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("open disk image file failed"));
        goto cleanup;
    }

    if (strstr(reply, "Could not open")) {
        size_t len = strlen(reply);
        if (reply[len - 1] == '\n')
            reply[len - 1] = '\0';

        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       reply);
        goto cleanup;
    }

    if (strstr(reply, "Image is not in")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Incorrect disk format"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safe_str);
    return ret;
}


int qemuMonitorTextDriveDel(qemuMonitorPtr mon,
                            const char *drivestr)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safedev;
    int ret = -1;

    if (!(safedev = qemuMonitorEscapeArg(drivestr)))
        goto cleanup;

    if (virAsprintf(&cmd, "drive_del %s", safedev) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        VIR_ERROR(_("deleting drive is not supported.  "
                    "This may leak data if disk is reassigned"));
        ret = 1;
        goto cleanup;

    /* (qemu) drive_del wark
     * Device 'wark' not found */
    } else if (strstr(reply, "Device '") && strstr(reply, "not found")) {
        /* NB: device not found errors mean the drive was auto-deleted and we
         * ignore the error */
    } else if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("deleting %s drive failed: %s"), drivestr, reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safedev);
    return ret;
}

int qemuMonitorTextSetDrivePassphrase(qemuMonitorPtr mon,
                                      const char *alias,
                                      const char *passphrase)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safe_str;

    safe_str = qemuMonitorEscapeArg(passphrase);
    if (!safe_str)
        return -1;

    if (virAsprintf(&cmd, "block_passwd %s \"%s\"", alias, safe_str) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("setting disk password is not supported"));
        goto cleanup;
    } else if (strstr(reply, "The entered password is invalid")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("the disk password is incorrect"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safe_str);
    return ret;
}


int
qemuMonitorTextCreateSnapshot(qemuMonitorPtr mon,
                              const char *name)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safename;

    if (!(safename = qemuMonitorEscapeArg(name)) ||
        virAsprintf(&cmd, "savevm \"%s\"", safename) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply))
        goto cleanup;

    if (strstr(reply, "Error while creating snapshot") ||
        strstr(reply, "Could not open VM state file") ||
        strstr(reply, "State blocked by non-migratable device") ||
        (strstr(reply, "Error") && strstr(reply, "while writing VM"))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to take snapshot: %s"), reply);
        goto cleanup;
    } else if (strstr(reply, "No block device can accept snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to take snapshots"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(safename);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}

int qemuMonitorTextLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safename;

    if (!(safename = qemuMonitorEscapeArg(name)) ||
        virAsprintf(&cmd, "loadvm \"%s\"", safename) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply))
        goto cleanup;

    if (strstr(reply, "No block device supports snapshots") != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to load snapshots"));
        goto cleanup;
    } else if (strstr(reply, "Could not find snapshot") != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("the snapshot '%s' does not exist, and was not loaded"),
                       name);
        goto cleanup;
    } else if (strstr(reply, "Snapshots not supported on device") != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", reply);
        goto cleanup;
    } else if (strstr(reply, "Could not open VM state file") != NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", reply);
        goto cleanup;
    } else if (strstr(reply, "Error") != NULL
             && strstr(reply, "while loading VM state") != NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", reply);
        goto cleanup;
    } else if (strstr(reply, "Error") != NULL
             && strstr(reply, "while activating snapshot on") != NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(safename);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}

int qemuMonitorTextDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safename;

    if (!(safename = qemuMonitorEscapeArg(name)) ||
        virAsprintf(&cmd, "delvm \"%s\"", safename) < 0)
        goto cleanup;
    if (qemuMonitorHMPCommand(mon, cmd, &reply))
        goto cleanup;

    if (strstr(reply, "No block device supports snapshots") != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to delete snapshots"));
        goto cleanup;
    } else if (strstr(reply, "Snapshots not supported on device") != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", reply);
        goto cleanup;
    } else if (strstr(reply, "Error") != NULL
             && strstr(reply, "while deleting snapshot") != NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(safename);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}


int qemuMonitorTextArbitraryCommand(qemuMonitorPtr mon, const char *cmd,
                                    char **reply)
{
    char *safecmd = NULL;
    int ret;

    if (!(safecmd = qemuMonitorEscapeArg(cmd)))
        return -1;

    ret = qemuMonitorHMPCommand(mon, safecmd, reply);

    VIR_FREE(safecmd);

    return ret;
}

int qemuMonitorTextInjectNMI(qemuMonitorPtr mon)
{
    char *reply = NULL;

    if (qemuMonitorHMPCommand(mon, "inject-nmi", &reply) < 0)
        return -1;

    if (strstr(reply, "unknown command") != NULL) {
        VIR_FREE(reply);

        /* fallback to 'nmi' if qemu has not supported "inject-nmi" yet. */
        if (qemuMonitorHMPCommand(mon, "nmi 0", &reply) < 0)
            return -1;
    }

    VIR_FREE(reply);
    return 0;
}

int qemuMonitorTextSendKey(qemuMonitorPtr mon,
                           unsigned int holdtime,
                           unsigned int *keycodes,
                           unsigned int nkeycodes)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *cmd, *reply = NULL;
    int ret = -1;

    if (nkeycodes > VIR_DOMAIN_SEND_KEY_MAX_KEYS || nkeycodes == 0)
        return -1;

    virBufferAddLit(&buf, "sendkey ");
    for (i = 0; i < nkeycodes; i++) {
        if (keycodes[i] > 0xffff) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("keycode %zu is invalid: 0x%X"),
                           i, keycodes[i]);
            virBufferFreeAndReset(&buf);
            return -1;
        }

        if (i)
            virBufferAddChar(&buf, '-');
        virBufferAsprintf(&buf, "0x%02X", keycodes[i]);
    }

    if (holdtime)
        virBufferAsprintf(&buf, " %u", holdtime);

    if (virBufferCheckError(&buf) < 0)
        return -1;

    cmd = virBufferContentAndReset(&buf);
    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to send key '%s'"), reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}

/* Returns -1 on error, -2 if not supported */
int qemuMonitorTextScreendump(qemuMonitorPtr mon, const char *file)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "screendump %s", file) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}


int qemuMonitorTextOpenGraphics(qemuMonitorPtr mon,
                                const char *protocol,
                                const char *fdname,
                                bool skipauth)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;

    if (virAsprintf(&cmd, "add_client %s %s %d", protocol, fdname, skipauth ? 0 : 1) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (STRNEQ(reply, ""))
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}


int qemuMonitorTextSetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr info)
{
    char *cmd = NULL;
    char *result = NULL;
    int ret = -1;
    const char *cmd_name = NULL;

    /* For the not specified fields, 0 by default */
    cmd_name = "block_set_io_throttle";
    if (virAsprintf(&cmd, "%s %s %llu %llu %llu %llu %llu %llu", cmd_name,
                    device, info->total_bytes_sec, info->read_bytes_sec,
                    info->write_bytes_sec, info->total_iops_sec,
                    info->read_iops_sec, info->write_iops_sec) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &result) < 0)
        goto cleanup;

    if (qemuMonitorTextCommandNotFound(cmd_name, result)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Command '%s' is not found"), cmd_name);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(result);
    return ret;
}

static int
qemuMonitorTextParseBlockIoThrottle(const char *result,
                                    const char *device,
                                    virDomainBlockIoTuneInfoPtr reply)
{
    char *dummy = NULL;
    int ret = -1;
    const char *p, *eol;
    int devnamelen = strlen(device);

    p = result;

    while (*p) {
        if (STREQLEN(p, device, devnamelen) &&
            p[devnamelen] == ':' && p[devnamelen+1] == ' ') {

            eol = strchr(p, '\n');
            if (!eol)
                eol = p + strlen(p);

            p += devnamelen + 2; /* Skip to first label. */

            while (*p) {
                if (STRPREFIX(p, "bps=")) {
                    p += strlen("bps=");
                    if (virStrToLong_ull(p, &dummy, 10, &reply->total_bytes_sec) == -1)
                        VIR_DEBUG("error reading total_bytes_sec: %s", p);
                } else if (STRPREFIX(p, "bps_rd=")) {
                    p += strlen("bps_rd=");
                    if (virStrToLong_ull(p, &dummy, 10, &reply->read_bytes_sec)  == -1)
                        VIR_DEBUG("error reading read_bytes_sec: %s", p);
                } else if (STRPREFIX(p, "bps_wr=")) {
                    p += strlen("bps_wr=");
                    if (virStrToLong_ull(p, &dummy, 10, &reply->write_bytes_sec) == -1)
                        VIR_DEBUG("error reading write_bytes_sec: %s", p);
                } else if (STRPREFIX(p, "iops=")) {
                    p += strlen("iops=");
                    if (virStrToLong_ull(p, &dummy, 10, &reply->total_iops_sec) == -1)
                        VIR_DEBUG("error reading total_iops_sec: %s", p);
                } else if (STRPREFIX(p, "iops_rd=")) {
                    p += strlen("iops_rd=");
                    if (virStrToLong_ull(p, &dummy, 10, &reply->read_iops_sec) == -1)
                        VIR_DEBUG("error reading read_iops_sec: %s", p);
                } else if (STRPREFIX(p, "iops_wr=")) {
                    p += strlen("iops_wr=");
                    if (virStrToLong_ull(p, &dummy, 10, &reply->write_iops_sec) == -1)
                        VIR_DEBUG("error reading write_iops_sec: %s", p);
                } else {
                    VIR_DEBUG(" unknown block info %s", p);
                }

                /* Skip to next label. */
                p = strchr(p, ' ');
                if (!p || p >= eol)
                    break;
                p++;
            }
            ret = 0;
            goto cleanup;
        }

        /* Skip to next line. */
        p = strchr(p, '\n');
        if (!p)
            break;
        p++;
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("No info for device '%s'"), device);

 cleanup:
    return ret;
}

int qemuMonitorTextGetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr reply)
{
    char *result = NULL;
    int ret = -1;
    const char *cmd_name = "info block";

    if (qemuMonitorHMPCommand(mon, cmd_name, &result) < 0)
        goto cleanup;

    if (qemuMonitorTextCommandNotFound(cmd_name, result)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Command '%s' is not found"), cmd_name);
        goto cleanup;
    }

    ret = qemuMonitorTextParseBlockIoThrottle(result, device, reply);

 cleanup:
    VIR_FREE(result);
    return ret;
}
