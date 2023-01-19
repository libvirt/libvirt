/*
 * qemu_logcontext.c: QEMU log context
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

#include "qemu_logcontext.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"

#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_logcontext");


struct _qemuLogContext {
    GObject parent;

    int writefd;
    int readfd; /* Only used if manager == NULL */
    off_t pos;
    ino_t inode; /* Only used if manager != NULL */
    char *path;
    virLogManager *manager;
};

G_DEFINE_TYPE(qemuLogContext, qemu_log_context, G_TYPE_OBJECT);

static void
qemuLogContextFinalize(GObject *obj);


static void
qemu_log_context_init(qemuLogContext *logctxt G_GNUC_UNUSED)
{
}


static void
qemu_log_context_class_init(qemuLogContextClass *klass)
{
    GObjectClass *obj = G_OBJECT_CLASS(klass);

    obj->finalize = qemuLogContextFinalize;
}


static void
qemuLogContextFinalize(GObject *object)
{
    qemuLogContext *ctxt = QEMU_LOG_CONTEXT(object);
    VIR_DEBUG("ctxt=%p", ctxt);

    virLogManagerFree(ctxt->manager);
    VIR_FREE(ctxt->path);
    VIR_FORCE_CLOSE(ctxt->writefd);
    VIR_FORCE_CLOSE(ctxt->readfd);
    G_OBJECT_CLASS(qemu_log_context_parent_class)->finalize(object);
}


qemuLogContext *
qemuLogContextNew(virQEMUDriver *driver,
                  virDomainObj *vm,
                  const char *basename)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuLogContext *ctxt = QEMU_LOG_CONTEXT(g_object_new(QEMU_TYPE_LOG_CONTEXT, NULL));

    VIR_DEBUG("Context new %p stdioLogD=%d", ctxt, cfg->stdioLogD);
    ctxt->writefd = -1;
    ctxt->readfd = -1;

    ctxt->path = g_strdup_printf("%s/%s.log", cfg->logDir, basename);

    if (cfg->stdioLogD) {
        ctxt->manager = virLogManagerNew(driver->privileged);
        if (!ctxt->manager)
            goto error;

        ctxt->writefd = virLogManagerDomainOpenLogFile(ctxt->manager,
                                                       "qemu",
                                                       vm->def->uuid,
                                                       vm->def->name,
                                                       ctxt->path,
                                                       0,
                                                       &ctxt->inode,
                                                       &ctxt->pos);
        if (ctxt->writefd < 0)
            goto error;
    } else {
        if ((ctxt->writefd = open(ctxt->path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR)) < 0) {
            virReportSystemError(errno, _("failed to create logfile %1$s"),
                                 ctxt->path);
            goto error;
        }
        if (virSetCloseExec(ctxt->writefd) < 0) {
            virReportSystemError(errno, _("failed to set close-on-exec flag on %1$s"),
                                 ctxt->path);
            goto error;
        }

        /* For unprivileged startup we must truncate the file since
         * we can't rely on logrotate. We don't use O_TRUNC since
         * it is better for SELinux policy if we truncate afterwards */
        if (!driver->privileged &&
            ftruncate(ctxt->writefd, 0) < 0) {
            virReportSystemError(errno, _("failed to truncate %1$s"),
                                 ctxt->path);
            goto error;
        }

        if ((ctxt->readfd = open(ctxt->path, O_RDONLY)) < 0) {
            virReportSystemError(errno, _("failed to open logfile %1$s"),
                                 ctxt->path);
            goto error;
        }
        if (virSetCloseExec(ctxt->readfd) < 0) {
            virReportSystemError(errno, _("failed to set close-on-exec flag on %1$s"),
                                 ctxt->path);
            goto error;
        }

        if ((ctxt->pos = lseek(ctxt->writefd, 0, SEEK_END)) < 0) {
            virReportSystemError(errno, _("failed to seek in log file %1$s"),
                                 ctxt->path);
            goto error;
        }
    }

    return ctxt;

 error:
    g_clear_object(&ctxt);
    return NULL;
}


int
qemuLogContextWrite(qemuLogContext *ctxt,
                    const char *fmt, ...)
{
    va_list argptr;
    g_autofree char *message = NULL;
    int ret = -1;

    va_start(argptr, fmt);

    message = g_strdup_vprintf(fmt, argptr);
    if (!ctxt->manager &&
        lseek(ctxt->writefd, 0, SEEK_END) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to seek to end of domain logfile"));
        goto cleanup;
    }
    if (safewrite(ctxt->writefd, message, strlen(message)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to write to domain logfile"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    va_end(argptr);
    return ret;
}


ssize_t
qemuLogContextRead(qemuLogContext *ctxt,
                   char **msg)
{
    char *buf;
    size_t buflen;

    VIR_DEBUG("Context read %p manager=%p inode=%llu pos=%llu",
              ctxt, ctxt->manager,
              (unsigned long long)ctxt->inode,
              (unsigned long long)ctxt->pos);

    if (ctxt->manager) {
        buf = virLogManagerDomainReadLogFile(ctxt->manager,
                                             ctxt->path,
                                             ctxt->inode,
                                             ctxt->pos,
                                             1024 * 128,
                                             0);
        if (!buf)
            return -1;
        buflen = strlen(buf);
    } else {
        ssize_t got;

        buflen = 1024 * 128;

        /* Best effort jump to start of messages */
        ignore_value(lseek(ctxt->readfd, ctxt->pos, SEEK_SET));

        buf = g_new0(char, buflen);

        got = saferead(ctxt->readfd, buf, buflen - 1);
        if (got < 0) {
            VIR_FREE(buf);
            virReportSystemError(errno, "%s",
                                 _("Unable to read from log file"));
            return -1;
        }

        buf[got] = '\0';

        buf = g_renew(char, buf, got + 1);
        buflen = got;
    }

    *msg = buf;

    return buflen;
}


/**
 * qemuLogContextFilter: Read and filter log for relevant messages
 * @ctxt: the domain log context
 * @msg: pointer to buffer to store the read messages in
 * @max: maximum length of the message returned in @msg after filtering
 *
 * Reads log output from @ctxt and filters it. Skips messages not produced by
 * the target executable or irrelevant messages. If @max is not zero, @buf will
 * contain at most @max characters from the end of the log and @buf will start
 * after a new line if possible.
 */
int
qemuLogContextReadFiltered(qemuLogContext *ctxt,
                           char **msg,
                           size_t max)
{
    char *buf;
    char *eol;
    char *filter_next;
    size_t skip;
    ssize_t got;

    if ((got = qemuLogContextRead(ctxt, &buf)) < 0)
        return -1;

    /* Filter out debug messages from intermediate libvirt process */
    filter_next = buf;
    while ((eol = strchr(filter_next, '\n'))) {
        *eol = '\0';
        if (virLogProbablyLogMessage(filter_next) ||
            strstr(filter_next, "char device redirected to")) {
            skip = (eol + 1) - filter_next;
            memmove(filter_next, eol + 1, buf + got - eol);
            got -= skip;
        } else {
            filter_next = eol + 1;
            *eol = '\n';
        }
    }

    if (got > 0 &&
        buf[got - 1] == '\n') {
        buf[got - 1] = '\0';
        got--;
    }

    if (max > 0 && got > max) {
        skip = got - max;

        if (buf[skip - 1] != '\n' &&
            (eol = strchr(buf + skip, '\n')) &&
            !virStringIsEmpty(eol + 1))
            skip = eol + 1 - buf;

        memmove(buf, buf + skip, got - skip + 1);
        got -= skip;
    }

    buf = g_renew(char, buf, got + 1);
    *msg = buf;
    return 0;
}


int
qemuLogContextGetWriteFD(qemuLogContext *ctxt)
{
    return ctxt->writefd;
}


void
qemuLogContextMarkPosition(qemuLogContext *ctxt)
{
    if (ctxt->manager)
        virLogManagerDomainGetLogFilePosition(ctxt->manager,
                                              ctxt->path,
                                              0,
                                              &ctxt->inode,
                                              &ctxt->pos);
    else
        ctxt->pos = lseek(ctxt->writefd, 0, SEEK_END);
}


virLogManager *
qemuLogContextGetManager(qemuLogContext *ctxt)
{
    return ctxt->manager;
}
