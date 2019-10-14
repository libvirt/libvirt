/*
 * log_handler.c: log management daemon handler
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "log_handler.h"
#include "virerror.h"
#include "virobject.h"
#include "virfile.h"
#include "viralloc.h"
#include "virstring.h"
#include "virlog.h"
#include "virrotatingfile.h"
#include "viruuid.h"

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "configmake.h"

VIR_LOG_INIT("logging.log_handler");

#define VIR_FROM_THIS VIR_FROM_LOGGING

#define DEFAULT_MODE 0600

typedef struct _virLogHandlerLogFile virLogHandlerLogFile;
typedef virLogHandlerLogFile *virLogHandlerLogFilePtr;

struct _virLogHandlerLogFile {
    virRotatingFileWriterPtr file;
    int watch;
    int pipefd; /* Read from QEMU via this */
    bool drained;

    char *driver;
    unsigned char domuuid[VIR_UUID_BUFLEN];
    char *domname;
};

struct _virLogHandler {
    virObjectLockable parent;

    bool privileged;
    size_t max_size;
    size_t max_backups;

    virLogHandlerLogFilePtr *files;
    size_t nfiles;

    virLogHandlerShutdownInhibitor inhibitor;
    void *opaque;
};

static virClassPtr virLogHandlerClass;
static void virLogHandlerDispose(void *obj);

static int
virLogHandlerOnceInit(void)
{
    if (!VIR_CLASS_NEW(virLogHandler, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLogHandler);


static void
virLogHandlerLogFileFree(virLogHandlerLogFilePtr file)
{
    if (!file)
        return;

    VIR_FORCE_CLOSE(file->pipefd);
    virRotatingFileWriterFree(file->file);

    if (file->watch != -1)
        virEventRemoveHandle(file->watch);

    VIR_FREE(file->driver);
    VIR_FREE(file->domname);
    VIR_FREE(file);
}


static void
virLogHandlerLogFileClose(virLogHandlerPtr handler,
                          virLogHandlerLogFilePtr file)
{
    size_t i;

    for (i = 0; i < handler->nfiles; i++) {
        if (handler->files[i] == file) {
            VIR_DELETE_ELEMENT(handler->files, i, handler->nfiles);
            virLogHandlerLogFileFree(file);
            break;
        }
    }
}


static virLogHandlerLogFilePtr
virLogHandlerGetLogFileFromWatch(virLogHandlerPtr handler,
                                 int watch)
{
    size_t i;

    for (i = 0; i < handler->nfiles; i++) {
        if (handler->files[i]->watch == watch)
            return handler->files[i];
    }

    return NULL;
}


static void
virLogHandlerDomainLogFileEvent(int watch,
                                int fd,
                                int events,
                                void *opaque)
{
    virLogHandlerPtr handler = opaque;
    virLogHandlerLogFilePtr logfile;
    char buf[1024];
    ssize_t len;

    virObjectLock(handler);
    logfile = virLogHandlerGetLogFileFromWatch(handler, watch);
    if (!logfile || logfile->pipefd != fd) {
        virEventRemoveHandle(watch);
        virObjectUnlock(handler);
        return;
    }

    if (logfile->drained) {
        logfile->drained = false;
        goto cleanup;
    }

 reread:
    len = read(fd, buf, sizeof(buf));
    if (len < 0) {
        if (errno == EINTR)
            goto reread;

        virReportSystemError(errno, "%s",
                             _("Unable to read from log pipe"));
        goto error;
    }

    if (virRotatingFileWriterAppend(logfile->file, buf, len) != len)
        goto error;

    if (events & VIR_EVENT_HANDLE_HANGUP)
        goto error;

 cleanup:
    virObjectUnlock(handler);
    return;

 error:
    handler->inhibitor(false, handler->opaque);
    virLogHandlerLogFileClose(handler, logfile);
    virObjectUnlock(handler);
}


virLogHandlerPtr
virLogHandlerNew(bool privileged,
                 size_t max_size,
                 size_t max_backups,
                 virLogHandlerShutdownInhibitor inhibitor,
                 void *opaque)
{
    virLogHandlerPtr handler;

    if (virLogHandlerInitialize() < 0)
        goto error;

    if (!(handler = virObjectLockableNew(virLogHandlerClass)))
        goto error;

    handler->privileged = privileged;
    handler->max_size = max_size;
    handler->max_backups = max_backups;
    handler->inhibitor = inhibitor;
    handler->opaque = opaque;

    return handler;

 error:
    return NULL;
}


static virLogHandlerLogFilePtr
virLogHandlerLogFilePostExecRestart(virLogHandlerPtr handler,
                                    virJSONValuePtr object)
{
    virLogHandlerLogFilePtr file;
    const char *path;
    const char *domuuid;
    const char *tmp;

    if (VIR_ALLOC(file) < 0)
        return NULL;

    handler->inhibitor(true, handler->opaque);

    if ((path = virJSONValueObjectGetString(object, "path")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing 'path' field in JSON document"));
        goto error;
    }

    if ((tmp = virJSONValueObjectGetString(object, "driver")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing 'driver' in JSON document"));
        goto error;
    }
    if (VIR_STRDUP(file->driver, tmp) < 0)
        goto error;

    if ((tmp = virJSONValueObjectGetString(object, "domname")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing 'domname' in JSON document"));
        goto error;
    }
    if (VIR_STRDUP(file->domname, tmp) < 0)
        goto error;

    if ((domuuid = virJSONValueObjectGetString(object, "domuuid")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing 'domuuid' in JSON document"));
        goto error;
    }
    if (virUUIDParse(domuuid, file->domuuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed 'domuuid' in JSON document"));
        goto error;
    }

    if ((file->file = virRotatingFileWriterNew(path,
                                               handler->max_size,
                                               handler->max_backups,
                                               false,
                                               DEFAULT_MODE)) == NULL)
        goto error;

    if (virJSONValueObjectGetNumberInt(object, "pipefd", &file->pipefd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing 'pipefd' in JSON document"));
        goto error;
    }
    if (virSetInherit(file->pipefd, false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot enable close-on-exec flag"));
        goto error;
    }

    return file;

 error:
    handler->inhibitor(false, handler->opaque);
    virLogHandlerLogFileFree(file);
    return NULL;
}


virLogHandlerPtr
virLogHandlerNewPostExecRestart(virJSONValuePtr object,
                                bool privileged,
                                size_t max_size,
                                size_t max_backups,
                                virLogHandlerShutdownInhibitor inhibitor,
                                void *opaque)
{
    virLogHandlerPtr handler;
    virJSONValuePtr files;
    size_t i;

    if (!(handler = virLogHandlerNew(privileged,
                                     max_size,
                                     max_backups,
                                     inhibitor,
                                     opaque)))
        return NULL;

    if (!(files = virJSONValueObjectGet(object, "files"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing files data from JSON file"));
        goto error;
    }

    if (!virJSONValueIsArray(files)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed files array"));
        goto error;
    }

    for (i = 0; i < virJSONValueArraySize(files); i++) {
        virLogHandlerLogFilePtr file;
        virJSONValuePtr child = virJSONValueArrayGet(files, i);

        if (!(file = virLogHandlerLogFilePostExecRestart(handler, child)))
            goto error;

        if (VIR_APPEND_ELEMENT_COPY(handler->files, handler->nfiles, file) < 0)
            goto error;

        if ((file->watch = virEventAddHandle(file->pipefd,
                                             VIR_EVENT_HANDLE_READABLE,
                                             virLogHandlerDomainLogFileEvent,
                                             handler,
                                             NULL)) < 0) {
            VIR_DELETE_ELEMENT(handler->files, handler->nfiles - 1, handler->nfiles);
            goto error;
        }
    }


    return handler;

 error:
    virObjectUnref(handler);
    return NULL;
}


static void
virLogHandlerDispose(void *obj)
{
    virLogHandlerPtr handler = obj;
    size_t i;

    for (i = 0; i < handler->nfiles; i++) {
        handler->inhibitor(false, handler->opaque);
        virLogHandlerLogFileFree(handler->files[i]);
    }
    VIR_FREE(handler->files);
}


int
virLogHandlerDomainOpenLogFile(virLogHandlerPtr handler,
                               const char *driver,
                               const unsigned char *domuuid,
                               const char *domname,
                               const char *path,
                               bool trunc,
                               ino_t *inode,
                               off_t *offset)
{
    size_t i;
    virLogHandlerLogFilePtr file = NULL;
    int pipefd[2] = { -1, -1 };

    virObjectLock(handler);

    handler->inhibitor(true, handler->opaque);

    for (i = 0; i < handler->nfiles; i++) {
        if (STREQ(virRotatingFileWriterGetPath(handler->files[i]->file),
                  path)) {
            virReportSystemError(EBUSY,
                                 _("Cannot open log file: '%s'"),
                                 path);
            goto error;
        }
    }

    if (pipe(pipefd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot open fifo pipe"));
        goto error;
    }
    if (VIR_ALLOC(file) < 0)
        goto error;

    file->watch = -1;
    file->pipefd = pipefd[0];
    pipefd[0] = -1;
    memcpy(file->domuuid, domuuid, VIR_UUID_BUFLEN);
    if (VIR_STRDUP(file->driver, driver) < 0 ||
        VIR_STRDUP(file->domname, domname) < 0)
        goto error;

    if ((file->file = virRotatingFileWriterNew(path,
                                               handler->max_size,
                                               handler->max_backups,
                                               trunc,
                                               DEFAULT_MODE)) == NULL)
        goto error;

    if (VIR_APPEND_ELEMENT_COPY(handler->files, handler->nfiles, file) < 0)
        goto error;

    if ((file->watch = virEventAddHandle(file->pipefd,
                                         VIR_EVENT_HANDLE_READABLE,
                                         virLogHandlerDomainLogFileEvent,
                                         handler,
                                         NULL)) < 0) {
        VIR_DELETE_ELEMENT(handler->files, handler->nfiles - 1, handler->nfiles);
        goto error;
    }

    *inode = virRotatingFileWriterGetINode(file->file);
    *offset = virRotatingFileWriterGetOffset(file->file);

    virObjectUnlock(handler);
    return pipefd[1];

 error:
    VIR_FORCE_CLOSE(pipefd[0]);
    VIR_FORCE_CLOSE(pipefd[1]);
    handler->inhibitor(false, handler->opaque);
    virLogHandlerLogFileFree(file);
    virObjectUnlock(handler);
    return -1;
}


static void
virLogHandlerDomainLogFileDrain(virLogHandlerLogFilePtr file)
{
    char buf[1024];
    ssize_t len;
    struct pollfd pfd;
    int ret;

    for (;;) {
        pfd.fd = file->pipefd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        ret = poll(&pfd, 1, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;

            return;
        }

        if (ret == 0)
            return;

        len = read(file->pipefd, buf, sizeof(buf));
        file->drained = true;
        if (len < 0) {
            if (errno == EINTR)
                continue;
            return;
        }

        if (virRotatingFileWriterAppend(file->file, buf, len) != len)
            return;
    }
}


int
virLogHandlerDomainGetLogFilePosition(virLogHandlerPtr handler,
                                      const char *path,
                                      unsigned int flags,
                                      ino_t *inode,
                                      off_t *offset)
{
    virLogHandlerLogFilePtr file = NULL;
    int ret = -1;
    size_t i;

    virCheckFlags(0, -1);

    virObjectLock(handler);

    for (i = 0; i < handler->nfiles; i++) {
        if (STREQ(virRotatingFileWriterGetPath(handler->files[i]->file),
                  path)) {
            file = handler->files[i];
            break;
        }
    }

    if (!file) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No open log file %s"),
                       path);
        goto cleanup;
    }

    virLogHandlerDomainLogFileDrain(file);

    *inode = virRotatingFileWriterGetINode(file->file);
    *offset = virRotatingFileWriterGetOffset(file->file);

    ret = 0;

 cleanup:
    virObjectUnlock(handler);
    return ret;
}


char *
virLogHandlerDomainReadLogFile(virLogHandlerPtr handler,
                               const char *path,
                               ino_t inode,
                               off_t offset,
                               size_t maxlen,
                               unsigned int flags)
{
    virRotatingFileReaderPtr file = NULL;
    char *data = NULL;
    ssize_t got;

    virCheckFlags(0, NULL);

    virObjectLock(handler);

    if (!(file = virRotatingFileReaderNew(path, handler->max_backups)))
        goto error;

    if (virRotatingFileReaderSeek(file, inode, offset) < 0)
        goto error;

    if (VIR_ALLOC_N(data, maxlen + 1) < 0)
        goto error;

    got = virRotatingFileReaderConsume(file, data, maxlen);
    if (got < 0)
        goto error;
    data[got] = '\0';

    virRotatingFileReaderFree(file);
    virObjectUnlock(handler);
    return data;

 error:
    VIR_FREE(data);
    virRotatingFileReaderFree(file);
    virObjectUnlock(handler);
    return NULL;
}


int
virLogHandlerDomainAppendLogFile(virLogHandlerPtr handler,
                                 const char *driver G_GNUC_UNUSED,
                                 const unsigned char *domuuid G_GNUC_UNUSED,
                                 const char *domname G_GNUC_UNUSED,
                                 const char *path,
                                 const char *message,
                                 unsigned int flags)
{
    size_t i;
    virRotatingFileWriterPtr writer = NULL;
    virRotatingFileWriterPtr newwriter = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    VIR_DEBUG("Appending to log '%s' message: '%s'", path, message);

    virObjectLock(handler);

    for (i = 0; i < handler->nfiles; i++) {
        if (STREQ(virRotatingFileWriterGetPath(handler->files[i]->file), path)) {
            writer = handler->files[i]->file;
            break;
        }
    }

    if (!writer) {
        if (!(newwriter = virRotatingFileWriterNew(path,
                                                   handler->max_size,
                                                   handler->max_backups,
                                                   false,
                                                   DEFAULT_MODE)))
            goto cleanup;

        writer = newwriter;
    }

    if (virRotatingFileWriterAppend(writer, message, strlen(message)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virRotatingFileWriterFree(newwriter);
    virObjectUnlock(handler);
    return ret;
}


virJSONValuePtr
virLogHandlerPreExecRestart(virLogHandlerPtr handler)
{
    virJSONValuePtr ret = virJSONValueNewObject();
    virJSONValuePtr files;
    size_t i;
    char domuuid[VIR_UUID_STRING_BUFLEN];

    if (!ret)
        return NULL;

    if (!(files = virJSONValueNewArray()))
        goto error;

    if (virJSONValueObjectAppend(ret, "files", files) < 0) {
        virJSONValueFree(files);
        goto error;
    }

    for (i = 0; i < handler->nfiles; i++) {
        virJSONValuePtr file = virJSONValueNewObject();
        if (!file)
            goto error;

        if (virJSONValueArrayAppend(files, file) < 0) {
            virJSONValueFree(file);
            goto error;
        }

        if (virJSONValueObjectAppendNumberInt(file, "pipefd",
                                              handler->files[i]->pipefd) < 0)
            goto error;

        if (virJSONValueObjectAppendString(file, "path",
                                           virRotatingFileWriterGetPath(handler->files[i]->file)) < 0)
            goto error;

        if (virJSONValueObjectAppendString(file, "driver",
                                           handler->files[i]->driver) < 0)
            goto error;

        if (virJSONValueObjectAppendString(file, "domname",
                                           handler->files[i]->domname) < 0)
            goto error;

        virUUIDFormat(handler->files[i]->domuuid, domuuid);
        if (virJSONValueObjectAppendString(file, "domuuid", domuuid) < 0)
            goto error;

        if (virSetInherit(handler->files[i]->pipefd, true) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot disable close-on-exec flag"));
            goto error;
        }
    }

    return ret;

 error:
    virJSONValueFree(ret);
    return NULL;
}
