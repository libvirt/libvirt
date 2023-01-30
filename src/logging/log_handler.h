/*
 * log_handler.h: log management daemon handler
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

#pragma once

#include "internal.h"
#include "virjson.h"
#include "log_daemon_config.h"
#include "virobject.h"
#include "virrotatingfile.h"

typedef void (*virLogHandlerShutdownInhibitor)(bool inhibit,
                                               void *opaque);

typedef struct _virLogHandlerLogFile virLogHandlerLogFile;
struct _virLogHandlerLogFile {
    virRotatingFileWriter *file;
    int watch;
    int pipefd; /* Read from QEMU via this */
    bool drained;

    char *driver;
    unsigned char domuuid[VIR_UUID_BUFLEN];
    char *domname;
};

typedef struct _virLogHandler virLogHandler;
struct _virLogHandler {
    virObjectLockable parent;

    bool privileged;
    virLogDaemonConfig *config;

    int cleanup_log_timer;

    virLogHandlerLogFile **files;
    size_t nfiles;

    virLogHandlerShutdownInhibitor inhibitor;
    void *opaque;
};

virLogHandler *virLogHandlerNew(bool privileged,
                                virLogDaemonConfig *config,
                                virLogHandlerShutdownInhibitor inhibitor,
                                void *opaque);
virLogHandler *virLogHandlerNewPostExecRestart(virJSONValue *child,
                                               bool privileged,
                                               virLogDaemonConfig *config,
                                               virLogHandlerShutdownInhibitor inhibitor,
                                               void *opaque);

void virLogHandlerFree(virLogHandler *handler);

int virLogHandlerDomainOpenLogFile(virLogHandler *handler,
                                   const char *driver,
                                   const unsigned char *domuuid,
                                   const char *domname,
                                   const char *path,
                                   bool trunc,
                                   ino_t *inode,
                                   off_t *offset);

int virLogHandlerDomainGetLogFilePosition(virLogHandler *handler,
                                          const char *path,
                                          unsigned int flags,
                                          ino_t *inode,
                                          off_t *offset);

char *virLogHandlerDomainReadLogFile(virLogHandler *handler,
                                     const char *path,
                                     ino_t inode,
                                     off_t offset,
                                     size_t maxlen,
                                     unsigned int flags);

int virLogHandlerDomainAppendLogFile(virLogHandler *handler,
                                     const char *driver,
                                     const unsigned char *domuuid,
                                     const char *domname,
                                     const char *path,
                                     const char *message,
                                     unsigned int flags);

virJSONValue *virLogHandlerPreExecRestart(virLogHandler *handler);
