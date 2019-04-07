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

#ifndef LIBVIRT_LOG_HANDLER_H
# define LIBVIRT_LOG_HANDLER_H

# include "internal.h"
# include "virjson.h"

typedef struct _virLogHandler virLogHandler;
typedef virLogHandler *virLogHandlerPtr;


typedef void (*virLogHandlerShutdownInhibitor)(bool inhibit,
                                               void *opaque);

virLogHandlerPtr virLogHandlerNew(bool privileged,
                                  size_t max_size,
                                  size_t max_backups,
                                  virLogHandlerShutdownInhibitor inhibitor,
                                  void *opaque);
virLogHandlerPtr virLogHandlerNewPostExecRestart(virJSONValuePtr child,
                                                 bool privileged,
                                                 size_t max_size,
                                                 size_t max_backups,
                                                 virLogHandlerShutdownInhibitor inhibitor,
                                                 void *opaque);

void virLogHandlerFree(virLogHandlerPtr handler);

int virLogHandlerDomainOpenLogFile(virLogHandlerPtr handler,
                                   const char *driver,
                                   const unsigned char *domuuid,
                                   const char *domname,
                                   const char *path,
                                   bool trunc,
                                   ino_t *inode,
                                   off_t *offset);

int virLogHandlerDomainGetLogFilePosition(virLogHandlerPtr handler,
                                          const char *path,
                                          unsigned int flags,
                                          ino_t *inode,
                                          off_t *offset);

char *virLogHandlerDomainReadLogFile(virLogHandlerPtr handler,
                                     const char *path,
                                     ino_t inode,
                                     off_t offset,
                                     size_t maxlen,
                                     unsigned int flags);

int virLogHandlerDomainAppendLogFile(virLogHandlerPtr handler,
                                     const char *driver,
                                     const unsigned char *domuuid,
                                     const char *domname,
                                     const char *path,
                                     const char *message,
                                     unsigned int flags);

virJSONValuePtr virLogHandlerPreExecRestart(virLogHandlerPtr handler);

#endif /* LIBVIRT_LOG_HANDLER_H */
