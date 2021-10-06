/*
 * log_manager.h: log management client
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

typedef struct _virLogManager virLogManager;

virLogManager *virLogManagerNew(bool privileged);

void virLogManagerFree(virLogManager *mgr);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virLogManager, virLogManagerFree);


int virLogManagerDomainOpenLogFile(virLogManager *mgr,
                                   const char *driver,
                                   const unsigned char *domuuid,
                                   const char *domname,
                                   const char *path,
                                   unsigned int flags,
                                   ino_t *inode,
                                   off_t *offset);

int virLogManagerDomainGetLogFilePosition(virLogManager *mgr,
                                          const char *path,
                                          unsigned int flags,
                                          ino_t *inode,
                                          off_t *offset);

char *virLogManagerDomainReadLogFile(virLogManager *mgr,
                                     const char *path,
                                     ino_t inode,
                                     off_t offset,
                                     size_t maxlen,
                                     unsigned int flags);

int virLogManagerDomainAppendMessage(virLogManager *mgr,
                                     const char *driver,
                                     const unsigned char *domuuid,
                                     const char *domname,
                                     const char *path,
                                     const char *message,
                                     unsigned int flags);
