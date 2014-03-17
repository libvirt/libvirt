/*
 * virpidfile.h: manipulation of pidfiles
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
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
 */

#ifndef __VIR_PIDFILE_H__
# define __VIR_PIDFILE_H__

# include <sys/types.h>
# include "internal.h"

char *virPidFileBuildPath(const char *dir,
                          const char *name);

int virPidFileWritePath(const char *path,
                        pid_t pid) ATTRIBUTE_RETURN_CHECK;
int virPidFileWrite(const char *dir,
                    const char *name,
                    pid_t pid) ATTRIBUTE_RETURN_CHECK;

int virPidFileReadPath(const char *path,
                       pid_t *pid) ATTRIBUTE_RETURN_CHECK;
int virPidFileRead(const char *dir,
                   const char *name,
                   pid_t *pid) ATTRIBUTE_RETURN_CHECK;

int virPidFileReadPathIfAlive(const char *path,
                              pid_t *pid,
                              const char *binpath) ATTRIBUTE_RETURN_CHECK;
int virPidFileReadIfAlive(const char *dir,
                          const char *name,
                          pid_t *pid,
                          const char *binpath) ATTRIBUTE_RETURN_CHECK;

int virPidFileDeletePath(const char *path);
int virPidFileDelete(const char *dir,
                     const char *name);


int virPidFileAcquirePath(const char *path,
                          bool waitForLock,
                          pid_t pid) ATTRIBUTE_RETURN_CHECK;
int virPidFileAcquire(const char *dir,
                      const char *name,
                      bool waitForLock,
                      pid_t pid) ATTRIBUTE_RETURN_CHECK;

int virPidFileReleasePath(const char *path,
                          int fd);
int virPidFileRelease(const char *dir,
                      const char *name,
                      int fd);

#endif /* __VIR_PIDFILE_H__ */
