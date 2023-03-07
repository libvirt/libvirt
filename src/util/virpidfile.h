/*
 * virpidfile.h: manipulation of pidfiles
 *
 * Copyright (C) 2010-2011, 2014 Red Hat, Inc.
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

#pragma once

#include <sys/types.h>
#include "internal.h"

char *virPidFileBuildPath(const char *dir,
                          const char *name);

int virPidFileWritePath(const char *path,
                        pid_t pid) G_GNUC_WARN_UNUSED_RESULT;
int virPidFileWrite(const char *dir,
                    const char *name,
                    pid_t pid) G_GNUC_WARN_UNUSED_RESULT;

int virPidFileReadPath(const char *path,
                       pid_t *pid) G_GNUC_WARN_UNUSED_RESULT;
int virPidFileRead(const char *dir,
                   const char *name,
                   pid_t *pid) G_GNUC_WARN_UNUSED_RESULT;

int virPidFileReadPathIfAlive(const char *path,
                              pid_t *pid,
                              const char *binpath) G_GNUC_WARN_UNUSED_RESULT;
int virPidFileReadIfAlive(const char *dir,
                          const char *name,
                          pid_t *pid,
                          const char *binpath) G_GNUC_WARN_UNUSED_RESULT;
int virPidFileReadPathIfLocked(const char *path,
                               pid_t *pid)  G_GNUC_WARN_UNUSED_RESULT;

int virPidFileDeletePath(const char *path);
int virPidFileDelete(const char *dir,
                     const char *name);


int virPidFileAcquirePathFull(const char *path,
                              bool waitForLock,
                              bool quiet,
                              pid_t pid) G_GNUC_WARN_UNUSED_RESULT;
int virPidFileAcquirePath(const char *path,
                          pid_t pid) G_GNUC_WARN_UNUSED_RESULT;
int virPidFileAcquire(const char *dir,
                      const char *name,
                      pid_t pid) G_GNUC_WARN_UNUSED_RESULT;

int virPidFileReleasePath(const char *path,
                          int fd);
int virPidFileRelease(const char *dir,
                      const char *name,
                      int fd);

int virPidFileConstructPath(bool privileged,
                            const char *statedir,
                            const char *progname,
                            char **pidfile);

int virPidFileForceCleanupPathFull(const char *path,
                                   bool group) ATTRIBUTE_NONNULL(1);
int virPidFileForceCleanupPath(const char *path) ATTRIBUTE_NONNULL(1);
