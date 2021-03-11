/*
 * virrotatingfile.h: reading/writing of auto-rotating files
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "internal.h"

typedef struct virRotatingFileWriter virRotatingFileWriter;

typedef struct virRotatingFileReader virRotatingFileReader;

virRotatingFileWriter *virRotatingFileWriterNew(const char *path,
                                                  off_t maxlen,
                                                  size_t maxbackup,
                                                  bool trunc,
                                                  mode_t mode);

virRotatingFileReader *virRotatingFileReaderNew(const char *path,
                                                  size_t maxbackup);

const char *virRotatingFileWriterGetPath(virRotatingFileWriter *file);

ino_t virRotatingFileWriterGetINode(virRotatingFileWriter *file);
off_t virRotatingFileWriterGetOffset(virRotatingFileWriter *file);

ssize_t virRotatingFileWriterAppend(virRotatingFileWriter *file,
                                    const char *buf,
                                    size_t len);

int virRotatingFileReaderSeek(virRotatingFileReader *file,
                              ino_t inode,
                              off_t offset);

ssize_t virRotatingFileReaderConsume(virRotatingFileReader *file,
                                     char *buf,
                                     size_t len);

void virRotatingFileWriterFree(virRotatingFileWriter *file);
void virRotatingFileReaderFree(virRotatingFileReader *file);
