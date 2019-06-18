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
typedef virRotatingFileWriter *virRotatingFileWriterPtr;

typedef struct virRotatingFileReader virRotatingFileReader;
typedef virRotatingFileReader *virRotatingFileReaderPtr;

virRotatingFileWriterPtr virRotatingFileWriterNew(const char *path,
                                                  off_t maxlen,
                                                  size_t maxbackup,
                                                  bool trunc,
                                                  mode_t mode);

virRotatingFileReaderPtr virRotatingFileReaderNew(const char *path,
                                                  size_t maxbackup);

const char *virRotatingFileWriterGetPath(virRotatingFileWriterPtr file);

ino_t virRotatingFileWriterGetINode(virRotatingFileWriterPtr file);
off_t virRotatingFileWriterGetOffset(virRotatingFileWriterPtr file);

ssize_t virRotatingFileWriterAppend(virRotatingFileWriterPtr file,
                                    const char *buf,
                                    size_t len);

int virRotatingFileReaderSeek(virRotatingFileReaderPtr file,
                              ino_t inode,
                              off_t offset);

ssize_t virRotatingFileReaderConsume(virRotatingFileReaderPtr file,
                                     char *buf,
                                     size_t len);

void virRotatingFileWriterFree(virRotatingFileWriterPtr file);
void virRotatingFileReaderFree(virRotatingFileReaderPtr file);
