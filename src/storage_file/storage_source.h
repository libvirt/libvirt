/*
 * storage_source.h: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009, 2012-2016 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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

#pragma once

#include "storage_source_conf.h"

#ifndef DEV_BSIZE
# define DEV_BSIZE 512
#endif

virStorageSource *
virStorageSourceGetMetadataFromFD(const char *path,
                                  int fd,
                                  int format);

virStorageSource *
virStorageSourceGetMetadataFromBuf(const char *path,
                                   char *buf,
                                   size_t len,
                                   int format)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

virStorageSource *
virStorageSourceChainLookup(virStorageSource *chain,
                            virStorageSource *startFrom,
                            const char *name,
                            const char *diskTarget,
                            virStorageSource **parent)
    ATTRIBUTE_NONNULL(1);

virStorageSource *
virStorageSourceChainLookupBySource(virStorageSource *chain,
                                    virStorageSource *base,
                                    virStorageSource **parent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virStorageSourceUpdatePhysicalSize(virStorageSource *src,
                                   int fd,
                                   struct stat const *sb);

int
virStorageSourceUpdateBackingSizes(virStorageSource *src,
                                   int fd,
                                   struct stat const *sb);

int
virStorageSourceUpdateCapacity(virStorageSource *src,
                               char *buf,
                               ssize_t len);

int
virStorageSourceNewFromBacking(virStorageSource *parent,
                               virStorageSource **backing);

int
virStorageSourceGetRelativeBackingPath(virStorageSource *top,
                                       virStorageSource *base,
                                       char **relpath)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
virStorageSourceNewFromBackingAbsolute(const char *path,
                                       virStorageSource **src);

int
virStorageSourceInit(virStorageSource *src);

int
virStorageSourceInitAs(virStorageSource *src,
                       uid_t uid, gid_t gid);

void
virStorageSourceDeinit(virStorageSource *src);

int
virStorageSourceCreate(virStorageSource *src);

int
virStorageSourceUnlink(virStorageSource *src);

int
virStorageSourceStat(virStorageSource *src,
                     struct stat *st);

ssize_t
virStorageSourceRead(virStorageSource *src,
                     size_t offset,
                     size_t len,
                     char **buf);

int
virStorageSourceAccess(virStorageSource *src,
                       int mode);

int
virStorageSourceChown(const virStorageSource *src,
                      uid_t uid,
                      gid_t gid);

int
virStorageSourceSupportsSecurityDriver(const virStorageSource *src);

int
virStorageSourceSupportsAccess(const virStorageSource *src);

int
virStorageSourceSupportsCreate(const virStorageSource *src);

int
virStorageSourceSupportsBackingChainTraversal(const virStorageSource *src);

int
virStorageSourceGetMetadata(virStorageSource *src,
                            uid_t uid, gid_t gid,
                            size_t max_depth,
                            bool report_broken)
    ATTRIBUTE_NONNULL(1);

int
virStorageSourceFetchRelativeBackingPath(virStorageSource *src,
                                         char **relPath)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virStorageSourceReportBrokenChain(int errcode,
                                  virStorageSource *src,
                                  virStorageSource *parent);
