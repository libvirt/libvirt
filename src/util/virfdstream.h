/*
 * virfdstream.h: generic streams impl for file descriptors
 *
 * Copyright (C) 2009-2012 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRFDSTREAM_H
# define LIBVIRT_VIRFDSTREAM_H

# include "internal.h"

/* internal callback, the generic one is used up by daemon stream driver */
/* the close callback is called with fdstream private data locked */
typedef void (*virFDStreamInternalCloseCb)(virStreamPtr st, void *opaque);

typedef void (*virFDStreamInternalCloseCbFreeOpaque)(void *opaque);


int virFDStreamOpen(virStreamPtr st,
                    int fd);

int virFDStreamConnectUNIX(virStreamPtr st,
                           const char *path,
                           bool abstract);

int virFDStreamOpenFile(virStreamPtr st,
                        const char *path,
                        unsigned long long offset,
                        unsigned long long length,
                        int oflags);
int virFDStreamCreateFile(virStreamPtr st,
                          const char *path,
                          unsigned long long offset,
                          unsigned long long length,
                          int oflags,
                          mode_t mode);
int virFDStreamOpenPTY(virStreamPtr st,
                       const char *path,
                       unsigned long long offset,
                       unsigned long long length,
                       int oflags);
int virFDStreamOpenBlockDevice(virStreamPtr st,
                               const char *path,
                               unsigned long long offset,
                               unsigned long long length,
                               bool sparse,
                               int oflags);

int virFDStreamSetInternalCloseCb(virStreamPtr st,
                                  virFDStreamInternalCloseCb cb,
                                  void *opaque,
                                  virFDStreamInternalCloseCbFreeOpaque fcb);
#endif /* LIBVIRT_VIRFDSTREAM_H */
