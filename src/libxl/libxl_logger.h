/*
 * libxl_logger.h: libxl logger implementation
 *
 * Copyright (c) 2016 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Authors:
 *     Cédric Bosdonnat <cbosdonnat@suse.com>
 */

#ifndef __LIBXL_LOGGER_H
# define __LIBXL_LOGGER_H

# include "util/virlog.h"

typedef struct xentoollog_logger_libvirt libxlLogger;
typedef libxlLogger *libxlLoggerPtr;

libxlLoggerPtr libxlLoggerNew(const char *logDir,
                              virLogPriority minLevel);
void libxlLoggerFree(libxlLoggerPtr logger);

void libxlLoggerOpenFile(libxlLoggerPtr logger, int id, const char *name,
                         const char *domain_config);
void libxlLoggerCloseFile(libxlLoggerPtr logger, int id);

#endif /* __LIBXL_LOGGER_H */
