/*
 * virkeyfile.h: "ini"-style configuration file handling
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_KEYFILE_H__
# define __VIR_KEYFILE_H__

# include "internal.h"

/**
 * virKeyFilePtr:
 * a pointer to a parsed configuration file
 */
typedef struct _virKeyFile virKeyFile;
typedef virKeyFile *virKeyFilePtr;

virKeyFilePtr virKeyFileNew(void);

int virKeyFileLoadFile(virKeyFilePtr conf,
                       const char *filename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virKeyFileLoadData(virKeyFilePtr conf,
                       const char *filename,
                       const char *data,
                       size_t len)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

void virKeyFileFree(virKeyFilePtr conf);

bool virKeyFileHasGroup(virKeyFilePtr conf,
                        const char *groupname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virKeyFileHasValue(virKeyFilePtr conf,
                        const char *groupname,
                        const char *valuename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

const char *virKeyFileGetValueString(virKeyFilePtr conf,
                                     const char *groupname,
                                     const char *valuename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

#endif /* __VIR_KEYFILE_H__ */
