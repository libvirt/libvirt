/*
 * viriscsi.h: helper APIs for managing iSCSI
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef __VIR_ISCSI_H__
# define __VIR_ISCSI_H__

# include "internal.h"

char *
virISCSIGetSession(const char *devpath,
                   bool probe)
    ATTRIBUTE_NONNULL(1);

int
virISCSIConnectionLogin(const char *portal,
                        const char *initiatoriqn,
                        const char *target)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

int
virISCSIConnectionLogout(const char *portal,
                         const char *initiatoriqn,
                         const char *target)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

int
virISCSIRescanLUNs(const char *session)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int
virISCSIScanTargets(const char *portal,
                    const char *initiatoriqn,
                    size_t *ntargetsret,
                    char ***targetsret)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int
virISCSINodeUpdate(const char *portal,
                   const char *target,
                   const char *name,
                   const char *value)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;
#endif
