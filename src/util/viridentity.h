/*
 * viridentity.h: helper APIs for managing user identities
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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
 *
 */

#ifndef __VIR_IDENTITY_H__
# define __VIR_IDENTITY_H__

# include "virobject.h"

typedef struct _virIdentity virIdentity;
typedef virIdentity *virIdentityPtr;

typedef enum {
      VIR_IDENTITY_ATTR_UNIX_USER_NAME,
      VIR_IDENTITY_ATTR_UNIX_GROUP_NAME,
      VIR_IDENTITY_ATTR_UNIX_PROCESS_ID,
      VIR_IDENTITY_ATTR_UNIX_PROCESS_TIME,
      VIR_IDENTITY_ATTR_SASL_USER_NAME,
      VIR_IDENTITY_ATTR_X509_DISTINGUISHED_NAME,
      VIR_IDENTITY_ATTR_SELINUX_CONTEXT,

      VIR_IDENTITY_ATTR_LAST,
} virIdentityAttrType;

virIdentityPtr virIdentityGetCurrent(void);
int virIdentitySetCurrent(virIdentityPtr ident);

virIdentityPtr virIdentityGetSystem(void);

virIdentityPtr virIdentityNew(void);

int virIdentitySetAttr(virIdentityPtr ident,
                       unsigned int attr,
                       const char *value)
    ATTRIBUTE_NONNULL(1)
    ATTRIBUTE_NONNULL(3);

int virIdentityGetAttr(virIdentityPtr ident,
                       unsigned int attr,
                       const char **value)
    ATTRIBUTE_NONNULL(1)
    ATTRIBUTE_NONNULL(3);

bool virIdentityIsEqual(virIdentityPtr identA,
                        virIdentityPtr identB)
    ATTRIBUTE_NONNULL(1)
    ATTRIBUTE_NONNULL(2);

#endif /* __VIR_IDENTITY_H__ */
