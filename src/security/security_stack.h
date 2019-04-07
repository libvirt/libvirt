/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * Stacked security driver
 */

#ifndef LIBVIRT_SECURITY_STACK_H
# define LIBVIRT_SECURITY_STACK_H

# include "security_driver.h"

extern virSecurityDriver virSecurityDriverStack;


int
virSecurityStackAddNested(virSecurityManagerPtr mgr,
                          virSecurityManagerPtr nested);
virSecurityManagerPtr
virSecurityStackGetPrimary(virSecurityManagerPtr mgr);

virSecurityManagerPtr*
virSecurityStackGetNested(virSecurityManagerPtr mgr);

#endif /* LIBVIRT_SECURITY_STACK_H */
