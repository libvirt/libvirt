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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * POSIX DAC security driver
 */

#include "security_driver.h"

#ifndef __VIR_SECURITY_DAC
# define __VIR_SECURITY_DAC

extern virSecurityDriver virSecurityDriverDAC;

void virSecurityDACSetUser(virSecurityManagerPtr mgr,
                           uid_t user);
void virSecurityDACSetGroup(virSecurityManagerPtr mgr,
                            gid_t group);

void virSecurityDACSetDynamicOwnership(virSecurityManagerPtr mgr,
                                       bool dynamic);

#endif /* __VIR_SECURITY_DAC */
