/*
 * Copyright (C) 2009 IBM Corp.
 * Copyright (C) 2007-2009 Red Hat, Inc.
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
 *     Gerhard Stenzel <gerhard.stenzel@de.ibm.com>
 */

#ifndef __QEMUD_BRIDGE_FILTER_H__
# define __QEMUD_BRIDGE_FILTER_H__


int networkAllowMacOnPort(virQEMUDriverPtr driver,
                          const char * ifname,
                          const virMacAddrPtr mac);
int networkDisallowMacOnPort(virQEMUDriverPtr driver,
                             const char * ifname,
                             const virMacAddrPtr mac);
int networkDisableAllFrames(virQEMUDriverPtr driver);
int networkAddEbtablesRules(virQEMUDriverPtr driver);


#endif /* __QEMUD_BRIDGE_FILTER_H__ */
