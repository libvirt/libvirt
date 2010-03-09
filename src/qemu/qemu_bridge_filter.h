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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Gerhard Stenzel <gerhard.stenzel@de.ibm.com>
 */

#ifndef __QEMUD_BRIDGE_FILTER_H__
# define __QEMUD_BRIDGE_FILTER_H__


int networkAllowMacOnPort(struct qemud_driver *driver,
                          const char * ifname,
                          const unsigned char * mac);
int networkDisallowMacOnPort(struct qemud_driver *driver,
                             const char * ifname,
                             const unsigned char * mac);
int networkDisableAllFrames(struct qemud_driver *driver);
int networkAddEbtablesRules(struct qemud_driver *driver);


#endif /* __QEMUD_BRIDGE_FILTER_H__ */
