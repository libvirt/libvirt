/*
 * Copyright IBM Corp. 2008
 *
 * lxc_controller.h: linux container process controller
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef LXC_CONTROLLER_H
#define LXC_CONTROLLER_H

#ifdef WITH_LXC

#include "lxc_conf.h"

int lxcControllerStart(const char *stateDir,
                       virDomainDefPtr def,
                       unsigned int nveths,
                       char **veths,
                       int monitor,
                       int appPty,
                       int logfd);

#endif /* WITH_LXC */

#endif /* LXC_CONTROLLER_H */
