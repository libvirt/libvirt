/*
 * Copyright IBM Corp. 2008
 *
 * lxc_container.h: header file for fcns run inside container
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

#ifndef LXC_CONTAINER_H
#define LXC_CONTAINER_H

#include "lxc_conf.h"

enum {
    LXC_CONTAINER_FEATURE_NET = (1 << 0),
};

int lxcContainerSendContinue(int control);

int lxcContainerStart(virDomainDefPtr def,
                      unsigned int nveths,
                      char **veths,
                      int control,
                      char *ttyPath);

int lxcContainerAvailable(int features);

#endif /* LXC_CONTAINER_H */
