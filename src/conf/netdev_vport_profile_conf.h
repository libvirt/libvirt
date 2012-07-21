/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_VPORT_PROFILE_CONF_H__
# define __VIR_NETDEV_VPORT_PROFILE_CONF_H__

# include "internal.h"
# include "virnetdevvportprofile.h"
# include "buf.h"
# include "xml.h"

virNetDevVPortProfilePtr
virNetDevVPortProfileParse(xmlNodePtr node);

int
virNetDevVPortProfileFormat(virNetDevVPortProfilePtr virtPort,
                            virBufferPtr buf);


#endif /* __VIR_NETDEV_VPORT_PROFILE_CONF_H__ */
