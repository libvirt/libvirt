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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_BANDWIDTH_CONF_H__
# define __VIR_NETDEV_BANDWIDTH_CONF_H__

# include "internal.h"
# include "virnetdevbandwidth.h"
# include "buf.h"
# include "xml.h"

virNetDevBandwidthPtr virNetDevBandwidthParse(xmlNodePtr node)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthFormat(virNetDevBandwidthPtr def,
                             virBufferPtr buf)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif /* __VIR_NETDEV_BANDWIDTH_CONF_H__ */
