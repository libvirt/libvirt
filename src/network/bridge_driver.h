/*
 * bridge_driver.h: core driver methods for managing networks
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 */

#ifndef LIBVIRT_BRIDGE_DRIVER_H
# define LIBVIRT_BRIDGE_DRIVER_H

# include "internal.h"
# include "domain_conf.h"
# include "vircommand.h"
# include "virdnsmasq.h"
# include "virnetworkobj.h"

int
networkRegister(void);

int
networkDnsmasqConfContents(virNetworkObjPtr obj,
                           const char *pidfile,
                           char **configstr,
                           dnsmasqContext *dctx,
                           dnsmasqCapsPtr caps);

#endif /* LIBVIRT_BRIDGE_DRIVER_H */
