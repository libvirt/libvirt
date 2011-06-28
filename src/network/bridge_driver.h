/*
 * network_driver.h: core driver methods for managing networks
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef __VIR_NETWORK__DRIVER_H
# define __VIR_NETWORK__DRIVER_H

# include <config.h>

# include "internal.h"
# include "network_conf.h"
# include "command.h"
# include "dnsmasq.h"

int networkRegister(void);
int networkBuildDhcpDaemonCommandLine(virNetworkObjPtr network,
                                      virCommandPtr *cmdout, char *pidfile,
                                      dnsmasqContext *dctx);

typedef char *(*networkDnsmasqLeaseFileNameFunc)(const char *netname);

/* this allows the testsuite to replace the lease filename resolver function */
extern networkDnsmasqLeaseFileNameFunc networkDnsmasqLeaseFileName;

#endif /* __VIR_NETWORK__DRIVER_H */
