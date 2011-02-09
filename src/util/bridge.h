/*
 * Copyright (C) 2007 Red Hat, Inc.
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
 *     Mark McLoughlin <markmc@redhat.com>
 */

#ifndef __QEMUD_BRIDGE_H__
# define __QEMUD_BRIDGE_H__

# include <config.h>

# if defined(WITH_BRIDGE)

#  include <net/if.h>
#  include <netinet/in.h>
#  include "network.h"

/**
 * BR_IFNAME_MAXLEN:
 * maximum size in byte of the name for an interface
 */
#  define BR_IFNAME_MAXLEN    IF_NAMESIZE

/**
 * BR_INET_ADDR_MAXLEN:
 * maximum size in bytes for an inet addess name
 */
#  define BR_INET_ADDR_MAXLEN INET_ADDRSTRLEN

typedef struct _brControl brControl;

int     brInit                  (brControl **ctl);
void    brShutdown              (brControl *ctl);

int     brAddBridge             (brControl *ctl,
                                 const char *name);
int     brDeleteBridge          (brControl *ctl,
                                 const char *name);
int     brHasBridge             (brControl *ctl,
                                 const char *name);

int     brAddInterface          (brControl *ctl,
                                 const char *bridge,
                                 const char *iface);
int     brDeleteInterface       (brControl *ctl,
                                 const char *bridge,
                                 const char *iface);

enum {
    BR_TAP_VNET_HDR = (1 << 0),
    BR_TAP_PERSIST =  (1 << 1),
};

int     brAddTap                (brControl *ctl,
                                 const char *bridge,
                                 char **ifname,
                                 const unsigned char *macaddr,
                                 int vnet_hdr,
                                 bool up,
                                 int *tapfd);

int     brDeleteTap             (brControl *ctl,
                                 const char *ifname);

int     brSetInterfaceUp        (brControl *ctl,
                                 const char *ifname,
                                 int up);
int     brGetInterfaceUp        (brControl *ctl,
                                 const char *ifname,
                                 int *up);

int     brAddInetAddress        (brControl *ctl,
                                 const char *ifname,
                                 virSocketAddr *addr,
                                 unsigned int prefix);
int     brDelInetAddress        (brControl *ctl,
                                 const char *ifname,
                                 virSocketAddr *addr,
                                 unsigned int prefix);

int     brSetForwardDelay       (brControl *ctl,
                                 const char *bridge,
                                 int delay);
int     brGetForwardDelay       (brControl *ctl,
                                 const char *bridge,
                                 int *delay);
int     brSetEnableSTP          (brControl *ctl,
                                 const char *bridge,
                                 int enable);
int     brGetEnableSTP          (brControl *ctl,
                                 const char *bridge,
                                 int *enable);

# endif /* WITH_BRIDGE */

#endif /* __QEMUD_BRIDGE_H__ */
