/*
 * Copyright (C) 2007-2010 Red Hat, Inc.
 * Copyright (C) 2010 Satoru SATOH <satoru.satoh@gmail.com>
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
 * based on iptables.h
 */

#ifndef __DNSMASQ_H__
# define __DNSMASQ_H__

# include "virsocketaddr.h"

typedef struct
{
    /*
     * Each entry holds a string, "<mac_addr>,<hostname>,<ip_addr>" such as
     * "01:23:45:67:89:0a,foo,10.0.0.3".
     */
    char *host;

} dnsmasqDhcpHost;

typedef struct
{
    unsigned int     nhosts;
    dnsmasqDhcpHost *hosts;

    char            *path;  /* Absolute path of dnsmasq's hostsfile. */
} dnsmasqHostsfile;

typedef struct
{
    unsigned int    nhostnames;
    char            *ip;
    char            **hostnames;

} dnsmasqAddnHost;

typedef struct
{
    unsigned int     nhosts;
    dnsmasqAddnHost *hosts;

    char            *path;  /* Absolute path of dnsmasq's hostsfile. */
} dnsmasqAddnHostsfile;

typedef struct
{
    char                 *config_dir;
    dnsmasqHostsfile     *hostsfile;
    dnsmasqAddnHostsfile *addnhostsfile;
} dnsmasqContext;

dnsmasqContext * dnsmasqContextNew(const char *network_name,
                                   const char *config_dir);
void             dnsmasqContextFree(dnsmasqContext *ctx);
int              dnsmasqAddDhcpHost(dnsmasqContext *ctx,
                                    const char *mac,
                                    virSocketAddr *ip,
                                    const char *name);
int              dnsmasqAddHost(dnsmasqContext *ctx,
                                virSocketAddr *ip,
                                const char *name);
int              dnsmasqSave(const dnsmasqContext *ctx);
int              dnsmasqDelete(const dnsmasqContext *ctx);
int              dnsmasqReload(pid_t pid);

#endif /* __DNSMASQ_H__ */
