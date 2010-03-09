/*
 * mdns.c: advertise libvirt hypervisor connections
 *
 * Copyright (C) 2007 Daniel P. Berrange
 *
 * Derived from Avahi example service provider code.
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

#include "internal.h"

#ifndef __VIRTD_MDNS_H__
# define __VIRTD_MDNS_H__

struct libvirtd_mdns;
struct libvirtd_mdns_group;
struct libvirtd_mdns_entry;

/**
 * Prepares a new mdns manager object for use
 */
struct libvirtd_mdns *libvirtd_mdns_new(void);

/**
 * Starts the mdns client, advertising any groups/entries currently registered
 *
 * @mdns: manager to start advertising
 *
 * Starts the mdns client. Services may not be immediately visible, since
 * it may asynchronously wait for the mdns service to startup
 *
 * returns -1 upon failure, 0 upon success.
 */
int libvirtd_mdns_start(struct libvirtd_mdns *mdns);

/**
 * Stops the mdns client, removing any advertisements
 *
 * @mdns: manager to start advertising
 *
 */
void libvirtd_mdns_stop(struct libvirtd_mdns *mdns);

/**
 * Adds a group container for advertisement
 *
 * @mdns manager to attach the group to
 * @name unique human readable service name
 *
 * returns the group record, or NULL upon failure
 */
struct libvirtd_mdns_group *libvirtd_mdns_add_group(struct libvirtd_mdns *mdns, const char *name);

/**
 * Removes a group container from advertisement
 *
 * @mdns amanger to detach group from
 * @group group to remove
 */
void libvirtd_mdns_remove_group(struct libvirtd_mdns *mdns, struct libvirtd_mdns_group *group);

/**
 * Adds a service entry in a group
 *
 * @group group to attach the entry to
 * @type service type string
 * @port tcp port number
 *
 * returns the service record, or NULL upon failure
 */
struct libvirtd_mdns_entry *libvirtd_mdns_add_entry(struct libvirtd_mdns_group *group, const char *type, int port);

/**
 * Removes a service entry from a group
 *
 * @group group to detach service entry from
 * @entry service entry to remove
 */
void libvirtd_mdns_remove_entry(struct libvirtd_mdns_group *group, struct libvirtd_mdns_entry *entry);

#endif /* __VIRTD_MDNS_H__ */
