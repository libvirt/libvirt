/*
 * virnetservermdns.h: advertise server sockets
 *
 * Copyright (C) 2011 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SERVER_MDNS_H__
# define __VIR_NET_SERVER_MDNS_H__

# include "internal.h"

typedef struct _virNetServerMDNS virNetServerMDNS;
typedef virNetServerMDNS *virNetServerMDNSPtr;
typedef struct _virNetServerMDNSGroup virNetServerMDNSGroup;
typedef virNetServerMDNSGroup *virNetServerMDNSGroupPtr;
typedef struct _virNetServerMDNSEntry virNetServerMDNSEntry;
typedef virNetServerMDNSEntry *virNetServerMDNSEntryPtr;


/**
 * Prepares a new mdns manager object for use
 */
virNetServerMDNSPtr virNetServerMDNSNew(void);

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
int virNetServerMDNSStart(virNetServerMDNSPtr mdns);

/**
 * Stops the mdns client, removing any advertisements
 *
 * @mdns: manager to start advertising
 *
 */
void virNetServerMDNSStop(virNetServerMDNSPtr mdns);

/**
 * Adds a group container for advertisement
 *
 * @mdns manager to attach the group to
 * @name unique human readable service name
 *
 * returns the group record, or NULL upon failure
 */
virNetServerMDNSGroupPtr virNetServerMDNSAddGroup(virNetServerMDNSPtr mdns,
                                                  const char *name);

/**
 * Removes a group container from advertisement
 *
 * @mdns amanger to detach group from
 * @group group to remove
 */
void virNetServerMDNSRemoveGroup(virNetServerMDNSPtr mdns,
                                 virNetServerMDNSGroupPtr group);

/**
 * Adds a service entry in a group
 *
 * @group group to attach the entry to
 * @type service type string
 * @port tcp port number
 *
 * returns the service record, or NULL upon failure
 */
virNetServerMDNSEntryPtr virNetServerMDNSAddEntry(virNetServerMDNSGroupPtr group,
                                                  const char *type, int port);

/**
 * Removes a service entry from a group
 *
 * @group group to detach service entry from
 * @entry service entry to remove
 */
void virNetServerMDNSRemoveEntry(virNetServerMDNSGroupPtr group,
                                 virNetServerMDNSEntryPtr entry);

void virNetServerMDNSFree(virNetServerMDNSPtr ptr);
void virNetServerMDNSGroupFree(virNetServerMDNSGroupPtr ptr);
void virNetServerMDNSEntryFree(virNetServerMDNSEntryPtr ptr);

#endif /* __VIR_NET_SERVER_MDNS_H__ */
