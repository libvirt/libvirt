/*
 * domain_lock.h: Locking for domain lifecycle operations
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 */

#ifndef LIBVIRT_DOMAIN_LOCK_H
# define LIBVIRT_DOMAIN_LOCK_H

# include "internal.h"
# include "domain_conf.h"
# include "lock_manager.h"

int virDomainLockProcessStart(virLockManagerPluginPtr plugin,
                              const char *uri,
                              virDomainObjPtr dom,
                              bool paused,
                              int *fd);
int virDomainLockProcessPause(virLockManagerPluginPtr plugin,
                              virDomainObjPtr dom,
                              char **state);
int virDomainLockProcessResume(virLockManagerPluginPtr plugin,
                               const char *uri,
                               virDomainObjPtr dom,
                               const char *state);
int virDomainLockProcessInquire(virLockManagerPluginPtr plugin,
                                virDomainObjPtr dom,
                                char **state);

int virDomainLockImageAttach(virLockManagerPluginPtr plugin,
                             const char *uri,
                             virDomainObjPtr dom,
                             virStorageSourcePtr src);
int virDomainLockImageDetach(virLockManagerPluginPtr plugin,
                             virDomainObjPtr dom,
                             virStorageSourcePtr src);

int virDomainLockLeaseAttach(virLockManagerPluginPtr plugin,
                             const char *uri,
                             virDomainObjPtr dom,
                             virDomainLeaseDefPtr lease);
int virDomainLockLeaseDetach(virLockManagerPluginPtr plugin,
                             virDomainObjPtr dom,
                             virDomainLeaseDefPtr lease);

#endif /* LIBVIRT_DOMAIN_LOCK_H */
