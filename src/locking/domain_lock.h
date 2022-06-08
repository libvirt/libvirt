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

#pragma once

#include "internal.h"
#include "lock_manager.h"

int virDomainLockProcessStart(virLockManagerPlugin *plugin,
                              const char *uri,
                              virDomainObj *dom,
                              bool paused,
                              int *fd);
int virDomainLockProcessPause(virLockManagerPlugin *plugin,
                              virDomainObj *dom,
                              char **state);
int virDomainLockProcessResume(virLockManagerPlugin *plugin,
                               const char *uri,
                               virDomainObj *dom,
                               const char *state);
int virDomainLockProcessInquire(virLockManagerPlugin *plugin,
                                virDomainObj *dom,
                                char **state);

int virDomainLockImageAttach(virLockManagerPlugin *plugin,
                             const char *uri,
                             virDomainObj *dom,
                             virStorageSource *src);
int virDomainLockImageDetach(virLockManagerPlugin *plugin,
                             virDomainObj *dom,
                             virStorageSource *src);

int virDomainLockLeaseAttach(virLockManagerPlugin *plugin,
                             const char *uri,
                             virDomainObj *dom,
                             virDomainLeaseDef *lease);
int virDomainLockLeaseDetach(virLockManagerPlugin *plugin,
                             virDomainObj *dom,
                             virDomainLeaseDef *lease);
