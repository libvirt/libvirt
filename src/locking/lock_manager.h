/*
 * lock_manager.h: Defines the internal lock manager API
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __VIR_LOCK_MANAGER_H__
# define __VIR_LOCK_MANAGER_H__

# include "internal.h"
# include "lock_driver.h"

typedef struct _virLockManagerPlugin virLockManagerPlugin;
typedef virLockManagerPlugin *virLockManagerPluginPtr;

virLockManagerPluginPtr virLockManagerPluginNew(const char *name,
                                                const char *configFile,
                                                unsigned int flags);
void virLockManagerPluginRef(virLockManagerPluginPtr plugin);
void virLockManagerPluginUnref(virLockManagerPluginPtr plugin);

const char *virLockManagerPluginGetName(virLockManagerPluginPtr plugin);
bool virLockManagerPluginUsesState(virLockManagerPluginPtr plugin);


virLockManagerPtr virLockManagerNew(virLockManagerPluginPtr plugin,
                                    unsigned int type,
                                    size_t nparams,
                                    virLockManagerParamPtr params,
                                    unsigned int flags);

int virLockManagerAddResource(virLockManagerPtr manager,
                              unsigned int type,
                              const char *name,
                              size_t nparams,
                              virLockManagerParamPtr params,
                              unsigned int flags);

int virLockManagerAcquire(virLockManagerPtr manager,
                          const char *state,
                          unsigned int flags,
                          int *fd);
int virLockManagerRelease(virLockManagerPtr manager,
                          char **state,
                          unsigned int flags);
int virLockManagerInquire(virLockManagerPtr manager,
                          char **state,
                          unsigned int flags);

int virLockManagerFree(virLockManagerPtr manager);

#endif /* __VIR_LOCK_MANAGER_H__ */
