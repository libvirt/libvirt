/*
 * domain_cgroup.h: cgroup functions shared between hypervisor drivers
 *
 * Copyright IBM Corp. 2020
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

#pragma once

#include "vircgroup.h"
#include "domain_conf.h"


int virDomainCgroupSetupBlkio(virCgroupPtr cgroup, virDomainBlkiotune blkio);
int virDomainCgroupSetupMemtune(virCgroupPtr cgroup, virDomainMemtune mem);
int virDomainCgroupSetupDomainBlkioParameters(virCgroupPtr cgroup,
                                              virDomainDefPtr def,
                                              virTypedParameterPtr params,
                                              int nparams);
int virDomainCgroupSetMemoryLimitParameters(virCgroupPtr cgroup,
                                            virDomainObjPtr vm,
                                            virDomainDefPtr liveDef,
                                            virDomainDefPtr persistentDef,
                                            virTypedParameterPtr params,
                                            int nparams);
