/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
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

#ifndef __VIR_QEMU_MONITOR_TEST_UTILS_H__
# define __VIR_QEMU_MONITOR_TEST_UTILS_H__

# include "domain_conf.h"
# include "qemu/qemu_conf.h"
# include "qemu/qemu_monitor.h"
# include "qemu/qemu_agent.h"

typedef struct _qemuMonitorTest qemuMonitorTest;
typedef qemuMonitorTest *qemuMonitorTestPtr;

typedef struct _qemuMonitorTestItem qemuMonitorTestItem;
typedef qemuMonitorTestItem *qemuMonitorTestItemPtr;
typedef int (*qemuMonitorTestResponseCallback)(qemuMonitorTestPtr test,
                                               qemuMonitorTestItemPtr item,
                                               const char *message);

int qemuMonitorTestAddHandler(qemuMonitorTestPtr test,
                              qemuMonitorTestResponseCallback cb,
                              void *opaque,
                              virFreeCallback freecb);

int qemuMonitorTestAddResponse(qemuMonitorTestPtr test,
                               const char *response);

int qemuMonitorTestAddInvalidCommandResponse(qemuMonitorTestPtr test,
                                             const char *expectedcommand,
                                             const char *actualcommand);

void *qemuMonitorTestItemGetPrivateData(qemuMonitorTestItemPtr item);

int qemuMonitorReportError(qemuMonitorTestPtr test, const char *errmsg, ...);

int qemuMonitorTestAddItem(qemuMonitorTestPtr test,
                           const char *command_name,
                           const char *response);

int qemuMonitorTestAddItemVerbatim(qemuMonitorTestPtr test,
                                   const char *command,
                                   const char *cmderr,
                                   const char *response);

int qemuMonitorTestAddAgentSyncResponse(qemuMonitorTestPtr test);

int qemuMonitorTestAddItemParams(qemuMonitorTestPtr test,
                                 const char *cmdname,
                                 const char *response,
                                 ...)
    ATTRIBUTE_SENTINEL;

int qemuMonitorTestAddItemExpect(qemuMonitorTestPtr test,
                                 const char *cmdname,
                                 const char *cmdargs,
                                 bool apostrophe,
                                 const char *response);

# define qemuMonitorTestNewSimple(json, xmlopt) \
    qemuMonitorTestNew(json, xmlopt, NULL, NULL, NULL)

qemuMonitorTestPtr qemuMonitorTestNew(bool json,
                                      virDomainXMLOptionPtr xmlopt,
                                      virDomainObjPtr vm,
                                      virQEMUDriverPtr driver,
                                      const char *greeting);

qemuMonitorTestPtr qemuMonitorTestNewFromFile(const char *fileName,
                                              virDomainXMLOptionPtr xmlopt,
                                              bool simple);

qemuMonitorTestPtr qemuMonitorTestNewAgent(virDomainXMLOptionPtr xmlopt);


void qemuMonitorTestFree(qemuMonitorTestPtr test);

qemuMonitorPtr qemuMonitorTestGetMonitor(qemuMonitorTestPtr test);
qemuAgentPtr qemuMonitorTestGetAgent(qemuMonitorTestPtr test);

#endif /* __VIR_QEMU_MONITOR_TEST_UTILS_H__ */
