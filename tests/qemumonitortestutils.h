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

#pragma once

#include "qemu/qemu_conf.h"
#include "qemu/qemu_monitor.h"
#include "qemu/qemu_agent.h"

typedef struct _qemuMonitorTest qemuMonitorTest;

typedef struct _qemuMonitorTestItem qemuMonitorTestItem;
typedef int (*qemuMonitorTestResponseCallback)(qemuMonitorTest *test,
                                               qemuMonitorTestItem *item,
                                               const char *message);

void
qemuMonitorTestAddHandler(qemuMonitorTest *test,
                          const char *identifier,
                          qemuMonitorTestResponseCallback cb,
                          void *opaque,
                          virFreeCallback freecb);

int
qemuMonitorTestAddResponse(qemuMonitorTest *test,
                           const char *response);

int
qemuMonitorTestAddInvalidCommandResponse(qemuMonitorTest *test,
                                         const char *expectedcommand,
                                         const char *actualcommand);

void *
qemuMonitorTestItemGetPrivateData(qemuMonitorTestItem *item);

int
qemuMonitorTestAddErrorResponse(qemuMonitorTest *test,
                                const char *errmsg,
                                ...);

void
qemuMonitorTestAllowUnusedCommands(qemuMonitorTest *test);
void
qemuMonitorTestSkipDeprecatedValidation(qemuMonitorTest *test,
                                        bool allowRemoved);

int
qemuMonitorTestAddItem(qemuMonitorTest *test,
                       const char *command_name,
                       const char *response);

int
qemuMonitorTestAddItemVerbatim(qemuMonitorTest *test,
                               const char *command,
                               const char *cmderr,
                               const char *response);

int
qemuMonitorTestAddAgentSyncResponse(qemuMonitorTest *test);

#define qemuMonitorTestNewSimple(xmlopt) \
    qemuMonitorTestNew(xmlopt, NULL, NULL, NULL)
#define qemuMonitorTestNewSchema(xmlopt, schema) \
    qemuMonitorTestNew(xmlopt, NULL, NULL, schema)

qemuMonitorTest *
qemuMonitorTestNew(virDomainXMLOption *xmlopt,
                   virDomainObj *vm,
                   const char *greeting,
                   GHashTable *schema);

qemuMonitorTest *
qemuMonitorTestNewFromFile(const char *fileName,
                           virDomainXMLOption *xmlopt,
                           bool simple);
qemuMonitorTest *
qemuMonitorTestNewFromFileFull(const char *fileName,
                               virQEMUDriver *driver,
                               virDomainObj *vm,
                               GHashTable *qmpschema);

qemuMonitorTest *
qemuMonitorTestNewAgent(virDomainXMLOption *xmlopt);


void
qemuMonitorTestFree(qemuMonitorTest *test);

qemuMonitor *
qemuMonitorTestGetMonitor(qemuMonitorTest *test);
qemuAgent *
qemuMonitorTestGetAgent(qemuMonitorTest *test);
virDomainObj *
qemuMonitorTestGetDomainObj(qemuMonitorTest *test);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMonitorTest, qemuMonitorTestFree);

struct qemuMonitorTestCommandReplyTuple {
    const char *command;
    const char *reply;
    size_t line; /* line number of @command */
};


int
qemuMonitorTestProcessFileEntries(char *inputstr,
                                  const char *fileName,
                                  struct qemuMonitorTestCommandReplyTuple **items,
                                  size_t *nitems);
