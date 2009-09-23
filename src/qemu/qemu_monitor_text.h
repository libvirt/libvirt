/*
 * qemu_monitor_text.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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


#ifndef QEMU_MONITOR_TEXT_H
#define QEMU_MONITOR_TEXT_H

#include "internal.h"

#include "domain_conf.h"

/* XXX remove these two from public header */
#define QEMU_CMD_PROMPT "\n(qemu) "
#define QEMU_PASSWD_PROMPT "Password: "

/* Return -1 for error, 0 for success */
typedef int qemudMonitorExtraPromptHandler(const virDomainObjPtr vm,
                                           const char *buf,
                                           const char *prompt,
                                           void *data);

/* These first 4 APIs are generic monitor interaction. They will
 * go away eventually
 */
int qemudMonitorCommand(const virDomainObjPtr vm,
                        const char *cmd,
                        char **reply);
int qemudMonitorCommandWithFd(const virDomainObjPtr vm,
                              const char *cmd,
                              int scm_fd,
                              char **reply);
int qemudMonitorCommandWithHandler(const virDomainObjPtr vm,
                                   const char *cmd,
                                   const char *extraPrompt,
                                   qemudMonitorExtraPromptHandler extraHandler,
                                   void *handlerData,
                                   int scm_fd,
                                   char **reply);
int qemudMonitorCommandExtra(const virDomainObjPtr vm,
                             const char *cmd,
                             const char *extra,
                             const char *extraPrompt,
                             int scm_fd,
                             char **reply);

/* Formal APIs for each required monitor command */

int qemuMonitorStartCPUs(virConnectPtr conn,
                         const virDomainObjPtr vm);
int qemuMonitorStopCPUs(const virDomainObjPtr vm);

int qemuMonitorGetCPUInfo(const virDomainObjPtr vm,
                          int **pids);

int qemuMonitorSetVNCPassword(const virDomainObjPtr vm,
                              const char *password);

#endif /* QEMU_MONITOR_TEXT_H */
