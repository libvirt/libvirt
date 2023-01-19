/*
 * qemu_logcontext.h: QEMU log context
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

#include <glib-object.h>
#include "qemu_conf.h"
#include "logging/log_manager.h"

#define QEMU_TYPE_LOG_CONTEXT qemu_log_context_get_type()
G_DECLARE_FINAL_TYPE(qemuLogContext, qemu_log_context, QEMU, LOG_CONTEXT, GObject);

qemuLogContext *qemuLogContextNew(virQEMUDriver *driver,
                                  virDomainObj *vm,
                                  const char *basename);
int qemuLogContextWrite(qemuLogContext *ctxt,
                        const char *fmt, ...) G_GNUC_PRINTF(2, 3);
ssize_t qemuLogContextRead(qemuLogContext *ctxt,
                           char **msg);
int qemuLogContextReadFiltered(qemuLogContext *ctxt,
                               char **msg,
                               size_t max);
int qemuLogContextGetWriteFD(qemuLogContext *ctxt);
void qemuLogContextMarkPosition(qemuLogContext *ctxt);

virLogManager *qemuLogContextGetManager(qemuLogContext *ctxt);
