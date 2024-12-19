/*
 * domain_logcontext.h: Domain log context
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
#include "logging/log_manager.h"
#include "virconftypes.h"
#include "domain_conf.h"

#define DOMAIN_TYPE_LOG_CONTEXT domain_log_context_get_type()
G_DECLARE_FINAL_TYPE(domainLogContext, domain_log_context, DOMAIN, LOG_CONTEXT, GObject);

domainLogContext *domainLogContextNew(bool stdioLogD,
                                      char *logDir,
                                      const char *driver_name,
                                      virDomainObj *vm,
                                      bool privileged,
                                      const char *basename);
int domainLogContextWrite(domainLogContext *ctxt,
                          const char *fmt, ...) G_GNUC_PRINTF(2, 3);
ssize_t domainLogContextRead(domainLogContext *ctxt,
                             char **msg);
int domainLogContextReadFiltered(domainLogContext *ctxt,
                                 char **msg,
                                 size_t max);
int domainLogContextGetWriteFD(domainLogContext *ctxt);
void domainLogContextMarkPosition(domainLogContext *ctxt);

virLogManager *domainLogContextGetManager(domainLogContext *ctxt);
