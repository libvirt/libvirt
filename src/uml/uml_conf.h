/*
 * config.h: VM configuration management
 *
 * Copyright (C) 2006, 2007, 2010 Red Hat, Inc.
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

#ifndef __UML_CONF_H
# define __UML_CONF_H

# include "internal.h"
# include "capabilities.h"
# include "network_conf.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "virterror_internal.h"
# include "threads.h"
# include "command.h"
# include "virhash.h"

# define umlDebug(fmt, ...) do {} while(0)

# define UML_CPUMASK_LEN CPU_SETSIZE

# define UML_MAX_CHAR_DEVICE 16

/* Main driver state */
struct uml_driver {
    virMutex lock;

    int privileged;

    unsigned long umlVersion;
    int nextvmid;

    virDomainObjList domains;

    char *configDir;
    char *autostartDir;
    char *logDir;
    char *monitorDir;

    int inotifyFD;
    int inotifyWatch;

    virCapsPtr caps;

    /* Event handling */
    virDomainEventStatePtr domainEventState;

    /* Mapping of 'char *uuidstr' -> virConnectPtr
     * of guests which will be automatically killed
     * when the virConnectPtr is closed*/
    virHashTablePtr autodestroy;
};


# define umlReportError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_UML, code, __FILE__,                  \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

virCapsPtr  umlCapsInit               (void);

virCommandPtr umlBuildCommandLine(virConnectPtr conn,
                                  struct uml_driver *driver,
                                  virDomainObjPtr dom);

#endif /* __UML_CONF_H */
