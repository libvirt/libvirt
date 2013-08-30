/*
 * libxl_domain.h: libxl domain object private state
 *
 * Copyright (C) 2011-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Authors:
 *     Jim Fehlig <jfehlig@suse.com>
 */

#ifndef LIBXL_DOMAIN_H
# define LIBXL_DOMAIN_H

# include <libxl.h>

# include "domain_conf.h"
# include "libxl_conf.h"
# include "virchrdev.h"

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
typedef libxlDomainObjPrivate *libxlDomainObjPrivatePtr;
struct _libxlDomainObjPrivate {
    virObjectLockable parent;

    /* per domain log stream for libxl messages */
    FILE *logger_file;
    xentoollog_logger *logger;
    /* per domain libxl ctx */
    libxl_ctx *ctx;
    /* console */
    virChrdevsPtr devs;
    libxl_evgen_domain_death *deathW;

    /* list of libxl timeout registrations */
    libxlEventHookInfoPtr timerRegistrations;
};


extern virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks;
extern virDomainDefParserConfig libxlDomainDefParserConfig;


int
libxlDomainObjPrivateInitCtx(virDomainObjPtr vm);

void
libxlDomainObjRegisteredTimeoutsCleanup(libxlDomainObjPrivatePtr priv);

#endif /* LIBXL_DOMAIN_H */
