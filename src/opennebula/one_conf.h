/*----------------------------------------------------------------------------------*/
/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright 2002-2009, Distributed Systems Architecture Group, Universidad
 * Complutense de Madrid (dsa-research.org)
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
 */
/*-----------------------------------------------------------------------------------*/

#ifndef ONE_CONF_H
# define ONE_CONF_H

# include <config.h>

# include "internal.h"
# include "domain_conf.h"
# include "capabilities.h"
# include "threads.h"
# include "one_client.h"

struct one_driver{
    virMutex lock;

    virCapsPtr caps;
    virDomainObjList domains;
    int nextid;
};

typedef struct one_driver one_driver_t;

virCapsPtr oneCapsInit(void);

int oneSubmitVM(one_driver_t* driver, virDomainObjPtr  vm);

char* xmlOneTemplate(virDomainDefPtr def);

# define oneError(code, ...)                                            \
    virReportErrorHelper(NULL, VIR_FROM_ONE, code, __FILE__,            \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#endif /* ONE_CONF_H */
