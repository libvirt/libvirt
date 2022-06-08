/*
 * moment_conf.c: domain snapshot/checkpoint base class
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include <config.h>

#include <sys/time.h>

#include "internal.h"
#include "moment_conf.h"
#include "domain_conf.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.moment_conf");

static virClass *virDomainMomentDefClass;
static void virDomainMomentDefDispose(void *obj);

static int
virDomainMomentOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainMomentDef, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainMoment);

virClass *
virClassForDomainMomentDef(void)
{
    if (virDomainMomentInitialize() < 0)
        return NULL;

    return virDomainMomentDefClass;
}

static void
virDomainMomentDefDispose(void *obj)
{
    virDomainMomentDef *def = obj;

    g_free(def->name);
    g_free(def->description);
    g_free(def->parent_name);
    virDomainDefFree(def->dom);
    virDomainDefFree(def->inactiveDom);
}

/* Provide defaults for creation time and moment name after parsing XML */
int
virDomainMomentDefPostParse(virDomainMomentDef *def)
{
    def->creationTime = g_get_real_time() / (1000*1000);

    if (!def->name)
        def->name = g_strdup_printf("%lld", def->creationTime);

    return 0;
}
