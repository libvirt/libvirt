/*
 * vz_utils.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2012 Parallels, Inc.
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
 * License along with this library; If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <stdarg.h>

#include "vircommand.h"
#include "virerror.h"
#include "viralloc.h"
#include "virjson.h"
#include "vz_utils.h"
#include "vz_sdk.h"
#include "virstring.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

/**
 * vzDomObjFromDomain:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be unlocked by virObjectUnlock().
 *
 * Returns the domain object without incremented reference counter which is locked
 * on success, NULL otherwise.
 */
virDomainObjPtr
vzDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    vzConnPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;

}

/**
 * vzDomObjFromDomainRef:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be released by calling virDomainObjEndAPI().
 *
 * Returns the domain object with incremented reference counter which is locked
 * on success, NULL otherwise.
 */
virDomainObjPtr
vzDomObjFromDomainRef(virDomainPtr domain)
{
    virDomainObjPtr vm;
    vzConnPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUIDRef(privconn->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

static int
vzDoCmdRun(char **outbuf, const char *binary, va_list list)
{
    virCommandPtr cmd = virCommandNewVAList(binary, list);
    int ret = -1;

    if (outbuf)
        virCommandSetOutputBuffer(cmd, outbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    if (ret && outbuf)
        VIR_FREE(*outbuf);
    return ret;
}

/*
 * Run command and return its output, pointer to
 * buffer or NULL in case of error. Caller os responsible
 * for freeing the buffer.
 */
char *
vzGetOutput(const char *binary, ...)
{
    char *outbuf;
    va_list list;
    int ret;

    va_start(list, binary);
    ret = vzDoCmdRun(&outbuf, binary, list);
    va_end(list);
    if (ret)
        return NULL;

    return outbuf;
}

virDomainObjPtr
vzNewDomain(vzConnPtr privconn, char *name, const unsigned char *uuid)
{
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom = NULL;
    vzDomObjPtr pdom = NULL;

    if (!(def = virDomainDefNewFull(name, uuid, -1)))
        goto error;

    if (VIR_ALLOC(pdom) < 0)
        goto error;

    if (virCondInit(&pdom->cache.cond) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("cannot initialize condition"));
        goto error;
    }
    pdom->cache.stats = PRL_INVALID_HANDLE;
    pdom->cache.count = -1;

    if (STREQ(privconn->drivername, "vz"))
        def->virtType = VIR_DOMAIN_VIRT_VZ;
    else
        def->virtType = VIR_DOMAIN_VIRT_PARALLELS;

    if (!(dom = virDomainObjListAdd(privconn->domains, def,
                                    privconn->xmlopt,
                                    0, NULL)))
        goto error;

    dom->privateData = pdom;
    dom->privateDataFreeFunc = prlsdkDomObjFreePrivate;
    dom->persistent = 1;
    return dom;

 error:
    if (pdom && pdom->cache.count == -1)
        virCondDestroy(&pdom->cache.cond);
    virDomainDefFree(def);
    VIR_FREE(pdom);
    return NULL;
}
