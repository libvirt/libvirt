/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Authors:
 *     James Morris <jmorris@namei.org>
 *
 */
#include <config.h>
#include <string.h>

#include "virterror_internal.h"

#include "security.h"
#ifdef WITH_SECDRIVER_SELINUX
#include "security_selinux.h"
#endif

static virSecurityDriverPtr security_drivers[] = {
#ifdef WITH_SECDRIVER_SELINUX
    &virSELinuxSecurityDriver,
#endif
    NULL
};

int
virSecurityDriverStartup(virSecurityDriverPtr *drv,
                         const char *name)
{
    unsigned int i;

    if (name && STREQ(name, "none"))
        return -2;

    for (i = 0; security_drivers[i] != NULL ; i++) {
        virSecurityDriverPtr tmp = security_drivers[i];

        if (name && STRNEQ(tmp->name, name))
            continue;

        switch (tmp->probe()) {
        case SECURITY_DRIVER_ENABLE:
            virSecurityDriverInit(tmp);
            if (tmp->open(NULL, tmp) == -1) {
                return -1;
            } else {
                *drv = tmp;
                return 0;
            }
            break;

        case SECURITY_DRIVER_DISABLE:
            break;

        default:
            return -1;
        }
    }
    return -2;
}

void
virSecurityReportError(virConnectPtr conn, int code, const char *fmt, ...)
{
    va_list args;
    char errorMessage[1024];

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage) - 1, fmt, args);
        va_end(args);
    } else
        errorMessage[0] = '\0';

    virRaiseError(conn, NULL, NULL, VIR_FROM_SECURITY, code,
                  VIR_ERR_ERROR, NULL, NULL, NULL, -1, -1, "%s",
                  errorMessage);
}

/*
 * Helpers
 */
void
virSecurityDriverInit(virSecurityDriverPtr drv)
{
    memset(&drv->_private, 0, sizeof drv->_private);
}

int
virSecurityDriverSetDOI(virConnectPtr conn,
                        virSecurityDriverPtr drv,
                        const char *doi)
{
    if (strlen(doi) >= VIR_SECURITY_DOI_BUFLEN) {
        virSecurityReportError(conn, VIR_ERR_ERROR,
                               _("%s: DOI \'%s\' is "
                               "longer than the maximum allowed length of %d"),
                               __func__, doi, VIR_SECURITY_DOI_BUFLEN - 1);
        return -1;
    }
    strcpy(drv->_private.doi, doi);
    return 0;
}

const char *
virSecurityDriverGetDOI(virSecurityDriverPtr drv)
{
    return drv->_private.doi;
}

const char *
virSecurityDriverGetModel(virSecurityDriverPtr drv)
{
    return drv->name;
}
