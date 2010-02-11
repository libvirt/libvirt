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

#include "security_driver.h"
#ifdef WITH_SECDRIVER_SELINUX
#include "security_selinux.h"
#endif

#ifdef WITH_SECDRIVER_APPARMOR
#include "security_apparmor.h"
#endif

static virSecurityDriverPtr security_drivers[] = {
#ifdef WITH_SECDRIVER_SELINUX
    &virSELinuxSecurityDriver,
#endif
#ifdef WITH_SECDRIVER_APPARMOR
    &virAppArmorSecurityDriver,
#endif
    NULL
};

int
virSecurityDriverVerify(virDomainDefPtr def)
{
    unsigned int i;
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (!secdef->model ||
        STREQ(secdef->model, "none"))
        return 0;

    for (i = 0; security_drivers[i] != NULL ; i++) {
        if (STREQ(security_drivers[i]->name, secdef->model)) {
            return security_drivers[i]->domainSecurityVerify(def);
        }
    }
    virSecurityReportError(VIR_ERR_XML_ERROR,
                           _("invalid security model '%s'"), secdef->model);
    return -1;
}

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
            if (tmp->open(tmp) == -1) {
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

/*
 * Helpers
 */
void
virSecurityDriverInit(virSecurityDriverPtr drv)
{
    memset(&drv->_private, 0, sizeof drv->_private);
}

int
virSecurityDriverSetDOI(virSecurityDriverPtr drv,
                        const char *doi)
{
    if (strlen(doi) >= VIR_SECURITY_DOI_BUFLEN) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
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
