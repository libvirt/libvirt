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
#include "logging.h"

#include "security_driver.h"
#ifdef WITH_SECDRIVER_SELINUX
# include "security_selinux.h"
#endif

#ifdef WITH_SECDRIVER_APPARMOR
# include "security_apparmor.h"
#endif

#include "security_nop.h"

static virSecurityDriverPtr security_drivers[] = {
#ifdef WITH_SECDRIVER_SELINUX
    &virSecurityDriverSELinux,
#endif
#ifdef WITH_SECDRIVER_APPARMOR
    &virAppArmorSecurityDriver,
#endif
    &virSecurityDriverNop, /* Must always be last, since it will always probe */
};

virSecurityDriverPtr virSecurityDriverLookup(const char *name)
{
    virSecurityDriverPtr drv = NULL;
    int i;

    VIR_DEBUG("name=%s", NULLSTR(name));

    for (i = 0; i < ARRAY_CARDINALITY(security_drivers) && !drv ; i++) {
        virSecurityDriverPtr tmp = security_drivers[i];

        if (name &&
            STRNEQ(tmp->name, name))
            continue;

        switch (tmp->probe()) {
        case SECURITY_DRIVER_ENABLE:
            VIR_DEBUG("Probed name=%s", tmp->name);
            drv = tmp;
            break;

        case SECURITY_DRIVER_DISABLE:
            VIR_DEBUG("Not enabled name=%s", tmp->name);
            break;

        default:
            return NULL;
        }
    }

    if (!drv) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Security driver %s not found"),
                               NULLSTR(name));
        return NULL;
    }

    return drv;
}
