/*
 * Copyright (C) 2022 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include "internal.h"
#include "virfile.h"

char *
virFindFileInPath(const char *file)
{
    if (STREQ_NULLABLE(file, "dnsmasq"))
        return g_strdup("/usr/sbin/dnsmasq");

    /* We should not need any other binaries so return NULL. */
    return NULL;
}
