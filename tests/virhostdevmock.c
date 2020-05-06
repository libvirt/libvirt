/*
 * Copyright (C) 2020 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include "virutil.h"

char *
virGetUserRuntimeDirectory(void)
{
    return g_build_filename(g_getenv("LIBVIRT_FAKE_ROOT_DIR"),
                            "user-runtime-directory", NULL);
}
