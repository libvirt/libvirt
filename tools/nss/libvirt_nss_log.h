/*
 * libvirt_nss_log: Logging for Name Service Switch plugin
 *
 * Copyright (C) 2025 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

typedef enum {
    NSS_DEBUG,
    NSS_ERROR,
} nssLogPriority;

#define DEBUG(...) \
    nssLog(NSS_DEBUG, __FUNCTION__, __LINE__, __VA_ARGS__)

#define ERROR(...) \
    nssLog(NSS_ERROR, __FUNCTION__, __LINE__, __VA_ARGS__)

void
nssLog(nssLogPriority prio,
       const char *func,
       int linenr,
       const char *fmt, ...) __attribute__ ((format(printf, 4, 5)));
