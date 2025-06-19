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
    nssLog(NSS_DEBUG, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define ERROR(...) \
    nssLog(NSS_ERROR, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define NSS_LOG_ENV_VAR "LIBVIRT_NSS_DEBUG"

void
nssLog(nssLogPriority prio,
       const char *filename,
       const char *func,
       int linenr,
       const char *fmt, ...) __attribute__ ((format(printf, 5, 6)));
