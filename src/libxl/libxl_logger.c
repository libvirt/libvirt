/*
 * libxl_logger.c: libxl logger implementation
 *
 * Copyright (c) 2016 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <libxl.h>

#include "internal.h"
#include "libxl_logger.h"
#include "util/viralloc.h"
#include "util/virfile.h"
#include "util/virhash.h"
#include "util/virthread.h"
#include "util/virtime.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_logger");

typedef struct xentoollog_logger_libvirt xentoollog_logger_libvirt;

struct xentoollog_logger_libvirt {
    xentoollog_logger vtable;
    xentoollog_level minLevel;
    const char *logDir;

    /* map storing the opened fds: "domid" -> FILE* */
    GHashTable *files;
    virMutex tableLock;
    FILE *defaultLogFile;
};

static void
libxlLoggerFileFree(void *payload)
{
    FILE *file = payload;
    VIR_FORCE_FCLOSE(file);
}

G_GNUC_PRINTF(5, 0) static void
libvirt_vmessage(xentoollog_logger *logger_in,
                 xentoollog_level level,
                 int errnoval,
                 const char *context,
                 const char *format,
                 va_list args)
{
    xentoollog_logger_libvirt *lg = (xentoollog_logger_libvirt *)logger_in;
    FILE *logFile = lg->defaultLogFile;
    char timestamp[VIR_TIME_STRING_BUFLEN];
    g_autofree char *message = NULL;
    char *start, *end;

    VIR_DEBUG("libvirt_vmessage: context='%s' format='%s'", context, format);

    if (level < lg->minLevel)
        return;

    message = g_strdup_vprintf(format, args);

    /* Should we print to a domain-specific log file? */
    if ((start = strstr(message, ": Domain ")) &&
        (end = strstr(start + 9, ":"))) {
        FILE *domainLogFile = NULL;

        VIR_DEBUG("Found domain log message");

        start = start + 9;
        *end = '\0';

        VIR_WITH_MUTEX_LOCK_GUARD(&lg->tableLock) {
            domainLogFile = virHashLookup(lg->files, start);
        }
        if (domainLogFile)
            logFile = domainLogFile;

        *end = ':';
    }

    /* Do the actual print to the log file */
    if (virTimeStringNowRaw(timestamp) < 0)
        timestamp[0] = '\0';

    fprintf(logFile, "%s: ", timestamp);
    if (context)
        fprintf(logFile, "%s: ", context);

    fprintf(logFile, "%s", message);

    if (errnoval >= 0)
        fprintf(logFile, ": %s", g_strerror(errnoval));

    fputc('\n', logFile);
    fflush(logFile);
}

static void
libvirt_progress(xentoollog_logger *logger_in G_GNUC_UNUSED,
                 const char *context G_GNUC_UNUSED,
                 const char *doingwhat G_GNUC_UNUSED,
                 int percent G_GNUC_UNUSED,
                 unsigned long done G_GNUC_UNUSED,
                 unsigned long total G_GNUC_UNUSED)
{
    /* This function purposedly does nothing: it's no logging info */
}

static void
libvirt_destroy(xentoollog_logger *logger_in)
{
    xentoollog_logger_libvirt *lg = (xentoollog_logger_libvirt*)logger_in;
    VIR_FREE(lg);
}


libxlLogger *
libxlLoggerNew(const char *logDir, virLogPriority minLevel)
{
    xentoollog_logger_libvirt logger;
    g_autofree char *path = NULL;

    switch (minLevel) {
    case VIR_LOG_DEBUG:
        logger.minLevel = XTL_DEBUG;
        break;
    case VIR_LOG_INFO:
        logger.minLevel = XTL_INFO;
        break;
    case VIR_LOG_WARN:
        logger.minLevel = XTL_WARN;
        break;
    case VIR_LOG_ERROR:
        logger.minLevel = XTL_ERROR;
        break;
    }
    logger.logDir = logDir;

    path = g_strdup_printf("%s/libxl-driver.log", logDir);

    if ((logger.defaultLogFile = fopen(path, "a")) == NULL)
        return NULL;

    if (virMutexInit(&logger.tableLock) < 0) {
        VIR_FORCE_FCLOSE(logger.defaultLogFile);
        return NULL;
    }

    logger.files = virHashNew(libxlLoggerFileFree);

    return XTL_NEW_LOGGER(libvirt, logger);
}

void
libxlLoggerFree(libxlLogger *logger)
{
    xentoollog_logger *xtl_logger = (xentoollog_logger*)logger;
    if (logger->defaultLogFile)
        VIR_FORCE_FCLOSE(logger->defaultLogFile);
    g_clear_pointer(&logger->files, g_hash_table_unref);
    virMutexDestroy(&logger->tableLock);
    xtl_logger_destroy(xtl_logger);
}

void
libxlLoggerOpenFile(libxlLogger *logger,
                    int id,
                    const char *name,
                    const char *domain_config)
{
    g_autofree char *path = NULL;
    FILE *logFile = NULL;
    g_autofree char *domidstr = NULL;

    path = g_strdup_printf("%s/%s.log", logger->logDir, name);
    domidstr = g_strdup_printf("%d", id);

    if (!(logFile = fopen(path, "a"))) {
        VIR_WARN("Failed to open log file %s: %s",
                 path, g_strerror(errno));
        return;
    }
    VIR_WITH_MUTEX_LOCK_GUARD(&logger->tableLock) {
        ignore_value(virHashAddEntry(logger->files, domidstr, logFile));
    }

    /* domain_config is non NULL only when starting a new domain */
    if (domain_config) {
        fprintf(logFile, "Domain start: %s\n", domain_config);
        fflush(logFile);
    }
}

void
libxlLoggerCloseFile(libxlLogger *logger, int id)
{
    g_autofree char *domidstr = g_strdup_printf("%d", id);
    VIR_LOCK_GUARD lock = virLockGuardLock(&logger->tableLock);

    ignore_value(virHashRemoveEntry(logger->files, domidstr));
}
