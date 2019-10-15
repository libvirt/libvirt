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
#include "util/virerror.h"
#include "util/virfile.h"
#include "util/virhash.h"
#include "util/virstring.h"
#include "util/virtime.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_logger");

typedef struct xentoollog_logger_libvirt xentoollog_logger_libvirt;

struct xentoollog_logger_libvirt {
    xentoollog_logger vtable;
    xentoollog_level minLevel;
    const char *logDir;

    /* map storing the opened fds: "domid" -> FILE* */
    virHashTablePtr files;
    FILE *defaultLogFile;
};

static void
libxlLoggerFileFree(void *payload, const void *key G_GNUC_UNUSED)
{
    FILE *file = payload;
    VIR_FORCE_FCLOSE(file);
    file = NULL;
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
    char *message = NULL;
    char *start, *end;
    char ebuf[1024];

    VIR_DEBUG("libvirt_vmessage: context='%s' format='%s'", context, format);

    if (level < lg->minLevel)
        return;

    if (virVasprintf(&message, format, args) < 0)
        return;

    /* Should we print to a domain-specific log file? */
    if ((start = strstr(message, ": Domain ")) &&
        (end = strstr(start + 9, ":"))) {
        FILE *domainLogFile;

        VIR_DEBUG("Found domain log message");

        start = start + 9;
        *end = '\0';

        domainLogFile = virHashLookup(lg->files, start);
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
        fprintf(logFile, ": %s", virStrerror(errnoval, ebuf, sizeof(ebuf)));

    fputc('\n', logFile);
    fflush(logFile);

    VIR_FREE(message);
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


libxlLoggerPtr
libxlLoggerNew(const char *logDir, virLogPriority minLevel)
{
    xentoollog_logger_libvirt logger;
    libxlLoggerPtr logger_out = NULL;
    char *path = NULL;

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

    if ((logger.files = virHashCreate(3, libxlLoggerFileFree)) == NULL)
        return NULL;

    if (virAsprintf(&path, "%s/libxl-driver.log", logDir) < 0)
        goto error;

    if ((logger.defaultLogFile = fopen(path, "a")) == NULL)
        goto error;

    logger_out = XTL_NEW_LOGGER(libvirt, logger);

 cleanup:
    VIR_FREE(path);
    return logger_out;

 error:
    virHashFree(logger.files);
    goto cleanup;
}

void
libxlLoggerFree(libxlLoggerPtr logger)
{
    xentoollog_logger *xtl_logger = (xentoollog_logger*)logger;
    if (logger->defaultLogFile)
        VIR_FORCE_FCLOSE(logger->defaultLogFile);
    virHashFree(logger->files);
    xtl_logger_destroy(xtl_logger);
}

void
libxlLoggerOpenFile(libxlLoggerPtr logger,
                    int id,
                    const char *name,
                    const char *domain_config)
{
    char *path = NULL;
    FILE *logFile = NULL;
    char *domidstr = NULL;
    char ebuf[1024];

    if (virAsprintf(&path, "%s/%s.log", logger->logDir, name) < 0 ||
        virAsprintf(&domidstr, "%d", id) < 0)
        goto cleanup;

    if (!(logFile = fopen(path, "a"))) {
        VIR_WARN("Failed to open log file %s: %s",
                 path, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto cleanup;
    }
    ignore_value(virHashAddEntry(logger->files, domidstr, logFile));

    /* domain_config is non NULL only when starting a new domain */
    if (domain_config) {
        fprintf(logFile, "Domain start: %s\n", domain_config);
        fflush(logFile);
    }

 cleanup:
    VIR_FREE(path);
    VIR_FREE(domidstr);
}

void
libxlLoggerCloseFile(libxlLoggerPtr logger, int id)
{
    char *domidstr = NULL;
    if (virAsprintf(&domidstr, "%d", id) < 0)
        return;

    ignore_value(virHashRemoveEntry(logger->files, domidstr));

    VIR_FREE(domidstr);
}
