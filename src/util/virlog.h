/*
 * virlog.h: internal logging and debugging
 *
 * Copyright (C) 2006-2008, 2011-2012 Red Hat, Inc.
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
 *
 */

#pragma once

#include "internal.h"

#ifdef PACKAGER_VERSION
# ifdef PACKAGER
#  define VIR_LOG_VERSION_STRING \
    "libvirt version: " VERSION ", package: " PACKAGER_VERSION " (" PACKAGER ")"
# else
#  define VIR_LOG_VERSION_STRING \
    "libvirt version: " VERSION ", package: " PACKAGER_VERSION
# endif
#else
# define VIR_LOG_VERSION_STRING \
    "libvirt version: " VERSION
#endif

/*
 * To be made public
 */
typedef enum {
    VIR_LOG_DEBUG = 1,
    VIR_LOG_INFO,
    VIR_LOG_WARN,
    VIR_LOG_ERROR,
} virLogPriority;

#define VIR_LOG_DEFAULT VIR_LOG_WARN

typedef enum {
    VIR_LOG_TO_STDERR = 0,
    VIR_LOG_TO_SYSLOG,
    VIR_LOG_TO_FILE,
    VIR_LOG_TO_JOURNALD,
    VIR_LOG_TO_OUTPUT_LAST,
} virLogDestination;

typedef struct _virLogSource virLogSource;
struct _virLogSource {
    const char *name;
    unsigned int priority;
    unsigned int serial;
};

/*
 * G_GNUC_UNUSED is to make gcc keep quiet if all the
 * log statements in a file are conditionally disabled
 * at compile time due to configure options.
 */
#define VIR_LOG_INIT(n) \
    static G_GNUC_UNUSED virLogSource virLogSelf = { \
        .name = "" n "", \
        .priority = VIR_LOG_ERROR, \
        .serial = 0, \
    }

#define VIR_DEBUG_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_DEBUG, filename, linenr, funcname, NULL, __VA_ARGS__)
#define VIR_INFO_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_INFO, filename, linenr, funcname, NULL, __VA_ARGS__)
#define VIR_WARN_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_WARN, filename, linenr, funcname, NULL, __VA_ARGS__)
#define VIR_ERROR_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_ERROR, filename, linenr, funcname, NULL, __VA_ARGS__)

#define VIR_DEBUG(...) \
    VIR_DEBUG_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define VIR_INFO(...) \
    VIR_INFO_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define VIR_WARN(...) \
    VIR_WARN_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define VIR_ERROR(...) \
    VIR_ERROR_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)


struct _virLogMetadata {
    const char *key;
    const char *s;              /* String value, or NULL to use "i" */
    int iv;
};

typedef struct _virLogMetadata virLogMetadata;

typedef struct _virLogOutput virLogOutput;

typedef struct _virLogFilter virLogFilter;

/**
 * virLogOutputFunc:
 * @src: the source of the log message
 * @priority: the priority for the message
 * @filename: file where the message was emitted
 * @linenr: line where the message was emitted
 * @funcname: the function emitting the message
 * @timestamp: zero terminated string with timestamp of the message
 * @metadata: NULL or metadata array, terminated by an item with NULL key
 * @rawstr: the unformatted message to log, zero terminated
 * @str: the message to log, preformatted and zero terminated
 * @data: extra output logging data
 *
 * Callback function used to output messages
 */
typedef void (*virLogOutputFunc) (virLogSource *src,
                                  virLogPriority priority,
                                  const char *filename,
                                  int linenr,
                                  const char *funcname,
                                  const char *timestamp,
                                  struct _virLogMetadata *metadata,
                                  const char *rawstr,
                                  const char *str,
                                  void *data);

/**
 * virLogCloseFunc:
 * @data: extra output logging data
 *
 * Callback function used to close a log output
 */
typedef void (*virLogCloseFunc) (void *data);

int virLogGetNbFilters(void);
int virLogGetNbOutputs(void);
char *virLogGetFilters(void);
char *virLogGetOutputs(void);
virLogPriority virLogGetDefaultPriority(void);
int virLogSetDefaultPriority(virLogPriority priority);
int virLogSetFromEnv(void) G_GNUC_WARN_UNUSED_RESULT;
void virLogOutputFree(virLogOutput *output);
void virLogOutputListFree(virLogOutput **list, int count);
void virLogFilterFree(virLogFilter *filter);
void virLogFilterListFree(virLogFilter **list, int count);
int virLogSetOutputs(const char *outputs);
int virLogSetFilters(const char *filters);
char *virLogGetDefaultOutput(void);
int virLogSetDefaultOutput(const char *fname, bool godaemon, bool privileged);

/*
 * Internal logging API
 */

void virLogLock(void);
void virLogUnlock(void);
int virLogReset(void);
int virLogParseDefaultPriority(const char *priority);
int virLogPriorityFromSyslog(int priority);
void virLogMessage(virLogSource *source,
                   virLogPriority priority,
                   const char *filename,
                   int linenr,
                   const char *funcname,
                   struct _virLogMetadata *metadata,
                   const char *fmt, ...) G_GNUC_PRINTF(7, 8);

bool virLogProbablyLogMessage(const char *str);
virLogOutput *virLogOutputNew(virLogOutputFunc f,
                                virLogCloseFunc c,
                                void *data,
                                virLogPriority priority,
                                virLogDestination dest,
                                const char *name) ATTRIBUTE_NONNULL(1);
virLogFilter *virLogFilterNew(const char *match,
                                virLogPriority priority) ATTRIBUTE_NONNULL(1);
int virLogFindOutput(virLogOutput **outputs, size_t noutputs,
                     virLogDestination dest, const void *opaque);
int virLogDefineOutputs(virLogOutput **outputs,
                        size_t noutputs) ATTRIBUTE_NONNULL(1);
int virLogDefineFilters(virLogFilter **filters, size_t nfilters);
virLogOutput *virLogParseOutput(const char *src) ATTRIBUTE_NONNULL(1);
virLogFilter *virLogParseFilter(const char *src) ATTRIBUTE_NONNULL(1);
int virLogParseOutputs(const char *src,
                       virLogOutput ***outputs) ATTRIBUTE_NONNULL(1);
int virLogParseFilters(const char *src,
                       virLogFilter ***filters) ATTRIBUTE_NONNULL(1);
