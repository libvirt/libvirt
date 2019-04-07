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

#ifndef LIBVIRT_VIRLOG_H
# define LIBVIRT_VIRLOG_H

# include "internal.h"
# include "virbuffer.h"

# ifdef PACKAGER_VERSION
#  ifdef PACKAGER
#   define VIR_LOG_VERSION_STRING \
     "libvirt version: " VERSION ", package: " PACKAGER_VERSION " (" PACKAGER ")"
#  else
#   define VIR_LOG_VERSION_STRING \
     "libvirt version: " VERSION ", package: " PACKAGER_VERSION
#  endif
# else
#  define VIR_LOG_VERSION_STRING \
    "libvirt version: " VERSION
# endif

/*
 * To be made public
 */
typedef enum {
    VIR_LOG_DEBUG = 1,
    VIR_LOG_INFO,
    VIR_LOG_WARN,
    VIR_LOG_ERROR,
} virLogPriority;

# define VIR_LOG_DEFAULT VIR_LOG_WARN

typedef enum {
    VIR_LOG_TO_STDERR = 0,
    VIR_LOG_TO_SYSLOG,
    VIR_LOG_TO_FILE,
    VIR_LOG_TO_JOURNALD,
    VIR_LOG_TO_OUTPUT_LAST,
} virLogDestination;

typedef struct _virLogSource virLogSource;
typedef virLogSource *virLogSourcePtr;

struct _virLogSource {
    const char *name;
    unsigned int priority;
    unsigned int serial;
    unsigned int flags;
};

/*
 * ATTRIBUTE_UNUSED is to make gcc keep quiet if all the
 * log statements in a file are conditionally disabled
 * at compile time due to configure options.
 */
# define VIR_LOG_INIT(n) \
    static ATTRIBUTE_UNUSED virLogSource virLogSelf = { \
        .name = "" n "", \
        .priority = VIR_LOG_ERROR, \
        .serial = 0, \
        .flags = 0, \
    }

/*
 * If configured with --enable-debug=yes then library calls
 * are printed to stderr for debugging or to an appropriate channel
 * defined at runtime from the libvirt daemon configuration file
 */
# ifdef ENABLE_DEBUG
#  define VIR_DEBUG_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_DEBUG, filename, linenr, funcname, NULL, __VA_ARGS__)
# else
/**
 * virLogEatParams:
 *
 * Do nothing but eat parameters.
 */
static inline void virLogEatParams(virLogSourcePtr unused, ...)
{
    /* Silence gcc */
    unused = unused;
}
#  define VIR_DEBUG_INT(src, filename, linenr, funcname, ...) \
    virLogEatParams(src, filename, linenr, funcname, __VA_ARGS__)
# endif /* !ENABLE_DEBUG */

# define VIR_INFO_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_INFO, filename, linenr, funcname, NULL, __VA_ARGS__)
# define VIR_WARN_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_WARN, filename, linenr, funcname, NULL, __VA_ARGS__)
# define VIR_ERROR_INT(src, filename, linenr, funcname, ...) \
    virLogMessage(src, VIR_LOG_ERROR, filename, linenr, funcname, NULL, __VA_ARGS__)

# define VIR_DEBUG(...) \
    VIR_DEBUG_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)
# define VIR_INFO(...) \
    VIR_INFO_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)
# define VIR_WARN(...) \
    VIR_WARN_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)
# define VIR_ERROR(...) \
    VIR_ERROR_INT(&virLogSelf, __FILE__, __LINE__, __func__, __VA_ARGS__)


struct _virLogMetadata {
    const char *key;
    const char *s;              /* String value, or NULL to use "i" */
    int iv;
};

typedef struct _virLogMetadata virLogMetadata;
typedef struct _virLogMetadata *virLogMetadataPtr;

typedef struct _virLogOutput virLogOutput;
typedef virLogOutput *virLogOutputPtr;

typedef struct _virLogFilter virLogFilter;
typedef virLogFilter *virLogFilterPtr;

/**
 * virLogOutputFunc:
 * @src: the source of the log message
 * @priority: the priority for the message
 * @filename: file where the message was emitted
 * @linenr: line where the message was emitted
 * @funcname: the function emitting the message
 * @timestamp: zero terminated string with timestamp of the message
 * @metadata: NULL or metadata array, terminated by an item with NULL key
 * @flags: flags associated with the message
 * @rawstr: the unformatted message to log, zero terminated
 * @str: the message to log, preformatted and zero terminated
 * @data: extra output logging data
 *
 * Callback function used to output messages
 */
typedef void (*virLogOutputFunc) (virLogSourcePtr src,
                                  virLogPriority priority,
                                  const char *filename,
                                  int linenr,
                                  const char *funcname,
                                  const char *timestamp,
                                  virLogMetadataPtr metadata,
                                  unsigned int flags,
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

typedef enum {
    VIR_LOG_STACK_TRACE = (1 << 0),
} virLogFilterFlags;

int virLogGetNbFilters(void);
int virLogGetNbOutputs(void);
char *virLogGetFilters(void);
char *virLogGetOutputs(void);
virLogPriority virLogGetDefaultPriority(void);
int virLogSetDefaultPriority(virLogPriority priority);
void virLogSetFromEnv(void);
void virLogOutputFree(virLogOutputPtr output);
void virLogOutputListFree(virLogOutputPtr *list, int count);
void virLogFilterFree(virLogFilterPtr filter);
void virLogFilterListFree(virLogFilterPtr *list, int count);
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
void virLogMessage(virLogSourcePtr source,
                   virLogPriority priority,
                   const char *filename,
                   int linenr,
                   const char *funcname,
                   virLogMetadataPtr metadata,
                   const char *fmt, ...) ATTRIBUTE_FMT_PRINTF(7, 8);
void virLogVMessage(virLogSourcePtr source,
                    virLogPriority priority,
                    const char *filename,
                    int linenr,
                    const char *funcname,
                    virLogMetadataPtr metadata,
                    const char *fmt,
                    va_list vargs) ATTRIBUTE_FMT_PRINTF(7, 0);

bool virLogProbablyLogMessage(const char *str);
virLogOutputPtr virLogOutputNew(virLogOutputFunc f,
                                virLogCloseFunc c,
                                void *data,
                                virLogPriority priority,
                                virLogDestination dest,
                                const char *name) ATTRIBUTE_NONNULL(1);
virLogFilterPtr virLogFilterNew(const char *match,
                                virLogPriority priority,
                                unsigned int flags) ATTRIBUTE_NONNULL(1);
int virLogFindOutput(virLogOutputPtr *outputs, size_t noutputs,
                     virLogDestination dest, const void *opaque);
int virLogDefineOutputs(virLogOutputPtr *outputs,
                        size_t noutputs) ATTRIBUTE_NONNULL(1);
int virLogDefineFilters(virLogFilterPtr *filters, size_t nfilters);
virLogOutputPtr virLogParseOutput(const char *src) ATTRIBUTE_NONNULL(1);
virLogFilterPtr virLogParseFilter(const char *src) ATTRIBUTE_NONNULL(1);
int virLogParseOutputs(const char *src,
                       virLogOutputPtr **outputs) ATTRIBUTE_NONNULL(1);
int virLogParseFilters(const char *src,
                       virLogFilterPtr **filters) ATTRIBUTE_NONNULL(1);

#endif /* LIBVIRT_VIRLOG_H */
