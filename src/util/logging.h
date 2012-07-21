/*
 * logging.h: internal logging and debugging
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __VIRTLOG_H_
# define __VIRTLOG_H_

# include "internal.h"
# include "buf.h"

/*
 * If configured with --enable-debug=yes then library calls
 * are printed to stderr for debugging or to an appropriate channel
 * defined at runtime from the libvirt daemon configuration file
 */
# ifdef ENABLE_DEBUG
#  define VIR_DEBUG_INT(category, f, l, ...)                            \
    virLogMessage(category, VIR_LOG_DEBUG, f, l, 0, __VA_ARGS__)
# else
/**
 * virLogEatParams:
 *
 * Do nothing but eat parameters.
 */
static inline void virLogEatParams(const char *unused, ...)
{
    /* Silence gcc */
    unused = unused;
}
#  define VIR_DEBUG_INT(category, f, l, ...)    \
    virLogEatParams(category, f, l, __VA_ARGS__)
# endif /* !ENABLE_DEBUG */

# define VIR_INFO_INT(category, f, l, ...)                              \
    virLogMessage(category, VIR_LOG_INFO, f, l, 0, __VA_ARGS__)
# define VIR_WARN_INT(category, f, l, ...)                              \
    virLogMessage(category, VIR_LOG_WARN, f, l, 0, __VA_ARGS__)
# define VIR_ERROR_INT(category, f, l, ...)                             \
    virLogMessage(category, VIR_LOG_ERROR, f, l, 0, __VA_ARGS__)

# define VIR_DEBUG(...)                                                 \
        VIR_DEBUG_INT("file." __FILE__, __func__, __LINE__, __VA_ARGS__)
# define VIR_INFO(...)                                                  \
        VIR_INFO_INT("file." __FILE__, __func__, __LINE__, __VA_ARGS__)
# define VIR_WARN(...)                                                  \
        VIR_WARN_INT("file." __FILE__, __func__, __LINE__, __VA_ARGS__)
# define VIR_ERROR(...)                                                 \
        VIR_ERROR_INT("file." __FILE__, __func__, __LINE__, __VA_ARGS__)

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
    VIR_LOG_TO_STDERR = 1,
    VIR_LOG_TO_SYSLOG,
    VIR_LOG_TO_FILE,
} virLogDestination;

/**
 * virLogOutputFunc:
 * @category: the category for the message
 * @priority: the priority for the message
 * @funcname: the function emitting the message
 * @linenr: line where the message was emitted
 * @timestamp: zero terminated string with timestamp of the message
 * @flags: flags associated with the message
 * @str: the message to log, preformatted and zero terminated
 * @data: extra output logging data
 *
 * Callback function used to output messages
 *
 * Returns the number of bytes written or -1 in case of error
 */
typedef int (*virLogOutputFunc) (const char *category, int priority,
                                 const char *funcname, long long linenr,
                                 const char *timestamp,
                                 unsigned int flags,
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
} virLogFlags;

extern int virLogGetNbFilters(void);
extern int virLogGetNbOutputs(void);
extern char *virLogGetFilters(void);
extern char *virLogGetOutputs(void);
extern int virLogGetDefaultPriority(void);
extern int virLogSetDefaultPriority(int priority);
extern void virLogSetFromEnv(void);
extern int virLogDefineFilter(const char *match, int priority,
                              unsigned int flags);
extern int virLogDefineOutput(virLogOutputFunc f, virLogCloseFunc c, void *data,
                              int priority, int dest, const char *name,
                              unsigned int flags);

/*
 * Internal logging API
 */

extern void virLogLock(void);
extern void virLogUnlock(void);
extern int virLogStartup(void);
extern int virLogReset(void);
extern void virLogShutdown(void);
extern int virLogParseDefaultPriority(const char *priority);
extern int virLogParseFilters(const char *filters);
extern int virLogParseOutputs(const char *output);
extern void virLogMessage(const char *category, int priority,
                          const char *funcname, long long linenr,
                          unsigned int flags,
                          const char *fmt, ...) ATTRIBUTE_FMT_PRINTF(6, 7);
extern void virLogVMessage(const char *category, int priority,
                           const char *funcname, long long linenr,
                           unsigned int flags,
                           const char *fmt,
                           va_list vargs) ATTRIBUTE_FMT_PRINTF(6, 0);
extern int virLogSetBufferSize(int size);
extern void virLogEmergencyDumpAll(int signum);
#endif
