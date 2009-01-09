/*
 * logging.h: internal logging and debugging
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __VIRTLOG_H_
#define __VIRTLOG_H_

#include "internal.h"

/*
 * If configured with --enable-debug=yes then library calls
 * are printed to stderr for debugging or to an appropriate channel
 * defined at runtime of from the libvirt daemon configuration file
 */
#ifdef ENABLE_DEBUG
#define VIR_DEBUG_INT(category, f, l, fmt,...)                             \
    virLogMessage(category, VIR_LOG_DEBUG, f, l, 0, fmt, __VA_ARGS__)
#define VIR_INFO_INT(category, f, l, fmt,...)                              \
    virLogMessage(category, VIR_LOG_INFO, f, l, 0, fmt, __VA_ARGS__)
#define VIR_WARN_INT(category, f, l, fmt,...)                              \
    virLogMessage(category, VIR_LOG_WARN, f, l, 0, fmt, __VA_ARGS__)
#define VIR_ERROR_INT(category, f, l, fmt,...)                             \
    virLogMessage(category, VIR_LOG_ERROR, f, l, 0, fmt, __VA_ARGS__)
#else
#define VIR_DEBUG_INT(category, f, l, fmt,...) \
    do { } while (0)
#define VIR_INFO_INT(category, f, l, fmt,...) \
    do { } while (0)
#define VIR_WARN_INT(category, f, l, fmt,...) \
    do { } while (0)
#define VIR_ERROR_INT(category, f, l, fmt,...) \
    do { } while (0)
#endif /* !ENABLE_DEBUG */

#define VIR_DEBUG(fmt,...)                                                  \
        VIR_DEBUG_INT("file." __FILE__, __func__, __LINE__, fmt, __VA_ARGS__)
#define VIR_DEBUG0(msg)                                                     \
        VIR_DEBUG_INT("file." __FILE__, __func__, __LINE__, "%s", msg)
#define VIR_INFO(fmt,...)                                                   \
        VIR_INFO_INT("file." __FILE__, __func__, __LINE__, fmt, __VA_ARGS__)
#define VIR_INFO0(msg)                                                      \
        VIR_INFO_INT("file." __FILE__, __func__, __LINE__, "%s", msg)
#define VIR_WARN(fmt,...)                                                   \
        VIR_WARN_INT("file." __FILE__, __func__, __LINE__, fmt, __VA_ARGS__)
#define VIR_WARN0(msg)                                                      \
        VIR_WARN_INT("file." __FILE__, __func__, __LINE__, "%s", msg)
#define VIR_ERROR(fmt,...)                                                  \
        VIR_ERROR_INT("file." __FILE__, __func__, __LINE__, fmt, __VA_ARGS__)
#define VIR_ERROR0(msg)                                                     \
        VIR_ERROR_INT("file." __FILE__, __func__, __LINE__, "%s", msg)

/* Legacy compat */
#define DEBUG(fmt,...)                                                  \
        VIR_DEBUG_INT("file." __FILE__, __func__, __LINE__, fmt, __VA_ARGS__)
#define DEBUG0(msg)                                                     \
        VIR_DEBUG_INT("file." __FILE__, __func__, __LINE__, "%s", msg)

/*
 * To be made public
 */
typedef enum {
    VIR_LOG_DEBUG = 1,
    VIR_LOG_INFO,
    VIR_LOG_WARN,
    VIR_LOG_ERROR,
} virLogPriority;

/**
 * virLogOutputFunc:
 * @category: the category for the message
 * @priority: the priority for the message
 * @funcname: the function emitting the message
 * @linenr: line where the message was emitted
 * @msg: the message to log, preformatted and zero terminated
 * @len: the lenght of the message in bytes without the terminating zero
 * @data: extra output logging data
 *
 * Callback function used to output messages
 *
 * Returns the number of bytes written or -1 in case of error
 */
typedef int (*virLogOutputFunc) (const char *category, int priority,
                                 const char *funcname, long long lineno,
                                 const char *str, int len, void *data);

/**
 * virLogCloseFunc:
 * @data: extra output logging data
 *
 * Callback function used to close a log output
 */
typedef void (*virLogCloseFunc) (void *data);

#ifdef ENABLE_DEBUG

extern int virLogSetDefaultPriority(int priority);
extern int virLogDefineFilter(const char *match, int priority, int flags);
extern int virLogDefineOutput(virLogOutputFunc f, virLogCloseFunc c,
                              void *data, int priority, int flags);

/*
 * Internal logging API
 */

extern int virLogStartup(void);
extern int virLogReset(void);
extern void virLogShutdown(void);
extern int virLogParseFilters(const char *filters);
extern int virLogParseOutputs(const char *output);
extern void virLogMessage(const char *category, int priority,
                          const char *funcname, long long linenr, int flags,
                          const char *fmt, ...) ATTRIBUTE_FORMAT(printf, 6, 7);

#else /* ENABLE_DEBUG */

#define virLogSetDefaultPriority(p)
#define virLogDefineFilter(m, p, f)
#define virLogDefineOutput(func, c, d, p, f)
#define virLogStartup()
#define virLogReset()
#define virLogShutdown()
#define virLogParseFilters(f)
#define virLogParseOutputs(o)
#define virLogMessage(c, p, func, l, f, fmt, __VA_ARGS__)

#endif /* ENABLE_DEBUG */

#endif
