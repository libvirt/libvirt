/*
 * virlog.c: internal logging and debugging
 *
 * Copyright (C) 2008, 2010-2014 Red Hat, Inc.
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

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>
#include <regex.h>
#if HAVE_SYSLOG_H
# include <syslog.h>
#endif
#include <sys/socket.h>
#if HAVE_SYS_UN_H
# include <sys/un.h>
#endif

#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "virutil.h"
#include "virbuffer.h"
#include "virthread.h"
#include "virfile.h"
#include "virtime.h"
#include "intprops.h"
#include "virstring.h"
#include "configmake.h"

/* Journald output is only supported on Linux new enough to expose
 * htole64.  */
#if HAVE_SYSLOG_H && defined(__linux__) && HAVE_DECL_HTOLE64
# define USE_JOURNALD 1
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.log");

static regex_t *virLogRegex;


#define VIR_LOG_DATE_REGEX "[0-9]{4}-[0-9]{2}-[0-9]{2}"
#define VIR_LOG_TIME_REGEX "[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}\\+[0-9]{4}"
#define VIR_LOG_PID_REGEX "[0-9]+"
#define VIR_LOG_LEVEL_REGEX "(debug|info|warning|error)"

#define VIR_LOG_REGEX \
    VIR_LOG_DATE_REGEX " " VIR_LOG_TIME_REGEX ": " \
    VIR_LOG_PID_REGEX ": " VIR_LOG_LEVEL_REGEX " : "

VIR_ENUM_DECL(virLogDestination);
VIR_ENUM_IMPL(virLogDestination, VIR_LOG_TO_OUTPUT_LAST,
              "stderr", "syslog", "file", "journald");

/*
 * Filters are used to refine the rules on what to keep or drop
 * based on a matching pattern (currently a substring)
 */
struct _virLogFilter {
    char *match;
    virLogPriority priority;
    unsigned int flags;
};

static int virLogFiltersSerial = 1;
static virLogFilterPtr *virLogFilters;
static size_t virLogNbFilters;

/*
 * Outputs are used to emit the messages retained
 * after filtering, multiple output can be used simultaneously
 */
struct _virLogOutput {
    bool logInitMessage;
    void *data;
    virLogOutputFunc f;
    virLogCloseFunc c;
    virLogPriority priority;
    virLogDestination dest;
    char *name;
};

static char *virLogDefaultOutput;
static virLogOutputPtr *virLogOutputs;
static size_t virLogNbOutputs;

/*
 * Default priorities
 */
static virLogPriority virLogDefaultPriority = VIR_LOG_DEFAULT;

static void virLogResetFilters(void);
static void virLogResetOutputs(void);
static void virLogOutputToFd(virLogSourcePtr src,
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


/*
 * Logs accesses must be serialized though a mutex
 */
virMutex virLogMutex;

void
virLogLock(void)
{
    virMutexLock(&virLogMutex);
}


void
virLogUnlock(void)
{
    virMutexUnlock(&virLogMutex);
}


static int
virLogSetDefaultOutputToStderr(void)
{
    return virAsprintf(&virLogDefaultOutput, "%d:stderr",
                       virLogDefaultPriority);
}


static int
virLogSetDefaultOutputToJournald(void)
{
    virLogPriority priority = virLogDefaultPriority;

    /* By default we don't want to log too much stuff into journald as
     * it may employ rate limiting and thus block libvirt execution. */
    if (priority == VIR_LOG_DEBUG)
        priority = VIR_LOG_INFO;

    return virAsprintf(&virLogDefaultOutput, "%d:journald", priority);
}


static int
virLogSetDefaultOutputToFile(const char *filename, bool privileged)
{
    int ret = -1;
    char *logdir = NULL;
    mode_t old_umask;

    if (privileged) {
        if (virAsprintf(&virLogDefaultOutput,
                        "%d:file:%s/log/libvirt/%s", virLogDefaultPriority,
                        LOCALSTATEDIR, filename) < 0)
            goto cleanup;
    } else {
        if (!(logdir = virGetUserCacheDirectory()))
            goto cleanup;

        old_umask = umask(077);
        if (virFileMakePath(logdir) < 0) {
            umask(old_umask);
            goto cleanup;
        }
        umask(old_umask);

        if (virAsprintf(&virLogDefaultOutput, "%d:file:%s/%s",
                        virLogDefaultPriority, logdir, filename) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(logdir);
    return ret;
}


/*
 * virLogSetDefaultOutput:
 * @filename: the file that the output should be redirected to (only needed
 *            when @godaemon equals true
 * @godaemon: whether we're running daemonized
 * @privileged: whether we're running with root privileges or not (session)
 *
 * Decides on what the default output (journald, file, stderr) should be
 * according to @filename, @godaemon, @privileged. This function should be run
 * exactly once at daemon startup, so no locks are used.
 *
 * Returns 0 on success, -1 in case of a failure.
 */
int
virLogSetDefaultOutput(const char *filename, bool godaemon, bool privileged)
{
    if (!godaemon)
        return virLogSetDefaultOutputToStderr();

    if (access("/run/systemd/journal/socket", W_OK) >= 0)
        return virLogSetDefaultOutputToJournald();

    return virLogSetDefaultOutputToFile(filename, privileged);
}


char *
virLogGetDefaultOutput(void)
{
    return virLogDefaultOutput;
}


static const char *
virLogPriorityString(virLogPriority lvl)
{
    switch (lvl) {
    case VIR_LOG_DEBUG:
        return "debug";
    case VIR_LOG_INFO:
        return "info";
    case VIR_LOG_WARN:
        return "warning";
    case VIR_LOG_ERROR:
        return "error";
    }
    return "unknown";
}


static int
virLogOnceInit(void)
{
    if (virMutexInit(&virLogMutex) < 0)
        return -1;

    virLogLock();
    virLogDefaultPriority = VIR_LOG_DEFAULT;

    if (VIR_ALLOC_QUIET(virLogRegex) >= 0) {
        if (regcomp(virLogRegex, VIR_LOG_REGEX, REG_EXTENDED) != 0)
            VIR_FREE(virLogRegex);
    }

    virLogUnlock();
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLog)


/**
 * virLogReset:
 *
 * Reset the logging module to its default initial state
 *
 * Returns 0 if successful, and -1 in case or error
 */
int
virLogReset(void)
{
    if (virLogInitialize() < 0)
        return -1;

    virLogLock();
    virLogResetFilters();
    virLogResetOutputs();
    virLogDefaultPriority = VIR_LOG_DEFAULT;
    virLogUnlock();
    return 0;
}

/**
 * virLogSetDefaultPriority:
 * @priority: the default priority level
 *
 * Set the default priority level, i.e. any logged data of a priority
 * equal or superior to this level will be logged, unless a specific rule
 * was defined for the log category of the message.
 *
 * Returns 0 if successful, -1 in case of error.
 */
int
virLogSetDefaultPriority(virLogPriority priority)
{
    if ((priority < VIR_LOG_DEBUG) || (priority > VIR_LOG_ERROR)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Failed to set logging priority, argument '%u' is "
                         "invalid"), priority);
        return -1;
    }
    if (virLogInitialize() < 0)
        return -1;

    virLogDefaultPriority = priority;
    return 0;
}


/**
 * virLogResetFilters:
 *
 * Removes the set of logging filters defined.
 */
static void
virLogResetFilters(void)
{
    virLogFilterListFree(virLogFilters, virLogNbFilters);
    virLogFilters = NULL;
    virLogNbFilters = 0;
    virLogFiltersSerial++;
}


void
virLogFilterFree(virLogFilterPtr filter)
{
    if (!filter)
        return;

    VIR_FREE(filter->match);
    VIR_FREE(filter);
}


/**
 * virLogFilterFreeList:
 * @list: list of filters to be freed
 * @count: number of elements in the list
 *
 * Frees a list of filters.
 */
void
virLogFilterListFree(virLogFilterPtr *list, int count)
{
    size_t i;

    if (!list || count < 0)
        return;

    for (i = 0; i < count; i++)
        virLogFilterFree(list[i]);
    VIR_FREE(list);
}


/**
 * virLogResetOutputs:
 *
 * Removes the set of logging output defined.
 */
static void
virLogResetOutputs(void)
{
    virLogOutputListFree(virLogOutputs, virLogNbOutputs);
    virLogOutputs = NULL;
    virLogNbOutputs = 0;
}


void
virLogOutputFree(virLogOutputPtr output)
{
    if (!output)
        return;

    if (output->c)
        output->c(output->data);
    VIR_FREE(output->name);
    VIR_FREE(output);

}


/**
 * virLogOutputsFreeList:
 * @list: list of outputs to be freed
 * @count: number of elements in the list
 *
 * Frees a list of outputs.
 */
void
virLogOutputListFree(virLogOutputPtr *list, int count)
{
    size_t i;

    if (!list || count < 0)
        return;

    for (i = 0; i < count; i++)
        virLogOutputFree(list[i]);
    VIR_FREE(list);
}


static int
virLogFormatString(char **msg,
                   int linenr,
                   const char *funcname,
                   virLogPriority priority,
                   const char *str)
{
    int ret;

    /*
     * Be careful when changing the following log message formatting, we rely
     * on it when stripping libvirt debug messages from qemu log files. So when
     * changing this, you might also need to change the code there.
     * virLogFormatString() function name is mentioned there so it's sufficient
     * to just grep for it to find the right place.
     */
    if ((funcname != NULL)) {
        ret = virAsprintfQuiet(msg, "%llu: %s : %s:%d : %s\n",
                               virThreadSelfID(), virLogPriorityString(priority),
                               funcname, linenr, str);
    } else {
        ret = virAsprintfQuiet(msg, "%llu: %s : %s\n",
                               virThreadSelfID(), virLogPriorityString(priority),
                               str);
    }
    return ret;
}


static int
virLogVersionString(const char **rawmsg,
                    char **msg)
{
    *rawmsg = VIR_LOG_VERSION_STRING;
    return virLogFormatString(msg, 0, NULL, VIR_LOG_INFO, VIR_LOG_VERSION_STRING);
}

/* Similar to virGetHostname() but avoids use of error
 * reporting APIs or logging APIs, to prevent recursion
 */
static int
virLogHostnameString(char **rawmsg,
                     char **msg)
{
    char *hostname = virGetHostnameQuiet();
    char *hoststr;

    if (!hostname)
        return -1;

    if (virAsprintfQuiet(&hoststr, "hostname: %s", hostname) < 0) {
        VIR_FREE(hostname);
        return -1;
    }
    VIR_FREE(hostname);

    if (virLogFormatString(msg, 0, NULL, VIR_LOG_INFO, hoststr) < 0) {
        VIR_FREE(hoststr);
        return -1;
    }
    *rawmsg = hoststr;
    return 0;
}


static void
virLogSourceUpdate(virLogSourcePtr source)
{
    virLogLock();
    if (source->serial < virLogFiltersSerial) {
        unsigned int priority = virLogDefaultPriority;
        unsigned int flags = 0;
        size_t i;

        for (i = 0; i < virLogNbFilters; i++) {
            if (strstr(source->name, virLogFilters[i]->match)) {
                priority = virLogFilters[i]->priority;
                flags = virLogFilters[i]->flags;
                break;
            }
        }

        source->priority = priority;
        source->flags = flags;
        source->serial = virLogFiltersSerial;
    }
    virLogUnlock();
}

/**
 * virLogMessage:
 * @source: where is that message coming from
 * @priority: the priority level
 * @filename: file where the message was emitted
 * @linenr: line where the message was emitted
 * @funcname: the function emitting the (debug) message
 * @metadata: NULL or metadata array, terminated by an item with NULL key
 * @fmt: the string format
 * @...: the arguments
 *
 * Call the libvirt logger with some information. Based on the configuration
 * the message may be stored, sent to output or just discarded
 */
void
virLogMessage(virLogSourcePtr source,
              virLogPriority priority,
              const char *filename,
              int linenr,
              const char *funcname,
              virLogMetadataPtr metadata,
              const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    virLogVMessage(source, priority,
                   filename, linenr, funcname,
                   metadata, fmt, ap);
    va_end(ap);
}


/**
 * virLogVMessage:
 * @source: where is that message coming from
 * @priority: the priority level
 * @filename: file where the message was emitted
 * @linenr: line where the message was emitted
 * @funcname: the function emitting the (debug) message
 * @metadata: NULL or metadata array, terminated by an item with NULL key
 * @fmt: the string format
 * @vargs: format args
 *
 * Call the libvirt logger with some information. Based on the configuration
 * the message may be stored, sent to output or just discarded
 */
void
virLogVMessage(virLogSourcePtr source,
               virLogPriority priority,
               const char *filename,
               int linenr,
               const char *funcname,
               virLogMetadataPtr metadata,
               const char *fmt,
               va_list vargs)
{
    static bool logInitMessageStderr = true;
    char *str = NULL;
    char *msg = NULL;
    char timestamp[VIR_TIME_STRING_BUFLEN];
    int ret;
    size_t i;
    int saved_errno = errno;
    unsigned int filterflags = 0;

    if (virLogInitialize() < 0)
        return;

    if (fmt == NULL)
        return;

    /*
     * 3 intentionally non-thread safe variable reads.
     * Since writes to the variable are serialized on
     * virLogLock, worst case result is a log message
     * is accidentally dropped or emitted, if another
     * thread is updating log filter list concurrently
     * with a log message emission.
     */
    if (source->serial < virLogFiltersSerial)
        virLogSourceUpdate(source);
    if (priority < source->priority)
        goto cleanup;
    filterflags = source->flags;

    /*
     * serialize the error message, add level and timestamp
     */
    if (virVasprintfQuiet(&str, fmt, vargs) < 0)
        goto cleanup;

    ret = virLogFormatString(&msg, linenr, funcname, priority, str);
    if (ret < 0)
        goto cleanup;

    if (virTimeStringNowRaw(timestamp) < 0)
        timestamp[0] = '\0';

    virLogLock();

    /*
     * Push the message to the outputs defined, if none exist then
     * use stderr.
     */
    for (i = 0; i < virLogNbOutputs; i++) {
        if (priority >= virLogOutputs[i]->priority) {
            if (virLogOutputs[i]->logInitMessage) {
                const char *rawinitmsg;
                char *hoststr = NULL;
                char *initmsg = NULL;
                if (virLogVersionString(&rawinitmsg, &initmsg) >= 0)
                    virLogOutputs[i]->f(&virLogSelf, VIR_LOG_INFO,
                                       __FILE__, __LINE__, __func__,
                                       timestamp, NULL, 0, rawinitmsg, initmsg,
                                       virLogOutputs[i]->data);
                VIR_FREE(initmsg);
                if (virLogHostnameString(&hoststr, &initmsg) >= 0)
                    virLogOutputs[i]->f(&virLogSelf, VIR_LOG_INFO,
                                       __FILE__, __LINE__, __func__,
                                       timestamp, NULL, 0, hoststr, initmsg,
                                       virLogOutputs[i]->data);
                VIR_FREE(hoststr);
                VIR_FREE(initmsg);
                virLogOutputs[i]->logInitMessage = false;
            }
            virLogOutputs[i]->f(source, priority,
                               filename, linenr, funcname,
                               timestamp, metadata, filterflags,
                               str, msg, virLogOutputs[i]->data);
        }
    }
    if (virLogNbOutputs == 0) {
        if (logInitMessageStderr) {
            const char *rawinitmsg;
            char *hoststr = NULL;
            char *initmsg = NULL;
            if (virLogVersionString(&rawinitmsg, &initmsg) >= 0)
                virLogOutputToFd(&virLogSelf, VIR_LOG_INFO,
                                 __FILE__, __LINE__, __func__,
                                 timestamp, NULL, 0, rawinitmsg, initmsg,
                                 (void *) STDERR_FILENO);
            VIR_FREE(initmsg);
            if (virLogHostnameString(&hoststr, &initmsg) >= 0)
                virLogOutputToFd(&virLogSelf, VIR_LOG_INFO,
                                 __FILE__, __LINE__, __func__,
                                 timestamp, NULL, 0, hoststr, initmsg,
                                 (void *) STDERR_FILENO);
            VIR_FREE(hoststr);
            VIR_FREE(initmsg);
            logInitMessageStderr = false;
        }
        virLogOutputToFd(source, priority,
                         filename, linenr, funcname,
                         timestamp, metadata, filterflags,
                         str, msg, (void *) STDERR_FILENO);
    }
    virLogUnlock();

 cleanup:
    VIR_FREE(str);
    VIR_FREE(msg);
    errno = saved_errno;
}


static void
virLogStackTraceToFd(int fd)
{
    void *array[100];
    int size;
    static bool doneWarning;
    const char *msg = "Stack trace not available on this platform\n";

#define STRIP_DEPTH 3
    size = backtrace(array, ARRAY_CARDINALITY(array));
    if (size) {
        backtrace_symbols_fd(array +  STRIP_DEPTH, size - STRIP_DEPTH, fd);
        ignore_value(safewrite(fd, "\n", 1));
    } else if (!doneWarning) {
        ignore_value(safewrite(fd, msg, strlen(msg)));
        doneWarning = true;
    }
#undef STRIP_DEPTH
}

static void
virLogOutputToFd(virLogSourcePtr source ATTRIBUTE_UNUSED,
                 virLogPriority priority ATTRIBUTE_UNUSED,
                 const char *filename ATTRIBUTE_UNUSED,
                 int linenr ATTRIBUTE_UNUSED,
                 const char *funcname ATTRIBUTE_UNUSED,
                 const char *timestamp,
                 virLogMetadataPtr metadata ATTRIBUTE_UNUSED,
                 unsigned int flags,
                 const char *rawstr ATTRIBUTE_UNUSED,
                 const char *str,
                 void *data)
{
    int fd = (intptr_t) data;
    char *msg;

    if (fd < 0)
        return;

    if (virAsprintfQuiet(&msg, "%s: %s", timestamp, str) < 0)
        return;

    ignore_value(safewrite(fd, msg, strlen(msg)));
    VIR_FREE(msg);

    if (flags & VIR_LOG_STACK_TRACE)
        virLogStackTraceToFd(fd);
}


static void
virLogCloseFd(void *data)
{
    int fd = (intptr_t) data;

    VIR_LOG_CLOSE(fd);
}


static virLogOutputPtr
virLogNewOutputToStderr(virLogPriority priority)
{
    return virLogOutputNew(virLogOutputToFd, NULL, (void *)STDERR_FILENO,
                           priority, VIR_LOG_TO_STDERR, NULL);
}


static virLogOutputPtr
virLogNewOutputToFile(virLogPriority priority,
                      const char *file)
{
    int fd;
    virLogOutputPtr ret = NULL;

    fd = open(file, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        virReportSystemError(errno, _("failed to open %s"), file);
        return NULL;
    }

    if (!(ret = virLogOutputNew(virLogOutputToFd, virLogCloseFd,
                                (void *)(intptr_t)fd,
                                priority, VIR_LOG_TO_FILE, file))) {
        VIR_LOG_CLOSE(fd);
        return NULL;
    }
    return ret;
}


#if HAVE_SYSLOG_H || USE_JOURNALD

/* Compat in case we build with journald, but no syslog */
# ifndef LOG_DEBUG
#  define LOG_DEBUG 7
# endif
# ifndef LOG_INFO
#  define LOG_INFO 6
# endif
# ifndef LOG_WARNING
#  define LOG_WARNING 4
# endif
# ifndef LOG_ERR
#  define LOG_ERR 3
# endif

static int
virLogPrioritySyslog(virLogPriority priority)
{
    switch (priority) {
    case VIR_LOG_DEBUG:
        return LOG_DEBUG;
    case VIR_LOG_INFO:
        return LOG_INFO;
    case VIR_LOG_WARN:
        return LOG_WARNING;
    case VIR_LOG_ERROR:
        return LOG_ERR;
    default:
        return LOG_ERR;
    }
}
#endif /* HAVE_SYSLOG_H || USE_JOURNALD */


#if HAVE_SYSLOG_H
static void
virLogOutputToSyslog(virLogSourcePtr source ATTRIBUTE_UNUSED,
                     virLogPriority priority,
                     const char *filename ATTRIBUTE_UNUSED,
                     int linenr ATTRIBUTE_UNUSED,
                     const char *funcname ATTRIBUTE_UNUSED,
                     const char *timestamp ATTRIBUTE_UNUSED,
                     virLogMetadataPtr metadata ATTRIBUTE_UNUSED,
                     unsigned int flags,
                     const char *rawstr ATTRIBUTE_UNUSED,
                     const char *str,
                     void *data ATTRIBUTE_UNUSED)
{
    virCheckFlags(VIR_LOG_STACK_TRACE,);

    syslog(virLogPrioritySyslog(priority), "%s", str);
}

static char *current_ident;


static void
virLogCloseSyslog(void *data ATTRIBUTE_UNUSED)
{
    closelog();
    VIR_FREE(current_ident);
}


static virLogOutputPtr
virLogNewOutputToSyslog(virLogPriority priority,
                        const char *ident)
{
    virLogOutputPtr ret = NULL;
    int at = -1;

    /* There are a couple of issues with syslog:
     * 1) If we re-opened the connection by calling openlog now, it would change
     * the message tag immediately which is not what we want, since we might be
     * in the middle of parsing of a new set of outputs where anything still can
     * go wrong and we would introduce an inconsistent state to the log. We're
     * also not holding a lock on the logger if we tried to change the tag
     * while other workers are actively logging.
     *
     * 2) Syslog keeps the open file descriptor private, so we can't just dup()
     * it like we would do with files if an output already existed.
     *
     * If a syslog connection already exists changing the message tag has to be
     * therefore special-cased and postponed until the very last moment.
     */
    if ((at = virLogFindOutput(virLogOutputs, virLogNbOutputs,
                               VIR_LOG_TO_SYSLOG, NULL)) < 0) {
        /*
         * rather than copying @ident, syslog uses caller's reference instead
         */
        VIR_FREE(current_ident);
        if (VIR_STRDUP(current_ident, ident) < 0)
            return NULL;

        openlog(current_ident, 0, 0);
    }

    if (!(ret = virLogOutputNew(virLogOutputToSyslog, virLogCloseSyslog,
                                NULL, priority, VIR_LOG_TO_SYSLOG, ident))) {
        if (at < 0) {
            closelog();
            VIR_FREE(current_ident);
        }
        return NULL;
    }
    return ret;
}


# if USE_JOURNALD
#  define IOVEC_SET(iov, data, size)            \
    do {                                        \
        struct iovec *_i = &(iov);              \
        _i->iov_base = (void*)(data);           \
        _i->iov_len = (size);                   \
    } while (0)

#  define IOVEC_SET_STRING(iov, str) IOVEC_SET(iov, str, strlen(str))

/* Used for conversion of numbers to strings, and for length of binary data */
#  define JOURNAL_BUF_SIZE (MAX(INT_BUFSIZE_BOUND(int), sizeof(uint64_t)))

struct journalState
{
    struct iovec *iov, *iov_end;
    char (*bufs)[JOURNAL_BUF_SIZE], (*bufs_end)[JOURNAL_BUF_SIZE];
};

static void
journalAddString(struct journalState *state, const char *field,
                 const char *value)
{
    static const char newline = '\n', equals = '=';

    if (strchr(value, '\n') != NULL) {
        uint64_t nstr;

        /* If 'str' contains a newline, then we must
         * encode the string length, since we can't
         * rely on the newline for the field separator
         */
        if (state->iov_end - state->iov < 5 || state->bufs == state->bufs_end)
            return; /* Silently drop */
        nstr = htole64(strlen(value));
        memcpy(state->bufs[0], &nstr, sizeof(nstr));

        IOVEC_SET_STRING(state->iov[0], field);
        IOVEC_SET(state->iov[1], &newline, sizeof(newline));
        IOVEC_SET(state->iov[2], state->bufs[0], sizeof(nstr));
        state->bufs++;
        state->iov += 3;
    } else {
        if (state->iov_end - state->iov < 4)
            return; /* Silently drop */
        IOVEC_SET_STRING(state->iov[0], field);
        IOVEC_SET(state->iov[1], (void *)&equals, sizeof(equals));
        state->iov += 2;
    }
    IOVEC_SET_STRING(state->iov[0], value);
    IOVEC_SET(state->iov[1], (void *)&newline, sizeof(newline));
    state->iov += 2;
}

static void
journalAddInt(struct journalState *state, const char *field, int value)
{
    static const char newline = '\n', equals = '=';

    char *num;

    if (state->iov_end - state->iov < 4 || state->bufs == state->bufs_end)
        return; /* Silently drop */

    num = virFormatIntDecimal(state->bufs[0], sizeof(state->bufs[0]), value);

    IOVEC_SET_STRING(state->iov[0], field);
    IOVEC_SET(state->iov[1], (void *)&equals, sizeof(equals));
    IOVEC_SET_STRING(state->iov[2], num);
    IOVEC_SET(state->iov[3], (void *)&newline, sizeof(newline));
    state->bufs++;
    state->iov += 4;
}

static void
virLogOutputToJournald(virLogSourcePtr source,
                       virLogPriority priority,
                       const char *filename,
                       int linenr,
                       const char *funcname,
                       const char *timestamp ATTRIBUTE_UNUSED,
                       virLogMetadataPtr metadata,
                       unsigned int flags,
                       const char *rawstr,
                       const char *str ATTRIBUTE_UNUSED,
                       void *data)
{
    virCheckFlags(VIR_LOG_STACK_TRACE,);
    int buffd = -1;
    int journalfd = (intptr_t) data;
    struct msghdr mh;
    struct sockaddr_un sa;
    union {
        struct cmsghdr cmsghdr;
        uint8_t buf[CMSG_SPACE(sizeof(int))];
    } control;
    struct cmsghdr *cmsg;
    /* We use /dev/shm instead of /tmp here, since we want this to
     * be a tmpfs, and one that is available from early boot on
     * and where unprivileged users can create files. */
    char path[] = "/dev/shm/journal.XXXXXX";
    size_t nmetadata = 0;

#  define NUM_FIELDS_CORE 6
#  define NUM_FIELDS_META 5
#  define NUM_FIELDS (NUM_FIELDS_CORE + NUM_FIELDS_META)
    struct iovec iov[NUM_FIELDS * 5];
    char iov_bufs[NUM_FIELDS][JOURNAL_BUF_SIZE];
    struct journalState state;

    state.iov = iov;
    state.iov_end = iov + ARRAY_CARDINALITY(iov);
    state.bufs = iov_bufs;
    state.bufs_end = iov_bufs + ARRAY_CARDINALITY(iov_bufs);

    journalAddString(&state, "MESSAGE", rawstr);
    journalAddInt(&state, "PRIORITY",
                  virLogPrioritySyslog(priority));
    journalAddInt(&state, "SYSLOG_FACILITY", LOG_DAEMON);
    journalAddString(&state, "LIBVIRT_SOURCE", source->name);
    if (filename)
        journalAddString(&state, "CODE_FILE", filename);
    journalAddInt(&state, "CODE_LINE", linenr);
    if (funcname)
        journalAddString(&state, "CODE_FUNC", funcname);
    if (metadata != NULL) {
        while (metadata->key != NULL &&
               nmetadata < NUM_FIELDS_META) {
            if (metadata->s != NULL)
                journalAddString(&state, metadata->key, metadata->s);
            else
                journalAddInt(&state, metadata->key, metadata->iv);
            metadata++;
            nmetadata++;
        }
    }

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (!virStrcpy(sa.sun_path, "/run/systemd/journal/socket", sizeof(sa.sun_path)))
        return;

    memset(&mh, 0, sizeof(mh));
    mh.msg_name = &sa;
    mh.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(sa.sun_path);
    mh.msg_iov = iov;
    mh.msg_iovlen = state.iov - iov;

    if (sendmsg(journalfd, &mh, MSG_NOSIGNAL) >= 0)
        return;

    if (errno != EMSGSIZE && errno != ENOBUFS)
        return;

    /* Message was too large, so dump to temporary file
     * and pass an FD to the journal
     */

    /* NB: mkostemp is not declared async signal safe by
     * POSIX, but this is Linux only code and the GLibc
     * impl is safe enough, only using open() and inline
     * asm to read a timestamp (falling back to gettimeofday
     * on some arches
     */
    if ((buffd = mkostemp(path, O_CLOEXEC|O_RDWR)) < 0)
        return;

    if (unlink(path) < 0)
        goto cleanup;

    if (writev(buffd, iov, state.iov - iov) < 0)
        goto cleanup;

    mh.msg_iov = NULL;
    mh.msg_iovlen = 0;

    memset(&control, 0, sizeof(control));
    mh.msg_control = &control;
    mh.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&mh);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &buffd, sizeof(int));

    mh.msg_controllen = cmsg->cmsg_len;

    ignore_value(sendmsg(journalfd, &mh, MSG_NOSIGNAL));

 cleanup:
    VIR_LOG_CLOSE(buffd);
}


static virLogOutputPtr
virLogNewOutputToJournald(int priority)
{
    int journalfd;
    virLogOutputPtr ret = NULL;

    if ((journalfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        return NULL;

    if (virSetInherit(journalfd, false) < 0) {
        VIR_LOG_CLOSE(journalfd);
        return NULL;
    }

    if (!(ret = virLogOutputNew(virLogOutputToJournald, virLogCloseFd,
                                (void *)(intptr_t) journalfd, priority,
                                VIR_LOG_TO_JOURNALD, NULL))) {
        VIR_LOG_CLOSE(journalfd);
        return NULL;
    }

    return ret;
}
# endif /* USE_JOURNALD */

int virLogPriorityFromSyslog(int priority)
{
    switch (priority) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
        return VIR_LOG_ERROR;
    case LOG_WARNING:
    case LOG_NOTICE:
        return VIR_LOG_WARN;
    case LOG_INFO:
        return VIR_LOG_INFO;
    case LOG_DEBUG:
        return VIR_LOG_DEBUG;
    }
    return VIR_LOG_ERROR;
}

#else /* HAVE_SYSLOG_H */
int virLogPriorityFromSyslog(int priority ATTRIBUTE_UNUSED)
{
    return VIR_LOG_ERROR;
}
#endif /* HAVE_SYSLOG_H */


/**
 * virLogGetDefaultPriority:
 *
 * Returns the current logging priority level.
 */
virLogPriority
virLogGetDefaultPriority(void)
{
    return virLogDefaultPriority;
}


/**
 * virLogGetFilters:
 *
 * Returns a string listing the current filters, in the format originally
 * specified in the config file or environment. Caller must free the
 * result.
 */
char *
virLogGetFilters(void)
{
    size_t i;
    virBuffer filterbuf = VIR_BUFFER_INITIALIZER;

    virLogLock();
    for (i = 0; i < virLogNbFilters; i++) {
        const char *sep = ":";
        if (virLogFilters[i]->flags & VIR_LOG_STACK_TRACE)
            sep = ":+";
        virBufferAsprintf(&filterbuf, "%d%s%s ",
                          virLogFilters[i]->priority,
                          sep,
                          virLogFilters[i]->match);
    }
    virLogUnlock();

    if (virBufferError(&filterbuf)) {
        virBufferFreeAndReset(&filterbuf);
        return NULL;
    }

    return virBufferContentAndReset(&filterbuf);
}


/**
 * virLogGetOutputs:
 *
 * Returns a string listing the current outputs, in the format originally
 * specified in the config file or environment. Caller must free the
 * result.
 */
char *
virLogGetOutputs(void)
{
    size_t i;
    virBuffer outputbuf = VIR_BUFFER_INITIALIZER;

    virLogLock();
    for (i = 0; i < virLogNbOutputs; i++) {
        virLogDestination dest = virLogOutputs[i]->dest;
        if (i)
            virBufferAddChar(&outputbuf, ' ');
        switch (dest) {
            case VIR_LOG_TO_SYSLOG:
            case VIR_LOG_TO_FILE:
                virBufferAsprintf(&outputbuf, "%d:%s:%s",
                                  virLogOutputs[i]->priority,
                                  virLogDestinationTypeToString(dest),
                                  virLogOutputs[i]->name);
                break;
            default:
                virBufferAsprintf(&outputbuf, "%d:%s",
                                  virLogOutputs[i]->priority,
                                  virLogDestinationTypeToString(dest));
        }
    }
    virLogUnlock();

    if (virBufferError(&outputbuf)) {
        virBufferFreeAndReset(&outputbuf);
        return NULL;
    }

    return virBufferContentAndReset(&outputbuf);
}


/**
 * virLogGetNbFilters:
 *
 * Returns the current number of defined log filters.
 */
int
virLogGetNbFilters(void)
{
    return virLogNbFilters;
}


/**
 * virLogGetNbOutputs:
 *
 * Returns the current number of defined log outputs.
 */
int
virLogGetNbOutputs(void)
{
    return virLogNbOutputs;
}


/**
 * virLogParseDefaultPriority:
 * @priority: string defining the desired logging level (either a numeric or a
 *            word form, see below)
 *
 * Parses the desired log priority level. The input @priority shall conform to
 * one of the following levels:
 *    1 = DEBUG
 *    2 = INFO
 *    3 = WARNING
 *    4 = ERROR
 *
 *
 * Returns the corresponding priority enum on success, -1 in case of error. A
 * call to virLogSetDefaultPriority should be issued upon returning from this
 * function.
 */
int
virLogParseDefaultPriority(const char *priority)
{
    if (STREQ(priority, "1") || STREQ(priority, "debug"))
        return VIR_LOG_DEBUG;
    else if (STREQ(priority, "2") || STREQ(priority, "info"))
        return VIR_LOG_INFO;
    else if (STREQ(priority, "3") || STREQ(priority, "warning"))
        return VIR_LOG_WARN;
    else if (STREQ(priority, "4") || STREQ(priority, "error"))
        return VIR_LOG_ERROR;
    return -1;
}


/**
 * virLogSetFromEnv:
 *
 * Sets virLogDefaultPriority, virLogFilters and virLogOutputs based on
 * environment variables.
 */
void
virLogSetFromEnv(void)
{
    const char *debugEnv;

    if (virLogInitialize() < 0)
        return;

    debugEnv = virGetEnvAllowSUID("LIBVIRT_DEBUG");
    if (debugEnv && *debugEnv)
        virLogSetDefaultPriority(virLogParseDefaultPriority(debugEnv));
    debugEnv = virGetEnvAllowSUID("LIBVIRT_LOG_FILTERS");
    if (debugEnv && *debugEnv)
        virLogSetFilters(debugEnv);
    debugEnv = virGetEnvAllowSUID("LIBVIRT_LOG_OUTPUTS");
    if (debugEnv && *debugEnv)
        virLogSetOutputs(debugEnv);
}


/*
 * Returns a true value if the first line in @str is
 * probably a log message generated by the libvirt
 * logging layer
 */
bool virLogProbablyLogMessage(const char *str)
{
    bool ret = false;
    if (!virLogRegex)
        return false;
    if (regexec(virLogRegex, str, 0, NULL, 0) == 0)
        ret = true;
    return ret;
}


/**
 * virLogOutputNew:
 * @f: the function to call to output a message
 * @c: the function to call to close the output (or NULL)
 * @data: extra data passed as first arg to functions @f and @c
 * @priority: minimal priority for this filter, use 0 for none
 * @dest: where to send output of this priority (see virLogDestination)
 * @name: additional data associated with syslog and file-based outputs (ident
 *        and filename respectively)
 *
 * Allocates and returns a new log output object. The object has to be later
 * defined, so that the output will be taken into account when emitting a
 * message.
 *
 * Returns reference to a newly created object or NULL in case of failure.
 */
virLogOutputPtr
virLogOutputNew(virLogOutputFunc f,
                virLogCloseFunc c,
                void *data,
                virLogPriority priority,
                virLogDestination dest,
                const char *name)
{
    virLogOutputPtr ret = NULL;
    char *ndup = NULL;

    if (dest == VIR_LOG_TO_SYSLOG || dest == VIR_LOG_TO_FILE) {
        if (!name) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Missing auxiliary data in output definition"));
            return NULL;
        }

        if (VIR_STRDUP(ndup, name) < 0)
            return NULL;
    }

    if (VIR_ALLOC(ret) < 0) {
        VIR_FREE(ndup);
        return NULL;
    }

    ret->logInitMessage = true;
    ret->f = f;
    ret->c = c;
    ret->data = data;
    ret->priority = priority;
    ret->dest = dest;
    ret->name = ndup;

    return ret;
}


/**
 * virLogFilterNew:
 * @match: the pattern to match
 * @priority: the priority to give to messages matching the pattern
 * @flags: extra flags, see virLogFilterFlags enum
 *
 * Allocates and returns a new log filter object. The object has to be later
 * defined, so that the pattern will be taken into account when executing the
 * log filters (to select or reject a particular message) on messages.
 *
 * The filter defines a rules that will apply only to messages matching
 * the pattern (currently if @match is a substring of the message category)
 *
 * Returns a reference to a newly created filter that needs to be defined using
 * virLogDefineFilters, or NULL in case of an error.
 */
virLogFilterPtr
virLogFilterNew(const char *match,
                virLogPriority priority,
                unsigned int flags)
{
    virLogFilterPtr ret = NULL;
    char *mdup = NULL;

    virCheckFlags(VIR_LOG_STACK_TRACE, NULL);

    if (priority < VIR_LOG_DEBUG || priority > VIR_LOG_ERROR) {
        virReportError(VIR_ERR_INVALID_ARG, _("Invalid log priority %d"),
                       priority);
        return NULL;
    }

    if (VIR_STRDUP_QUIET(mdup, match) < 0)
        return NULL;

    if (VIR_ALLOC_QUIET(ret) < 0) {
        VIR_FREE(mdup);
        return NULL;
    }

    ret->match = mdup;
    ret->priority = priority;
    ret->flags = flags;

    return ret;
}


/**
 * virLogFindOutput:
 * @outputs: a list of outputs where to look for the output of type @dest
 * @noutputs: number of elements in @outputs
 * @dest: destination type of an output
 * @opaque: opaque data to the method (only filename at the moment)
 *
 * Looks for an output of destination type @dest in the source list @outputs.
 * If such an output exists, index of the object in the list is returned.
 * In case of the destination being of type FILE also a comparison of the
 * output's filename with @opaque is performed first.
 *
 * Returns the index of the object in the list or -1 if no object matching the
 * specified @dest type and/or @opaque data one was found.
 */
int
virLogFindOutput(virLogOutputPtr *outputs, size_t noutputs,
                 virLogDestination dest, const void *opaque)
{
    size_t i;
    const char *name = opaque;

    for (i = 0; i < noutputs; i++) {
        if (dest == outputs[i]->dest &&
            (STREQ_NULLABLE(outputs[i]->name, name)))
                return i;
    }

    return -1;
}


/**
 * virLogDefineOutputs:
 * @outputs: new set of outputs to be defined
 * @noutputs: number of outputs in @outputs
 *
 * Resets any existing set of outputs and defines a completely new one.
 *
 * Returns number of outputs successfully defined or -1 in case of error;
 */
int
virLogDefineOutputs(virLogOutputPtr *outputs, size_t noutputs)
{
#if HAVE_SYSLOG_H
    int id;
    char *tmp = NULL;
#endif /* HAVE_SYSLOG_H */

    if (virLogInitialize() < 0)
        return -1;

    virLogLock();
    virLogResetOutputs();

#if HAVE_SYSLOG_H
    /* syslog needs to be special-cased, since it keeps the fd in private */
    if ((id = virLogFindOutput(outputs, noutputs, VIR_LOG_TO_SYSLOG,
                               current_ident)) != -1) {
        /* nothing can go wrong now (except for malloc) and since we're also
         * holding the lock so it's safe to call openlog and change the message
         * tag
         */
        if (VIR_STRDUP_QUIET(tmp, outputs[id]->name) < 0) {
            virLogUnlock();
            return -1;
        }
        VIR_FREE(current_ident);
        current_ident = tmp;
        openlog(current_ident, 0, 0);
    }
#endif /* HAVE_SYSLOG_H */

    virLogOutputs = outputs;
    virLogNbOutputs = noutputs;

    virLogUnlock();
    return 0;
}


/**
 * virLogDefineFilters:
 * @filters: new set of filters to be defined
 * @nfilters: number of filters in @filters
 *
 * Resets any existing set of filters and defines a completely new one. The
 * resulting set can also be empty in which case NULL should be passed to
 * @filters.
 *
 * Returns 0 on success or -1 in case of error.
 */
int
virLogDefineFilters(virLogFilterPtr *filters, size_t nfilters)
{
    if (virLogInitialize() < 0)
        return -1;

    virLogLock();
    virLogResetFilters();
    virLogFilters = filters;
    virLogNbFilters = nfilters;
    virLogUnlock();

    return 0;
}


/**
 * virLogParseOutput:
 * @src: string defining a single output
 *
 * The format of @src should be one of the following:
 *    x:stderr - output is sent to stderr
 *    x:journald - output is sent to journald
 *    x:syslog:name - output is sent to syslog using 'name' as the message tag
 *    x:file:abs_file_path - output is sent to file specified by 'abs_file_path'
 *
 *      'x' - minimal priority level which acts as a filter meaning that only
 *            messages with priority level greater than or equal to 'x' will be
 *            sent to output @src; supported values for 'x' are as follows:
 *              1: DEBUG
 *              2: INFO
 *              3: WARNING
 *              4: ERROR
 *
 * Parses @src string into a logging object type. If running in setuid mode,
 * then only destination of type 'stderr' is permitted.
 *
 * Returns a newly created logging object from @src on success or NULL in case
 * of an error.
 */
virLogOutputPtr
virLogParseOutput(const char *src)
{
    virLogOutputPtr ret = NULL;
    char **tokens = NULL;
    char *abspath = NULL;
    size_t count = 0;
    virLogPriority prio;
    int dest;
    bool isSUID = virIsSUID();

    VIR_DEBUG("output=%s", src);

    /* split our format prio:destination:additional_data to tokens and parse
     * them individually
     */
    if (!(tokens = virStringSplitCount(src, ":", 0, &count)) || count < 2) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Malformed format for output '%s'"), src);
        goto cleanup;
    }

    if (virStrToLong_uip(tokens[0], NULL, 10, &prio) < 0 ||
        (prio < VIR_LOG_DEBUG) || (prio > VIR_LOG_ERROR)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid priority '%s' for output '%s'"),
                       tokens[0], src);
        goto cleanup;
    }

    if ((dest = virLogDestinationTypeFromString(tokens[1])) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid destination '%s' for output '%s'"),
                       tokens[1], src);
        goto cleanup;
    }

    if (((dest == VIR_LOG_TO_STDERR ||
          dest == VIR_LOG_TO_JOURNALD) && count != 2) ||
        ((dest == VIR_LOG_TO_FILE ||
          dest == VIR_LOG_TO_SYSLOG) && count != 3)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Output '%s' does not meet the format requirements "
                         "for destination type '%s'"), src, tokens[1]);
        goto cleanup;
    }

    /* if running with setuid, only 'stderr' is allowed */
    if (isSUID && dest != VIR_LOG_TO_STDERR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Running with SUID permits only destination of type "
                         "'stderr'"));
        goto cleanup;
    }

    switch ((virLogDestination) dest) {
    case VIR_LOG_TO_STDERR:
        ret = virLogNewOutputToStderr(prio);
        break;
    case VIR_LOG_TO_SYSLOG:
#if HAVE_SYSLOG_H
        ret = virLogNewOutputToSyslog(prio, tokens[2]);
#endif
        break;
    case VIR_LOG_TO_FILE:
        if (virFileAbsPath(tokens[2], &abspath) < 0)
            goto cleanup;
        ret = virLogNewOutputToFile(prio, abspath);
        VIR_FREE(abspath);
        break;
    case VIR_LOG_TO_JOURNALD:
#if USE_JOURNALD
        ret = virLogNewOutputToJournald(prio);
#endif
        break;
    case VIR_LOG_TO_OUTPUT_LAST:
        break;
    }

 cleanup:
    virStringListFree(tokens);
    return ret;
}


/**
 * virLogParseFilter:
 * @src: string defining a single filter
 *
 * The format of @src should be one of the following:
 *    x:name - filter affecting all modules which match 'name'
 *    x:+name
 *
 *      '+' - hints the logger to also include a stack trace for every message
 *      'name' - match string which either matches a name of a directory in
 *               libvirt's source tree which in turn affects all modules in
 *               that directory or it can matches a specific module within a
 *               directory, e.g. 'util.file' will only affect messages from
 *               module virfile.c inside src/util/ directory
 *      'x' - minimal priority level which acts as a filter meaning that only
 *            messages with priority level greater than or equal to 'x' will be
 *            sent to output; supported values for 'x' are as follows:
 *              1: DEBUG
 *              2: INFO
 *              3: WARNING
 *              4: ERROR
 *
 * Parses @src string into a logging object type.
 *
 * Returns a newly created logging object from @src on success or NULL in case
 * of an error.
 */
virLogFilterPtr
virLogParseFilter(const char *src)
{
    virLogFilterPtr ret = NULL;
    size_t count = 0;
    virLogPriority prio;
    char **tokens = NULL;
    unsigned int flags = 0;
    char *match = NULL;

    VIR_DEBUG("filter=%s", src);

    /* split our format prio:match_str to tokens and parse them individually */
    if (!(tokens = virStringSplitCount(src, ":", 0, &count)) || count != 2) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Malformed format for filter '%s'"), src);
        goto cleanup;
    }

    if (virStrToLong_uip(tokens[0], NULL, 10, &prio) < 0 ||
        (prio < VIR_LOG_DEBUG) || (prio > VIR_LOG_ERROR)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid priority '%s' for output '%s'"),
                       tokens[0], src);
        goto cleanup;
    }

    match = tokens[1];
    if (match[0] == '+') {
        flags |= VIR_LOG_STACK_TRACE;
        match++;
    }

    /* match string cannot comprise just from a single '+' */
    if (!*match) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid match string '%s'"), tokens[1]);

        goto cleanup;
    }

    if (!(ret = virLogFilterNew(match, prio, flags)))
        goto cleanup;

 cleanup:
    virStringListFree(tokens);
    return ret;
}

/**
 * virLogParseOutputs:
 * @src: string defining a (set of) output(s)
 * @outputs: user-supplied list where parsed outputs from @src shall be stored
 *
 * Parses a (set of) output(s) into a list of logging objects. Multiple outputs
 * can be defined within @src string, they just need to be separated by spaces.
 * If running in setuid mode, then only the 'stderr' output will be allowed.
 *
 * Returns the number of outputs parsed or -1 in case of error.
 */
int
virLogParseOutputs(const char *src, virLogOutputPtr **outputs)
{
    int ret = -1;
    int at = -1;
    size_t noutputs = 0;
    size_t i, count;
    char **strings = NULL;
    virLogOutputPtr output = NULL;
    virLogOutputPtr *list = NULL;

    VIR_DEBUG("outputs=%s", src);

    if (!(strings = virStringSplitCount(src, " ", 0, &count)))
        goto cleanup;

    for (i = 0; i < count; i++) {
        /* virStringSplit may return empty strings */
        if (STREQ(strings[i], ""))
            continue;

        if (!(output = virLogParseOutput(strings[i])))
            goto cleanup;

        /* let's check if a duplicate output does not already exist in which
         * case we need to replace it with its last occurrence, however, rather
         * than first deleting the duplicate and then adding the new one, the
         * new output object is added first so in case of an error we don't
         * lose the old entry
         */
        at = virLogFindOutput(list, noutputs, output->dest, output->name);
        if (VIR_APPEND_ELEMENT(list, noutputs, output) < 0) {
            virLogOutputFree(output);
            goto cleanup;
        }
        if (at >= 0) {
            virLogOutputFree(list[at]);
            VIR_DELETE_ELEMENT(list, at, noutputs);
        }
    }

    ret = noutputs;
    *outputs = list;
    list = NULL;
 cleanup:
    virStringListFree(strings);
    return ret;
}

/**
 * virLogParseFilters:
 * @src: string defining a (set of) filter(s)
 * @filters: pointer to a list where the individual filters shall be parsed
 *
 * This method parses @src and produces a list of individual filters which then
 * needs to be passed to virLogDefineFilters in order to be set and taken into
 * effect.
 * Multiple filters can be defined in a single @src, they just need to be
 * separated by spaces.
 *
 * Returns the number of filter parsed or -1 in case of error.
 */
int
virLogParseFilters(const char *src, virLogFilterPtr **filters)
{
    int ret = -1;
    size_t nfilters = 0;
    size_t i, count;
    char **strings = NULL;
    virLogFilterPtr filter = NULL;
    virLogFilterPtr *list = NULL;

    VIR_DEBUG("filters=%s", src);

    if (!(strings = virStringSplitCount(src, " ", 0, &count)))
        goto cleanup;

    for (i = 0; i < count; i++) {
        /* virStringSplit may return empty strings */
        if (STREQ(strings[i], ""))
            continue;

        if (!(filter = virLogParseFilter(strings[i])))
            goto cleanup;

        if (VIR_APPEND_ELEMENT(list, nfilters, filter)) {
            virLogFilterFree(filter);
            goto cleanup;
        }
    }

    ret = nfilters;
    *filters = list;
    list = NULL;
 cleanup:
    virStringListFree(strings);
    return ret;
}

/**
 * virLogSetOutputs:
 * @outputs: string defining a (set of) output(s)
 *
 * Replaces the current set of defined outputs with a new set of outputs.
 * Should the set be empty or NULL, a default output is used according to the
 * daemon's runtime attributes.
 *
 * Returns 0 on success or -1 in case of an error.
 */
int
virLogSetOutputs(const char *src)
{
    int ret = -1;
    int noutputs = 0;
    const char *outputstr = virLogDefaultOutput;
    virLogOutputPtr *outputs = NULL;

    if (virLogInitialize() < 0)
        return -1;

    if (src && *src)
        outputstr = src;

    if ((noutputs = virLogParseOutputs(outputstr, &outputs)) < 0)
        goto cleanup;

    if (virLogDefineOutputs(outputs, noutputs) < 0)
        goto cleanup;

    outputs = NULL;
    ret = 0;
 cleanup:
    virLogOutputListFree(outputs, noutputs);
    return ret;
}


/**
 * virLogSetFilters:
 * @src: string defining a (set of) filter(s)
 *
 * Replaces the current set of defined filters with a new set of filters.
 *
 * Returns 0 on success or -1 in case of an error.
 */
int
virLogSetFilters(const char *src)
{
    int ret = -1;
    int nfilters = 0;
    virLogFilterPtr *filters = NULL;

    if (virLogInitialize() < 0)
        return -1;

    if (src && (nfilters = virLogParseFilters(src, &filters)) < 0)
        goto cleanup;

    if (virLogDefineFilters(filters, nfilters) < 0)
        goto cleanup;

    filters = NULL;
    ret = 0;
 cleanup:
    virLogFilterListFree(filters, nfilters);
    return ret;
}
