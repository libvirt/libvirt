/*
 * virlog.c: internal logging and debugging
 *
 * Copyright (C) 2008, 2010-2013 Red Hat, Inc.
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
#include <signal.h>
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

/* Journald output is only supported on Linux new enough to expose
 * htole64.  */
#if HAVE_SYSLOG_H && defined(__linux__) && HAVE_DECL_HTOLE64
# define USE_JOURNALD 1
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_ENUM_DECL(virLogSource)
VIR_ENUM_IMPL(virLogSource, VIR_LOG_FROM_LAST,
              "file",
              "error",
              "audit",
              "trace",
              "library");

/*
 * A logging buffer to keep some history over logs
 */

static int virLogSize = 64 * 1024;
static char *virLogBuffer = NULL;
static int virLogLen = 0;
static int virLogStart = 0;
static int virLogEnd = 0;
static regex_t *virLogRegex = NULL;


#define VIR_LOG_DATE_REGEX "[0-9]{4}-[0-9]{2}-[0-9]{2}"
#define VIR_LOG_TIME_REGEX "[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}\\+[0-9]{4}"
#define VIR_LOG_PID_REGEX "[0-9]+"
#define VIR_LOG_LEVEL_REGEX "(debug|info|warning|error)"

#define VIR_LOG_REGEX \
    VIR_LOG_DATE_REGEX " " VIR_LOG_TIME_REGEX ": " \
    VIR_LOG_PID_REGEX ": " VIR_LOG_LEVEL_REGEX " : "

/*
 * Filters are used to refine the rules on what to keep or drop
 * based on a matching pattern (currently a substring)
 */
struct _virLogFilter {
    char *match;
    virLogPriority priority;
    unsigned int flags;
};
typedef struct _virLogFilter virLogFilter;
typedef virLogFilter *virLogFilterPtr;

static virLogFilterPtr virLogFilters = NULL;
static int virLogNbFilters = 0;

/*
 * Outputs are used to emit the messages retained
 * after filtering, multiple output can be used simultaneously
 */
struct _virLogOutput {
    bool logVersion;
    void *data;
    virLogOutputFunc f;
    virLogCloseFunc c;
    virLogPriority priority;
    virLogDestination dest;
    char *name;
};
typedef struct _virLogOutput virLogOutput;
typedef virLogOutput *virLogOutputPtr;

static virLogOutputPtr virLogOutputs = NULL;
static int virLogNbOutputs = 0;

/*
 * Default priorities
 */
static virLogPriority virLogDefaultPriority = VIR_LOG_DEFAULT;

static int virLogResetFilters(void);
static int virLogResetOutputs(void);
static void virLogOutputToFd(virLogSource src,
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


static const char *
virLogOutputString(virLogDestination ldest)
{
    switch (ldest) {
    case VIR_LOG_TO_STDERR:
        return "stderr";
    case VIR_LOG_TO_SYSLOG:
        return "syslog";
    case VIR_LOG_TO_FILE:
        return "file";
    case VIR_LOG_TO_JOURNALD:
        return "journald";
    }
    return "unknown";
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
    const char *pbm = NULL;

    if (virMutexInit(&virLogMutex) < 0)
        return -1;

    virLogLock();
    if (VIR_ALLOC_N_QUIET(virLogBuffer, virLogSize + 1) < 0) {
        /*
         * The debug buffer is not a critical component, allow startup
         * even in case of failure to allocate it in case of a
         * configuration mistake.
         */
        virLogSize = 64 * 1024;
        if (VIR_ALLOC_N_QUIET(virLogBuffer, virLogSize + 1) < 0) {
            pbm = "Failed to allocate debug buffer: deactivating debug log\n";
            virLogSize = 0;
        } else {
            pbm = "Failed to allocate debug buffer: reduced to 64 kB\n";
        }
    }
    virLogLen = 0;
    virLogStart = 0;
    virLogEnd = 0;
    virLogDefaultPriority = VIR_LOG_DEFAULT;

    if (VIR_ALLOC_QUIET(virLogRegex) >= 0) {
        if (regcomp(virLogRegex, VIR_LOG_REGEX, REG_EXTENDED) != 0)
            VIR_FREE(virLogRegex);
    }

    virLogUnlock();
    if (pbm)
        VIR_WARN("%s", pbm);
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLog)


/**
 * virLogSetBufferSize:
 * @size: size of the buffer in kilobytes or <= 0 to deactivate
 *
 * Dynamically set the size or deactivate the logging buffer used to keep
 * a trace of all recent debug output. Note that the content of the buffer
 * is lost if it gets reallocated.
 *
 * Return -1 in case of failure or 0 in case of success
 */
int
virLogSetBufferSize(int size)
{
    int ret = 0;
    int oldsize;
    char *oldLogBuffer;
    const char *pbm = NULL;

    if (size < 0)
        size = 0;

    if (virLogInitialize() < 0)
        return -1;

    if (size * 1024 == virLogSize)
        return ret;

    virLogLock();

    oldsize = virLogSize;
    oldLogBuffer = virLogBuffer;

    if (INT_MAX / 1024 <= size) {
        pbm = "Requested log size of %d kB too large\n";
        ret = -1;
        goto error;
    }

    virLogSize = size * 1024;
    if (VIR_ALLOC_N_QUIET(virLogBuffer, virLogSize + 1) < 0) {
        pbm = "Failed to allocate debug buffer of %d kB\n";
        virLogBuffer = oldLogBuffer;
        virLogSize = oldsize;
        ret = -1;
        goto error;
    }
    VIR_FREE(oldLogBuffer);
    virLogLen = 0;
    virLogStart = 0;
    virLogEnd = 0;

error:
    virLogUnlock();
    if (pbm)
        VIR_ERROR(pbm, size);
    return ret;
}


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
    virLogLen = 0;
    virLogStart = 0;
    virLogEnd = 0;
    virLogDefaultPriority = VIR_LOG_DEFAULT;
    virLogUnlock();
    return 0;
}


/*
 * Store a string in the ring buffer
 */
static void
virLogStr(const char *str)
{
    int tmp;
    int len;

    if ((str == NULL) || (virLogBuffer == NULL) || (virLogSize <= 0))
        return;
    len = strlen(str);
    if (len >= virLogSize)
        return;

    /*
     * copy the data and reset the end, we cycle over the end of the buffer
     */
    if (virLogEnd + len >= virLogSize) {
        tmp = virLogSize - virLogEnd;
        memcpy(&virLogBuffer[virLogEnd], str, tmp);
        memcpy(&virLogBuffer[0], &str[tmp], len - tmp);
        virLogEnd = len - tmp;
    } else {
        memcpy(&virLogBuffer[virLogEnd], str, len);
        virLogEnd += len;
    }
    virLogBuffer[virLogEnd] = 0;
    /*
     * Update the log length, and if full move the start index
     */
    virLogLen += len;
    if (virLogLen > virLogSize) {
        tmp = virLogLen - virLogSize;
        virLogLen = virLogSize;
        virLogStart += tmp;
        if (virLogStart >= virLogSize)
            virLogStart -= virLogSize;
    }
}


static void
virLogDumpAllFD(const char *msg, int len)
{
    size_t i;
    bool found = false;

    if (len <= 0)
        len = strlen(msg);

    for (i = 0; i < virLogNbOutputs; i++) {
        if (virLogOutputs[i].f == virLogOutputToFd) {
            int fd = (intptr_t) virLogOutputs[i].data;

            if (fd >= 0) {
                ignore_value(safewrite(fd, msg, len));
                found = true;
            }
        }
    }
    if (!found)
        ignore_value(safewrite(STDERR_FILENO, msg, len));
}


/**
 * virLogEmergencyDumpAll:
 * @signum: the signal number
 *
 * Emergency function called, possibly from a signal handler.
 * It need to output the debug ring buffer through the log
 * output which are safe to use from a signal handler.
 * In case none is found it is emitted to standard error.
 */
void
virLogEmergencyDumpAll(int signum)
{
    int len;
    int oldLogStart, oldLogLen;

    switch (signum) {
#ifdef SIGFPE
        case SIGFPE:
            virLogDumpAllFD("Caught signal Floating-point exception", -1);
            break;
#endif
#ifdef SIGSEGV
        case SIGSEGV:
            virLogDumpAllFD("Caught Segmentation violation", -1);
            break;
#endif
#ifdef SIGILL
        case SIGILL:
            virLogDumpAllFD("Caught illegal instruction", -1);
            break;
#endif
#ifdef SIGABRT
        case SIGABRT:
            virLogDumpAllFD("Caught abort signal", -1);
            break;
#endif
#ifdef SIGBUS
        case SIGBUS:
            virLogDumpAllFD("Caught bus error", -1);
            break;
#endif
#ifdef SIGUSR2
        case SIGUSR2:
            virLogDumpAllFD("Caught User-defined signal 2", -1);
            break;
#endif
        default:
            virLogDumpAllFD("Caught unexpected signal", -1);
            break;
    }
    if ((virLogBuffer == NULL) || (virLogSize <= 0)) {
        virLogDumpAllFD(" internal log buffer deactivated\n", -1);
        return;
    }

    virLogDumpAllFD(" dumping internal log buffer:\n", -1);
    virLogDumpAllFD("\n\n    ====== start of log =====\n\n", -1);

    /*
     * Since we can't lock the buffer safely from a signal handler
     * we mark it as empty in case of concurrent access, and proceed
     * with the data, at worse we will output something a bit weird
     * if another thread start logging messages at the same time.
     * Note that virLogStr() uses virLogEnd for the computations and
     * writes to the buffer and only then updates virLogLen and virLogStart
     * so it's best to reset it first.
     */
    oldLogStart = virLogStart;
    oldLogLen = virLogLen;
    virLogEnd = 0;
    virLogLen = 0;
    virLogStart = 0;

    while (oldLogLen > 0) {
        if (oldLogStart + oldLogLen < virLogSize) {
            virLogBuffer[oldLogStart + oldLogLen] = 0;
            virLogDumpAllFD(&virLogBuffer[oldLogStart], oldLogLen);
            oldLogStart += oldLogLen;
            oldLogLen = 0;
        } else {
            len = virLogSize - oldLogStart;
            virLogBuffer[virLogSize] = 0;
            virLogDumpAllFD(&virLogBuffer[oldLogStart], len);
            oldLogLen -= len;
            oldLogStart = 0;
        }
    }
    virLogDumpAllFD("\n\n     ====== end of log =====\n\n", -1);
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
        VIR_WARN("Ignoring invalid log level setting.");
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
 *
 * Returns the number of filters removed
 */
static int
virLogResetFilters(void)
{
    size_t i;

    for (i = 0; i < virLogNbFilters; i++)
        VIR_FREE(virLogFilters[i].match);
    VIR_FREE(virLogFilters);
    virLogNbFilters = 0;
    return i;
}


/**
 * virLogDefineFilter:
 * @match: the pattern to match
 * @priority: the priority to give to messages matching the pattern
 * @flags: extra flags, see virLogFilterFlags enum
 *
 * Defines a pattern used for log filtering, it allow to select or
 * reject messages independently of the default priority.
 * The filter defines a rules that will apply only to messages matching
 * the pattern (currently if @match is a substring of the message category)
 *
 * Returns -1 in case of failure or the filter number if successful
 */
int
virLogDefineFilter(const char *match,
                   virLogPriority priority,
                   unsigned int flags)
{
    size_t i;
    int ret = -1;
    char *mdup = NULL;

    virCheckFlags(VIR_LOG_STACK_TRACE, -1);

    if (virLogInitialize() < 0)
        return -1;

    if ((match == NULL) || (priority < VIR_LOG_DEBUG) ||
        (priority > VIR_LOG_ERROR))
        return -1;

    virLogLock();
    for (i = 0; i < virLogNbFilters; i++) {
        if (STREQ(virLogFilters[i].match, match)) {
            virLogFilters[i].priority = priority;
            ret = i;
            goto cleanup;
        }
    }

    if (VIR_STRDUP_QUIET(mdup, match) < 0)
        goto cleanup;
    if (VIR_REALLOC_N_QUIET(virLogFilters, virLogNbFilters + 1)) {
        VIR_FREE(mdup);
        goto cleanup;
    }
    ret = virLogNbFilters;
    virLogFilters[i].match = mdup;
    virLogFilters[i].priority = priority;
    virLogFilters[i].flags = flags;
    virLogNbFilters++;
cleanup:
    virLogUnlock();
    if (ret < 0)
        virReportOOMError();
    return ret;
}


/**
 * virLogFiltersCheck:
 * @input: the input string
 *
 * Check the input of the message against the existing filters. Currently
 * the match is just a substring check of the category used as the input
 * string, a more subtle approach could be used instead
 *
 * Returns 0 if not matched or the new priority if found.
 */
static int
virLogFiltersCheck(const char *input,
                   unsigned int *flags)
{
    int ret = 0;
    size_t i;

    virLogLock();
    for (i = 0; i < virLogNbFilters; i++) {
        if (strstr(input, virLogFilters[i].match)) {
            ret = virLogFilters[i].priority;
            *flags = virLogFilters[i].flags;
            break;
        }
    }
    virLogUnlock();
    return ret;
}


/**
 * virLogResetOutputs:
 *
 * Removes the set of logging output defined.
 *
 * Returns the number of output removed
 */
static int
virLogResetOutputs(void)
{
    size_t i;

    for (i = 0; i < virLogNbOutputs; i++) {
        if (virLogOutputs[i].c != NULL)
            virLogOutputs[i].c(virLogOutputs[i].data);
        VIR_FREE(virLogOutputs[i].name);
    }
    VIR_FREE(virLogOutputs);
    i = virLogNbOutputs;
    virLogNbOutputs = 0;
    return i;
}


/**
 * virLogDefineOutput:
 * @f: the function to call to output a message
 * @c: the function to call to close the output (or NULL)
 * @data: extra data passed as first arg to the function
 * @priority: minimal priority for this filter, use 0 for none
 * @dest: where to send output of this priority
 * @name: optional name data associated with an output
 * @flags: extra flag, currently unused
 *
 * Defines an output function for log messages. Each message once
 * gone though filtering is emitted through each registered output.
 *
 * Returns -1 in case of failure or the output number if successful
 */
int
virLogDefineOutput(virLogOutputFunc f,
                   virLogCloseFunc c,
                   void *data,
                   virLogPriority priority,
                   virLogDestination dest,
                   const char *name,
                   unsigned int flags)
{
    int ret = -1;
    char *ndup = NULL;

    virCheckFlags(0, -1);

    if (virLogInitialize() < 0)
        return -1;

    if (f == NULL)
        return -1;

    if (dest == VIR_LOG_TO_SYSLOG || dest == VIR_LOG_TO_FILE) {
        if (!name) {
            virReportOOMError();
            return -1;
        }
        if (VIR_STRDUP(ndup, name) < 0)
            return -1;
    }

    virLogLock();
    if (VIR_REALLOC_N_QUIET(virLogOutputs, virLogNbOutputs + 1)) {
        VIR_FREE(ndup);
        goto cleanup;
    }
    ret = virLogNbOutputs++;
    virLogOutputs[ret].logVersion = true;
    virLogOutputs[ret].f = f;
    virLogOutputs[ret].c = c;
    virLogOutputs[ret].data = data;
    virLogOutputs[ret].priority = priority;
    virLogOutputs[ret].dest = dest;
    virLogOutputs[ret].name = ndup;
cleanup:
    virLogUnlock();
    return ret;
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
#ifdef PACKAGER_VERSION
# ifdef PACKAGER
#  define LOG_VERSION_STRING \
    "libvirt version: " VERSION ", package: " PACKAGER_VERSION " (" PACKAGER ")"
# else
#  define LOG_VERSION_STRING \
    "libvirt version: " VERSION ", package: " PACKAGER_VERSION
# endif
#else
# define LOG_VERSION_STRING  \
    "libvirt version: " VERSION
#endif

    *rawmsg = LOG_VERSION_STRING;
    return virLogFormatString(msg, 0, NULL, VIR_LOG_INFO, LOG_VERSION_STRING);
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
virLogMessage(virLogSource source,
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
virLogVMessage(virLogSource source,
               virLogPriority priority,
               const char *filename,
               int linenr,
               const char *funcname,
               virLogMetadataPtr metadata,
               const char *fmt,
               va_list vargs)
{
    static bool logVersionStderr = true;
    char *str = NULL;
    char *msg = NULL;
    char timestamp[VIR_TIME_STRING_BUFLEN];
    int fprio, ret;
    size_t i;
    int saved_errno = errno;
    bool emit = true;
    unsigned int filterflags = 0;

    if (virLogInitialize() < 0)
        return;

    if (fmt == NULL)
        goto cleanup;

    /*
     * check against list of specific logging patterns
     */
    fprio = virLogFiltersCheck(filename, &filterflags);
    if (fprio == 0) {
        if (priority < virLogDefaultPriority)
            emit = false;
    } else if (priority < fprio) {
        emit = false;
    }

    if (!emit && ((virLogBuffer == NULL) || (virLogSize <= 0)))
        goto cleanup;

    /*
     * serialize the error message, add level and timestamp
     */
    if (virVasprintfQuiet(&str, fmt, vargs) < 0) {
        goto cleanup;
    }

    ret = virLogFormatString(&msg, linenr, funcname, priority, str);
    if (ret < 0)
        goto cleanup;

    if (virTimeStringNowRaw(timestamp) < 0)
        timestamp[0] = '\0';

    /*
     * Log based on defaults, first store in the history buffer,
     * then if emit push the message on the outputs defined, if none
     * use stderr.
     * NOTE: the locking is a single point of contention for multiple
     *       threads, but avoid intermixing. Maybe set up locks per output
     *       to improve paralellism.
     */
    virLogLock();
    virLogStr(timestamp);
    virLogStr(": ");
    virLogStr(msg);
    virLogUnlock();
    if (!emit)
        goto cleanup;

    virLogLock();
    for (i = 0; i < virLogNbOutputs; i++) {
        if (priority >= virLogOutputs[i].priority) {
            if (virLogOutputs[i].logVersion) {
                const char *rawver;
                char *ver = NULL;
                if (virLogVersionString(&rawver, &ver) >= 0)
                    virLogOutputs[i].f(VIR_LOG_FROM_FILE, VIR_LOG_INFO,
                                       __FILE__, __LINE__, __func__,
                                       timestamp, NULL, 0, rawver, ver,
                                       virLogOutputs[i].data);
                VIR_FREE(ver);
                virLogOutputs[i].logVersion = false;
            }
            virLogOutputs[i].f(source, priority,
                               filename, linenr, funcname,
                               timestamp, metadata, filterflags,
                               str, msg, virLogOutputs[i].data);
        }
    }
    if ((virLogNbOutputs == 0) && (source != VIR_LOG_FROM_ERROR)) {
        if (logVersionStderr) {
            const char *rawver;
            char *ver = NULL;
            if (virLogVersionString(&rawver, &ver) >= 0)
                virLogOutputToFd(VIR_LOG_FROM_FILE, VIR_LOG_INFO,
                                 __FILE__, __LINE__, __func__,
                                 timestamp, NULL, 0, rawver, ver,
                                 (void *) STDERR_FILENO);
            VIR_FREE(ver);
            logVersionStderr = false;
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
    static bool doneWarning = false;
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
virLogOutputToFd(virLogSource source ATTRIBUTE_UNUSED,
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


static int
virLogAddOutputToStderr(virLogPriority priority)
{
    if (virLogDefineOutput(virLogOutputToFd, NULL, (void *)2L, priority,
                           VIR_LOG_TO_STDERR, NULL, 0) < 0)
        return -1;
    return 0;
}


static int
virLogAddOutputToFile(virLogPriority priority,
                      const char *file)
{
    int fd;

    fd = open(file, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return -1;
    if (virLogDefineOutput(virLogOutputToFd, virLogCloseFd,
                           (void *)(intptr_t)fd,
                           priority, VIR_LOG_TO_FILE, file, 0) < 0) {
        VIR_FORCE_CLOSE(fd);
        return -1;
    }
    return 0;
}


#if HAVE_SYSLOG_H
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


static void
virLogOutputToSyslog(virLogSource source ATTRIBUTE_UNUSED,
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

static char *current_ident = NULL;


static void
virLogCloseSyslog(void *data ATTRIBUTE_UNUSED)
{
    closelog();
    VIR_FREE(current_ident);
}


static int
virLogAddOutputToSyslog(virLogPriority priority,
                        const char *ident)
{
    /*
     * ident needs to be kept around on Solaris
     */
    VIR_FREE(current_ident);
    if (VIR_STRDUP(current_ident, ident) < 0)
        return -1;

    openlog(current_ident, 0, 0);
    if (virLogDefineOutput(virLogOutputToSyslog, virLogCloseSyslog, NULL,
                           priority, VIR_LOG_TO_SYSLOG, ident, 0) < 0) {
        closelog();
        VIR_FREE(current_ident);
        return -1;
    }
    return 0;
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

static int journalfd = -1;

static void
virLogOutputToJournald(virLogSource source,
                       virLogPriority priority,
                       const char *filename,
                       int linenr,
                       const char *funcname,
                       const char *timestamp ATTRIBUTE_UNUSED,
                       virLogMetadataPtr metadata ATTRIBUTE_UNUSED,
                       unsigned int flags,
                       const char *rawstr,
                       const char *str ATTRIBUTE_UNUSED,
                       void *data ATTRIBUTE_UNUSED)
{
    virCheckFlags(VIR_LOG_STACK_TRACE,);
    int buffd = -1;
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

#  define NUM_FIELDS 6
    struct iovec iov[NUM_FIELDS * 5];
    char iov_bufs[NUM_FIELDS][JOURNAL_BUF_SIZE];
    struct journalState state;

    state.iov = iov;
    state.iov_end = iov + ARRAY_CARDINALITY(iov);
    state.bufs = iov_bufs;
    state.bufs_end = iov_bufs + ARRAY_CARDINALITY(iov_bufs);

    journalAddString(&state, "MESSAGE", rawstr);
    journalAddInt(&state, "PRIORITY", priority);
    journalAddString(&state, "LIBVIRT_SOURCE",
                     virLogSourceTypeToString(source));
    if (filename)
        journalAddString(&state, "CODE_FILE", filename);
    journalAddInt(&state, "CODE_LINE", linenr);
    if (funcname)
        journalAddString(&state, "CODE_FUNC", funcname);

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

    sendmsg(journalfd, &mh, MSG_NOSIGNAL);

cleanup:
    VIR_LOG_CLOSE(buffd);
}


static void virLogCloseJournald(void *data ATTRIBUTE_UNUSED)
{
    VIR_LOG_CLOSE(journalfd);
}


static int virLogAddOutputToJournald(int priority)
{
    if ((journalfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        return -1;
    if (virSetInherit(journalfd, false) < 0) {
        VIR_LOG_CLOSE(journalfd);
        return -1;
    }
    if (virLogDefineOutput(virLogOutputToJournald, virLogCloseJournald, NULL,
                           priority, VIR_LOG_TO_JOURNALD, NULL, 0) < 0) {
        return -1;
    }
    return 0;
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

#define IS_SPACE(cur)                                                   \
    ((*cur == ' ') || (*cur == '\t') || (*cur == '\n') ||               \
     (*cur == '\r') || (*cur == '\\'))


/**
 * virLogParseOutputs:
 * @outputs: string defining a (set of) output(s)
 *
 * The format for an output can be:
 *    x:stderr
 *       output goes to stderr
 *    x:syslog:name
 *       use syslog for the output and use the given name as the ident
 *    x:file:file_path
 *       output to a file, with the given filepath
 * In all case the x prefix is the minimal level, acting as a filter
 *    1: DEBUG
 *    2: INFO
 *    3: WARNING
 *    4: ERROR
 *
 * Multiple output can be defined in a single @output, they just need to be
 * separated by spaces.
 *
 * If running in setuid mode, then only the 'stderr' output will
 * be allowed
 *
 * Returns the number of output parsed and installed or -1 in case of error
 */
int
virLogParseOutputs(const char *outputs)
{
    const char *cur = outputs, *str;
    char *name;
    char *abspath;
    virLogPriority prio;
    int ret = -1;
    int count = 0;
    bool isSUID = virIsSUID();

    if (cur == NULL)
        return -1;

    VIR_DEBUG("outputs=%s", outputs);

    virSkipSpaces(&cur);
    while (*cur != 0) {
        prio= virParseNumber(&cur);
        if ((prio < VIR_LOG_DEBUG) || (prio > VIR_LOG_ERROR))
            goto cleanup;
        if (*cur != ':')
            goto cleanup;
        cur++;
        if (STREQLEN(cur, "stderr", 6)) {
            cur += 6;
            if (virLogAddOutputToStderr(prio) == 0)
                count++;
        } else if (STREQLEN(cur, "syslog", 6)) {
            if (isSUID)
                goto cleanup;
            cur += 6;
            if (*cur != ':')
                goto cleanup;
            cur++;
            str = cur;
            while ((*cur != 0) && (!IS_SPACE(cur)))
                cur++;
            if (str == cur)
                goto cleanup;
#if HAVE_SYSLOG_H
            if (VIR_STRNDUP(name, str, cur - str) < 0)
                goto cleanup;
            if (virLogAddOutputToSyslog(prio, name) == 0)
                count++;
            VIR_FREE(name);
#endif /* HAVE_SYSLOG_H */
        } else if (STREQLEN(cur, "file", 4)) {
            if (isSUID)
                goto cleanup;
            cur += 4;
            if (*cur != ':')
                goto cleanup;
            cur++;
            str = cur;
            while ((*cur != 0) && (!IS_SPACE(cur)))
                cur++;
            if (str == cur)
                goto cleanup;
            if (VIR_STRNDUP(name, str, cur - str) < 0)
                goto cleanup;
            if (virFileAbsPath(name, &abspath) < 0) {
                VIR_FREE(name);
                return -1; /* skip warning here because setting was fine */
            }
            if (virLogAddOutputToFile(prio, abspath) == 0)
                count++;
            VIR_FREE(name);
            VIR_FREE(abspath);
        } else if (STREQLEN(cur, "journald", 8)) {
            if (isSUID)
                goto cleanup;
            cur += 8;
#if USE_JOURNALD
            if (virLogAddOutputToJournald(prio) == 0)
                count++;
#endif /* USE_JOURNALD */
        } else {
            goto cleanup;
        }
        virSkipSpaces(&cur);
    }
    ret = count;
cleanup:
    if (ret == -1)
        VIR_WARN("Ignoring invalid log output setting.");
    return ret;
}


/**
 * virLogParseFilters:
 * @filters: string defining a (set of) filter(s)
 *
 * The format for a filter is:
 *    x:name
 *       where name is a match string
 * the x prefix is the minimal level where the messages should be logged
 *    1: DEBUG
 *    2: INFO
 *    3: WARNING
 *    4: ERROR
 *
 * Multiple filter can be defined in a single @filters, they just need to be
 * separated by spaces.
 *
 * Returns the number of filter parsed and installed or -1 in case of error
 */
int
virLogParseFilters(const char *filters)
{
    const char *cur = filters, *str;
    char *name;
    virLogPriority prio;
    int ret = -1;
    int count = 0;

    if (cur == NULL)
        return -1;

    virSkipSpaces(&cur);
    while (*cur != 0) {
        unsigned int flags = 0;
        prio= virParseNumber(&cur);
        if ((prio < VIR_LOG_DEBUG) || (prio > VIR_LOG_ERROR))
            goto cleanup;
        if (*cur != ':')
            goto cleanup;
        cur++;
        if (*cur == '+') {
            flags |= VIR_LOG_STACK_TRACE;
            cur++;
        }
        str = cur;
        while ((*cur != 0) && (!IS_SPACE(cur)))
            cur++;
        if (str == cur)
            goto cleanup;
        if (VIR_STRNDUP(name, str, cur - str) < 0)
            goto cleanup;
        if (virLogDefineFilter(name, prio, flags) >= 0)
            count++;
        VIR_FREE(name);
        virSkipSpaces(&cur);
    }
    ret = count;
cleanup:
    if (ret == -1)
        VIR_WARN("Ignoring invalid log filter setting.");
    return ret;
}


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
        if (virLogFilters[i].flags & VIR_LOG_STACK_TRACE)
            sep = ":+";
        virBufferAsprintf(&filterbuf, "%d%s%s ",
                          virLogFilters[i].priority,
                          sep,
                          virLogFilters[i].match);
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
        virLogDestination dest = virLogOutputs[i].dest;
        if (i)
            virBufferAddChar(&outputbuf, ' ');
        switch (dest) {
            case VIR_LOG_TO_SYSLOG:
            case VIR_LOG_TO_FILE:
                virBufferAsprintf(&outputbuf, "%d:%s:%s",
                                  virLogOutputs[i].priority,
                                  virLogOutputString(dest),
                                  virLogOutputs[i].name);
                break;
            default:
                virBufferAsprintf(&outputbuf, "%d:%s",
                                  virLogOutputs[i].priority,
                                  virLogOutputString(dest));
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
 * @priority: string defining the desired logging level
 *
 * Parses and sets the default log priority level. It can take a string or
 * number corresponding to the following levels:
 *    1: DEBUG
 *    2: INFO
 *    3: WARNING
 *    4: ERROR
 *
 * Returns the parsed log level or -1 on error.
 */
int
virLogParseDefaultPriority(const char *priority)
{
    int ret = -1;

    if (STREQ(priority, "1") || STREQ(priority, "debug"))
        ret = virLogSetDefaultPriority(VIR_LOG_DEBUG);
    else if (STREQ(priority, "2") || STREQ(priority, "info"))
        ret = virLogSetDefaultPriority(VIR_LOG_INFO);
    else if (STREQ(priority, "3") || STREQ(priority, "warning"))
        ret = virLogSetDefaultPriority(VIR_LOG_WARN);
    else if (STREQ(priority, "4") || STREQ(priority, "error"))
        ret = virLogSetDefaultPriority(VIR_LOG_ERROR);
    else
        VIR_WARN("Ignoring invalid log level setting");

    return ret;
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
        virLogParseDefaultPriority(debugEnv);
    debugEnv = virGetEnvAllowSUID("LIBVIRT_LOG_FILTERS");
    if (debugEnv && *debugEnv)
        virLogParseFilters(debugEnv);
    debugEnv = virGetEnvAllowSUID("LIBVIRT_LOG_OUTPUTS");
    if (debugEnv && *debugEnv)
        virLogParseOutputs(debugEnv);
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
