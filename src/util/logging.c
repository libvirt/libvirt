/*
 * logging.c: internal logging and debugging
 *
 * Copyright (C) 2008, 2010-2012 Red Hat, Inc.
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
#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "ignore-value.h"
#include "virterror_internal.h"
#include "logging.h"
#include "memory.h"
#include "util.h"
#include "buf.h"
#include "threads.h"
#include "virfile.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/*
 * A logging buffer to keep some history over logs
 */

static int virLogSize = 64 * 1024;
static char *virLogBuffer = NULL;
static int virLogLen = 0;
static int virLogStart = 0;
static int virLogEnd = 0;

/*
 * Filters are used to refine the rules on what to keep or drop
 * based on a matching pattern (currently a substring)
 */
struct _virLogFilter {
    const char *match;
    int priority;
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
    int priority;
    virLogDestination dest;
    const char *name;
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
static int virLogOutputToFd(const char *category, int priority,
                            const char *funcname, long long linenr,
                            const char *timestamp, const char *str,
                            void *data);

/*
 * Logs accesses must be serialized though a mutex
 */
virMutex virLogMutex;

void virLogLock(void)
{
    virMutexLock(&virLogMutex);
}
void virLogUnlock(void)
{
    virMutexUnlock(&virLogMutex);
}

static const char *virLogOutputString(virLogDestination ldest) {
    switch (ldest) {
    case VIR_LOG_TO_STDERR:
        return "stderr";
    case VIR_LOG_TO_SYSLOG:
        return "syslog";
    case VIR_LOG_TO_FILE:
        return "file";
    }
    return "unknown";
}

static const char *virLogPriorityString(virLogPriority lvl) {
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

static int virLogInitialized = 0;

/**
 * virLogStartup:
 *
 * Initialize the logging module
 *
 * Returns 0 if successful, and -1 in case or error
 */
int virLogStartup(void) {
    const char *pbm = NULL;

    if (virLogInitialized)
        return -1;

    if (virMutexInit(&virLogMutex) < 0)
        return -1;

    virLogInitialized = 1;
    virLogLock();
    if (VIR_ALLOC_N(virLogBuffer, virLogSize + 1) < 0) {
        /*
         * The debug buffer is not a critical component, allow startup
         * even in case of failure to allocate it in case of a
         * configuration mistake.
         */
        virLogSize = 64 * 1024;
        if (VIR_ALLOC_N(virLogBuffer, virLogSize + 1) < 0) {
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
    virLogUnlock();
    if (pbm)
        VIR_WARN("%s", pbm);
    return 0;
}

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
extern int
virLogSetBufferSize(int size) {
    int ret = 0;
    int oldsize;
    char *oldLogBuffer;
    const char *pbm = NULL;

    if (size < 0)
        size = 0;

    if ((virLogInitialized == 0) || (size * 1024 == virLogSize))
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
    if (VIR_ALLOC_N(virLogBuffer, virLogSize + 1) < 0) {
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
int virLogReset(void) {
    if (!virLogInitialized)
        return virLogStartup();

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
/**
 * virLogShutdown:
 *
 * Shutdown the logging module
 */
void virLogShutdown(void) {
    if (!virLogInitialized)
        return;
    virLogLock();
    virLogResetFilters();
    virLogResetOutputs();
    virLogLen = 0;
    virLogStart = 0;
    virLogEnd = 0;
    VIR_FREE(virLogBuffer);
    virLogUnlock();
    virMutexDestroy(&virLogMutex);
    virLogInitialized = 0;
}

/*
 * Store a string in the ring buffer
 */
static void virLogStr(const char *str)
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

static void virLogDumpAllFD(const char *msg, int len) {
    int i, found = 0;

    if (len <= 0)
        len = strlen(msg);

    for (i = 0; i < virLogNbOutputs;i++) {
        if (virLogOutputs[i].f == virLogOutputToFd) {
            int fd = (intptr_t) virLogOutputs[i].data;

            if (fd >= 0) {
                ignore_value (safewrite(fd, msg, len));
                found = 1;
            }
        }
    }
    if (!found)
        ignore_value (safewrite(STDERR_FILENO, msg, len));
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
virLogEmergencyDumpAll(int signum) {
    int len;
    int oldLogStart, oldLogLen;

    switch (signum) {
#ifdef SIGFPE
        case SIGFPE:
            virLogDumpAllFD( "Caught signal Floating-point exception", -1);
            break;
#endif
#ifdef SIGSEGV
        case SIGSEGV:
            virLogDumpAllFD( "Caught Segmentation violation", -1);
            break;
#endif
#ifdef SIGILL
        case SIGILL:
            virLogDumpAllFD( "Caught illegal instruction", -1);
            break;
#endif
#ifdef SIGABRT
        case SIGABRT:
            virLogDumpAllFD( "Caught abort signal", -1);
            break;
#endif
#ifdef SIGBUS
        case SIGBUS:
            virLogDumpAllFD( "Caught bus error", -1);
            break;
#endif
#ifdef SIGUSR2
        case SIGUSR2:
            virLogDumpAllFD( "Caught User-defined signal 2", -1);
            break;
#endif
        default:
            virLogDumpAllFD( "Caught unexpected signal", -1);
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
int virLogSetDefaultPriority(int priority) {
    if ((priority < VIR_LOG_DEBUG) || (priority > VIR_LOG_ERROR)) {
        VIR_WARN("Ignoring invalid log level setting.");
        return -1;
    }
    if (!virLogInitialized)
        virLogStartup();
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
static int virLogResetFilters(void) {
    int i;

    for (i = 0; i < virLogNbFilters;i++)
        VIR_FREE(virLogFilters[i].match);
    VIR_FREE(virLogFilters);
    virLogNbFilters = 0;
    return i;
}

/**
 * virLogDefineFilter:
 * @match: the pattern to match
 * @priority: the priority to give to messages matching the pattern
 * @flags: extra flag, currently unused
 *
 * Defines a pattern used for log filtering, it allow to select or
 * reject messages independently of the default priority.
 * The filter defines a rules that will apply only to messages matching
 * the pattern (currently if @match is a substring of the message category)
 *
 * Returns -1 in case of failure or the filter number if successful
 */
int virLogDefineFilter(const char *match, int priority,
                       unsigned int flags)
{
    int i;
    char *mdup = NULL;

    virCheckFlags(0, -1);

    if ((match == NULL) || (priority < VIR_LOG_DEBUG) ||
        (priority > VIR_LOG_ERROR))
        return -1;

    virLogLock();
    for (i = 0;i < virLogNbFilters;i++) {
        if (STREQ(virLogFilters[i].match, match)) {
            virLogFilters[i].priority = priority;
            goto cleanup;
        }
    }

    mdup = strdup(match);
    if (mdup == NULL) {
        i = -1;
        goto cleanup;
    }
    i = virLogNbFilters;
    if (VIR_REALLOC_N(virLogFilters, virLogNbFilters + 1)) {
        i = -1;
        VIR_FREE(mdup);
        goto cleanup;
    }
    virLogFilters[i].match = mdup;
    virLogFilters[i].priority = priority;
    virLogNbFilters++;
cleanup:
    virLogUnlock();
    return i;
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
static int virLogFiltersCheck(const char *input) {
    int ret = 0;
    int i;

    virLogLock();
    for (i = 0;i < virLogNbFilters;i++) {
        if (strstr(input, virLogFilters[i].match)) {
            ret = virLogFilters[i].priority;
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
static int virLogResetOutputs(void) {
    int i;

    for (i = 0;i < virLogNbOutputs;i++) {
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
int virLogDefineOutput(virLogOutputFunc f, virLogCloseFunc c, void *data,
                       int priority, int dest, const char *name,
                       unsigned int flags)
{
    int ret = -1;
    char *ndup = NULL;

    virCheckFlags(0, -1);

    if (f == NULL)
        return -1;

    if (dest == VIR_LOG_TO_SYSLOG || dest == VIR_LOG_TO_FILE) {
        if (name == NULL)
            return -1;
        ndup = strdup(name);
        if (ndup == NULL)
            return -1;
    }

    virLogLock();
    if (VIR_REALLOC_N(virLogOutputs, virLogNbOutputs + 1)) {
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
                   const char *funcname,
                   long long linenr,
                   int priority,
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
        ret = virAsprintf(msg, "%d: %s : %s:%lld : %s\n",
                          virThreadSelfID(), virLogPriorityString(priority),
                          funcname, linenr, str);
    } else {
        ret = virAsprintf(msg, "%d: %s : %s\n",
                          virThreadSelfID(), virLogPriorityString(priority),
                          str);
    }
    return ret;
}

static int
virLogVersionString(char **msg)
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

    return virLogFormatString(msg, NULL, 0, VIR_LOG_INFO, LOG_VERSION_STRING);
}

/**
 * virLogMessage:
 * @category: where is that message coming from
 * @priority: the priority level
 * @funcname: the function emitting the (debug) message
 * @linenr: line where the message was emitted
 * @flags: extra flags, 1 if coming from the error handler
 * @fmt: the string format
 * @...: the arguments
 *
 * Call the libvirt logger with some information. Based on the configuration
 * the message may be stored, sent to output or just discarded
 */
void virLogMessage(const char *category, int priority, const char *funcname,
                   long long linenr, unsigned int flags, const char *fmt, ...)
{
    static bool logVersionStderr = true;
    char *str = NULL;
    char *msg = NULL;
    char timestamp[VIR_TIME_STRING_BUFLEN];
    int fprio, i, ret;
    int saved_errno = errno;
    int emit = 1;
    va_list ap;

    if (!virLogInitialized)
        virLogStartup();

    if (fmt == NULL)
        goto cleanup;

    /*
     * check against list of specific logging patterns
     */
    fprio = virLogFiltersCheck(category);
    if (fprio == 0) {
        if (priority < virLogDefaultPriority)
            emit = 0;
    } else if (priority < fprio) {
        emit = 0;
    }

    if ((emit == 0) && ((virLogBuffer == NULL) || (virLogSize <= 0)))
        goto cleanup;

    /*
     * serialize the error message, add level and timestamp
     */
    va_start(ap, fmt);
    if (virVasprintf(&str, fmt, ap) < 0) {
        va_end(ap);
        goto cleanup;
    }
    va_end(ap);

    ret = virLogFormatString(&msg, funcname, linenr, priority, str);
    VIR_FREE(str);
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
    virLogStr(msg);
    virLogUnlock();
    if (emit == 0)
        goto cleanup;

    virLogLock();
    for (i = 0; i < virLogNbOutputs; i++) {
        if (priority >= virLogOutputs[i].priority) {
            if (virLogOutputs[i].logVersion) {
                char *ver = NULL;
                if (virLogVersionString(&ver) >= 0)
                    virLogOutputs[i].f(category, VIR_LOG_INFO,
                                       __func__, __LINE__,
                                       timestamp, ver,
                                       virLogOutputs[i].data);
                VIR_FREE(ver);
                virLogOutputs[i].logVersion = false;
            }
            virLogOutputs[i].f(category, priority, funcname, linenr,
                               timestamp, msg, virLogOutputs[i].data);
        }
    }
    if ((virLogNbOutputs == 0) && (flags != 1)) {
        if (logVersionStderr) {
            char *ver = NULL;
            if (virLogVersionString(&ver) >= 0)
                virLogOutputToFd(category, VIR_LOG_INFO,
                                 __func__, __LINE__,
                                 timestamp, ver,
                                 (void *) STDERR_FILENO);
            VIR_FREE(ver);
            logVersionStderr = false;
        }
        virLogOutputToFd(category, priority, funcname, linenr,
                         timestamp, msg, (void *) STDERR_FILENO);
    }
    virLogUnlock();

cleanup:
    VIR_FREE(msg);
    errno = saved_errno;
}

static int virLogOutputToFd(const char *category ATTRIBUTE_UNUSED,
                            int priority ATTRIBUTE_UNUSED,
                            const char *funcname ATTRIBUTE_UNUSED,
                            long long linenr ATTRIBUTE_UNUSED,
                            const char *timestamp,
                            const char *str,
                            void *data)
{
    int fd = (intptr_t) data;
    int ret;
    char *msg;

    if (fd < 0)
        return -1;

    if (virAsprintf(&msg, "%s: %s", timestamp, str) < 0)
        return -1;

    ret = safewrite(fd, msg, strlen(msg));
    VIR_FREE(msg);

    return ret;
}

static void virLogCloseFd(void *data) {
    int fd = (intptr_t) data;

    VIR_FORCE_CLOSE(fd);
}

static int virLogAddOutputToStderr(int priority) {
    if (virLogDefineOutput(virLogOutputToFd, NULL, (void *)2L, priority,
                           VIR_LOG_TO_STDERR, NULL, 0) < 0)
        return -1;
    return 0;
}

static int virLogAddOutputToFile(int priority, const char *file) {
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
static int virLogOutputToSyslog(const char *category ATTRIBUTE_UNUSED,
                                int priority,
                                const char *funcname ATTRIBUTE_UNUSED,
                                long long linenr ATTRIBUTE_UNUSED,
                                const char *timestamp ATTRIBUTE_UNUSED,
                                const char *str,
                                void *data ATTRIBUTE_UNUSED)
{
    int prio;

    switch (priority) {
        case VIR_LOG_DEBUG:
            prio = LOG_DEBUG;
            break;
        case VIR_LOG_INFO:
            prio = LOG_INFO;
            break;
        case VIR_LOG_WARN:
            prio = LOG_WARNING;
            break;
        case VIR_LOG_ERROR:
            prio = LOG_ERR;
            break;
        default:
            prio = LOG_ERR;
    }
    syslog(prio, "%s", str);
    return strlen(str);
}

static char *current_ident = NULL;

static void virLogCloseSyslog(void *data ATTRIBUTE_UNUSED) {
    closelog();
    VIR_FREE(current_ident);
}

static int virLogAddOutputToSyslog(int priority, const char *ident) {
    /*
     * ident needs to be kept around on Solaris
     */
    VIR_FREE(current_ident);
    current_ident = strdup(ident);
    if (current_ident == NULL)
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
 *    0: everything
 *    1: DEBUG
 *    2: INFO
 *    3: WARNING
 *    4: ERROR
 *
 * Multiple output can be defined in a single @output, they just need to be
 * separated by spaces.
 *
 * Returns the number of output parsed and installed or -1 in case of error
 */
int virLogParseOutputs(const char *outputs) {
    const char *cur = outputs, *str;
    char *name;
    char *abspath;
    int prio;
    int ret = -1;
    int count = 0;

    if (cur == NULL)
        return -1;

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
            name = strndup(str, cur - str);
            if (name == NULL)
                goto cleanup;
            if (virLogAddOutputToSyslog(prio, name) == 0)
                count++;
            VIR_FREE(name);
#endif /* HAVE_SYSLOG_H */
        } else if (STREQLEN(cur, "file", 4)) {
            cur += 4;
            if (*cur != ':')
                goto cleanup;
            cur++;
            str = cur;
            while ((*cur != 0) && (!IS_SPACE(cur)))
                cur++;
            if (str == cur)
                goto cleanup;
            name = strndup(str, cur - str);
            if (name == NULL)
                goto cleanup;
            if (virFileAbsPath(name, &abspath) < 0) {
                VIR_FREE(name);
                return -1; /* skip warning here because setting was fine */
            }
            if (virLogAddOutputToFile(prio, abspath) == 0)
                count++;
            VIR_FREE(name);
            VIR_FREE(abspath);
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
int virLogParseFilters(const char *filters) {
    const char *cur = filters, *str;
    char *name;
    int prio;
    int ret = -1;
    int count = 0;

    if (cur == NULL)
        return -1;

    virSkipSpaces(&cur);
    while (*cur != 0) {
        prio= virParseNumber(&cur);
        if ((prio < VIR_LOG_DEBUG) || (prio > VIR_LOG_ERROR))
            goto cleanup;
        if (*cur != ':')
            goto cleanup;
        cur++;
        str = cur;
        while ((*cur != 0) && (!IS_SPACE(cur)))
            cur++;
        if (str == cur)
            goto cleanup;
        name = strndup(str, cur - str);
        if (name == NULL)
            goto cleanup;
        if (virLogDefineFilter(name, prio, 0) >= 0)
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
int virLogGetDefaultPriority(void) {
    return virLogDefaultPriority;
}

/**
 * virLogGetFilters:
 *
 * Returns a string listing the current filters, in the format originally
 * specified in the config file or environment. Caller must free the
 * result.
 */
char *virLogGetFilters(void) {
    int i;
    virBuffer filterbuf = VIR_BUFFER_INITIALIZER;

    virLogLock();
    for (i = 0; i < virLogNbFilters; i++) {
        virBufferAsprintf(&filterbuf, "%d:%s ", virLogFilters[i].priority,
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
char *virLogGetOutputs(void) {
    int i;
    virBuffer outputbuf = VIR_BUFFER_INITIALIZER;

    virLogLock();
    for (i = 0; i < virLogNbOutputs; i++) {
        int dest = virLogOutputs[i].dest;
        if (i)
            virBufferAsprintf(&outputbuf, " ");
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
int virLogGetNbFilters(void) {
    return virLogNbFilters;
}

/**
 * virLogGetNbOutputs:
 *
 * Returns the current number of defined log outputs.
 */
int virLogGetNbOutputs(void) {
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
int virLogParseDefaultPriority(const char *priority) {
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
void virLogSetFromEnv(void) {
    char *debugEnv;

    debugEnv = getenv("LIBVIRT_DEBUG");
    if (debugEnv && *debugEnv)
        virLogParseDefaultPriority(debugEnv);
    debugEnv = getenv("LIBVIRT_LOG_FILTERS");
    if (debugEnv && *debugEnv)
        virLogParseFilters(debugEnv);
    debugEnv = getenv("LIBVIRT_LOG_OUTPUTS");
    if (debugEnv && *debugEnv)
        virLogParseOutputs(debugEnv);
}
