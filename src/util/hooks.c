/*
 * hooks.c: implementation of the synchronous hooks support
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2010 Daniel Veillard
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
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "virterror_internal.h"
#include "hooks.h"
#include "util.h"
#include "conf/domain_conf.h"
#include "logging.h"
#include "memory.h"
#include "files.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_HOOK

#define virHookReportError(code, ...)                              \
    virReportErrorHelper(NULL, VIR_FROM_HOOK, code, __FILE__,      \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#define LIBVIRT_HOOK_DIR SYSCONFDIR "/libvirt/hooks"

VIR_ENUM_DECL(virHookDriver)
VIR_ENUM_DECL(virHookDaemonOp)
VIR_ENUM_DECL(virHookSubop)
VIR_ENUM_DECL(virHookQemuOp)
VIR_ENUM_DECL(virHookLxcOp)

VIR_ENUM_IMPL(virHookDriver,
              VIR_HOOK_DRIVER_LAST,
              "daemon",
              "qemu",
              "lxc")

VIR_ENUM_IMPL(virHookDaemonOp, VIR_HOOK_DAEMON_OP_LAST,
              "start",
              "shutdown",
              "reload")

VIR_ENUM_IMPL(virHookSubop, VIR_HOOK_SUBOP_LAST,
              "-",
              "begin",
              "end")

VIR_ENUM_IMPL(virHookQemuOp, VIR_HOOK_QEMU_OP_LAST,
              "start",
              "stopped")

VIR_ENUM_IMPL(virHookLxcOp, VIR_HOOK_LXC_OP_LAST,
              "start",
              "stopped")

static int virHooksFound = -1;

/**
 * virHookCheck:
 * @driver: the driver name "daemon", "qemu", "lxc"...
 *
 * Check is there is an installed hook for the given driver, if this
 * is the case register it. Then subsequent calls to virHookCall
 * will call the hook if found.
 *
 * Returns 1 if found, 0 if not found, and -1 in case of error
 */
static int
virHookCheck(int no, const char *driver) {
    char *path;
    struct stat sb;
    int ret;

    if (driver == NULL) {
        virHookReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Invalid hook name for #%d"), no);
        return(-1);
    }

    ret = virBuildPath(&path, LIBVIRT_HOOK_DIR, driver);
    if ((ret < 0) || (path == NULL)) {
        virHookReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to build path for %s hook"),
                           driver);
        return(-1);
    }

    if (stat(path, &sb) < 0) {
        ret = 0;
        VIR_DEBUG("No hook script %s", path);
    } else {
        if ((access(path, X_OK) != 0) || (!S_ISREG(sb.st_mode))) {
            ret = 0;
            VIR_WARN("Non executable hook script %s", path);
        } else {
            ret = 1;
            VIR_DEBUG("Found hook script %s", path);
        }
    }

    VIR_FREE(path);
    return(ret);
}

/*
 * virHookInitialize:
 *
 * Initialize synchronous hooks support.
 * Check is there is an installed hook for all the drivers
 *
 * Returns the number of hooks found or -1 in case of failure
 */
int
virHookInitialize(void) {
    int i, res, ret = 0;

    virHooksFound = 0;
    for (i = 0;i < VIR_HOOK_DRIVER_LAST;i++) {
        res = virHookCheck(i, virHookDriverTypeToString(i));
        if (res < 0)
            return(-1);

        if (res == 1) {
            virHooksFound |= (1 << i);
            ret++;
        }
    }
    return(ret);
}

/**
 * virHookPresent:
 * @driver: the driver number (from virHookDriver enum)
 *
 * Check if a hook exists for the given driver, this is needed
 * to avoid unnecessary work if the hook is not present
 *
 * Returns 1 if present, 0 otherwise
 */
int
virHookPresent(int driver) {
    if ((driver < VIR_HOOK_DRIVER_DAEMON) ||
        (driver >= VIR_HOOK_DRIVER_LAST))
        return(0);
    if (virHooksFound == -1)
        return(0);

    if ((virHooksFound & (1 << driver)) == 0)
        return(0);
    return(1);
}

/*
 * virHookCall:
 * @driver: the driver number (from virHookDriver enum)
 * @id: an id for the object '-' if non available for example on daemon hooks
 * @op: the operation on the id e.g. VIR_HOOK_QEMU_OP_START
 * @sub_op: a sub_operation, currently unused
 * @extra: optional string information
 * @input: extra input given to the script on stdin
 *
 * Implement a hook call, where the external script for the driver is
 * called with the given information. This is a synchronous call, we wait for
 * execution completion
 *
 * Returns: 0 if the execution succeeded, 1 if the script was not found or
 *          invalid parameters, and -1 if script returned an error
 */
#ifdef WIN32
int
virHookCall(int driver ATTRIBUTE_UNUSED,
            const char *id ATTRIBUTE_UNUSED,
            int op ATTRIBUTE_UNUSED,
            int sub_op ATTRIBUTE_UNUSED,
            const char *extra ATTRIBUTE_UNUSED,
            const char *input ATTRIBUTE_UNUSED) {
    virReportSystemError(ENOSYS, "%s",
                         _("spawning hooks not supported on this platform"));
    return -1;
}
#else
int
virHookCall(int driver, const char *id, int op, int sub_op, const char *extra,
            const char *input) {
    int ret, waitret, exitstatus, i;
    char *path;
    int argc = 0, arga = 0;
    const char **argv = NULL;
    int envc = 0, enva = 0;
    const char **env = NULL;
    const char *drvstr;
    const char *opstr;
    const char *subopstr;
    pid_t pid;
    int outfd = -1, errfd = -1;
    int pipefd[2] = { -1, -1};
    char *outbuf = NULL;
    char *errbuf = NULL;

    if ((driver < VIR_HOOK_DRIVER_DAEMON) ||
        (driver >= VIR_HOOK_DRIVER_LAST))
        return(1);

    /*
     * We cache the availability of the script to minimize impact at
     * runtime if no script is defined, this is being reset on SIGHUP
     */
    if ((virHooksFound == -1) ||
        ((driver == VIR_HOOK_DRIVER_DAEMON) &&
         (op == VIR_HOOK_DAEMON_OP_RELOAD)))
        virHookInitialize();

    if ((virHooksFound & (1 << driver)) == 0)
        return(1);

    drvstr = virHookDriverTypeToString(driver);

    opstr = NULL;
    switch (driver) {
        case VIR_HOOK_DRIVER_DAEMON:
            opstr = virHookDaemonOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_QEMU:
            opstr = virHookQemuOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_LXC:
            opstr = virHookLxcOpTypeToString(op);
            break;
    }
    if (opstr == NULL) {
        virHookReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Hook for %s, failed to find operation #%d"),
                           drvstr, op);
        return(1);
    }
    subopstr = virHookSubopTypeToString(sub_op);
    if (subopstr == NULL)
        subopstr = "-";
    if (extra == NULL)
        extra = "-";

    ret = virBuildPath(&path, LIBVIRT_HOOK_DIR, drvstr);
    if ((ret < 0) || (path == NULL)) {
        virHookReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to build path for %s hook"),
                           drvstr);
        return(-1);
    }

    /*
     * Convenience macros borrowed from qemudBuildCommandLine()
     */
# define ADD_ARG_SPACE                                                   \
    do {                                                                \
        if (argc == arga) {                                             \
            arga += 10;                                                 \
            if (VIR_REALLOC_N(argv, arga) < 0)                          \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

# define ADD_ARG(thisarg)                                                \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        argv[argc++] = thisarg;                                         \
    } while (0)

# define ADD_ARG_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ARG_SPACE;                                                  \
        if ((argv[argc++] = strdup(thisarg)) == NULL)                   \
            goto no_memory;                                             \
    } while (0)

# define ADD_ENV_SPACE                                                   \
    do {                                                                \
        if (envc == enva) {                                             \
            enva += 10;                                                 \
            if (VIR_REALLOC_N(env, enva) < 0)                           \
                goto no_memory;                                         \
        }                                                               \
    } while (0)

# define ADD_ENV(thisarg)                                                \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        env[envc++] = thisarg;                                          \
    } while (0)

# define ADD_ENV_LIT(thisarg)                                            \
    do {                                                                \
        ADD_ENV_SPACE;                                                  \
        if ((env[envc++] = strdup(thisarg)) == NULL)                    \
            goto no_memory;                                             \
    } while (0)

# define ADD_ENV_PAIR(envname, val)                                      \
    do {                                                                \
        char *envval;                                                   \
        ADD_ENV_SPACE;                                                  \
        if (virAsprintf(&envval, "%s=%s", envname, val) < 0)            \
            goto no_memory;                                             \
        env[envc++] = envval;                                           \
    } while (0)

# define ADD_ENV_COPY(envname)                                           \
    do {                                                                \
        char *val = getenv(envname);                                    \
        if (val != NULL) {                                              \
            ADD_ENV_PAIR(envname, val);                                 \
        }                                                               \
    } while (0)

    ADD_ENV_LIT("LC_ALL=C");

    ADD_ENV_COPY("LD_PRELOAD");
    ADD_ENV_COPY("LD_LIBRARY_PATH");
    ADD_ENV_COPY("PATH");
    ADD_ENV_COPY("HOME");
    ADD_ENV_COPY("USER");
    ADD_ENV_COPY("LOGNAME");
    ADD_ENV_COPY("TMPDIR");
    ADD_ENV(NULL);

    ADD_ARG_LIT(path);
    ADD_ARG_LIT(id);
    ADD_ARG_LIT(opstr);
    ADD_ARG_LIT(subopstr);

    ADD_ARG_LIT(extra);
    ADD_ARG(NULL);

    /* pass any optional input on the script stdin */
    if (input != NULL) {
        if (pipe(pipefd) < -1) {
            virReportSystemError(errno, "%s",
                             _("unable to create pipe for hook input"));
            ret = 1;
            goto cleanup;
        }
        if (safewrite(pipefd[1], input, strlen(input)) < 0) {
            virReportSystemError(errno, "%s",
                             _("unable to write to pipe for hook input"));
            ret = 1;
            goto cleanup;
        }
        ret = virExec(argv, env, NULL, &pid, pipefd[0], &outfd, &errfd,
                      VIR_EXEC_NONE | VIR_EXEC_NONBLOCK);
        if (VIR_CLOSE(pipefd[1]) < 0) {
            virReportSystemError(errno, "%s",
                             _("unable to close pipe for hook input"));
        }
    } else {
        ret = virExec(argv, env, NULL, &pid, -1, &outfd, &errfd,
                      VIR_EXEC_NONE | VIR_EXEC_NONBLOCK);
    }
    if (ret < 0) {
        virHookReportError(VIR_ERR_HOOK_SCRIPT_FAILED,
                           _("Failed to execute %s hook script"),
                           path);
        ret = 1;
        goto cleanup;
    }

    /*
     * we are interested in the error log if any and make sure the
     * script doesn't block on stdout/stderr descriptors being full
     * stdout can be useful for debug too.
     */
    if (virPipeReadUntilEOF(outfd, errfd, &outbuf, &errbuf) < 0) {
        virReportSystemError(errno, _("cannot wait for '%s'"), path);
        while (waitpid(pid, &exitstatus, 0) == -1 && errno == EINTR)
            ;
        ret = 1;
        goto cleanup;
    }

    if (outbuf)
        VIR_DEBUG("Command stdout: %s", outbuf);
    if (errbuf)
        VIR_DEBUG("Command stderr: %s", errbuf);

    while ((waitret = waitpid(pid, &exitstatus, 0) == -1) &&
           (errno == EINTR));
    if (waitret == -1) {
        virReportSystemError(errno, _("Failed to wait for '%s'"), path);
        ret = 1;
        goto cleanup;
    }
    if (exitstatus != 0) {
        virHookReportError(VIR_ERR_HOOK_SCRIPT_FAILED,
                           _("Hook script %s %s failed with error code %d:%s"),
                           path, drvstr, exitstatus, errbuf);
        ret = -1;
    }

cleanup:
    if (VIR_CLOSE(pipefd[0]) < 0) {
        virReportSystemError(errno, "%s",
                         _("unable to close pipe for hook input"));
        ret = 1;
    }
    if (VIR_CLOSE(pipefd[1]) < 0) {
        virReportSystemError(errno, "%s",
                         _("unable to close pipe for hook input"));
        ret = 1;
    }
    if (argv) {
        for (i = 0 ; i < argc ; i++)
            VIR_FREE((argv)[i]);
        VIR_FREE(argv);
    }
    if (env) {
        for (i = 0 ; i < envc ; i++)
            VIR_FREE((env)[i]);
        VIR_FREE(env);
    }
    VIR_FREE(outbuf);
    VIR_FREE(errbuf);
    VIR_FREE(path);

    return(ret);

no_memory:
    virReportOOMError();

    goto cleanup;

# undef ADD_ARG
# undef ADD_ARG_LIT
# undef ADD_ARG_SPACE
# undef ADD_USBDISK
# undef ADD_ENV
# undef ADD_ENV_COPY
# undef ADD_ENV_LIT
# undef ADD_ENV_SPACE
}
#endif
