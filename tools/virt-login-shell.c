/*
 * virt-login-shell.c: a shell to connect to a container
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
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
 * Daniel Walsh <dwalsh@redhat.com>
 */
#include <config.h>

#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "virutil.h"
#include "virfile.h"
#include "virprocess.h"
#include "configmake.h"
#include "virstring.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virgettext.h"
#define VIR_FROM_THIS VIR_FROM_NONE

static const char *conf_file = SYSCONFDIR "/libvirt/virt-login-shell.conf";

static int virLoginShellAllowedUser(virConfPtr conf,
                                    const char *name,
                                    gid_t *groups,
                                    size_t ngroups)
{
    virConfValuePtr p;
    int ret = -1;
    char *ptr = NULL;
    size_t i;
    char *gname = NULL;

    p = virConfGetValue(conf, "allowed_users");
    if (p && p->type == VIR_CONF_LIST) {
        virConfValuePtr pp;

        /* Calc length and check items */
        for (pp = p->list; pp; pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportSystemError(EINVAL, "%s",
                                     _("allowed_users must be a list of strings"));
                goto cleanup;
            } else {
                /*
                  If string begins with a % this indicates a linux group.
                  Check to see if the user is in the Linux Group.
                */
                if (pp->str[0] == '%') {
                    ptr = &pp->str[1];
                    if (!*ptr)
                        continue;
                    for (i = 0; i < ngroups; i++) {
                        if (!(gname = virGetGroupName(groups[i])))
                            continue;
                        if (fnmatch(ptr, gname, 0) == 0) {
                            ret = 0;
                            goto cleanup;
                        }
                        VIR_FREE(gname);
                    }
                    continue;
                }
                if (fnmatch(pp->str, name, 0) == 0) {
                    ret = 0;
                    goto cleanup;
                }
            }
        }
    }
    virReportSystemError(EPERM,
                         _("%s not matched against 'allowed_users' in %s"),
                         name, conf_file);
 cleanup:
    VIR_FREE(gname);
    return ret;
}

static int virLoginShellGetAutoShell(virConfPtr conf,
                                     bool *autoshell)
{
    virConfValuePtr p;

    p = virConfGetValue(conf, "auto_shell");
    if (!p) {
        *autoshell = false;
    } else if (p->type == VIR_CONF_LONG ||
               p->type == VIR_CONF_ULONG) {
        *autoshell = (p->l != 0);
    } else {
        virReportSystemError(EINVAL, "%s",
                             _("auto_shell must be a boolean value"));
        return -1;
    }
    return 0;
}

static int virLoginShellGetShellArgv(virConfPtr conf,
                                     char ***retshargv,
                                     size_t *retshargvlen)
{
    size_t i;
    size_t len;
    char **shargv = NULL;
    virConfValuePtr p, pp;

    p = virConfGetValue(conf, "shell");
    if (!p) {
        len = 1; /* /bin/sh */
    } else if (p->type == VIR_CONF_LIST) {
        /* Calc length and check items */
        for (len = 0, pp = p->list; pp; len++, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportSystemError(EINVAL, "%s",
                                     _("shell must be a list of strings"));
                goto error;
            }
        }
    } else if (p->type == VIR_CONF_STRING) {
        len = 1; /* /path/to/shell */
    } else {
        virReportSystemError(EINVAL, "%s",
                             _("shell must be a list of strings"));
        goto error;
    }

    len++; /* NULL terminator */

    if (VIR_ALLOC_N(shargv, len) < 0)
        goto error;

    i = 0;
    if (!p) {
        if (VIR_STRDUP(shargv[i++], "/bin/sh") < 0)
            goto error;
    } else if (p->type == VIR_CONF_LIST) {
        for (pp = p->list; pp; pp = pp->next) {
            if (VIR_STRDUP(shargv[i++], pp->str) < 0)
                goto error;
        }
    } else if (p->type == VIR_CONF_STRING) {
        if (VIR_STRDUP(shargv[i++], p->str) < 0)
            goto error;
    }

    shargv[i] = NULL;

    *retshargvlen = i;
    *retshargv = shargv;

    return 0;
 error:
    *retshargv = NULL;
    *retshargvlen = 0;
    virStringFreeList(shargv);
    return -1;
}

static char *progname;

/*
 * Print usage
 */
static void
usage(void)
{
    fprintf(stdout,
            _("\n"
              "Usage:\n"
              "  %s [option]\n\n"
              "Options:\n"
              "  -h | --help            Display program help\n"
              "  -V | --version         Display program version\n"
              "  -c CMD                 Run CMD via shell\n"
              "\n"
              "libvirt login shell\n"),
            progname);
    return;
}

/* Display version information. */
static void
show_version(void)
{
    printf("%s (%s) %s\n", progname, PACKAGE_NAME, PACKAGE_VERSION);
}


int
main(int argc, char **argv)
{
    virConfPtr conf = NULL;
    const char *login_shell_path = conf_file;
    pid_t cpid = -1;
    int ret = EXIT_CANCELED;
    int status;
    uid_t uid = getuid();
    gid_t gid = getgid();
    char *name = NULL;
    char **shargv = NULL;
    size_t shargvlen = 0;
    char *shcmd = NULL;
    virSecurityModelPtr secmodel = NULL;
    virSecurityLabelPtr seclabel = NULL;
    virDomainPtr dom = NULL;
    virConnectPtr conn = NULL;
    char *homedir = NULL;
    int arg;
    int longindex = -1;
    int ngroups;
    gid_t *groups = NULL;
    ssize_t nfdlist = 0;
    int *fdlist = NULL;
    int openmax;
    size_t i;
    const char *cmdstr = NULL;
    char *tmp;
    char *term = NULL;
    virErrorPtr saved_err = NULL;
    bool autoshell = false;

    struct option opt[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", optional_argument, NULL, 'V'},
        {NULL, 0, NULL, 0}
    };
    if (virInitialize() < 0) {
        fprintf(stderr, _("Failed to initialize libvirt error handling"));
        return EXIT_CANCELED;
    }

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    progname = argv[0];
    if (virGettextInitialize() < 0)
        return ret;

    while ((arg = getopt_long(argc, argv, "hVc:", opt, &longindex)) != -1) {
        switch (arg) {
        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'V':
            show_version();
            exit(EXIT_SUCCESS);

        case 'c':
            cmdstr = optarg;
            break;

        case '?':
        default:
            usage();
            exit(EXIT_CANCELED);
        }
    }

    if (argc > optind) {
        virReportSystemError(EINVAL, _("%s takes no options"), progname);
        goto cleanup;
    }

    if (uid == 0) {
        virReportSystemError(EPERM, _("%s must be run by non root users"),
                             progname);
        goto cleanup;
    }

    name = virGetUserName(uid);
    if (!name)
        goto cleanup;

    homedir = virGetUserDirectoryByUID(uid);
    if (!homedir)
        goto cleanup;

    if (!(conf = virConfReadFile(login_shell_path, 0)))
        goto cleanup;

    if ((ngroups = virGetGroupList(uid, gid, &groups)) < 0)
        goto cleanup;

    if (virLoginShellAllowedUser(conf, name, groups, ngroups) < 0)
        goto cleanup;

    if (virLoginShellGetShellArgv(conf, &shargv, &shargvlen) < 0)
        goto cleanup;

    if (virLoginShellGetAutoShell(conf, &autoshell) < 0)
        goto cleanup;

    conn = virConnectOpen("lxc:///");
    if (!conn)
        goto cleanup;

    dom = virDomainLookupByName(conn, name);
    if (!dom)
        goto cleanup;

    if (!virDomainIsActive(dom) && virDomainCreate(dom) < 0) {
        virErrorPtr last_error;
        last_error = virGetLastError();
        if (last_error->code != VIR_ERR_OPERATION_INVALID) {
            virReportSystemError(last_error->code,
                                 _("Can't create %s container: %s"),
                                 name, last_error->message);
            goto cleanup;
        }
    }

    openmax = sysconf(_SC_OPEN_MAX);
    if (openmax < 0) {
        virReportSystemError(errno,  "%s",
                             _("sysconf(_SC_OPEN_MAX) failed"));
        goto cleanup;
    }

    if ((nfdlist = virDomainLxcOpenNamespace(dom, &fdlist, 0)) < 0)
        goto cleanup;
    if (VIR_ALLOC(secmodel) < 0)
        goto cleanup;
    if (VIR_ALLOC(seclabel) < 0)
        goto cleanup;
    if (virNodeGetSecurityModel(conn, secmodel) < 0)
        goto cleanup;
    if (virDomainGetSecurityLabel(dom, seclabel) < 0)
        goto cleanup;
    if (virSetUIDGID(0, 0, NULL, 0) < 0)
        goto cleanup;
    if (virDomainLxcEnterSecurityLabel(secmodel, seclabel, NULL, 0) < 0)
        goto cleanup;
    if (virDomainLxcEnterCGroup(dom, 0) < 0)
        goto cleanup;
    if (nfdlist > 0 &&
        virDomainLxcEnterNamespace(dom, nfdlist, fdlist, NULL, NULL, 0) < 0)
        goto cleanup;
    if (virSetUIDGID(uid, gid, groups, ngroups) < 0)
        goto cleanup;
    if (chdir(homedir) < 0) {
        virReportSystemError(errno, _("Unable to chdir(%s)"), homedir);
        goto cleanup;
    }

    if (autoshell) {
        tmp = virGetUserShell(uid);
        if (tmp) {
            virStringFreeList(shargv);
            shargvlen = 1;
            if (VIR_ALLOC_N(shargv[0], shargvlen + 1) < 0) {
                VIR_FREE(tmp);
                goto cleanup;
            }
            shargv[0] = tmp;
            shargv[1] = NULL;
        }
    }

    if (cmdstr) {
        if (VIR_REALLOC_N(shargv, shargvlen + 3) < 0)
            goto cleanup;
        if (VIR_STRDUP(shargv[shargvlen++], "-c") < 0)
            goto cleanup;
        if (VIR_STRDUP(shargv[shargvlen++], cmdstr) < 0)
            goto cleanup;
        shargv[shargvlen] = NULL;
    }

    /* We need to modify the first elementin shargv
     * so that it has the relative filename and has
     * a leading '-' to indicate it is a login shell
     */
    shcmd = shargv[0];
    if (shcmd[0] != '/') {
        virReportSystemError(errno,
                             _("Shell '%s' should have absolute path"),
                             shcmd);
        goto cleanup;
    }
    tmp = strrchr(shcmd, '/');
    if (VIR_STRDUP(shargv[0], tmp) < 0)
        goto cleanup;
    shargv[0][0] = '-';

    /* We're duping the string because the clearenv()
     * call will shortly release the pointer we get
     * back from virGetEnvAllowSUID() right here */
    if (VIR_STRDUP(term, virGetEnvAllowSUID("TERM")) < 0)
        goto cleanup;

    /* A fork is required to create new process in correct pid namespace.  */
    if ((cpid = virFork()) < 0)
        goto cleanup;

    if (cpid == 0) {
        int tmpfd;

        for (i = 3; i < openmax; i++) {
            tmpfd = i;
            VIR_MASS_CLOSE(tmpfd);
        }

        clearenv();
        setenv("PATH", "/bin:/usr/bin", 1);
        setenv("SHELL", shcmd, 1);
        setenv("USER", name, 1);
        setenv("LOGNAME", name, 1);
        setenv("HOME", homedir, 1);
        if (term)
            setenv("TERM", term, 1);

        if (execv(shcmd, (char *const*) shargv) < 0) {
            virReportSystemError(errno, _("Unable to exec shell %s"),
                                 shcmd);
            virDispatchError(NULL);
            return errno == ENOENT ? EXIT_ENOENT : EXIT_CANNOT_INVOKE;
        }
    }

    /* At this point, the parent is now waiting for the child to exit,
     * but as that may take a long time, we release resources now.  */
 cleanup:
    saved_err = virSaveLastError();

    if (nfdlist > 0)
        for (i = 0; i < nfdlist; i++)
            VIR_FORCE_CLOSE(fdlist[i]);
    VIR_FREE(fdlist);
    virConfFree(conf);
    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);
    virStringFreeList(shargv);
    VIR_FREE(shcmd);
    VIR_FREE(term);
    VIR_FREE(name);
    VIR_FREE(homedir);
    VIR_FREE(seclabel);
    VIR_FREE(secmodel);
    VIR_FREE(groups);

    if (virProcessWait(cpid, &status, true) == 0)
        virProcessExitWithStatus(status);

    if (saved_err) {
        virSetError(saved_err);
        virDispatchError(NULL);
    }
    return ret;
}
