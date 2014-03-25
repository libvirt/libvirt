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
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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
#define VIR_FROM_THIS VIR_FROM_NONE

static const char *conf_file = SYSCONFDIR "/libvirt/virt-login-shell.conf";

static int virLoginShellAllowedUser(virConfPtr conf,
                                    const char *name,
                                    gid_t *groups)
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
                                     _("shell must be a list of strings"));
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
                    for (i = 0; groups[i]; i++) {
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

static char **virLoginShellGetShellArgv(virConfPtr conf)
{
    size_t i;
    char **shargv = NULL;
    virConfValuePtr p;

    p = virConfGetValue(conf, "shell");
    if (!p)
        return virStringSplit("/bin/sh -l", " ", 3);

    if (p->type == VIR_CONF_LIST) {
        size_t len;
        virConfValuePtr pp;

        /* Calc length and check items */
        for (len = 0, pp = p->list; pp; len++, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportSystemError(EINVAL, "%s",
                                     _("shell must be a list of strings"));
                goto error;
            }
        }

        if (VIR_ALLOC_N(shargv, len + 1) < 0)
            goto error;
        for (i = 0, pp = p->list; pp; i++, pp = pp->next) {
            if (VIR_STRDUP(shargv[i], pp->str) < 0)
                goto error;
        }
    }
    return shargv;
 error:
    virStringFreeList(shargv);
    return NULL;
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

    struct option opt[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", optional_argument, NULL, 'V'},
        {NULL, 0, NULL, 0}
    };
    if (virInitialize() < 0) {
        fprintf(stderr, _("Failed to initialize libvirt error handling"));
        return EXIT_CANCELED;
    }

    setenv("PATH", "/bin:/usr/bin", 1);

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    progname = argv[0];
    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        /* failure to setup locale is not fatal */
    }
    if (!bindtextdomain(PACKAGE, LOCALEDIR)) {
        perror("bindtextdomain");
        return ret;
    }
    if (!textdomain(PACKAGE)) {
        perror("textdomain");
        return ret;
    }

    while ((arg = getopt_long(argc, argv, "hV", opt, &longindex)) != -1) {
        switch (arg) {
        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'V':
            show_version();
            exit(EXIT_SUCCESS);

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

    if (virLoginShellAllowedUser(conf, name, groups) < 0)
        goto cleanup;

    if (!(shargv = virLoginShellGetShellArgv(conf)))
        goto cleanup;

    conn = virConnectOpen("lxc:///");
    if (!conn)
        goto cleanup;

    dom = virDomainLookupByName(conn, name);
    if (!dom)
        goto cleanup;

    if (!virDomainIsActive(dom) && virDomainCreate(dom)) {
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
    if (nfdlist > 0 &&
        virDomainLxcEnterNamespace(dom, nfdlist, fdlist, NULL, NULL, 0) < 0)
        goto cleanup;
    if (virSetUIDGID(uid, gid, groups, ngroups) < 0)
        goto cleanup;
    if (chdir(homedir) < 0) {
        virReportSystemError(errno, _("Unable to chdir(%s)"), homedir);
        goto cleanup;
    }

    /* A fork is required to create new process in correct pid namespace.  */
    if ((cpid = virFork()) < 0)
        goto cleanup;

    if (cpid == 0) {
        int tmpfd;

        for (i = 3; i < openmax; i++) {
            tmpfd = i;
            VIR_MASS_CLOSE(tmpfd);
        }
        if (execv(shargv[0], (char *const*) shargv) < 0) {
            virReportSystemError(errno, _("Unable to exec shell %s"),
                                 shargv[0]);
            virDispatchError(NULL);
            return errno == ENOENT ? EXIT_ENOENT : EXIT_CANNOT_INVOKE;
        }
    }

    /* At this point, the parent is now waiting for the child to exit,
     * but as that may take a long time, we release resources now.  */
 cleanup:
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
    VIR_FREE(name);
    VIR_FREE(homedir);
    VIR_FREE(seclabel);
    VIR_FREE(secmodel);
    VIR_FREE(groups);

    if (virProcessWait(cpid, &status, true) == 0)
        virProcessExitWithStatus(status);

    if (virGetLastError())
        virDispatchError(NULL);
    return ret;
}
