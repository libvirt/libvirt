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

#include <stdarg.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <locale.h>

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

static ssize_t nfdlist;
static int *fdlist;
static const char *conf_file = SYSCONFDIR "/libvirt/virt-login-shell.conf";

static void virLoginShellFini(virConnectPtr conn, virDomainPtr dom)
{
    size_t i;

    for (i = 0; i < nfdlist; i++)
        VIR_FORCE_CLOSE(fdlist[i]);
    VIR_FREE(fdlist);
    nfdlist = 0;
    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);
}

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
    char **shargv=NULL;
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
    pid_t cpid;
    int ret = EXIT_FAILURE;
    int status;
    int status2;
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

    struct option opt[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", optional_argument, NULL, 'V'},
        {NULL, 0, NULL, 0}
    };
    if (virInitialize() < 0) {
        fprintf(stderr, _("Failed to initialize libvirt Error Handling"));
        return EXIT_FAILURE;
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
            exit(EXIT_FAILURE);
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

    if (virFork(&cpid) < 0)
        goto cleanup;

    if (cpid == 0) {
        pid_t ccpid;

        int openmax = sysconf(_SC_OPEN_MAX);
        int fd;

        /* Fork once because we don't want to affect
         * virt-login-shell's namespace itself
         */
        if (virSetUIDGID(0, 0, NULL, 0) < 0)
            return EXIT_FAILURE;

        if (virDomainLxcEnterSecurityLabel(secmodel,
                                           seclabel,
                                           NULL,
                                           0) < 0)
            return EXIT_FAILURE;

        if (nfdlist > 0) {
            if (virDomainLxcEnterNamespace(dom,
                                           nfdlist,
                                           fdlist,
                                           NULL,
                                           NULL,
                                           0) < 0)
                return EXIT_FAILURE;
        }

        ret = virSetUIDGID(uid, gid, groups, ngroups);
        VIR_FREE(groups);
        if (ret < 0)
            return EXIT_FAILURE;

        if (openmax < 0) {
            virReportSystemError(errno,  "%s",
                                 _("sysconf(_SC_OPEN_MAX) failed"));
            return EXIT_FAILURE;
        }
        for (fd = 3; fd < openmax; fd++) {
            int tmpfd = fd;
            VIR_MASS_CLOSE(tmpfd);
        }

        if (virFork(&ccpid) < 0)
            return EXIT_FAILURE;

        if (ccpid == 0) {
            if (chdir(homedir) < 0) {
                virReportSystemError(errno, _("Unable to chdir(%s)"), homedir);
                return EXIT_FAILURE;
            }
            if (execv(shargv[0], (char *const*) shargv) < 0) {
                virReportSystemError(errno, _("Unable to exec shell %s"),
                                     shargv[0]);
                return EXIT_FAILURE;
            }
        }
        return virProcessWait(ccpid, &status2);
    }
    ret = virProcessWait(cpid, &status);

cleanup:
    virConfFree(conf);
    virLoginShellFini(conn, dom);
    virStringFreeList(shargv);
    VIR_FREE(name);
    VIR_FREE(homedir);
    VIR_FREE(seclabel);
    VIR_FREE(secmodel);
    VIR_FREE(groups);
    if (ret)
        virDispatchError(NULL);
    return ret;
}
