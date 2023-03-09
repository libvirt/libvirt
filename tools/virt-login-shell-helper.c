/*
 * virt-login-shell-helper.c: a shell to connect to a container
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
 */
#include <config.h>

#include <getopt.h>
#include <signal.h>
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

static int virLoginShellAllowedUser(virConf *conf,
                                    const char *name,
                                    gid_t *groups,
                                    size_t ngroups)
{
    int ret = -1;
    size_t i;
    char *gname = NULL;
    g_auto(GStrv) users = NULL;
    char **entries;

    if (virConfGetValueStringList(conf, "allowed_users", false, &users) < 0)
        goto cleanup;


    for (entries = users; entries && *entries; entries++) {
        char *entry = *entries;
        /*
          If string begins with a % this indicates a linux group.
          Check to see if the user is in the Linux Group.
        */
        if (entry[0] == '%') {
            entry++;
            if (!*entry)
                continue;
            for (i = 0; i < ngroups; i++) {
                if (!(gname = virGetGroupName(groups[i])))
                    continue;
                if (g_pattern_match_simple(entry, gname)) {
                    ret = 0;
                    goto cleanup;
                }
                VIR_FREE(gname);
            }
        } else {
            if (g_pattern_match_simple(entry, name)) {
                ret = 0;
                goto cleanup;
            }
        }
    }
    virReportSystemError(EPERM,
                         _("%1$s not matched against 'allowed_users' in %2$s"),
                         name, conf_file);
 cleanup:
    VIR_FREE(gname);
    return ret;
}


static int virLoginShellGetShellArgv(virConf *conf,
                                     char ***shargv,
                                     size_t *shargvlen)
{
    int rv;

    if ((rv = virConfGetValueStringList(conf, "shell", true, shargv)) < 0)
        return -1;

    if (rv == 0) {
        *shargv = g_new0(char *, 2);
        (*shargv)[0] = g_strdup("/bin/sh");
        *shargvlen = 1;
    } else {
        *shargvlen = g_strv_length(*shargv);
    }
    return 0;
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
              "  %1$s [option]\n\n"
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


static void
hideErrorFunc(void *opaque G_GNUC_UNUSED,
              virErrorPtr err G_GNUC_UNUSED)
{
}

int
main(int argc, char **argv)
{
    g_autoptr(virConf) conf = NULL;
    const char *login_shell_path = conf_file;
    pid_t cpid = -1;
    int ret = EXIT_CANCELED;
    int status;
    unsigned long long uidval;
    unsigned long long gidval;
    uid_t uid;
    gid_t gid;
    char *name = NULL;
    g_auto(GStrv) shargv = NULL;
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
        { "help", no_argument, NULL, 'h' },
        { "version", optional_argument, NULL, 'V' },
        { NULL, 0, NULL, 0 },
    };
    if (virInitialize() < 0) {
        fprintf(stderr, _("Failed to initialize libvirt error handling"));
        return EXIT_CANCELED;
    }

    virSetErrorFunc(NULL, hideErrorFunc);
    virSetErrorLogPriorityFunc(NULL);

    progname = argv[0];
    if (virGettextInitialize() < 0)
        return ret;

    if (geteuid() != 0) {
        fprintf(stderr, _("%1$s: must be run as root\n"), argv[0]);
        return ret;
    }

    if (getuid() != 0) {
        fprintf(stderr, _("%1$s: must not be run setuid root\n"), argv[0]);
        return ret;
    }

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

    if (optind != (argc - 2)) {
        virReportSystemError(EINVAL, _("%1$s expects UID and GID parameters"), progname);
        goto cleanup;
    }

    if (virStrToLong_ull(argv[optind], NULL, 10, &uidval) < 0 ||
        ((uid_t)uidval) != uidval) {
        virReportSystemError(EINVAL, _("%1$s cannot parse UID '%2$s'"),
                             progname, argv[optind]);
        goto cleanup;
    }

    optind++;
    if (virStrToLong_ull(argv[optind], NULL, 10, &gidval) < 0 ||
        ((gid_t)gidval) != gidval) {
        virReportSystemError(EINVAL, _("%1$s cannot parse GID '%2$s'"),
                             progname, argv[optind]);
        goto cleanup;
    }

    uid = (uid_t)uidval;
    gid = (gid_t)gidval;

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

    if (virConfGetValueBool(conf, "auto_shell", &autoshell) < 0)
        goto cleanup;

    conn = virConnectOpen("lxc:///system");
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
                                 _("Can't create %1$s container: %2$s"),
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
    secmodel = g_new0(virSecurityModel, 1);
    seclabel = g_new0(virSecurityLabel, 1);
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
        virReportSystemError(errno, _("Unable to chdir(%1$s)"), homedir);
        goto cleanup;
    }

    if (autoshell) {
        tmp = virGetUserShell(uid);
        if (tmp) {
            g_strfreev(shargv);
            shargvlen = 1;
            shargv = g_new0(char *, shargvlen + 1);
            shargv[0] = tmp;
            shargv[1] = NULL;
        }
    }

    if (cmdstr) {
        VIR_REALLOC_N(shargv, shargvlen + 3);
        shargv[shargvlen++] = g_strdup("-c");
        shargv[shargvlen++] = g_strdup(cmdstr);
        shargv[shargvlen] = NULL;
    }

    /* We need to modify the first elementin shargv
     * so that it has the relative filename and has
     * a leading '-' to indicate it is a login shell
     */
    shcmd = shargv[0];
    if (!g_path_is_absolute(shcmd)) {
        virReportSystemError(errno,
                             _("Shell '%1$s' should have absolute path"),
                             shcmd);
        goto cleanup;
    }
    tmp = strrchr(shcmd, '/');
    shargv[0] = g_strdup(tmp);
    shargv[0][0] = '-';

    /* We're duping the string because the clearenv()
     * call will shortly release the pointer we get
     * back from getenv() right here */
    term = g_strdup(getenv("TERM"));

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
        g_setenv("PATH", "/bin:/usr/bin", TRUE);
        g_setenv("SHELL", shcmd, TRUE);
        g_setenv("USER", name, TRUE);
        g_setenv("LOGNAME", name, TRUE);
        g_setenv("HOME", homedir, TRUE);
        if (term)
            g_setenv("TERM", term, TRUE);

        if (execv(shcmd, (char *const*) shargv) < 0) {
            virReportSystemError(errno, _("Unable to exec shell %1$s"),
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
    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);
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
        fprintf(stderr, "%s: %s\n", argv[0], virGetLastErrorMessage());
    }
    return ret;
}
