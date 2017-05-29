/*
 * Copyright (C) 2011-2014 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */


#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <selinux/selinux.h>
#include <selinux/context.h>
#include <attr/xattr.h>

#include "internal.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "qemu/qemu_domain.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "security/security_manager.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.securityselinuxlabeltest");

static virQEMUDriver driver;

static virSecurityManagerPtr mgr;

typedef struct testSELinuxFile testSELinuxFile;

struct testSELinuxFile {
    char *file;
    char *context;
};

static int
testUserXattrEnabled(void)
{
    int ret = -1;
    ssize_t len;
    const char *con_value = "system_u:object_r:svirt_image_t:s0:c41,c264";
    char *path = NULL;
    if (virAsprintf(&path, "%s/securityselinuxlabeldata/testxattr",
                    abs_builddir) < 0)
        goto cleanup;

    if (virFileMakePath(abs_builddir "/securityselinuxlabeldata") < 0 ||
        virFileTouch(path, 0600) < 0)
        goto cleanup;

    len = setxattr(path, "user.libvirt.selinux", con_value,
                   strlen(con_value), 0);
    if (len < 0) {
        if (errno == EOPNOTSUPP)
            ret = 0;
        goto cleanup;
    }

    ret = 1;

 cleanup:
    unlink(path);
    rmdir(abs_builddir "/securityselinuxlabeldata");
    VIR_FREE(path);
    return ret;
}

static int
testSELinuxMungePath(char **path)
{
    char *tmp;

    if (virAsprintf(&tmp, "%s/securityselinuxlabeldata%s",
                    abs_builddir, *path) < 0)
        return -1;

    VIR_FREE(*path);
    *path = tmp;
    return 0;
}

static int
testSELinuxLoadFileList(const char *testname,
                        testSELinuxFile **files,
                        size_t *nfiles)
{
    int ret = -1;
    char *path = NULL;
    FILE *fp = NULL;
    char *line = NULL;

    *files = NULL;
    *nfiles = 0;

    if (virAsprintf(&path, "%s/securityselinuxlabeldata/%s.txt",
                    abs_srcdir, testname) < 0)
        goto cleanup;

    if (!(fp = fopen(path, "r")))
        goto cleanup;

    if (VIR_ALLOC_N(line, 1024) < 0)
        goto cleanup;

    while (!feof(fp)) {
        char *file = NULL, *context = NULL, *tmp;
        if (!fgets(line, 1024, fp)) {
            if (!feof(fp))
                goto cleanup;
            break;
        }

        tmp = strchr(line, ';');
        if (!tmp) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "unexpected format for line '%s'",
                           line);
            goto cleanup;
        }
        *tmp = '\0';
        tmp++;

        if (virAsprintf(&file, "%s/securityselinuxlabeldata%s",
                        abs_builddir, line) < 0)
            goto cleanup;
        if (*tmp != '\0' && *tmp != '\n') {
            if (VIR_STRDUP(context, tmp) < 0) {
                VIR_FREE(file);
                goto cleanup;
            }

            tmp = strchr(context, '\n');
            if (tmp)
                *tmp = '\0';
        }

        if (VIR_EXPAND_N(*files, *nfiles, 1) < 0) {
            VIR_FREE(file);
            VIR_FREE(context);
            goto cleanup;
        }

        (*files)[(*nfiles)-1].file = file;
        (*files)[(*nfiles)-1].context = context;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_FCLOSE(fp);
    VIR_FREE(path);
    VIR_FREE(line);
    return ret;
}


static virDomainDefPtr
testSELinuxLoadDef(const char *testname)
{
    char *xmlfile = NULL;
    virDomainDefPtr def = NULL;
    size_t i;

    if (virAsprintf(&xmlfile, "%s/securityselinuxlabeldata/%s.xml",
                    abs_srcdir, testname) < 0)
        goto cleanup;

    if (!(def = virDomainDefParseFile(xmlfile, driver.caps, driver.xmlopt,
                                      NULL, 0)))
        goto cleanup;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->src->type != VIR_STORAGE_TYPE_FILE &&
            def->disks[i]->src->type != VIR_STORAGE_TYPE_BLOCK)
            continue;

        if (testSELinuxMungePath(&def->disks[i]->src->path) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->nserials; i++) {
        if (def->serials[i]->source->type != VIR_DOMAIN_CHR_TYPE_FILE &&
            def->serials[i]->source->type != VIR_DOMAIN_CHR_TYPE_PIPE &&
            def->serials[i]->source->type != VIR_DOMAIN_CHR_TYPE_DEV &&
            def->serials[i]->source->type != VIR_DOMAIN_CHR_TYPE_UNIX)
            continue;

        if (def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX) {
            if (testSELinuxMungePath(&def->serials[i]->source->data.nix.path) < 0)
                goto cleanup;
        } else {
            if (testSELinuxMungePath(&def->serials[i]->source->data.file.path) < 0)
                goto cleanup;
        }
    }

    if (def->os.kernel &&
        testSELinuxMungePath(&def->os.kernel) < 0)
        goto cleanup;
    if (def->os.initrd &&
        testSELinuxMungePath(&def->os.initrd) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(xmlfile);
    return def;
}


static int
testSELinuxCreateDisks(testSELinuxFile *files, size_t nfiles)
{
    size_t i;

    if (virFileMakePath(abs_builddir "/securityselinuxlabeldata/nfs") < 0)
        return -1;

    for (i = 0; i < nfiles; i++) {
        if (virFileTouch(files[i].file, 0600) < 0)
            return -1;
    }
    return 0;
}

static int
testSELinuxDeleteDisks(testSELinuxFile *files, size_t nfiles)
{
    size_t i;

    for (i = 0; i < nfiles; i++) {
        if (unlink(files[i].file) < 0)
            return -1;
    }
    if (rmdir(abs_builddir "/securityselinuxlabeldata/nfs") < 0)
        return -1;
    /* Ignore failure to remove non-empty directory with in-tree build */
    rmdir(abs_builddir "/securityselinuxlabeldata");
    return 0;
}

static int
testSELinuxCheckLabels(testSELinuxFile *files, size_t nfiles)
{
    size_t i;
    security_context_t ctx;

    for (i = 0; i < nfiles; i++) {
        ctx = NULL;
        if (getfilecon(files[i].file, &ctx) < 0) {
            if (errno == ENODATA) {
                /* nothing to do */
            } else if (errno == EOPNOTSUPP) {
                if (VIR_STRDUP(ctx, "EOPNOTSUPP") < 0)
                    return -1;
            } else {
                virReportSystemError(errno,
                                     "Cannot read label on %s",
                                     files[i].file);
                return -1;
            }
        }
        if (STRNEQ_NULLABLE(files[i].context, ctx)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "File %s context '%s' did not match epected '%s'",
                           files[i].file, ctx, files[i].context);
            VIR_FREE(ctx);
            return -1;
        }
        VIR_FREE(ctx);
    }
    return 0;
}

static int
testSELinuxLabeling(const void *opaque)
{
    const char *testname = opaque;
    int ret = -1;
    testSELinuxFile *files = NULL;
    size_t nfiles = 0;
    size_t i;
    virDomainDefPtr def = NULL;

    if (testSELinuxLoadFileList(testname, &files, &nfiles) < 0)
        goto cleanup;

    if (testSELinuxCreateDisks(files, nfiles) < 0)
        goto cleanup;

    if (!(def = testSELinuxLoadDef(testname)))
        goto cleanup;

    if (virSecurityManagerSetAllLabel(mgr, def, NULL, false) < 0)
        goto cleanup;

    if (testSELinuxCheckLabels(files, nfiles) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (testSELinuxDeleteDisks(files, nfiles) < 0)
        VIR_WARN("unable to fully clean up");

    virDomainDefFree(def);
    for (i = 0; i < nfiles; i++) {
        VIR_FREE(files[i].file);
        VIR_FREE(files[i].context);
    }
    VIR_FREE(files);
    if (ret < 0)
        VIR_TEST_VERBOSE("%s\n", virGetLastErrorMessage());
    return ret;
}



static int
mymain(void)
{
    int ret = 0;
    int rc = testUserXattrEnabled();

    if (rc < 0)
        return EXIT_FAILURE;
    if (!rc)
        return EXIT_AM_SKIP;

    if (!(mgr = virSecurityManagerNew("selinux", "QEMU",
                                      VIR_SECURITY_MANAGER_DEFAULT_CONFINED |
                                      VIR_SECURITY_MANAGER_PRIVILEGED))) {
        VIR_TEST_VERBOSE("Unable to initialize security driver: %s\n",
                         virGetLastErrorMessage());
        return EXIT_FAILURE;
    }

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

#define DO_TEST_LABELING(name)                                           \
    if (virTestRun("Labelling " # name, testSELinuxLabeling, name) < 0)  \
        ret = -1;

    setcon((security_context_t)"system_r:system_u:libvirtd_t:s0:c0.c1023");

    DO_TEST_LABELING("disks");
    DO_TEST_LABELING("kernel");
    DO_TEST_LABELING("chardev");
    DO_TEST_LABELING("nfs");

    qemuTestDriverFree(&driver);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/libsecurityselinuxhelper.so")
