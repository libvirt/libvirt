/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
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

#include <time.h>

#include <selinux/selinux.h>
#include <selinux/context.h>

#include "internal.h"
#include "testutils.h"
#include "virlog.h"
#include "security/security_manager.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.securityselinuxtest");

struct testSELinuxGenLabelData {
    virSecurityManager *mgr;

    const char *pidcon;

    bool dynamic;
    const char *label;
    const char *baselabel;

    const char *user;
    const char *role;
    const char *imagerole;
    const char *type;
    const char *imagetype;

    int sensMin;
    int sensMax;
    int catMin;
    int catMax;
};

static virDomainDef *
testBuildDomainDef(bool dynamic,
                   const char *label,
                   const char *baselabel)
{
    g_autoptr(virDomainDef) def = NULL;
    virSecurityLabelDef *secdef = NULL;

    if (!(def = virDomainDefNew(NULL)))
        goto error;

    def->virtType = VIR_DOMAIN_VIRT_KVM;
    def->seclabels = g_new0(virSecurityLabelDef *, 1);

    secdef = g_new0(virSecurityLabelDef, 1);

    secdef->model = g_strdup("selinux");

    secdef->type = dynamic ? VIR_DOMAIN_SECLABEL_DYNAMIC : VIR_DOMAIN_SECLABEL_STATIC;
    if (label)
        secdef->label = g_strdup(label);

    if (baselabel)
        secdef->baselabel = g_strdup(baselabel);

    def->seclabels[0] = secdef;
    def->nseclabels++;
    return g_steal_pointer(&def);

 error:
    virSecurityLabelDefFree(secdef);
    return NULL;
}


static bool
testSELinuxCheckCon(context_t con,
                    const char *user,
                    const char *role,
                    const char *type,
                    int sensMin,
                    int sensMax G_GNUC_UNUSED,
                    int catMin,
                    int catMax)
{
    const char *range;
    char *tmp;
    int gotSens;
    int gotCatOne;
    int gotCatTwo;

    if (STRNEQ(context_user_get(con), user)) {
        fprintf(stderr, "Expect user %s got %s\n",
                user, context_user_get(con));
        return false;
    }
    if (STRNEQ(context_role_get(con), role)) {
        fprintf(stderr, "Expect role %s got %s\n",
                role, context_role_get(con));
        return false;
    }
    if (STRNEQ(context_type_get(con), type)) {
        fprintf(stderr, "Expect type %s got %s\n",
                type, context_type_get(con));
        return false;
    }

    range = context_range_get(con);
    if (range[0] != 's') {
        fprintf(stderr, "Malformed range %s, cannot find sensitivity\n",
                range);
        return false;
    }
    if (virStrToLong_i(range + 1, &tmp, 10, &gotSens) < 0 ||
        !tmp) {
        fprintf(stderr, "Malformed range %s, cannot parse sensitivity\n",
                range + 1);
        return false;
    }
    if (*tmp != ':') {
        fprintf(stderr, "Malformed range %s, too many sensitivity values\n",
                tmp);
        return false;
    }
    tmp++;
    if (*tmp != 'c') {
        fprintf(stderr, "Malformed range %s, cannot find first category\n",
                tmp);
        return false;
    }
    tmp++;
    if (virStrToLong_i(tmp, &tmp, 10, &gotCatOne) < 0) {
        fprintf(stderr, "Malformed range %s, cannot parse category one\n",
                tmp);
        return false;
    }
    if (tmp && *tmp == ',')
        tmp++;
    if (tmp && *tmp == 'c') {
        tmp++;
        if (virStrToLong_i(tmp, &tmp, 10, &gotCatTwo) < 0) {
            fprintf(stderr, "Malformed range %s, cannot parse category two\n",
                    tmp);
            return false;
        }
        if (*tmp != '\0') {
            fprintf(stderr, "Malformed range %s, junk after second category\n",
                    tmp);
            return false;
        }
        if (gotCatOne == gotCatTwo) {
            fprintf(stderr, "Saw category pair %d,%d where cats were equal\n",
                    gotCatOne, gotCatTwo);
            return false;
        }
    } else {
        gotCatTwo = gotCatOne;
    }

    if (gotSens != sensMin) {
        fprintf(stderr, "Sensitivity %d is not equal to min %d\n",
                gotSens, sensMin);
        return false;
    }
    if (gotCatOne < catMin ||
        gotCatOne > catMax) {
        fprintf(stderr, "Category one %d is out of range %d-%d\n",
                gotCatTwo, catMin, catMax);
        return false;
    }
    if (gotCatTwo < catMin ||
        gotCatTwo > catMax) {
        fprintf(stderr, "Category two %d is out of range %d-%d\n",
                gotCatTwo, catMin, catMax);
        return false;
    }

    if (gotCatOne > gotCatTwo) {
        fprintf(stderr, "Category one %d is greater than category two %d\n",
                gotCatOne, gotCatTwo);
        return false;
    }

    return true;
}

static int
testSELinuxGenLabel(const void *opaque)
{
    const struct testSELinuxGenLabelData *data = opaque;
    int ret = -1;
    g_autoptr(virDomainDef) def = NULL;
    context_t con = NULL;
    context_t imgcon = NULL;

    if (setcon_raw(data->pidcon) < 0) {
        perror("Cannot set process security context");
        return -1;
    }

    if (!(def = testBuildDomainDef(data->dynamic,
                                   data->label,
                                   data->baselabel)))
        goto cleanup;

    if (virSecurityManagerGenLabel(data->mgr, def) < 0) {
        fprintf(stderr, "Cannot generate label: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    VIR_DEBUG("label=%s imagelabel=%s",
              def->seclabels[0]->label, def->seclabels[0]->imagelabel);

    if (!(con = context_new(def->seclabels[0]->label)))
        goto cleanup;
    if (!(imgcon = context_new(def->seclabels[0]->imagelabel)))
        goto cleanup;

    if (!testSELinuxCheckCon(con,
                             data->user, data->role, data->type,
                             data->sensMin, data->sensMax,
                             data->catMin, data->catMax))
        goto cleanup;

    if (!testSELinuxCheckCon(imgcon,
                             data->user, data->imagerole, data->imagetype,
                             data->sensMin, data->sensMax,
                             data->catMin, data->catMax))
        goto cleanup;

    ret = 0;

 cleanup:
    context_free(con);
    context_free(imgcon);
    return ret;
}



static int
mymain(void)
{
    int ret = 0;
    virSecurityManager *mgr;

    if (!(mgr = virSecurityManagerNew("selinux", "QEMU",
                                      VIR_SECURITY_MANAGER_DEFAULT_CONFINED |
                                      VIR_SECURITY_MANAGER_PRIVILEGED))) {
        fprintf(stderr, "Unable to initialize security driver: %s\n",
                virGetLastErrorMessage());
        return EXIT_FAILURE;
    }

#define DO_TEST_GEN_LABEL(desc, pidcon, \
                          dynamic, label, baselabel, \
                          user, role, imageRole, \
                          type, imageType, \
                          sensMin, sensMax, catMin, catMax) \
    do { \
        struct testSELinuxGenLabelData data = { \
            mgr, pidcon, dynamic, label, baselabel, \
            user, role, imageRole, type, imageType, \
            sensMin, sensMax, catMin, catMax \
        }; \
        if (virTestRun("GenLabel " # desc, testSELinuxGenLabel, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_GEN_LABEL("dynamic unconfined, s0, c0.c1023",
                      "unconfined_u:unconfined_r:unconfined_t:s0",
                      true, NULL, NULL,
                      "unconfined_u", "unconfined_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      0, 0, 0, 1023);
    DO_TEST_GEN_LABEL("dynamic unconfined, s0, c0.c1023",
                      "unconfined_u:unconfined_r:unconfined_t:s0-s0",
                      true, NULL, NULL,
                      "unconfined_u", "unconfined_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      0, 0, 0, 1023);
    DO_TEST_GEN_LABEL("dynamic unconfined, s0, c0.c1023",
                      "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
                      true, NULL, NULL,
                      "unconfined_u", "unconfined_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      0, 0, 0, 1023);
    DO_TEST_GEN_LABEL("dynamic virtd, s0, c0.c1023",
                      "system_u:system_r:virtd_t:s0-s0:c0.c1023",
                      true, NULL, NULL,
                      "system_u", "system_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      0, 0, 0, 1023);
    DO_TEST_GEN_LABEL("dynamic virtd, s0, c0.c10",
                      "system_u:system_r:virtd_t:s0-s0:c0.c10",
                      true, NULL, NULL,
                      "system_u", "system_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      0, 0, 0, 10);
    DO_TEST_GEN_LABEL("dynamic virtd, s2-s3, c0.c1023",
                      "system_u:system_r:virtd_t:s2-s3:c0.c1023",
                      true, NULL, NULL,
                      "system_u", "system_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      2, 3, 0, 1023);
    DO_TEST_GEN_LABEL("dynamic virtd, missing range",
                      "system_u:system_r:virtd_t",
                      true, NULL, NULL,
                      "system_u", "system_r", "object_r",
                      "svirt_t", "svirt_image_t",
                      0, 0, 0, 1023);

    virObjectUnref(mgr);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/libsecurityselinuxhelper.so")
