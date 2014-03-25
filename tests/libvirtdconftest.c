/*
 * Copyright (C) 2012-2014 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

#include "testutils.h"
#include "daemon/libvirtd-config.h"
#include "virutil.h"
#include "c-ctype.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virconf.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.libvirtdconftest");

struct testCorruptData {
    size_t *params;
    const char *filedata;
    const char *filename;
    size_t paramnum;
};

static char *
munge_param(const char *datain,
            size_t *params,
            size_t paramnum,
            int *type)
{
    char *dataout;
    const char *sol;
    const char *eol;
    const char *eq;
    const char *tmp;
    size_t dataoutlen;
    const char *replace = NULL;

    sol = datain + params[paramnum];
    eq = strchr(sol, '=');
    eol = strchr(sol, '\n');

    for (tmp = eq + 1; tmp < eol  && !replace; tmp++) {
        if (c_isspace(*tmp))
            continue;
        if (c_isdigit(*tmp)) {
            *type = VIR_CONF_LONG;
            replace = "\"foo\"";
        } else if (*tmp == '[') {
            *type = VIR_CONF_LIST;
            replace = "666";
        } else {
            *type = VIR_CONF_STRING;
            replace = "666";
        }
    }

    dataoutlen = (eq - datain) + 1 +
        strlen(replace) +
        strlen(eol) + 1;

    if (VIR_ALLOC_N(dataout, dataoutlen) < 0)
        return NULL;
    memcpy(dataout, datain, (eq - datain) + 1);
    memcpy(dataout + (eq - datain) + 1,
           replace, strlen(replace));
    memcpy(dataout + (eq - datain) + 1 + strlen(replace),
           eol, strlen(eol) + 1);

    return dataout;
}

static int
testCorrupt(const void *opaque)
{
    const struct testCorruptData *data = opaque;
    struct daemonConfig *conf = daemonConfigNew(false);
    int ret = 0;
    int type = VIR_CONF_NONE;
    char *newdata = munge_param(data->filedata,
                                data->params,
                                data->paramnum,
                                &type);
    virErrorPtr err = NULL;

    if (!newdata)
        return -1;

    //VIR_DEBUG("New config [%s]", newdata);

    if (daemonConfigLoadData(conf, data->filename, newdata) != -1) {
        VIR_DEBUG("Did not see a failure");
        ret = -1;
        goto cleanup;
    }

    err = virGetLastError();
    if (!err || !err->message) {
        VIR_DEBUG("No error or message %p", err);
        ret = -1;
        goto cleanup;
    }

#if !WITH_SASL
    if (strstr(err->message, "unsupported auth sasl")) {
        VIR_DEBUG("sasl unsupported, skipping this config");
        goto cleanup;
    }
#endif

    switch (type) {
    case VIR_CONF_LONG:
        if (!strstr(err->message, "invalid type: got string; expected long")) {
            VIR_DEBUG("Wrong error for long: '%s'",
                      err->message);
            ret = -1;
        }
        break;
    case VIR_CONF_STRING:
        if (!strstr(err->message, "invalid type: got long; expected string")) {
            VIR_DEBUG("Wrong error for string: '%s'",
                      err->message);
            ret = -1;
        }
        break;
    case VIR_CONF_LIST:
        if (!strstr(err->message, "must be a string or list of strings")) {
            VIR_DEBUG("Wrong error for list: '%s'",
                      err->message);
            ret = -1;
        }
        break;
    }

 cleanup:
    VIR_FREE(newdata);
    daemonConfigFree(conf);
    return ret;
}

static int
uncomment_all_params(char *data,
                     size_t **ret)
{
    size_t count = 0;
    char *tmp;
    size_t *params = 0;

    tmp = data;
    while (tmp && *tmp) {
        tmp = strchr(tmp, '\n');
        if (!tmp)
            break;

        tmp++;

        /* Uncomment any lines starting   #some_var */
        if (*tmp == '#' &&
            c_isalpha(*(tmp + 1))) {
            if (VIR_EXPAND_N(params, count, 1) < 0) {
                VIR_FREE(params);
                return -1;
            }
            *tmp = ' ';
            params[count-1] = (tmp + 1) - data;
        }
    }
    if (VIR_EXPAND_N(params, count, 1) < 0) {
        VIR_FREE(params);
        return -1;
    }
    params[count-1] = 0;
    *ret = params;
    return count;
}

static int
mymain(void)
{
    int ret = 0;
    char *filedata = NULL;
    char *filename = NULL;
    size_t i;
    size_t *params = NULL;

    if (virAsprintf(&filename, "%s/../daemon/libvirtd.conf",
                    abs_srcdir) < 0) {
        perror("Format filename");
        return EXIT_FAILURE;
    }

    if (virFileReadAll(filename, 1024*1024, &filedata) < 0) {
        virErrorPtr err = virGetLastError();
        fprintf(stderr, "Cannot load %s for testing: %s", filename, err->message);
        ret = -1;
        goto cleanup;
    }

    if (uncomment_all_params(filedata, &params) < 0){
        perror("Find params");
        ret = -1;
        goto cleanup;
    }
    VIR_DEBUG("Initial config [%s]", filedata);
    for (i = 0; params[i] != 0; i++) {
        const struct testCorruptData data = { params, filedata, filename, i };
        /* Skip now ignored config param */
        if (STRPREFIX(filedata + params[i], "log_buffer_size"))
            continue;
        if (virtTestRun("Test corruption", testCorrupt, &data) < 0)
            ret = -1;
    }

 cleanup:
    VIR_FREE(filename);
    VIR_FREE(filedata);
    VIR_FREE(params);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
