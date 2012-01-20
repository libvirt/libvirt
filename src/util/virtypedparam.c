/*
 * virtypedparam.c: utility functions for dealing with virTypedParameters
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
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
#include "virtypedparam.h"

#include <stdarg.h>

#include "memory.h"
#include "util.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virUtilError(code, ...)                                            \
        virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,                \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

VIR_ENUM_DECL(virTypedParameter)
VIR_ENUM_IMPL(virTypedParameter, VIR_TYPED_PARAM_LAST,
              "unknown",
              "int",
              "uint",
              "llong",
              "ullong",
              "double",
              "boolean",
              "string")

void
virTypedParameterArrayClear(virTypedParameterPtr params, int nparams)
{
    int i;

    if (!params)
        return;

    for (i = 0; i < nparams; i++) {
        if (params[i].type == VIR_TYPED_PARAM_STRING)
            VIR_FREE(params[i].value.s);
    }
}

/* Validate that PARAMS contains only recognized parameter names with
 * correct types, and with no duplicates.  Pass in as many name/type
 * pairs as appropriate, and pass NULL to end the list of accepted
 * parameters.  Return 0 on success, -1 on failure with error message
 * already issued.  */
int
virTypedParameterArrayValidate(virTypedParameterPtr params, int nparams, ...)
{
    va_list ap;
    int ret = -1;
    int i, j;
    const char *name;
    int type;

    va_start(ap, nparams);

    /* Yes, this is quadratic, but since we reject duplicates and
     * unknowns, it is constrained by the number of var-args passed
     * in, which is expected to be small enough to not be
     * noticeable.  */
    for (i = 0; i < nparams; i++) {
        va_end(ap);
        va_start(ap, nparams);

        name = va_arg(ap, const char *);
        while (name) {
            type = va_arg(ap, int);
            if (STREQ(params[i].field, name)) {
                if (params[i].type != type) {
                    const char *badtype;

                    badtype = virTypedParameterTypeToString(params[i].type);
                    if (!badtype)
                        badtype = virTypedParameterTypeToString(0);
                    virUtilError(VIR_ERR_INVALID_ARG,
                                 _("invalid type '%s' for parameter '%s', "
                                   "expected '%s'"),
                                 badtype, params[i].field,
                                 virTypedParameterTypeToString(type));
                }
                break;
            }
            name = va_arg(ap, const char *);
        }
        if (!name) {
            virUtilError(VIR_ERR_INVALID_ARG,
                         _("parameter '%s' not supported"),
                         params[i].field);
            goto cleanup;
        }
        for (j = 0; j < i; j++) {
            if (STREQ(params[i].field, params[j].field)) {
                virUtilError(VIR_ERR_INVALID_ARG,
                             _("parameter '%s' occurs multiple times"),
                             params[i].field);
                goto cleanup;
            }
        }
    }

    ret = 0;
cleanup:
    va_end(ap);
    return ret;

}

/* Assign name, type, and the appropriately typed arg to param; in the
 * case of a string, the caller is assumed to have malloc'd a string,
 * or can pass NULL to have this function malloc an empty string.
 * Return 0 on success, -1 after an error message on failure.  */
int
virTypedParameterAssign(virTypedParameterPtr param, const char *name,
                        int type, ...)
{
    va_list ap;
    int ret = -1;

    va_start(ap, type);

    if (virStrcpyStatic(param->field, name) == NULL) {
        virUtilError(VIR_ERR_INTERNAL_ERROR, _("Field name '%s' too long"),
                     name);
        goto cleanup;
    }
    param->type = type;
    switch (type)
    {
    case VIR_TYPED_PARAM_INT:
        param->value.i = va_arg(ap, int);
        break;
    case VIR_TYPED_PARAM_UINT:
        param->value.ui = va_arg(ap, unsigned int);
        break;
    case VIR_TYPED_PARAM_LLONG:
        param->value.l = va_arg(ap, long long int);
        break;
    case VIR_TYPED_PARAM_ULLONG:
        param->value.ul = va_arg(ap, unsigned long long int);
        break;
    case VIR_TYPED_PARAM_DOUBLE:
        param->value.d = va_arg(ap, double);
        break;
    case VIR_TYPED_PARAM_BOOLEAN:
        param->value.b = !!va_arg(ap, int);
        break;
    case VIR_TYPED_PARAM_STRING:
        param->value.s = va_arg(ap, char *);
        if (!param->value.s)
            param->value.s = strdup("");
        if (!param->value.s) {
            virReportOOMError();
            goto cleanup;
        }
        break;
    default:
        virUtilError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected type %d for field %s"), type, name);
        goto cleanup;
    }

    ret = 0;
cleanup:
    va_end(ap);
    return ret;
}
