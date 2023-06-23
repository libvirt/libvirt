/*
 * virtypedparam.c: utility functions for dealing with virTypedParameters
 *
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>
#include "virtypedparam.h"

#include <stdarg.h>

#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_ENUM_IMPL(virTypedParameter,
              VIR_TYPED_PARAM_LAST,
              "unknown",
              "int",
              "uint",
              "llong",
              "ullong",
              "double",
              "boolean",
              "string",
);

static int
virTypedParamsSortName(const void *left, const void *right)
{
    const virTypedParameter *param_left = left, *param_right = right;
    return strcmp(param_left->field, param_right->field);
}

/* Validate that PARAMS contains only recognized parameter names with
 * correct types, and with no duplicates except for parameters
 * specified with VIR_TYPED_PARAM_MULTIPLE flag in type.
 * Pass in as many name/type pairs as appropriate, and pass NULL to end
 * the list of accepted parameters.  Return 0 on success, -1 on failure
 * with error message already issued.  */
int
virTypedParamsValidate(virTypedParameterPtr params, int nparams, ...)
{
    va_list ap;
    size_t i;
    size_t j;
    const char *name;
    const char *last_name = NULL;
    size_t nkeys = 0;
    size_t nkeysalloc = 0;
    g_autofree virTypedParameterPtr sorted = NULL;
    g_autofree virTypedParameterPtr keys = NULL;

    if (!nparams) {
        return 0;
    }

    va_start(ap, nparams);

    sorted = g_new0(virTypedParameter, nparams);

    /* Here we intentionally don't copy values */
    memcpy(sorted, params, sizeof(*params) * nparams);
    qsort(sorted, nparams, sizeof(*sorted), virTypedParamsSortName);

    name = va_arg(ap, const char *);
    while (name) {
        int type = va_arg(ap, int);
        VIR_RESIZE_N(keys, nkeysalloc, nkeys, 1);

        if (virStrcpyStatic(keys[nkeys].field, name) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field name '%1$s' too long"), name);
            va_end(ap);
            return -1;
        }

        keys[nkeys].type = type & ~VIR_TYPED_PARAM_MULTIPLE;
        /* Value is not used anyway */
        keys[nkeys].value.i = type & VIR_TYPED_PARAM_MULTIPLE;

        nkeys++;
        name = va_arg(ap, const char *);
    }

    va_end(ap);

    qsort(keys, nkeys, sizeof(*keys), virTypedParamsSortName);

    for (i = 0, j = 0; i < nparams && j < nkeys;) {
        if (STRNEQ(sorted[i].field, keys[j].field)) {
            j++;
        } else {
            const char *expecttype = virTypedParameterTypeToString(keys[j].type);
            int type = sorted[i].type;

            if (STREQ_NULLABLE(last_name, sorted[i].field) &&
                !(keys[j].value.i & VIR_TYPED_PARAM_MULTIPLE)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("parameter '%1$s' occurs multiple times"),
                               sorted[i].field);
                return -1;
            }

            if (keys[j].type == VIR_TYPED_PARAM_UNSIGNED &&
                (type == VIR_TYPED_PARAM_UINT ||
                 type == VIR_TYPED_PARAM_ULLONG)) {
                type = VIR_TYPED_PARAM_UNSIGNED;
                expecttype = "uint, ullong";
            }

            if (type != keys[j].type) {
                const char *badtype;

                badtype = virTypedParameterTypeToString(sorted[i].type);
                if (!badtype)
                    badtype = virTypedParameterTypeToString(0);
                virReportError(VIR_ERR_INVALID_ARG,
                               _("invalid type '%1$s' for parameter '%2$s', expected '%3$s'"),
                               badtype, sorted[i].field, expecttype);
                return -1;
            }
            last_name = sorted[i].field;
            i++;
        }
    }

    if (j == nkeys && i != nparams) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("parameter '%1$s' not supported"),
                       sorted[i].field);
        return -1;
    }

    return 0;
}


/* Check if params contains only specified parameter names. Return true if
 * only specified names are present in params, false if params contains any
 * unspecified parameter name. */
bool
virTypedParamsCheck(virTypedParameterPtr params,
                    int nparams,
                    const char **names,
                    int nnames)
{
    size_t i, j;

    for (i = 0; i < nparams; i++) {
        bool found = false;
        for (j = 0; j < nnames; j++) {
            if (STREQ(params[i].field, names[j])) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }

    return true;
}

char *
virTypedParameterToString(virTypedParameterPtr param)
{
    char *value = NULL;

    switch ((virTypedParameterType) param->type) {
    case VIR_TYPED_PARAM_INT:
        value = g_strdup_printf("%d", param->value.i);
        break;
    case VIR_TYPED_PARAM_UINT:
        value = g_strdup_printf("%u", param->value.ui);
        break;
    case VIR_TYPED_PARAM_LLONG:
        value = g_strdup_printf("%lld", param->value.l);
        break;
    case VIR_TYPED_PARAM_ULLONG:
        value = g_strdup_printf("%llu", param->value.ul);
        break;
    case VIR_TYPED_PARAM_DOUBLE:
        value = g_strdup_printf("%g", param->value.d);
        break;
    case VIR_TYPED_PARAM_BOOLEAN:
        value = g_strdup_printf("%d", param->value.b);
        break;
    case VIR_TYPED_PARAM_STRING:
        value = g_strdup(param->value.s);
        break;
    case VIR_TYPED_PARAM_LAST:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected type %1$d for field %2$s"),
                       param->type, param->field);
    }

    return value;
}


static void
virTypedParameterAssignValueVArgs(virTypedParameterPtr param,
                                  virTypedParameterType type,
                                  va_list ap,
                                  bool copystr)
{
    param->type = type;
    switch (type) {
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
        if (copystr) {
            param->value.s = g_strdup(va_arg(ap, char *));
        } else {
            param->value.s = va_arg(ap, char *);
        }

        if (!param->value.s)
            param->value.s = g_strdup("");
        break;
    case VIR_TYPED_PARAM_LAST:
        break;
    }
}


static void
virTypedParameterAssignValue(virTypedParameterPtr param,
                             virTypedParameterType type,
                             ...)
{
    va_list ap;

    va_start(ap, type);
    virTypedParameterAssignValueVArgs(param, type, ap, true);
    va_end(ap);
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

    if (virStrcpyStatic(param->field, name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Field name '%1$s' too long"),
                       name);
        return -1;
    }

    if (type < VIR_TYPED_PARAM_INT ||
        type >= VIR_TYPED_PARAM_LAST) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected type %1$d for field %2$s"), type, name);
        return -1;
    }

    va_start(ap, type);
    virTypedParameterAssignValueVArgs(param, type, ap, false);
    va_end(ap);

    return 0;
}


/**
 * virTypedParamsReplaceString:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to set
 * @value: the value to store into the parameter
 *
 * Sets new value @value to parameter called @name with char * type. If the
 * parameter does not exist yet in @params, it is automatically created and
 * @naprams is incremented by one. Otherwise current value of the parameter
 * is freed on success. The function creates its own copy of @value string,
 * which needs to be freed using virTypedParamsFree or virTypedParamsClear.
 *
 * Returns 0 on success, -1 on error.
 */
int
virTypedParamsReplaceString(virTypedParameterPtr *params,
                            int *nparams,
                            const char *name,
                            const char *value)
{
    char *str = NULL;
    char *old = NULL;
    size_t n = *nparams;
    virTypedParameterPtr param;

    param = virTypedParamsGet(*params, n, name);
    if (param) {
        if (param->type != VIR_TYPED_PARAM_STRING) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Parameter '%1$s' is not a string"),
                           param->field);
            return -1;
        }
        old = param->value.s;
    } else {
        VIR_EXPAND_N(*params, n, 1);
        param = *params + n - 1;
    }

    str = g_strdup(value);

    if (virTypedParameterAssign(param, name,
                                VIR_TYPED_PARAM_STRING, str) < 0) {
        param->value.s = old;
        VIR_FREE(str);
        return -1;
    }
    VIR_FREE(old);

    *nparams = n;
    return 0;
}


void
virTypedParamsCopy(virTypedParameterPtr *dst,
                   virTypedParameterPtr src,
                   int nparams)
{
    size_t i;

    *dst = NULL;
    if (!src || nparams <= 0)
        return;

    *dst = g_new0(virTypedParameter, nparams);

    for (i = 0; i < nparams; i++) {
        ignore_value(virStrcpyStatic((*dst)[i].field, src[i].field));
        (*dst)[i].type = src[i].type;
        if (src[i].type == VIR_TYPED_PARAM_STRING) {
            (*dst)[i].value.s = g_strdup(src[i].value.s);
        } else {
            (*dst)[i].value = src[i].value;
        }
    }
}


/**
 * virTypedParamsFilter:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @ret: pointer to the returned array
 *
 * Filters @params retaining only the parameters named @name in the
 * resulting array @ret. Caller should free the @ret array but not
 * the items since they are pointing to the @params elements.
 *
 * Returns amount of elements in @ret on success, -1 on error.
 */
int
virTypedParamsFilter(virTypedParameterPtr params,
                     int nparams,
                     const char *name,
                     virTypedParameterPtr **ret)
{
    size_t i, n = 0;

    *ret = g_new0(virTypedParameterPtr, nparams);

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].field, name)) {
            (*ret)[n] = &params[i];
            n++;
        }
    }

    return n;
}


/**
 * virTypedParamsGetStringList:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @values: array of returned values
 *
 * Finds all parameters with desired @name within @params and
 * store their values into @values. The @values array is self
 * allocated and its length is stored into @picked. When no
 * longer needed, caller should free the returned array, but not
 * the items since they are taken from @params array.
 *
 * Returns amount of strings in @values array on success,
 * -1 otherwise.
 */
int
virTypedParamsGetStringList(virTypedParameterPtr params,
                            int nparams,
                            const char *name,
                            const char ***values)
{
    size_t i, n;
    int nfiltered;
    virTypedParameterPtr *filtered = NULL;

    virCheckNonNullArgGoto(values, error);
    *values = NULL;

    nfiltered = virTypedParamsFilter(params, nparams, name, &filtered);

    if (nfiltered < 0)
        goto error;

    if (nfiltered)
        *values = g_new0(const char *, nfiltered);

    for (n = 0, i = 0; i < nfiltered; i++) {
        if (filtered[i]->type == VIR_TYPED_PARAM_STRING)
            (*values)[n++] = filtered[i]->value.s;
    }

    VIR_FREE(filtered);
    return n;

 error:
    if (values)
        VIR_FREE(*values);
    VIR_FREE(filtered);
    return -1;
}


/**
 * virTypedParamsGetUnsigned:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its 'unsigned long long' or
 * 'unsigned int' value in @value.
 *
 * This is an internal variand which expects that the typed parameters were
 * already validated by calling virTypedParamsValidate and the appropriate
 * parameter has the expected type.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on invalid usage.
 */
int
virTypedParamsGetUnsigned(virTypedParameterPtr params,
                          int nparams,
                          const char *name,
                          unsigned long long *value)
{
    virTypedParameterPtr param;

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    switch ((virTypedParameterType) param->type) {
    case VIR_TYPED_PARAM_UINT:
        *value = param->value.ui;
        break;

    case VIR_TYPED_PARAM_ULLONG:
        *value = param->value.ul;
        break;

    case VIR_TYPED_PARAM_INT:
    case VIR_TYPED_PARAM_LLONG:
    case VIR_TYPED_PARAM_DOUBLE:
    case VIR_TYPED_PARAM_BOOLEAN:
    case VIR_TYPED_PARAM_STRING:
    case VIR_TYPED_PARAM_LAST:
    default:
        return -1;
    }

    return 1;
}


/**
 * virTypedParamsRemoteFree:
 * @remote_params_val: array of typed parameters as specified by
 *                     (remote|admin)_protocol.h
 * @remote_params_len: number of parameters in @remote_params_val
 *
 * Frees memory used by string representations of parameter identificators,
 * memory used by string values of parameters and the memory occupied by
 * @remote_params_val itself.
 *
 * Returns nothing.
 */
void
virTypedParamsRemoteFree(struct _virTypedParameterRemote *remote_params_val,
                         unsigned int remote_params_len)
{
    size_t i;

    if (!remote_params_val)
        return;

    for (i = 0; i < remote_params_len; i++) {
        g_free(remote_params_val[i].field);
        if (remote_params_val[i].value.type == VIR_TYPED_PARAM_STRING)
            g_free(remote_params_val[i].value.remote_typed_param_value.s);
    }
    g_free(remote_params_val);
}


/**
 * virTypedParamsDeserialize:
 * @remote_params: protocol data to be deserialized (obtained from remote side)
 * @remote_params_len: number of parameters returned in @remote_params
 * @limit: user specified maximum limit to @remote_params_len
 * @params: pointer which will hold the deserialized @remote_params data
 * @nparams: number of entries in @params
 *
 * This function will attempt to deserialize protocol-encoded data obtained
 * from remote side. Two modes of operation are supported, depending on the
 * caller's design:
 * 1) Older APIs do not rely on deserializer allocating memory for @params,
 *    thus calling the deserializer twice, once to find out the actual number of
 *    parameters for @params to hold, followed by an allocation of @params and
 *    a second call to the deserializer to actually retrieve the data.
 * 2) Newer APIs rely completely on the deserializer to allocate the right
 *    amount of memory for @params to hold all the data obtained in
 *    @remote_params.
 *
 * If used with model 1, two checks are performed, first one comparing the user
 * specified limit to the actual size of remote data and the second one
 * verifying the user allocated amount of memory is indeed capable of holding
 * remote data @remote_params.
 * With model 2, only the first check against @limit is performed.
 *
 * Returns 0 on success or -1 in case of an error.
 */
int
virTypedParamsDeserialize(struct _virTypedParameterRemote *remote_params,
                          unsigned int remote_params_len,
                          int limit,
                          virTypedParameterPtr *params,
                          int *nparams)
{
    size_t i = 0;
    int rv = -1;
    bool userAllocated = *params != NULL;

    if (limit && remote_params_len > limit) {
        virReportError(VIR_ERR_RPC,
                       _("too many parameters '%1$u' for limit '%2$d'"),
                       remote_params_len, limit);
        goto cleanup;
    }

    if (userAllocated) {
        /* Check the length of the returned list carefully. */
        if (remote_params_len > *nparams) {
            virReportError(VIR_ERR_RPC,
                           _("too many parameters '%1$u' for nparams '%2$d'"),
                           remote_params_len, *nparams);
            goto cleanup;
        }
    } else {
        *params = g_new0(virTypedParameter, remote_params_len);
    }
    *nparams = remote_params_len;

    /* Deserialize the result. */
    for (i = 0; i < remote_params_len; ++i) {
        virTypedParameterPtr param = *params + i;
        struct _virTypedParameterRemote *remote_param = remote_params + i;

        if (virStrcpyStatic(param->field,
                            remote_param->field) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("parameter %1$s too big for destination"),
                           remote_param->field);
            goto cleanup;
        }

        param->type = remote_param->value.type;
        switch ((virTypedParameterType) param->type) {
        case VIR_TYPED_PARAM_INT:
            param->value.i = remote_param->value.remote_typed_param_value.i;
            break;
        case VIR_TYPED_PARAM_UINT:
            param->value.ui = remote_param->value.remote_typed_param_value.ui;
            break;
        case VIR_TYPED_PARAM_LLONG:
            param->value.l = remote_param->value.remote_typed_param_value.l;
            break;
        case VIR_TYPED_PARAM_ULLONG:
            param->value.ul = remote_param->value.remote_typed_param_value.ul;
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            param->value.d = remote_param->value.remote_typed_param_value.d;
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            param->value.b = remote_param->value.remote_typed_param_value.b;
            break;
        case VIR_TYPED_PARAM_STRING:
            param->value.s = g_strdup(remote_param->value.remote_typed_param_value.s);
            break;
        case VIR_TYPED_PARAM_LAST:
        default:
            virReportError(VIR_ERR_RPC, _("unknown parameter type: %1$d"),
                           param->type);
            goto cleanup;
        }
    }

    rv = 0;

 cleanup:
    if (rv < 0) {
        if (userAllocated) {
            virTypedParamsClear(*params, i);
        } else {
            virTypedParamsFree(*params, i);
            *params = NULL;
            *nparams = 0;
        }
    }
    return rv;
}


/**
 * virTypedParamsSerialize:
 * @params: array of parameters to be serialized and later sent to remote side
 * @nparams: number of elements in @params
 * @limit: user specified maximum limit to @remote_params_len
 * @remote_params_val: protocol independent remote representation of @params
 * @remote_params_len: the final number of elements in @remote_params_val
 * @flags: bitwise-OR of virTypedParameterFlags
 *
 * This method serializes typed parameters provided by @params into
 * @remote_params_val which is the representation actually being sent.
 * It also checks, if the @limit imposed by RPC on the maximum number of
 * parameters is not exceeded.
 *
 * Server side using this method also filters out any string parameters that
 * must not be returned to older clients and handles possibly sparse arrays
 * returned by some APIs.
 *
 * Returns 0 on success, -1 on error.
 */
int
virTypedParamsSerialize(virTypedParameterPtr params,
                        int nparams,
                        int limit,
                        struct _virTypedParameterRemote **remote_params_val,
                        unsigned int *remote_params_len,
                        unsigned int flags)
{
    size_t i;
    size_t j;
    int rv = -1;
    struct _virTypedParameterRemote *params_val = NULL;
    int params_len = nparams;

    if (nparams > limit) {
        virReportError(VIR_ERR_RPC,
                       _("too many parameters '%1$d' for limit '%2$d'"),
                       nparams, limit);
        goto cleanup;
    }

    params_val = g_new0(struct _virTypedParameterRemote, nparams);

    for (i = 0, j = 0; i < nparams; ++i) {
        virTypedParameterPtr param = params + i;
        struct _virTypedParameterRemote *val = params_val + j;
        /* NOTE: Following snippet is relevant to server only, because
         * virDomainGetCPUStats can return a sparse array; also, we can't pass
         * back strings to older clients. */
        if (!param->type ||
            (!(flags & VIR_TYPED_PARAM_STRING_OKAY) &&
             param->type == VIR_TYPED_PARAM_STRING)) {
            --params_len;
            continue;
        }

        /* This will be either freed by virNetServerDispatchCall or call(),
         * depending on the calling side, i.e. server or client */
        val->field = g_strdup(param->field);
        val->value.type = param->type;
        switch ((virTypedParameterType) param->type) {
        case VIR_TYPED_PARAM_INT:
            val->value.remote_typed_param_value.i = param->value.i;
            break;
        case VIR_TYPED_PARAM_UINT:
            val->value.remote_typed_param_value.ui = param->value.ui;
            break;
        case VIR_TYPED_PARAM_LLONG:
            val->value.remote_typed_param_value.l = param->value.l;
            break;
        case VIR_TYPED_PARAM_ULLONG:
            val->value.remote_typed_param_value.ul = param->value.ul;
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            val->value.remote_typed_param_value.d = param->value.d;
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            val->value.remote_typed_param_value.b = param->value.b;
            break;
        case VIR_TYPED_PARAM_STRING:
            val->value.remote_typed_param_value.s = g_strdup(param->value.s);
            break;
        case VIR_TYPED_PARAM_LAST:
        default:
            virReportError(VIR_ERR_RPC, _("unknown parameter type: %1$d"),
                           param->type);
            goto cleanup;
        }
        j++;
    }

    *remote_params_len = params_len;
    *remote_params_val = g_steal_pointer(&params_val);
    rv = 0;

 cleanup:
    virTypedParamsRemoteFree(params_val, nparams);
    return rv;
}


struct _virTypedParamList {
    virTypedParameterPtr par;
    size_t npar;
    size_t par_alloc;

    char *err_name; /* overly long field name for error message */
};


virTypedParamList *
virTypedParamListNew(void)
{
    return g_new0(virTypedParamList, 1);
}


/**
 * virTypedParamListConcat:
 * @to: typed param list to concatenate into
 * @fromptr: pointer to pointer to a typed param list to concatenate into @to
 *
 * Concatenates all params from the virTypedParamList pointed to by @fromptr
 * into @to and deallocates the list pointed to by @fromptr and clears the
 * variable.
 */
void
virTypedParamListConcat(virTypedParamList *to,
                        virTypedParamList **fromptr)
{
    g_autoptr(virTypedParamList) from = g_steal_pointer(fromptr);

    VIR_RESIZE_N(to->par, to->par_alloc, to->npar, from->npar);

    memcpy(to->par + to->npar, from->par, sizeof(*(to->par)) * from->npar);
    to->npar += from->npar;
    from->npar = 0;

    if (!to->err_name)
        to->err_name = g_steal_pointer(&from->err_name);
}


void
virTypedParamListFree(virTypedParamList *list)
{
    if (!list)
        return;

    virTypedParamsFree(list->par, list->npar);
    g_free(list->err_name);
    g_free(list);
}


/**
 * virTypedParamListFetch:
 *
 * @list: virTypedParamList object
 * @par: if not NULL filled with the typed parameters stored in @list
 * @npar: if not NULL filled with the number of typed parameters stored in @list
 *
 * Checks that @list has no errors stored and optionally fills @par and @npar
 * with a valid list of typed parameters. The typed parameters still belong to
 * @list and will be freed together.
 */
int
virTypedParamListFetch(virTypedParamList *list,
                       virTypedParameterPtr *par,
                       size_t *npar)
{
    if (list->err_name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Field name '%1$s' too long"),
                       list->err_name);
        return -1;
    }

    if (par)
        *par = list->par;

    if (npar)
        *npar = list->npar;

    return 0;
}


int
virTypedParamListSteal(virTypedParamList *list,
                       virTypedParameterPtr *par,
                       int *npar)
{
    size_t nparams;

    if (virTypedParamListFetch(list, par, &nparams) < 0)
        return -1;

    /* most callers expect 'int', so help them out */
    *npar = nparams;

    list->par = NULL;
    list->npar = 0;
    list->par_alloc = 0;

    return 0;
}


virTypedParamList *
virTypedParamListFromParams(virTypedParameterPtr *params,
                            size_t nparams)
{
    virTypedParamList *l = virTypedParamListNew();

    l->par = g_steal_pointer(params);
    l->npar = nparams;
    l->par_alloc = nparams;

    return l;
}


static void G_GNUC_PRINTF(3, 0)
virTypedParamSetNameVPrintf(virTypedParamList *list,
                            virTypedParameterPtr par,
                            const char *fmt,
                            va_list ap)
{
    g_autofree char *name = g_strdup_vprintf(fmt, ap);

    if (virStrcpyStatic(par->field, name) < 0) {
        if (!list->err_name)
            list->err_name = g_steal_pointer(&name);
    }
}


static virTypedParameterPtr
virTypedParamListExtend(virTypedParamList *list)
{
    VIR_RESIZE_N(list->par, list->par_alloc, list->npar, 1);

    list->npar++;

    return list->par + (list->npar - 1);
}


void
virTypedParamListAddInt(virTypedParamList *list,
                        int value,
                        const char *namefmt,
                        ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_INT, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


void
virTypedParamListAddUInt(virTypedParamList *list,
                         unsigned int value,
                         const char *namefmt,
                         ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_UINT, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


void
virTypedParamListAddLLong(virTypedParamList *list,
                          long long value,
                          const char *namefmt,
                          ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_LLONG, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


void
virTypedParamListAddULLong(virTypedParamList *list,
                           unsigned long long value,
                           const char *namefmt,
                           ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_ULLONG, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


/**
 * virTypedParamListAddUnsigned:
 * @list: typed parameter list
 * @value: value to add  (see below on details)
 * @namefmt: formatting string for constructing the name of the added value
 * @...: additional parameters to format the name
 *
 * Adds a new typed parameter to @list. The name of the parameter is formatted
 * from @fmt.
 *
 * @value is added as VIR_TYPED_PARAM_UINT, unless it doesn't fit into the data
 * type in which case it's added as VIR_TYPED_PARAM_ULLONG.
 */
void
virTypedParamListAddUnsigned(virTypedParamList *list,
                             unsigned long long value,
                             const char *namefmt,
                             ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    if (value > UINT_MAX) {
        virTypedParameterAssignValue(par, VIR_TYPED_PARAM_ULLONG, value);
    } else {
        unsigned int ival = value;

        virTypedParameterAssignValue(par, VIR_TYPED_PARAM_UINT, ival);
    }

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


void
virTypedParamListAddString(virTypedParamList *list,
                           const char *value,
                           const char *namefmt,
                           ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_STRING, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


void
virTypedParamListAddBoolean(virTypedParamList *list,
                            bool value,
                            const char *namefmt,
                            ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_BOOLEAN, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}


void
virTypedParamListAddDouble(virTypedParamList *list,
                           double value,
                           const char *namefmt,
                           ...)
{
    virTypedParameterPtr par = virTypedParamListExtend(list);
    va_list ap;

    virTypedParameterAssignValue(par, VIR_TYPED_PARAM_DOUBLE, value);

    va_start(ap, namefmt);
    virTypedParamSetNameVPrintf(list, par, namefmt, ap);
    va_end(ap);
}
