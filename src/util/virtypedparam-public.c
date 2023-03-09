/*
 * virtypedparam-public.c: utility functions for dealing with virTypedParameters
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

#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/* Assign name, type, and convert the argument from a const string.
 * In case of a string, the string is copied.
 * Return 0 on success, -1 after an error message on failure.  */
static int
virTypedParameterAssignFromStr(virTypedParameterPtr param,
                               const char *name,
                               int type,
                               const char *val)
{
    if (!val) {
        virReportError(VIR_ERR_INVALID_ARG, _("NULL value for field '%1$s'"),
                       name);
        return -1;
    }

    if (virStrcpyStatic(param->field, name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Field name '%1$s' too long"),
                       name);
        return -1;
    }

    param->type = type;
    switch (type) {
    case VIR_TYPED_PARAM_INT:
        if (virStrToLong_i(val, NULL, 10, &param->value.i) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid value for field '%1$s': expected int"),
                           name);
            return -1;
        }
        break;
    case VIR_TYPED_PARAM_UINT:
        if (virStrToLong_ui(val, NULL, 10, &param->value.ui) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid value for field '%1$s': expected unsigned int"),
                           name);
            return -1;
        }
        break;
    case VIR_TYPED_PARAM_LLONG:
        if (virStrToLong_ll(val, NULL, 10, &param->value.l) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid value for field '%1$s': expected long long"),
                           name);
            return -1;
        }
        break;
    case VIR_TYPED_PARAM_ULLONG:
        if (virStrToLong_ull(val, NULL, 10, &param->value.ul) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid value for field '%1$s': expected unsigned long long"),
                           name);
            return -1;
        }
        break;
    case VIR_TYPED_PARAM_DOUBLE:
        if (virStrToDouble(val, NULL, &param->value.d) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid value for field '%1$s': expected double"),
                           name);
            return -1;
        }
        break;
    case VIR_TYPED_PARAM_BOOLEAN:
        if (STRCASEEQ(val, "true") || STREQ(val, "1")) {
            param->value.b = true;
        } else if (STRCASEEQ(val, "false") || STREQ(val, "0")) {
            param->value.b = false;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid boolean value for field '%1$s'"), name);
            return -1;
        }
        break;
    case VIR_TYPED_PARAM_STRING:
        param->value.s = g_strdup(val);
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected type %1$d for field %2$s"), type, name);
        return -1;
    }

    return 0;
}

/* The following APIs are public and their signature may never change. */

/**
 * virTypedParamsGet:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 *
 * Finds typed parameter called @name.
 *
 * Returns pointer to the parameter or NULL if it does not exist in @params.
 * This function does not raise an error, even when returning NULL.
 *
 * Since: 1.0.2
 */
virTypedParameterPtr
virTypedParamsGet(virTypedParameterPtr params,
                  int nparams,
                  const char *name)
{
    size_t i;

    /* No need to reset errors, since this function doesn't report any.  */

    if (!params || !name)
        return NULL;

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].field, name))
            return params + i;
    }

    return NULL;
}


#define VIR_TYPED_PARAM_CHECK_TYPE(check_type) \
    do { if (param->type != check_type) { \
        virReportError(VIR_ERR_INVALID_ARG, \
                       _("Invalid type '%1$s' requested for parameter '%2$s', actual type is '%3$s'"), \
                       virTypedParameterTypeToString(check_type), \
                       name, \
                       virTypedParameterTypeToString(param->type)); \
        virDispatchError(NULL); \
        return -1; \
    } } while (0)


/**
 * virTypedParamsGetInt:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its int value in @value. The
 * function fails with VIR_ERR_INVALID_ARG error if the parameter does not
 * have the expected type. By passing NULL as @value, the function may be
 * used to check presence and type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetInt(virTypedParameterPtr params,
                     int nparams,
                     const char *name,
                     int *value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_INT);
    if (value)
        *value = param->value.i;

    return 1;
}


/**
 * virTypedParamsGetUInt:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its unsigned int value in
 * @value. The function fails with VIR_ERR_INVALID_ARG error if the parameter
 * does not have the expected type. By passing NULL as @value, the function
 * may be used to check presence and type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetUInt(virTypedParameterPtr params,
                      int nparams,
                      const char *name,
                      unsigned int *value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_UINT);
    if (value)
        *value = param->value.ui;

    return 1;
}


/**
 * virTypedParamsGetLLong:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its long long int value in
 * @value. The function fails with VIR_ERR_INVALID_ARG error if the parameter
 * does not have the expected type. By passing NULL as @value, the function
 * may be used to check presence and type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetLLong(virTypedParameterPtr params,
                       int nparams,
                       const char *name,
                       long long *value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_LLONG);
    if (value)
        *value = param->value.l;

    return 1;
}


/**
 * virTypedParamsGetULLong:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its unsigned long long int
 * value in @value. The function fails with VIR_ERR_INVALID_ARG error if the
 * parameter does not have the expected type. By passing NULL as @value, the
 * function may be used to check presence and type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetULLong(virTypedParameterPtr params,
                        int nparams,
                        const char *name,
                        unsigned long long *value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_ULLONG);
    if (value)
        *value = param->value.ul;

    return 1;
}


/**
 * virTypedParamsGetDouble:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its double value in @value.
 * The function fails with VIR_ERR_INVALID_ARG error if the parameter does not
 * have the expected type. By passing NULL as @value, the function may be used
 * to check presence and type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetDouble(virTypedParameterPtr params,
                        int nparams,
                        const char *name,
                        double *value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_DOUBLE);
    if (value)
        *value = param->value.d;

    return 1;
}


/**
 * virTypedParamsGetBoolean:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its boolean value in @value.
 * The function fails with VIR_ERR_INVALID_ARG error if the parameter does not
 * have the expected type. By passing NULL as @value, the function may be used
 * to check presence and type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetBoolean(virTypedParameterPtr params,
                         int nparams,
                         const char *name,
                         int *value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_BOOLEAN);
    if (value)
        *value = !!param->value.b;

    return 1;
}


/**
 * virTypedParamsGetString:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @name: name of the parameter to find
 * @value: where to store the parameter's value
 *
 * Finds typed parameter called @name and store its char * value in @value.
 * The function does not create a copy of the string and the caller must not
 * free the string @value points to. The function fails with
 * VIR_ERR_INVALID_ARG error if the parameter does not have the expected type.
 * By passing NULL as @value, the function may be used to check presence and
 * type of the parameter.
 *
 * Returns 1 on success, 0 when the parameter does not exist in @params, or
 * -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsGetString(virTypedParameterPtr params,
                        int nparams,
                        const char *name,
                        const char **value)
{
    virTypedParameterPtr param;

    virResetLastError();

    if (!(param = virTypedParamsGet(params, nparams, name)))
        return 0;

    VIR_TYPED_PARAM_CHECK_TYPE(VIR_TYPED_PARAM_STRING);
    if (value)
        *value = param->value.s;

    return 1;
}


/**
 * virTypedParamsAddInt:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with int type and sets its value to @value.
 * If @params array points to NULL or to a space that is not large enough to
 * accommodate the new parameter (@maxparams < @nparams + 1), the function
 * allocates more space for it and updates @maxparams. On success, @nparams
 * is incremented by one. The function fails with VIR_ERR_INVALID_ARG error
 * if the parameter already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddInt(virTypedParameterPtr *params,
                     int *nparams,
                     int *maxparams,
                     const char *name,
                     int value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_INT, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsAddUInt:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with unsigned int type and sets its value
 * to @value. If @params array points to NULL or to a space that is not large
 * enough to accommodate the new parameter (@maxparams < @nparams + 1), the
 * function allocates more space for it and updates @maxparams. On success,
 * @nparams is incremented by one. The function fails with VIR_ERR_INVALID_ARG
 * error if the parameter already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddUInt(virTypedParameterPtr *params,
                      int *nparams,
                      int *maxparams,
                      const char *name,
                      unsigned int value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_UINT, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsAddLLong:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with long long int type and sets its value
 * to @value. If @params array points to NULL or to a space that is not large
 * enough to accommodate the new parameter (@maxparams < @nparams + 1), the
 * function allocates more space for it and updates @maxparams. On success,
 * @nparams is incremented by one. The function fails with VIR_ERR_INVALID_ARG
 * error if the parameter already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddLLong(virTypedParameterPtr *params,
                       int *nparams,
                       int *maxparams,
                       const char *name,
                       long long value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_LLONG, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsAddULLong:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with unsigned long long type and sets its
 * value to @value. If @params array points to NULL or to a space that is not
 * large enough to accommodate the new parameter (@maxparams < @nparams + 1),
 * the function allocates more space for it and updates @maxparams. On success,
 * @nparams is incremented by one. The function fails with VIR_ERR_INVALID_ARG
 * error if the parameter already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddULLong(virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        const char *name,
                        unsigned long long value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_ULLONG, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsAddDouble:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with double type and sets its value to
 * @value. If @params array points to NULL or to a space that is not large
 * enough to accommodate the new parameter (@maxparams < @nparams + 1), the
 * function allocates more space for it and updates @maxparams. On success,
 * @nparams is incremented by one. The function fails with VIR_ERR_INVALID_ARG
 * error if the parameter already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddDouble(virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        const char *name,
                        double value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_DOUBLE, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsAddBoolean:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with boolean type and sets its value to
 * @value. If @params array points to NULL or to a space that is not large
 * enough to accommodate the new parameter (@maxparams < @nparams + 1), the
 * function allocates more space for it and updates @maxparams. On success,
 * @nparams is incremented by one. The function fails with VIR_ERR_INVALID_ARG
 * error if the parameter already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddBoolean(virTypedParameterPtr *params,
                         int *nparams,
                         int *maxparams,
                         const char *name,
                         int value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_BOOLEAN, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsAddString:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @value: the value to store into the new parameter
 *
 * Adds new parameter called @name with char * type and sets its value to
 * @value. The function creates its own copy of @value string, which needs to
 * be freed using virTypedParamsFree or virTypedParamsClear. If @params array
 * points to NULL or to a space that is not large enough to accommodate the
 * new parameter (@maxparams < @nparams + 1), the function allocates more
 * space for it and updates @maxparams. On success, @nparams is incremented
 * by one. The function fails with VIR_ERR_INVALID_ARG error if the parameter
 * already exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddString(virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        const char *name,
                        const char *value)
{
    char *str = NULL;
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    str = g_strdup(value);

    if (virTypedParameterAssign(*params + n, name,
                                VIR_TYPED_PARAM_STRING, str) < 0) {
        VIR_FREE(str);
        goto error;
    }

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virTypedParamsAddStringList:
 * @params: array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to store values to
 * @values: the values to store into the new parameters
 *
 * Packs NULL-terminated list of strings @values into @params under the
 * key @name.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.2.17
 */
int
virTypedParamsAddStringList(virTypedParameterPtr *params,
                            int *nparams,
                            int *maxparams,
                            const char *name,
                            const char **values)
{
    size_t i;
    int rv = -1;

    if (!values)
        return 0;

    for (i = 0; values[i]; i++) {
        if ((rv = virTypedParamsAddString(params, nparams, maxparams,
                                          name, values[i])) < 0)
            break;
    }

    return rv;
}


/**
 * virTypedParamsAddFromString:
 * @params: pointer to the array of typed parameters
 * @nparams: number of parameters in the @params array
 * @maxparams: maximum number of parameters that can be stored in @params
 *      array without allocating more memory
 * @name: name of the parameter to find
 * @type: type of the parameter
 * @value: the value to store into the new parameter encoded as a string
 *
 * Adds new parameter called @name with the requested @type and parses its
 * value from the @value string. If the requested type is string, the function
 * creates its own copy of the @value string, which needs to be freed using
 * virTypedParamsFree or virTypedParamsClear. If @params array points to NULL
 * or to a space that is not large enough to accommodate the new parameter
 * (@maxparams < @nparams + 1), the function allocates more space for it and
 * updates @maxparams. On success, @nparams is incremented by one. The
 * function fails with VIR_ERR_INVALID_ARG error if the parameter already
 * exists in @params.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 1.0.2
 */
int
virTypedParamsAddFromString(virTypedParameterPtr *params,
                            int *nparams,
                            int *maxparams,
                            const char *name,
                            int type,
                            const char *value)
{
    size_t max = *maxparams;
    size_t n = *nparams;

    virResetLastError();

    VIR_RESIZE_N(*params, max, n, 1);
    *maxparams = max;

    if (virTypedParameterAssignFromStr(*params + n, name, type, value) < 0)
        goto error;

    *nparams += 1;
    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virTypedParamsClear:
 * @params: the array of typed parameters
 * @nparams: number of parameters in the @params array
 *
 * Frees all memory used by string parameters. The memory occupied by @params
 * is not freed; use virTypedParamsFree if you want it to be freed too.
 *
 * Returns nothing.
 *
 * Since: 1.0.2
 */
void
virTypedParamsClear(virTypedParameterPtr params,
                    int nparams)
{
    size_t i;

    if (!params)
        return;

    for (i = 0; i < nparams; i++) {
        if (params[i].type == VIR_TYPED_PARAM_STRING)
            VIR_FREE(params[i].value.s);
    }
}


/**
 * virTypedParamsFree:
 * @params: the array of typed parameters
 * @nparams: number of parameters in the @params array
 *
 * Frees all memory used by string parameters and the memory occupied by
 * @params.
 *
 * Returns nothing.
 *
 * Since: 1.0.2
 */
void
virTypedParamsFree(virTypedParameterPtr params,
                   int nparams)
{
    virTypedParamsClear(params, nparams);
    g_free(params);
}
