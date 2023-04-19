/*
 * virtypedparam.h: managing typed parameters
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "internal.h"
#include "virenum.h"


/**
 * VIR_TYPED_PARAM_UNSIGNED:
 *
 * Special typed parameter type only used with virTypedParamsValidate to
 * indicate that both VIR_TYPED_PARAM_UINT and VIR_TYPED_PARAM_ULLONG types
 * are acceptable for given value.
 */
#define VIR_TYPED_PARAM_UNSIGNED (VIR_TYPED_PARAM_LAST + 1)
/**
 * VIR_TYPED_PARAM_MULTIPLE:
 *
 * Flag indicating that the params has multiple occurrences of the parameter.
 * Only used as a flag for @type argument of the virTypedParamsValidate.
 */
#define VIR_TYPED_PARAM_MULTIPLE (1U << 31)

G_STATIC_ASSERT(!(VIR_TYPED_PARAM_LAST & VIR_TYPED_PARAM_MULTIPLE));

typedef struct _virTypedParameterRemoteValue virTypedParameterRemoteValue;
struct _virTypedParameterRemoteValue {
    int type;
    union {
        int i; /* exempt from syntax-check */
        unsigned int ui;
        long long int l;
        unsigned long long int ul;
        double d;
        char b;
        char *s;
    } remote_typed_param_value;
};


struct _virTypedParameterRemote {
    char *field;
    virTypedParameterRemoteValue value;
};


int
virTypedParamsValidate(virTypedParameterPtr params,
                       int nparams,
                       /* const char *name, int type ... */ ...)
    G_GNUC_NULL_TERMINATED G_GNUC_WARN_UNUSED_RESULT;

bool
virTypedParamsCheck(virTypedParameterPtr params,
                    int nparams,
                    const char **names,
                    int nnames);

int
virTypedParamsGetStringList(virTypedParameterPtr params,
                            int nparams,
                            const char *name,
                            const char ***values);
int
virTypedParamsFilter(virTypedParameterPtr params,
                     int nparams,
                     const char *name,
                     virTypedParameterPtr **ret)
    G_GNUC_WARN_UNUSED_RESULT;

int
virTypedParamsGetUnsigned(virTypedParameterPtr params,
                          int nparams,
                          const char *name,
                          unsigned long long *value);

int
virTypedParameterAssign(virTypedParameterPtr param,
                        const char *name,
                        int type, /* TYPE arg */ ...)
    G_GNUC_WARN_UNUSED_RESULT;

int
virTypedParamsReplaceString(virTypedParameterPtr *params,
                            int *nparams,
                            const char *name,
                            const char *value);

void
virTypedParamsCopy(virTypedParameterPtr *dst,
                   virTypedParameterPtr src,
                   int nparams);

char *
virTypedParameterToString(virTypedParameterPtr param);

void
virTypedParamsRemoteFree(struct _virTypedParameterRemote *remote_params_val,
                         unsigned int remote_params_len);

int
virTypedParamsDeserialize(struct _virTypedParameterRemote *remote_params,
                          unsigned int remote_params_len,
                          int limit,
                          virTypedParameterPtr *params,
                          int *nparams);

int
virTypedParamsSerialize(virTypedParameterPtr params,
                        int nparams,
                        int limit,
                        struct _virTypedParameterRemote **remote_params_val,
                        unsigned int *remote_params_len,
                        unsigned int flags);

VIR_ENUM_DECL(virTypedParameter);

#define VIR_TYPED_PARAMS_DEBUG(params, nparams) \
    do { \
        int _i; \
        if (!params) \
            break; \
        for (_i = 0; _i < (nparams); _i++) { \
            char *_value = virTypedParameterToString((params) + _i); \
            VIR_DEBUG("params[\"%s\"]=(%s)%s", \
                      (params)[_i].field, \
                      virTypedParameterTypeToString((params)[_i].type), \
                      NULLSTR(_value)); \
            VIR_FREE(_value); \
        } \
    } while (0)

typedef struct _virTypedParamList virTypedParamList;

void
virTypedParamListFree(virTypedParamList *list);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virTypedParamList, virTypedParamListFree);
virTypedParamList *virTypedParamListNew(void);

int
virTypedParamListSteal(virTypedParamList *list,
                       virTypedParameterPtr *par,
                       int *npar);

int
virTypedParamListFetch(virTypedParamList *list,
                           virTypedParameterPtr *par,
                           size_t *npar)
    G_GNUC_WARN_UNUSED_RESULT;

virTypedParamList *
virTypedParamListFromParams(virTypedParameterPtr *params,
                            size_t nparams);

void
virTypedParamListConcat(virTypedParamList *to,
                        virTypedParamList **fromptr);

void
virTypedParamListAddInt(virTypedParamList *list,
                        int value,
                        const char *namefmt,
                        ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddUInt(virTypedParamList *list,
                         unsigned int value,
                         const char *namefmt,
                         ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddLLong(virTypedParamList *list,
                          long long value,
                          const char *namefmt,
                          ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddULLong(virTypedParamList *list,
                           unsigned long long value,
                           const char *namefmt,
                           ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddUnsigned(virTypedParamList *list,
                             unsigned long long value,
                             const char *namefmt,
                             ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddString(virTypedParamList *list,
                           const char *value,
                           const char *namefmt,
                           ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddBoolean(virTypedParamList *list,
                            bool value,
                            const char *namefmt,
                            ...)
    G_GNUC_PRINTF(3, 4);
void
virTypedParamListAddDouble(virTypedParamList *list,
                           double value,
                           const char *namefmt,
                           ...)
    G_GNUC_PRINTF(3, 4);
