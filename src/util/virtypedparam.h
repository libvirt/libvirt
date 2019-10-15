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
#include "virutil.h"
#include "virenum.h"
#include "virautoclean.h"

/**
 * VIR_TYPED_PARAM_MULTIPLE:
 *
 * Flag indicating that the params has multiple occurrences of the parameter.
 * Only used as a flag for @type argument of the virTypedParamsValidate.
 */
#define VIR_TYPED_PARAM_MULTIPLE (1U << 31)

verify(!(VIR_TYPED_PARAM_LAST & VIR_TYPED_PARAM_MULTIPLE));

typedef struct _virTypedParameterRemoteValue virTypedParameterRemoteValue;
typedef struct virTypedParameterRemoteValue *virTypedParameterRemoteValuePtr;

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

typedef struct _virTypedParameterRemote *virTypedParameterRemotePtr;

struct _virTypedParameterRemote {
    char *field;
    virTypedParameterRemoteValue value;
};


int virTypedParamsValidate(virTypedParameterPtr params, int nparams,
                           /* const char *name, int type ... */ ...)
    G_GNUC_NULL_TERMINATED G_GNUC_WARN_UNUSED_RESULT;

bool virTypedParamsCheck(virTypedParameterPtr params,
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


int virTypedParameterAssign(virTypedParameterPtr param, const char *name,
                            int type, /* TYPE arg */ ...)
    G_GNUC_WARN_UNUSED_RESULT;

int virTypedParamsReplaceString(virTypedParameterPtr *params,
                                int *nparams,
                                const char *name,
                                const char *value);

int virTypedParamsCopy(virTypedParameterPtr *dst,
                       virTypedParameterPtr src,
                       int nparams);

char *virTypedParameterToString(virTypedParameterPtr param);

void virTypedParamsRemoteFree(virTypedParameterRemotePtr remote_params_val,
                              unsigned int remote_params_len);

int virTypedParamsDeserialize(virTypedParameterRemotePtr remote_params,
                              unsigned int remote_params_len,
                              int limit,
                              virTypedParameterPtr *params,
                              int *nparams);

int virTypedParamsSerialize(virTypedParameterPtr params,
                            int nparams,
                            int limit,
                            virTypedParameterRemotePtr *remote_params_val,
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
typedef virTypedParamList *virTypedParamListPtr;

struct _virTypedParamList {
    virTypedParameterPtr par;
    size_t npar;
    size_t par_alloc;
};

void virTypedParamListFree(virTypedParamListPtr list);
VIR_DEFINE_AUTOPTR_FUNC(virTypedParamList, virTypedParamListFree);

size_t virTypedParamListStealParams(virTypedParamListPtr list,
                                    virTypedParameterPtr *params);

int virTypedParamListAddInt(virTypedParamListPtr list,
                            int value,
                            const char *namefmt,
                            ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
int virTypedParamListAddUInt(virTypedParamListPtr list,
                             unsigned int value,
                             const char *namefmt,
                             ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
int virTypedParamListAddLLong(virTypedParamListPtr list,
                              long long value,
                              const char *namefmt,
                              ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
int virTypedParamListAddULLong(virTypedParamListPtr list,
                               unsigned long long value,
                               const char *namefmt,
                               ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
int virTypedParamListAddString(virTypedParamListPtr list,
                               const char *value,
                               const char *namefmt,
                               ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
int virTypedParamListAddBoolean(virTypedParamListPtr list,
                                bool value,
                                const char *namefmt,
                                ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
int virTypedParamListAddDouble(virTypedParamListPtr list,
                               double value,
                               const char *namefmt,
                               ...)
    G_GNUC_PRINTF(3, 4) G_GNUC_WARN_UNUSED_RESULT;
