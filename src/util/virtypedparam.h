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


#ifndef __VIR_TYPED_PARAM_H_
# define __VIR_TYPED_PARAM_H_

# include "internal.h"
# include "virutil.h"

int virTypedParamsValidate(virTypedParameterPtr params, int nparams,
                           /* const char *name, int type ... */ ...)
    ATTRIBUTE_SENTINEL ATTRIBUTE_RETURN_CHECK;

bool virTypedParamsCheck(virTypedParameterPtr params,
                         int nparams,
                         const char **names,
                         int nnames);

int virTypedParameterAssign(virTypedParameterPtr param, const char *name,
                            int type, /* TYPE arg */ ...)
    ATTRIBUTE_RETURN_CHECK;

int virTypedParameterAssignFromStr(virTypedParameterPtr param,
                                   const char *name,
                                   int type,
                                   const char *val)
    ATTRIBUTE_RETURN_CHECK;

int virTypedParamsReplaceString(virTypedParameterPtr *params,
                                int *nparams,
                                const char *name,
                                const char *value);

int virTypedParamsCopy(virTypedParameterPtr *dst,
                       virTypedParameterPtr src,
                       int nparams);

char *virTypedParameterToString(virTypedParameterPtr param);

VIR_ENUM_DECL(virTypedParameter)

# define VIR_TYPED_PARAMS_DEBUG(params, nparams)                            \
    do {                                                                    \
        int _i;                                                             \
        if (!params)                                                        \
            break;                                                          \
        for (_i = 0; _i < (nparams); _i++) {                                \
            char *_value = virTypedParameterToString((params) + _i);        \
            VIR_DEBUG("params[\"%s\"]=(%s)%s",                              \
                      (params)[_i].field,                                   \
                      virTypedParameterTypeToString((params)[_i].type),     \
                      NULLSTR(_value));                                     \
            VIR_FREE(_value);                                               \
        }                                                                   \
    } while (0)

#endif /* __VIR_TYPED_PARAM_H */
