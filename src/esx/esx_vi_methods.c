/*
 * esx_vi_methods.c: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2009-2010 Matthias Bolte <matthias.bolte@googlemail.com>
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

#include "virbuffer.h"
#include "viralloc.h"
#include "viruuid.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX



#define ESX_VI__METHOD__CHECK_OUTPUT__None                                    \
    /* nothing */



#define ESX_VI__METHOD__CHECK_OUTPUT__NotNone                                 \
    if (!output || *output) {                                                 \
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));  \
        return -1;                                                            \
    }



#define ESX_VI__METHOD__CHECK_OUTPUT__RequiredItem                            \
    ESX_VI__METHOD__CHECK_OUTPUT__NotNone



#define ESX_VI__METHOD__CHECK_OUTPUT__RequiredList                            \
    ESX_VI__METHOD__CHECK_OUTPUT__NotNone



#define ESX_VI__METHOD__CHECK_OUTPUT__OptionalItem                            \
    ESX_VI__METHOD__CHECK_OUTPUT__NotNone



#define ESX_VI__METHOD__CHECK_OUTPUT__OptionalList                            \
    ESX_VI__METHOD__CHECK_OUTPUT__NotNone



#define ESX_VI__METHOD__DESERIALIZE_OUTPUT__None(_type, _suffix)              \
    /* nothing */



#define ESX_VI__METHOD__DESERIALIZE_OUTPUT__RequiredItem(_type, _suffix)      \
    if (esxVI_##_type##_Deserialize##_suffix(response->node, output) < 0) {   \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD__DESERIALIZE_OUTPUT__RequiredList(_type, _suffix)      \
    if (esxVI_##_type##_DeserializeList(response->node, output) < 0) {        \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD__DESERIALIZE_OUTPUT__OptionalItem(_type, _suffix)      \
    if (response->node &&                                                     \
        esxVI_##_type##_Deserialize##_suffix(response->node, output) < 0) {   \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD__DESERIALIZE_OUTPUT__OptionalList(_type, _suffix)      \
    if (response->node &&                                                     \
        esxVI_##_type##_DeserializeList(response->node, output) < 0) {        \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD(_name, _this_from_service, _parameters, _output_type,  \
                       _deserialize_suffix, _occurrence, _validate,           \
                       _serialize)                                            \
    int                                                                       \
    esxVI_##_name _parameters                                                 \
    {                                                                         \
        int result = -1;                                                      \
        const char *methodName = #_name;                                      \
        virBuffer buffer = VIR_BUFFER_INITIALIZER;                            \
        char *request = NULL;                                                 \
        esxVI_Response *response = NULL;                                      \
                                                                              \
        ESX_VI__METHOD__PARAMETER__THIS__##_this_from_service                 \
                                                                              \
        ESX_VI__METHOD__CHECK_OUTPUT__##_occurrence                           \
                                                                              \
        _validate                                                             \
                                                                              \
        virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);               \
        virBufferAddLit(&buffer, "<"#_name" xmlns=\"urn:vim25\">");           \
                                                                              \
        _serialize                                                            \
                                                                              \
        virBufferAddLit(&buffer, "</"#_name">");                              \
        virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);               \
                                                                              \
        if (virBufferError(&buffer)) {                                        \
            virReportOOMError();                                              \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        request = virBufferContentAndReset(&buffer);                          \
                                                                              \
        if (esxVI_Context_Execute(ctx, methodName, request, &response,        \
                                  esxVI_Occurrence_##_occurrence) < 0) {      \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        ESX_VI__METHOD__DESERIALIZE_OUTPUT__##_occurrence                     \
          (_output_type, _deserialize_suffix)                                 \
                                                                              \
        result = 0;                                                           \
                                                                              \
      cleanup:                                                                \
        if (result < 0) {                                                     \
            virBufferFreeAndReset(&buffer);                                   \
        }                                                                     \
                                                                              \
        VIR_FREE(request);                                                    \
        esxVI_Response_Free(&response);                                       \
                                                                              \
        return result;                                                        \
    }



#define ESX_VI__METHOD__PARAMETER__THIS_FROM_SERVICE(_type, _name)            \
    esxVI_##_type *_this = NULL;                                              \
                                                                              \
    if (!ctx->service) {                                                      \
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call"));      \
        return -1;                                                            \
    }                                                                         \
                                                                              \
    _this = ctx->service->_name;



#define ESX_VI__METHOD__PARAMETER__THIS__/* explicit _this */                 \
    /* nothing */



/*
 * A required parameter must be != 0 (NULL for pointers, "undefined" == 0 for
 * enumeration values).
 *
 * To be used as part of ESX_VI__METHOD.
 */
#define ESX_VI__METHOD__PARAMETER__REQUIRE(_name)                             \
    if (_name == 0) {                                                         \
        virReportError(VIR_ERR_INTERNAL_ERROR,                                \
                       "Required parameter '%s' is missing for call to %s",   \
                       #_name, methodName);                                   \
        return -1;                                                            \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE(_type, _name)                    \
    if (esxVI_##_type##_Serialize(_name, #_name, &buffer) < 0) {              \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(_type, _name)               \
    if (esxVI_##_type##_SerializeList(_name, #_name, &buffer) < 0) {          \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(_type, _name)              \
    if (esxVI_##_type##_SerializeValue(_name, #_name, &buffer) < 0) {         \
        goto cleanup;                                                         \
    }



#include "esx_vi_methods.generated.macro"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Methods
 */

int
esxVI_RetrieveServiceContent(esxVI_Context *ctx,
                             esxVI_ServiceContent **serviceContent)
{
    int result = -1;
    const char *request = ESX_VI__SOAP__REQUEST_HEADER
                            "<RetrieveServiceContent xmlns=\"urn:vim25\">"
                              "<_this xmlns=\"urn:vim25\" "
                                     "xsi:type=\"ManagedObjectReference\" "
                                     "type=\"ServiceInstance\">"
                                "ServiceInstance"
                              "</_this>"
                            "</RetrieveServiceContent>"
                          ESX_VI__SOAP__REQUEST_FOOTER;
    esxVI_Response *response = NULL;

    if (!serviceContent || *serviceContent) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_Context_Execute(ctx, "RetrieveServiceContent", request,
                              &response, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_ServiceContent_Deserialize(response->node, serviceContent) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_Response_Free(&response);

    return result;
}



/* esxVI_ValidateMigration */
ESX_VI__METHOD(ValidateMigration, /* special _this */,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *vm,          /* required, list */
                esxVI_VirtualMachinePowerState state,      /* optional */
                esxVI_String *testType,                    /* optional, list */
                esxVI_ManagedObjectReference *pool,        /* optional */
                esxVI_ManagedObjectReference *host,        /* optional */
                esxVI_Event **output),                     /* optional, list */
               Event, /* nothing */, OptionalList,
{
    ESX_VI__METHOD__PARAMETER__REQUIRE(vm)
},
{
    virBufferAddLit(&buffer, "<_this xmlns=\"urn:vim25\" "
                                    "xsi:type=\"ManagedObjectReference\" "
                                    "type=\"ServiceInstance\">"
                               "ServiceInstance"
                             "</_this>");
    ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(ManagedObjectReference, vm)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(VirtualMachinePowerState, state)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(String, testType)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, pool)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, host)
})



#include "esx_vi_methods.generated.c"
