
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "buf.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX



#define ESX_VI__SOAP__REQUEST_HEADER                                          \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"                            \
    "<soapenv:Envelope "                                                      \
      "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "          \
      "xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" "          \
      "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "              \
      "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"                       \
    "<soapenv:Body>"



#define ESX_VI__SOAP__REQUEST_FOOTER                                          \
    "</soapenv:Body>"                                                         \
    "</soapenv:Envelope>"



#define ESX_VI__METHOD(_name, _parameters, _occurrence, _prolog, _validate,   \
                       _serialize, _deserialize)                              \
    int                                                                       \
    esxVI_##_name _parameters                                                 \
    {                                                                         \
        int result = 0;                                                       \
        const char* method_name = #_name;                                     \
        virBuffer buffer = VIR_BUFFER_INITIALIZER;                            \
        char *request = NULL;                                                 \
        esxVI_Response *response = NULL;                                      \
                                                                              \
        _prolog                                                               \
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
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        request = virBufferContentAndReset(&buffer);                          \
                                                                              \
        if (esxVI_Context_Execute(ctx, #_name, request, &response,            \
                                  esxVI_Occurrence_##_occurrence) < 0) {      \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        if (response->node != NULL) {                                         \
            _deserialize                                                      \
        }                                                                     \
                                                                              \
      cleanup:                                                                \
        VIR_FREE(request);                                                    \
        esxVI_Response_Free(&response);                                       \
                                                                              \
        return result;                                                        \
                                                                              \
      failure:                                                                \
        virBufferFreeAndReset(&buffer);                                       \
                                                                              \
        result = -1;                                                          \
                                                                              \
        goto cleanup;                                                         \
    }



#define ESX_VI__METHOD__CHECK_SERVICE()                                       \
    if (ctx->service == NULL) {                                               \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call"));        \
        return -1;                                                            \
    }



#define ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(_name)                        \
    if (_name == NULL || *_name != NULL) {                                    \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));    \
        return -1;                                                            \
    }



/*
 * A required parameter must be != 0 (NULL for pointers, "undefined" == 0 for
 * enumeration values).
 *
 * To be used as part of ESX_VI__METHOD.
 */
#define ESX_VI__METHOD__PARAMETER__REQUIRE(_name)                             \
    if (_name == 0) {                                                         \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                                  \
                     "Required parameter '%s' is missing for call to %s",     \
                     #_name, method_name);                                    \
        return -1;                                                            \
    }



#define ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(_name)                        \
    if (_name == 0) {                                                         \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                                  \
                     "Required parameter '_this' is missing for call to %s",  \
                     method_name);                                            \
        return -1;                                                            \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE(_type, _name)                    \
    if (esxVI_##_type##_Serialize(_name, #_name, &buffer) < 0) {              \
        goto failure;                                                         \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(_type, _name)               \
    if (esxVI_##_type##_SerializeList(_name, #_name, &buffer) < 0) {          \
        goto failure;                                                         \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(_type, _name)              \
    if (esxVI_##_type##_SerializeValue(_name, #_name, &buffer) < 0) {         \
        goto failure;                                                         \
    }



#define ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(_type, _name)               \
    if (esxVI_##_type##_Serialize(_name, "_this", &buffer) < 0) {             \
        goto failure;                                                         \
    }



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Methods
 */

int
esxVI_RetrieveServiceContent(esxVI_Context *ctx,
                             esxVI_ServiceContent **serviceContent)
{
    int result = 0;
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

    if (serviceContent == NULL || *serviceContent != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_Context_Execute(ctx, "RetrieveServiceContent", request,
                              &response, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_ServiceContent_Deserialize(response->node, serviceContent) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_Response_Free(&response);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



/* esxVI_Login */
ESX_VI__METHOD(Login,
               (esxVI_Context *ctx,
                const char *userName, const char *password,
                esxVI_UserSession **userSession),
               RequiredItem,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(userSession)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->sessionManager)
    ESX_VI__METHOD__PARAMETER__REQUIRE(userName)
    ESX_VI__METHOD__PARAMETER__REQUIRE(password)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->sessionManager)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, userName)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, password)
},
{
    if (esxVI_UserSession_Deserialize(response->node, userSession) < 0) {
        goto failure;
    }
})



/* esxVI_Logout */
ESX_VI__METHOD(Logout, (esxVI_Context *ctx), None,
{
    ESX_VI__METHOD__CHECK_SERVICE()
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->sessionManager)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->sessionManager)
},
{
})



/* esxVI_SessionIsActive */
ESX_VI__METHOD(SessionIsActive,
               (esxVI_Context *ctx, const char *sessionID,
                const char *userName, esxVI_Boolean *active),
               RequiredItem,
{
    ESX_VI__METHOD__CHECK_SERVICE()

    if (active == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->sessionManager)
    ESX_VI__METHOD__PARAMETER__REQUIRE(sessionID)
    ESX_VI__METHOD__PARAMETER__REQUIRE(userName)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->sessionManager)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, sessionID)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, userName)
},
{
    if (esxVI_Boolean_Deserialize(response->node, active) < 0) {
        goto failure;
    }
})



/* esxVI_RetrieveProperties */
ESX_VI__METHOD(RetrieveProperties,
               (esxVI_Context *ctx,
                esxVI_PropertyFilterSpec *specSet, /* list */
                esxVI_ObjectContent **objectContentList),
               OptionalList,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(objectContentList)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->propertyCollector)
    ESX_VI__METHOD__PARAMETER__REQUIRE(specSet)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->propertyCollector)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(PropertyFilterSpec, specSet)
},
{
    if (esxVI_ObjectContent_DeserializeList(response->node,
                                            objectContentList) < 0) {
        goto failure;
    }
})



/* esxVI_PowerOnVM_Task */
ESX_VI__METHOD(PowerOnVM_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_PowerOffVM_Task */
ESX_VI__METHOD(PowerOffVM_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_SuspendVM_Task */
ESX_VI__METHOD(SuspendVM_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_MigrateVM_Task */
ESX_VI__METHOD(MigrateVM_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                esxVI_ManagedObjectReference *pool,
                esxVI_ManagedObjectReference *host,
                esxVI_VirtualMachineMovePriority priority,
                esxVI_VirtualMachinePowerState state,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
    ESX_VI__METHOD__PARAMETER__REQUIRE(priority)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, pool)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, host)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(VirtualMachineMovePriority, priority)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(VirtualMachinePowerState, state)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_ReconfigVM_Task */
ESX_VI__METHOD(ReconfigVM_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                esxVI_VirtualMachineConfigSpec *spec,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
    ESX_VI__METHOD__PARAMETER__REQUIRE(spec)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(VirtualMachineConfigSpec, spec)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_RegisterVM_Task */
ESX_VI__METHOD(RegisterVM_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *folder,
                const char *path, const char *name,
                esxVI_Boolean asTemplate,
                esxVI_ManagedObjectReference *pool,
                esxVI_ManagedObjectReference *host,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(folder)
    ESX_VI__METHOD__PARAMETER__REQUIRE(path)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference, folder)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, path)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, name)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, asTemplate)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, pool)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, host)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_CreateSnapshot_Task */
ESX_VI__METHOD(CreateSnapshot_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                const char *name, const char *description,
                esxVI_Boolean memory, esxVI_Boolean quiesce,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
    ESX_VI__METHOD__PARAMETER__REQUIRE(name)
    ESX_VI__METHOD__PARAMETER__REQUIRE(memory)
    ESX_VI__METHOD__PARAMETER__REQUIRE(quiesce)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, name)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, description)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, memory)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, quiesce)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_RevertToSnapshot_Task */
ESX_VI__METHOD(RevertToSnapshot_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachineSnapshot,
                esxVI_ManagedObjectReference *host,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachineSnapshot)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachineSnapshot)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, host)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_RemoveSnapshot_Task */
ESX_VI__METHOD(RemoveSnapshot_Task,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachineSnapshot,
                esxVI_Boolean removeChildren,
                esxVI_ManagedObjectReference **task),
               RequiredItem,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(task)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachineSnapshot)
    ESX_VI__METHOD__PARAMETER__REQUIRE(removeChildren)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachineSnapshot)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, removeChildren)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node, task) < 0) {
        goto failure;
    }
})



/* esxVI_CancelTask */
ESX_VI__METHOD(CancelTask,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *task),
               None,
{
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(task)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference, task)
},
{
})



/* esxVI_UnregisterVM */
ESX_VI__METHOD(UnregisterVM,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine),
               None,
{
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
},
{
})



/* esxVI_AnswerVM */
ESX_VI__METHOD(AnswerVM,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine,
                const char *questionId,
                const char *answerChoice),
               None,
{
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
    ESX_VI__METHOD__PARAMETER__REQUIRE(questionId)
    ESX_VI__METHOD__PARAMETER__REQUIRE(answerChoice)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, questionId)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, answerChoice)
},
{
})



/* esxVI_CreateFilter */
ESX_VI__METHOD(CreateFilter,
               (esxVI_Context *ctx,
                esxVI_PropertyFilterSpec *spec,
                esxVI_Boolean partialUpdates,
                esxVI_ManagedObjectReference **propertyFilter),
               RequiredItem,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(propertyFilter)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->propertyCollector)
    ESX_VI__METHOD__PARAMETER__REQUIRE(spec)
    ESX_VI__METHOD__PARAMETER__REQUIRE(partialUpdates)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->propertyCollector)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(PropertyFilterSpec, spec)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, partialUpdates)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node,
                                                 propertyFilter) < 0) {
        goto failure;
    }
})



/* esxVI_DestroyPropertyFilter */
ESX_VI__METHOD(DestroyPropertyFilter,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *propertyFilter),
               None,
{
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(propertyFilter)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              propertyFilter)
},
{
})



/* esxVI_WaitForUpdates */
ESX_VI__METHOD(WaitForUpdates,
               (esxVI_Context *ctx,
                const char *version,
                esxVI_UpdateSet **updateSet),
               RequiredItem,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(updateSet)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->propertyCollector)
    ESX_VI__METHOD__PARAMETER__REQUIRE(version)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->propertyCollector)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, version)
},
{
    if (esxVI_UpdateSet_Deserialize(response->node, updateSet) < 0) {
        goto failure;
    }
})



/* esxVI_RebootGuest */
ESX_VI__METHOD(RebootGuest,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine),
               None,
{
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
},
{
})



/* esxVI_ShutdownGuest */
ESX_VI__METHOD(ShutdownGuest,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *virtualMachine),
               None,
{
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(virtualMachine)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              virtualMachine)
},
{
})



/* esxVI_ValidateMigration */
ESX_VI__METHOD(ValidateMigration,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *vm, /* list */
                esxVI_VirtualMachinePowerState state,
                esxVI_String *testType, /* list */
                esxVI_ManagedObjectReference *pool,
                esxVI_ManagedObjectReference *host,
                esxVI_Event **eventList),
               OptionalList,
{
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(eventList)
},
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
},
{
    if (esxVI_Event_DeserializeList(response->node, eventList) < 0) {
        goto failure;
    }
})



/* esxVI_FindByIp */
ESX_VI__METHOD(FindByIp,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *datacenter,
                const char *ip,
                esxVI_Boolean vmSearch,
                esxVI_ManagedObjectReference **managedObjectReference),
               OptionalItem,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(managedObjectReference)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->searchIndex)
    ESX_VI__METHOD__PARAMETER__REQUIRE(ip)
    ESX_VI__METHOD__PARAMETER__REQUIRE(vmSearch)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->searchIndex)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, datacenter)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, ip)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, vmSearch)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node,
                                                 managedObjectReference) < 0) {
        goto failure;
    }
})



/* esxVI_FindByUuid */
ESX_VI__METHOD(FindByUuid,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *datacenter,
                const char *uuid, /* string */
                esxVI_Boolean vmSearch,
                esxVI_ManagedObjectReference **managedObjectReference),
               OptionalItem,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(managedObjectReference)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->searchIndex)
    ESX_VI__METHOD__PARAMETER__REQUIRE(uuid)
    ESX_VI__METHOD__PARAMETER__REQUIRE(vmSearch)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->searchIndex)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, datacenter)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, uuid)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Boolean, vmSearch)
},
{
    if (esxVI_ManagedObjectReference_Deserialize(response->node,
                                                 managedObjectReference) < 0) {
        goto failure;
    }
})



/* esxVI_QueryAvailablePerfMetric */
ESX_VI__METHOD(QueryAvailablePerfMetric,
               (esxVI_Context *ctx,
                esxVI_ManagedObjectReference *entity,
                esxVI_DateTime *beginTime,
                esxVI_DateTime *endTime,
                esxVI_Int *intervalId,
                esxVI_PerfMetricId **perfMetricIdList),
               OptionalList,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(perfMetricIdList)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->perfManager)
    ESX_VI__METHOD__PARAMETER__REQUIRE(entity)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->perfManager)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(ManagedObjectReference, entity)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(DateTime, beginTime)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(DateTime, endTime)
    ESX_VI__METHOD__PARAMETER__SERIALIZE(Int, intervalId)
},
{
    if (esxVI_PerfMetricId_DeserializeList(response->node,
                                           perfMetricIdList) < 0) {
        goto failure;
    }
})



/* esxVI_QueryPerfCounter */
ESX_VI__METHOD(QueryPerfCounter,
               (esxVI_Context *ctx,
                esxVI_Int *counterId, /* list */
                esxVI_PerfCounterInfo **perfCounterInfoList),
               OptionalList,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(perfCounterInfoList)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->perfManager)
    ESX_VI__METHOD__PARAMETER__REQUIRE(counterId)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->perfManager)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(Int, counterId)
},
{
    if (esxVI_PerfCounterInfo_DeserializeList(response->node,
                                              perfCounterInfoList) < 0) {
        goto failure;
    }
})



/* esxVI_QueryPerf */
ESX_VI__METHOD(QueryPerf,
               (esxVI_Context *ctx,
                esxVI_PerfQuerySpec *querySpec, /* list */
                esxVI_PerfEntityMetric **perfEntityMetricList),
               OptionalList,
{
    ESX_VI__METHOD__CHECK_SERVICE()
    ESX_VI__METHOD__PARAMETER__CHECK_OUTPUT(perfEntityMetricList)
},
{
    ESX_VI__METHOD__PARAMETER__REQUIRE_THIS(ctx->service->perfManager)
    ESX_VI__METHOD__PARAMETER__REQUIRE(querySpec)
},
{
    ESX_VI__METHOD__PARAMETER__SERIALIZE_THIS(ManagedObjectReference,
                                              ctx->service->perfManager)
    ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(PerfQuerySpec, querySpec)
},
{
    if (esxVI_PerfEntityMetric_DeserializeList(response->node,
                                               perfEntityMetricList) < 0) {
        goto failure;
    }
})
