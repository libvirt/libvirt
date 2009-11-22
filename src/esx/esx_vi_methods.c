
/*
 * esx_vi_methods.c: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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
#include "virterror_internal.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX

#define ESX_VI_ERROR(conn, code, fmt...)                                      \
    virReportErrorHelper(conn, VIR_FROM_ESX, code, __FILE__,  __FUNCTION__,   \
                         __LINE__, fmt)

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



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Methods
 */

int
esxVI_RetrieveServiceContent(virConnectPtr conn, esxVI_Context *ctx,
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
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxVI_Context_Execute(conn, ctx, "RetrieveServiceContent", request,
                              &response, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_ServiceContent_Deserialize(conn, response->node,
                                         serviceContent) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_Response_Free(&response);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_Login(virConnectPtr conn, esxVI_Context *ctx,
            const char *userName, const char *password,
            esxVI_UserSession **userSession)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (userSession == NULL || *userSession != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<Login xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn,
                                               ctx->service->sessionManager,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, userName, "userName", &buffer,
                                    esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, password, "password", &buffer,
                                    esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</Login>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "Login", request, &response,
                              esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_UserSession_Deserialize(conn, response->node, userSession) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_Logout(virConnectPtr conn, esxVI_Context *ctx)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<Logout xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn,
                                               ctx->service->sessionManager,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</Logout>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "Logout", request, &response,
                              esxVI_Occurrence_None) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_SessionIsActive(virConnectPtr conn, esxVI_Context *ctx,
                      const char *sessionID, const char *userName,
                      esxVI_Boolean *active)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (active == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<SessionIsActive xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn,
                                               ctx->service->sessionManager,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, sessionID, "sessionID", &buffer,
                                    esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, userName, "userName", &buffer,
                                    esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</SessionIsActive>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "SessionIsActive", request,
                              &response, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_Boolean_Deserialize(conn, response->node, active) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_RetrieveProperties(virConnectPtr conn, esxVI_Context *ctx,
                         esxVI_PropertyFilterSpec *propertyFilterSpecList,
                         esxVI_ObjectContent **objectContentList)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (objectContentList == NULL || *objectContentList != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<RetrieveProperties xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn,
                                               ctx->service->propertyCollector,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_PropertyFilterSpec_SerializeList(conn, propertyFilterSpecList,
                                               "specSet", &buffer,
                                               esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</RetrieveProperties>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "RetrieveProperties", request,
                              &response, esxVI_Occurrence_List) < 0 ||
        esxVI_ObjectContent_DeserializeList(conn, response->node,
                                            objectContentList) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_PowerOnVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                     esxVI_ManagedObjectReference *virtualMachine,
                     esxVI_ManagedObjectReference **task)
{
    return esxVI_StartSimpleVirtualMachineTask(conn, ctx, "PowerOnVM",
                                               virtualMachine, task);
}



int
esxVI_PowerOffVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                      esxVI_ManagedObjectReference *virtualMachine,
                      esxVI_ManagedObjectReference **task)
{
    return esxVI_StartSimpleVirtualMachineTask(conn, ctx, "PowerOffVM",
                                               virtualMachine, task);
}



int
esxVI_SuspendVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                     esxVI_ManagedObjectReference *virtualMachine,
                     esxVI_ManagedObjectReference **task)
{
    return esxVI_StartSimpleVirtualMachineTask(conn, ctx, "SuspendVM",
                                               virtualMachine, task);
}



int
esxVI_MigrateVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                     esxVI_ManagedObjectReference *virtualMachine,
                     esxVI_ManagedObjectReference *resourcePool,
                     esxVI_ManagedObjectReference *hostSystem,
                     esxVI_ManagedObjectReference **task)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;

    if (task == NULL || *task != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<MigrateVM_Task xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, virtualMachine, "_this",
                                               &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, resourcePool, "pool",
                                               &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, hostSystem, "host",
                                               &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_VirtualMachineMovePriority_Serialize
          (conn, esxVI_VirtualMachineMovePriority_DefaultPriority,
           "priority", &buffer, esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</MigrateVM_Task>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_StartVirtualMachineTask(conn, ctx, "MigrateVM", request,
                                      task) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_ReconfigVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                      esxVI_ManagedObjectReference *virtualMachine,
                      esxVI_VirtualMachineConfigSpec *spec,
                      esxVI_ManagedObjectReference **task)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;

    if (task == NULL || *task != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<ReconfigVM_Task xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, virtualMachine, "_this",
                                               &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_VirtualMachineConfigSpec_Serialize(conn, spec, "spec", &buffer,
                                                 esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</ReconfigVM_Task>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_StartVirtualMachineTask(conn, ctx, "ReconfigVM", request,
                                      task) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_RegisterVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                      esxVI_ManagedObjectReference *folder,
                      const char *path, const char *name,
                      esxVI_Boolean asTemplate,
                      esxVI_ManagedObjectReference *resourcePool,
                      esxVI_ManagedObjectReference *hostSystem,
                      esxVI_ManagedObjectReference **task)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;

    if (task == NULL || *task != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<RegisterVM_Task xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, folder, "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, path, "path", &buffer,
                                    esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, name, "name", &buffer,
                                    esxVI_Boolean_False) < 0 ||
        esxVI_Boolean_Serialize(conn, asTemplate, "asTemplate", &buffer,
                                esxVI_Boolean_False) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, resourcePool, "pool",
                                               &buffer,
                                               esxVI_Boolean_False) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, hostSystem, "host",
                                               &buffer,
                                               esxVI_Boolean_False) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</RegisterVM_Task>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_StartVirtualMachineTask(conn, ctx, "RegisterVM", request,
                                      task) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_CancelTask(virConnectPtr conn, esxVI_Context *ctx,
                 esxVI_ManagedObjectReference *task)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<CancelTask xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, task, "_this", &buffer,
                                               esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</CancelTask>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "UnregisterVM", request, &response,
                              esxVI_Occurrence_None) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    if (request == NULL) {
        request = virBufferContentAndReset(&buffer);
    }

    result = -1;

    goto cleanup;
}



int
esxVI_UnregisterVM(virConnectPtr conn, esxVI_Context *ctx,
                   esxVI_ManagedObjectReference *virtualMachine)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<UnregisterVM xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, virtualMachine, "_this",
                                               &buffer,
                                               esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</UnregisterVM>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "AnswerVM", request, &response,
                              esxVI_Occurrence_None) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_AnswerVM(virConnectPtr conn, esxVI_Context *ctx,
               esxVI_ManagedObjectReference *virtualMachine,
               const char *questionId, const char *answerChoice)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<AnswerVM xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, virtualMachine, "_this",
                                               &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, questionId, "questionId",
                                    &buffer, esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, answerChoice, "answerChoice",
                                    &buffer, esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</AnswerVM>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, request, NULL, &response,
                              esxVI_Boolean_False) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    if (request == NULL) {
        request = virBufferContentAndReset(&buffer);
    }

    result = -1;

    goto cleanup;
}



int
esxVI_CreateFilter(virConnectPtr conn, esxVI_Context *ctx,
                   esxVI_PropertyFilterSpec *propertyFilterSpec,
                   esxVI_Boolean partialUpdates,
                   esxVI_ManagedObjectReference **propertyFilter)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (propertyFilter == NULL || *propertyFilter != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<CreateFilter xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn,
                                               ctx->service->propertyCollector,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_PropertyFilterSpec_Serialize(conn, propertyFilterSpec, "spec",
                                           &buffer, esxVI_Boolean_True) < 0 ||
        esxVI_Boolean_Serialize(conn, partialUpdates, "partialUpdates",
                                &buffer, esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</CreateFilter>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "CreateFilter", request, &response,
                              esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_ManagedObjectReference_Deserialize(conn, response->node,
                                                 propertyFilter,
                                                 "PropertyFilter") < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_DestroyPropertyFilter(virConnectPtr conn, esxVI_Context *ctx,
                            esxVI_ManagedObjectReference *propertyFilter)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<DestroyPropertyFilter xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, propertyFilter, "_this",
                                               &buffer,
                                               esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</DestroyPropertyFilter>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "DestroyPropertyFilter", request,
                              &response, esxVI_Occurrence_None) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_WaitForUpdates(virConnectPtr conn, esxVI_Context *ctx,
                     const char *version, esxVI_UpdateSet **updateSet)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (updateSet == NULL || *updateSet != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<WaitForUpdates xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn,
                                               ctx->service->propertyCollector,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_String_SerializeValue(conn, version, "version", &buffer,
                                    esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</WaitForUpdates>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "WaitForUpdates", request,
                              &response, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_UpdateSet_Deserialize(conn, response->node, updateSet) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_RebootGuest(virConnectPtr conn, esxVI_Context *ctx,
                  esxVI_ManagedObjectReference *virtualMachine)
{
    return esxVI_SimpleVirtualMachineMethod(conn, ctx, "RebootGuest",
                                            virtualMachine);
}



int
esxVI_ShutdownGuest(virConnectPtr conn, esxVI_Context *ctx,
                    esxVI_ManagedObjectReference *virtualMachine)
{
    return esxVI_SimpleVirtualMachineMethod(conn, ctx, "ShutdownGuest",
                                            virtualMachine);
}



int
esxVI_ValidateMigration(virConnectPtr conn, esxVI_Context *ctx,
                        esxVI_ManagedObjectReference *virtualMachineList,
                        esxVI_VirtualMachinePowerState powerState,
                        esxVI_String *testTypeList,
                        esxVI_ManagedObjectReference *resourcePool,
                        esxVI_ManagedObjectReference *hostSystem,
                        esxVI_Event **eventList)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (eventList == NULL || *eventList != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<ValidateMigration xmlns=\"urn:vim25\">"
                             "<_this xmlns=\"urn:vim25\" "
                                    "xsi:type=\"ManagedObjectReference\" "
                                    "type=\"ServiceInstance\">"
                               "ServiceInstance"
                             "</_this>");

    if (esxVI_ManagedObjectReference_SerializeList(conn, virtualMachineList,
                                                   "vm", &buffer,
                                                   esxVI_Boolean_True) < 0 ||
        esxVI_VirtualMachinePowerState_Serialize(conn, powerState, "state",
                                                 &buffer,
                                                 esxVI_Boolean_False) < 0 ||
        esxVI_String_SerializeList(conn, testTypeList, "testType", &buffer,
                                   esxVI_Boolean_False) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, resourcePool, "pool",
                                               &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, hostSystem, "host",
                                               &buffer,
                                               esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</ValidateMigration>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "ValidateMigration", request,
                              &response, esxVI_Occurrence_List) < 0 ||
        esxVI_Event_DeserializeList(conn, response->node, eventList) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_FindByIp(virConnectPtr conn, esxVI_Context *ctx,
                 esxVI_ManagedObjectReference *datacenter,
                 const char *ip, esxVI_Boolean vmSearch,
                 esxVI_ManagedObjectReference **managedObjectReference)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (managedObjectReference == NULL || *managedObjectReference != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<FindByIp xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, ctx->service->searchIndex,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, datacenter,
                                               "datacenter", &buffer,
                                               esxVI_Boolean_False) < 0 ||
        esxVI_String_SerializeValue(conn, ip, "ip", &buffer,
                                    esxVI_Boolean_True) < 0 ||
        esxVI_Boolean_Serialize(conn, vmSearch, "vmSearch", &buffer,
                                esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</FindByIp>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "FindByIp", request, &response,
                              esxVI_Occurrence_OptionalItem) < 0 ||
        esxVI_ManagedObjectReference_Deserialize
          (conn, response->node, managedObjectReference,
           vmSearch == esxVI_Boolean_True ? "VirtualMachine"
                                          : "HostSystem") < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_FindByUuid(virConnectPtr conn, esxVI_Context *ctx,
                 esxVI_ManagedObjectReference *datacenter,
                 const unsigned char *uuid, esxVI_Boolean vmSearch,
                 esxVI_ManagedObjectReference **managedObjectReference)
{
    int result = 0;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (managedObjectReference == NULL || *managedObjectReference != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virUUIDFormat(uuid, uuid_string);

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<FindByUuid xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, ctx->service->searchIndex,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, datacenter,
                                               "datacenter", &buffer,
                                               esxVI_Boolean_False) < 0 ||
        esxVI_String_SerializeValue(conn, uuid_string, "uuid", &buffer,
                                    esxVI_Boolean_True) < 0 ||
        esxVI_Boolean_Serialize(conn, vmSearch, "vmSearch", &buffer,
                                esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</FindByUuid>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "FindByUuid", request, &response,
                              esxVI_Occurrence_OptionalItem) < 0) {
        goto failure;
    }

    if (response->node == NULL) {
        goto cleanup;
    }

    if (esxVI_ManagedObjectReference_Deserialize
          (conn, response->node, managedObjectReference,
           vmSearch == esxVI_Boolean_True ? "VirtualMachine"
                                          : "HostSystem") < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_QueryAvailablePerfMetric(virConnectPtr conn, esxVI_Context *ctx,
                               esxVI_ManagedObjectReference *entity,
                               esxVI_DateTime *beginTime,
                               esxVI_DateTime *endTime, esxVI_Int *intervalId,
                               esxVI_PerfMetricId **perfMetricIdList)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (perfMetricIdList == NULL || *perfMetricIdList != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<QueryAvailablePerfMetric xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, ctx->service->perfManager,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_ManagedObjectReference_Serialize(conn, entity,
                                               "entity", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_DateTime_Serialize(conn, beginTime, "beginTime", &buffer,
                                 esxVI_Boolean_False) < 0 ||
        esxVI_DateTime_Serialize(conn, endTime, "endTime", &buffer,
                                 esxVI_Boolean_False) < 0 ||
        esxVI_Int_Serialize(conn, intervalId, "intervalId", &buffer,
                            esxVI_Boolean_False) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</QueryAvailablePerfMetric>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "QueryAvailablePerfMetric", request,
                              &response, esxVI_Occurrence_List) < 0 ||
        esxVI_PerfMetricId_DeserializeList(conn, response->node,
                                           perfMetricIdList) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_QueryPerfCounter(virConnectPtr conn, esxVI_Context *ctx,
                       esxVI_Int *counterIdList,
                       esxVI_PerfCounterInfo **perfCounterInfoList)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (perfCounterInfoList == NULL || *perfCounterInfoList != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<QueryPerfCounter xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, ctx->service->perfManager,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_Int_SerializeList(conn, counterIdList, "counterId", &buffer,
                                esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</QueryPerfCounter>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "QueryPerfCounter", request,
                              &response, esxVI_Occurrence_List) < 0 ||
        esxVI_PerfCounterInfo_DeserializeList(conn, response->node,
                                              perfCounterInfoList) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_QueryPerf(virConnectPtr conn, esxVI_Context *ctx,
                esxVI_PerfQuerySpec *querySpecList,
                esxVI_PerfEntityMetric **perfEntityMetricList)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *request = NULL;
    esxVI_Response *response = NULL;

    if (ctx->service == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid call");
        return -1;
    }

    if (perfEntityMetricList == NULL || *perfEntityMetricList != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_HEADER);
    virBufferAddLit(&buffer, "<QueryPerf xmlns=\"urn:vim25\">");

    if (esxVI_ManagedObjectReference_Serialize(conn, ctx->service->perfManager,
                                               "_this", &buffer,
                                               esxVI_Boolean_True) < 0 ||
        esxVI_PerfQuerySpec_SerializeList(conn, querySpecList, "querySpec",
                                          &buffer, esxVI_Boolean_True) < 0) {
        goto failure;
    }

    virBufferAddLit(&buffer, "</QueryPerf>");
    virBufferAddLit(&buffer, ESX_VI__SOAP__REQUEST_FOOTER);

    if (virBufferError(&buffer)) {
        virReportOOMError(conn);
        goto failure;
    }

    request = virBufferContentAndReset(&buffer);

    if (esxVI_Context_Execute(conn, ctx, "QueryPerf", request, &response,
                              esxVI_Occurrence_List) < 0 ||
        esxVI_PerfEntityMetric_DeserializeList(conn, response->node,
                                               perfEntityMetricList) < 0) {
        goto failure;
    }

  cleanup:
    VIR_FREE(request);
    esxVI_Response_Free(&response);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}
