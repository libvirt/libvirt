/*
 * hyperv_wmi.c: general WMI over WSMAN related functions and structures for
 *               managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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

#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "hyperv_private.h"
#include "hyperv_wmi.h"
#include "virstring.h"

#define WS_SERIALIZER_FREE_MEM_WORKS 0

#define ROOT_CIMV2 \
    "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*"

#define ROOT_VIRTUALIZATION \
    "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/virtualization/*"

#define VIR_FROM_THIS VIR_FROM_HYPERV



int
hyperyVerifyResponse(WsManClient *client, WsXmlDocH response,
                     const char *detail)
{
    int lastError = wsmc_get_last_error(client);
    int responseCode = wsmc_get_response_code(client);
    WsManFault *fault;

    if (lastError != WS_LASTERR_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Transport error during %s: %s (%d)"),
                       detail, wsman_transport_get_last_error_string(lastError),
                       lastError);
        return -1;
    }

    /* Check the HTTP response code and report an error if it's not 200 (OK),
     * 400 (Bad Request) or 500 (Internal Server Error) */
    if (responseCode != 200 && responseCode != 400 && responseCode != 500) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected HTTP response during %s: %d"),
                       detail, responseCode);
        return -1;
    }

    if (response == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Empty response during %s"), detail);
        return -1;
    }

    if (wsmc_check_for_fault(response)) {
        fault = wsmc_fault_new();

        if (fault == NULL) {
            virReportOOMError();
            return -1;
        }

        wsmc_get_fault_data(response, fault);

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("SOAP fault during %s: code '%s', subcode '%s', "
                         "reason '%s', detail '%s'"),
                       detail, NULLSTR(fault->code), NULLSTR(fault->subcode),
                       NULLSTR(fault->reason), NULLSTR(fault->fault_detail));

        wsmc_fault_destroy(fault);
        return -1;
    }

    return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object
 */

int
hypervEnumAndPull(hypervPrivate *priv, virBufferPtr query, const char *root,
                  XmlSerializerInfo *serializerInfo, const char *resourceUri,
                  const char *className, hypervObject **list)
{
    int result = -1;
    WsSerializerContextH serializerContext;
    client_opt_t *options = NULL;
    char *query_string = NULL;
    filter_t *filter = NULL;
    WsXmlDocH response = NULL;
    char *enumContext = NULL;
    hypervObject *head = NULL;
    hypervObject *tail = NULL;
    WsXmlNodeH node = NULL;
    XML_TYPE_PTR data = NULL;
    hypervObject *object;

    if (list == NULL || *list != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virBufferError(query)) {
        virReportOOMError();
        return -1;
    }

    serializerContext = wsmc_get_serialization_context(priv->client);

    options = wsmc_options_init();

    if (options == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize options"));
        goto cleanup;
    }

    query_string = virBufferContentAndReset(query);
    filter = filter_create_simple(WSM_WQL_FILTER_DIALECT, query_string);

    if (filter == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create filter"));
        goto cleanup;
    }

    response = wsmc_action_enumerate(priv->client, root, options, filter);

    if (hyperyVerifyResponse(priv->client, response, "enumeration") < 0) {
        goto cleanup;
    }

    enumContext = wsmc_get_enum_context(response);

    ws_xml_destroy_doc(response);
    response = NULL;

    while (enumContext != NULL && *enumContext != '\0') {
        response = wsmc_action_pull(priv->client, resourceUri, options,
                                    filter, enumContext);

        if (hyperyVerifyResponse(priv->client, response, "pull") < 0) {
            goto cleanup;
        }

        node = ws_xml_get_soap_body(response);

        if (node == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not lookup SOAP body"));
            goto cleanup;
        }

        node = ws_xml_get_child(node, 0, XML_NS_ENUMERATION, WSENUM_PULL_RESP);

        if (node == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not lookup pull response"));
            goto cleanup;
        }

        node = ws_xml_get_child(node, 0, XML_NS_ENUMERATION, WSENUM_ITEMS);

        if (node == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not lookup pull response items"));
            goto cleanup;
        }

        if (ws_xml_get_child(node, 0, resourceUri, className) == NULL) {
            break;
        }

        data = ws_deserialize(serializerContext, node, serializerInfo,
                              className, resourceUri, NULL, 0, 0);

        if (data == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not deserialize pull response item"));
            goto cleanup;
        }

        if (VIR_ALLOC(object) < 0)
            goto cleanup;

        object->serializerInfo = serializerInfo;
        object->data = data;

        data = NULL;

        if (head == NULL) {
            head = object;
        } else {
            tail->next = object;
        }

        tail = object;

        VIR_FREE(enumContext);
        enumContext = wsmc_get_enum_context(response);

        ws_xml_destroy_doc(response);
        response = NULL;
    }

    *list = head;
    head = NULL;

    result = 0;

 cleanup:
    if (options != NULL) {
        wsmc_options_destroy(options);
    }

    if (filter != NULL) {
        filter_destroy(filter);
    }

    if (data != NULL) {
#if WS_SERIALIZER_FREE_MEM_WORKS
        /* FIXME: ws_serializer_free_mem is broken in openwsman <= 2.2.6,
         *        see hypervFreeObject for a detailed explanation. */
        if (ws_serializer_free_mem(serializerContext, data,
                                   serializerInfo) < 0) {
            VIR_ERROR(_("Could not free deserialized data"));
        }
#endif
    }

    VIR_FREE(query_string);
    ws_xml_destroy_doc(response);
    VIR_FREE(enumContext);
    hypervFreeObject(priv, head);

    return result;
}

void
hypervFreeObject(hypervPrivate *priv ATTRIBUTE_UNUSED, hypervObject *object)
{
    hypervObject *next;
#if WS_SERIALIZER_FREE_MEM_WORKS
    WsSerializerContextH serializerContext;
#endif

    if (object == NULL) {
        return;
    }

#if WS_SERIALIZER_FREE_MEM_WORKS
    serializerContext = wsmc_get_serialization_context(priv->client);
#endif

    while (object != NULL) {
        next = object->next;

#if WS_SERIALIZER_FREE_MEM_WORKS
        /* FIXME: ws_serializer_free_mem is broken in openwsman <= 2.2.6,
         *        but this is not that critical, because openwsman keeps
         *        track of all allocations of the deserializer and frees
         *        them in wsmc_release. So this doesn't result in a real
         *        memory leak, but just in piling up unused memory until
         *        the connection is closed. */
        if (ws_serializer_free_mem(serializerContext, object->data,
                                   object->serializerInfo) < 0) {
            VIR_ERROR(_("Could not free deserialized data"));
        }
#endif

        VIR_FREE(object);

        object = next;
    }
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * CIM/Msvm_ReturnCode
 */

const char *
hypervReturnCodeToString(int returnCode)
{
    switch (returnCode) {
      case CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR:
        return _("Completed with no error");

      case CIM_RETURNCODE_NOT_SUPPORTED:
        return _("Not supported");

      case CIM_RETURNCODE_UNKNOWN_ERROR:
        return _("Unknown error");

      case CIM_RETURNCODE_CANNOT_COMPLETE_WITHIN_TIMEOUT_PERIOD:
        return _("Cannot complete within timeout period");

      case CIM_RETURNCODE_FAILED:
        return _("Failed");

      case CIM_RETURNCODE_INVALID_PARAMETER:
        return _("Invalid parameter");

      case CIM_RETURNCODE_IN_USE:
        return _("In use");

      case CIM_RETURNCODE_TRANSITION_STARTED:
        return _("Transition started");

      case CIM_RETURNCODE_INVALID_STATE_TRANSITION:
        return _("Invalid state transition");

      case CIM_RETURNCODE_TIMEOUT_PARAMETER_NOT_SUPPORTED:
        return _("Timeout parameter not supported");

      case CIM_RETURNCODE_BUSY:
        return _("Busy");

      case MSVM_RETURNCODE_FAILED:
        return _("Failed");

      case MSVM_RETURNCODE_ACCESS_DENIED:
        return _("Access denied");

      case MSVM_RETURNCODE_NOT_SUPPORTED:
        return _("Not supported");

      case MSVM_RETURNCODE_STATUS_IS_UNKNOWN:
        return _("Status is unknown");

      case MSVM_RETURNCODE_TIMEOUT:
        return _("Timeout");

      case MSVM_RETURNCODE_INVALID_PARAMETER:
        return _("Invalid parameter");

      case MSVM_RETURNCODE_SYSTEM_IS_IN_USE:
        return _("System is in use");

      case MSVM_RETURNCODE_INVALID_STATE_FOR_THIS_OPERATION:
        return _("Invalid state for this operation");

      case MSVM_RETURNCODE_INCORRECT_DATA_TYPE:
        return _("Incorrect data type");

      case MSVM_RETURNCODE_SYSTEM_IS_NOT_AVAILABLE:
        return _("System is not available");

      case MSVM_RETURNCODE_OUT_OF_MEMORY:
        return _("Out of memory");

      default:
        return _("Unknown return code");
    }
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_ComputerSystem
 */

int
hypervInvokeMsvmComputerSystemRequestStateChange(virDomainPtr domain,
                                                 int requestedState)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    WsXmlDocH response = NULL;
    client_opt_t *options = NULL;
    char *selector = NULL;
    char *properties = NULL;
    char *returnValue = NULL;
    int returnCode;
    char *instanceID = NULL;
    virBuffer query = VIR_BUFFER_INITIALIZER;
    Msvm_ConcreteJob *concreteJob = NULL;
    bool completed = false;

    virUUIDFormat(domain->uuid, uuid_string);

    if (virAsprintf(&selector, "Name=%s&CreationClassName=Msvm_ComputerSystem",
                    uuid_string) < 0 ||
        virAsprintf(&properties, "RequestedState=%d", requestedState) < 0)
        goto cleanup;

    options = wsmc_options_init();

    if (options == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize options"));
        goto cleanup;
    }

    wsmc_add_selectors_from_str(options, selector);
    wsmc_add_prop_from_str(options, properties);

    /* Invoke method */
    response = wsmc_action_invoke(priv->client, MSVM_COMPUTERSYSTEM_RESOURCE_URI,
                                  options, "RequestStateChange", NULL);

    if (hyperyVerifyResponse(priv->client, response, "invocation") < 0) {
        goto cleanup;
    }

    /* Check return value */
    returnValue = ws_xml_get_xpath_value(response, (char *)"/s:Envelope/s:Body/p:RequestStateChange_OUTPUT/p:ReturnValue");

    if (returnValue == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not lookup %s for %s invocation"),
                       "ReturnValue", "RequestStateChange");
        goto cleanup;
    }

    if (virStrToLong_i(returnValue, NULL, 10, &returnCode) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse return code from '%s'"), returnValue);
        goto cleanup;
    }

    if (returnCode == CIM_RETURNCODE_TRANSITION_STARTED) {
        /* Get concrete job object */
        instanceID = ws_xml_get_xpath_value(response, (char *)"/s:Envelope/s:Body/p:RequestStateChange_OUTPUT/p:Job/a:ReferenceParameters/w:SelectorSet/w:Selector[@Name='InstanceID']");

        if (instanceID == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not lookup %s for %s invocation"),
                           "InstanceID", "RequestStateChange");
            goto cleanup;
        }

        /* FIXME: Poll every 100ms until the job completes or fails. There
         *        seems to be no other way than polling. */
        while (!completed) {
            virBufferAddLit(&query, MSVM_CONCRETEJOB_WQL_SELECT);
            virBufferAsprintf(&query, "where InstanceID = \"%s\"", instanceID);

            if (hypervGetMsvmConcreteJobList(priv, &query, &concreteJob) < 0) {
                goto cleanup;
            }

            if (concreteJob == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not lookup %s for %s invocation"),
                               "Msvm_ConcreteJob", "RequestStateChange");
                goto cleanup;
            }

            switch (concreteJob->data->JobState) {
              case MSVM_CONCRETEJOB_JOBSTATE_NEW:
              case MSVM_CONCRETEJOB_JOBSTATE_STARTING:
              case MSVM_CONCRETEJOB_JOBSTATE_RUNNING:
              case MSVM_CONCRETEJOB_JOBSTATE_SHUTTING_DOWN:
                hypervFreeObject(priv, (hypervObject *)concreteJob);
                concreteJob = NULL;

                usleep(100 * 1000);
                continue;

              case MSVM_CONCRETEJOB_JOBSTATE_COMPLETED:
                completed = true;
                break;

              case MSVM_CONCRETEJOB_JOBSTATE_TERMINATED:
              case MSVM_CONCRETEJOB_JOBSTATE_KILLED:
              case MSVM_CONCRETEJOB_JOBSTATE_EXCEPTION:
              case MSVM_CONCRETEJOB_JOBSTATE_SERVICE:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Concrete job for %s invocation is in error state"),
                               "RequestStateChange");
                goto cleanup;

              default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Concrete job for %s invocation is in unknown state"),
                               "RequestStateChange");
                goto cleanup;
            }
        }
    } else if (returnCode != CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invocation of %s returned an error: %s (%d)"),
                       "RequestStateChange", hypervReturnCodeToString(returnCode),
                       returnCode);
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (options != NULL) {
        wsmc_options_destroy(options);
    }

    ws_xml_destroy_doc(response);
    VIR_FREE(selector);
    VIR_FREE(properties);
    VIR_FREE(returnValue);
    VIR_FREE(instanceID);
    hypervFreeObject(priv, (hypervObject *)concreteJob);

    return result;
}

int
hypervMsvmComputerSystemEnabledStateToDomainState
  (Msvm_ComputerSystem *computerSystem)
{
    switch (computerSystem->data->EnabledState) {
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_UNKNOWN:
        return VIR_DOMAIN_NOSTATE;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_ENABLED:
        return VIR_DOMAIN_RUNNING;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_DISABLED:
        return VIR_DOMAIN_SHUTOFF;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_PAUSED:
        return VIR_DOMAIN_PAUSED;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED: /* managed save */
        return VIR_DOMAIN_SHUTOFF;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_STARTING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SNAPSHOTTING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SAVING:
        return VIR_DOMAIN_RUNNING;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_STOPPING:
        return VIR_DOMAIN_SHUTDOWN;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_PAUSING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_RESUMING:
        return VIR_DOMAIN_RUNNING;

      default:
        return VIR_DOMAIN_NOSTATE;
    }
}

bool
hypervIsMsvmComputerSystemActive(Msvm_ComputerSystem *computerSystem,
                                 bool *in_transition)
{
    if (in_transition != NULL) {
        *in_transition = false;
    }

    switch (computerSystem->data->EnabledState) {
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_UNKNOWN:
        return false;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_ENABLED:
        return true;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_DISABLED:
        return false;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_PAUSED:
        return true;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED: /* managed save */
        return false;

      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_STARTING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SNAPSHOTTING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SAVING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_STOPPING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_PAUSING:
      case MSVM_COMPUTERSYSTEM_ENABLEDSTATE_RESUMING:
        if (in_transition != NULL) {
            *in_transition = true;
        }

        return true;

      default:
        return false;
    }
}

int
hypervMsvmComputerSystemToDomain(virConnectPtr conn,
                                 Msvm_ComputerSystem *computerSystem,
                                 virDomainPtr *domain)
{
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (domain == NULL || *domain != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virUUIDParse(computerSystem->data->Name, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%s'"),
                       computerSystem->data->Name);
        return -1;
    }

    *domain = virGetDomain(conn, computerSystem->data->ElementName, uuid);

    if (*domain == NULL) {
        return -1;
    }

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL)) {
        (*domain)->id = computerSystem->data->ProcessID;
    } else {
        (*domain)->id = -1;
    }

    return 0;
}

int
hypervMsvmComputerSystemFromDomain(virDomainPtr domain,
                                   Msvm_ComputerSystem **computerSystem)
{
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    virBuffer query = VIR_BUFFER_INITIALIZER;

    if (computerSystem == NULL || *computerSystem != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virUUIDFormat(domain->uuid, uuid_string);

    virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_SELECT);
    virBufferAddLit(&query, "where ");
    virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_VIRTUAL);
    virBufferAsprintf(&query, "and Name = \"%s\"", uuid_string);

    if (hypervGetMsvmComputerSystemList(priv, &query, computerSystem) < 0) {
        return -1;
    }

    if (*computerSystem == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with UUID %s"), uuid_string);
        return -1;
    }

    return 0;
}



#include "hyperv_wmi.generated.c"
