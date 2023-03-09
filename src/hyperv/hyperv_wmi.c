/*
 * hyperv_wmi.c: general WMI over WSMAN related functions and structures for
 *               managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2017 Datto Inc
 * Copyright (C) 2014 Red Hat, Inc.
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

#include <wsman-soap.h>
#include <wsman-xml.h>
#include <wsman-xml-binding.h>

#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "hyperv_private.h"
#include "hyperv_wmi.h"
#include "virstring.h"
#include "virlog.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV

#define HYPERV_JOB_TIMEOUT_MS 300000

VIR_LOG_INIT("hyperv.hyperv_wmi");

int
hypervGetWmiClassList(hypervPrivate *priv, hypervWmiClassInfo *wmiInfo,
                      virBuffer *query, hypervObject **wmiClass)
{
    hypervWqlQuery wqlQuery = HYPERV_WQL_QUERY_INITIALIZER;

    wqlQuery.info = wmiInfo;
    wqlQuery.query = query;

    return hypervEnumAndPull(priv, &wqlQuery, wmiClass);
}


int
hypervVerifyResponse(WsManClient *client, WsXmlDocH response,
                     const char *detail)
{
    int lastError = wsmc_get_last_error(client);
    int responseCode = wsmc_get_response_code(client);
    WsManFault *fault;

    if (lastError != WS_LASTERR_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Transport error during %1$s: %2$s (%3$d)"),
                       detail, wsman_transport_get_last_error_string(lastError),
                       lastError);
        return -1;
    }

    /* Check the HTTP response code and report an error if it's not 200 (OK),
     * 400 (Bad Request) or 500 (Internal Server Error) */
    if (responseCode != 200 && responseCode != 400 && responseCode != 500) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected HTTP response during %1$s: %2$d"),
                       detail, responseCode);
        return -1;
    }

    if (response == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Empty response during %1$s"), detail);
        return -1;
    }

    if (wsmc_check_for_fault(response)) {
        if (!(fault = wsmc_fault_new()))
            abort();

        wsmc_get_fault_data(response, fault);

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("SOAP fault during %1$s: code '%2$s', subcode '%3$s', reason '%4$s', detail '%5$s'"),
                       detail, NULLSTR(fault->code), NULLSTR(fault->subcode),
                       NULLSTR(fault->reason), NULLSTR(fault->fault_detail));

        wsmc_fault_destroy(fault);
        return -1;
    }

    return 0;
}


/*
 * Methods to work with method invocation parameters
 */

/*
 * hypervCreateInvokeParamsList:
 * @method: The name of the method you are calling
 * @selector: The selector for the object you are invoking the method on
 * @obj: The WmiInfo of the object class you are invoking the method on.
 *
 * Create a new InvokeParamsList object for the method call.
 *
 * Returns a pointer to the newly instantiated object on success, which should
 * be freed by hypervInvokeMethod. Otherwise returns NULL.
 */
hypervInvokeParamsList *
hypervCreateInvokeParamsList(const char *method,
                             const char *selector,
                             hypervWmiClassInfo *info)
{
    hypervInvokeParamsList *params = NULL;

    params = g_new0(hypervInvokeParamsList, 1);

    params->params = g_new0(hypervParam, HYPERV_DEFAULT_PARAM_COUNT);

    params->method = method;
    params->ns = info->rootUri;
    params->resourceUri = info->resourceUri;
    params->selector = selector;
    params->nbParams = 0;
    params->nbAvailParams = HYPERV_DEFAULT_PARAM_COUNT;

    return params;
}


/*
 * hypervFreeInvokeParams:
 * @params: Params object to be freed
 *
 */
void
hypervFreeInvokeParams(hypervInvokeParamsList *params)
{
    hypervParam *p = NULL;
    size_t i = 0;

    if (params == NULL)
        return;

    for (i = 0; i < params->nbParams; i++) {
        p = &(params->params[i]);

        switch (p->type) {
        case HYPERV_SIMPLE_PARAM:
            break;
        case HYPERV_EPR_PARAM:
            virBufferFreeAndReset(p->epr.query);
            break;
        case HYPERV_EMBEDDED_PARAM:
            hypervFreeEmbeddedParam(p->embedded.table);
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid parameter type passed to free"));
        }
    }

    g_free(params->params);
    g_free(params);
}


static inline int
hypervCheckParams(hypervInvokeParamsList *params)
{
    if (params->nbParams + 1 > params->nbAvailParams) {
        VIR_EXPAND_N(params->params, params->nbAvailParams, 5);
    }

    return 0;
}


/*
 * hypervAddSimpleParam:
 * @params: Params object to add to
 * @name: Name of the parameter
 * @value: Value of the parameter
 *
 * Add a param of type HYPERV_SIMPLE_PARAM, which is essentially a serialized
 * key/value pair.
 *
 * Returns -1 on failure, 0 on success.
 */
int
hypervAddSimpleParam(hypervInvokeParamsList *params, const char *name,
                     const char *value)
{
    hypervParam *p = NULL;

    if (hypervCheckParams(params) < 0)
        return -1;

    p = &params->params[params->nbParams];
    p->type = HYPERV_SIMPLE_PARAM;

    p->simple.name = name;
    p->simple.value = value;

    params->nbParams++;

    return 0;
}


/*
 * hypervAddEprParam:
 * @params: Params object to add to
 * @name: Parameter name
 * @priv: hypervPrivate object associated with the connection
 * @query: WQL filter
 * @eprInfo: WmiInfo of the object being filtered
 *
 * Adds an EPR param to the params list. Returns -1 on failure, 0 on success.
 */
int
hypervAddEprParam(hypervInvokeParamsList *params,
                  const char *name,
                  virBuffer *query,
                  hypervWmiClassInfo *classInfo)
{
    hypervParam *p = NULL;

    if (hypervCheckParams(params) < 0)
        return -1;

    p = &params->params[params->nbParams];
    p->type = HYPERV_EPR_PARAM;
    p->epr.name = name;
    p->epr.query = query;
    p->epr.info = classInfo;
    params->nbParams++;

    return 0;
}


/*
 * hypervCreateEmbeddedParam:
 * @info: WmiInfo of the object type to serialize
 *
 * Instantiates a GHashTable pre-filled with all the properties pre-added
 * a key/value pairs set to NULL. The user then sets only those properties that
 * they wish to serialize, and passes the table via hypervAddEmbeddedParam.
 *
 * Returns a pointer to the GHashTable on success, otherwise NULL.
 */
GHashTable *
hypervCreateEmbeddedParam(hypervWmiClassInfo *classInfo)
{
    size_t i;
    g_autoptr(GHashTable) table = virHashNew(NULL);
    XmlSerializerInfo *typeinfo = NULL;

    typeinfo = classInfo->serializerInfo;

    for (i = 0; typeinfo[i].name != NULL; i++) {
        XmlSerializerInfo *item = &typeinfo[i];

        if (virHashAddEntry(table, item->name, NULL) < 0)
            return NULL;
    }

    return g_steal_pointer(&table);
}


/**
 * hypervSetEmbeddedProperty:
 * @table: hash table allocated earlier by hypervCreateEmbeddedParam()
 * @name: name of the property
 * @value: value of the property
 *
 * For given table of properties, set property of @name to @value.
 * Please note, that the hash table does NOT become owner of the @value and
 * thus caller must ensure the pointer validity.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
hypervSetEmbeddedProperty(GHashTable *table,
                          const char *name,
                          const char *value)
{
    return virHashUpdateEntry(table, name, (void*) value);
}


/*
 * hypervAddEmbeddedParam:
 * @params: Params list to add to
 * @name: Name of the parameter
 * @table: pointer to table of properties to add
 * @info: WmiInfo of the object to serialize
 *
 * Add a GHashTable containing object properties as an embedded param to
 * an invocation list.
 *
 * Upon successful return the @table is consumed and the pointer is cleared out.
 *
 * Returns -1 on failure, 0 on success.
 */
int
hypervAddEmbeddedParam(hypervInvokeParamsList *params,
                       const char *name,
                       GHashTable **table,
                       hypervWmiClassInfo *classInfo)
{
    hypervParam *p = NULL;

    if (hypervCheckParams(params) < 0)
        return -1;

    p = &params->params[params->nbParams];
    p->type = HYPERV_EMBEDDED_PARAM;
    p->embedded.name = name;
    p->embedded.table = g_steal_pointer(table);
    p->embedded.info = classInfo;
    params->nbParams++;

    return 0;
}


/*
 * hypervFreeEmbeddedParam:
 * @param: Pointer to embedded param to free
 *
 * Free the embedded param hash table.
 */
void
hypervFreeEmbeddedParam(GHashTable *p)
{
    g_clear_pointer(&p, g_hash_table_unref);
}


/*
 * Serializing parameters to XML and invoking methods
 */
static int
hypervGetCimTypeInfo(hypervCimType *typemap, const char *name,
                     hypervCimType **property)
{
    size_t i = 0;
    while (typemap[i].name[0] != '\0') {
        if (STREQ(typemap[i].name, name)) {
            *property = &typemap[i];
            return 0;
        }
        i++;
    }

    return -1;
}


static int
hypervCreateInvokeXmlDoc(hypervInvokeParamsList *params, WsXmlDocH *docRoot)
{
    g_autofree char *method = g_strdup_printf("%s_INPUT", params->method);
    g_auto(WsXmlDocH) invokeXmlDocRoot = ws_xml_create_doc(NULL, method);
    WsXmlNodeH xmlNodeMethod = NULL;

    if (!invokeXmlDocRoot) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not instantiate XML document"));
        return -1;
    }

    xmlNodeMethod = xml_parser_get_root(invokeXmlDocRoot);
    if (!xmlNodeMethod) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get root node of XML document"));
        return -1;
    }

    /* add resource URI as namespace */
    ws_xml_set_ns(xmlNodeMethod, params->resourceUri, "p");

    *docRoot = g_steal_pointer(&invokeXmlDocRoot);

    return 0;
}


static int
hypervSerializeSimpleParam(hypervParam *p, const char *resourceUri,
                           WsXmlNodeH *methodNode)
{
    WsXmlNodeH xmlNodeParam = NULL;

    xmlNodeParam = ws_xml_add_child(*methodNode, resourceUri,
                                    p->simple.name, p->simple.value);
    if (xmlNodeParam == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create simple param"));
        return -1;
    }

    return 0;
}


static int
hypervSerializeEprParam(hypervParam *p, hypervPrivate *priv,
                        const char *resourceUri, WsXmlNodeH *methodNode)
{
    WsXmlNodeH xmlNodeParam = NULL,
               xmlNodeTemp = NULL,
               xmlNodeAddr = NULL,
               xmlNodeRef = NULL;
    g_auto(WsXmlDocH) xmlDocResponse = NULL;
    g_autoptr(client_opt_t) options = NULL;
    g_autoptr(filter_t) filter = NULL;
    g_autofree char *enumContext = NULL;
    g_autofree char *query_string = NULL;

    /* init and set up options */
    options = wsmc_options_init();
    if (!options) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not init options"));
        return -1;
    }
    wsmc_set_action_option(options, FLAG_ENUMERATION_ENUM_EPR);

    query_string = virBufferContentAndReset(p->epr.query);

    filter = filter_create_simple(WSM_WQL_FILTER_DIALECT, query_string);
    if (!filter) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not create WQL filter"));
        return -1;
    }

    /* enumerate based on the filter from this query */
    xmlDocResponse = wsmc_action_enumerate(priv->client, p->epr.info->rootUri,
                                           options, filter);
    if (hypervVerifyResponse(priv->client, xmlDocResponse, "enumeration") < 0)
        return -1;

    /* Get context */
    enumContext = wsmc_get_enum_context(xmlDocResponse);
    ws_xml_destroy_doc(xmlDocResponse);

    /* Pull using filter and enum context */
    xmlDocResponse = wsmc_action_pull(priv->client, resourceUri, options,
                                      filter, enumContext);

    if (hypervVerifyResponse(priv->client, xmlDocResponse, "pull") < 0)
        return -1;

    /* drill down and extract EPR node children */
    if (!(xmlNodeTemp = ws_xml_get_soap_body(xmlDocResponse))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get SOAP body"));
        return -1;
    }

    if (!(xmlNodeTemp = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ENUMERATION,
                                         WSENUM_PULL_RESP))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get response"));
        return -1;
    }

    if (!(xmlNodeTemp = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ENUMERATION, WSENUM_ITEMS))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get response items"));
        return -1;
    }

    if (!(xmlNodeTemp = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ADDRESSING, WSA_EPR))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get EPR items"));
        return -1;
    }

    if (!(xmlNodeAddr = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ADDRESSING,
                                         WSA_ADDRESS))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get EPR address"));
        return -1;
    }

    if (!(xmlNodeRef = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ADDRESSING,
                                        WSA_REFERENCE_PARAMETERS))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not lookup EPR item reference parameters"));
        return -1;
    }

    /* now build a new xml doc with the EPR node children */
    if (!(xmlNodeParam = ws_xml_add_child(*methodNode, resourceUri,
                                          p->epr.name, NULL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not add child node to methodNode"));
        return -1;
    }

    if (!ws_xml_ns_add(xmlNodeParam, "http://schemas.xmlsoap.org/ws/2004/08/addressing", "a")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set namespace address for xmlNodeParam"));
        return -1;
    }

    if (!ws_xml_ns_add(xmlNodeParam, "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", "w")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set wsman namespace address for xmlNodeParam"));
        return -1;
    }

    ws_xml_duplicate_tree(xmlNodeParam, xmlNodeAddr);
    ws_xml_duplicate_tree(xmlNodeParam, xmlNodeRef);

    /* we did it! */
    return 0;
}


static int
hypervSerializeEmbeddedParam(hypervParam *p, const char *resourceUri,
                             WsXmlNodeH *methodNode)
{
    WsXmlNodeH xmlNodeInstance = NULL,
               xmlNodeProperty = NULL,
               xmlNodeParam = NULL,
               xmlNodeArray = NULL;
    g_auto(WsXmlDocH) xmlDocTemp = NULL;
    g_auto(WsXmlDocH) xmlDocCdata = NULL;
    g_autofree char *cdataContent = NULL;
    xmlNodePtr xmlNodeCdata = NULL;
    hypervWmiClassInfo *classInfo = p->embedded.info;
    g_autofree virHashKeyValuePair *items = NULL;
    hypervCimType *property = NULL;
    ssize_t numKeys = -1;
    int len = 0, i = 0;

    if (!(xmlNodeParam = ws_xml_add_child(*methodNode, resourceUri, p->embedded.name,
                                          NULL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not add child node %1$s"),
                       p->embedded.name);
        return -1;
    }

    /* create the temp xml doc */

    /* start with the INSTANCE node */
    if (!(xmlDocTemp = ws_xml_create_doc(NULL, "INSTANCE"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create temporary xml doc"));
        return -1;
    }

    if (!(xmlNodeInstance = xml_parser_get_root(xmlDocTemp))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get temp xml doc root"));
        return -1;
    }

    /* add CLASSNAME node to INSTANCE node */
    if (!(ws_xml_add_node_attr(xmlNodeInstance, NULL, "CLASSNAME",
                               classInfo->name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not add attribute to node"));
        return -1;
    }

    /* retrieve parameters out of hash table */
    numKeys = virHashSize(p->embedded.table);
    items = virHashGetItems(p->embedded.table, NULL, false);
    if (!items) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not read embedded param hash table"));
        return -1;
    }

    /* Add the parameters */
    for (i = 0; i < numKeys; i++) {
        const char *name = items[i].key;
        const char *value = items[i].value;

        if (value != NULL) {
            if (hypervGetCimTypeInfo(classInfo->propertyInfo, name,
                                     &property) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not read type information"));
                return -1;
            }

            if (!(xmlNodeProperty = ws_xml_add_child(xmlNodeInstance, NULL,
                                                     property->isArray ? "PROPERTY.ARRAY" : "PROPERTY",
                                                     NULL))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not add child to XML node"));
                return -1;
            }

            if (!(ws_xml_add_node_attr(xmlNodeProperty, NULL, "NAME", name))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not add attribute to XML node"));
                return -1;
            }

            if (!(ws_xml_add_node_attr(xmlNodeProperty, NULL, "TYPE", property->type))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not add attribute to XML node"));
                return -1;
            }

            /* If this attribute is an array, add VALUE.ARRAY node */
            if (property->isArray) {
                if (!(xmlNodeArray = ws_xml_add_child(xmlNodeProperty, NULL,
                                                      "VALUE.ARRAY", NULL))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Could not add child to XML node"));
                    return -1;
                }
            }

            /* add the child */
            if (!(ws_xml_add_child(property->isArray ? xmlNodeArray : xmlNodeProperty,
                                   NULL, "VALUE", value))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not add child to XML node"));
                return -1;
            }

            xmlNodeArray = NULL;
            xmlNodeProperty = NULL;
        }
    }

    /* create CDATA node */
    ws_xml_dump_memory_node_tree(xmlNodeInstance, &cdataContent, &len);

    if (!(xmlNodeCdata = xmlNewCDataBlock((xmlDocPtr) xmlDocCdata,
                                          (xmlChar *)cdataContent, len))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create CDATA element"));
        return -1;
    }

    /*
     * Add CDATA node to the doc root
     *
     * FIXME: there is no openwsman wrapper for xmlNewCDataBlock, so instead
     * silence clang alignment warnings by casting to a void pointer first
     */
    if (!(xmlAddChild((xmlNodePtr)(void *)xmlNodeParam, xmlNodeCdata))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not add CDATA to doc root"));
        return -1;
    }

    /* we did it! */
    return 0;
}


/*
 * hypervInvokeMethod:
 * @priv: hypervPrivate object associated with the connection
 * @paramsPtr: pointer to object containing the all necessary information for
 *             method invocation (consumed on invocation)
 * @res: Optional out parameter to contain the response XML.
 *
 * Performs an invocation described by object at @paramsPtr, and optionally
 * returns the XML containing the result.
 *
 * Please note that, object at @paramsPtr is consumed by this function and the
 * pointer is cleared out, regardless of returning success or failure.
 *
 * Returns -1 on failure, 0 on success.
 */
int
hypervInvokeMethod(hypervPrivate *priv,
                   hypervInvokeParamsList **paramsPtr,
                   WsXmlDocH *res)
{
    g_autoptr(hypervInvokeParamsList) params = *paramsPtr;
    size_t i = 0;
    int returnCode;
    g_auto(WsXmlDocH) paramsDocRoot = NULL;
    g_autoptr(client_opt_t) options = NULL;
    g_auto(WsXmlDocH) response = NULL;
    WsXmlNodeH methodNode = NULL;
    g_autofree char *returnValue_xpath = NULL;
    g_autofree char *jobcode_instance_xpath = NULL;
    g_autofree char *returnValue = NULL;
    g_autofree char *instanceID = NULL;
    bool completed = false;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_ConcreteJob) job = NULL;
    int jobState = -1;
    hypervParam *p = NULL;
    int timeout = HYPERV_JOB_TIMEOUT_MS;

    *paramsPtr = NULL;

    if (hypervCreateInvokeXmlDoc(params, &paramsDocRoot) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create XML document"));
        return -1;
    }

    methodNode = xml_parser_get_root(paramsDocRoot);
    if (!methodNode) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get root of XML document"));
        return -1;
    }

    /* Serialize parameters */
    for (i = 0; i < params->nbParams; i++) {
        p = &(params->params[i]);

        switch (p->type) {
        case HYPERV_SIMPLE_PARAM:
            if (hypervSerializeSimpleParam(p, params->resourceUri,
                                           &methodNode) < 0)
                return -1;
            break;
        case HYPERV_EPR_PARAM:
            if (hypervSerializeEprParam(p, priv, params->resourceUri,
                                        &methodNode) < 0)
                return -1;
            break;
        case HYPERV_EMBEDDED_PARAM:
            if (hypervSerializeEmbeddedParam(p, params->resourceUri,
                                             &methodNode) < 0)
                return -1;
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unknown parameter type"));
            return -1;
        }
    }

    /* Invoke the method and get the response */

    options = wsmc_options_init();
    if (!options) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not init options"));
        return -1;
    }
    wsmc_add_selectors_from_str(options, params->selector);

    /* do the invoke */
    response = wsmc_action_invoke(priv->client, params->resourceUri, options,
                                  params->method, paramsDocRoot);

    /* check return code of invocation */
    returnValue_xpath = g_strdup_printf("/s:Envelope/s:Body/p:%s_OUTPUT/p:ReturnValue",
                                        params->method);

    returnValue = ws_xml_get_xpath_value(response, returnValue_xpath);
    if (!returnValue) {
        g_autofree char *faultReason_xpath = g_strdup("/s:Envelope/s:Body/s:Fault/s:Reason/s:Text");
        g_autofree char *faultReason = ws_xml_get_xpath_value(response, faultReason_xpath);

        if (faultReason)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("WS-Management fault during %1$s invocation: %2$s"),
                           params->method, faultReason);
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get return value for %1$s invocation"),
                           params->method);

        return -1;
    }

    if (virStrToLong_i(returnValue, NULL, 10, &returnCode) < 0)
        return -1;

    if (returnCode == CIM_RETURNCODE_TRANSITION_STARTED) {
        jobcode_instance_xpath = g_strdup_printf("/s:Envelope/s:Body/p:%s_OUTPUT/p:Job/a:ReferenceParameters/"
                                                 "w:SelectorSet/w:Selector[@Name='InstanceID']",
                                                 params->method);

        instanceID = ws_xml_get_xpath_value(response, jobcode_instance_xpath);
        if (!instanceID) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get instance ID for %1$s invocation"),
                           params->method);
            return -1;
        }

        /*
         * Poll Hyper-V about the job until either the job completes or fails,
         * or 5 minutes have elapsed.
         *
         * Windows has its own timeout on running WMI method calls (it calls
         * these "jobs"), by default set to 1 minute. The administrator can
         * change this to whatever they want, however, so we can't rely on it.
         *
         * Therefore, to avoid waiting in this loop for a very long-running job
         * to complete, we instead bail after 5 minutes no matter what. NOTE that
         * this does not mean that the remote job has terminated on the Windows
         * side! That is up to Windows to control, we don't do anything about it.
         */
        while (!completed && timeout >= 0) {
            virBufferEscapeSQL(&query,
                               MSVM_CONCRETEJOB_WQL_SELECT
                               "WHERE InstanceID = '%s'", instanceID);

            if (hypervGetWmiClass(Msvm_ConcreteJob, &job) < 0 || !job)
                return -1;

            jobState = job->data->JobState;
            switch (jobState) {
            case MSVM_CONCRETEJOB_JOBSTATE_NEW:
            case MSVM_CONCRETEJOB_JOBSTATE_STARTING:
            case MSVM_CONCRETEJOB_JOBSTATE_RUNNING:
            case MSVM_CONCRETEJOB_JOBSTATE_SHUTTING_DOWN:
                hypervFreeObject((hypervObject *)job);
                job = NULL;
                g_usleep(100 * 1000); /* sleep 100 ms */
                timeout -= 100;
                continue;
            case MSVM_CONCRETEJOB_JOBSTATE_COMPLETED:
                completed = true;
                break;
            case MSVM_CONCRETEJOB_JOBSTATE_TERMINATED:
            case MSVM_CONCRETEJOB_JOBSTATE_KILLED:
            case MSVM_CONCRETEJOB_JOBSTATE_EXCEPTION:
            case MSVM_CONCRETEJOB_JOBSTATE_SERVICE:
                return -1;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unknown invocation state"));
                return -1;
            }
        }
        if (!completed && timeout < 0) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("Timeout waiting for %1$s invocation"), params->method);
            return -1;
        }
    } else if (returnCode != CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invocation of %1$s returned an error: %2$s (%3$d)"),
                       params->method, hypervReturnCodeToString(returnCode),
                       returnCode);
        return -1;
    }

    if (res)
        *res = g_steal_pointer(&response);

    return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object
 */

/* This function guarantees that wqlQuery->query is reset, even on failure */
int
hypervEnumAndPull(hypervPrivate *priv, hypervWqlQuery *wqlQuery,
                  hypervObject **list)
{
    WsSerializerContextH serializerContext;
    g_autoptr(client_opt_t) options = NULL;
    g_autofree char *query_string = NULL;
    hypervWmiClassInfo *wmiInfo = wqlQuery->info;
    g_autoptr(filter_t) filter = NULL;
    g_auto(WsXmlDocH) response = NULL;
    g_autofree char *enumContext = NULL;
    g_autoptr(hypervObject) head = NULL;
    hypervObject *tail = NULL;
    WsXmlNodeH node = NULL;
    hypervObject *object;

    query_string = virBufferContentAndReset(wqlQuery->query);

    if (list == NULL || *list != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        VIR_FREE(query_string);
        return -1;
    }

    serializerContext = wsmc_get_serialization_context(priv->client);

    options = wsmc_options_init();

    if (options == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize options"));
        return -1;
    }

    filter = filter_create_simple(WSM_WQL_FILTER_DIALECT, query_string);

    if (filter == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create filter"));
        return -1;
    }

    response = wsmc_action_enumerate(priv->client, wmiInfo->rootUri, options,
                                     filter);

    if (hypervVerifyResponse(priv->client, response, "enumeration") < 0)
        return -1;

    enumContext = wsmc_get_enum_context(response);

    g_clear_pointer(&response, ws_xml_destroy_doc);

    while (enumContext != NULL && *enumContext != '\0') {
        XML_TYPE_PTR data = NULL;

        response = wsmc_action_pull(priv->client, wmiInfo->resourceUri, options,
                                    filter, enumContext);

        if (hypervVerifyResponse(priv->client, response, "pull") < 0)
            return -1;

        node = ws_xml_get_soap_body(response);

        if (node == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not lookup SOAP body"));
            return -1;
        }

        node = ws_xml_get_child(node, 0, XML_NS_ENUMERATION, WSENUM_PULL_RESP);

        if (node == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not lookup pull response"));
            return -1;
        }

        node = ws_xml_get_child(node, 0, XML_NS_ENUMERATION, WSENUM_ITEMS);

        if (node == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not lookup pull response items"));
            return -1;
        }

        if (ws_xml_get_child(node, 0, wmiInfo->resourceUri,
                             wmiInfo->name) == NULL)
            break;

        data = ws_deserialize(serializerContext, node, wmiInfo->serializerInfo,
                              wmiInfo->name, wmiInfo->resourceUri, NULL, 0, 0);

        if (data == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not deserialize pull response item"));
            return -1;
        }

        object = g_new0(hypervObject, 1);
        object->info = wmiInfo;
        object->data = data;
        object->priv = priv;

        if (head == NULL) {
            head = object;
        } else {
            tail->next = object;
        }

        tail = object;

        VIR_FREE(enumContext);
        enumContext = wsmc_get_enum_context(response);

        g_clear_pointer(&response, ws_xml_destroy_doc);
    }

    *list = g_steal_pointer(&head);

    return 0;
}


void
hypervFreeObject(void *object)
{
    hypervObject *next;
    WsSerializerContextH serializerContext;

    if (object == NULL)
        return;

    serializerContext = wsmc_get_serialization_context(((hypervObject *)object)->priv->client);

    while (object != NULL) {
        next = ((hypervObject *)object)->next;

        ((hypervObject *)object)->priv = NULL;

        if (ws_serializer_free_mem(serializerContext, ((hypervObject *)object)->data,
                                   ((hypervObject *)object)->info->serializerInfo) < 0) {
            VIR_ERROR(_("Could not free deserialized data"));
        }

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
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    g_auto(WsXmlDocH) response = NULL;
    g_autoptr(client_opt_t) options = NULL;
    g_autofree char *selector = NULL;
    g_autofree char *properties = NULL;
    g_autofree char *returnValue = NULL;
    int returnCode;
    g_autofree char *instanceID = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_ConcreteJob) concreteJob = NULL;
    bool completed = false;

    virUUIDFormat(domain->uuid, uuid_string);

    selector = g_strdup_printf("Name=%s&CreationClassName=Msvm_ComputerSystem", uuid_string);
    properties = g_strdup_printf("RequestedState=%d", requestedState);

    options = wsmc_options_init();

    if (options == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize options"));
        return -1;
    }

    wsmc_add_selectors_from_str(options, selector);
    wsmc_add_prop_from_str(options, properties);

    /* Invoke method */
    response = wsmc_action_invoke(priv->client, MSVM_COMPUTERSYSTEM_RESOURCE_URI,
                                  options, "RequestStateChange", NULL);

    if (hypervVerifyResponse(priv->client, response, "invocation") < 0)
        return -1;

    /* Check return value */
    returnValue = ws_xml_get_xpath_value(response, (char *)"/s:Envelope/s:Body/p:RequestStateChange_OUTPUT/p:ReturnValue");

    if (returnValue == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not lookup %1$s for %2$s invocation"),
                       "ReturnValue", "RequestStateChange");
        return -1;
    }

    if (virStrToLong_i(returnValue, NULL, 10, &returnCode) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse return code from '%1$s'"), returnValue);
        return -1;
    }

    if (returnCode == CIM_RETURNCODE_TRANSITION_STARTED) {
        /* Get concrete job object */
        instanceID = ws_xml_get_xpath_value(response, (char *)"/s:Envelope/s:Body/p:RequestStateChange_OUTPUT/p:Job/a:ReferenceParameters/w:SelectorSet/w:Selector[@Name='InstanceID']");

        if (instanceID == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not lookup %1$s for %2$s invocation"),
                           "InstanceID", "RequestStateChange");
            return -1;
        }

        /* FIXME: Poll every 100ms until the job completes or fails. There
         *        seems to be no other way than polling. */
        while (!completed) {
            virBufferAsprintf(&query,
                              MSVM_CONCRETEJOB_WQL_SELECT
                              "WHERE InstanceID = '%s'", instanceID);

            if (hypervGetWmiClass(Msvm_ConcreteJob, &concreteJob) < 0)
                return -1;

            if (concreteJob == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not lookup %1$s for %2$s invocation"),
                               "Msvm_ConcreteJob", "RequestStateChange");
                return -1;
            }

            switch (concreteJob->data->JobState) {
            case MSVM_CONCRETEJOB_JOBSTATE_NEW:
            case MSVM_CONCRETEJOB_JOBSTATE_STARTING:
            case MSVM_CONCRETEJOB_JOBSTATE_RUNNING:
            case MSVM_CONCRETEJOB_JOBSTATE_SHUTTING_DOWN:
                hypervFreeObject((hypervObject *)concreteJob);
                concreteJob = NULL;

                g_usleep(100 * 1000);
                continue;

            case MSVM_CONCRETEJOB_JOBSTATE_COMPLETED:
                completed = true;
                break;

            case MSVM_CONCRETEJOB_JOBSTATE_TERMINATED:
            case MSVM_CONCRETEJOB_JOBSTATE_KILLED:
            case MSVM_CONCRETEJOB_JOBSTATE_EXCEPTION:
            case MSVM_CONCRETEJOB_JOBSTATE_SERVICE:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Concrete job for %1$s invocation is in error state"),
                               "RequestStateChange");
                return -1;

            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Concrete job for %1$s invocation is in unknown state"),
                               "RequestStateChange");
                return -1;
            }
        }
    } else if (returnCode != CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invocation of %1$s returned an error: %2$s (%3$d)"),
                       "RequestStateChange", hypervReturnCodeToString(returnCode),
                       returnCode);
        return -1;
    }

    return 0;
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
    if (in_transition != NULL)
        *in_transition = false;

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
        if (in_transition != NULL)
            *in_transition = true;

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
    int id = -1;

    if (domain == NULL || *domain != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virUUIDParse(computerSystem->data->Name, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%1$s'"),
                       computerSystem->data->Name);
        return -1;
    }

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL))
        id = computerSystem->data->ProcessID;

    *domain = virGetDomain(conn, computerSystem->data->ElementName, uuid, id);

    return *domain ? 0 : -1;
}


int
hypervMsvmComputerSystemFromUUID(hypervPrivate *priv, const char *uuid,
                                 Msvm_ComputerSystem **computerSystem)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;

    if (!computerSystem || *computerSystem) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virBufferEscapeSQL(&query,
                       MSVM_COMPUTERSYSTEM_WQL_SELECT
                       "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL
                       "AND Name = '%s'", uuid);

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystem) < 0)
        return -1;

    if (!*computerSystem) {
        virReportError(VIR_ERR_NO_DOMAIN, _("No domain with UUID %1$s"), uuid);
        return -1;
    }

    return 0;
}


int
hypervMsvmComputerSystemFromDomain(virDomainPtr domain,
                                   Msvm_ComputerSystem **computerSystem)
{
    hypervPrivate *priv = domain->conn->privateData;
    char uuidString[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(domain->uuid, uuidString);

    return hypervMsvmComputerSystemFromUUID(priv, uuidString, computerSystem);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Generic "Get WMI class list" helpers
 */

int
hypervGetMsvmVirtualSystemSettingDataFromUUID(hypervPrivate *priv,
                                              const char *uuid_string,
                                              Msvm_VirtualSystemSettingData **list)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&query,
                      "ASSOCIATORS OF {Msvm_ComputerSystem.CreationClassName='Msvm_ComputerSystem',Name='%s'} "
                      "WHERE AssocClass = Msvm_SettingsDefineState "
                      "ResultClass = Msvm_VirtualSystemSettingData",
                      uuid_string);

    if (hypervGetWmiClass(Msvm_VirtualSystemSettingData, list) < 0 || !*list)
        return -1;

    return 0;
}


#define hypervGetSettingData(type, id, out) \
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER; \
    virBufferEscapeSQL(&query, \
                       "ASSOCIATORS OF {Msvm_VirtualSystemSettingData.InstanceID='%s'} " \
                       "WHERE AssocClass = Msvm_VirtualSystemSettingDataComponent " \
                       "ResultClass = " #type, \
                       id); \
    if (hypervGetWmiClass(type, out) < 0) \
        return -1


int
hypervGetResourceAllocationSD(hypervPrivate *priv,
                              const char *id,
                              Msvm_ResourceAllocationSettingData **data)
{
    hypervGetSettingData(Msvm_ResourceAllocationSettingData, id, data);

    if (!*data) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up resource allocation setting data with virtual system instance ID '%1$s'"),
                       id);
        return -1;
    }

    return 0;
}


int
hypervGetProcessorSD(hypervPrivate *priv,
                     const char *id,
                     Msvm_ProcessorSettingData **data)
{
    hypervGetSettingData(Msvm_ProcessorSettingData, id, data);

    if (!*data) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up processor setting data with virtual system instance ID '%1$s'"),
                       id);
        return -1;
    }

    return 0;
}


int
hypervGetMemorySD(hypervPrivate *priv,
                  const char *vssd_instanceid,
                  Msvm_MemorySettingData **list)
{
    hypervGetSettingData(Msvm_MemorySettingData, vssd_instanceid, list);

    if (!*list)
        return -1;

    return 0;
}


int
hypervGetStorageAllocationSD(hypervPrivate *priv,
                             const char *id,
                             Msvm_StorageAllocationSettingData **data)
{
    hypervGetSettingData(Msvm_StorageAllocationSettingData, id, data);
    return 0;
}


int
hypervGetSerialPortSD(hypervPrivate *priv,
                      const char *id,
                      Msvm_SerialPortSettingData **data)
{
    hypervGetSettingData(Msvm_SerialPortSettingData, id, data);
    return 0;
}


int
hypervGetSyntheticEthernetPortSD(hypervPrivate *priv,
                                 const char *id,
                                 Msvm_SyntheticEthernetPortSettingData **data)
{
    hypervGetSettingData(Msvm_SyntheticEthernetPortSettingData, id, data);
    return 0;
}


int
hypervGetEthernetPortAllocationSD(hypervPrivate *priv,
                                  const char *id,
                                  Msvm_EthernetPortAllocationSettingData **data)
{
    hypervGetSettingData(Msvm_EthernetPortAllocationSettingData, id, data);
    return 0;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_VirtualSystemManagementService
 */

int
hypervMsvmVSMSAddResourceSettings(virDomainPtr domain,
                                  GHashTable **resourceSettingsPtr,
                                  hypervWmiClassInfo *wmiInfo,
                                  WsXmlDocH *response)
{
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(GHashTable) resourceSettings = *resourceSettingsPtr;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_auto(virBuffer) eprQuery = VIR_BUFFER_INITIALIZER;

    *resourceSettingsPtr = NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    virBufferEscapeSQL(&eprQuery,
                       MSVM_VIRTUALSYSTEMSETTINGDATA_WQL_SELECT "WHERE InstanceID='%s'",
                       vssd->data->InstanceID);

    params = hypervCreateInvokeParamsList("AddResourceSettings",
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);

    if (!params)
        return -1;

    if (hypervAddEprParam(params, "AffectedConfiguration",
                          &eprQuery, Msvm_VirtualSystemSettingData_WmiInfo) < 0)
        return -1;

    if (hypervAddEmbeddedParam(params, "ResourceSettings", &resourceSettings, wmiInfo) < 0) {
        hypervFreeEmbeddedParam(resourceSettings);
        return -1;
    }

    if (hypervInvokeMethod(priv, &params, response) < 0)
        return -1;

    return 0;
}


int
hypervMsvmVSMSModifyResourceSettings(hypervPrivate *priv,
                                     GHashTable **resourceSettingsPtr,
                                     hypervWmiClassInfo *wmiInfo)
{
    g_autoptr(GHashTable) resourceSettings = *resourceSettingsPtr;
    g_autoptr(hypervInvokeParamsList) params = NULL;

    *resourceSettingsPtr = NULL;

    params = hypervCreateInvokeParamsList("ModifyResourceSettings",
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);

    if (!params)
        return -1;

    if (hypervAddEmbeddedParam(params, "ResourceSettings", &resourceSettings, wmiInfo) < 0) {
        hypervFreeEmbeddedParam(resourceSettings);
        return -1;
    }

    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        return -1;

    return 0;
}
