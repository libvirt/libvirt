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

#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "hyperv_private.h"
#include "hyperv_wmi.h"
#include "virstring.h"
#include "openwsman.h"
#include "virlog.h"

#define WS_SERIALIZER_FREE_MEM_WORKS 0

#define VIR_FROM_THIS VIR_FROM_HYPERV

#define HYPERV_JOB_TIMEOUT_MS 300000

VIR_LOG_INIT("hyperv.hyperv_wmi");

static int
hypervGetWmiClassInfo(hypervPrivate *priv, hypervWmiClassInfoListPtr list,
                      hypervWmiClassInfoPtr *info)
{
    const char *version = "v2";
    size_t i;

    if (list->count == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The WMI class info list is empty"));
        return -1;
    }

    /* if there's just one WMI class and isn't versioned, assume "shared" */
    if (list->count == 1 && list->objs[0]->version == NULL) {
        *info = list->objs[0];
        return 0;
    }

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1)
        version = "v1";

    for (i = 0; i < list->count; i++) {
       if (STRCASEEQ(list->objs[i]->version, version)) {
           *info = list->objs[i];
           return 0;
       }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Could not match WMI class info for version %s"),
                   version);

    return -1;
}

static int
hypervGetWmiClassList(hypervPrivate *priv, hypervWmiClassInfoListPtr wmiInfo,
                      virBufferPtr query, hypervObject **wmiClass)
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


/*
 * Methods to work with method invocation parameters
 */

/*
 * hypervCreateInvokeParamsList:
 * @priv: hypervPrivate object associated with the connection.
 * @method: The name of the method you are calling
 * @selector: The selector for the object you are invoking the method on
 * @obj: The WmiInfo of the object class you are invoking the method on.
 *
 * Create a new InvokeParamsList object for the method call.
 *
 * Returns a pointer to the newly instantiated object on success, which should
 * be freed by hypervInvokeMethod. Otherwise returns NULL.
 */
hypervInvokeParamsListPtr
hypervCreateInvokeParamsList(hypervPrivate *priv, const char *method,
        const char *selector, hypervWmiClassInfoListPtr obj)
{
    hypervInvokeParamsListPtr params = NULL;
    hypervWmiClassInfoPtr info = NULL;

    if (hypervGetWmiClassInfo(priv, obj, &info) < 0)
        goto cleanup;

    if (VIR_ALLOC(params) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(params->params,
                HYPERV_DEFAULT_PARAM_COUNT) < 0) {
        VIR_FREE(params);
        goto cleanup;
    }

    params->method = method;
    params->ns = info->rootUri;
    params->resourceUri = info->resourceUri;
    params->selector = selector;
    params->nbParams = 0;
    params->nbAvailParams = HYPERV_DEFAULT_PARAM_COUNT;

 cleanup:
    return params;
}

/*
 * hypervFreeInvokeParams:
 * @params: Params object to be freed
 *
 */
void
hypervFreeInvokeParams(hypervInvokeParamsListPtr params)
{
    hypervParamPtr p = NULL;
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

    VIR_DISPOSE_N(params->params, params->nbAvailParams);
    VIR_FREE(params);
}

static inline int
hypervCheckParams(hypervInvokeParamsListPtr params)
{
    if (params->nbParams + 1 > params->nbAvailParams) {
        if (VIR_EXPAND_N(params->params, params->nbAvailParams, 5) < 0)
            return -1;
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
hypervAddSimpleParam(hypervInvokeParamsListPtr params, const char *name,
        const char *value)
{
    int result = -1;
    hypervParamPtr p = NULL;

    if (hypervCheckParams(params) < 0)
        goto cleanup;

    p = &params->params[params->nbParams];
    p->type = HYPERV_SIMPLE_PARAM;

    p->simple.name = name;
    p->simple.value = value;

    params->nbParams++;

    result = 0;

 cleanup:
    return result;
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
hypervAddEprParam(hypervInvokeParamsListPtr params, const char *name,
        hypervPrivate *priv, virBufferPtr query,
        hypervWmiClassInfoListPtr eprInfo)
{
    hypervParamPtr p = NULL;
    hypervWmiClassInfoPtr classInfo = NULL;

    if (hypervGetWmiClassInfo(priv, eprInfo, &classInfo) < 0 ||
            hypervCheckParams(params) < 0)
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
 * @priv: hypervPrivate object associated with the connection
 * @info: WmiInfo of the object type to serialize
 *
 * Instantiates a virHashTable pre-filled with all the properties pre-added
 * a key/value pairs set to NULL. The user then sets only those properties that
 * they wish to serialize, and passes the table via hypervAddEmbeddedParam.
 *
 * Returns a pointer to the virHashTable on success, otherwise NULL.
 */
virHashTablePtr
hypervCreateEmbeddedParam(hypervPrivate *priv, hypervWmiClassInfoListPtr info)
{
    size_t i;
    int count = 0;
    virHashTablePtr table = NULL;
    XmlSerializerInfo *typeinfo = NULL;
    XmlSerializerInfo *item = NULL;
    hypervWmiClassInfoPtr classInfo = NULL;

    /* Get the typeinfo out of the class info list */
    if (hypervGetWmiClassInfo(priv, info, &classInfo) < 0)
        goto error;

    typeinfo = classInfo->serializerInfo;

    /* loop through the items to find out how many fields there are */
    for (i = 0; typeinfo[i].name != NULL; i++) {}
    count = i;

    table = virHashCreate(count, NULL);
    if (table == NULL)
        goto error;

    for (i = 0; typeinfo[i].name != NULL; i++) {
        item = &typeinfo[i];

        if (virHashAddEntry(table, item->name, NULL) < 0)
            goto error;
    }

    return table;

 error:
    virHashFree(table);
    return NULL;
}

int
hypervSetEmbeddedProperty(virHashTablePtr table, const char *name, char *value)
{
    return virHashUpdateEntry(table, name, value);
}

/*
 * hypervAddEmbeddedParam:
 * @params: Params list to add to
 * @priv: hypervPrivate object associated with the connection
 * @name: Name of the parameter
 * @table: table of properties to add
 * @info: WmiInfo of the object to serialize
 *
 * Add a virHashTable containing object properties as an embedded param to
 * an invocation list. Returns -1 on failure, 0 on success.
 */
int
hypervAddEmbeddedParam(hypervInvokeParamsListPtr params, hypervPrivate *priv,
        const char *name, virHashTablePtr table, hypervWmiClassInfoListPtr info)
{
    hypervParamPtr p = NULL;
    hypervWmiClassInfoPtr classInfo = NULL;

    if (hypervCheckParams(params) < 0)
        return -1;

    /* Get the typeinfo out of the class info list */
    if (hypervGetWmiClassInfo(priv, info, &classInfo) < 0)
        return -1;

    p = &params->params[params->nbParams];
    p->type = HYPERV_EMBEDDED_PARAM;
    p->embedded.name = name;
    p->embedded.table = table;
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
hypervFreeEmbeddedParam(virHashTablePtr p)
{
    virHashFree(p);
}

/*
 * Serializing parameters to XML and invoking methods
 */

static int
hypervGetCimTypeInfo(hypervCimTypePtr typemap, const char *name,
        hypervCimTypePtr *property)
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
hypervCreateInvokeXmlDoc(hypervInvokeParamsListPtr params, WsXmlDocH *docRoot)
{
    int result = -1;
    char *method = NULL;
    WsXmlNodeH xmlNodeMethod = NULL;

    if (virAsprintf(&method, "%s_INPUT", params->method) < 0)
        goto cleanup;

    *docRoot = ws_xml_create_doc(NULL, method);
    if (*docRoot == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not instantiate XML document"));
        goto cleanup;
    }

    xmlNodeMethod = xml_parser_get_root(*docRoot);
    if (xmlNodeMethod == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not get root node of XML document"));
        goto cleanup;
    }

    /* add resource URI as namespace */
    ws_xml_set_ns(xmlNodeMethod, params->resourceUri, "p");

    result = 0;

 cleanup:
    if (result < 0 && *docRoot != NULL) {
        ws_xml_destroy_doc(*docRoot);
        *docRoot = NULL;
    }
    VIR_FREE(method);
    return result;
}

static int
hypervSerializeSimpleParam(hypervParamPtr p, const char *resourceUri,
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
hypervSerializeEprParam(hypervParamPtr p, hypervPrivate *priv,
        const char *resourceUri, WsXmlDocH doc, WsXmlNodeH *methodNode)
{
    int result = -1;
    WsXmlNodeH xmlNodeParam = NULL,
               xmlNodeTemp = NULL,
               xmlNodeAddr = NULL,
               xmlNodeRef = NULL;
    xmlNodePtr xmlNodeAddrPtr = NULL,
               xmlNodeRefPtr = NULL;
    WsXmlDocH xmlDocResponse = NULL;
    xmlDocPtr docPtr = (xmlDocPtr) doc->parserDoc;
    WsXmlNsH ns = NULL;
    client_opt_t *options = NULL;
    filter_t *filter = NULL;
    char *enumContext = NULL;
    char *query_string = NULL;

    /* init and set up options */
    options = wsmc_options_init();
    if (!options) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not init options"));
        goto cleanup;
    }
    wsmc_set_action_option(options, FLAG_ENUMERATION_ENUM_EPR);

    /* Get query and create filter based on it */
    if (virBufferCheckError(p->epr.query) < 0) {
        virBufferFreeAndReset(p->epr.query);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid query"));
        goto cleanup;
    }
    query_string = virBufferContentAndReset(p->epr.query);

    filter = filter_create_simple(WSM_WQL_FILTER_DIALECT, query_string);
    if (!filter) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not create WQL filter"));
        goto cleanup;
    }

    /* enumerate based on the filter from this query */
    xmlDocResponse = wsmc_action_enumerate(priv->client, p->epr.info->rootUri,
            options, filter);
    if (hypervVerifyResponse(priv->client, xmlDocResponse, "enumeration") < 0)
        goto cleanup;

    /* Get context */
    enumContext = wsmc_get_enum_context(xmlDocResponse);
    ws_xml_destroy_doc(xmlDocResponse);

    /* Pull using filter and enum context */
    xmlDocResponse = wsmc_action_pull(priv->client, resourceUri, options,
            filter, enumContext);

    if (hypervVerifyResponse(priv->client, xmlDocResponse, "pull") < 0)
        goto cleanup;

    /* drill down and extract EPR node children */
    if (!(xmlNodeTemp = ws_xml_get_soap_body(xmlDocResponse))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get SOAP body"));
        goto cleanup;
    }

    if (!(xmlNodeTemp = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ENUMERATION,
            WSENUM_PULL_RESP))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get response"));
        goto cleanup;
    }

    if (!(xmlNodeTemp = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ENUMERATION, WSENUM_ITEMS))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get response items"));
        goto cleanup;
    }

    if (!(xmlNodeTemp = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ADDRESSING, WSA_EPR))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get EPR items"));
        goto cleanup;
    }

    if (!(xmlNodeAddr = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ADDRESSING,
                    WSA_ADDRESS))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not get EPR address"));
        goto cleanup;
    }

    if (!(xmlNodeAddrPtr = xmlDocCopyNode((xmlNodePtr) xmlNodeAddr, docPtr, 1))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not copy EPR address"));
        goto cleanup;
    }

    if (!(xmlNodeRef = ws_xml_get_child(xmlNodeTemp, 0, XML_NS_ADDRESSING,
            WSA_REFERENCE_PARAMETERS))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not lookup EPR item reference parameters"));
        goto cleanup;
    }

    if (!(xmlNodeRefPtr = xmlDocCopyNode((xmlNodePtr) xmlNodeRef, docPtr, 1))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not copy EPR item reference parameters"));
        goto cleanup;
    }

    /* now build a new xml doc with the EPR node children */
    if (!(xmlNodeParam = ws_xml_add_child(*methodNode, resourceUri,
                    p->epr.name, NULL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not add child node to xmlNodeParam"));
        goto cleanup;
    }

    if (!(ns = ws_xml_ns_add(xmlNodeParam,
                    "http://schemas.xmlsoap.org/ws/2004/08/addressing", "a"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not set namespace address for xmlNodeParam"));
        goto cleanup;
    }

    if (!(ns = ws_xml_ns_add(xmlNodeParam,
                    "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", "w"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not set wsman namespace address for xmlNodeParam"));
        goto cleanup;
    }

    if (xmlAddChild((xmlNodePtr) *methodNode, (xmlNodePtr) xmlNodeParam) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not add child to xml parent node"));
        goto cleanup;
    }

    if (xmlAddChild((xmlNodePtr) xmlNodeParam, xmlNodeAddrPtr) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not add child to xml parent node"));
        goto cleanup;
    }

    if (xmlAddChild((xmlNodePtr) xmlNodeParam, xmlNodeRefPtr) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not add child to xml parent node"));
        goto cleanup;
    }

    /* we did it! */
    result = 0;

 cleanup:
    if (options != NULL)
        wsmc_options_destroy(options);
    if (filter != NULL)
        filter_destroy(filter);
    ws_xml_destroy_doc(xmlDocResponse);
    VIR_FREE(enumContext);
    VIR_FREE(query_string);
    return result;
}

static int
hypervSerializeEmbeddedParam(hypervParamPtr p, const char *resourceUri,
        WsXmlNodeH *methodNode)
{
    int result = -1;
    WsXmlNodeH xmlNodeInstance = NULL,
               xmlNodeProperty = NULL,
               xmlNodeParam = NULL,
               xmlNodeArray = NULL;
    WsXmlDocH xmlDocTemp = NULL,
              xmlDocCdata = NULL;
    xmlBufferPtr xmlBufferNode = NULL;
    const xmlChar *xmlCharCdataContent = NULL;
    xmlNodePtr xmlNodeCdata = NULL;
    hypervWmiClassInfoPtr classInfo = p->embedded.info;
    virHashKeyValuePairPtr items = NULL;
    hypervCimTypePtr property = NULL;
    ssize_t numKeys = -1;
    int len = 0, i = 0;

    if (!(xmlNodeParam = ws_xml_add_child(*methodNode, resourceUri, p->embedded.name,
                    NULL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not add child node %s"),
                p->embedded.name);
        goto cleanup;
    }

    /* create the temp xml doc */

    /* start with the INSTANCE node */
    if (!(xmlDocTemp = ws_xml_create_doc(NULL, "INSTANCE"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not create temporary xml doc"));
        goto cleanup;
    }

    if (!(xmlNodeInstance = xml_parser_get_root(xmlDocTemp))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not get temp xml doc root"));
        goto cleanup;
    }

    /* add CLASSNAME node to INSTANCE node */
    if (!(ws_xml_add_node_attr(xmlNodeInstance, NULL, "CLASSNAME",
                classInfo->name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not add attribute to node"));
        goto cleanup;
    }

    /* retrieve parameters out of hash table */
    numKeys = virHashSize(p->embedded.table);
    items = virHashGetItems(p->embedded.table, NULL);
    if (!items) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not read embedded param hash table"));
        goto cleanup;
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
                goto cleanup;
            }

            if (!(xmlNodeProperty = ws_xml_add_child(xmlNodeInstance, NULL,
                            property->isArray ? "PROPERTY.ARRAY" : "PROPERTY",
                            NULL))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not add child to XML node"));
                goto cleanup;
            }

            if (!(ws_xml_add_node_attr(xmlNodeProperty, NULL, "NAME", name))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not add attribute to XML node"));
                goto cleanup;
            }

            if (!(ws_xml_add_node_attr(xmlNodeProperty, NULL, "TYPE", property->type))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not add attribute to XML node"));
                goto cleanup;
            }

            /* If this attribute is an array, add VALUE.ARRAY node */
            if (property->isArray) {
                if (!(xmlNodeArray = ws_xml_add_child(xmlNodeProperty, NULL,
                                "VALUE.ARRAY", NULL))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Could not add child to XML node"));
                    goto cleanup;
                }
            }

            /* add the child */
            if (!(ws_xml_add_child(property->isArray ? xmlNodeArray : xmlNodeProperty,
                        NULL, "VALUE", value))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not add child to XML node"));
                goto cleanup;
            }

            xmlNodeArray = NULL;
            xmlNodeProperty = NULL;
        }
    }

    /* create CDATA node */
    xmlBufferNode = xmlBufferCreate();
    if (xmlNodeDump(xmlBufferNode, (xmlDocPtr) xmlDocTemp->parserDoc,
                (xmlNodePtr) xmlNodeInstance, 0, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not get root of temp XML doc"));
        goto cleanup;
    }

    len = xmlBufferLength(xmlBufferNode);
    xmlCharCdataContent = xmlBufferContent(xmlBufferNode);
    if (!(xmlNodeCdata = xmlNewCDataBlock((xmlDocPtr) xmlDocCdata,
                    xmlCharCdataContent, len))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not create CDATA element"));
        goto cleanup;
    }

    /* Add CDATA node to the doc root */
    if (!(xmlAddChild((xmlNodePtr) xmlNodeParam, xmlNodeCdata))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not add CDATA to doc root"));
        goto cleanup;
    }

    /* we did it! */
    result = 0;

 cleanup:
    VIR_FREE(items);
    ws_xml_destroy_doc(xmlDocCdata);
    ws_xml_destroy_doc(xmlDocTemp);
    xmlBufferFree(xmlBufferNode);
    return result;
}


/*
 * hypervInvokeMethod:
 * @priv: hypervPrivate object associated with the connection
 * @params: object containing the all necessary information for method
 * invocation
 * @res: Optional out parameter to contain the response XML.
 *
 * Performs an invocation described by @params, and optionally returns the
 * XML containing the result. Returns -1 on failure, 0 on success.
 */
int
hypervInvokeMethod(hypervPrivate *priv, hypervInvokeParamsListPtr params,
        WsXmlDocH *res)
{
    int result = -1;
    size_t i = 0;
    int returnCode;
    WsXmlDocH paramsDocRoot = NULL;
    client_opt_t *options = NULL;
    WsXmlDocH response = NULL;
    WsXmlNodeH methodNode = NULL;
    char *returnValue_xpath = NULL;
    char *jobcode_instance_xpath = NULL;
    char *returnValue = NULL;
    char *instanceID = NULL;
    bool completed = false;
    virBuffer query = VIR_BUFFER_INITIALIZER;
    Msvm_ConcreteJob *job = NULL;
    int jobState = -1;
    hypervParamPtr p = NULL;
    int timeout = HYPERV_JOB_TIMEOUT_MS;

    if (hypervCreateInvokeXmlDoc(params, &paramsDocRoot) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not create XML document"));
        goto cleanup;
    }

    methodNode = xml_parser_get_root(paramsDocRoot);
    if (!methodNode) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Could not get root of XML document"));
        goto cleanup;
    }

    /* Serialize parameters */
    for (i = 0; i < params->nbParams; i++) {
        p = &(params->params[i]);

        switch (p->type) {
            case HYPERV_SIMPLE_PARAM:
                if (hypervSerializeSimpleParam(p, params->resourceUri,
                            &methodNode) < 0)
                    goto cleanup;
                break;
            case HYPERV_EPR_PARAM:
                if (hypervSerializeEprParam(p, priv, params->resourceUri,
                            paramsDocRoot, &methodNode) < 0)
                    goto cleanup;
                break;
            case HYPERV_EMBEDDED_PARAM:
                if (hypervSerializeEmbeddedParam(p, params->resourceUri,
                            &methodNode) < 0)
                    goto cleanup;
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Unknown parameter type"));
                goto cleanup;
        }
    }

    /* Invoke the method and get the response */

    options = wsmc_options_init();
    if (!options) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not init options"));
        goto cleanup;
    }
    wsmc_add_selectors_from_str(options, params->selector);

    /* do the invoke */
    response = wsmc_action_invoke(priv->client, params->resourceUri, options,
            params->method, paramsDocRoot);

    /* check return code of invocation */
    if (virAsprintf(&returnValue_xpath, "/s:Envelope/s:Body/p:%s_OUTPUT/p:ReturnValue",
            params->method) < 0)
        goto cleanup;

    returnValue = ws_xml_get_xpath_value(response, returnValue_xpath);
    if (!returnValue) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get return value for %s invocation"),
                       params->method);
        goto cleanup;
    }

    if (virStrToLong_i(returnValue, NULL, 10, &returnCode) < 0)
        goto cleanup;

    if (returnCode == CIM_RETURNCODE_TRANSITION_STARTED) {
        if (virAsprintf(&jobcode_instance_xpath,
                    "/s:Envelope/s:Body/p:%s_OUTPUT/p:Job/a:ReferenceParameters/"
                    "w:SelectorSet/w:Selector[@Name='InstanceID']",
                    params->method) < 0) {
            goto cleanup;
        }

        instanceID = ws_xml_get_xpath_value(response, jobcode_instance_xpath);
        if (!instanceID) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get instance ID for %s invocation"),
                           params->method);
            goto cleanup;
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
            virBufferAddLit(&query, MSVM_CONCRETEJOB_WQL_SELECT);
            virBufferAsprintf(&query, "where InstanceID = \"%s\"", instanceID);

            if (hypervGetMsvmConcreteJobList(priv, &query, &job) < 0
                    || job == NULL)
                goto cleanup;

            jobState = job->data.common->JobState;
            switch (jobState) {
                case MSVM_CONCRETEJOB_JOBSTATE_NEW:
                case MSVM_CONCRETEJOB_JOBSTATE_STARTING:
                case MSVM_CONCRETEJOB_JOBSTATE_RUNNING:
                case MSVM_CONCRETEJOB_JOBSTATE_SHUTTING_DOWN:
                    hypervFreeObject(priv, (hypervObject *) job);
                    job = NULL;
                    usleep(100 * 1000); /* sleep 100 ms */
                    timeout -= 100;
                    continue;
                case MSVM_CONCRETEJOB_JOBSTATE_COMPLETED:
                    completed = true;
                    break;
                case MSVM_CONCRETEJOB_JOBSTATE_TERMINATED:
                case MSVM_CONCRETEJOB_JOBSTATE_KILLED:
                case MSVM_CONCRETEJOB_JOBSTATE_EXCEPTION:
                case MSVM_CONCRETEJOB_JOBSTATE_SERVICE:
                    goto cleanup;
                default:
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Unknown invocation state"));
                    goto cleanup;
            }
        }
        if (!completed && timeout < 0) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                    _("Timeout waiting for %s invocation"), params->method);
            goto cleanup;
        }
    } else if (returnCode != CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invocation of %s returned an error: %s (%d)"),
                    params->method, hypervReturnCodeToString(returnCode),
                    returnCode);
        goto cleanup;
    }

    if (res)
        *res = response;

    result = 0;

 cleanup:
    if (options)
        wsmc_options_destroy(options);
    if (response && (!res))
        ws_xml_destroy_doc(response);
    if (paramsDocRoot)
        ws_xml_destroy_doc(paramsDocRoot);
    VIR_FREE(returnValue_xpath);
    VIR_FREE(jobcode_instance_xpath);
    VIR_FREE(returnValue);
    VIR_FREE(instanceID);
    virBufferFreeAndReset(&query);
    hypervFreeObject(priv, (hypervObject *) job);
    hypervFreeInvokeParams(params);
    return result;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object
 */

/* This function guarantees that wqlQuery->query is reset, even on failure */
int
hypervEnumAndPull(hypervPrivate *priv, hypervWqlQueryPtr wqlQuery,
                  hypervObject **list)
{
    int result = -1;
    WsSerializerContextH serializerContext;
    client_opt_t *options = NULL;
    char *query_string = NULL;
    hypervWmiClassInfoPtr wmiInfo = NULL;
    filter_t *filter = NULL;
    WsXmlDocH response = NULL;
    char *enumContext = NULL;
    hypervObject *head = NULL;
    hypervObject *tail = NULL;
    WsXmlNodeH node = NULL;
    XML_TYPE_PTR data = NULL;
    hypervObject *object;

    if (virBufferCheckError(wqlQuery->query) < 0) {
        virBufferFreeAndReset(wqlQuery->query);
        return -1;
    }

    query_string = virBufferContentAndReset(wqlQuery->query);

    if (list == NULL || *list != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        VIR_FREE(query_string);
        return -1;
    }

    if (hypervGetWmiClassInfo(priv, wqlQuery->info, &wmiInfo) < 0)
        goto cleanup;

    serializerContext = wsmc_get_serialization_context(priv->client);

    options = wsmc_options_init();

    if (options == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize options"));
        goto cleanup;
    }

    filter = filter_create_simple(WSM_WQL_FILTER_DIALECT, query_string);

    if (filter == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create filter"));
        goto cleanup;
    }

    response = wsmc_action_enumerate(priv->client, wmiInfo->rootUri, options,
                                     filter);

    if (hypervVerifyResponse(priv->client, response, "enumeration") < 0)
        goto cleanup;

    enumContext = wsmc_get_enum_context(response);

    ws_xml_destroy_doc(response);
    response = NULL;

    while (enumContext != NULL && *enumContext != '\0') {
        response = wsmc_action_pull(priv->client, wmiInfo->resourceUri, options,
                                    filter, enumContext);

        if (hypervVerifyResponse(priv->client, response, "pull") < 0)
            goto cleanup;

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

        if (ws_xml_get_child(node, 0, wmiInfo->resourceUri,
                             wmiInfo->name) == NULL)
            break;

        data = ws_deserialize(serializerContext, node, wmiInfo->serializerInfo,
                              wmiInfo->name, wmiInfo->resourceUri, NULL, 0, 0);

        if (data == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not deserialize pull response item"));
            goto cleanup;
        }

        if (VIR_ALLOC(object) < 0)
            goto cleanup;

        object->info = wmiInfo;
        object->data.common = data;

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
    if (options != NULL)
        wsmc_options_destroy(options);

    if (filter != NULL)
        filter_destroy(filter);

    if (data != NULL) {
#if WS_SERIALIZER_FREE_MEM_WORKS
        /* FIXME: ws_serializer_free_mem is broken in openwsman <= 2.2.6,
         *        see hypervFreeObject for a detailed explanation. */
        if (ws_serializer_free_mem(serializerContext, data,
                                   wmiInfo->serializerInfo) < 0) {
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

    if (object == NULL)
        return;

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
        if (ws_serializer_free_mem(serializerContext, object->data.common,
                                   object->info->serializerInfo) < 0) {
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
 * Generic "Get WMI class list" helpers
 */

int
hypervGetMsvmComputerSystemList(hypervPrivate *priv, virBufferPtr query,
                                Msvm_ComputerSystem **list)
{
    return hypervGetWmiClassList(priv, Msvm_ComputerSystem_WmiInfo, query,
                                 (hypervObject **) list);
}

int
hypervGetMsvmConcreteJobList(hypervPrivate *priv, virBufferPtr query,
                             Msvm_ConcreteJob **list)
{
    return hypervGetWmiClassList(priv, Msvm_ConcreteJob_WmiInfo, query,
                                 (hypervObject **) list);
}

int
hypervGetWin32ComputerSystemList(hypervPrivate *priv, virBufferPtr query,
                                 Win32_ComputerSystem **list)
{
    return hypervGetWmiClassList(priv, Win32_ComputerSystem_WmiInfo, query,
                                 (hypervObject **) list);
}

int
hypervGetWin32ProcessorList(hypervPrivate *priv, virBufferPtr query,
                            Win32_Processor **list)
{
    return hypervGetWmiClassList(priv, Win32_Processor_WmiInfo, query,
                                 (hypervObject **) list);
}

int
hypervGetMsvmVirtualSystemSettingDataList(hypervPrivate *priv,
                                          virBufferPtr query,
                                          Msvm_VirtualSystemSettingData **list)
{
    return hypervGetWmiClassList(priv, Msvm_VirtualSystemSettingData_WmiInfo, query,
                                 (hypervObject **) list);
}

int
hypervGetMsvmProcessorSettingDataList(hypervPrivate *priv,
                                      virBufferPtr query,
                                      Msvm_ProcessorSettingData **list)
{
    return hypervGetWmiClassList(priv, Msvm_ProcessorSettingData_WmiInfo, query,
                                 (hypervObject **) list);
}

int
hypervGetMsvmMemorySettingDataList(hypervPrivate *priv, virBufferPtr query,
                                   Msvm_MemorySettingData **list)
{
    return hypervGetWmiClassList(priv, Msvm_MemorySettingData_WmiInfo, query,
                                 (hypervObject **) list);
}

int hypervGetMsvmKeyboardList(hypervPrivate *priv, virBufferPtr query,
                              Msvm_Keyboard **list)
{
    return hypervGetWmiClassList(priv, Msvm_Keyboard_WmiInfo, query,
                                 (hypervObject **) list);
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
    const char *resourceUri = MSVM_COMPUTERSYSTEM_V2_RESOURCE_URI;

    virUUIDFormat(domain->uuid, uuid_string);

    if (virAsprintf(&selector, "Name=%s&CreationClassName=Msvm_ComputerSystem",
                    uuid_string) < 0 ||
        virAsprintf(&properties, "RequestedState=%d", requestedState) < 0)
        goto cleanup;

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1)
        resourceUri = MSVM_COMPUTERSYSTEM_V1_RESOURCE_URI;

    options = wsmc_options_init();

    if (options == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize options"));
        goto cleanup;
    }

    wsmc_add_selectors_from_str(options, selector);
    wsmc_add_prop_from_str(options, properties);

    /* Invoke method */
    response = wsmc_action_invoke(priv->client, resourceUri,
                                  options, "RequestStateChange", NULL);

    if (hypervVerifyResponse(priv->client, response, "invocation") < 0)
        goto cleanup;

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

            if (hypervGetMsvmConcreteJobList(priv, &query, &concreteJob) < 0)
                goto cleanup;

            if (concreteJob == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not lookup %s for %s invocation"),
                               "Msvm_ConcreteJob", "RequestStateChange");
                goto cleanup;
            }

            switch (concreteJob->data.common->JobState) {
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
    if (options != NULL)
        wsmc_options_destroy(options);

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
    switch (computerSystem->data.common->EnabledState) {
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

    switch (computerSystem->data.common->EnabledState) {
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

    if (virUUIDParse(computerSystem->data.common->Name, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%s'"),
                       computerSystem->data.common->Name);
        return -1;
    }

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL))
        id = computerSystem->data.common->ProcessID;

    *domain = virGetDomain(conn, computerSystem->data.common->ElementName, uuid, id);

    return *domain ? 0 : -1;
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

    if (hypervGetMsvmComputerSystemList(priv, &query, computerSystem) < 0)
        return -1;

    if (*computerSystem == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with UUID %s"), uuid_string);
        return -1;
    }

    return 0;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_VirtualSystemSettingData
 */

int
hypervGetMsvmVirtualSystemSettingDataFromUUID(hypervPrivate *priv,
        const char *uuid_string, Msvm_VirtualSystemSettingData **list)
{
    virBuffer query = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&query,
            "associators of "
            "{Msvm_ComputerSystem.CreationClassName=\"Msvm_ComputerSystem\","
            "Name=\"%s\"} "
            "where AssocClass = Msvm_SettingsDefineState "
            "ResultClass = Msvm_VirtualSystemSettingData",
            uuid_string);

    if (hypervGetWmiClassList(priv, Msvm_VirtualSystemSettingData_WmiInfo, &query,
                (hypervObject **) list) < 0 || *list == NULL)
        return -1;

    return 0;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_MemorySettingData
 */

int
hypervGetMsvmMemorySettingDataFromVSSD(hypervPrivate *priv,
        const char *vssd_instanceid, Msvm_MemorySettingData **list)
{
    virBuffer query = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&query,
            "associators of "
            "{Msvm_VirtualSystemSettingData.InstanceID=\"%s\"} "
            "where AssocClass = Msvm_VirtualSystemSettingDataComponent "
            "ResultClass = Msvm_MemorySettingData",
            vssd_instanceid);

    if (hypervGetWmiClassList(priv, Msvm_MemorySettingData_WmiInfo, &query,
                (hypervObject **) list) < 0 || *list == NULL)
        return -1;

    return 0;
}
