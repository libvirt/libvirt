
/*
 * esx_vi.c: client for the VMware VI API 2.5 to manage ESX hosts
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

#include <libxml/parser.h>
#include <libxml/xpathInternals.h>

#include "buf.h"
#include "memory.h"
#include "logging.h"
#include "util.h"
#include "uuid.h"
#include "xml.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX



#define ESX_VI__SOAP__RESPONSE_XPATH(_type)                                   \
    ((char *)"/soapenv:Envelope/soapenv:Body/"                                \
               "vim:"_type"Response/vim:returnval")



#define ESX_VI__TEMPLATE__ALLOC(_type)                                        \
    int                                                                       \
    esxVI_##_type##_Alloc(esxVI_##_type **ptrptr)                             \
    {                                                                         \
        return esxVI_Alloc((void **)ptrptr, sizeof(esxVI_##_type));           \
    }



#define ESX_VI__TEMPLATE__FREE(_type, _body)                                  \
    void                                                                      \
    esxVI_##_type##_Free(esxVI_##_type **ptrptr)                              \
    {                                                                         \
        esxVI_##_type *item = NULL;                                           \
                                                                              \
        if (ptrptr == NULL || *ptrptr == NULL) {                              \
            return;                                                           \
        }                                                                     \
                                                                              \
        item = *ptrptr;                                                       \
                                                                              \
        _body                                                                 \
                                                                              \
        VIR_FREE(*ptrptr);                                                    \
    }



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

/* esxVI_Context_Alloc */
ESX_VI__TEMPLATE__ALLOC(Context);

/* esxVI_Context_Free */
ESX_VI__TEMPLATE__FREE(Context,
{
    VIR_FREE(item->url);
    VIR_FREE(item->ipAddress);

    if (item->curl_handle != NULL) {
        curl_easy_cleanup(item->curl_handle);
    }

    if (item->curl_headers != NULL) {
        curl_slist_free_all(item->curl_headers);
    }

    virMutexDestroy(&item->curl_lock);

    VIR_FREE(item->username);
    VIR_FREE(item->password);
    esxVI_ServiceContent_Free(&item->service);
    esxVI_UserSession_Free(&item->session);
    esxVI_ManagedObjectReference_Free(&item->datacenter);
    esxVI_ManagedObjectReference_Free(&item->vmFolder);
    esxVI_ManagedObjectReference_Free(&item->hostFolder);
    esxVI_SelectionSpec_Free(&item->fullTraversalSpecList);
});

static size_t
esxVI_CURL_ReadString(char *data, size_t size, size_t nmemb, void *ptrptr)
{
    const char *content = *(const char **)ptrptr;
    size_t available = 0;
    size_t requested = size * nmemb;

    if (content == NULL) {
        return 0;
    }

    available = strlen(content);

    if (available == 0) {
        return 0;
    }

    if (requested > available) {
        requested = available;
    }

    memcpy(data, content, requested);

    *(const char **)ptrptr = content + requested;

    return requested;
}

static size_t
esxVI_CURL_WriteBuffer(char *data, size_t size, size_t nmemb, void *buffer)
{
    if (buffer != NULL) {
        virBufferAdd((virBufferPtr) buffer, data, size * nmemb);

        return size * nmemb;
    }

    return 0;
}

#define ESX_VI__CURL__ENABLE_DEBUG_OUTPUT 0

#if ESX_VI__CURL__ENABLE_DEBUG_OUTPUT
static int
esxVI_CURL_Debug(CURL *curl ATTRIBUTE_UNUSED, curl_infotype type,
                 char *info, size_t size, void *data ATTRIBUTE_UNUSED)
{
    char *buffer = NULL;

    /*
     * The libcurl documentation says:
     *
     *    The data pointed to by the char * passed to this function WILL NOT
     *    be zero terminated, but will be exactly of the size as told by the
     *    size_t argument.
     *
     * To handle this properly in order to pass the info string to VIR_DEBUG
     * a zero terminated copy of the info string has to be allocated.
     */
    if (VIR_ALLOC_N(buffer, size + 1) < 0) {
        return 0;
    }

    if (virStrncpy(buffer, info, size, size + 1) == NULL) {
        VIR_FREE(buffer);
        return 0;
    }

    switch (type) {
      case CURLINFO_TEXT:
        if (size > 0 && buffer[size - 1] == '\n') {
            buffer[size - 1] = '\0';
        }

        VIR_DEBUG("CURLINFO_TEXT [[[[%s]]]]", buffer);
        break;

      case CURLINFO_HEADER_IN:
        VIR_DEBUG("CURLINFO_HEADER_IN [[[[%s]]]]", buffer);
        break;

      case CURLINFO_HEADER_OUT:
        VIR_DEBUG("CURLINFO_HEADER_OUT [[[[%s]]]]", buffer);
        break;

      case CURLINFO_DATA_IN:
        VIR_DEBUG("CURLINFO_DATA_IN [[[[%s]]]]", buffer);
        break;

      case CURLINFO_DATA_OUT:
        VIR_DEBUG("CURLINFO_DATA_OUT [[[[%s]]]]", buffer);
        break;

      default:
        VIR_DEBUG0("unknown");
        break;
    }

    VIR_FREE(buffer);

    return 0;
}
#endif

static int
esxVI_CURL_Perform(esxVI_Context *ctx, const char *url)
{
    CURLcode errorCode;
    long responseCode = 0;
#if LIBCURL_VERSION_NUM >= 0x071202 /* 7.18.2 */
    const char *redirectUrl = NULL;
#endif

    errorCode = curl_easy_perform(ctx->curl_handle);

    if (errorCode != CURLE_OK) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("curl_easy_perform() returned an error: %s (%d) : %s"),
                     curl_easy_strerror(errorCode), errorCode, ctx->curl_error);
        return -1;
    }

    errorCode = curl_easy_getinfo(ctx->curl_handle, CURLINFO_RESPONSE_CODE,
                                  &responseCode);

    if (errorCode != CURLE_OK) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned an "
                       "error: %s (%d) : %s"), curl_easy_strerror(errorCode),
                     errorCode, ctx->curl_error);
        return -1;
    }

    if (responseCode < 0) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned a "
                       "negative response code"));
        return -1;
    }

    if (responseCode == 301) {
#if LIBCURL_VERSION_NUM >= 0x071202 /* 7.18.2 */
        errorCode = curl_easy_getinfo(ctx->curl_handle, CURLINFO_REDIRECT_URL,
                                      &redirectUrl);

        if (errorCode != CURLE_OK) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("curl_easy_getinfo(CURLINFO_REDIRECT_URL) returned "
                           "an error: %s (%d) : %s"),
                         curl_easy_strerror(errorCode),
                         errorCode, ctx->curl_error);
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("The server redirects from '%s' to '%s'"), url,
                         redirectUrl);
        }
#else
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("The server redirects from '%s'"), url);
#endif

        return -1;
    }

    return responseCode;
}

int
esxVI_Context_Connect(esxVI_Context *ctx, const char *url,
                      const char *ipAddress, const char *username,
                      const char *password, int noVerify)
{
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datacenterList = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (ctx == NULL || url == NULL || ipAddress == NULL || username == NULL ||
        password == NULL || ctx->url != NULL || ctx->service != NULL ||
        ctx->curl_handle != NULL || ctx->curl_headers != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        goto failure;
    }

    if (esxVI_String_DeepCopyValue(&ctx->url, url) < 0 ||
        esxVI_String_DeepCopyValue(&ctx->ipAddress, ipAddress) < 0) {
        goto failure;
    }

    ctx->curl_handle = curl_easy_init();

    if (ctx->curl_handle == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not initialize CURL"));
        goto failure;
    }

    ctx->curl_headers = curl_slist_append(ctx->curl_headers, "Content-Type: "
                                          "text/xml; charset=UTF-8");

    /*
     * Add a dummy expect header to stop CURL from waiting for a response code
     * 100 (Continue) from the server before continuing the POST operation.
     * Waiting for this response would slowdown each communication with the
     * server by approx. 2 sec, because the server doesn't send the expected
     * 100 (Continue) response and the wait times out resulting in wasting
     * approx. 2 sec per POST operation.
     */
    ctx->curl_headers = curl_slist_append(ctx->curl_headers,
                                          "Expect: nothing");

    if (ctx->curl_headers == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not build CURL header list"));
        goto failure;
    }

    curl_easy_setopt(ctx->curl_handle, CURLOPT_URL, ctx->url);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_USERAGENT, "libvirt-esx");
    curl_easy_setopt(ctx->curl_handle, CURLOPT_HEADER, 0);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_FOLLOWLOCATION, 0);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_SSL_VERIFYPEER, noVerify ? 0 : 1);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_SSL_VERIFYHOST, noVerify ? 0 : 2);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(ctx->curl_handle, CURLOPT_HTTPHEADER, ctx->curl_headers);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_READFUNCTION,
                     esxVI_CURL_ReadString);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_WRITEFUNCTION,
                     esxVI_CURL_WriteBuffer);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_ERRORBUFFER,
                     ctx->curl_error);
#if ESX_VI__CURL__ENABLE_DEBUG_OUTPUT
    curl_easy_setopt(ctx->curl_handle, CURLOPT_DEBUGFUNCTION, esxVI_CURL_Debug);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_VERBOSE, 1);
#endif

    if (virMutexInit(&ctx->curl_lock) < 0) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not initialize CURL mutex"));
        goto failure;
    }

    ctx->username = strdup(username);
    ctx->password = strdup(password);

    if (ctx->username == NULL || ctx->password == NULL) {
        virReportOOMError();
        goto failure;
    }

    if (esxVI_RetrieveServiceContent(ctx, &ctx->service) < 0) {
        goto failure;
    }

    if (STREQ(ctx->service->about->apiType, "HostAgent") ||
        STREQ(ctx->service->about->apiType, "VirtualCenter")) {
        if (STRPREFIX(ctx->service->about->apiVersion, "2.5")) {
            ctx->apiVersion = esxVI_APIVersion_25;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "4.0")) {
            ctx->apiVersion = esxVI_APIVersion_40;
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Expecting VI API major/minor version '2.5' or '4.0' "
                           "but found '%s'"), ctx->service->about->apiVersion);
            goto failure;
        }

        if (STREQ(ctx->service->about->productLineId, "gsx")) {
            if (STRPREFIX(ctx->service->about->version, "2.0")) {
                ctx->productVersion = esxVI_ProductVersion_GSX20;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Expecting GSX major/minor version '2.0' but "
                               "found '%s'"), ctx->service->about->version);
                goto failure;
            }
        } else if (STREQ(ctx->service->about->productLineId, "esx") ||
                   STREQ(ctx->service->about->productLineId, "embeddedEsx")) {
            if (STRPREFIX(ctx->service->about->version, "3.5")) {
                ctx->productVersion = esxVI_ProductVersion_ESX35;
            } else if (STRPREFIX(ctx->service->about->version, "4.0")) {
                ctx->productVersion = esxVI_ProductVersion_ESX40;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Expecting ESX major/minor version '3.5' or "
                               "'4.0' but found '%s'"),
                             ctx->service->about->version);
                goto failure;
            }
        } else if (STREQ(ctx->service->about->productLineId, "vpx")) {
            if (STRPREFIX(ctx->service->about->version, "2.5")) {
                ctx->productVersion = esxVI_ProductVersion_VPX25;
            } else if (STRPREFIX(ctx->service->about->version, "4.0")) {
                ctx->productVersion = esxVI_ProductVersion_VPX40;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Expecting VPX major/minor version '2.5' or '4.0' "
                               "but found '%s'"), ctx->service->about->version);
                goto failure;
            }
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Expecting product 'gsx' or 'esx' or 'embeddedEsx' "
                           "or 'vpx' but found '%s'"),
                         ctx->service->about->productLineId);
            goto failure;
        }
    } else {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Expecting VI API type 'HostAgent' or 'VirtualCenter' "
                       "but found '%s'"), ctx->service->about->apiType);
        goto failure;
    }

    if (esxVI_Login(ctx, username, password, NULL, &ctx->session) < 0) {
        goto failure;
    }

    esxVI_BuildFullTraversalSpecList(&ctx->fullTraversalSpecList);

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "vmFolder\0"
                                           "hostFolder\0") < 0) {
        goto failure;
    }

    /* Get pointer to Datacenter for later use */
    if (esxVI_LookupObjectContentByType(ctx, ctx->service->rootFolder,
                                        "Datacenter", propertyNameList,
                                        esxVI_Boolean_True,
                                        &datacenterList) < 0) {
        goto failure;
    }

    if (datacenterList == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve the 'datacenter' object from the "
                       "VI host/center"));
        goto failure;
    }

    ctx->datacenter = datacenterList->obj;
    datacenterList->obj = NULL;

    /* Get pointer to vmFolder and hostFolder for later use */
    for (dynamicProperty = datacenterList->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "vmFolder")) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, &ctx->vmFolder)) {
                goto failure;
            }
        } else if (STREQ(dynamicProperty->name, "hostFolder")) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, &ctx->hostFolder)) {
                goto failure;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (ctx->vmFolder == NULL || ctx->hostFolder == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("The 'datacenter' object is missing the "
                       "'vmFolder'/'hostFolder' property"));
        goto failure;
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datacenterList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}

int
esxVI_Context_DownloadFile(esxVI_Context *ctx, const char *url, char **content)
{
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    int responseCode = 0;

    if (content == NULL || *content != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        goto failure;
    }

    virMutexLock(&ctx->curl_lock);

    curl_easy_setopt(ctx->curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_UPLOAD, 0);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_HTTPGET, 1);

    responseCode = esxVI_CURL_Perform(ctx, url);

    virMutexUnlock(&ctx->curl_lock);

    if (responseCode < 0) {
        goto failure;
    } else if (responseCode != 200) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("HTTP response code %d for download from '%s'"),
                     responseCode, url);
        goto failure;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto failure;
    }

    *content = virBufferContentAndReset(&buffer);

    return 0;

  failure:
    virBufferFreeAndReset(&buffer);

    return -1;
}

int
esxVI_Context_UploadFile(esxVI_Context *ctx, const char *url,
                         const char *content)
{
    int responseCode = 0;

    if (content == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virMutexLock(&ctx->curl_lock);

    curl_easy_setopt(ctx->curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_READDATA, &content);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_INFILESIZE, strlen(content));

    responseCode = esxVI_CURL_Perform(ctx, url);

    virMutexUnlock(&ctx->curl_lock);

    if (responseCode < 0) {
        return -1;
    } else if (responseCode != 200 && responseCode != 201) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("HTTP response code %d for upload to '%s'"),
                     responseCode, url);
        return -1;
    }

    return 0;
}

int
esxVI_Context_Execute(esxVI_Context *ctx, const char *methodName,
                      const char *request, esxVI_Response **response,
                      esxVI_Occurrence occurrence)
{
    int result = 0;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    esxVI_Fault *fault = NULL;
    char *xpathExpression = NULL;
    xmlXPathContextPtr xpathContext = NULL;
    xmlNodePtr responseNode = NULL;

    if (request == NULL || response == NULL || *response != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        goto failure;
    }

    if (esxVI_Response_Alloc(response) < 0) {
        goto failure;
    }

    virMutexLock(&ctx->curl_lock);

    curl_easy_setopt(ctx->curl_handle, CURLOPT_URL, ctx->url);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_UPLOAD, 0);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(ctx->curl_handle, CURLOPT_POSTFIELDSIZE, strlen(request));

    (*response)->responseCode = esxVI_CURL_Perform(ctx, ctx->url);

    virMutexUnlock(&ctx->curl_lock);

    if ((*response)->responseCode < 0) {
        goto failure;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto failure;
    }

    (*response)->content = virBufferContentAndReset(&buffer);

    if ((*response)->responseCode == 500 || (*response)->responseCode == 200) {
        (*response)->document = xmlReadDoc(BAD_CAST (*response)->content, "",
                                           NULL, XML_PARSE_NONET);

        if ((*response)->document == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Response for call to '%s' could not be parsed"),
                         methodName);
            goto failure;
        }

        if (xmlDocGetRootElement((*response)->document) == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Response for call to '%s' is an empty XML document"),
                         methodName);
            goto failure;
        }

        xpathContext = xmlXPathNewContext((*response)->document);

        if (xpathContext == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Could not create XPath context"));
            goto failure;
        }

        xmlXPathRegisterNs(xpathContext, BAD_CAST "soapenv",
                           BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/");
        xmlXPathRegisterNs(xpathContext, BAD_CAST "vim", BAD_CAST "urn:vim25");

        if ((*response)->responseCode == 500) {
            (*response)->node =
              virXPathNode("/soapenv:Envelope/soapenv:Body/soapenv:Fault",
                           xpathContext);

            if ((*response)->node == NULL) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("HTTP response code %d for call to '%s'. "
                               "Fault is unknown, XPath evaluation failed"),
                             (*response)->responseCode, methodName);
                goto failure;
            }

            if (esxVI_Fault_Deserialize((*response)->node, &fault) < 0) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("HTTP response code %d for call to '%s'. "
                               "Fault is unknown, deserialization failed"),
                             (*response)->responseCode, methodName);
                goto failure;
            }

            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("HTTP response code %d for call to '%s'. "
                           "Fault: %s - %s"), (*response)->responseCode,
                         methodName, fault->faultcode, fault->faultstring);

            /* FIXME: Dump raw response until detail part gets deserialized */
            VIR_DEBUG("HTTP response code %d for call to '%s' [[[[%s]]]]",
                      (*response)->responseCode, methodName,
                      (*response)->content);

            goto failure;
        } else {
            if (virAsprintf(&xpathExpression,
                            "/soapenv:Envelope/soapenv:Body/vim:%sResponse",
                            methodName) < 0) {
                virReportOOMError();
                goto failure;
            }

            responseNode = virXPathNode(xpathExpression, xpathContext);

            if (responseNode == NULL) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("XPath evaluation of response for call to '%s' "
                               "failed"), methodName);
                goto failure;
            }

            xpathContext->node = responseNode;
            (*response)->node = virXPathNode("./vim:returnval", xpathContext);

            switch (occurrence) {
              case esxVI_Occurrence_RequiredItem:
                if ((*response)->node == NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned an empty result, "
                                   "expecting a non-empty result"), methodName);
                    goto failure;
                } else if ((*response)->node->next != NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned a list, expecting "
                                   "exactly one item"), methodName);
                    goto failure;
                }

                break;

              case esxVI_Occurrence_RequiredList:
                if ((*response)->node == NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned an empty result, "
                                   "expecting a non-empty result"), methodName);
                    goto failure;
                }

                break;

              case esxVI_Occurrence_OptionalItem:
                if ((*response)->node != NULL &&
                    (*response)->node->next != NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned a list, expecting "
                                   "exactly one item"), methodName);
                    goto failure;
                }

                break;

              case esxVI_Occurrence_OptionalList:
                /* Any amount of items is valid */
                break;

              case esxVI_Occurrence_None:
                if ((*response)->node != NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned something, expecting "
                                   "an empty result"), methodName);
                    goto failure;
                }

                break;

              default:
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Invalid argument (occurrence)"));
                goto failure;
            }
        }
    } else {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("HTTP response code %d for call to '%s'"),
                     (*response)->responseCode, methodName);
        goto failure;
    }

  cleanup:
    VIR_FREE(xpathExpression);
    xmlXPathFreeContext(xpathContext);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);
    esxVI_Response_Free(response);
    esxVI_Fault_Free(&fault);

    result = -1;

    goto cleanup;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Response
 */

/* esxVI_Response_Alloc */
ESX_VI__TEMPLATE__ALLOC(Response);

/* esxVI_Response_Free */
ESX_VI__TEMPLATE__FREE(Response,
{
    VIR_FREE(item->content);

    if (item->document != NULL) {
        xmlFreeDoc(item->document);
    }
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Enumeration
 */

int
esxVI_Enumeration_CastFromAnyType(const esxVI_Enumeration *enumeration,
                                  esxVI_AnyType *anyType, int *value)
{
    int i;

    if (anyType == NULL || value == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *value = 0; /* undefined */

    if (anyType->type != enumeration->type) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Expecting type '%s' but found '%s'"),
                     esxVI_Type_ToString(enumeration->type),
                     esxVI_Type_ToString(anyType->type));
        return -1;
    }

    for (i = 0; enumeration->values[i].name != NULL; ++i) {
        if (STREQ(anyType->value, enumeration->values[i].name)) {
            *value = enumeration->values[i].value;
            return 0;
        }
    }

    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                 _("Unknown value '%s' for %s"), anyType->value,
                 esxVI_Type_ToString(enumeration->type));

    return -1;
}

int
esxVI_Enumeration_Serialize(const esxVI_Enumeration *enumeration,
                            int value, const char *element, virBufferPtr output)
{
    int i;
    const char *name = NULL;

    if (element == NULL || output == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (value == 0) { /* undefined */
        return 0;
    }

    for (i = 0; enumeration->values[i].name != NULL; ++i) {
        if (value == enumeration->values[i].value) {
            name = enumeration->values[i].name;
            break;
        }
    }

    if (name == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    ESV_VI__XML_TAG__OPEN(output, element,
                          esxVI_Type_ToString(enumeration->type));

    virBufferAdd(output, name, -1);

    ESV_VI__XML_TAG__CLOSE(output, element);

    return 0;
}

int
esxVI_Enumeration_Deserialize(const esxVI_Enumeration *enumeration,
                              xmlNodePtr node, int *value)
{
    int i;
    int result = 0;
    char *name = NULL;

    if (value == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        goto failure;
    }

    *value = 0; /* undefined */

    if (esxVI_String_DeserializeValue(node, &name) < 0) {
        goto failure;
    }

    for (i = 0; enumeration->values[i].name != NULL; ++i) {
        if (STREQ(name, enumeration->values[i].name)) {
            *value = enumeration->values[i].value;
            goto cleanup;
        }
    }

    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, _("Unknown value '%s' for %s"),
                 name, esxVI_Type_ToString(enumeration->type));

  cleanup:
    VIR_FREE(name);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * List
 */

int
esxVI_List_Append(esxVI_List **list, esxVI_List *item)
{
    esxVI_List *next = NULL;

    if (list == NULL || item == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (*list == NULL) {
        *list = item;
        return 0;
    }

    next = *list;

    while (next->_next != NULL) {
        next = next->_next;
    }

    next->_next = item;

    return 0;
}

int
esxVI_List_DeepCopy(esxVI_List **destList, esxVI_List *srcList,
                    esxVI_List_DeepCopyFunc deepCopyFunc,
                    esxVI_List_FreeFunc freeFunc)
{
    esxVI_List *dest = NULL;
    esxVI_List *src = NULL;

    if (destList == NULL || *destList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        goto failure;
    }

    for (src = srcList; src != NULL; src = src->_next) {
        if (deepCopyFunc(&dest, src) < 0 ||
            esxVI_List_Append(destList, dest) < 0) {
            goto failure;
        }

        dest = NULL;
    }

    return 0;

  failure:
    freeFunc(&dest);
    freeFunc(destList);

    return -1;
}

int
esxVI_List_CastFromAnyType(esxVI_AnyType *anyType, esxVI_List **list,
                           esxVI_List_CastFromAnyTypeFunc castFromAnyTypeFunc,
                           esxVI_List_FreeFunc freeFunc)
{
    int result = 0;
    xmlNodePtr childNode = NULL;
    esxVI_AnyType *childAnyType = NULL;
    esxVI_List *item = NULL;

    if (list == NULL || *list != NULL ||
        castFromAnyTypeFunc == NULL || freeFunc == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (anyType == NULL) {
        return 0;
    }

    if (! STRPREFIX(anyType->other, "ArrayOf")) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Expecting type to begin with 'ArrayOf' but found '%s'"),
                     anyType->other);
        return -1;
    }

    for (childNode = anyType->node->children; childNode != NULL;
         childNode = childNode->next) {
        if (childNode->type != XML_ELEMENT_NODE) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Wrong XML element type %d"), childNode->type);
            goto failure;
        }

        esxVI_AnyType_Free(&childAnyType);

        if (esxVI_AnyType_Deserialize(childNode, &childAnyType) < 0 ||
            castFromAnyTypeFunc(childAnyType, &item) < 0 ||
            esxVI_List_Append(list, item) < 0) {
            goto failure;
        }

        item = NULL;
    }

  cleanup:
    esxVI_AnyType_Free(&childAnyType);

    return result;

  failure:
    freeFunc(&item);
    freeFunc(list);

    result = -1;

    goto cleanup;
}

int
esxVI_List_Serialize(esxVI_List *list, const char *element,
                     virBufferPtr output,
                     esxVI_List_SerializeFunc serializeFunc)
{
    esxVI_List *item = NULL;

    if (element == NULL || output == NULL || serializeFunc == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (list == NULL) {
        return 0;
    }

    for (item = list; item != NULL; item = item->_next) {
        if (serializeFunc(item, element, output) < 0) {
            return -1;
        }
    }

    return 0;
}

int
esxVI_List_Deserialize(xmlNodePtr node, esxVI_List **list,
                       esxVI_List_DeserializeFunc deserializeFunc,
                       esxVI_List_FreeFunc freeFunc)
{
    esxVI_List *item = NULL;

    if (list == NULL || *list != NULL ||
        deserializeFunc == NULL || freeFunc == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (node == NULL) {
        return 0;
    }

    for (; node != NULL; node = node->next) {
        if (node->type != XML_ELEMENT_NODE) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Wrong XML element type %d"), node->type);
            goto failure;
        }

        if (deserializeFunc(node, &item) < 0 ||
            esxVI_List_Append(list, item) < 0) {
            goto failure;
        }

        item = NULL;
    }

    return 0;

  failure:
    freeFunc(&item);
    freeFunc(list);

    return -1;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Utility and Convenience Functions
 *
 * Function naming scheme:
 *  - 'lookup' functions query the ESX or vCenter for information
 *  - 'get' functions get information from a local object
 */

int
esxVI_Alloc(void **ptrptr, size_t size)
{
    if (ptrptr == NULL || *ptrptr != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virAllocN(ptrptr, size, 1) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}



int
esxVI_BuildFullTraversalSpecItem(esxVI_SelectionSpec **fullTraversalSpecList,
                                 const char *name, const char *type,
                                 const char *path, const char *selectSetNames)
{
    esxVI_TraversalSpec *traversalSpec = NULL;
    esxVI_SelectionSpec *selectionSpec = NULL;
    const char *currentSelectSetName = NULL;

    if (fullTraversalSpecList == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_TraversalSpec_Alloc(&traversalSpec) < 0 ||
        esxVI_String_DeepCopyValue(&traversalSpec->name, name) < 0 ||
        esxVI_String_DeepCopyValue(&traversalSpec->type, type) < 0 ||
        esxVI_String_DeepCopyValue(&traversalSpec->path, path) < 0) {
        goto failure;
    }

    traversalSpec->skip = esxVI_Boolean_False;

    if (selectSetNames != NULL) {
        currentSelectSetName = selectSetNames;

        while (currentSelectSetName != NULL && *currentSelectSetName != '\0') {
            if (esxVI_SelectionSpec_Alloc(&selectionSpec) < 0 ||
                esxVI_String_DeepCopyValue(&selectionSpec->name,
                                           currentSelectSetName) < 0 ||
                esxVI_SelectionSpec_AppendToList(&traversalSpec->selectSet,
                                                 selectionSpec) < 0) {
                goto failure;
            }

            selectionSpec = NULL;
            currentSelectSetName += strlen(currentSelectSetName) + 1;
        }
    }

    if (esxVI_SelectionSpec_AppendToList(fullTraversalSpecList,
                                         esxVI_SelectionSpec_DynamicCast
                                           (traversalSpec)) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_TraversalSpec_Free(&traversalSpec);
    esxVI_SelectionSpec_Free(&selectionSpec);

    return -1;
}



int
esxVI_BuildFullTraversalSpecList(esxVI_SelectionSpec **fullTraversalSpecList)
{
    if (fullTraversalSpecList == NULL || *fullTraversalSpecList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "visitFolders",
                                         "Folder", "childEntity",
                                         "visitFolders\0"
                                         "datacenterToDatastore\0"
                                         "datacenterToVmFolder\0"
                                         "datacenterToHostFolder\0"
                                         "computeResourceToHost\0"
                                         "computeResourceToResourcePool\0"
                                         "hostSystemToVm\0"
                                         "resourcePoolToVm\0") < 0) {
        goto failure;
    }

    /* Traversal through datastore branch */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "datacenterToDatastore",
                                         "Datacenter", "datastore",
                                         NULL) < 0) {
        goto failure;
    }

    /* Traversal through vmFolder branch */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "datacenterToVmFolder",
                                         "Datacenter", "vmFolder",
                                         "visitFolders\0") < 0) {
        goto failure;
    }

    /* Traversal through hostFolder branch  */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "datacenterToHostFolder",
                                         "Datacenter", "hostFolder",
                                         "visitFolders\0") < 0) {
        goto failure;
    }

    /* Traversal through host branch  */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "computeResourceToHost",
                                         "ComputeResource", "host",
                                         NULL) < 0) {
        goto failure;
    }

    /* Traversal through resourcePool branch */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "computeResourceToResourcePool",
                                         "ComputeResource", "resourcePool",
                                         "resourcePoolToResourcePool\0"
                                         "resourcePoolToVm\0") < 0) {
        goto failure;
    }

    /* Recurse through all resource pools */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "resourcePoolToResourcePool",
                                         "ResourcePool", "resourcePool",
                                         "resourcePoolToResourcePool\0"
                                         "resourcePoolToVm\0") < 0) {
        goto failure;
    }

    /* Recurse through all hosts */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "hostSystemToVm",
                                         "HostSystem", "vm",
                                         "visitFolders\0") < 0) {
        goto failure;
    }

    /* Recurse through all resource pools */
    if (esxVI_BuildFullTraversalSpecItem(fullTraversalSpecList,
                                         "resourcePoolToVm",
                                         "ResourcePool", "vm", NULL) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_SelectionSpec_Free(fullTraversalSpecList);

    return -1;
}



/*
 * Can't use the SessionIsActive() function here, because at least
 * 'ESX Server 3.5.0 build-64607' returns an 'method not implemented' fault if
 * you try to call it. Query the session manager for the current session of
 * this connection instead and re-login if there is no current session for this
 * connection.
 *
 * Update: 'ESX 4.0.0 build-171294' doesn't implement this method.
 */
#define ESX_VI_USE_SESSION_IS_ACTIVE 0

int
esxVI_EnsureSession(esxVI_Context *ctx)
{
#if ESX_VI_USE_SESSION_IS_ACTIVE
    esxVI_Boolean active = esxVI_Boolean_Undefined;
#else
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *sessionManager = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_UserSession *currentSession = NULL;
#endif

    if (ctx->session == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call"));
        return -1;
    }

#if ESX_VI_USE_SESSION_IS_ACTIVE
    if (esxVI_SessionIsActive(ctx, ctx->session->key, ctx->session->userName,
                              &active) < 0) {
        return -1;
    }

    if (active != esxVI_Boolean_True) {
        esxVI_UserSession_Free(&ctx->session);

        if (esxVI_Login(ctx, ctx->username, ctx->password, NULL,
                        &ctx->session) < 0) {
            return -1;
        }
    }

    return 0;
#else
    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "currentSession") < 0 ||
        esxVI_LookupObjectContentByType(ctx, ctx->service->sessionManager,
                                        "SessionManager", propertyNameList,
                                        esxVI_Boolean_False,
                                        &sessionManager) < 0) {
        goto failure;
    }

    for (dynamicProperty = sessionManager->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "currentSession")) {
            if (esxVI_UserSession_CastFromAnyType(dynamicProperty->val,
                                                  &currentSession) < 0) {
                goto failure;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (currentSession == NULL) {
        esxVI_UserSession_Free(&ctx->session);

        if (esxVI_Login(ctx, ctx->username, ctx->password, NULL,
                        &ctx->session) < 0) {
            goto failure;
        }
    } else if (STRNEQ(ctx->session->key, currentSession->key)) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Key of the current session differs from the key at "
                       "last login"));
        goto failure;
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&sessionManager);
    esxVI_UserSession_Free(&currentSession);

    return result;

  failure:
    result = -1;

    goto cleanup;
#endif
}



int
esxVI_LookupObjectContentByType(esxVI_Context *ctx,
                                esxVI_ManagedObjectReference *root,
                                const char *type,
                                esxVI_String *propertyNameList,
                                esxVI_Boolean recurse,
                                esxVI_ObjectContent **objectContentList)
{
    int result = 0;
    esxVI_ObjectSpec *objectSpec = NULL;
    esxVI_PropertySpec *propertySpec = NULL;
    esxVI_PropertyFilterSpec *propertyFilterSpec = NULL;

    if (ctx->fullTraversalSpecList == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call"));
        return -1;
    }

    if (esxVI_ObjectSpec_Alloc(&objectSpec) < 0) {
        goto failure;
    }

    objectSpec->obj = root;
    objectSpec->skip = esxVI_Boolean_False;

    if (recurse == esxVI_Boolean_True) {
        objectSpec->selectSet = ctx->fullTraversalSpecList;
    }

    if (esxVI_PropertySpec_Alloc(&propertySpec) < 0) {
        goto failure;
    }

    propertySpec->type = (char *)type;
    propertySpec->pathSet = propertyNameList;

    if (esxVI_PropertyFilterSpec_Alloc(&propertyFilterSpec) < 0 ||
        esxVI_PropertySpec_AppendToList(&propertyFilterSpec->propSet,
                                        propertySpec) < 0 ||
        esxVI_ObjectSpec_AppendToList(&propertyFilterSpec->objectSet,
                                      objectSpec) < 0) {
        goto failure;
    }

    result = esxVI_RetrieveProperties(ctx, propertyFilterSpec,
                                      objectContentList);

  cleanup:
    /*
     * Remove values given by the caller from the data structures to prevent
     * them from being freed by the call to esxVI_PropertyFilterSpec_Free().
     */
    if (objectSpec != NULL) {
        objectSpec->obj = NULL;
        objectSpec->selectSet = NULL;
    }

    if (propertySpec != NULL) {
        propertySpec->type = NULL;
        propertySpec->pathSet = NULL;
    }

    esxVI_PropertyFilterSpec_Free(&propertyFilterSpec);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_GetManagedEntityStatus(esxVI_ObjectContent *objectContent,
                             const char *propertyName,
                             esxVI_ManagedEntityStatus *managedEntityStatus)
{
    esxVI_DynamicProperty *dynamicProperty;

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            return esxVI_ManagedEntityStatus_CastFromAnyType
                     (dynamicProperty->val, managedEntityStatus);
        }
    }

    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                 _("Missing '%s' property while looking for "
                   "ManagedEntityStatus"), propertyName);

    return -1;
}



int
esxVI_GetVirtualMachinePowerState(esxVI_ObjectContent *virtualMachine,
                                  esxVI_VirtualMachinePowerState *powerState)
{
    esxVI_DynamicProperty *dynamicProperty;

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.powerState")) {
            return esxVI_VirtualMachinePowerState_CastFromAnyType
                     (dynamicProperty->val, powerState);
        }
    }

    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Missing 'runtime.powerState' property"));

    return -1;
}



int
esxVI_GetVirtualMachineQuestionInfo
  (esxVI_ObjectContent *virtualMachine,
   esxVI_VirtualMachineQuestionInfo **questionInfo)
{
    esxVI_DynamicProperty *dynamicProperty;

    if (questionInfo == NULL || *questionInfo != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.question")) {
            if (esxVI_VirtualMachineQuestionInfo_CastFromAnyType
                  (dynamicProperty->val, questionInfo) < 0) {
                return -1;
            }
        }
    }

    return 0;
}



int
esxVI_LookupNumberOfDomainsByPowerState(esxVI_Context *ctx,
                                        esxVI_VirtualMachinePowerState powerState,
                                        esxVI_Boolean inverse)
{
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_VirtualMachinePowerState powerState_;
    int numberOfDomains = 0;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupObjectContentByType(ctx, ctx->vmFolder, "VirtualMachine",
                                        propertyNameList, esxVI_Boolean_True,
                                        &virtualMachineList) < 0) {
        goto failure;
    }

    for (virtualMachine = virtualMachineList; virtualMachine != NULL;
         virtualMachine = virtualMachine->_next) {
        for (dynamicProperty = virtualMachine->propSet;
             dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "runtime.powerState")) {
                if (esxVI_VirtualMachinePowerState_CastFromAnyType
                      (dynamicProperty->val, &powerState_) < 0) {
                    goto failure;
                }

                if ((inverse != esxVI_Boolean_True &&
                     powerState_ == powerState) ||
                    (inverse == esxVI_Boolean_True &&
                     powerState_ != powerState)) {
                    numberOfDomains++;
                }
            } else {
                VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
            }
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);

    return numberOfDomains;

  failure:
    numberOfDomains = -1;

    goto cleanup;
}



int
esxVI_GetVirtualMachineIdentity(esxVI_ObjectContent *virtualMachine,
                                int *id, char **name, unsigned char *uuid)
{
    const char *uuid_string = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ManagedEntityStatus configStatus = esxVI_ManagedEntityStatus_Undefined;

    if (STRNEQ(virtualMachine->obj->type, "VirtualMachine")) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("ObjectContent does not reference a virtual machine"));
        return -1;
    }

    if (id != NULL) {
        if (esxUtil_ParseVirtualMachineIDString
              (virtualMachine->obj->value, id) < 0 || *id <= 0) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Could not parse positive integer from '%s'"),
                         virtualMachine->obj->value);
            goto failure;
        }
    }

    if (name != NULL) {
        if (*name != NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
            goto failure;
        }

        for (dynamicProperty = virtualMachine->propSet;
             dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "name")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto failure;
                }

                *name = strdup(dynamicProperty->val->string);

                if (*name == NULL) {
                    virReportOOMError();
                    goto failure;
                }

                break;
            }
        }

        if (*name == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Could not get name of virtual machine"));
            goto failure;
        }
    }

    if (uuid != NULL) {
        if (esxVI_GetManagedEntityStatus(virtualMachine, "configStatus",
                                         &configStatus) < 0) {
            goto failure;
        }

        if (configStatus == esxVI_ManagedEntityStatus_Green) {
            for (dynamicProperty = virtualMachine->propSet;
                 dynamicProperty != NULL;
                 dynamicProperty = dynamicProperty->_next) {
                if (STREQ(dynamicProperty->name, "config.uuid")) {
                    if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                                 esxVI_Type_String) < 0) {
                        goto failure;
                    }

                    uuid_string = dynamicProperty->val->string;
                    break;
                }
            }

            if (uuid_string == NULL) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Could not get UUID of virtual machine"));
                goto failure;
            }

            if (virUUIDParse(uuid_string, uuid) < 0) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Could not parse UUID from string '%s'"),
                             uuid_string);
                goto failure;
            }
        } else {
            memset(uuid, 0, VIR_UUID_BUFLEN);

            VIR_WARN0("Cannot access UUID, because 'configStatus' property "
                      "indicates a config problem");
        }
    }

    return 0;

  failure:
    if (name != NULL) {
        VIR_FREE(*name);
    }

    return -1;
}



int
esxVI_GetNumberOfSnapshotTrees
  (esxVI_VirtualMachineSnapshotTree *snapshotTreeList)
{
    int count = 0;
    esxVI_VirtualMachineSnapshotTree *snapshotTree;

    for (snapshotTree = snapshotTreeList; snapshotTree != NULL;
         snapshotTree = snapshotTree->_next) {
        count += 1 + esxVI_GetNumberOfSnapshotTrees
                       (snapshotTree->childSnapshotList);
    }

    return count;
}



int
esxVI_GetSnapshotTreeNames(esxVI_VirtualMachineSnapshotTree *snapshotTreeList,
                           char **names, int nameslen)
{
    int count = 0;
    int result;
    int i;
    esxVI_VirtualMachineSnapshotTree *snapshotTree;

    for (snapshotTree = snapshotTreeList;
         snapshotTree != NULL && count < nameslen;
         snapshotTree = snapshotTree->_next) {
        names[count] = strdup(snapshotTree->name);

        if (names[count] == NULL) {
            virReportOOMError();
            goto failure;
        }

        count++;

        if (count >= nameslen) {
            break;
        }

        result = esxVI_GetSnapshotTreeNames(snapshotTree->childSnapshotList,
                                            names + count, nameslen - count);

        if (result < 0) {
            goto failure;
        }

        count += result;
    }

    return count;

  failure:
    for (i = 0; i < count; ++i) {
        VIR_FREE(names[i]);
    }

    return -1;
}



int
esxVI_GetSnapshotTreeByName
  (esxVI_VirtualMachineSnapshotTree *snapshotTreeList, const char *name,
   esxVI_VirtualMachineSnapshotTree **snapshotTree,
   esxVI_VirtualMachineSnapshotTree **snapshotTreeParent,
   esxVI_Occurrence occurrence)
{
    esxVI_VirtualMachineSnapshotTree *candidate;

    if (snapshotTree == NULL || *snapshotTree != NULL ||
        snapshotTreeParent == NULL || *snapshotTreeParent != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (candidate = snapshotTreeList; candidate != NULL;
         candidate = candidate->_next) {
        if (STREQ(candidate->name, name)) {
            *snapshotTree = candidate;
            *snapshotTreeParent = NULL;
            return 1;
        }

        if (esxVI_GetSnapshotTreeByName(candidate->childSnapshotList, name,
                                        snapshotTree, snapshotTreeParent,
                                        occurrence) > 0) {
            if (*snapshotTreeParent == NULL) {
                *snapshotTreeParent = candidate;
            }

            return 1;
        }
    }

    if (occurrence == esxVI_Occurrence_OptionalItem) {
        return 0;
    } else {
        ESX_VI_ERROR(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                     _("Could not find snapshot with name '%s'"), name);

        return -1;
    }
}



int
esxVI_GetSnapshotTreeBySnapshot
  (esxVI_VirtualMachineSnapshotTree *snapshotTreeList,
   esxVI_ManagedObjectReference *snapshot,
   esxVI_VirtualMachineSnapshotTree **snapshotTree)
{
    esxVI_VirtualMachineSnapshotTree *candidate;

    if (snapshotTree == NULL || *snapshotTree != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (candidate = snapshotTreeList; candidate != NULL;
         candidate = candidate->_next) {
        if (STREQ(candidate->snapshot->value, snapshot->value)) {
            *snapshotTree = candidate;
            return 0;
        }

        if (esxVI_GetSnapshotTreeBySnapshot(candidate->childSnapshotList,
                                            snapshot, snapshotTree) >= 0) {
            return 0;
        }
    }

    ESX_VI_ERROR(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                 _("Could not find domain snapshot with internal name '%s'"),
                 snapshot->value);

    return -1;
}



int
esxVI_LookupResourcePoolByHostSystem
  (esxVI_Context *ctx, esxVI_ObjectContent *hostSystem,
   esxVI_ManagedObjectReference **resourcePool)
{
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;
    esxVI_ObjectContent *computeResource = NULL;

    if (resourcePool == NULL || *resourcePool != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "parent")) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, &managedObjectReference) < 0) {
                goto failure;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (managedObjectReference == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve compute resource of host system"));
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "resourcePool") < 0 ||
        esxVI_LookupObjectContentByType(ctx, managedObjectReference,
                                        "ComputeResource", propertyNameList,
                                        esxVI_Boolean_False,
                                        &computeResource) < 0) {
        goto failure;
    }

    if (computeResource == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve compute resource of host system"));
        goto failure;
    }

    for (dynamicProperty = computeResource->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "resourcePool")) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, resourcePool) < 0) {
                goto failure;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if ((*resourcePool) == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve resource pool of compute resource"));
        goto failure;
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&managedObjectReference);
    esxVI_ObjectContent_Free(&computeResource);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupHostSystemByIp(esxVI_Context *ctx, const char *ipAddress,
                           esxVI_String *propertyNameList,
                           esxVI_ObjectContent **hostSystem)
{
    int result = 0;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;

    if (hostSystem == NULL || *hostSystem != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_FindByIp(ctx, ctx->datacenter, ipAddress, esxVI_Boolean_False,
                       &managedObjectReference) < 0) {
        goto failure;
    }

    if (managedObjectReference == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not find host system with IP address '%s'"),
                     ipAddress);
        goto failure;
    }

    if (esxVI_LookupObjectContentByType(ctx, managedObjectReference,
                                        "HostSystem", propertyNameList,
                                        esxVI_Boolean_False, hostSystem) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_ManagedObjectReference_Free(&managedObjectReference);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupVirtualMachineByUuid(esxVI_Context *ctx, const unsigned char *uuid,
                                 esxVI_String *propertyNameList,
                                 esxVI_ObjectContent **virtualMachine,
                                 esxVI_Occurrence occurrence)
{
    int result = 0;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (virtualMachine == NULL || *virtualMachine != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virUUIDFormat(uuid, uuid_string);

    if (esxVI_FindByUuid(ctx, ctx->datacenter, uuid_string, esxVI_Boolean_True,
                         &managedObjectReference) < 0) {
        goto failure;
    }

    if (managedObjectReference == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            return 0;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_DOMAIN,
                         _("Could not find domain with UUID '%s'"),
                         uuid_string);
            goto failure;
        }
    }

    if (esxVI_LookupObjectContentByType(ctx, managedObjectReference,
                                        "VirtualMachine", propertyNameList,
                                        esxVI_Boolean_False,
                                        virtualMachine) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_ManagedObjectReference_Free(&managedObjectReference);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupVirtualMachineByName(esxVI_Context *ctx, const char *name,
                                 esxVI_String *propertyNameList,
                                 esxVI_ObjectContent **virtualMachine,
                                 esxVI_Occurrence occurrence)
{
    int result = 0;
    esxVI_String *completePropertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *candidate = NULL;
    char *name_candidate = NULL;

    if (virtualMachine == NULL || *virtualMachine != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_DeepCopyList(&completePropertyNameList,
                                  propertyNameList) < 0 ||
        esxVI_String_AppendValueToList(&completePropertyNameList, "name") < 0 ||
        esxVI_LookupObjectContentByType(ctx, ctx->vmFolder, "VirtualMachine",
                                        completePropertyNameList,
                                        esxVI_Boolean_True,
                                        &virtualMachineList) < 0) {
        goto failure;
    }

    for (candidate = virtualMachineList; candidate != NULL;
         candidate = candidate->_next) {
        VIR_FREE(name_candidate);

        if (esxVI_GetVirtualMachineIdentity(candidate, NULL, &name_candidate,
                                            NULL) < 0) {
            goto failure;
        }

        if (STRNEQ(name, name_candidate)) {
            continue;
        }

        if (esxVI_ObjectContent_DeepCopy(virtualMachine, candidate) < 0) {
            goto failure;
        }

        break;
    }

    if (*virtualMachine == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            return 0;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_DOMAIN,
                         _("Could not find domain with name '%s'"), name);
            goto failure;
        }
    }

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);
    VIR_FREE(name_candidate);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupVirtualMachineByUuidAndPrepareForTask
  (esxVI_Context *ctx, const unsigned char *uuid,
   esxVI_String *propertyNameList, esxVI_ObjectContent **virtualMachine,
   esxVI_Boolean autoAnswer)
{
    int result = 0;
    esxVI_String *completePropertyNameList = NULL;
    esxVI_VirtualMachineQuestionInfo *questionInfo = NULL;
    esxVI_TaskInfo *pendingTaskInfoList = NULL;

    if (esxVI_String_DeepCopyList(&completePropertyNameList,
                                  propertyNameList) < 0 ||
        esxVI_String_AppendValueListToList(&completePropertyNameList,
                                           "runtime.question\0"
                                           "recentTask\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, uuid, completePropertyNameList,
                                         virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachineQuestionInfo(*virtualMachine,
                                            &questionInfo) < 0 ||
        esxVI_LookupPendingTaskInfoListByVirtualMachine
           (ctx, *virtualMachine, &pendingTaskInfoList) < 0) {
        goto failure;
    }

    if (questionInfo != NULL &&
        esxVI_HandleVirtualMachineQuestion(ctx, (*virtualMachine)->obj,
                                           questionInfo, autoAnswer) < 0) {
        goto failure;
    }

    if (pendingTaskInfoList != NULL) {
        ESX_VI_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Other tasks are pending for this domain"));
        goto failure;
    }

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_VirtualMachineQuestionInfo_Free(&questionInfo);
    esxVI_TaskInfo_Free(&pendingTaskInfoList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupDatastoreByName(esxVI_Context *ctx, const char *name,
                            esxVI_String *propertyNameList,
                            esxVI_ObjectContent **datastore,
                            esxVI_Occurrence occurrence)
{
    int result = 0;
    esxVI_String *completePropertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *candidate = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;
    size_t offset = strlen("/vmfs/volumes/");
    int numInaccessibleDatastores = 0;

    if (datastore == NULL || *datastore != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /* Get all datastores */
    if (esxVI_String_DeepCopyList(&completePropertyNameList,
                                  propertyNameList) < 0 ||
        esxVI_String_AppendValueListToList(&completePropertyNameList,
                                           "summary.accessible\0"
                                           "summary.name\0"
                                           "summary.url\0") < 0) {
        goto failure;
    }

    if (esxVI_LookupObjectContentByType(ctx, ctx->datacenter, "Datastore",
                                        completePropertyNameList,
                                        esxVI_Boolean_True,
                                        &datastoreList) < 0) {
        goto failure;
    }

    if (datastoreList == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            goto cleanup;
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("No datastores available"));
            goto failure;
        }
    }

    /* Search for a matching datastore */
    for (candidate = datastoreList; candidate != NULL;
         candidate = candidate->_next) {
        accessible = esxVI_Boolean_Undefined;

        for (dynamicProperty = candidate->propSet; dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.accessible")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_Boolean) < 0) {
                    goto failure;
                }

                accessible = dynamicProperty->val->boolean;
                break;
            }
        }

        if (accessible == esxVI_Boolean_Undefined) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Got incomplete response while querying for the "
                           "datastore 'summary.accessible' property"));
            goto failure;
        }

        if (accessible == esxVI_Boolean_False) {
            ++numInaccessibleDatastores;
        }

        for (dynamicProperty = candidate->propSet; dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.accessible")) {
                /* Ignore it */
            } else if (STREQ(dynamicProperty->name, "summary.name")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto failure;
                }

                if (STREQ(dynamicProperty->val->string, name)) {
                    if (esxVI_ObjectContent_DeepCopy(datastore,
                                                     candidate) < 0) {
                        goto failure;
                    }

                    /* Found datastore with matching name */
                    goto cleanup;
                }
            } else if (STREQ(dynamicProperty->name, "summary.url")) {
                if (accessible == esxVI_Boolean_False) {
                    /*
                     * The 'summary.url' property of an inaccessible datastore
                     * is invalid and cannot be used to identify the datastore.
                     */
                    continue;
                }

                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto failure;
                }

                if (! STRPREFIX(dynamicProperty->val->string,
                                "/vmfs/volumes/")) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Datastore URL '%s' has unexpected prefix, "
                                   "expecting '/vmfs/volumes/' prefix"),
                                 dynamicProperty->val->string);
                    goto failure;
                }

                if (STREQ(dynamicProperty->val->string + offset, name)) {
                    if (esxVI_ObjectContent_DeepCopy(datastore,
                                                     candidate) < 0) {
                        goto failure;
                    }

                    /* Found datastore with matching URL suffix */
                    goto cleanup;
                }
            } else {
                VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
            }
        }
    }

    if (occurrence != esxVI_Occurrence_OptionalItem) {
        if (numInaccessibleDatastores > 0) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Could not find datastore '%s', maybe it's "
                           "inaccessible"), name);
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Could not find datastore '%s'"), name);
        }

        goto failure;
    }

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int esxVI_LookupTaskInfoByTask(esxVI_Context *ctx,
                               esxVI_ManagedObjectReference *task,
                               esxVI_TaskInfo **taskInfo)
{
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *objectContent = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (taskInfo == NULL || *taskInfo != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "info") < 0 ||
        esxVI_LookupObjectContentByType(ctx, task, "Task", propertyNameList,
                                        esxVI_Boolean_False,
                                        &objectContent) < 0) {
        goto failure;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "info")) {
            if (esxVI_TaskInfo_CastFromAnyType(dynamicProperty->val,
                                               taskInfo) < 0) {
                goto failure;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&objectContent);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupPendingTaskInfoListByVirtualMachine
  (esxVI_Context *ctx, esxVI_ObjectContent *virtualMachine,
   esxVI_TaskInfo **pendingTaskInfoList)
{
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ManagedObjectReference *recentTaskList = NULL;
    esxVI_ManagedObjectReference *recentTask = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_TaskInfo *taskInfo = NULL;

    if (pendingTaskInfoList == NULL || *pendingTaskInfoList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /* Get list of recent tasks */
    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "recentTask")) {
            if (esxVI_ManagedObjectReference_CastListFromAnyType
                  (dynamicProperty->val, &recentTaskList) < 0) {
                goto failure;
            }

            break;
        }
    }

    /* Lookup task info for each task */
    for (recentTask = recentTaskList; recentTask != NULL;
         recentTask = recentTask->_next) {
        if (esxVI_LookupTaskInfoByTask(ctx, recentTask, &taskInfo) < 0) {
            goto failure;
        }

        if (taskInfo->state == esxVI_TaskInfoState_Queued ||
            taskInfo->state == esxVI_TaskInfoState_Running) {
            if (esxVI_TaskInfo_AppendToList(pendingTaskInfoList,
                                            taskInfo) < 0) {
                goto failure;
            }

            taskInfo = NULL;
        } else {
            esxVI_TaskInfo_Free(&taskInfo);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&recentTaskList);
    esxVI_TaskInfo_Free(&taskInfo);

    return result;

  failure:
    esxVI_TaskInfo_Free(pendingTaskInfoList);

    result = -1;

    goto cleanup;
}



int
esxVI_LookupAndHandleVirtualMachineQuestion(esxVI_Context *ctx,
                                            const unsigned char *uuid,
                                            esxVI_Boolean autoAnswer)
{
    int result = 0;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachineQuestionInfo *questionInfo = NULL;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.question") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, uuid, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachineQuestionInfo(virtualMachine,
                                            &questionInfo) < 0) {
        goto failure;
    }

    if (questionInfo != NULL &&
        esxVI_HandleVirtualMachineQuestion(ctx, virtualMachine->obj,
                                           questionInfo, autoAnswer) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_VirtualMachineQuestionInfo_Free(&questionInfo);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_LookupRootSnapshotTreeList
  (esxVI_Context *ctx, const unsigned char *virtualMachineUuid,
   esxVI_VirtualMachineSnapshotTree **rootSnapshotTreeList)
{
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (rootSnapshotTreeList == NULL || *rootSnapshotTreeList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "snapshot.rootSnapshotList") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, virtualMachineUuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "snapshot.rootSnapshotList")) {
            if (esxVI_VirtualMachineSnapshotTree_CastListFromAnyType
                  (dynamicProperty->val, rootSnapshotTreeList) < 0) {
                goto failure;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;

  failure:
    esxVI_VirtualMachineSnapshotTree_Free(rootSnapshotTreeList);

    result = -1;

    goto cleanup;
}



int
esxVI_LookupCurrentSnapshotTree
  (esxVI_Context *ctx, const unsigned char *virtualMachineUuid,
   esxVI_VirtualMachineSnapshotTree **currentSnapshotTree,
   esxVI_Occurrence occurrence)
{
    int result = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ManagedObjectReference *currentSnapshot = NULL;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;

    if (currentSnapshotTree == NULL || *currentSnapshotTree != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "snapshot.currentSnapshot\0"
                                           "snapshot.rootSnapshotList\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, virtualMachineUuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "snapshot.currentSnapshot")) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, &currentSnapshot) < 0) {
                goto failure;
            }
        } else if (STREQ(dynamicProperty->name, "snapshot.rootSnapshotList")) {
            if (esxVI_VirtualMachineSnapshotTree_CastListFromAnyType
                  (dynamicProperty->val, &rootSnapshotTreeList) < 0) {
                goto failure;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (currentSnapshot == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            return 0;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                         _("Domain has no current snapshot"));
            goto failure;
        }
    }

    if (rootSnapshotTreeList == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not lookup root snapshot list"));
        goto failure;
    }

    if (esxVI_GetSnapshotTreeBySnapshot(rootSnapshotTreeList, currentSnapshot,
                                        &snapshotTree) < 0 ||
        esxVI_VirtualMachineSnapshotTree_DeepCopy(currentSnapshotTree,
                                                  snapshotTree) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_ManagedObjectReference_Free(&currentSnapshot);
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_HandleVirtualMachineQuestion
  (esxVI_Context *ctx, esxVI_ManagedObjectReference *virtualMachine,
   esxVI_VirtualMachineQuestionInfo *questionInfo,
   esxVI_Boolean autoAnswer)
{
    int result = 0;
    esxVI_ElementDescription *elementDescription = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    esxVI_ElementDescription *answerChoice = NULL;
    int answerIndex = 0;
    char *possibleAnswers = NULL;

    if (questionInfo->choice->choiceInfo != NULL) {
        for (elementDescription = questionInfo->choice->choiceInfo;
             elementDescription != NULL;
             elementDescription = elementDescription->_next) {
            virBufferVSprintf(&buffer, "'%s'", elementDescription->label);

            if (elementDescription->_next != NULL) {
                virBufferAddLit(&buffer, ", ");
            }

            if (answerChoice == NULL &&
                questionInfo->choice->defaultIndex != NULL &&
                questionInfo->choice->defaultIndex->value == answerIndex) {
                answerChoice = elementDescription;
            }

            ++answerIndex;
        }

        if (virBufferError(&buffer)) {
            virReportOOMError();
            goto failure;
        }

        possibleAnswers = virBufferContentAndReset(&buffer);
    }

    if (autoAnswer == esxVI_Boolean_True) {
        if (possibleAnswers == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Pending question blocks virtual machine execution, "
                           "question is '%s', no possible answers"),
                         questionInfo->text);
            goto failure;
        } else if (answerChoice == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Pending question blocks virtual machine execution, "
                           "question is '%s', possible answers are %s, but no "
                           "default answer is specified"), questionInfo->text,
                         possibleAnswers);
            goto failure;
        }

        VIR_INFO("Pending question blocks virtual machine execution, "
                 "question is '%s', possible answers are %s, responding "
                 "with default answer '%s'", questionInfo->text,
                 possibleAnswers, answerChoice->label);

        if (esxVI_AnswerVM(ctx, virtualMachine, questionInfo->id,
                           answerChoice->key) < 0) {
            goto failure;
        }
    } else {
        if (possibleAnswers != NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Pending question blocks virtual machine execution, "
                           "question is '%s', possible answers are %s"),
                         questionInfo->text, possibleAnswers);
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Pending question blocks virtual machine execution, "
                           "question is '%s', no possible answers"),
                         questionInfo->text);
        }

        goto failure;
    }

  cleanup:
    VIR_FREE(possibleAnswers);

    return result;

  failure:
    virBufferFreeAndReset(&buffer);

    result = -1;

    goto cleanup;
}



int
esxVI_WaitForTaskCompletion(esxVI_Context *ctx,
                            esxVI_ManagedObjectReference *task,
                            const unsigned char *virtualMachineUuid,
                            esxVI_Boolean autoAnswer,
                            esxVI_TaskInfoState *finalState)
{
    int result = 0;
    esxVI_ObjectSpec *objectSpec = NULL;
    esxVI_PropertySpec *propertySpec = NULL;
    esxVI_PropertyFilterSpec *propertyFilterSpec = NULL;
    esxVI_ManagedObjectReference *propertyFilter = NULL;
    char *version = NULL;
    esxVI_UpdateSet *updateSet = NULL;
    esxVI_PropertyFilterUpdate *propertyFilterUpdate = NULL;
    esxVI_ObjectUpdate *objectUpdate = NULL;
    esxVI_PropertyChange *propertyChange = NULL;
    esxVI_AnyType *propertyValue = NULL;
    esxVI_TaskInfoState state = esxVI_TaskInfoState_Undefined;
    esxVI_TaskInfo *taskInfo = NULL;

    version = strdup("");

    if (version == NULL) {
        virReportOOMError();
        goto failure;
    }

    if (esxVI_ObjectSpec_Alloc(&objectSpec) < 0) {
        goto failure;
    }

    objectSpec->obj = task;
    objectSpec->skip = esxVI_Boolean_False;

    if (esxVI_PropertySpec_Alloc(&propertySpec) < 0) {
        goto failure;
    }

    propertySpec->type = task->type;

    if (esxVI_String_AppendValueToList(&propertySpec->pathSet,
                                       "info.state") < 0 ||
        esxVI_PropertyFilterSpec_Alloc(&propertyFilterSpec) < 0 ||
        esxVI_PropertySpec_AppendToList(&propertyFilterSpec->propSet,
                                        propertySpec) < 0 ||
        esxVI_ObjectSpec_AppendToList(&propertyFilterSpec->objectSet,
                                      objectSpec) < 0 ||
        esxVI_CreateFilter(ctx, propertyFilterSpec, esxVI_Boolean_True,
                           &propertyFilter) < 0) {
        goto failure;
    }

    while (state != esxVI_TaskInfoState_Success &&
           state != esxVI_TaskInfoState_Error) {
        esxVI_UpdateSet_Free(&updateSet);

        if (virtualMachineUuid != NULL) {
            if (esxVI_LookupAndHandleVirtualMachineQuestion
                  (ctx, virtualMachineUuid, autoAnswer) < 0) {
                /*
                 * FIXME: Disable error reporting here, so possible errors from
                 *        esxVI_LookupTaskInfoByTask() and esxVI_CancelTask()
                 *        don't overwrite the actual error
                 */
                if (esxVI_LookupTaskInfoByTask(ctx, task, &taskInfo)) {
                    goto failure;
                }

                if (taskInfo->cancelable == esxVI_Boolean_True) {
                    if (esxVI_CancelTask(ctx, task) < 0) {
                        VIR_ERROR0("Cancelable task is blocked by an "
                                   "unanswered question but cancelation "
                                   "failed");
                    }
                } else {
                    VIR_ERROR0("Non-cancelable task is blocked by an "
                               "unanswered question");
                }

                /* FIXME: Enable error reporting here again */

                goto failure;
            }
        }

        if (esxVI_WaitForUpdates(ctx, version, &updateSet) < 0) {
            goto failure;
        }

        VIR_FREE(version);
        version = strdup(updateSet->version);

        if (version == NULL) {
            virReportOOMError();
            goto failure;
        }

        if (updateSet->filterSet == NULL) {
            continue;
        }

        for (propertyFilterUpdate = updateSet->filterSet;
             propertyFilterUpdate != NULL;
             propertyFilterUpdate = propertyFilterUpdate->_next) {
            for (objectUpdate = propertyFilterUpdate->objectSet;
                 objectUpdate != NULL; objectUpdate = objectUpdate->_next) {
                for (propertyChange = objectUpdate->changeSet;
                     propertyChange != NULL;
                     propertyChange = propertyChange->_next) {
                    if (STREQ(propertyChange->name, "info.state")) {
                        if (propertyChange->op == esxVI_PropertyChangeOp_Add ||
                            propertyChange->op == esxVI_PropertyChangeOp_Assign) {
                            propertyValue = propertyChange->val;
                        } else {
                            propertyValue = NULL;
                        }
                    }
                }
            }
        }

        if (propertyValue == NULL) {
            continue;
        }

        if (esxVI_TaskInfoState_CastFromAnyType(propertyValue, &state) < 0) {
            goto failure;
        }
    }

    if (esxVI_DestroyPropertyFilter(ctx, propertyFilter) < 0) {
        VIR_DEBUG0("DestroyPropertyFilter failed");
    }

    if (esxVI_TaskInfoState_CastFromAnyType(propertyValue, finalState) < 0) {
        goto failure;
    }

  cleanup:
    /*
     * Remove values given by the caller from the data structures to prevent
     * them from being freed by the call to esxVI_PropertyFilterSpec_Free().
     */
    if (objectSpec != NULL) {
        objectSpec->obj = NULL;
    }

    if (propertySpec != NULL) {
        propertySpec->type = NULL;
    }

    esxVI_PropertyFilterSpec_Free(&propertyFilterSpec);
    esxVI_ManagedObjectReference_Free(&propertyFilter);
    VIR_FREE(version);
    esxVI_UpdateSet_Free(&updateSet);
    esxVI_TaskInfo_Free(&taskInfo);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



int
esxVI_ParseHostCpuIdInfo(esxVI_ParsedHostCpuIdInfo *parsedHostCpuIdInfo,
                         esxVI_HostCpuIdInfo *hostCpuIdInfo)
{
    int expectedLength = 39; /* = strlen("----:----:----:----:----:----:----:----"); */
    char *input[4] = { hostCpuIdInfo->eax, hostCpuIdInfo->ebx,
                       hostCpuIdInfo->ecx, hostCpuIdInfo->edx };
    char *output[4] = { parsedHostCpuIdInfo->eax, parsedHostCpuIdInfo->ebx,
                        parsedHostCpuIdInfo->ecx, parsedHostCpuIdInfo->edx };
    const char *name[4] = { "eax", "ebx", "ecx", "edx" };
    int r, i, o;

    memset(parsedHostCpuIdInfo, 0, sizeof (*parsedHostCpuIdInfo));

    parsedHostCpuIdInfo->level = hostCpuIdInfo->level->value;

    for (r = 0; r < 4; ++r) {
        if (strlen(input[r]) != expectedLength) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("HostCpuIdInfo register '%s' has an unexpected length"),
                         name[r]);
            goto failure;
        }

        /* Strip the ':' and invert the "bit" order from 31..0 to 0..31 */
        for (i = 0, o = 31; i < expectedLength; i += 5, o -= 4) {
            output[r][o] = input[r][i];
            output[r][o - 1] = input[r][i + 1];
            output[r][o - 2] = input[r][i + 2];
            output[r][o - 3] = input[r][i + 3];

            if (i + 4 < expectedLength && input[r][i + 4] != ':') {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("HostCpuIdInfo register '%s' has an unexpected format"),
                             name[r]);
                goto failure;
            }
        }
    }

    return 0;

  failure:
    memset(parsedHostCpuIdInfo, 0, sizeof (*parsedHostCpuIdInfo));

    return -1;
}
