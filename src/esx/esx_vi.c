
/*
 * esx_vi.c: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2009-2011 Matthias Bolte <matthias.bolte@googlemail.com>
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
#include "vmx.h"
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
        esxVI_##_type *item ATTRIBUTE_UNUSED;                                 \
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
 * CURL
 */

/* esxVI_CURL_Alloc */
ESX_VI__TEMPLATE__ALLOC(CURL)

/* esxVI_CURL_Free */
ESX_VI__TEMPLATE__FREE(CURL,
{
    esxVI_SharedCURL *shared = item->shared;

    if (shared != NULL) {
        esxVI_SharedCURL_Remove(shared, item);

        if (shared->count == 0) {
            esxVI_SharedCURL_Free(&shared);
        }
    }

    if (item->handle != NULL) {
        curl_easy_cleanup(item->handle);
    }

    if (item->headers != NULL) {
        curl_slist_free_all(item->headers);
    }

    virMutexDestroy(&item->lock);
})

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
        VIR_DEBUG("unknown");
        break;
    }

    VIR_FREE(buffer);

    return 0;
}
#endif

static int
esxVI_CURL_Perform(esxVI_CURL *curl, const char *url)
{
    CURLcode errorCode;
    long responseCode = 0;
#if LIBCURL_VERSION_NUM >= 0x071202 /* 7.18.2 */
    const char *redirectUrl = NULL;
#endif

    errorCode = curl_easy_perform(curl->handle);

    if (errorCode != CURLE_OK) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("curl_easy_perform() returned an error: %s (%d) : %s"),
                     curl_easy_strerror(errorCode), errorCode, curl->error);
        return -1;
    }

    errorCode = curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE,
                                  &responseCode);

    if (errorCode != CURLE_OK) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned an "
                       "error: %s (%d) : %s"), curl_easy_strerror(errorCode),
                     errorCode, curl->error);
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
        errorCode = curl_easy_getinfo(curl->handle, CURLINFO_REDIRECT_URL,
                                      &redirectUrl);

        if (errorCode != CURLE_OK) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("curl_easy_getinfo(CURLINFO_REDIRECT_URL) returned "
                           "an error: %s (%d) : %s"),
                         curl_easy_strerror(errorCode),
                         errorCode, curl->error);
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
esxVI_CURL_Connect(esxVI_CURL *curl, esxUtil_ParsedUri *parsedUri)
{
    if (curl->handle != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call"));
        return -1;
    }

    curl->handle = curl_easy_init();

    if (curl->handle == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not initialize CURL"));
        return -1;
    }

    curl->headers = curl_slist_append(curl->headers,
                                      "Content-Type: text/xml; charset=UTF-8");

    /*
     * Add an empty expect header to stop CURL from waiting for a response code
     * 100 (Continue) from the server before continuing the POST operation.
     * Waiting for this response would slowdown each communication with the
     * server by approx. 2 sec, because the server doesn't send the expected
     * 100 (Continue) response and the wait times out resulting in wasting
     * approx. 2 sec per POST operation.
     */
    curl->headers = curl_slist_append(curl->headers, "Expect:");

    if (curl->headers == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not build CURL header list"));
        return -1;
    }

    curl_easy_setopt(curl->handle, CURLOPT_USERAGENT, "libvirt-esx");
    curl_easy_setopt(curl->handle, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl->handle, CURLOPT_FOLLOWLOCATION, 0);
    curl_easy_setopt(curl->handle, CURLOPT_SSL_VERIFYPEER,
                     parsedUri->noVerify ? 0 : 1);
    curl_easy_setopt(curl->handle, CURLOPT_SSL_VERIFYHOST,
                     parsedUri->noVerify ? 0 : 2);
    curl_easy_setopt(curl->handle, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl->handle, CURLOPT_HTTPHEADER, curl->headers);
    curl_easy_setopt(curl->handle, CURLOPT_READFUNCTION,
                     esxVI_CURL_ReadString);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEFUNCTION,
                     esxVI_CURL_WriteBuffer);
    curl_easy_setopt(curl->handle, CURLOPT_ERRORBUFFER, curl->error);
#if ESX_VI__CURL__ENABLE_DEBUG_OUTPUT
    curl_easy_setopt(curl->handle, CURLOPT_DEBUGFUNCTION, esxVI_CURL_Debug);
    curl_easy_setopt(curl->handle, CURLOPT_VERBOSE, 1);
#endif

    if (parsedUri->proxy) {
        curl_easy_setopt(curl->handle, CURLOPT_PROXY,
                         parsedUri->proxy_hostname);
        curl_easy_setopt(curl->handle, CURLOPT_PROXYTYPE,
                         parsedUri->proxy_type);
        curl_easy_setopt(curl->handle, CURLOPT_PROXYPORT,
                         parsedUri->proxy_port);
    }

    if (virMutexInit(&curl->lock) < 0) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not initialize CURL mutex"));
        return -1;
    }

    return 0;
}

int
esxVI_CURL_Download(esxVI_CURL *curl, const char *url, char **content)
{
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    int responseCode = 0;

    if (content == NULL || *content != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virMutexLock(&curl->lock);

    curl_easy_setopt(curl->handle, CURLOPT_URL, url);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 0);
    curl_easy_setopt(curl->handle, CURLOPT_HTTPGET, 1);

    responseCode = esxVI_CURL_Perform(curl, url);

    virMutexUnlock(&curl->lock);

    if (responseCode < 0) {
        goto cleanup;
    } else if (responseCode != 200) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("HTTP response code %d for download from '%s'"),
                     responseCode, url);
        goto cleanup;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    *content = virBufferContentAndReset(&buffer);

  cleanup:
    if (*content == NULL) {
        virBufferFreeAndReset(&buffer);
        return -1;
    }

    return 0;
}

int
esxVI_CURL_Upload(esxVI_CURL *curl, const char *url, const char *content)
{
    int responseCode = 0;

    if (content == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virMutexLock(&curl->lock);

    curl_easy_setopt(curl->handle, CURLOPT_URL, url);
    curl_easy_setopt(curl->handle, CURLOPT_READDATA, &content);
    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl->handle, CURLOPT_INFILESIZE, strlen(content));

    responseCode = esxVI_CURL_Perform(curl, url);

    virMutexUnlock(&curl->lock);

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



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * SharedCURL
 */

static void
esxVI_SharedCURL_Lock(CURL *handle ATTRIBUTE_UNUSED, curl_lock_data data,
                      curl_lock_access access_ ATTRIBUTE_UNUSED, void *userptr)
{
    int i;
    esxVI_SharedCURL *shared = userptr;

    switch (data) {
      case CURL_LOCK_DATA_SHARE:
        i = 0;
        break;

      case CURL_LOCK_DATA_COOKIE:
        i = 1;
        break;

      case CURL_LOCK_DATA_DNS:
        i = 2;
        break;

      default:
        VIR_ERROR(_("Trying to lock unknown SharedCURL lock %d"), (int)data);
        return;
    }

    virMutexLock(&shared->locks[i]);
}

static void
esxVI_SharedCURL_Unlock(CURL *handle ATTRIBUTE_UNUSED, curl_lock_data data,
                        void *userptr)
{
    int i;
    esxVI_SharedCURL *shared = userptr;

    switch (data) {
      case CURL_LOCK_DATA_SHARE:
        i = 0;
        break;

      case CURL_LOCK_DATA_COOKIE:
        i = 1;
        break;

      case CURL_LOCK_DATA_DNS:
        i = 2;
        break;

      default:
        VIR_ERROR(_("Trying to unlock unknown SharedCURL lock %d"), (int)data);
        return;
    }

    virMutexUnlock(&shared->locks[i]);
}

/* esxVI_SharedCURL_Alloc */
ESX_VI__TEMPLATE__ALLOC(SharedCURL)

/* esxVI_SharedCURL_Free */
ESX_VI__TEMPLATE__FREE(SharedCURL,
{
    int i;

    if (item->count > 0) {
        /* Better leak than crash */
        VIR_ERROR(_("Trying to free SharedCURL object that is still in use"));
        return;
    }

    if (item->handle != NULL) {
        curl_share_cleanup(item->handle);
    }

    for (i = 0; i < ARRAY_CARDINALITY(item->locks); ++i) {
        virMutexDestroy(&item->locks[i]);
    }
})

int
esxVI_SharedCURL_Add(esxVI_SharedCURL *shared, esxVI_CURL *curl)
{
    int i;

    if (curl->handle == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Cannot share uninitialized CURL handle"));
        return -1;
    }

    if (curl->shared != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Cannot share CURL handle that is already shared"));
        return -1;
    }

    if (shared->handle == NULL) {
        shared->handle = curl_share_init();

        if (shared->handle == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Could not initialize CURL (share)"));
            return -1;
        }

        curl_share_setopt(shared->handle, CURLSHOPT_LOCKFUNC,
                          esxVI_SharedCURL_Lock);
        curl_share_setopt(shared->handle, CURLSHOPT_UNLOCKFUNC,
                          esxVI_SharedCURL_Unlock);
        curl_share_setopt(shared->handle, CURLSHOPT_USERDATA, shared);
        curl_share_setopt(shared->handle, CURLSHOPT_SHARE,
                          CURL_LOCK_DATA_COOKIE);
        curl_share_setopt(shared->handle, CURLSHOPT_SHARE,
                          CURL_LOCK_DATA_DNS);

        for (i = 0; i < ARRAY_CARDINALITY(shared->locks); ++i) {
            if (virMutexInit(&shared->locks[i]) < 0) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Could not initialize a CURL (share) mutex"));
                return -1;
            }
        }
    }

    curl_easy_setopt(curl->handle, CURLOPT_SHARE, shared->handle);

    curl->shared = shared;
    ++shared->count;

    return 0;
}

int
esxVI_SharedCURL_Remove(esxVI_SharedCURL *shared, esxVI_CURL *curl)
{
    if (curl->handle == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Cannot unshare uninitialized CURL handle"));
        return -1;
    }

    if (curl->shared == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Cannot unshare CURL handle that is not shared"));
        return -1;
    }

    if (curl->shared != shared) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("CURL (share) mismatch"));
        return -1;
    }

    curl_easy_setopt(curl->handle, CURLOPT_SHARE, NULL);

    curl->shared = NULL;
    --shared->count;

    return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

/* esxVI_Context_Alloc */
ESX_VI__TEMPLATE__ALLOC(Context)

/* esxVI_Context_Free */
ESX_VI__TEMPLATE__FREE(Context,
{
    if (item->sessionLock != NULL) {
        virMutexDestroy(item->sessionLock);
    }

    esxVI_CURL_Free(&item->curl);
    VIR_FREE(item->url);
    VIR_FREE(item->ipAddress);
    VIR_FREE(item->username);
    VIR_FREE(item->password);
    esxVI_ServiceContent_Free(&item->service);
    esxVI_UserSession_Free(&item->session);
    VIR_FREE(item->sessionLock);
    esxVI_Datacenter_Free(&item->datacenter);
    VIR_FREE(item->datacenterPath);
    esxVI_ComputeResource_Free(&item->computeResource);
    VIR_FREE(item->computeResourcePath);
    esxVI_HostSystem_Free(&item->hostSystem);
    VIR_FREE(item->hostSystemName);
    esxVI_SelectionSpec_Free(&item->selectSet_folderToChildEntity);
    esxVI_SelectionSpec_Free(&item->selectSet_hostSystemToParent);
    esxVI_SelectionSpec_Free(&item->selectSet_hostSystemToVm);
    esxVI_SelectionSpec_Free(&item->selectSet_hostSystemToDatastore);
    esxVI_SelectionSpec_Free(&item->selectSet_computeResourceToHost);
    esxVI_SelectionSpec_Free(&item->selectSet_computeResourceToParentToParent);
})

int
esxVI_Context_Connect(esxVI_Context *ctx, const char *url,
                      const char *ipAddress, const char *username,
                      const char *password, esxUtil_ParsedUri *parsedUri)
{
    if (ctx == NULL || url == NULL || ipAddress == NULL || username == NULL ||
        password == NULL || ctx->url != NULL || ctx->service != NULL ||
        ctx->curl != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_CURL_Alloc(&ctx->curl) < 0 ||
        esxVI_CURL_Connect(ctx->curl, parsedUri) < 0 ||
        esxVI_String_DeepCopyValue(&ctx->url, url) < 0 ||
        esxVI_String_DeepCopyValue(&ctx->ipAddress, ipAddress) < 0 ||
        esxVI_String_DeepCopyValue(&ctx->username, username) < 0 ||
        esxVI_String_DeepCopyValue(&ctx->password, password) < 0) {
        return -1;
    }

    if (VIR_ALLOC(ctx->sessionLock) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virMutexInit(ctx->sessionLock) < 0) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not initialize session mutex"));
        return -1;
    }

    if (esxVI_RetrieveServiceContent(ctx, &ctx->service) < 0) {
        return -1;
    }

    if (STREQ(ctx->service->about->apiType, "HostAgent") ||
        STREQ(ctx->service->about->apiType, "VirtualCenter")) {
        if (STRPREFIX(ctx->service->about->apiVersion, "2.5")) {
            ctx->apiVersion = esxVI_APIVersion_25;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "4.0")) {
            ctx->apiVersion = esxVI_APIVersion_40;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "4.1")) {
            ctx->apiVersion = esxVI_APIVersion_41;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "4.")) {
            ctx->apiVersion = esxVI_APIVersion_4x;

            VIR_WARN("Found untested VI API major/minor version '%s'",
                     ctx->service->about->apiVersion);
        } else if (STRPREFIX(ctx->service->about->apiVersion, "5.0")) {
            ctx->apiVersion = esxVI_APIVersion_50;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "5.")) {
            ctx->apiVersion = esxVI_APIVersion_5x;

            VIR_WARN("Found untested VI API major/minor version '%s'",
                     ctx->service->about->apiVersion);
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Expecting VI API major/minor version '2.5', '4.x' or "
                           "'5.x' but found '%s'"), ctx->service->about->apiVersion);
            return -1;
        }

        if (STREQ(ctx->service->about->productLineId, "gsx")) {
            if (STRPREFIX(ctx->service->about->version, "2.0")) {
                ctx->productVersion = esxVI_ProductVersion_GSX20;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Expecting GSX major/minor version '2.0' but "
                               "found '%s'"), ctx->service->about->version);
                return -1;
            }
        } else if (STREQ(ctx->service->about->productLineId, "esx") ||
                   STREQ(ctx->service->about->productLineId, "embeddedEsx")) {
            if (STRPREFIX(ctx->service->about->version, "3.5")) {
                ctx->productVersion = esxVI_ProductVersion_ESX35;
            } else if (STRPREFIX(ctx->service->about->version, "4.0")) {
                ctx->productVersion = esxVI_ProductVersion_ESX40;
            } else if (STRPREFIX(ctx->service->about->version, "4.1")) {
                ctx->productVersion = esxVI_ProductVersion_ESX41;
            } else if (STRPREFIX(ctx->service->about->version, "4.")) {
                ctx->productVersion = esxVI_ProductVersion_ESX4x;

                VIR_WARN("Found untested ESX major/minor version '%s'",
                         ctx->service->about->version);
            } else if (STRPREFIX(ctx->service->about->version, "5.0")) {
                ctx->productVersion = esxVI_ProductVersion_ESX50;
            } else if (STRPREFIX(ctx->service->about->version, "5.")) {
                ctx->productVersion = esxVI_ProductVersion_ESX5x;

                VIR_WARN("Found untested ESX major/minor version '%s'",
                         ctx->service->about->version);
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Expecting ESX major/minor version '3.5', "
                               "'4.x' or '5.x' but found '%s'"),
                             ctx->service->about->version);
                return -1;
            }
        } else if (STREQ(ctx->service->about->productLineId, "vpx")) {
            if (STRPREFIX(ctx->service->about->version, "2.5")) {
                ctx->productVersion = esxVI_ProductVersion_VPX25;
            } else if (STRPREFIX(ctx->service->about->version, "4.0")) {
                ctx->productVersion = esxVI_ProductVersion_VPX40;
            } else if (STRPREFIX(ctx->service->about->version, "4.1")) {
                ctx->productVersion = esxVI_ProductVersion_VPX41;
            } else if (STRPREFIX(ctx->service->about->version, "4.")) {
                ctx->productVersion = esxVI_ProductVersion_VPX4x;

                VIR_WARN("Found untested VPX major/minor version '%s'",
                         ctx->service->about->version);
            } else if (STRPREFIX(ctx->service->about->version, "5.0")) {
                ctx->productVersion = esxVI_ProductVersion_VPX50;
            } else if (STRPREFIX(ctx->service->about->version, "5.")) {
                ctx->productVersion = esxVI_ProductVersion_VPX5x;

                VIR_WARN("Found untested VPX major/minor version '%s'",
                         ctx->service->about->version);
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Expecting VPX major/minor version '2.5', '4.x' "
                               "or '5.x' but found '%s'"),
                               ctx->service->about->version);
                return -1;
            }
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Expecting product 'gsx' or 'esx' or 'embeddedEsx' "
                           "or 'vpx' but found '%s'"),
                         ctx->service->about->productLineId);
            return -1;
        }
    } else {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Expecting VI API type 'HostAgent' or 'VirtualCenter' "
                       "but found '%s'"), ctx->service->about->apiType);
        return -1;
    }

    if (ctx->productVersion & esxVI_ProductVersion_ESX) {
        /*
         * FIXME: Actually this should be detected by really calling
         * QueryVirtualDiskUuid and checking if a NotImplemented fault is
         * returned. But currently we don't deserialized the details of a
         * possbile fault and therefore we don't know if the fault was a
         * NotImplemented fault or not.
         */
        ctx->hasQueryVirtualDiskUuid = true;
    }

    if (ctx->productVersion & esxVI_ProductVersion_VPX) {
        ctx->hasSessionIsActive = true;
    }

    if (esxVI_Login(ctx, username, password, NULL, &ctx->session) < 0 ||
        esxVI_BuildSelectSetCollection(ctx) < 0) {
        return -1;
    }

    return 0;
}

int
esxVI_Context_LookupManagedObjects(esxVI_Context *ctx)
{
    /* Lookup Datacenter */
    if (esxVI_LookupDatacenter(ctx, NULL, ctx->service->rootFolder, NULL,
                               &ctx->datacenter,
                               esxVI_Occurrence_RequiredItem) < 0) {
        return -1;
    }

    ctx->datacenterPath = strdup(ctx->datacenter->name);

    if (ctx->datacenterPath == NULL) {
        virReportOOMError();
        return -1;
    }

    /* Lookup (Cluster)ComputeResource */
    if (esxVI_LookupComputeResource(ctx, NULL, ctx->datacenter->hostFolder,
                                    NULL, &ctx->computeResource,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        return -1;
    }

    if (ctx->computeResource->resourcePool == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve resource pool"));
        return -1;
    }

    ctx->computeResourcePath = strdup(ctx->computeResource->name);

    if (ctx->computeResourcePath == NULL) {
        virReportOOMError();
        return -1;
    }

    /* Lookup HostSystem */
    if (esxVI_LookupHostSystem(ctx, NULL, ctx->computeResource->_reference,
                               NULL, &ctx->hostSystem,
                               esxVI_Occurrence_RequiredItem) < 0) {
        return -1;
    }

    ctx->hostSystemName = strdup(ctx->hostSystem->name);

    if (ctx->hostSystemName == NULL) {
        virReportOOMError();
        return -1;
    }

    return 0;
}

int
esxVI_Context_LookupManagedObjectsByPath(esxVI_Context *ctx, const char *path)
{
    int result = -1;
    char *tmp = NULL;
    char *saveptr = NULL;
    char *previousItem = NULL;
    char *item = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    esxVI_ManagedObjectReference *root = NULL;
    esxVI_Folder *folder = NULL;

    tmp = strdup(path);

    if (tmp == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    /* Lookup Datacenter */
    item = strtok_r(tmp, "/", &saveptr);

    if (item == NULL) {
        ESX_VI_ERROR(VIR_ERR_INVALID_ARG,
                     _("Path '%s' does not specify a datacenter"), path);
        goto cleanup;
    }

    root = ctx->service->rootFolder;

    while (ctx->datacenter == NULL && item != NULL) {
        esxVI_Folder_Free(&folder);

        /* Try to lookup item as a folder */
        if (esxVI_LookupFolder(ctx, item, root, NULL, &folder,
                               esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (folder != NULL) {
            /* It's a folder, use it as new lookup root */
            if (root != ctx->service->rootFolder) {
                esxVI_ManagedObjectReference_Free(&root);
            }

            root = folder->_reference;
            folder->_reference = NULL;
        } else {
            /* Try to lookup item as a datacenter */
            if (esxVI_LookupDatacenter(ctx, item, root, NULL, &ctx->datacenter,
                                       esxVI_Occurrence_OptionalItem) < 0) {
                goto cleanup;
            }
        }

        /* Build datacenter path */
        if (virBufferUse(&buffer) > 0) {
            virBufferAddChar(&buffer, '/');
        }

        virBufferAdd(&buffer, item, -1);

        previousItem = item;
        item = strtok_r(NULL, "/", &saveptr);
    }

    if (ctx->datacenter == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not find datacenter specified in '%s'"), path);
        goto cleanup;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    ctx->datacenterPath = virBufferContentAndReset(&buffer);

    /* Lookup (Cluster)ComputeResource */
    if (item == NULL) {
        ESX_VI_ERROR(VIR_ERR_INVALID_ARG,
                     _("Path '%s' does not specify a compute resource"), path);
        goto cleanup;
    }

    if (root != ctx->service->rootFolder) {
        esxVI_ManagedObjectReference_Free(&root);
    }

    root = ctx->datacenter->hostFolder;

    while (ctx->computeResource == NULL && item != NULL) {
        esxVI_Folder_Free(&folder);

        /* Try to lookup item as a folder */
        if (esxVI_LookupFolder(ctx, item, root, NULL, &folder,
                               esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (folder != NULL) {
            /* It's a folder, use it as new lookup root */
            if (root != ctx->datacenter->hostFolder) {
                esxVI_ManagedObjectReference_Free(&root);
            }

            root = folder->_reference;
            folder->_reference = NULL;
        } else {
            /* Try to lookup item as a compute resource */
            if (esxVI_LookupComputeResource(ctx, item, root, NULL,
                                            &ctx->computeResource,
                                            esxVI_Occurrence_OptionalItem) < 0) {
                goto cleanup;
            }
        }

        /* Build compute resource path */
        if (virBufferUse(&buffer) > 0) {
            virBufferAddChar(&buffer, '/');
        }

        virBufferAdd(&buffer, item, -1);

        previousItem = item;
        item = strtok_r(NULL, "/", &saveptr);
    }

    if (ctx->computeResource == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not find compute resource specified in '%s'"),
                     path);
        goto cleanup;
    }

    if (ctx->computeResource->resourcePool == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve resource pool"));
        goto cleanup;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    ctx->computeResourcePath = virBufferContentAndReset(&buffer);

    /* Lookup HostSystem */
    if (STREQ(ctx->computeResource->_reference->type,
              "ClusterComputeResource")) {
        if (item == NULL) {
            ESX_VI_ERROR(VIR_ERR_INVALID_ARG,
                         _("Path '%s' does not specify a host system"), path);
            goto cleanup;
        }

        /* The path specified a cluster, it has to specify a host system too */
        previousItem = item;
        item = strtok_r(NULL, "/", &saveptr);
    }

    if (item != NULL) {
        ESX_VI_ERROR(VIR_ERR_INVALID_ARG,
                     _("Path '%s' ends with an excess item"), path);
        goto cleanup;
    }

    ctx->hostSystemName = strdup(previousItem);

    if (ctx->hostSystemName == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    if (esxVI_LookupHostSystem(ctx, ctx->hostSystemName,
                               ctx->computeResource->_reference, NULL,
                               &ctx->hostSystem,
                               esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (ctx->hostSystem == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not find host system specified in '%s'"), path);
        goto cleanup;
    }

    result = 0;

  cleanup:
    if (result < 0) {
        virBufferFreeAndReset(&buffer);
    }

    if (root != ctx->service->rootFolder &&
        (ctx->datacenter == NULL || root != ctx->datacenter->hostFolder)) {
        esxVI_ManagedObjectReference_Free(&root);
    }

    VIR_FREE(tmp);
    esxVI_Folder_Free(&folder);

    return result;
}

int
esxVI_Context_LookupManagedObjectsByHostSystemIp(esxVI_Context *ctx,
                                                 const char *hostSystemIpAddress)
{
    int result = -1;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;

    /* Lookup HostSystem */
    if (esxVI_FindByIp(ctx, NULL, hostSystemIpAddress, esxVI_Boolean_False,
                       &managedObjectReference) < 0 ||
        esxVI_LookupHostSystem(ctx, NULL, managedObjectReference, NULL,
                               &ctx->hostSystem,
                               esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* Lookup (Cluster)ComputeResource */
    if (esxVI_LookupComputeResource(ctx, NULL, ctx->hostSystem->_reference,
                                    NULL, &ctx->computeResource,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (ctx->computeResource->resourcePool == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve resource pool"));
        goto cleanup;
    }

    /* Lookup Datacenter */
    if (esxVI_LookupDatacenter(ctx, NULL, ctx->computeResource->_reference,
                               NULL, &ctx->datacenter,
                               esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_ManagedObjectReference_Free(&managedObjectReference);

    return result;
}

int
esxVI_Context_Execute(esxVI_Context *ctx, const char *methodName,
                      const char *request, esxVI_Response **response,
                      esxVI_Occurrence occurrence)
{
    int result = -1;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    esxVI_Fault *fault = NULL;
    char *xpathExpression = NULL;
    xmlXPathContextPtr xpathContext = NULL;
    xmlNodePtr responseNode = NULL;

    if (request == NULL || response == NULL || *response != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_Response_Alloc(response) < 0) {
        return -1;
    }

    virMutexLock(&ctx->curl->lock);

    curl_easy_setopt(ctx->curl->handle, CURLOPT_URL, ctx->url);
    curl_easy_setopt(ctx->curl->handle, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(ctx->curl->handle, CURLOPT_UPLOAD, 0);
    curl_easy_setopt(ctx->curl->handle, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(ctx->curl->handle, CURLOPT_POSTFIELDSIZE, strlen(request));

    (*response)->responseCode = esxVI_CURL_Perform(ctx->curl, ctx->url);

    virMutexUnlock(&ctx->curl->lock);

    if ((*response)->responseCode < 0) {
        goto cleanup;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    (*response)->content = virBufferContentAndReset(&buffer);

    if ((*response)->responseCode == 500 || (*response)->responseCode == 200) {
        (*response)->document = virXMLParseStringCtxt((*response)->content,
                                                      _("(esx execute response)"),
                                                      &xpathContext);

        if ((*response)->document == NULL) {
            goto cleanup;
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
                goto cleanup;
            }

            if (esxVI_Fault_Deserialize((*response)->node, &fault) < 0) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("HTTP response code %d for call to '%s'. "
                               "Fault is unknown, deserialization failed"),
                             (*response)->responseCode, methodName);
                goto cleanup;
            }

            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("HTTP response code %d for call to '%s'. "
                           "Fault: %s - %s"), (*response)->responseCode,
                         methodName, fault->faultcode, fault->faultstring);

            /* FIXME: Dump raw response until detail part gets deserialized */
            VIR_DEBUG("HTTP response code %d for call to '%s' [[[[%s]]]]",
                      (*response)->responseCode, methodName,
                      (*response)->content);

            goto cleanup;
        } else {
            if (virAsprintf(&xpathExpression,
                            "/soapenv:Envelope/soapenv:Body/vim:%sResponse",
                            methodName) < 0) {
                virReportOOMError();
                goto cleanup;
            }

            responseNode = virXPathNode(xpathExpression, xpathContext);

            if (responseNode == NULL) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("XPath evaluation of response for call to '%s' "
                               "failed"), methodName);
                goto cleanup;
            }

            xpathContext->node = responseNode;
            (*response)->node = virXPathNode("./vim:returnval", xpathContext);

            switch (occurrence) {
              case esxVI_Occurrence_RequiredItem:
                if ((*response)->node == NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned an empty result, "
                                   "expecting a non-empty result"), methodName);
                    goto cleanup;
                } else if ((*response)->node->next != NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned a list, expecting "
                                   "exactly one item"), methodName);
                    goto cleanup;
                }

                break;

              case esxVI_Occurrence_RequiredList:
                if ((*response)->node == NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned an empty result, "
                                   "expecting a non-empty result"), methodName);
                    goto cleanup;
                }

                break;

              case esxVI_Occurrence_OptionalItem:
                if ((*response)->node != NULL &&
                    (*response)->node->next != NULL) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Call to '%s' returned a list, expecting "
                                   "exactly one item"), methodName);
                    goto cleanup;
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
                    goto cleanup;
                }

                break;

              default:
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Invalid argument (occurrence)"));
                goto cleanup;
            }
        }
    } else {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("HTTP response code %d for call to '%s'"),
                     (*response)->responseCode, methodName);
        goto cleanup;
    }

    result = 0;

  cleanup:
    if (result < 0) {
        virBufferFreeAndReset(&buffer);
        esxVI_Response_Free(response);
        esxVI_Fault_Free(&fault);
    }

    VIR_FREE(xpathExpression);
    xmlXPathFreeContext(xpathContext);

    return result;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Response
 */

/* esxVI_Response_Alloc */
ESX_VI__TEMPLATE__ALLOC(Response)

/* esxVI_Response_Free */
ESX_VI__TEMPLATE__FREE(Response,
{
    VIR_FREE(item->content);

    xmlFreeDoc(item->document);
})



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
    int result = -1;
    char *name = NULL;

    if (value == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *value = 0; /* undefined */

    if (esxVI_String_DeserializeValue(node, &name) < 0) {
        return -1;
    }

    for (i = 0; enumeration->values[i].name != NULL; ++i) {
        if (STREQ(name, enumeration->values[i].name)) {
            *value = enumeration->values[i].value;
            result = 0;
            break;
        }
    }

    if (result < 0) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, _("Unknown value '%s' for %s"),
                     name, esxVI_Type_ToString(enumeration->type));
    }

    VIR_FREE(name);

    return result;
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
        return -1;
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
    int result = -1;
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
            goto cleanup;
        }

        esxVI_AnyType_Free(&childAnyType);

        if (esxVI_AnyType_Deserialize(childNode, &childAnyType) < 0 ||
            castFromAnyTypeFunc(childAnyType, &item) < 0 ||
            esxVI_List_Append(list, item) < 0) {
            goto cleanup;
        }

        item = NULL;
    }

    result = 0;

  cleanup:
    if (result < 0) {
        freeFunc(&item);
        freeFunc(list);
    }

    esxVI_AnyType_Free(&childAnyType);

    return result;
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
esxVI_BuildSelectSet(esxVI_SelectionSpec **selectSet,
                     const char *name, const char *type,
                     const char *path, const char *selectSetNames)
{
    esxVI_TraversalSpec *traversalSpec = NULL;
    esxVI_SelectionSpec *selectionSpec = NULL;
    const char *currentSelectSetName = NULL;

    if (selectSet == NULL) {
        /*
         * Don't check for *selectSet != NULL here because selectSet is a list
         * and might contain items already. This function appends to selectSet.
         */
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

    if (esxVI_SelectionSpec_AppendToList(selectSet,
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
esxVI_BuildSelectSetCollection(esxVI_Context *ctx)
{
    /* Folder -> childEntity (ManagedEntity) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_folderToChildEntity,
                             "folderToChildEntity",
                             "Folder", "childEntity", NULL) < 0) {
        return -1;
    }

    /* ComputeResource -> host (HostSystem) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_computeResourceToHost,
                             "computeResourceToHost",
                             "ComputeResource", "host", NULL) < 0) {
        return -1;
    }

    /* ComputeResource -> datastore (Datastore) *//*
    if (esxVI_BuildSelectSet(&ctx->selectSet_computeResourceToDatastore,
                             "computeResourceToDatastore",
                             "ComputeResource", "datastore", NULL) < 0) {
        return -1;
    }*/

    /* ResourcePool -> resourcePool (ResourcePool) *//*
    if (esxVI_BuildSelectSet(&ctx->selectSet_resourcePoolToVm,
                             "resourcePoolToResourcePool",
                             "ResourcePool", "resourcePool",
                             "resourcePoolToResourcePool\0"
                             "resourcePoolToVm\0") < 0) {
        return -1;
    }*/

    /* ResourcePool -> vm (VirtualMachine) *//*
    if (esxVI_BuildSelectSet(&ctx->selectSet_resourcePoolToVm,
                             "resourcePoolToVm",
                             "ResourcePool", "vm", NULL) < 0) {
        return -1;
    }*/

    /* HostSystem -> parent (ComputeResource) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_hostSystemToParent,
                             "hostSystemToParent",
                             "HostSystem", "parent", NULL) < 0) {
        return -1;
    }

    /* HostSystem -> vm (VirtualMachine) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_hostSystemToVm,
                             "hostSystemToVm",
                             "HostSystem", "vm", NULL) < 0) {
        return -1;
    }

    /* HostSystem -> datastore (Datastore) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_hostSystemToDatastore,
                             "hostSystemToDatastore",
                             "HostSystem", "datastore", NULL) < 0) {
        return -1;
    }

    /* Folder -> parent (Folder, Datacenter) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_computeResourceToParentToParent,
                             "managedEntityToParent",
                             "ManagedEntity", "parent", NULL) < 0) {
        return -1;
    }

    /* ComputeResource -> parent (Folder) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_computeResourceToParentToParent,
                             "computeResourceToParent",
                             "ComputeResource", "parent",
                             "managedEntityToParent\0") < 0) {
        return -1;
    }

    return 0;
}



int
esxVI_EnsureSession(esxVI_Context *ctx)
{
    int result = -1;
    esxVI_Boolean active = esxVI_Boolean_Undefined;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *sessionManager = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_UserSession *currentSession = NULL;

    if (ctx->sessionLock == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call, no mutex"));
        return -1;
    }

    virMutexLock(ctx->sessionLock);

    if (ctx->session == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call, no session"));
        goto cleanup;
    }

    if (ctx->hasSessionIsActive) {
        /*
         * Use SessionIsActive to check if there is an active session for this
         * connection, and re-login if there isn't.
         */
        if (esxVI_SessionIsActive(ctx, ctx->session->key,
                                  ctx->session->userName, &active) < 0) {
            goto cleanup;
        }

        if (active != esxVI_Boolean_True) {
            esxVI_UserSession_Free(&ctx->session);

            if (esxVI_Login(ctx, ctx->username, ctx->password, NULL,
                            &ctx->session) < 0) {
                goto cleanup;
            }
        }
    } else {
        /*
         * Query the session manager for the current session of this connection
         * and re-login if there is no current session for this connection.
         */
        if (esxVI_String_AppendValueToList(&propertyNameList,
                                           "currentSession") < 0 ||
            esxVI_LookupObjectContentByType(ctx, ctx->service->sessionManager,
                                            "SessionManager", propertyNameList,
                                            &sessionManager,
                                            esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        for (dynamicProperty = sessionManager->propSet; dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "currentSession")) {
                if (esxVI_UserSession_CastFromAnyType(dynamicProperty->val,
                                                      &currentSession) < 0) {
                    goto cleanup;
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
                goto cleanup;
            }
        } else if (STRNEQ(ctx->session->key, currentSession->key)) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Key of the current session differs from the key at "
                           "last login"));
            goto cleanup;
        }
    }

    result = 0;

  cleanup:
    virMutexUnlock(ctx->sessionLock);

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&sessionManager);
    esxVI_UserSession_Free(&currentSession);

    return result;
}



int
esxVI_LookupObjectContentByType(esxVI_Context *ctx,
                                esxVI_ManagedObjectReference *root,
                                const char *type,
                                esxVI_String *propertyNameList,
                                esxVI_ObjectContent **objectContentList,
                                esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_ObjectSpec *objectSpec = NULL;
    esxVI_PropertySpec *propertySpec = NULL;
    esxVI_PropertyFilterSpec *propertyFilterSpec = NULL;

    if (objectContentList == NULL || *objectContentList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_ObjectSpec_Alloc(&objectSpec) < 0) {
        return -1;
    }

    objectSpec->obj = root;
    objectSpec->skip = esxVI_Boolean_False;

    if (STRNEQ(root->type, type) || STREQ(root->type, "Folder")) {
        if (STREQ(root->type, "Folder")) {
            if (STREQ(type, "Folder") || STREQ(type, "Datacenter") ||
                STREQ(type, "ComputeResource") ||
                STREQ(type, "ClusterComputeResource")) {
                objectSpec->selectSet = ctx->selectSet_folderToChildEntity;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Invalid lookup of '%s' from '%s'"),
                             type, root->type);
                goto cleanup;
            }
        } else if (STREQ(root->type, "ComputeResource") ||
                   STREQ(root->type, "ClusterComputeResource")) {
            if (STREQ(type, "HostSystem")) {
                objectSpec->selectSet = ctx->selectSet_computeResourceToHost;
            } else if (STREQ(type, "Datacenter")) {
                objectSpec->selectSet = ctx->selectSet_computeResourceToParentToParent;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Invalid lookup of '%s' from '%s'"),
                             type, root->type);
                goto cleanup;
            }
        } else if (STREQ(root->type, "HostSystem")) {
            if (STREQ(type, "ComputeResource") ||
                STREQ(type, "ClusterComputeResource")) {
                objectSpec->selectSet = ctx->selectSet_hostSystemToParent;
            } else if (STREQ(type, "VirtualMachine")) {
                objectSpec->selectSet = ctx->selectSet_hostSystemToVm;
            } else if (STREQ(type, "Datastore")) {
                objectSpec->selectSet = ctx->selectSet_hostSystemToDatastore;
            } else {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("Invalid lookup of '%s' from '%s'"),
                             type, root->type);
                goto cleanup;
            }
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Invalid lookup from '%s'"), root->type);
            goto cleanup;
        }
    }

    if (esxVI_PropertySpec_Alloc(&propertySpec) < 0) {
        goto cleanup;
    }

    propertySpec->type = (char *)type;
    propertySpec->pathSet = propertyNameList;

    if (esxVI_PropertyFilterSpec_Alloc(&propertyFilterSpec) < 0 ||
        esxVI_PropertySpec_AppendToList(&propertyFilterSpec->propSet,
                                        propertySpec) < 0 ||
        esxVI_ObjectSpec_AppendToList(&propertyFilterSpec->objectSet,
                                      objectSpec) < 0 ||
        esxVI_RetrieveProperties(ctx, propertyFilterSpec,
                                 objectContentList) < 0) {
        goto cleanup;
    }

    if (*objectContentList == NULL) {
        switch (occurrence) {
          case esxVI_Occurrence_OptionalItem:
          case esxVI_Occurrence_OptionalList:
            result = 0;
            break;

          case esxVI_Occurrence_RequiredItem:
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Could not lookup '%s' from '%s'"),
                         type, root->type);
            break;

          case esxVI_Occurrence_RequiredList:
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Could not lookup '%s' list from '%s'"),
                         type, root->type);
            break;

          default:
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Invalid occurrence value"));
            break;
        }

        goto cleanup;
    }

    result = 0;

  cleanup:
    /*
     * Remove values given by the caller from the data structures to prevent
     * them from being freed by the call to esxVI_PropertyFilterSpec_Free().
     */
    objectSpec->obj = NULL;
    objectSpec->selectSet = NULL;
    if (propertySpec != NULL) {
        propertySpec->type = NULL;
        propertySpec->pathSet = NULL;
    }

    esxVI_PropertyFilterSpec_Free(&propertyFilterSpec);

    return result;
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
esxVI_GetBoolean(esxVI_ObjectContent *objectContent, const char *propertyName,
                 esxVI_Boolean *value, esxVI_Occurrence occurrence)
{
    esxVI_DynamicProperty *dynamicProperty;

    if (value == NULL || *value != esxVI_Boolean_Undefined) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Boolean) < 0) {
                return -1;
            }

            *value = dynamicProperty->val->boolean;
            break;
        }
    }

    if (*value == esxVI_Boolean_Undefined &&
        occurrence == esxVI_Occurrence_RequiredItem) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Missing '%s' property"), propertyName);
        return -1;
    }

    return 0;
}



int
esxVI_GetLong(esxVI_ObjectContent *objectContent, const char *propertyName,
              esxVI_Long **value, esxVI_Occurrence occurrence)
{
    esxVI_DynamicProperty *dynamicProperty;

    if (value == NULL || *value != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            if (esxVI_Long_CastFromAnyType(dynamicProperty->val, value) < 0) {
                return -1;
            }

            break;
        }
    }

    if (*value == NULL && occurrence == esxVI_Occurrence_RequiredItem) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Missing '%s' property"), propertyName);
        return -1;
    }

    return 0;
}



int
esxVI_GetStringValue(esxVI_ObjectContent *objectContent,
                     const char *propertyName,
                     char **value, esxVI_Occurrence occurrence)
{
    esxVI_DynamicProperty *dynamicProperty;

    if (value == NULL || *value != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                return -1;
            }

            *value = dynamicProperty->val->string;
            break;
        }
    }

    if (*value == NULL && occurrence == esxVI_Occurrence_RequiredItem) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Missing '%s' property"), propertyName);
        return -1;
    }

    return 0;
}



int
esxVI_GetManagedObjectReference(esxVI_ObjectContent *objectContent,
                                const char *propertyName,
                                esxVI_ManagedObjectReference **value,
                                esxVI_Occurrence occurrence)
{
    esxVI_DynamicProperty *dynamicProperty;

    if (value == NULL || *value != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, value) < 0) {
                return -1;
            }

            break;
        }
    }

    if (*value == NULL && occurrence == esxVI_Occurrence_RequiredItem) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Missing '%s' property"), propertyName);
        return -1;
    }

    return 0;
}



int
esxVI_LookupNumberOfDomainsByPowerState(esxVI_Context *ctx,
                                        esxVI_VirtualMachinePowerState powerState,
                                        bool inverse)
{
    bool success = false;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_VirtualMachinePowerState powerState_;
    int count = 0;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineList(ctx, propertyNameList,
                                       &virtualMachineList) < 0) {
        goto cleanup;
    }

    for (virtualMachine = virtualMachineList; virtualMachine != NULL;
         virtualMachine = virtualMachine->_next) {
        for (dynamicProperty = virtualMachine->propSet;
             dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "runtime.powerState")) {
                if (esxVI_VirtualMachinePowerState_CastFromAnyType
                      (dynamicProperty->val, &powerState_) < 0) {
                    goto cleanup;
                }

                if ((!inverse && powerState_ == powerState) ||
                    ( inverse && powerState_ != powerState)) {
                    count++;
                }
            } else {
                VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
            }
        }
    }

    success = true;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);

    return success ? count : -1;
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

                if (virVMXUnescapeHexPercent(*name) < 0) {
                    ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("Domain name contains invalid escape sequence"));
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

            VIR_WARN("Cannot access UUID, because 'configStatus' property "
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
  (esxVI_VirtualMachineSnapshotTree *snapshotTreeList, bool recurse,
   bool leaves)
{
    int count = 0;
    esxVI_VirtualMachineSnapshotTree *snapshotTree;

    for (snapshotTree = snapshotTreeList; snapshotTree != NULL;
         snapshotTree = snapshotTree->_next) {
        if (!(leaves && snapshotTree->childSnapshotList))
            count++;
        if (recurse)
            count += esxVI_GetNumberOfSnapshotTrees
                (snapshotTree->childSnapshotList, true, leaves);
    }

    return count;
}



int
esxVI_GetSnapshotTreeNames(esxVI_VirtualMachineSnapshotTree *snapshotTreeList,
                           char **names, int nameslen, bool recurse,
                           bool leaves)
{
    int count = 0;
    int result;
    int i;
    esxVI_VirtualMachineSnapshotTree *snapshotTree;

    for (snapshotTree = snapshotTreeList;
         snapshotTree != NULL && count < nameslen;
         snapshotTree = snapshotTree->_next) {
        if (!(leaves && snapshotTree->childSnapshotList)) {
            names[count] = strdup(snapshotTree->name);

            if (names[count] == NULL) {
                virReportOOMError();
                goto failure;
            }

            count++;
        }

        if (count >= nameslen) {
            break;
        }

        if (recurse) {
            result = esxVI_GetSnapshotTreeNames(snapshotTree->childSnapshotList,
                                                names + count,
                                                nameslen - count,
                                                true, leaves);

            if (result < 0) {
                goto failure;
            }

            count += result;
        }
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
        (snapshotTreeParent && *snapshotTreeParent != NULL)) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (candidate = snapshotTreeList; candidate != NULL;
         candidate = candidate->_next) {
        if (STREQ(candidate->name, name)) {
            *snapshotTree = candidate;
            if (snapshotTreeParent)
                *snapshotTreeParent = NULL;
            return 1;
        }

        if (esxVI_GetSnapshotTreeByName(candidate->childSnapshotList, name,
                                        snapshotTree, snapshotTreeParent,
                                        occurrence) > 0) {
            if (snapshotTreeParent && *snapshotTreeParent == NULL) {
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
esxVI_LookupHostSystemProperties(esxVI_Context *ctx,
                                 esxVI_String *propertyNameList,
                                 esxVI_ObjectContent **hostSystem)
{
    return esxVI_LookupObjectContentByType(ctx, ctx->hostSystem->_reference,
                                           "HostSystem", propertyNameList,
                                           hostSystem,
                                           esxVI_Occurrence_RequiredItem);
}



int
esxVI_LookupVirtualMachineList(esxVI_Context *ctx,
                               esxVI_String *propertyNameList,
                               esxVI_ObjectContent **virtualMachineList)
{
    /* FIXME: Switch from ctx->hostSystem to ctx->computeResource->resourcePool
     *        for cluster support */
    return esxVI_LookupObjectContentByType(ctx, ctx->hostSystem->_reference,
                                           "VirtualMachine", propertyNameList,
                                           virtualMachineList,
                                           esxVI_Occurrence_OptionalList);
}



int
esxVI_LookupVirtualMachineByUuid(esxVI_Context *ctx, const unsigned char *uuid,
                                 esxVI_String *propertyNameList,
                                 esxVI_ObjectContent **virtualMachine,
                                 esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (virtualMachine == NULL || *virtualMachine != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virUUIDFormat(uuid, uuid_string);

    if (esxVI_FindByUuid(ctx, ctx->datacenter->_reference, uuid_string,
                         esxVI_Boolean_True, &managedObjectReference) < 0) {
        return -1;
    }

    if (managedObjectReference == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_DOMAIN,
                         _("Could not find domain with UUID '%s'"),
                         uuid_string);
            goto cleanup;
        }
    }

    if (esxVI_LookupObjectContentByType(ctx, managedObjectReference,
                                        "VirtualMachine", propertyNameList,
                                        virtualMachine,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_ManagedObjectReference_Free(&managedObjectReference);

    return result;
}



int
esxVI_LookupVirtualMachineByName(esxVI_Context *ctx, const char *name,
                                 esxVI_String *propertyNameList,
                                 esxVI_ObjectContent **virtualMachine,
                                 esxVI_Occurrence occurrence)
{
    int result = -1;
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
        esxVI_LookupVirtualMachineList(ctx, completePropertyNameList,
                                       &virtualMachineList) < 0) {
        goto cleanup;
    }

    for (candidate = virtualMachineList; candidate != NULL;
         candidate = candidate->_next) {
        VIR_FREE(name_candidate);

        if (esxVI_GetVirtualMachineIdentity(candidate, NULL, &name_candidate,
                                            NULL) < 0) {
            goto cleanup;
        }

        if (STRNEQ(name, name_candidate)) {
            continue;
        }

        if (esxVI_ObjectContent_DeepCopy(virtualMachine, candidate) < 0) {
            goto cleanup;
        }

        break;
    }

    if (*virtualMachine == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_DOMAIN,
                         _("Could not find domain with name '%s'"), name);
            goto cleanup;
        }
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);
    VIR_FREE(name_candidate);

    return result;
}



int
esxVI_LookupVirtualMachineByUuidAndPrepareForTask
  (esxVI_Context *ctx, const unsigned char *uuid,
   esxVI_String *propertyNameList, esxVI_ObjectContent **virtualMachine,
   bool autoAnswer)
{
    int result = -1;
    esxVI_String *completePropertyNameList = NULL;
    esxVI_VirtualMachineQuestionInfo *questionInfo = NULL;
    esxVI_TaskInfo *pendingTaskInfoList = NULL;
    bool blocked;

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
        goto cleanup;
    }

    if (questionInfo != NULL &&
        esxVI_HandleVirtualMachineQuestion(ctx, (*virtualMachine)->obj,
                                           questionInfo, autoAnswer,
                                           &blocked) < 0) {
        goto cleanup;
    }

    if (pendingTaskInfoList != NULL) {
        ESX_VI_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                     _("Other tasks are pending for this domain"));
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_VirtualMachineQuestionInfo_Free(&questionInfo);
    esxVI_TaskInfo_Free(&pendingTaskInfoList);

    return result;
}



int
esxVI_LookupDatastoreList(esxVI_Context *ctx, esxVI_String *propertyNameList,
                          esxVI_ObjectContent **datastoreList)
{
    /* FIXME: Switch from ctx->hostSystem to ctx->computeResource for cluster
     *        support */
    return esxVI_LookupObjectContentByType(ctx, ctx->hostSystem->_reference,
                                           "Datastore", propertyNameList,
                                           datastoreList,
                                           esxVI_Occurrence_OptionalList);
}



int
esxVI_LookupDatastoreByName(esxVI_Context *ctx, const char *name,
                            esxVI_String *propertyNameList,
                            esxVI_ObjectContent **datastore,
                            esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_String *completePropertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *candidate = NULL;
    char *name_candidate;

    if (datastore == NULL || *datastore != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /* Get all datastores */
    if (esxVI_String_DeepCopyList(&completePropertyNameList,
                                  propertyNameList) < 0 ||
        esxVI_String_AppendValueToList(&completePropertyNameList,
                                       "summary.name") < 0 ||
        esxVI_LookupDatastoreList(ctx, completePropertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    /* Search for a matching datastore */
    for (candidate = datastoreList; candidate != NULL;
         candidate = candidate->_next) {
        name_candidate = NULL;

        if (esxVI_GetStringValue(candidate, "summary.name", &name_candidate,
                                 esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        if (STREQ(name_candidate, name)) {
            if (esxVI_ObjectContent_DeepCopy(datastore, candidate) < 0) {
                goto cleanup;
            }

            /* Found datastore with matching name */
            result = 0;

            goto cleanup;
        }
    }

    if (*datastore == NULL && occurrence != esxVI_Occurrence_OptionalItem) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not find datastore with name '%s'"), name);
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);

    return result;
}


int
esxVI_LookupDatastoreByAbsolutePath(esxVI_Context *ctx,
                                    const char *absolutePath,
                                    esxVI_String *propertyNameList,
                                    esxVI_ObjectContent **datastore,
                                    esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_String *completePropertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *candidate = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_DatastoreHostMount *datastoreHostMountList = NULL;
    esxVI_DatastoreHostMount *datastoreHostMount = NULL;

    if (datastore == NULL || *datastore != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /* Get all datastores */
    if (esxVI_String_DeepCopyList(&completePropertyNameList,
                                  propertyNameList) < 0 ||
        esxVI_String_AppendValueToList(&completePropertyNameList, "host") < 0 ||
        esxVI_LookupDatastoreList(ctx, completePropertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    /* Search for a matching datastore */
    for (candidate = datastoreList; candidate != NULL;
         candidate = candidate->_next) {
        esxVI_DatastoreHostMount_Free(&datastoreHostMountList);

        for (dynamicProperty = candidate->propSet; dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "host")) {
                if (esxVI_DatastoreHostMount_CastListFromAnyType
                      (dynamicProperty->val, &datastoreHostMountList) < 0) {
                    goto cleanup;
                }

                break;
            }
        }

        if (datastoreHostMountList == NULL) {
            continue;
        }

        for (datastoreHostMount = datastoreHostMountList;
             datastoreHostMount != NULL;
             datastoreHostMount = datastoreHostMount->_next) {
            if (STRNEQ(ctx->hostSystem->_reference->value,
                       datastoreHostMount->key->value)) {
                continue;
            }

            if (STRPREFIX(absolutePath, datastoreHostMount->mountInfo->path)) {
                if (esxVI_ObjectContent_DeepCopy(datastore, candidate) < 0) {
                    goto cleanup;
                }

                /* Found datastore with matching mount path */
                result = 0;

                goto cleanup;
            }
        }
    }

    if (*datastore == NULL && occurrence != esxVI_Occurrence_OptionalItem) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not find datastore containing absolute path '%s'"),
                     absolutePath);
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&completePropertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);
    esxVI_DatastoreHostMount_Free(&datastoreHostMountList);

    return result;
}



int
esxVI_LookupDatastoreHostMount(esxVI_Context *ctx,
                               esxVI_ManagedObjectReference *datastore,
                               esxVI_DatastoreHostMount **hostMount)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *objectContent = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_DatastoreHostMount *hostMountList = NULL;
    esxVI_DatastoreHostMount *candidate = NULL;

    if (hostMount == NULL || *hostMount != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "host") < 0 ||
        esxVI_LookupObjectContentByType(ctx, datastore, "Datastore",
                                        propertyNameList, &objectContent,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "host")) {
            if (esxVI_DatastoreHostMount_CastListFromAnyType
                  (dynamicProperty->val, &hostMountList) < 0) {
                goto cleanup;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    for (candidate = hostMountList; candidate != NULL;
         candidate = candidate->_next) {
        if (STRNEQ(ctx->hostSystem->_reference->value, candidate->key->value)) {
            continue;
        }

        if (esxVI_DatastoreHostMount_DeepCopy(hostMount, candidate) < 0) {
            goto cleanup;
        }

        break;
    }

    if (*hostMount == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not lookup datastore host mount"));
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&objectContent);
    esxVI_DatastoreHostMount_Free(&hostMountList);

    return result;
}


int
esxVI_LookupTaskInfoByTask(esxVI_Context *ctx,
                           esxVI_ManagedObjectReference *task,
                           esxVI_TaskInfo **taskInfo)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *objectContent = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (taskInfo == NULL || *taskInfo != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "info") < 0 ||
        esxVI_LookupObjectContentByType(ctx, task, "Task", propertyNameList,
                                        &objectContent,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "info")) {
            if (esxVI_TaskInfo_CastFromAnyType(dynamicProperty->val,
                                               taskInfo) < 0) {
                goto cleanup;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&objectContent);

    return result;
}



int
esxVI_LookupPendingTaskInfoListByVirtualMachine
  (esxVI_Context *ctx, esxVI_ObjectContent *virtualMachine,
   esxVI_TaskInfo **pendingTaskInfoList)
{
    int result = -1;
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
                goto cleanup;
            }

            break;
        }
    }

    /* Lookup task info for each task */
    for (recentTask = recentTaskList; recentTask != NULL;
         recentTask = recentTask->_next) {
        if (esxVI_LookupTaskInfoByTask(ctx, recentTask, &taskInfo) < 0) {
            goto cleanup;
        }

        if (taskInfo->state == esxVI_TaskInfoState_Queued ||
            taskInfo->state == esxVI_TaskInfoState_Running) {
            if (esxVI_TaskInfo_AppendToList(pendingTaskInfoList,
                                            taskInfo) < 0) {
                goto cleanup;
            }

            taskInfo = NULL;
        } else {
            esxVI_TaskInfo_Free(&taskInfo);
        }
    }

    result = 0;

  cleanup:
    if (result < 0) {
        esxVI_TaskInfo_Free(pendingTaskInfoList);
    }

    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&recentTaskList);
    esxVI_TaskInfo_Free(&taskInfo);

    return result;
}



int
esxVI_LookupAndHandleVirtualMachineQuestion(esxVI_Context *ctx,
                                            const unsigned char *uuid,
                                            esxVI_Occurrence occurrence,
                                            bool autoAnswer, bool *blocked)
{
    int result = -1;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachineQuestionInfo *questionInfo = NULL;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.question") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, uuid, propertyNameList,
                                         &virtualMachine, occurrence) < 0) {
        goto cleanup;
    }

    if (virtualMachine != NULL) {
        if (esxVI_GetVirtualMachineQuestionInfo(virtualMachine,
                                                &questionInfo) < 0) {
            goto cleanup;
        }

        if (questionInfo != NULL &&
            esxVI_HandleVirtualMachineQuestion(ctx, virtualMachine->obj,
                                               questionInfo, autoAnswer,
                                               blocked) < 0) {
            goto cleanup;
        }
    }

    result = 0;

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_VirtualMachineQuestionInfo_Free(&questionInfo);

    return result;
}



int
esxVI_LookupRootSnapshotTreeList
  (esxVI_Context *ctx, const unsigned char *virtualMachineUuid,
   esxVI_VirtualMachineSnapshotTree **rootSnapshotTreeList)
{
    int result = -1;
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
        goto cleanup;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "snapshot.rootSnapshotList")) {
            if (esxVI_VirtualMachineSnapshotTree_CastListFromAnyType
                  (dynamicProperty->val, rootSnapshotTreeList) < 0) {
                goto cleanup;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    result = 0;

  cleanup:
    if (result < 0) {
        esxVI_VirtualMachineSnapshotTree_Free(rootSnapshotTreeList);
    }

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;
}



int
esxVI_LookupCurrentSnapshotTree
  (esxVI_Context *ctx, const unsigned char *virtualMachineUuid,
   esxVI_VirtualMachineSnapshotTree **currentSnapshotTree,
   esxVI_Occurrence occurrence)
{
    int result = -1;
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
        goto cleanup;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "snapshot.currentSnapshot")) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, &currentSnapshot) < 0) {
                goto cleanup;
            }
        } else if (STREQ(dynamicProperty->name, "snapshot.rootSnapshotList")) {
            if (esxVI_VirtualMachineSnapshotTree_CastListFromAnyType
                  (dynamicProperty->val, &rootSnapshotTreeList) < 0) {
                goto cleanup;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (currentSnapshot == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                         _("Domain has no current snapshot"));
            goto cleanup;
        }
    }

    if (rootSnapshotTreeList == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not lookup root snapshot list"));
        goto cleanup;
    }

    if (esxVI_GetSnapshotTreeBySnapshot(rootSnapshotTreeList, currentSnapshot,
                                        &snapshotTree) < 0 ||
        esxVI_VirtualMachineSnapshotTree_DeepCopy(currentSnapshotTree,
                                                  snapshotTree) < 0) {
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_ManagedObjectReference_Free(&currentSnapshot);
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return result;
}



int
esxVI_LookupFileInfoByDatastorePath(esxVI_Context *ctx,
                                    const char *datastorePath,
                                    bool lookupFolder,
                                    esxVI_FileInfo **fileInfo,
                                    esxVI_Occurrence occurrence)
{
    int result = -1;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *directoryAndFileName = NULL;
    char *fileName = NULL;
    size_t length;
    char *datastorePathWithoutFileName = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_ManagedObjectReference *hostDatastoreBrowser = NULL;
    esxVI_HostDatastoreBrowserSearchSpec *searchSpec = NULL;
    esxVI_FolderFileQuery *folderFileQuery = NULL;
    esxVI_VmDiskFileQuery *vmDiskFileQuery = NULL;
    esxVI_IsoImageFileQuery *isoImageFileQuery = NULL;
    esxVI_FloppyImageFileQuery *floppyImageFileQuery = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;
    esxVI_TaskInfo *taskInfo = NULL;
    esxVI_HostDatastoreBrowserSearchResults *searchResults = NULL;

    if (fileInfo == NULL || *fileInfo != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxUtil_ParseDatastorePath(datastorePath, &datastoreName,
                                   &directoryName, &directoryAndFileName) < 0) {
        goto cleanup;
    }

    if (STREQ(directoryName, directoryAndFileName)) {
        /*
         * The <path> part of the datatore path didn't contain a '/', assume
         * that the <path> part is actually the file name.
         */
        if (virAsprintf(&datastorePathWithoutFileName, "[%s]",
                        datastoreName) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (esxVI_String_DeepCopyValue(&fileName, directoryAndFileName) < 0) {
            goto cleanup;
        }
    } else {
        if (virAsprintf(&datastorePathWithoutFileName, "[%s] %s",
                        datastoreName, directoryName) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        length = strlen(directoryName);

        if (directoryAndFileName[length] != '/' ||
            directoryAndFileName[length + 1] == '\0') {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Datastore path '%s' doesn't reference a file"),
                         datastorePath);
            goto cleanup;
        }

        if (esxVI_String_DeepCopyValue(&fileName,
                                       directoryAndFileName + length + 1) < 0) {
            goto cleanup;
        }
    }

    /* Lookup HostDatastoreBrowser */
    if (esxVI_String_AppendValueToList(&propertyNameList, "browser") < 0 ||
        esxVI_LookupDatastoreByName(ctx, datastoreName, propertyNameList,
                                    &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetManagedObjectReference(datastore, "browser",
                                        &hostDatastoreBrowser,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* Build HostDatastoreBrowserSearchSpec */
    if (esxVI_HostDatastoreBrowserSearchSpec_Alloc(&searchSpec) < 0 ||
        esxVI_FileQueryFlags_Alloc(&searchSpec->details) < 0) {
        goto cleanup;
    }

    searchSpec->details->fileType = esxVI_Boolean_True;
    searchSpec->details->fileSize = esxVI_Boolean_True;
    searchSpec->details->modification = esxVI_Boolean_False;

    if (lookupFolder) {
        if (esxVI_FolderFileQuery_Alloc(&folderFileQuery) < 0 ||
            esxVI_FileQuery_AppendToList
              (&searchSpec->query,
               esxVI_FileQuery_DynamicCast(folderFileQuery)) < 0) {
            goto cleanup;
        }
    } else {
        if (esxVI_VmDiskFileQuery_Alloc(&vmDiskFileQuery) < 0 ||
            esxVI_VmDiskFileQueryFlags_Alloc(&vmDiskFileQuery->details) < 0 ||
            esxVI_FileQuery_AppendToList
              (&searchSpec->query,
               esxVI_FileQuery_DynamicCast(vmDiskFileQuery)) < 0) {
            goto cleanup;
        }

        vmDiskFileQuery->details->diskType = esxVI_Boolean_False;
        vmDiskFileQuery->details->capacityKb = esxVI_Boolean_True;
        vmDiskFileQuery->details->hardwareVersion = esxVI_Boolean_False;
        vmDiskFileQuery->details->controllerType = esxVI_Boolean_True;
        vmDiskFileQuery->details->diskExtents = esxVI_Boolean_False;

        if (esxVI_IsoImageFileQuery_Alloc(&isoImageFileQuery) < 0 ||
            esxVI_FileQuery_AppendToList
              (&searchSpec->query,
               esxVI_FileQuery_DynamicCast(isoImageFileQuery)) < 0) {
            goto cleanup;
        }

        if (esxVI_FloppyImageFileQuery_Alloc(&floppyImageFileQuery) < 0 ||
            esxVI_FileQuery_AppendToList
              (&searchSpec->query,
               esxVI_FileQuery_DynamicCast(floppyImageFileQuery)) < 0) {
            goto cleanup;
        }
    }

    if (esxVI_String_Alloc(&searchSpec->matchPattern) < 0) {
        goto cleanup;
    }

    searchSpec->matchPattern->value = fileName;

    /* Search datastore for file */
    if (esxVI_SearchDatastore_Task(ctx, hostDatastoreBrowser,
                                   datastorePathWithoutFileName, searchSpec,
                                   &task) < 0 ||
        esxVI_WaitForTaskCompletion(ctx, task, NULL, esxVI_Occurrence_None,
                                    false, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not search in datastore '%s': %s"),
                     datastoreName, taskInfoErrorMessage);
        goto cleanup;
    }

    if (esxVI_LookupTaskInfoByTask(ctx, task, &taskInfo) < 0 ||
        esxVI_HostDatastoreBrowserSearchResults_CastFromAnyType
          (taskInfo->result, &searchResults) < 0) {
        goto cleanup;
    }

    /* Interpret search result */
    if (searchResults->file == NULL) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            ESX_VI_ERROR(VIR_ERR_NO_STORAGE_VOL,
                         _("No storage volume with key or path '%s'"),
                         datastorePath);
            goto cleanup;
        }
    }

    *fileInfo = searchResults->file;
    searchResults->file = NULL;

    result = 0;

  cleanup:
    /* Don't double free fileName */
    if (searchSpec != NULL && searchSpec->matchPattern != NULL) {
        searchSpec->matchPattern->value = NULL;
    }

    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(directoryAndFileName);
    VIR_FREE(fileName);
    VIR_FREE(datastorePathWithoutFileName);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);
    esxVI_ManagedObjectReference_Free(&hostDatastoreBrowser);
    esxVI_HostDatastoreBrowserSearchSpec_Free(&searchSpec);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);
    esxVI_TaskInfo_Free(&taskInfo);
    esxVI_HostDatastoreBrowserSearchResults_Free(&searchResults);

    return result;
}



int
esxVI_LookupDatastoreContentByDatastoreName
  (esxVI_Context *ctx, const char *datastoreName,
   esxVI_HostDatastoreBrowserSearchResults **searchResultsList)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_ManagedObjectReference *hostDatastoreBrowser = NULL;
    esxVI_HostDatastoreBrowserSearchSpec *searchSpec = NULL;
    esxVI_VmDiskFileQuery *vmDiskFileQuery = NULL;
    esxVI_IsoImageFileQuery *isoImageFileQuery = NULL;
    esxVI_FloppyImageFileQuery *floppyImageFileQuery = NULL;
    char *datastorePath = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;
    esxVI_TaskInfo *taskInfo = NULL;

    if (searchResultsList == NULL || *searchResultsList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /* Lookup Datastore and HostDatastoreBrowser */
    if (esxVI_String_AppendValueToList(&propertyNameList, "browser") < 0 ||
        esxVI_LookupDatastoreByName(ctx, datastoreName, propertyNameList,
                                    &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetManagedObjectReference(datastore, "browser",
                                        &hostDatastoreBrowser,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* Build HostDatastoreBrowserSearchSpec */
    if (esxVI_HostDatastoreBrowserSearchSpec_Alloc(&searchSpec) < 0 ||
        esxVI_FileQueryFlags_Alloc(&searchSpec->details) < 0) {
        goto cleanup;
    }

    searchSpec->details->fileType = esxVI_Boolean_True;
    searchSpec->details->fileSize = esxVI_Boolean_True;
    searchSpec->details->modification = esxVI_Boolean_False;

    if (esxVI_VmDiskFileQuery_Alloc(&vmDiskFileQuery) < 0 ||
        esxVI_VmDiskFileQueryFlags_Alloc(&vmDiskFileQuery->details) < 0 ||
        esxVI_FileQuery_AppendToList
          (&searchSpec->query,
           esxVI_FileQuery_DynamicCast(vmDiskFileQuery)) < 0) {
        goto cleanup;
    }

    vmDiskFileQuery->details->diskType = esxVI_Boolean_False;
    vmDiskFileQuery->details->capacityKb = esxVI_Boolean_True;
    vmDiskFileQuery->details->hardwareVersion = esxVI_Boolean_False;
    vmDiskFileQuery->details->controllerType = esxVI_Boolean_True;
    vmDiskFileQuery->details->diskExtents = esxVI_Boolean_False;

    if (esxVI_IsoImageFileQuery_Alloc(&isoImageFileQuery) < 0 ||
        esxVI_FileQuery_AppendToList
          (&searchSpec->query,
           esxVI_FileQuery_DynamicCast(isoImageFileQuery)) < 0) {
        goto cleanup;
    }

    if (esxVI_FloppyImageFileQuery_Alloc(&floppyImageFileQuery) < 0 ||
        esxVI_FileQuery_AppendToList
          (&searchSpec->query,
           esxVI_FileQuery_DynamicCast(floppyImageFileQuery)) < 0) {
        goto cleanup;
    }

    /* Search datastore for files */
    if (virAsprintf(&datastorePath, "[%s]", datastoreName) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (esxVI_SearchDatastoreSubFolders_Task(ctx, hostDatastoreBrowser,
                                             datastorePath, searchSpec,
                                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(ctx, task, NULL, esxVI_Occurrence_None,
                                    false, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Could not serach in datastore '%s': %s"),
                     datastoreName, taskInfoErrorMessage);
        goto cleanup;
    }

    if (esxVI_LookupTaskInfoByTask(ctx, task, &taskInfo) < 0 ||
        esxVI_HostDatastoreBrowserSearchResults_CastListFromAnyType
          (taskInfo->result, searchResultsList) < 0) {
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);
    esxVI_ManagedObjectReference_Free(&hostDatastoreBrowser);
    esxVI_HostDatastoreBrowserSearchSpec_Free(&searchSpec);
    VIR_FREE(datastorePath);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);
    esxVI_TaskInfo_Free(&taskInfo);

    return result;
}



int
esxVI_LookupStorageVolumeKeyByDatastorePath(esxVI_Context *ctx,
                                            const char *datastorePath,
                                            char **key)
{
    int result = -1;
    esxVI_FileInfo *fileInfo = NULL;
    char *uuid_string = NULL;

    if (key == NULL || *key != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (ctx->hasQueryVirtualDiskUuid) {
        if (esxVI_LookupFileInfoByDatastorePath
              (ctx, datastorePath, false, &fileInfo,
               esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        if (esxVI_VmDiskFileInfo_DynamicCast(fileInfo) != NULL) {
            /* VirtualDisks have a UUID, use it as key */
            if (esxVI_QueryVirtualDiskUuid(ctx, datastorePath,
                                           ctx->datacenter->_reference,
                                           &uuid_string) < 0) {
                goto cleanup;
            }

            if (VIR_ALLOC_N(*key, VIR_UUID_STRING_BUFLEN) < 0) {
                virReportOOMError();
                goto cleanup;
            }

            if (esxUtil_ReformatUuid(uuid_string, *key) < 0) {
                goto cleanup;
            }
        }
    }

    if (*key == NULL) {
        /* Other files don't have a UUID, fall back to the path as key */
        if (esxVI_String_DeepCopyValue(key, datastorePath) < 0) {
            goto cleanup;
        }
    }

    result = 0;

  cleanup:
    esxVI_FileInfo_Free(&fileInfo);
    VIR_FREE(uuid_string);

    return result;
}



int
esxVI_LookupAutoStartDefaults(esxVI_Context *ctx,
                              esxVI_AutoStartDefaults **defaults)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostAutoStartManager = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (defaults == NULL || *defaults != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /*
     * Lookup HostAutoStartManagerConfig from the HostAutoStartManager because
     * for some reason this is much faster than looking up the same info from
     * the HostSystem config.
     */
    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.defaults") < 0 ||
        esxVI_LookupObjectContentByType
          (ctx, ctx->hostSystem->configManager->autoStartManager,
           "HostAutoStartManager", propertyNameList,
           &hostAutoStartManager, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostAutoStartManager->propSet;
         dynamicProperty != NULL; dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.defaults")) {
            if (esxVI_AutoStartDefaults_CastFromAnyType(dynamicProperty->val,
                                                        defaults) < 0) {
                goto cleanup;
            }

            break;
        }
    }

    if (*defaults == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not retrieve the AutoStartDefaults object"));
        goto cleanup;
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostAutoStartManager);

    return result;
}



int
esxVI_LookupAutoStartPowerInfoList(esxVI_Context *ctx,
                                   esxVI_AutoStartPowerInfo **powerInfoList)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostAutoStartManager = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (powerInfoList == NULL || *powerInfoList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /*
     * Lookup HostAutoStartManagerConfig from the HostAutoStartManager because
     * for some reason this is much faster than looking up the same info from
     * the HostSystem config.
     */
    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.powerInfo") < 0 ||
        esxVI_LookupObjectContentByType
          (ctx, ctx->hostSystem->configManager->autoStartManager,
           "HostAutoStartManager", propertyNameList,
           &hostAutoStartManager, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostAutoStartManager->propSet;
         dynamicProperty != NULL; dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.powerInfo")) {
            if (esxVI_AutoStartPowerInfo_CastListFromAnyType
                  (dynamicProperty->val, powerInfoList) < 0) {
                goto cleanup;
            }

            break;
        }
    }

    result = 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostAutoStartManager);

    return result;
}



int
esxVI_HandleVirtualMachineQuestion
  (esxVI_Context *ctx, esxVI_ManagedObjectReference *virtualMachine,
   esxVI_VirtualMachineQuestionInfo *questionInfo, bool autoAnswer,
   bool *blocked)
{
    int result = -1;
    esxVI_ElementDescription *elementDescription = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    esxVI_ElementDescription *answerChoice = NULL;
    int answerIndex = 0;
    char *possibleAnswers = NULL;

    if (blocked == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *blocked = false;

    if (questionInfo->choice->choiceInfo != NULL) {
        for (elementDescription = questionInfo->choice->choiceInfo;
             elementDescription != NULL;
             elementDescription = elementDescription->_next) {
            virBufferAsprintf(&buffer, "'%s'", elementDescription->label);

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
            goto cleanup;
        }

        possibleAnswers = virBufferContentAndReset(&buffer);
    }

    if (autoAnswer) {
        if (possibleAnswers == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Pending question blocks virtual machine execution, "
                           "question is '%s', no possible answers"),
                         questionInfo->text);

            *blocked = true;
            goto cleanup;
        } else if (answerChoice == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Pending question blocks virtual machine execution, "
                           "question is '%s', possible answers are %s, but no "
                           "default answer is specified"), questionInfo->text,
                         possibleAnswers);

            *blocked = true;
            goto cleanup;
        }

        VIR_INFO("Pending question blocks virtual machine execution, "
                 "question is '%s', possible answers are %s, responding "
                 "with default answer '%s'", questionInfo->text,
                 possibleAnswers, answerChoice->label);

        if (esxVI_AnswerVM(ctx, virtualMachine, questionInfo->id,
                           answerChoice->key) < 0) {
            goto cleanup;
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

        *blocked = true;
        goto cleanup;
    }

    result = 0;

  cleanup:
    if (result < 0) {
        virBufferFreeAndReset(&buffer);
    }

    VIR_FREE(possibleAnswers);

    return result;
}



int
esxVI_WaitForTaskCompletion(esxVI_Context *ctx,
                            esxVI_ManagedObjectReference *task,
                            const unsigned char *virtualMachineUuid,
                            esxVI_Occurrence virtualMachineOccurrence,
                            bool autoAnswer, esxVI_TaskInfoState *finalState,
                            char **errorMessage)
{
    int result = -1;
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
    bool blocked;
    esxVI_TaskInfo *taskInfo = NULL;

    if (errorMessage == NULL || *errorMessage != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    version = strdup("");

    if (version == NULL) {
        virReportOOMError();
        return -1;
    }

    if (esxVI_ObjectSpec_Alloc(&objectSpec) < 0) {
        goto cleanup;
    }

    objectSpec->obj = task;
    objectSpec->skip = esxVI_Boolean_False;

    if (esxVI_PropertySpec_Alloc(&propertySpec) < 0) {
        goto cleanup;
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
        goto cleanup;
    }

    while (state != esxVI_TaskInfoState_Success &&
           state != esxVI_TaskInfoState_Error) {
        esxVI_UpdateSet_Free(&updateSet);

        if (virtualMachineUuid != NULL) {
            if (esxVI_LookupAndHandleVirtualMachineQuestion
                  (ctx, virtualMachineUuid, virtualMachineOccurrence,
                   autoAnswer, &blocked) < 0) {
                /*
                 * FIXME: Disable error reporting here, so possible errors from
                 *        esxVI_LookupTaskInfoByTask() and esxVI_CancelTask()
                 *        don't overwrite the actual error
                 */
                if (esxVI_LookupTaskInfoByTask(ctx, task, &taskInfo)) {
                    goto cleanup;
                }

                if (taskInfo->cancelable == esxVI_Boolean_True) {
                    if (esxVI_CancelTask(ctx, task) < 0 && blocked) {
                        VIR_ERROR(_("Cancelable task is blocked by an "
                                     "unanswered question but cancellation "
                                     "failed"));
                    }
                } else if (blocked) {
                    VIR_ERROR(_("Non-cancelable task is blocked by an "
                                 "unanswered question"));
                }

                /* FIXME: Enable error reporting here again */

                goto cleanup;
            }
        }

        if (esxVI_WaitForUpdates(ctx, version, &updateSet) < 0) {
            goto cleanup;
        }

        VIR_FREE(version);
        version = strdup(updateSet->version);

        if (version == NULL) {
            virReportOOMError();
            goto cleanup;
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
            goto cleanup;
        }
    }

    if (esxVI_DestroyPropertyFilter(ctx, propertyFilter) < 0) {
        VIR_DEBUG("DestroyPropertyFilter failed");
    }

    if (esxVI_TaskInfoState_CastFromAnyType(propertyValue, finalState) < 0) {
        goto cleanup;
    }

    if (*finalState != esxVI_TaskInfoState_Success) {
        if (esxVI_LookupTaskInfoByTask(ctx, task, &taskInfo)) {
            goto cleanup;
        }

        if (taskInfo->error == NULL) {
            *errorMessage = strdup(_("Unknown error"));

            if (*errorMessage == NULL) {
                virReportOOMError();
                goto cleanup;
            }
        } else if (taskInfo->error->localizedMessage == NULL) {
            *errorMessage = strdup(taskInfo->error->fault->_actualType);

            if (*errorMessage == NULL) {
                virReportOOMError();
                goto cleanup;
            }
        } else {
            if (virAsprintf(errorMessage, "%s - %s",
                            taskInfo->error->fault->_actualType,
                            taskInfo->error->localizedMessage) < 0) {
                virReportOOMError();
                goto cleanup;
            }
        }
    }

    result = 0;

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

    memset(parsedHostCpuIdInfo, 0, sizeof(*parsedHostCpuIdInfo));

    parsedHostCpuIdInfo->level = hostCpuIdInfo->level->value;

    for (r = 0; r < 4; ++r) {
        if (strlen(input[r]) != expectedLength) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("HostCpuIdInfo register '%s' has an unexpected length"),
                         name[r]);
            return -1;
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
                return -1;
            }
        }
    }

    return 0;
}



int
esxVI_ProductVersionToDefaultVirtualHWVersion(esxVI_ProductVersion productVersion)
{
    /*
     * virtualHW.version compatibility matrix:
     *
     *              4 7 8   API
     *   ESX 3.5    +       2.5
     *   ESX 4.0    + +     4.0
     *   ESX 4.1    + +     4.1
     *   ESX 5.0    + + +   5.0
     *   GSX 2.0    + +     2.5
     */
    switch (productVersion) {
      case esxVI_ProductVersion_ESX35:
      case esxVI_ProductVersion_VPX25:
        return 4;

      case esxVI_ProductVersion_GSX20:
      case esxVI_ProductVersion_ESX40:
      case esxVI_ProductVersion_ESX41:
      case esxVI_ProductVersion_VPX40:
      case esxVI_ProductVersion_VPX41:
        return 7;

      case esxVI_ProductVersion_ESX4x:
      case esxVI_ProductVersion_VPX4x:
        return 7;

      case esxVI_ProductVersion_ESX50:
      case esxVI_ProductVersion_VPX50:
        return 8;

      case esxVI_ProductVersion_ESX5x:
      case esxVI_ProductVersion_VPX5x:
        return 8;

      default:
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Unexpected product version"));
        return -1;
    }
}




#define ESX_VI__TEMPLATE__PROPERTY__CAST_FROM_ANY_TYPE_IGNORE(_name)          \
    if (STREQ(dynamicProperty->name, #_name)) {                               \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__CAST_FROM_ANY_TYPE(_type, _name)          \
    if (STREQ(dynamicProperty->name, #_name)) {                               \
        if (esxVI_##_type##_CastFromAnyType(dynamicProperty->val,             \
                                            &(*ptrptr)->_name) < 0) {         \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__CAST_LIST_FROM_ANY_TYPE(_type, _name)     \
    if (STREQ(dynamicProperty->name, #_name)) {                               \
        if (esxVI_##_type##_CastListFromAnyType(dynamicProperty->val,         \
                                                &(*ptrptr)->_name) < 0) {     \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__CAST_VALUE_FROM_ANY_TYPE(_type, _name)    \
    if (STREQ(dynamicProperty->name, #_name)) {                               \
        if (esxVI_##_type##_CastValueFromAnyType(dynamicProperty->val,        \
                                                 &(*ptrptr)->_name) < 0) {    \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__LOOKUP(_type, _complete_properties,                 \
                                 _cast_from_anytype)                          \
    int                                                                       \
    esxVI_Lookup##_type(esxVI_Context *ctx, const char* name /* optional */,  \
                        esxVI_ManagedObjectReference *root,                   \
                        esxVI_String *selectedPropertyNameList /* optional */,\
                        esxVI_##_type **ptrptr, esxVI_Occurrence occurrence)  \
    {                                                                         \
        int result = -1;                                                      \
        const char *completePropertyNameValueList = _complete_properties;     \
        esxVI_String *propertyNameList = NULL;                                \
        esxVI_ObjectContent *objectContent = NULL;                            \
        esxVI_ObjectContent *objectContentList = NULL;                        \
        esxVI_DynamicProperty *dynamicProperty = NULL;                        \
                                                                              \
        if (ptrptr == NULL || *ptrptr != NULL) {                              \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        propertyNameList = selectedPropertyNameList;                          \
                                                                              \
        if (propertyNameList == NULL &&                                       \
            esxVI_String_AppendValueListToList                                \
              (&propertyNameList, completePropertyNameValueList) < 0) {       \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        if (esxVI_LookupManagedObjectHelper(ctx, name, root, #_type,          \
                                            propertyNameList, &objectContent, \
                                            &objectContentList,               \
                                            occurrence) < 0) {                \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        if (objectContent == NULL) {                                          \
            /* not found, exit early */                                       \
            result = 0;                                                       \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Alloc(ptrptr) < 0) {                              \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        if (esxVI_ManagedObjectReference_DeepCopy(&(*ptrptr)->_reference,     \
                                                  objectContent->obj) < 0) {  \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        for (dynamicProperty = objectContent->propSet;                        \
             dynamicProperty != NULL;                                         \
             dynamicProperty = dynamicProperty->_next) {                      \
            _cast_from_anytype                                                \
                                                                              \
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);      \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Validate(*ptrptr, selectedPropertyNameList) < 0) {\
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        result = 0;                                                           \
                                                                              \
      cleanup:                                                                \
        if (result < 0) {                                                     \
            esxVI_##_type##_Free(ptrptr);                                     \
        }                                                                     \
                                                                              \
        if (propertyNameList != selectedPropertyNameList) {                   \
            esxVI_String_Free(&propertyNameList);                             \
        }                                                                     \
                                                                              \
        esxVI_ObjectContent_Free(&objectContentList);                         \
                                                                              \
        return result;                                                        \
    }



static int
esxVI_LookupManagedObjectHelper(esxVI_Context *ctx,
                                const char *name /* optional */,
                                esxVI_ManagedObjectReference *root,
                                const char *type,
                                esxVI_String *propertyNameList,
                                esxVI_ObjectContent **objectContent,
                                esxVI_ObjectContent **objectContentList,
                                esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_ObjectContent *candidate = NULL;
    char *name_candidate;

    if (objectContent == NULL || *objectContent != NULL ||
        objectContentList == NULL || *objectContentList != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!esxVI_String_ListContainsValue(propertyNameList, "name")) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Missing 'name' property in %s lookup"), type);
        goto cleanup;
    }

    if (esxVI_LookupObjectContentByType(ctx, root, type, propertyNameList,
                                        objectContentList,
                                        esxVI_Occurrence_OptionalList) < 0) {
        goto cleanup;
    }

    /* Search for a matching item */
    if (name != NULL) {
        for (candidate = *objectContentList; candidate != NULL;
             candidate = candidate->_next) {
            name_candidate = NULL;

            if (esxVI_GetStringValue(candidate, "name", &name_candidate,
                                     esxVI_Occurrence_RequiredItem) < 0) {
                goto cleanup;
            }

            if (STREQ(name_candidate, name)) {
                /* Found item with matching name */
                break;
            }
        }
    } else {
        candidate = *objectContentList;
    }

    if (candidate == NULL) {
        if (occurrence != esxVI_Occurrence_OptionalItem) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Could not find %s with name '%s'"), type, name);
            goto cleanup;
        }

        result = 0;

        goto cleanup;
    }

    result = 0;

  cleanup:
    if (result < 0) {
        esxVI_ObjectContent_Free(objectContentList);
    } else {
        *objectContent = candidate;
    }

    return result;
}



#include "esx_vi.generated.c"
