/*
 * esx_vi.c: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright (C) 2009-2012 Matthias Bolte <matthias.bolte@googlemail.com>
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

#include <libxml/parser.h>
#include <libxml/xpathInternals.h>

#include "virbuffer.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "vmx.h"
#include "virxml.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ESX

VIR_LOG_INIT("esx.esx_vi");

#define ESX_VI__SOAP__RESPONSE_XPATH(_type)                                   \
    ((char *)"/soapenv:Envelope/soapenv:Body/"                                \
               "vim:"_type"Response/vim:returnval")



#define ESX_VI__TEMPLATE__ALLOC(_type)                                        \
    int                                                                       \
    esxVI_##_type##_Alloc(esxVI_##_type **ptrptr)                             \
    {                                                                         \
        if (!ptrptr || *ptrptr) {                                             \
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument")); \
            return -1;                                                  \
        }                                                               \
                                                                        \
        if (VIR_ALLOC(*ptrptr) < 0)                                     \
            return -1;                                                  \
        return 0;                                                       \
    }



#define ESX_VI__TEMPLATE__FREE(_type, _body)                                  \
    void                                                                      \
    esxVI_##_type##_Free(esxVI_##_type **ptrptr)                              \
    {                                                                         \
        esxVI_##_type *item ATTRIBUTE_UNUSED;                                 \
                                                                              \
        if (!ptrptr || !(*ptrptr)) {                                          \
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
    esxVI_MultiCURL *multi = item->multi;

    if (shared) {
        esxVI_SharedCURL_Remove(shared, item);

        if (shared->count == 0) {
            esxVI_SharedCURL_Free(&shared);
        }
    }

    if (multi) {
        esxVI_MultiCURL_Remove(multi, item);

        if (multi->count == 0) {
            esxVI_MultiCURL_Free(&multi);
        }
    }

    if (item->handle) {
        curl_easy_cleanup(item->handle);
    }

    if (item->headers) {
        curl_slist_free_all(item->headers);
    }

    virMutexDestroy(&item->lock);
})

static size_t
esxVI_CURL_ReadString(char *data, size_t size, size_t nmemb, void *userdata)
{
    const char *content = *(const char **)userdata;
    size_t available = 0;
    size_t requested = size * nmemb;

    if (!content) {
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

    *(const char **)userdata = content + requested;

    return requested;
}

static size_t
esxVI_CURL_WriteBuffer(char *data, size_t size, size_t nmemb, void *userdata)
{
    virBufferPtr buffer = userdata;

    if (buffer) {
        /*
         * Using a virBuffer to store the download data limits the downloadable
         * size. This is no problem as esxVI_CURL_Download and esxVI_CURL_Perform
         * are meant to download small things such as VMX files, VMDK metadata
         * files and SOAP responses.
         */
        if (size * nmemb > INT32_MAX / 2 - virBufferUse(buffer)) {
            return 0;
        }

        virBufferAdd(buffer, data, size * nmemb);

        return size * nmemb;
    }

    return 0;
}

#define ESX_VI__CURL__ENABLE_DEBUG_OUTPUT 0

#if ESX_VI__CURL__ENABLE_DEBUG_OUTPUT
static int
esxVI_CURL_Debug(CURL *curl ATTRIBUTE_UNUSED, curl_infotype type,
                 char *info, size_t size, void *userdata ATTRIBUTE_UNUSED)
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

    if (!virStrncpy(buffer, info, size, size + 1)) {
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("curl_easy_perform() returned an error: %s (%d) : %s"),
                       curl_easy_strerror(errorCode), errorCode, curl->error);
        return -1;
    }

    errorCode = curl_easy_getinfo(curl->handle, CURLINFO_RESPONSE_CODE,
                                  &responseCode);

    if (errorCode != CURLE_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned an "
                         "error: %s (%d) : %s"), curl_easy_strerror(errorCode),
                       errorCode, curl->error);
        return -1;
    }

    if (responseCode < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned a "
                         "negative response code"));
        return -1;
    }

    if (responseCode == 301) {
#if LIBCURL_VERSION_NUM >= 0x071202 /* 7.18.2 */
        errorCode = curl_easy_getinfo(curl->handle, CURLINFO_REDIRECT_URL,
                                      &redirectUrl);

        if (errorCode != CURLE_OK) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("curl_easy_getinfo(CURLINFO_REDIRECT_URL) returned "
                             "an error: %s (%d) : %s"),
                           curl_easy_strerror(errorCode),
                           errorCode, curl->error);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("The server redirects from '%s' to '%s'"), url,
                           redirectUrl);
        }
#else
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("The server redirects from '%s'"), url);
#endif

        return -1;
    }

    return responseCode;
}

int
esxVI_CURL_Connect(esxVI_CURL *curl, esxUtil_ParsedUri *parsedUri)
{
    if (curl->handle) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call"));
        return -1;
    }

    curl->handle = curl_easy_init();

    if (!curl->handle) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    if (!curl->headers) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not build CURL header list"));
        return -1;
    }

    curl_easy_setopt(curl->handle, CURLOPT_USERAGENT, "libvirt-esx");
    curl_easy_setopt(curl->handle, CURLOPT_NOSIGNAL, 1);
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
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize CURL mutex"));
        return -1;
    }

    return 0;
}

int
esxVI_CURL_Download(esxVI_CURL *curl, const char *url, char **content,
                    unsigned long long offset, unsigned long long *length)
{
    char *range = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    int responseCode = 0;

    if (!content || *content) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (length && *length > 0) {
        /*
         * Using a virBuffer to store the download data limits the downloadable
         * size. This is no problem as esxVI_CURL_Download is meant to download
         * small things such as VMX of VMDK metadata files.
         */
        if (*length > INT32_MAX / 2) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Download length it too large"));
            return -1;
        }

        if (virAsprintf(&range, "%llu-%llu", offset, offset + *length - 1) < 0)
            goto cleanup;
    } else if (offset > 0) {
        if (virAsprintf(&range, "%llu-", offset) < 0)
            goto cleanup;
    }

    virMutexLock(&curl->lock);

    curl_easy_setopt(curl->handle, CURLOPT_URL, url);
    curl_easy_setopt(curl->handle, CURLOPT_RANGE, range);
    curl_easy_setopt(curl->handle, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 0);
    curl_easy_setopt(curl->handle, CURLOPT_HTTPGET, 1);

    responseCode = esxVI_CURL_Perform(curl, url);

    virMutexUnlock(&curl->lock);

    if (responseCode < 0) {
        goto cleanup;
    } else if (responseCode != 200 && responseCode != 206) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("HTTP response code %d for download from '%s'"),
                       responseCode, url);
        goto cleanup;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    if (length) {
        *length = virBufferUse(&buffer);
    }

    *content = virBufferContentAndReset(&buffer);

 cleanup:
    VIR_FREE(range);

    if (!(*content)) {
        virBufferFreeAndReset(&buffer);
        return -1;
    }

    return 0;
}

int
esxVI_CURL_Upload(esxVI_CURL *curl, const char *url, const char *content)
{
    int responseCode = 0;

    if (!content) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virMutexLock(&curl->lock);

    curl_easy_setopt(curl->handle, CURLOPT_URL, url);
    curl_easy_setopt(curl->handle, CURLOPT_RANGE, NULL);
    curl_easy_setopt(curl->handle, CURLOPT_READDATA, &content);
    curl_easy_setopt(curl->handle, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl->handle, CURLOPT_INFILESIZE, strlen(content));

    responseCode = esxVI_CURL_Perform(curl, url);

    virMutexUnlock(&curl->lock);

    if (responseCode < 0) {
        return -1;
    } else if (responseCode != 200 && responseCode != 201) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    size_t i;
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
    size_t i;
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
    size_t i;

    if (item->count > 0) {
        /* Better leak than crash */
        VIR_ERROR(_("Trying to free SharedCURL object that is still in use"));
        return;
    }

    if (item->handle) {
        curl_share_cleanup(item->handle);
    }

    for (i = 0; i < ARRAY_CARDINALITY(item->locks); ++i) {
        virMutexDestroy(&item->locks[i]);
    }
})

int
esxVI_SharedCURL_Add(esxVI_SharedCURL *shared, esxVI_CURL *curl)
{
    size_t i;

    if (!curl->handle) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot share uninitialized CURL handle"));
        return -1;
    }

    if (curl->shared) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot share CURL handle that is already shared"));
        return -1;
    }

    if (!shared->handle) {
        shared->handle = curl_share_init();

        if (!shared->handle) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not initialize a CURL (share) mutex"));
                return -1;
            }
        }
    }

    virMutexLock(&curl->lock);

    curl_easy_setopt(curl->handle, CURLOPT_SHARE, shared->handle);

    curl->shared = shared;
    ++shared->count;

    virMutexUnlock(&curl->lock);

    return 0;
}

int
esxVI_SharedCURL_Remove(esxVI_SharedCURL *shared, esxVI_CURL *curl)
{
    if (!curl->handle) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot unshare uninitialized CURL handle"));
        return -1;
    }

    if (!curl->shared) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot unshare CURL handle that is not shared"));
        return -1;
    }

    if (curl->shared != shared) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("CURL (share) mismatch"));
        return -1;
    }

    virMutexLock(&curl->lock);

    curl_easy_setopt(curl->handle, CURLOPT_SHARE, NULL);

    curl->shared = NULL;
    --shared->count;

    virMutexUnlock(&curl->lock);

    return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * MultiCURL
 */

/* esxVI_MultiCURL_Alloc */
ESX_VI__TEMPLATE__ALLOC(MultiCURL)

/* esxVI_MultiCURL_Free */
ESX_VI__TEMPLATE__FREE(MultiCURL,
{
    if (item->count > 0) {
        /* Better leak than crash */
        VIR_ERROR(_("Trying to free MultiCURL object that is still in use"));
        return;
    }

    if (item->handle) {
        curl_multi_cleanup(item->handle);
    }
})

int
esxVI_MultiCURL_Add(esxVI_MultiCURL *multi, esxVI_CURL *curl)
{
    if (!curl->handle) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot add uninitialized CURL handle to a multi handle"));
        return -1;
    }

    if (curl->multi) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot add CURL handle to a multi handle twice"));
        return -1;
    }

    if (!multi->handle) {
        multi->handle = curl_multi_init();

        if (!multi->handle) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not initialize CURL (multi)"));
            return -1;
        }
    }

    virMutexLock(&curl->lock);

    curl_multi_add_handle(multi->handle, curl->handle);

    curl->multi = multi;
    ++multi->count;

    virMutexUnlock(&curl->lock);

    return 0;
}

int
esxVI_MultiCURL_Remove(esxVI_MultiCURL *multi, esxVI_CURL *curl)
{
    if (!curl->handle) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot remove uninitialized CURL handle from a "
                         "multi handle"));
        return -1;
    }

    if (!curl->multi) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot remove CURL handle from a multi handle when it "
                         "wasn't added before"));
        return -1;
    }

    if (curl->multi != multi) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("CURL (multi) mismatch"));
        return -1;
    }

    virMutexLock(&curl->lock);

    curl_multi_remove_handle(multi->handle, curl->handle);

    curl->multi = NULL;
    --multi->count;

    virMutexUnlock(&curl->lock);

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
    if (item->sessionLock) {
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
    esxVI_SelectionSpec_Free(&item->selectSet_datacenterToNetwork);
})

int
esxVI_Context_Connect(esxVI_Context *ctx, const char *url,
                      const char *ipAddress, const char *username,
                      const char *password, esxUtil_ParsedUri *parsedUri)
{
    if (!ctx || !url || !ipAddress || !username ||
        !password || ctx->url || ctx->service || ctx->curl) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_CURL_Alloc(&ctx->curl) < 0 ||
        esxVI_CURL_Connect(ctx->curl, parsedUri) < 0 ||
        VIR_STRDUP(ctx->url, url) < 0 ||
        VIR_STRDUP(ctx->ipAddress, ipAddress) < 0 ||
        VIR_STRDUP(ctx->username, username) < 0 ||
        VIR_STRDUP(ctx->password, password) < 0) {
        return -1;
    }

    if (VIR_ALLOC(ctx->sessionLock) < 0)
        return -1;

    if (virMutexInit(ctx->sessionLock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        } else if (STRPREFIX(ctx->service->about->apiVersion, "5.0")) {
            ctx->apiVersion = esxVI_APIVersion_50;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "5.1")) {
            ctx->apiVersion = esxVI_APIVersion_51;
        } else if (STRPREFIX(ctx->service->about->apiVersion, "5.")) {
            ctx->apiVersion = esxVI_APIVersion_5x;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting VI API major/minor version '2.5', '4.x' or "
                             "'5.x' but found '%s'"), ctx->service->about->apiVersion);
            return -1;
        }

        if (STREQ(ctx->service->about->productLineId, "gsx")) {
            if (STRPREFIX(ctx->service->about->version, "2.0")) {
                ctx->productVersion = esxVI_ProductVersion_GSX20;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
            } else if (STRPREFIX(ctx->service->about->version, "5.0")) {
                ctx->productVersion = esxVI_ProductVersion_ESX50;
            } else if (STRPREFIX(ctx->service->about->version, "5.1")) {
                ctx->productVersion = esxVI_ProductVersion_ESX51;
            } else if (STRPREFIX(ctx->service->about->version, "5.")) {
                ctx->productVersion = esxVI_ProductVersion_ESX5x;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
            } else if (STRPREFIX(ctx->service->about->version, "5.0")) {
                ctx->productVersion = esxVI_ProductVersion_VPX50;
            } else if (STRPREFIX(ctx->service->about->version, "5.1")) {
                ctx->productVersion = esxVI_ProductVersion_VPX51;
            } else if (STRPREFIX(ctx->service->about->version, "5.")) {
                ctx->productVersion = esxVI_ProductVersion_VPX5x;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Expecting VPX major/minor version '2.5', '4.x' "
                                 "or '5.x' but found '%s'"),
                               ctx->service->about->version);
                return -1;
            }
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting product 'gsx' or 'esx' or 'embeddedEsx' "
                             "or 'vpx' but found '%s'"),
                           ctx->service->about->productLineId);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (VIR_STRDUP(ctx->datacenterPath, ctx->datacenter->name) < 0)
        return -1;

    /* Lookup (Cluster)ComputeResource */
    if (esxVI_LookupComputeResource(ctx, NULL, ctx->datacenter->hostFolder,
                                    NULL, &ctx->computeResource,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        return -1;
    }

    if (!ctx->computeResource->resourcePool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not retrieve resource pool"));
        return -1;
    }

    if (VIR_STRDUP(ctx->computeResourcePath, ctx->computeResource->name) < 0)
        return -1;

    /* Lookup HostSystem */
    if (esxVI_LookupHostSystem(ctx, NULL, ctx->computeResource->_reference,
                               NULL, &ctx->hostSystem,
                               esxVI_Occurrence_RequiredItem) < 0) {
        return -1;
    }

    if (VIR_STRDUP(ctx->hostSystemName, ctx->hostSystem->name) < 0)
        return -1;

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

    if (VIR_STRDUP(tmp, path) < 0)
        goto cleanup;

    /* Lookup Datacenter */
    item = strtok_r(tmp, "/", &saveptr);

    if (!item) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Path '%s' does not specify a datacenter"), path);
        goto cleanup;
    }

    root = ctx->service->rootFolder;

    while (!ctx->datacenter && item) {
        esxVI_Folder_Free(&folder);

        /* Try to lookup item as a folder */
        if (esxVI_LookupFolder(ctx, item, root, NULL, &folder,
                               esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (folder) {
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

    if (!ctx->datacenter) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find datacenter specified in '%s'"), path);
        goto cleanup;
    }

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    ctx->datacenterPath = virBufferContentAndReset(&buffer);

    /* Lookup (Cluster)ComputeResource */
    if (!item) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Path '%s' does not specify a compute resource"), path);
        goto cleanup;
    }

    if (root != ctx->service->rootFolder) {
        esxVI_ManagedObjectReference_Free(&root);
    }

    root = ctx->datacenter->hostFolder;

    while (!ctx->computeResource && item) {
        esxVI_Folder_Free(&folder);

        /* Try to lookup item as a folder */
        if (esxVI_LookupFolder(ctx, item, root, NULL, &folder,
                               esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (folder) {
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

    if (!ctx->computeResource) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find compute resource specified in '%s'"),
                       path);
        goto cleanup;
    }

    if (!ctx->computeResource->resourcePool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        if (!item) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Path '%s' does not specify a host system"), path);
            goto cleanup;
        }

        /* The path specified a cluster, it has to specify a host system too */
        previousItem = item;
        item = strtok_r(NULL, "/", &saveptr);
    }

    if (item) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Path '%s' ends with an excess item"), path);
        goto cleanup;
    }

    if (VIR_STRDUP(ctx->hostSystemName, previousItem) < 0)
        goto cleanup;

    if (esxVI_LookupHostSystem(ctx, ctx->hostSystemName,
                               ctx->computeResource->_reference, NULL,
                               &ctx->hostSystem,
                               esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!ctx->hostSystem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find host system specified in '%s'"), path);
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virBufferFreeAndReset(&buffer);
    }

    if (root != ctx->service->rootFolder &&
        (!ctx->datacenter || root != ctx->datacenter->hostFolder)) {
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

    if (!ctx->computeResource->resourcePool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    if (!request || !response || *response) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_Response_Alloc(response) < 0) {
        return -1;
    }

    virMutexLock(&ctx->curl->lock);

    curl_easy_setopt(ctx->curl->handle, CURLOPT_URL, ctx->url);
    curl_easy_setopt(ctx->curl->handle, CURLOPT_RANGE, NULL);
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

        if (!(*response)->document) {
            goto cleanup;
        }

        xmlXPathRegisterNs(xpathContext, BAD_CAST "soapenv",
                           BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/");
        xmlXPathRegisterNs(xpathContext, BAD_CAST "vim", BAD_CAST "urn:vim25");

        if ((*response)->responseCode == 500) {
            (*response)->node =
              virXPathNode("/soapenv:Envelope/soapenv:Body/soapenv:Fault",
                           xpathContext);

            if (!(*response)->node) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("HTTP response code %d for call to '%s'. "
                                 "Fault is unknown, XPath evaluation failed"),
                               (*response)->responseCode, methodName);
                goto cleanup;
            }

            if (esxVI_Fault_Deserialize((*response)->node, &fault) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("HTTP response code %d for call to '%s'. "
                                 "Fault is unknown, deserialization failed"),
                               (*response)->responseCode, methodName);
                goto cleanup;
            }

            virReportError(VIR_ERR_INTERNAL_ERROR,
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
                            methodName) < 0)
                goto cleanup;

            responseNode = virXPathNode(xpathExpression, xpathContext);

            if (!responseNode) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("XPath evaluation of response for call to '%s' "
                                 "failed"), methodName);
                goto cleanup;
            }

            xpathContext->node = responseNode;
            (*response)->node = virXPathNode("./vim:returnval", xpathContext);

            switch (occurrence) {
              case esxVI_Occurrence_RequiredItem:
                if (!(*response)->node) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Call to '%s' returned an empty result, "
                                     "expecting a non-empty result"), methodName);
                    goto cleanup;
                } else if ((*response)->node->next) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Call to '%s' returned a list, expecting "
                                     "exactly one item"), methodName);
                    goto cleanup;
                }

                break;

              case esxVI_Occurrence_RequiredList:
                if (!(*response)->node) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Call to '%s' returned an empty result, "
                                     "expecting a non-empty result"), methodName);
                    goto cleanup;
                }

                break;

              case esxVI_Occurrence_OptionalItem:
                if ((*response)->node &&
                    (*response)->node->next) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Call to '%s' returned a list, expecting "
                                     "exactly one item"), methodName);
                    goto cleanup;
                }

                break;

              case esxVI_Occurrence_OptionalList:
                /* Any amount of items is valid */
                break;

              case esxVI_Occurrence_None:
                if ((*response)->node) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Call to '%s' returned something, expecting "
                                     "an empty result"), methodName);
                    goto cleanup;
                }

                break;

              default:
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Invalid argument (occurrence)"));
                goto cleanup;
            }
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    size_t i;

    if (!anyType || !value) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *value = 0; /* undefined */

    if (anyType->type != enumeration->type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting type '%s' but found '%s'"),
                       esxVI_Type_ToString(enumeration->type),
                       esxVI_AnyType_TypeToString(anyType));
        return -1;
    }

    for (i = 0; enumeration->values[i].name; ++i) {
        if (STREQ(anyType->value, enumeration->values[i].name)) {
            *value = enumeration->values[i].value;
            return 0;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unknown value '%s' for %s"), anyType->value,
                   esxVI_Type_ToString(enumeration->type));

    return -1;
}

int
esxVI_Enumeration_Serialize(const esxVI_Enumeration *enumeration,
                            int value, const char *element, virBufferPtr output)
{
    size_t i;
    const char *name = NULL;

    if (!element || !output) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (value == 0) { /* undefined */
        return 0;
    }

    for (i = 0; enumeration->values[i].name; ++i) {
        if (value == enumeration->values[i].value) {
            name = enumeration->values[i].name;
            break;
        }
    }

    if (!name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
    size_t i;
    int result = -1;
    char *name = NULL;

    if (!value) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *value = 0; /* undefined */

    if (esxVI_String_DeserializeValue(node, &name) < 0) {
        return -1;
    }

    for (i = 0; enumeration->values[i].name; ++i) {
        if (STREQ(name, enumeration->values[i].name)) {
            *value = enumeration->values[i].value;
            result = 0;
            break;
        }
    }

    if (result < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Unknown value '%s' for %s"),
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

    if (!list || !item) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!(*list)) {
        *list = item;
        return 0;
    }

    next = *list;

    while (next->_next) {
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

    if (!destList || *destList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (src = srcList; src; src = src->_next) {
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

    if (!list || *list || !castFromAnyTypeFunc || !freeFunc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!anyType) {
        return 0;
    }

    if (! STRPREFIX(anyType->other, "ArrayOf")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting type to begin with 'ArrayOf' but found '%s'"),
                       anyType->other);
        return -1;
    }

    for (childNode = anyType->node->children; childNode;
         childNode = childNode->next) {
        if (childNode->type != XML_ELEMENT_NODE) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (!element || !output || !serializeFunc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!list) {
        return 0;
    }

    for (item = list; item; item = item->_next) {
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

    if (!list || *list || !deserializeFunc || !freeFunc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!node) {
        return 0;
    }

    for (; node; node = node->next) {
        if (node->type != XML_ELEMENT_NODE) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
esxVI_BuildSelectSet(esxVI_SelectionSpec **selectSet,
                     const char *name, const char *type,
                     const char *path, const char *selectSetNames)
{
    esxVI_TraversalSpec *traversalSpec = NULL;
    esxVI_SelectionSpec *selectionSpec = NULL;
    const char *currentSelectSetName = NULL;

    if (!selectSet) {
        /*
         * Don't check for *selectSet != NULL here because selectSet is a list
         * and might contain items already. This function appends to selectSet.
         */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_TraversalSpec_Alloc(&traversalSpec) < 0 ||
        VIR_STRDUP(traversalSpec->name, name) < 0 ||
        VIR_STRDUP(traversalSpec->type, type) < 0 ||
        VIR_STRDUP(traversalSpec->path, path) < 0) {
        goto failure;
    }

    traversalSpec->skip = esxVI_Boolean_False;

    if (selectSetNames) {
        currentSelectSetName = selectSetNames;

        while (currentSelectSetName && *currentSelectSetName != '\0') {
            if (esxVI_SelectionSpec_Alloc(&selectionSpec) < 0 ||
                VIR_STRDUP(selectionSpec->name, currentSelectSetName) < 0 ||
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

    /* Datacenter -> network (Network) */
    if (esxVI_BuildSelectSet(&ctx->selectSet_datacenterToNetwork,
                             "datacenterToNetwork",
                             "Datacenter", "network", NULL) < 0) {
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

    if (!ctx->sessionLock) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call, no mutex"));
        return -1;
    }

    virMutexLock(ctx->sessionLock);

    if (!ctx->session) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid call, no session"));
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

        for (dynamicProperty = sessionManager->propSet; dynamicProperty;
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

        if (!currentSession) {
            esxVI_UserSession_Free(&ctx->session);

            if (esxVI_Login(ctx, ctx->username, ctx->password, NULL,
                            &ctx->session) < 0) {
                goto cleanup;
            }
        } else if (STRNEQ(ctx->session->key, currentSession->key)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
    bool objectSpec_isAppended = false;
    esxVI_PropertySpec *propertySpec = NULL;
    bool propertySpec_isAppended = false;
    esxVI_PropertyFilterSpec *propertyFilterSpec = NULL;

    if (!objectContentList || *objectContentList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Invalid lookup of '%s' from '%s'"),
                               type, root->type);
                goto cleanup;
            }
        } else if (STREQ(root->type, "Datacenter")) {
            if (STREQ(type, "Network")) {
                objectSpec->selectSet = ctx->selectSet_datacenterToNetwork;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Invalid lookup of '%s' from '%s'"),
                               type, root->type);
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
                                        propertySpec) < 0) {
        goto cleanup;
    }

    propertySpec_isAppended = true;

    if (esxVI_ObjectSpec_AppendToList(&propertyFilterSpec->objectSet,
                                      objectSpec) < 0) {
        goto cleanup;
    }

    objectSpec_isAppended = true;

    if (esxVI_RetrieveProperties(ctx, propertyFilterSpec,
                                 objectContentList) < 0) {
        goto cleanup;
    }

    if (!(*objectContentList)) {
        switch (occurrence) {
          case esxVI_Occurrence_OptionalItem:
          case esxVI_Occurrence_OptionalList:
            result = 0;
            break;

          case esxVI_Occurrence_RequiredItem:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not lookup '%s' from '%s'"),
                           type, root->type);
            break;

          case esxVI_Occurrence_RequiredList:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not lookup '%s' list from '%s'"),
                           type, root->type);
            break;

          default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
     * objectSpec cannot be NULL here.
     */
    objectSpec->obj = NULL;
    objectSpec->selectSet = NULL;

    if (propertySpec) {
        propertySpec->type = NULL;
        propertySpec->pathSet = NULL;
    }

    if (!objectSpec_isAppended) {
        esxVI_ObjectSpec_Free(&objectSpec);
    }

    if (!propertySpec_isAppended) {
        esxVI_PropertySpec_Free(&propertySpec);
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

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            return esxVI_ManagedEntityStatus_CastFromAnyType
                     (dynamicProperty->val, managedEntityStatus);
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Missing '%s' property while looking for "
                     "ManagedEntityStatus"), propertyName);

    return -1;
}



int
esxVI_GetVirtualMachinePowerState(esxVI_ObjectContent *virtualMachine,
                                  esxVI_VirtualMachinePowerState *powerState)
{
    esxVI_DynamicProperty *dynamicProperty;

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.powerState")) {
            return esxVI_VirtualMachinePowerState_CastFromAnyType
                     (dynamicProperty->val, powerState);
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Missing 'runtime.powerState' property"));

    return -1;
}



int
esxVI_GetVirtualMachineQuestionInfo
  (esxVI_ObjectContent *virtualMachine,
   esxVI_VirtualMachineQuestionInfo **questionInfo)
{
    esxVI_DynamicProperty *dynamicProperty;

    if (!questionInfo || *questionInfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
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

    if (!value || *value != esxVI_Boolean_Undefined) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (!value || *value) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            if (esxVI_Long_CastFromAnyType(dynamicProperty->val, value) < 0) {
                return -1;
            }

            break;
        }
    }

    if (!(*value) && occurrence == esxVI_Occurrence_RequiredItem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (!value || *value) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
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

    if (!(*value) && occurrence == esxVI_Occurrence_RequiredItem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (!value || *value) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, propertyName)) {
            if (esxVI_ManagedObjectReference_CastFromAnyType
                  (dynamicProperty->val, value) < 0) {
                return -1;
            }

            break;
        }
    }

    if (!(*value) && occurrence == esxVI_Occurrence_RequiredItem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    for (virtualMachine = virtualMachineList; virtualMachine;
         virtualMachine = virtualMachine->_next) {
        for (dynamicProperty = virtualMachine->propSet;
             dynamicProperty;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "runtime.powerState")) {
                if (esxVI_VirtualMachinePowerState_CastFromAnyType
                      (dynamicProperty->val, &powerState_) < 0) {
                    goto cleanup;
                }

                if ((!inverse && powerState_ == powerState) ||
                    (inverse && powerState_ != powerState)) {
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
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("ObjectContent does not reference a virtual machine"));
        return -1;
    }

    if (id) {
        if (esxUtil_ParseVirtualMachineIDString
              (virtualMachine->obj->value, id) < 0 || *id <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse positive integer from '%s'"),
                           virtualMachine->obj->value);
            goto failure;
        }
    }

    if (name) {
        if (*name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
            goto failure;
        }

        for (dynamicProperty = virtualMachine->propSet;
             dynamicProperty;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "name")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto failure;
                }

                if (VIR_STRDUP(*name, dynamicProperty->val->string) < 0)
                    goto failure;

                if (virVMXUnescapeHexPercent(*name) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Domain name contains invalid escape sequence"));
                    goto failure;
                }

                break;
            }
        }

        if (!(*name)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not get name of virtual machine"));
            goto failure;
        }
    }

    if (uuid) {
        if (esxVI_GetManagedEntityStatus(virtualMachine, "configStatus",
                                         &configStatus) < 0) {
            goto failure;
        }

        if (configStatus == esxVI_ManagedEntityStatus_Green) {
            for (dynamicProperty = virtualMachine->propSet;
                 dynamicProperty;
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

            if (!uuid_string) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not get UUID of virtual machine"));
                goto failure;
            }

            if (virUUIDParse(uuid_string, uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
    if (name) {
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

    for (snapshotTree = snapshotTreeList; snapshotTree;
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
    size_t i;
    esxVI_VirtualMachineSnapshotTree *snapshotTree;

    for (snapshotTree = snapshotTreeList;
         snapshotTree && count < nameslen;
         snapshotTree = snapshotTree->_next) {
        if (!(leaves && snapshotTree->childSnapshotList)) {
            if (VIR_STRDUP(names[count], snapshotTree->name) < 0)
                goto failure;

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

    if (!snapshotTree || *snapshotTree ||
        (snapshotTreeParent && *snapshotTreeParent)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (candidate = snapshotTreeList; candidate;
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
            if (snapshotTreeParent && !(*snapshotTreeParent)) {
                *snapshotTreeParent = candidate;
            }

            return 1;
        }
    }

    if (occurrence == esxVI_Occurrence_OptionalItem) {
        return 0;
    } else {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
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

    if (!snapshotTree || *snapshotTree) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    for (candidate = snapshotTreeList; candidate;
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

    virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
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

    if (!virtualMachine || *virtualMachine) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virUUIDFormat(uuid, uuid_string);

    if (esxVI_FindByUuid(ctx, ctx->datacenter->_reference, uuid_string,
                         esxVI_Boolean_True, esxVI_Boolean_Undefined,
                         &managedObjectReference) < 0) {
        return -1;
    }

    if (!managedObjectReference) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            virReportError(VIR_ERR_NO_DOMAIN,
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

    if (!virtualMachine || *virtualMachine) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_DeepCopyList(&completePropertyNameList,
                                  propertyNameList) < 0 ||
        esxVI_String_AppendValueToList(&completePropertyNameList, "name") < 0 ||
        esxVI_LookupVirtualMachineList(ctx, completePropertyNameList,
                                       &virtualMachineList) < 0) {
        goto cleanup;
    }

    for (candidate = virtualMachineList; candidate;
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

    if (!(*virtualMachine)) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            virReportError(VIR_ERR_NO_DOMAIN,
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

    if (questionInfo &&
        esxVI_HandleVirtualMachineQuestion(ctx, (*virtualMachine)->obj,
                                           questionInfo, autoAnswer,
                                           &blocked) < 0) {
        goto cleanup;
    }

    if (pendingTaskInfoList) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
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

    if (!datastore || *datastore) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
    for (candidate = datastoreList; candidate;
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

    if (!(*datastore) && occurrence != esxVI_Occurrence_OptionalItem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (!datastore || *datastore) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
    for (candidate = datastoreList; candidate;
         candidate = candidate->_next) {
        esxVI_DatastoreHostMount_Free(&datastoreHostMountList);

        for (dynamicProperty = candidate->propSet; dynamicProperty;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "host")) {
                if (esxVI_DatastoreHostMount_CastListFromAnyType
                      (dynamicProperty->val, &datastoreHostMountList) < 0) {
                    goto cleanup;
                }

                break;
            }
        }

        if (!datastoreHostMountList) {
            continue;
        }

        for (datastoreHostMount = datastoreHostMountList;
             datastoreHostMount;
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

    if (!(*datastore) && occurrence != esxVI_Occurrence_OptionalItem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
                               esxVI_DatastoreHostMount **hostMount,
                               esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *objectContent = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_DatastoreHostMount *hostMountList = NULL;
    esxVI_DatastoreHostMount *candidate = NULL;

    if (!hostMount || *hostMount) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "host") < 0 ||
        esxVI_LookupObjectContentByType(ctx, datastore, "Datastore",
                                        propertyNameList, &objectContent,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
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

    for (candidate = hostMountList; candidate;
         candidate = candidate->_next) {
        if (STRNEQ(ctx->hostSystem->_reference->value, candidate->key->value)) {
            continue;
        }

        if (esxVI_DatastoreHostMount_DeepCopy(hostMount, candidate) < 0) {
            goto cleanup;
        }

        break;
    }

    if (!(*hostMount) && occurrence == esxVI_Occurrence_RequiredItem) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    if (!taskInfo || *taskInfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "info") < 0 ||
        esxVI_LookupObjectContentByType(ctx, task, "Task", propertyNameList,
                                        &objectContent,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = objectContent->propSet; dynamicProperty;
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

    if (!pendingTaskInfoList || *pendingTaskInfoList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /* Get list of recent tasks */
    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
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
    for (recentTask = recentTaskList; recentTask;
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

    if (virtualMachine) {
        if (esxVI_GetVirtualMachineQuestionInfo(virtualMachine,
                                                &questionInfo) < 0) {
            goto cleanup;
        }

        if (questionInfo &&
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

    if (!rootSnapshotTreeList || *rootSnapshotTreeList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "snapshot.rootSnapshotList") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, virtualMachineUuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
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

    if (!currentSnapshotTree || *currentSnapshotTree) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
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

    if (!currentSnapshot) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                           _("Domain has no current snapshot"));
            goto cleanup;
        }
    }

    if (!rootSnapshotTreeList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    if (!fileInfo || *fileInfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
                        datastoreName) < 0)
            goto cleanup;

        if (VIR_STRDUP(fileName, directoryAndFileName) < 0) {
            goto cleanup;
        }
    } else {
        if (virAsprintf(&datastorePathWithoutFileName, "[%s] %s",
                        datastoreName, directoryName) < 0)
            goto cleanup;

        length = strlen(directoryName);

        if (directoryAndFileName[length] != '/' ||
            directoryAndFileName[length + 1] == '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Datastore path '%s' doesn't reference a file"),
                           datastorePath);
            goto cleanup;
        }

        if (VIR_STRDUP(fileName, directoryAndFileName + length + 1) < 0) {
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
        folderFileQuery = NULL;
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
        vmDiskFileQuery = NULL;

        if (esxVI_IsoImageFileQuery_Alloc(&isoImageFileQuery) < 0 ||
            esxVI_FileQuery_AppendToList
              (&searchSpec->query,
               esxVI_FileQuery_DynamicCast(isoImageFileQuery)) < 0) {
            goto cleanup;
        }
        isoImageFileQuery = NULL;

        if (esxVI_FloppyImageFileQuery_Alloc(&floppyImageFileQuery) < 0 ||
            esxVI_FileQuery_AppendToList
              (&searchSpec->query,
               esxVI_FileQuery_DynamicCast(floppyImageFileQuery)) < 0) {
            goto cleanup;
        }
        floppyImageFileQuery = NULL;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    if (!searchResults->file) {
        if (occurrence == esxVI_Occurrence_OptionalItem) {
            result = 0;

            goto cleanup;
        } else {
            virReportError(VIR_ERR_NO_STORAGE_VOL,
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
    if (searchSpec && searchSpec->matchPattern) {
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
    esxVI_FolderFileQuery_Free(&folderFileQuery);
    esxVI_VmDiskFileQuery_Free(&vmDiskFileQuery);
    esxVI_IsoImageFileQuery_Free(&isoImageFileQuery);
    esxVI_FloppyImageFileQuery_Free(&floppyImageFileQuery);

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

    if (!searchResultsList || *searchResultsList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
    vmDiskFileQuery = NULL;

    if (esxVI_IsoImageFileQuery_Alloc(&isoImageFileQuery) < 0 ||
        esxVI_FileQuery_AppendToList
          (&searchSpec->query,
           esxVI_FileQuery_DynamicCast(isoImageFileQuery)) < 0) {
        goto cleanup;
    }
    isoImageFileQuery = NULL;

    if (esxVI_FloppyImageFileQuery_Alloc(&floppyImageFileQuery) < 0 ||
        esxVI_FileQuery_AppendToList
          (&searchSpec->query,
           esxVI_FileQuery_DynamicCast(floppyImageFileQuery)) < 0) {
        goto cleanup;
    }
    floppyImageFileQuery = NULL;

    /* Search datastore for files */
    if (virAsprintf(&datastorePath, "[%s]", datastoreName) < 0)
        goto cleanup;

    if (esxVI_SearchDatastoreSubFolders_Task(ctx, hostDatastoreBrowser,
                                             datastorePath, searchSpec,
                                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(ctx, task, NULL, esxVI_Occurrence_None,
                                    false, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not search in datastore '%s': %s"),
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
    esxVI_VmDiskFileQuery_Free(&vmDiskFileQuery);
    esxVI_IsoImageFileQuery_Free(&isoImageFileQuery);
    esxVI_FloppyImageFileQuery_Free(&floppyImageFileQuery);

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

    if (!key || *key) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (ctx->hasQueryVirtualDiskUuid) {
        if (esxVI_LookupFileInfoByDatastorePath
              (ctx, datastorePath, false, &fileInfo,
               esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        if (esxVI_VmDiskFileInfo_DynamicCast(fileInfo)) {
            /* VirtualDisks have a UUID, use it as key */
            if (esxVI_QueryVirtualDiskUuid(ctx, datastorePath,
                                           ctx->datacenter->_reference,
                                           &uuid_string) < 0) {
                goto cleanup;
            }

            if (VIR_ALLOC_N(*key, VIR_UUID_STRING_BUFLEN) < 0)
                goto cleanup;

            if (esxUtil_ReformatUuid(uuid_string, *key) < 0) {
                goto cleanup;
            }
        }
    }

    if (!(*key)) {
        /* Other files don't have a UUID, fall back to the path as key */
        if (VIR_STRDUP(*key, datastorePath) < 0) {
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

    if (!defaults || *defaults) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
         dynamicProperty; dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.defaults")) {
            if (esxVI_AutoStartDefaults_CastFromAnyType(dynamicProperty->val,
                                                        defaults) < 0) {
                goto cleanup;
            }

            break;
        }
    }

    if (!(*defaults)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    if (!powerInfoList || *powerInfoList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
         dynamicProperty; dynamicProperty = dynamicProperty->_next) {
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
esxVI_LookupPhysicalNicList(esxVI_Context *ctx,
                            esxVI_PhysicalNic **physicalNicList)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (!physicalNicList || *physicalNicList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.network.pnic") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.network.pnic")) {
            if (esxVI_PhysicalNic_CastListFromAnyType(dynamicProperty->val,
                                                      physicalNicList) < 0) {
                goto cleanup;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}



int
esxVI_LookupPhysicalNicByName(esxVI_Context *ctx, const char *name,
                              esxVI_PhysicalNic **physicalNic,
                              esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_PhysicalNic *physicalNicList = NULL;
    esxVI_PhysicalNic *candidate = NULL;

    if (!physicalNic || *physicalNic) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_LookupPhysicalNicList(ctx, &physicalNicList) < 0) {
        goto cleanup;
    }

    /* Search for a matching physical NIC */
    for (candidate = physicalNicList; candidate;
         candidate = candidate->_next) {
        if (STRCASEEQ(candidate->device, name)) {
            if (esxVI_PhysicalNic_DeepCopy(physicalNic, candidate) < 0) {
                goto cleanup;
            }

            /* Found physical NIC with matching name */
            result = 0;

            goto cleanup;
        }
    }

    if (!(*physicalNic) && occurrence != esxVI_Occurrence_OptionalItem) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("Could not find physical NIC with name '%s'"), name);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_PhysicalNic_Free(&physicalNicList);

    return result;
}



int
esxVI_LookupPhysicalNicByMACAddress(esxVI_Context *ctx, const char *mac,
                                    esxVI_PhysicalNic **physicalNic,
                                    esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_PhysicalNic *physicalNicList = NULL;
    esxVI_PhysicalNic *candidate = NULL;

    if (!physicalNic || *physicalNic) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_LookupPhysicalNicList(ctx, &physicalNicList) < 0) {
        goto cleanup;
    }

    /* Search for a matching physical NIC */
    for (candidate = physicalNicList; candidate;
         candidate = candidate->_next) {
        if (STRCASEEQ(candidate->mac, mac)) {
            if (esxVI_PhysicalNic_DeepCopy(physicalNic, candidate) < 0) {
                goto cleanup;
            }

            /* Found physical NIC with matching MAC address */
            result = 0;

            goto cleanup;
        }
    }

    if (!(*physicalNic) && occurrence != esxVI_Occurrence_OptionalItem) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("Could not find physical NIC with MAC address '%s'"), mac);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_PhysicalNic_Free(&physicalNicList);

    return result;
}



int
esxVI_LookupHostVirtualSwitchList(esxVI_Context *ctx,
                                  esxVI_HostVirtualSwitch **hostVirtualSwitchList)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (!hostVirtualSwitchList || *hostVirtualSwitchList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.network.vswitch") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.network.vswitch")) {
            if (esxVI_HostVirtualSwitch_CastListFromAnyType
                 (dynamicProperty->val, hostVirtualSwitchList) < 0) {
                goto cleanup;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}



int
esxVI_LookupHostVirtualSwitchByName(esxVI_Context *ctx, const char *name,
                                    esxVI_HostVirtualSwitch **hostVirtualSwitch,
                                    esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_HostVirtualSwitch *hostVirtualSwitchList = NULL;
    esxVI_HostVirtualSwitch *candidate = NULL;

    if (!hostVirtualSwitch || *hostVirtualSwitch) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_LookupHostVirtualSwitchList(ctx, &hostVirtualSwitchList) < 0) {
        goto cleanup;
    }

    /* Search for a matching HostVirtualSwitch */
    for (candidate = hostVirtualSwitchList; candidate;
         candidate = candidate->_next) {
        if (STREQ(candidate->name, name)) {
            if (esxVI_HostVirtualSwitch_DeepCopy(hostVirtualSwitch,
                                                 candidate) < 0) {
                goto cleanup;
            }

            /* Found HostVirtualSwitch with matching name */
            result = 0;

            goto cleanup;
        }
    }

    if (!(*hostVirtualSwitch) &&
        occurrence != esxVI_Occurrence_OptionalItem) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("Could not find HostVirtualSwitch with name '%s'"),
                       name);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitchList);

    return result;
}



int
esxVI_LookupHostPortGroupList(esxVI_Context *ctx,
                              esxVI_HostPortGroup **hostPortGroupList)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (!hostPortGroupList || *hostPortGroupList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.network.portgroup") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.network.portgroup")) {
            if (esxVI_HostPortGroup_CastListFromAnyType
                  (dynamicProperty->val, hostPortGroupList) < 0) {
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
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}



int
esxVI_LookupNetworkList(esxVI_Context *ctx, esxVI_String *propertyNameList,
                        esxVI_ObjectContent **networkList)
{
    return esxVI_LookupObjectContentByType(ctx, ctx->datacenter->_reference,
                                           "Network", propertyNameList,
                                           networkList,
                                           esxVI_Occurrence_OptionalList);
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

    if (!blocked) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *blocked = false;

    if (questionInfo->choice->choiceInfo) {
        for (elementDescription = questionInfo->choice->choiceInfo;
             elementDescription;
             elementDescription = elementDescription->_next) {
            virBufferAsprintf(&buffer, "'%s'", elementDescription->label);

            if (elementDescription->_next) {
                virBufferAddLit(&buffer, ", ");
            }

            if (!answerChoice &&
                questionInfo->choice->defaultIndex &&
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
        if (!possibleAnswers) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Pending question blocks virtual machine execution, "
                             "question is '%s', no possible answers"),
                           questionInfo->text);

            *blocked = true;
            goto cleanup;
        } else if (!answerChoice) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
        if (possibleAnswers) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Pending question blocks virtual machine execution, "
                             "question is '%s', possible answers are %s"),
                           questionInfo->text, possibleAnswers);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
    bool objectSpec_isAppended = false;
    esxVI_PropertySpec *propertySpec = NULL;
    bool propertySpec_isAppended = false;
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

    if (!errorMessage || *errorMessage) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_STRDUP(version, "") < 0)
        return -1;

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
                                        propertySpec) < 0) {
        goto cleanup;
    }

    propertySpec_isAppended = true;

    if (esxVI_ObjectSpec_AppendToList(&propertyFilterSpec->objectSet,
                                      objectSpec) < 0) {
        goto cleanup;
    }

    objectSpec_isAppended = true;

    if (esxVI_CreateFilter(ctx, propertyFilterSpec, esxVI_Boolean_True,
                           &propertyFilter) < 0) {
        goto cleanup;
    }

    while (state != esxVI_TaskInfoState_Success &&
           state != esxVI_TaskInfoState_Error) {
        esxVI_UpdateSet_Free(&updateSet);

        if (virtualMachineUuid) {
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
        if (VIR_STRDUP(version, updateSet->version) < 0)
            goto cleanup;

        if (!updateSet->filterSet) {
            continue;
        }

        for (propertyFilterUpdate = updateSet->filterSet;
             propertyFilterUpdate;
             propertyFilterUpdate = propertyFilterUpdate->_next) {
            for (objectUpdate = propertyFilterUpdate->objectSet;
                 objectUpdate; objectUpdate = objectUpdate->_next) {
                for (propertyChange = objectUpdate->changeSet;
                     propertyChange;
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

        if (!propertyValue) {
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

        if (!taskInfo->error) {
            if (VIR_STRDUP(*errorMessage, _("Unknown error")) < 0)
                goto cleanup;
        } else if (!taskInfo->error->localizedMessage) {
            if (VIR_STRDUP(*errorMessage, taskInfo->error->fault->_actualType) < 0)
                goto cleanup;
        } else {
            if (virAsprintf(errorMessage, "%s - %s",
                            taskInfo->error->fault->_actualType,
                            taskInfo->error->localizedMessage) < 0)
                goto cleanup;
        }
    }

    result = 0;

 cleanup:
    /*
     * Remove values given by the caller from the data structures to prevent
     * them from being freed by the call to esxVI_PropertyFilterSpec_Free().
     */
    if (objectSpec) {
        objectSpec->obj = NULL;
    }

    if (propertySpec) {
        propertySpec->type = NULL;
    }

    if (!objectSpec_isAppended) {
        esxVI_ObjectSpec_Free(&objectSpec);
    }

    if (!propertySpec_isAppended) {
        esxVI_PropertySpec_Free(&propertySpec);
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
    size_t r, i, o;

    memset(parsedHostCpuIdInfo, 0, sizeof(*parsedHostCpuIdInfo));

    parsedHostCpuIdInfo->level = hostCpuIdInfo->level->value;

    for (r = 0; r < 4; ++r) {
        if (strlen(input[r]) != expectedLength) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
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

      case esxVI_ProductVersion_ESX51:
      case esxVI_ProductVersion_ESX5x:
      case esxVI_ProductVersion_VPX51:
      case esxVI_ProductVersion_VPX5x:
        return 8;

      default:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpected product version"));
        return -1;
    }
}



int
esxVI_LookupHostInternetScsiHbaStaticTargetByName
  (esxVI_Context *ctx, const char *name,
   esxVI_HostInternetScsiHbaStaticTarget **target, esxVI_Occurrence occurrence)
{
    int result = -1;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *candidate = NULL;

    if (esxVI_LookupHostInternetScsiHba(ctx, &hostInternetScsiHba) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain hostInternetScsiHba"));
        goto cleanup;
    }

    if (!hostInternetScsiHba) {
        /* iSCSI adapter may not be enabled for this host */
        return 0;
    }

    for (candidate = hostInternetScsiHba->configuredStaticTarget;
         candidate; candidate = candidate->_next) {
        if (STREQ(candidate->iScsiName, name)) {
            break;
        }
    }

    if (!candidate) {
        if (occurrence == esxVI_Occurrence_RequiredItem) {
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           _("Could not find storage pool with name: %s"), name);
        }

        goto cleanup;
    }

    if (esxVI_HostInternetScsiHbaStaticTarget_DeepCopy(target, candidate) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return result;
}



int
esxVI_LookupHostInternetScsiHba(esxVI_Context *ctx,
                                esxVI_HostInternetScsiHba **hostInternetScsiHba)
{
    int result = -1;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_HostHostBusAdapter *hostHostBusAdapterList = NULL;
    esxVI_HostHostBusAdapter *hostHostBusAdapter = NULL;

    if (esxVI_String_AppendValueToList
          (&propertyNameList, "config.storageDevice.hostBusAdapter") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name,
                  "config.storageDevice.hostBusAdapter")) {
            if (esxVI_HostHostBusAdapter_CastListFromAnyType
                (dynamicProperty->val, &hostHostBusAdapterList) < 0 ||
                !hostHostBusAdapterList) {
                goto cleanup;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    /* See vSphere API documentation about HostInternetScsiHba for details */
    for (hostHostBusAdapter = hostHostBusAdapterList;
         hostHostBusAdapter;
         hostHostBusAdapter = hostHostBusAdapter->_next) {
        esxVI_HostInternetScsiHba *candidate =
            esxVI_HostInternetScsiHba_DynamicCast(hostHostBusAdapter);

        if (candidate) {
            if (esxVI_HostInternetScsiHba_DeepCopy(hostInternetScsiHba,
                  candidate) < 0) {
                goto cleanup;
            }
            break;
        }
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_HostHostBusAdapter_Free(&hostHostBusAdapterList);

    return result;
}



int
esxVI_LookupScsiLunList(esxVI_Context *ctx, esxVI_ScsiLun **scsiLunList)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.storageDevice.scsiLun") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.storageDevice.scsiLun")) {
            if (esxVI_ScsiLun_CastListFromAnyType(dynamicProperty->val,
                                                  scsiLunList) < 0) {
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
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}



int
esxVI_LookupHostScsiTopologyLunListByTargetName
  (esxVI_Context *ctx, const char *name,
   esxVI_HostScsiTopologyLun **hostScsiTopologyLunList)
{
    int result = -1;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_HostScsiTopologyInterface *hostScsiInterfaceList = NULL;
    esxVI_HostScsiTopologyInterface *hostScsiInterface = NULL;
    esxVI_HostScsiTopologyTarget *hostScsiTopologyTarget = NULL;
    bool found = false;
    esxVI_HostInternetScsiTargetTransport *candidate = NULL;

    if (!hostScsiTopologyLunList || *hostScsiTopologyLunList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList
          (&propertyNameList,
           "config.storageDevice.scsiTopology.adapter") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name,
                  "config.storageDevice.scsiTopology.adapter")) {
            esxVI_HostScsiTopologyInterface_Free(&hostScsiInterfaceList);

            if (esxVI_HostScsiTopologyInterface_CastListFromAnyType
                  (dynamicProperty->val, &hostScsiInterfaceList) < 0) {
                goto cleanup;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (hostScsiInterfaceList == NULL) {
        /* iSCSI adapter may not be enabled */
        return 0;
    }

    /* See vSphere API documentation about HostScsiTopologyInterface */
    for (hostScsiInterface = hostScsiInterfaceList;
         hostScsiInterface && !found;
         hostScsiInterface = hostScsiInterface->_next) {
        for (hostScsiTopologyTarget = hostScsiInterface->target;
             hostScsiTopologyTarget;
             hostScsiTopologyTarget = hostScsiTopologyTarget->_next) {
            candidate = esxVI_HostInternetScsiTargetTransport_DynamicCast
                          (hostScsiTopologyTarget->transport);

            if (candidate && STREQ(candidate->iScsiName, name)) {
                found = true;
                break;
            }
        }
    }

    if (!found || !hostScsiTopologyTarget) {
        goto cleanup;
    }

    if (!hostScsiTopologyTarget->lun) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Target not found"));
        goto cleanup;
    }

    if (esxVI_HostScsiTopologyLun_DeepCopyList(hostScsiTopologyLunList,
                                               hostScsiTopologyTarget->lun) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_HostScsiTopologyInterface_Free(&hostScsiInterfaceList);

    return result;
}



int
esxVI_LookupStoragePoolNameByScsiLunKey(esxVI_Context *ctx,
                                        const char *key,
                                        char **poolName)
{
    int result = -1;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_HostScsiTopologyInterface *hostScsiInterfaceList = NULL;
    esxVI_HostScsiTopologyInterface *hostScsiInterface = NULL;
    esxVI_HostScsiTopologyTarget *hostScsiTopologyTarget = NULL;
    esxVI_HostInternetScsiTargetTransport *candidate;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLun;
    bool found = false;

    if (!poolName || *poolName) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_AppendValueToList
          (&propertyNameList,
           "config.storageDevice.scsiTopology.adapter") < 0 ||
        esxVI_LookupHostSystemProperties(ctx, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name,
                  "config.storageDevice.scsiTopology.adapter")) {
            esxVI_HostScsiTopologyInterface_Free(&hostScsiInterfaceList);

            if (esxVI_HostScsiTopologyInterface_CastListFromAnyType
                  (dynamicProperty->val, &hostScsiInterfaceList) < 0) {
                goto cleanup;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (!hostScsiInterfaceList) {
        /* iSCSI adapter may not be enabled */
        return 0;
    }

    /* See vSphere API documentation about HostScsiTopologyInterface */
    for (hostScsiInterface = hostScsiInterfaceList;
         hostScsiInterface && !found;
         hostScsiInterface = hostScsiInterface->_next) {
        for (hostScsiTopologyTarget = hostScsiInterface->target;
             hostScsiTopologyTarget;
             hostScsiTopologyTarget = hostScsiTopologyTarget->_next) {
            candidate = esxVI_HostInternetScsiTargetTransport_DynamicCast
                (hostScsiTopologyTarget->transport);

            if (candidate) {
                /* iterate hostScsiTopologyLun list to find matching key */
                for (hostScsiTopologyLun = hostScsiTopologyTarget->lun;
                     hostScsiTopologyLun;
                     hostScsiTopologyLun = hostScsiTopologyLun->_next) {
                    if (STREQ(hostScsiTopologyLun->scsiLun, key) &&
                        VIR_STRDUP(*poolName, candidate->iScsiName) < 0)
                        goto cleanup;
                }

                /* hostScsiTopologyLun iteration done, terminate loop */
                break;
            }
        }
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_String_Free(&propertyNameList);
    esxVI_HostScsiTopologyInterface_Free(&hostScsiInterfaceList);

    return result;
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
        if (!ptrptr || *ptrptr) {                                             \
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",                      \
                           _("Invalid argument"));                            \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        propertyNameList = selectedPropertyNameList;                          \
                                                                              \
        if (!propertyNameList &&                                              \
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
        if (!objectContent) {                                                 \
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
             dynamicProperty;                                                 \
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

    if (!objectContent || *objectContent ||
        !objectContentList || *objectContentList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!esxVI_String_ListContainsValue(propertyNameList, "name")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing 'name' property in %s lookup"), type);
        goto cleanup;
    }

    if (esxVI_LookupObjectContentByType(ctx, root, type, propertyNameList,
                                        objectContentList,
                                        esxVI_Occurrence_OptionalList) < 0) {
        goto cleanup;
    }

    /* Search for a matching item */
    if (name) {
        for (candidate = *objectContentList; candidate;
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

    if (!candidate) {
        if (occurrence != esxVI_Occurrence_OptionalItem) {
            if (name) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find %s with name '%s'"), type, name);
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find %s"), type);
            }

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
