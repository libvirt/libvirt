/*
 * esx_stream.c: libcurl based stream driver
 *
 * Copyright (C) 2012-2014 Matthias Bolte <matthias.bolte@googlemail.com>
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
#include "datatypes.h"
#include "viralloc.h"
#include "esx_stream.h"

#define VIR_FROM_THIS VIR_FROM_ESX

/*
 * This libcurl based stream driver cannot use a libcurl easy handle alone
 * because curl_easy_perform would do the whole transfer before it returns.
 * But there is no place in the stream handling concept that would allow for
 * such a call to be made. The stream is driven by esxStream(Send|Recv) which
 * is probably called multiple times to send/receive the stream in chunks.
 * Therefore, a libcurl multi handle is used that allows to perform the data
 * transfer in chunks and also allows to support non-blocking operations.
 *
 * In the upload direction esxStreamSend is called to push data into the
 * stream and libcurl will call esxVI_CURL_ReadStream to pull data out of
 * the stream to upload it via HTTP(S). To realize this esxStreamSend calls
 * esxStreamTransfer that uses esxVI_MultiCURL_(Wait|Perform) to drive the
 * transfer and makes libcurl read up the data passed to esxStreamSend.
 *
 * In the download direction esxStreamRecv is called to pull data out of the
 * stream and libcurl will call esxVI_CURL_WriteStream to push data into the
 * stream that it has downloaded via HTTP(S). To realize this esxStreamRecv
 * calls esxStreamTransfer that uses esxVI_MultiCURL_(Wait|Perform) to drive
 * the transfer and makes libcurl write to the buffer passed to esxStreamRecv.
 *
 * The download direction requires some extra logic because libcurl might
 * call esxVI_CURL_WriteStream with more data than there is space left in the
 * buffer passed to esxStreamRecv. But esxVI_CURL_WriteStream is not allowed
 * to handle only a part of the incoming data, it needs to handle it all at
 * once. Therefore the stream driver manages a backlog buffer that holds the
 * extra data that didn't fit into the esxStreamRecv buffer anymore. The next
 * time esxStreamRecv is called it'll read the data from the backlog buffer
 * first before asking libcurl for more data.
 *
 * Typically libcurl will call esxVI_CURL_WriteStream with up to 16kb data
 * this means that the typically maximum backlog size should be 16kb as well.
 */

enum _esxStreamMode {
    ESX_STREAM_MODE_UPLOAD = 1,
    ESX_STREAM_MODE_DOWNLOAD = 2
};

typedef struct _esxStreamPrivate esxStreamPrivate;
typedef enum _esxStreamMode esxStreamMode;

struct _esxStreamPrivate {
    esxVI_CURL *curl;
    int mode;

    /* Backlog of downloaded data that has not been esxStreamRecv'ed yet */
    char *backlog;
    size_t backlog_size;
    size_t backlog_used;

    /* Buffer given to esxStream(Send|Recv) to (read|write) data (from|to) */
    char *buffer;
    size_t buffer_size;
    size_t buffer_used;
};

static size_t
esxVI_CURL_ReadStream(char *output, size_t size, size_t nmemb, void *userdata)
{
    esxStreamPrivate *priv = userdata;
    size_t output_size = size * nmemb;
    size_t output_used = 0;

    if (output_size > priv->buffer_used)
        output_used = priv->buffer_used;
    else
        output_used = output_size;

    memcpy(output, priv->buffer + priv->buffer_size - priv->buffer_used,
           output_used);

    priv->buffer_used -= output_used;

    return output_used;
}

static size_t
esxVI_CURL_WriteStream(char *input, size_t size, size_t nmemb, void *userdata)
{
    esxStreamPrivate *priv = userdata;
    size_t input_size = size * nmemb;
    size_t input_used = priv->buffer_size - priv->buffer_used;

    if (input_size == 0)
        return input_size;

    if (input_used > input_size)
        input_used = input_size;

    /* Fill buffer */
    memcpy(priv->buffer + priv->buffer_used, input, input_used);
    priv->buffer_used += input_used;

    /* Move rest to backlog */
    if (input_size > input_used) {
        size_t input_remaining = input_size - input_used;
        size_t backlog_remaining = priv->backlog_size - priv->backlog_used;

        if (!priv->backlog) {
            priv->backlog_size = input_remaining;
            priv->backlog_used = 0;

            priv->backlog = g_new0(char, priv->backlog_size);
        } else if (input_remaining > backlog_remaining) {
            priv->backlog_size += input_remaining - backlog_remaining;

            VIR_REALLOC_N(priv->backlog, priv->backlog_size);
        }

        memcpy(priv->backlog + priv->backlog_used, input + input_used,
               input_remaining);

        priv->backlog_used += input_remaining;
    }

    return input_size;
}

/* Returns -1 on error, 0 if it needs to be called again, and 1 if it's done for now */
static int
esxStreamTransfer(esxStreamPrivate *priv, bool blocking)
{
    int runningHandles = 0;
    long responseCode = 0;
    int status;
    CURLcode errorCode;

    if (blocking) {
        if (esxVI_MultiCURL_Wait(priv->curl->multi, &runningHandles) < 0)
            return -1;
    } else {
        if (esxVI_MultiCURL_Perform(priv->curl->multi, &runningHandles) < 0)
            return -1;
    }

    if (runningHandles == 0) {
        /* Transfer is done check for result */
        status = esxVI_MultiCURL_CheckFirstMessage(priv->curl->multi,
                                                   &responseCode, &errorCode);

        if (status == 0) {
            /* No message, transfer finished successfully */
            return 1;
        }

        if (status < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not complete transfer: %1$s (%2$d)"),
                           curl_easy_strerror(errorCode), errorCode);
            return -1;
        }

        if (responseCode != 200 && responseCode != 206) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected HTTP response code %1$lu"),
                           responseCode);
            return -1;
        }

        return 1;
    }

    return blocking ? 0 : 1;
}

static int
esxStreamSend(virStreamPtr stream, const char *data, size_t nbytes)
{
    int result = -1;
    esxStreamPrivate *priv = stream->privateData;

    if (nbytes == 0)
        return 0;

    if (!priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Stream is not open"));
        return -1;
    }

    if (priv->mode != ESX_STREAM_MODE_UPLOAD) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("Not an upload stream"));
        return -1;
    }

    VIR_WITH_MUTEX_LOCK_GUARD(&priv->curl->lock) {
        priv->buffer = (char *)data;
        priv->buffer_size = nbytes;
        priv->buffer_used = nbytes;

        if (stream->flags & VIR_STREAM_NONBLOCK) {
            if (esxStreamTransfer(priv, false) < 0)
                return -1;

            if (priv->buffer_used >= priv->buffer_size)
                return -2;
        } else /* blocking */ {
            do {
                int status = esxStreamTransfer(priv, true);

                if (status < 0)
                    return -1;

                if (status > 0)
                    break;
            } while (priv->buffer_used > 0);
        }

        result = priv->buffer_size - priv->buffer_used;
    }

    return result;
}

static int
esxStreamRecvFlags(virStreamPtr stream,
                   char *data,
                   size_t nbytes,
                   unsigned int flags)
{
    int result = -1;
    esxStreamPrivate *priv = stream->privateData;

    virCheckFlags(0, -1);

    if (nbytes == 0)
        return 0;

    if (!priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Stream is not open"));
        return -1;
    }

    if (priv->mode != ESX_STREAM_MODE_DOWNLOAD) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("Not a download stream"));
        return -1;
    }

    VIR_WITH_MUTEX_LOCK_GUARD(&priv->curl->lock) {
        priv->buffer = data;
        priv->buffer_size = nbytes;
        priv->buffer_used = 0;

        if (priv->backlog_used > 0) {
            if (priv->buffer_size > priv->backlog_used)
                priv->buffer_used = priv->backlog_used;
            else
                priv->buffer_used = priv->buffer_size;

            memcpy(priv->buffer, priv->backlog, priv->buffer_used);
            memmove(priv->backlog, priv->backlog + priv->buffer_used,
                    priv->backlog_used - priv->buffer_used);

            priv->backlog_used -= priv->buffer_used;
        } else if (stream->flags & VIR_STREAM_NONBLOCK) {
            if (esxStreamTransfer(priv, false) < 0)
                return -1;

            if (priv->buffer_used == 0)
                return -2;
        } else /* blocking */ {
            do {
                int status = esxStreamTransfer(priv, true);

                if (status < 0)
                    return -1;

                if (status > 0)
                    break;
            } while (priv->buffer_used < priv->buffer_size);
        }

        result = priv->buffer_used;
    }

    return result;
}

static int
esxStreamRecv(virStreamPtr stream,
              char *data,
              size_t nbytes)
{
    return esxStreamRecvFlags(stream, data, nbytes, 0);
}

static void
esxFreeStreamPrivate(esxStreamPrivate **priv)
{
    if (!priv || !*priv)
        return;

    esxVI_CURL_Free(&(*priv)->curl);
    g_free((*priv)->backlog);
    g_free(*priv);
}

static int
esxStreamClose(virStreamPtr stream, bool finish)
{
    int result = 0;
    esxStreamPrivate *priv = stream->privateData;

    if (!priv)
        return 0;

    VIR_WITH_MUTEX_LOCK_GUARD(&priv->curl->lock) {
        if (finish && priv->backlog_used > 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Stream has untransferred data left"));
            result = -1;
        }

        stream->privateData = NULL;
    }

    esxFreeStreamPrivate(&priv);

    return result;
}

static int
esxStreamFinish(virStreamPtr stream)
{
    return esxStreamClose(stream, true);
}

static int
esxStreamAbort(virStreamPtr stream)
{
    return esxStreamClose(stream, false);
}

virStreamDriver esxStreamDriver = {
    .streamSend = esxStreamSend,
    .streamRecv = esxStreamRecv,
    .streamRecvFlags = esxStreamRecvFlags,
    /* FIXME: streamAddCallback missing */
    /* FIXME: streamUpdateCallback missing */
    /* FIXME: streamRemoveCallback missing */
    .streamFinish = esxStreamFinish,
    .streamAbort = esxStreamAbort,
};

static int
esxStreamOpen(virStreamPtr stream, esxPrivate *priv, const char *url,
              unsigned long long offset, unsigned long long length, int mode)
{
    int result = -1;
    esxStreamPrivate *streamPriv;
    g_autofree char *range = NULL;
    esxVI_MultiCURL *multi = NULL;

    /* FIXME: Although there is already some code in place to deal with
     *        non-blocking streams it is currently incomplete, so usage
     *        of the non-blocking mode is denied here for now. */
    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Non-blocking streams are not supported yet"));
        return -1;
    }

    streamPriv = g_new0(esxStreamPrivate, 1);

    streamPriv->mode = mode;

    if (length > 0) {
        range = g_strdup_printf("%llu-%llu", offset, offset + length - 1);
    } else if (offset > 0) {
        range = g_strdup_printf("%llu-", offset);
    }

    if (esxVI_CURL_Alloc(&streamPriv->curl) < 0 ||
        esxVI_CURL_Connect(streamPriv->curl, priv->parsedUri) < 0)
        goto cleanup;

    if (mode == ESX_STREAM_MODE_UPLOAD) {
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_UPLOAD, 1);
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_READFUNCTION,
                         esxVI_CURL_ReadStream);
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_READDATA, streamPriv);
    } else {
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_UPLOAD, 0);
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_WRITEFUNCTION,
                         esxVI_CURL_WriteStream);
        curl_easy_setopt(streamPriv->curl->handle, CURLOPT_WRITEDATA, streamPriv);
    }

    curl_easy_setopt(streamPriv->curl->handle, CURLOPT_URL, url);
    curl_easy_setopt(streamPriv->curl->handle, CURLOPT_RANGE, range);

    curl_easy_setopt(streamPriv->curl->handle, CURLOPT_USERNAME,
                     priv->primary->username);
    curl_easy_setopt(streamPriv->curl->handle, CURLOPT_PASSWORD,
                     priv->primary->password);

    if (esxVI_MultiCURL_Alloc(&multi) < 0 ||
        esxVI_MultiCURL_Add(multi, streamPriv->curl) < 0)
        goto cleanup;

    stream->driver = &esxStreamDriver;
    stream->privateData = streamPriv;

    result = 0;

 cleanup:
    if (result < 0) {
        if (streamPriv->curl && multi != streamPriv->curl->multi)
            esxVI_MultiCURL_Free(&multi);

        esxFreeStreamPrivate(&streamPriv);
    }

    return result;
}

int
esxStreamOpenUpload(virStreamPtr stream, esxPrivate *priv, const char *url)
{
    return esxStreamOpen(stream, priv, url, 0, 0, ESX_STREAM_MODE_UPLOAD);
}

int
esxStreamOpenDownload(virStreamPtr stream, esxPrivate *priv, const char *url,
                      unsigned long long offset, unsigned long long length)
{
    return esxStreamOpen(stream, priv, url, offset, length, ESX_STREAM_MODE_DOWNLOAD);
}
