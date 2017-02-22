/*
 * virqemu.c: utilities for working with qemu and its tools
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
#include "virerror.h"
#include "virlog.h"
#include "virqemu.h"
#include "virstring.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.qemu");

struct virQEMUCommandLineJSONIteratorData {
    const char *prefix;
    virBufferPtr buf;
    virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc;
};


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValuePtr value,
                                   virBufferPtr buf,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested);



int
virQEMUBuildCommandLineJSONArrayBitmap(const char *key,
                                       virJSONValuePtr array,
                                       virBufferPtr buf)
{
    ssize_t pos = -1;
    ssize_t end;
    virBitmapPtr bitmap = NULL;

    if (virJSONValueGetArrayAsBitmap(array, &bitmap) < 0)
        return -1;

    while ((pos = virBitmapNextSetBit(bitmap, pos)) > -1) {
        if ((end = virBitmapNextClearBit(bitmap, pos)) < 0)
            end = virBitmapLastSetBit(bitmap) + 1;

        if (end - 1 > pos) {
            virBufferAsprintf(buf, "%s=%zd-%zd,", key, pos, end - 1);
            pos = end;
        } else {
            virBufferAsprintf(buf, "%s=%zd,", key, pos);
        }
    }

    virBitmapFree(bitmap);

    return 0;
}


int
virQEMUBuildCommandLineJSONArrayNumbered(const char *key,
                                         virJSONValuePtr array,
                                         virBufferPtr buf)
{
    virJSONValuePtr member;
    char *prefix = NULL;
    size_t i;
    int ret = 0;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        member = virJSONValueArrayGet((virJSONValuePtr) array, i);

        if (virAsprintf(&prefix, "%s.%zu", key, i) < 0)
            goto cleanup;

        if (virQEMUBuildCommandLineJSONRecurse(prefix, member, buf,
                                               virQEMUBuildCommandLineJSONArrayNumbered,
                                               true) < 0)
            goto cleanup;

        VIR_FREE(prefix);
    }

    ret = 0;

 cleanup:
    VIR_FREE(prefix);
    return ret;
}


/* internal iterator to handle nested object formatting */
static int
virQEMUBuildCommandLineJSONIterate(const char *key,
                                   virJSONValuePtr value,
                                   void *opaque)
{
    struct virQEMUCommandLineJSONIteratorData *data = opaque;
    char *tmpkey = NULL;
    int ret = -1;

    if (data->prefix) {
        if (virAsprintf(&tmpkey, "%s.%s", data->prefix, key) < 0)
            return -1;

        ret = virQEMUBuildCommandLineJSONRecurse(tmpkey, value, data->buf,
                                                 data->arrayFunc, false);

        VIR_FREE(tmpkey);
    } else {
        ret = virQEMUBuildCommandLineJSONRecurse(key, value, data->buf,
                                                 data->arrayFunc, false);
    }

    return ret;
}


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValuePtr value,
                                   virBufferPtr buf,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested)
{
    struct virQEMUCommandLineJSONIteratorData data = { key, buf, arrayFunc };
    virJSONValuePtr elem;
    size_t i;

    if (!key && value->type != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only JSON objects can be top level"));
        return -1;
    }

    switch ((virJSONType) value->type) {
    case VIR_JSON_TYPE_STRING:
        virBufferAsprintf(buf, "%s=", key);
        virQEMUBuildBufferEscapeComma(buf, value->data.string);
        virBufferAddLit(buf, ",");
        break;

    case VIR_JSON_TYPE_NUMBER:
        virBufferAsprintf(buf, "%s=%s,", key, value->data.number);
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        if (value->data.boolean)
            virBufferAsprintf(buf, "%s=yes,", key);
        else
            virBufferAsprintf(buf, "%s=no,", key);

        break;

    case VIR_JSON_TYPE_ARRAY:
        if (nested) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("nested JSON array to commandline conversion is "
                             "not supported"));
            return -1;
        }

        if (!arrayFunc || arrayFunc(key, value, buf) < 0) {
            /* fallback, treat the array as a non-bitmap, adding the key
             * for each member */
            for (i = 0; i < virJSONValueArraySize(value); i++) {
                elem = virJSONValueArrayGet((virJSONValuePtr)value, i);

                /* recurse to avoid duplicating code */
                if (virQEMUBuildCommandLineJSONRecurse(key, elem, buf,
                                                       arrayFunc, true) < 0)
                    return -1;
            }
        }
        break;

    case VIR_JSON_TYPE_OBJECT:
        if (virJSONValueObjectForeachKeyValue(value,
                                              virQEMUBuildCommandLineJSONIterate,
                                              &data) < 0)
            return -1;
        break;

    case VIR_JSON_TYPE_NULL:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("NULL JSON type can't be converted to commandline"));
        return -1;
    }

    return 0;
}


/**
 * virQEMUBuildCommandLineJSON:
 * @value: json object containing the value
 * @buf: otuput buffer
 * @arrayFunc: array formatter function to allow for different syntax
 *
 * Formats JSON value object into command line parameters suitable for use with
 * qemu.
 *
 * Returns 0 on success -1 on error.
 */
int
virQEMUBuildCommandLineJSON(virJSONValuePtr value,
                            virBufferPtr buf,
                            virQEMUBuildCommandLineJSONArrayFormatFunc array)
{
    if (virQEMUBuildCommandLineJSONRecurse(NULL, value, buf, array, false) < 0)
        return -1;

    virBufferTrim(buf, ",", -1);

    return 0;
}


char *
virQEMUBuildObjectCommandlineFromJSON(const char *type,
                                      const char *alias,
                                      virJSONValuePtr props)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *ret = NULL;

    virBufferAsprintf(&buf, "%s,id=%s,", type, alias);

    if (virQEMUBuildCommandLineJSON(props, &buf,
                                    virQEMUBuildCommandLineJSONArrayBitmap) < 0)
        goto cleanup;

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    ret = virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}


char *
virQEMUBuildDriveCommandlineFromJSON(virJSONValuePtr srcdef)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *ret = NULL;

    if (virQEMUBuildCommandLineJSON(srcdef, &buf,
                                    virQEMUBuildCommandLineJSONArrayNumbered) < 0)
        goto cleanup;

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    ret = virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}


/**
 * virQEMUBuildBufferEscapeComma:
 * @buf: buffer to append the escaped string
 * @str: the string to escape
 *
 * qemu requires that any values passed on the command line which contain
 * a ',' must escape it using an extra ',' as the escape character
 */
void
virQEMUBuildBufferEscapeComma(virBufferPtr buf, const char *str)
{
    virBufferEscape(buf, ',', ",", "%s", str);
}


/**
 * virQEMUBuildBufferEscape:
 * @buf: buffer to append the escaped string
 * @str: the string to escape
 *
 * Some characters passed as values on the QEMU command line must be escaped.
 *
 *  - ',' must by escaped by ','
 *  - '=' must by escaped by '\'
 */
void
virQEMUBuildBufferEscape(virBufferPtr buf, const char *str)
{
    virBufferEscapeN(buf, "%s", str, ',', ",", '\\', "=", NULL);
}


/**
 * virQEMUBuildLuksOpts:
 * @buf: buffer to build the string into
 * @enc: pointer to encryption info
 * @alias: alias to use
 *
 * Generate the string for id=$alias and any encryption options for
 * into the buffer.
 *
 * Important note, a trailing comma (",") is built into the return since
 * it's expected other arguments are appended after the id=$alias string.
 * So either turn something like:
 *
 *     "key-secret=$alias,"
 *
 * or
 *     "key-secret=$alias,cipher-alg=twofish-256,cipher-mode=cbc,
 *     hash-alg=sha256,ivgen-alg=plain64,igven-hash-alg=sha256,"
 *
 */
void
virQEMUBuildLuksOpts(virBufferPtr buf,
                     virStorageEncryptionInfoDefPtr enc,
                     const char *alias)
{
    virBufferAsprintf(buf, "key-secret=%s,", alias);

    if (!enc->cipher_name)
        return;

    virBufferAddLit(buf, "cipher-alg=");
    virQEMUBuildBufferEscapeComma(buf, enc->cipher_name);
    virBufferAsprintf(buf, "-%u,", enc->cipher_size);
    if (enc->cipher_mode) {
        virBufferAddLit(buf, "cipher-mode=");
        virQEMUBuildBufferEscapeComma(buf, enc->cipher_mode);
        virBufferAddLit(buf, ",");
    }
    if (enc->cipher_hash) {
        virBufferAddLit(buf, "hash-alg=");
        virQEMUBuildBufferEscapeComma(buf, enc->cipher_hash);
        virBufferAddLit(buf, ",");
    }
    if (!enc->ivgen_name)
        return;

    virBufferAddLit(buf, "ivgen-alg=");
    virQEMUBuildBufferEscapeComma(buf, enc->ivgen_name);
    virBufferAddLit(buf, ",");

    if (enc->ivgen_hash) {
        virBufferAddLit(buf, "ivgen-hash-alg=");
        virQEMUBuildBufferEscapeComma(buf, enc->ivgen_hash);
        virBufferAddLit(buf, ",");
    }
}
