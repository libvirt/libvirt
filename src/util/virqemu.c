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
    g_autoptr(virBitmap) bitmap = NULL;

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

    return 0;
}


int
virQEMUBuildCommandLineJSONArrayNumbered(const char *key,
                                         virJSONValuePtr array,
                                         virBufferPtr buf)
{
    virJSONValuePtr member;
    size_t i;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        member = virJSONValueArrayGet((virJSONValuePtr) array, i);
        g_autofree char *prefix = NULL;

        if (virAsprintf(&prefix, "%s.%zu", key, i) < 0)
            return 0;

        if (virQEMUBuildCommandLineJSONRecurse(prefix, member, buf,
                                               virQEMUBuildCommandLineJSONArrayNumbered,
                                               true) < 0)
            return 0;
    }

    return 0;
}


/* internal iterator to handle nested object formatting */
static int
virQEMUBuildCommandLineJSONIterate(const char *key,
                                   virJSONValuePtr value,
                                   void *opaque)
{
    struct virQEMUCommandLineJSONIteratorData *data = opaque;

    if (data->prefix) {
        g_autofree char *tmpkey = NULL;

        if (virAsprintf(&tmpkey, "%s.%s", data->prefix, key) < 0)
            return -1;

        return virQEMUBuildCommandLineJSONRecurse(tmpkey, value, data->buf,
                                                  data->arrayFunc, false);
    } else {
        return virQEMUBuildCommandLineJSONRecurse(key, value, data->buf,
                                                  data->arrayFunc, false);
    }
}


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValuePtr value,
                                   virBufferPtr buf,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested)
{
    struct virQEMUCommandLineJSONIteratorData data = { key, buf, arrayFunc };
    virJSONType type = virJSONValueGetType(value);
    virJSONValuePtr elem;
    bool tmp;
    size_t i;

    if (!key && type != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only JSON objects can be top level"));
        return -1;
    }

    switch (type) {
    case VIR_JSON_TYPE_STRING:
        virBufferAsprintf(buf, "%s=", key);
        virQEMUBuildBufferEscapeComma(buf, virJSONValueGetString(value));
        virBufferAddLit(buf, ",");
        break;

    case VIR_JSON_TYPE_NUMBER:
        virBufferAsprintf(buf, "%s=%s,", key, virJSONValueGetNumberString(value));
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        virJSONValueGetBoolean(value, &tmp);
        if (tmp)
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


static int
virQEMUBuildObjectCommandlineFromJSONInternal(virBufferPtr buf,
                                              const char *type,
                                              const char *alias,
                                              virJSONValuePtr props)
{
    if (!type || !alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'type'(%s) or 'alias'(%s) field of QOM 'object'"),
                       NULLSTR(type), NULLSTR(alias));
        return -1;
    }

    virBufferAsprintf(buf, "%s,id=%s,", type, alias);

    if (props &&
        virQEMUBuildCommandLineJSON(props, buf,
                                    virQEMUBuildCommandLineJSONArrayBitmap) < 0)
        return -1;

    return 0;
}


int
virQEMUBuildObjectCommandlineFromJSON(virBufferPtr buf,
                                      virJSONValuePtr objprops)
{
    const char *type = virJSONValueObjectGetString(objprops, "qom-type");
    const char *alias = virJSONValueObjectGetString(objprops, "id");
    virJSONValuePtr props = virJSONValueObjectGetObject(objprops, "props");

    return virQEMUBuildObjectCommandlineFromJSONInternal(buf, type, alias, props);
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
 * virQEMUBuildQemuImgKeySecretOpts:
 * @buf: buffer to build the string into
 * @encinfo: pointer to encryption info
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
virQEMUBuildQemuImgKeySecretOpts(virBufferPtr buf,
                                 virStorageEncryptionInfoDefPtr encinfo,
                                 const char *alias)
{
    virBufferAsprintf(buf, "key-secret=%s,", alias);

    if (!encinfo->cipher_name)
        return;

    virBufferAddLit(buf, "cipher-alg=");
    virQEMUBuildBufferEscapeComma(buf, encinfo->cipher_name);
    virBufferAsprintf(buf, "-%u,", encinfo->cipher_size);
    if (encinfo->cipher_mode) {
        virBufferAddLit(buf, "cipher-mode=");
        virQEMUBuildBufferEscapeComma(buf, encinfo->cipher_mode);
        virBufferAddLit(buf, ",");
    }
    if (encinfo->cipher_hash) {
        virBufferAddLit(buf, "hash-alg=");
        virQEMUBuildBufferEscapeComma(buf, encinfo->cipher_hash);
        virBufferAddLit(buf, ",");
    }
    if (!encinfo->ivgen_name)
        return;

    virBufferAddLit(buf, "ivgen-alg=");
    virQEMUBuildBufferEscapeComma(buf, encinfo->ivgen_name);
    virBufferAddLit(buf, ",");

    if (encinfo->ivgen_hash) {
        virBufferAddLit(buf, "ivgen-hash-alg=");
        virQEMUBuildBufferEscapeComma(buf, encinfo->ivgen_hash);
        virBufferAddLit(buf, ",");
    }
}
