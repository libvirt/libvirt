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
#include "virbitmap.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.qemu");

struct virQEMUCommandLineJSONIteratorData {
    const char *prefix;
    virBuffer *buf;
    const char *skipKey;
    virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc;
};


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValue *value,
                                   virBuffer *buf,
                                   const char *skipKey,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested);



int
virQEMUBuildCommandLineJSONArrayBitmap(const char *key,
                                       virJSONValue *array,
                                       virBuffer *buf)
{
    ssize_t pos = -1;
    ssize_t end;
    g_autoptr(virBitmap) bitmap = virBitmapNew(0);
    size_t i;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        virJSONValue *member = virJSONValueArrayGet(array, i);
        unsigned long long value;

        if (virJSONValueGetNumberUlong(member, &value) < 0)
            return -1;

        virBitmapSetBitExpand(bitmap, value);
    }

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
                                         virJSONValue *array,
                                         virBuffer *buf)
{
    virJSONValue *member;
    size_t i;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        g_autofree char *prefix = NULL;

        member = virJSONValueArrayGet((virJSONValue *) array, i);
        prefix = g_strdup_printf("%s.%zu", key, i);

        if (virQEMUBuildCommandLineJSONRecurse(prefix, member, buf, NULL,
                                               virQEMUBuildCommandLineJSONArrayNumbered,
                                               true) < 0)
            return 0;
    }

    return 0;
}


/**
 * This array converter is for quirky cases where the QMP schema mandates an
 * array of objects with only one attribute 'str' which needs to be formatted as
 * repeated key-value pairs without the 'str' being printed:
 *
 * 'guestfwd': [
 *                  { "str": "tcp:10.0.2.1:4600-chardev:charchannel0" },
 *                  { "str": "...."},
 *             ]
 *
 *  guestfwd=tcp:10.0.2.1:4600-chardev:charchannel0,guestfwd=...
 */
int
virQEMUBuildCommandLineJSONArrayObjectsStr(const char *key,
                                           virJSONValue *array,
                                           virBuffer *buf)
{
    g_auto(virBuffer) tmp = VIR_BUFFER_INITIALIZER;
    size_t i;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        virJSONValue *member = virJSONValueArrayGet(array, i);
        const char *str = virJSONValueObjectGetString(member, "str");

        if (!str)
            return -1;

        virBufferAsprintf(&tmp, "%s=%s,", key, str);
    }

    virBufferAddBuffer(buf, &tmp);
    return 0;
}


/* internal iterator to handle nested object formatting */
static int
virQEMUBuildCommandLineJSONIterate(const char *key,
                                   virJSONValue *value,
                                   void *opaque)
{
    struct virQEMUCommandLineJSONIteratorData *data = opaque;
    g_autofree char *tmpkey = NULL;

    if (STREQ_NULLABLE(key, data->skipKey))
        return 0;

    if (data->prefix)
        key = tmpkey = g_strdup_printf("%s.%s", data->prefix, key);

    return virQEMUBuildCommandLineJSONRecurse(key, value, data->buf, NULL,
                                              data->arrayFunc, false);
}


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValue *value,
                                   virBuffer *buf,
                                   const char *skipKey,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested)
{
    struct virQEMUCommandLineJSONIteratorData data = { key, buf, skipKey, arrayFunc };
    virJSONType type = virJSONValueGetType(value);
    virJSONValue *elem;
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
            virBufferAsprintf(buf, "%s=on,", key);
        else
            virBufferAsprintf(buf, "%s=off,", key);
        break;

    case VIR_JSON_TYPE_ARRAY:
        if (nested) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("nested JSON array to commandline conversion is not supported"));
            return -1;
        }

        if (!arrayFunc) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("JSON array -> commandline conversion function not provided"));
            return -1;
        }

        if (arrayFunc(key, value, buf) < 0) {
            /* fallback, treat the array as a non-bitmap, adding the key
             * for each member */
            for (i = 0; i < virJSONValueArraySize(value); i++) {
                elem = virJSONValueArrayGet((virJSONValue *)value, i);

                /* recurse to avoid duplicating code */
                if (virQEMUBuildCommandLineJSONRecurse(key, elem, buf, NULL,
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
 * @skipKey: name of key inside the top level object that will be handled
 *           separately by caller
 * @arrayFunc: array formatter function to allow for different syntax
 *
 * Formats JSON value object into command line parameters suitable for use with
 * qemu.
 *
 * Returns 0 on success -1 on error.
 */
int
virQEMUBuildCommandLineJSON(virJSONValue *value,
                            virBuffer *buf,
                            const char *skipKey,
                            virQEMUBuildCommandLineJSONArrayFormatFunc array)
{
    if (virQEMUBuildCommandLineJSONRecurse(NULL, value, buf, skipKey, array, false) < 0)
        return -1;

    virBufferTrim(buf, ",");

    return 0;
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
virQEMUBuildBufferEscapeComma(virBuffer *buf, const char *str)
{
    virBufferEscape(buf, ',', ",", "%s", str);
}
