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
    const char *skipKey;
    bool onOff;
    virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc;
};


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValuePtr value,
                                   virBufferPtr buf,
                                   const char *skipKey,
                                   bool onOff,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested);



int
virQEMUBuildCommandLineJSONArrayBitmap(const char *key,
                                       virJSONValuePtr array,
                                       virBufferPtr buf,
                                       const char *skipKey G_GNUC_UNUSED,
                                       bool onOff G_GNUC_UNUSED)
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
                                         virBufferPtr buf,
                                         const char *skipKey,
                                         bool onOff)
{
    virJSONValuePtr member;
    size_t i;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        g_autofree char *prefix = NULL;

        member = virJSONValueArrayGet((virJSONValuePtr) array, i);
        prefix = g_strdup_printf("%s.%zu", key, i);

        if (virQEMUBuildCommandLineJSONRecurse(prefix, member, buf, skipKey, onOff,
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
static int
virQEMUBuildCommandLineJSONArrayObjectsStr(const char *key,
                                           virJSONValuePtr array,
                                           virBufferPtr buf,
                                           const char *skipKey G_GNUC_UNUSED,
                                           bool onOff G_GNUC_UNUSED)
{
    g_auto(virBuffer) tmp = VIR_BUFFER_INITIALIZER;
    size_t i;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        virJSONValuePtr member = virJSONValueArrayGet(array, i);
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
                                   virJSONValuePtr value,
                                   void *opaque)
{
    struct virQEMUCommandLineJSONIteratorData *data = opaque;

    if (STREQ_NULLABLE(key, data->skipKey))
        return 0;

    if (data->prefix) {
        g_autofree char *tmpkey = NULL;

        tmpkey = g_strdup_printf("%s.%s", data->prefix, key);

        return virQEMUBuildCommandLineJSONRecurse(tmpkey, value, data->buf,
                                                  data->skipKey, data->onOff,
                                                  data->arrayFunc, false);
    } else {
        return virQEMUBuildCommandLineJSONRecurse(key, value, data->buf,
                                                  data->skipKey, data->onOff,
                                                  data->arrayFunc, false);
    }
}


static int
virQEMUBuildCommandLineJSONRecurse(const char *key,
                                   virJSONValuePtr value,
                                   virBufferPtr buf,
                                   const char *skipKey,
                                   bool onOff,
                                   virQEMUBuildCommandLineJSONArrayFormatFunc arrayFunc,
                                   bool nested)
{
    struct virQEMUCommandLineJSONIteratorData data = { key, buf, skipKey, onOff, arrayFunc };
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
        if (onOff) {
            if (tmp)
                virBufferAsprintf(buf, "%s=on,", key);
            else
                virBufferAsprintf(buf, "%s=off,", key);
        } else {
            if (tmp)
                virBufferAsprintf(buf, "%s=yes,", key);
            else
                virBufferAsprintf(buf, "%s=no,", key);
        }

        break;

    case VIR_JSON_TYPE_ARRAY:
        if (nested) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("nested JSON array to commandline conversion is "
                             "not supported"));
            return -1;
        }

        if (!arrayFunc || arrayFunc(key, value, buf, skipKey, onOff) < 0) {
            /* fallback, treat the array as a non-bitmap, adding the key
             * for each member */
            for (i = 0; i < virJSONValueArraySize(value); i++) {
                elem = virJSONValueArrayGet((virJSONValuePtr)value, i);

                /* recurse to avoid duplicating code */
                if (virQEMUBuildCommandLineJSONRecurse(key, elem, buf, skipKey,
                                                       onOff, arrayFunc, true) < 0)
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
 * @skipKey: name of key that will be handled separately by caller
 * @onOff: Use 'on' and 'off' for boolean values rather than 'yes' and 'no'
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
                            const char *skipKey,
                            bool onOff,
                            virQEMUBuildCommandLineJSONArrayFormatFunc array)
{
    if (virQEMUBuildCommandLineJSONRecurse(NULL, value, buf, skipKey, onOff, array, false) < 0)
        return -1;

    virBufferTrim(buf, ",");

    return 0;
}


/**
 * virQEMUBuildNetdevCommandlineFromJSON:
 * @props: JSON properties describing a netdev
 * @rawjson: don't transform to commandline args, but just stringify json
 *
 * Converts @props into arguments for -netdev including all the quirks and
 * differences between the monitor and command line syntax.
 *
 * @rawjson is meant for testing of the schema in the xml2argvtest
 */
char *
virQEMUBuildNetdevCommandlineFromJSON(virJSONValuePtr props,
                                      bool rawjson)
{
    const char *type = virJSONValueObjectGetString(props, "type");
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (rawjson)
        return virJSONValueToString(props, false);

    virBufferAsprintf(&buf, "%s,", type);

    if (virQEMUBuildCommandLineJSON(props, &buf, "type", true,
                                    virQEMUBuildCommandLineJSONArrayObjectsStr) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
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

    virBufferAsprintf(buf, "%s,id=%s", type, alias);

    if (props) {
        virBufferAddLit(buf, ",");
        if (virQEMUBuildCommandLineJSON(props, buf, NULL, false,
                                virQEMUBuildCommandLineJSONArrayBitmap) < 0)
            return -1;
    }

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
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virQEMUBuildCommandLineJSON(srcdef, &buf, NULL, false,
                                    virQEMUBuildCommandLineJSONArrayNumbered) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
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
