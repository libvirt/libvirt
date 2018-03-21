/*
 * qemu_qapi.c: helper functions for QEMU QAPI schema handling
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
 */

#include <config.h>

#include "qemu_qapi.h"

#include "viralloc.h"
#include "virstring.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_qapi");


/**
 * virQEMUQAPISchemaObjectGetType:
 * @field: name of the object containing the requested type
 * @name: name of the requested type
 * @namefield: name of the object property holding @name
 *
 * Helper that selects the type of a QMP schema object member or it's variant
 * member. Returns the type string on success or NULL on error.
 */
static const char *
virQEMUQAPISchemaObjectGetType(const char *field,
                               const char *name,
                               const char *namefield,
                               virJSONValuePtr elem)
{
    virJSONValuePtr arr;
    virJSONValuePtr cur;
    const char *curname;
    const char *type;
    size_t i;

    if (!(arr = virJSONValueObjectGetArray(elem, field)))
        return NULL;

    for (i = 0; i < virJSONValueArraySize(arr); i++) {
        if (!(cur = virJSONValueArrayGet(arr, i)) ||
            !(curname = virJSONValueObjectGetString(cur, namefield)) ||
            !(type = virJSONValueObjectGetString(cur, "type")))
            continue;

        if (STREQ(name, curname))
            return type;
    }

    return NULL;
}


static virJSONValuePtr
virQEMUQAPISchemaTraverse(const char *baseName,
                          char **query,
                          virHashTablePtr schema)
{
    virJSONValuePtr base;
    const char *metatype;

    while (1) {
        if (!(base = virHashLookup(schema, baseName)))
            return NULL;

        if (!*query)
            return base;

        if (!(metatype = virJSONValueObjectGetString(base, "meta-type")))
            return NULL;

        /* flatten arrays by default */
        if (STREQ(metatype, "array")) {
            if (!(baseName = virJSONValueObjectGetString(base, "element-type")))
                return NULL;

            continue;
        } else if (STREQ(metatype, "object")) {
            if (**query == '+')
                baseName = virQEMUQAPISchemaObjectGetType("variants",
                                                          *query + 1,
                                                          "case", base);
            else
                baseName = virQEMUQAPISchemaObjectGetType("members",
                                                          *query,
                                                          "name", base);

            if (!baseName)
                return NULL;
        } else if (STREQ(metatype, "command") ||
                   STREQ(metatype, "event")) {
            if (!(baseName = virJSONValueObjectGetString(base, *query)))
                return NULL;
        } else {
            /* alternates, basic types and enums can't be entered */
            return NULL;
        }

        query++;
    }

    return base;
}


/**
 * virQEMUQAPISchemaPathGet:
 * @query: string specifying the required data type (see below)
 * @schema: hash table containing the schema data
 * @entry: filled with the located schema object requested by @query
 *
 * Retrieves the requested schema entry specified by @query to @entry. The
 * @query parameter has the following syntax which is very closely tied to the
 * qemu schema syntax entries separated by slashes with a few special characters:
 *
 * "command_or_event/attribute/subattribute/+variant_discriminator/subattribute"
 *
 * command_or_event: name of the event or attribute to introspect
 * attribute: selects whether arguments or return type should be introspected
 *            ("arg-type" or "ret-type" for commands, "arg-type" for events)
 * subattribute: specifies member name of object types
 * +variant_discriminator: In the case of unionized objects, select a
 *                         specific case to introspect.
 *
 * Array types are automatically flattened to the singular type. Alternate
 * types are currently not supported.
 *
 * The above types can be chained arbitrarily using slashes to construct any
 * path into the schema tree.
 *
 * Returns 0 on success (including if the requested schema was not found) and
 * fills @entry appropriately. On failure returns -1 and sets an appropriate
 * error message.
 */
int
virQEMUQAPISchemaPathGet(const char *query,
                         virHashTablePtr schema,
                         virJSONValuePtr *entry)
{
    char **elems = NULL;

    *entry = NULL;

    if (!(elems = virStringSplit(query, "/", 0)))
        return -1;

    if (!*elems) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("malformed query string"));
        virStringListFree(elems);
        return -1;
    }

    *entry = virQEMUQAPISchemaTraverse(*elems, elems + 1, schema);

    virStringListFree(elems);
    return 0;
}


bool
virQEMUQAPISchemaPathExists(const char *query,
                            virHashTablePtr schema)
{
    virJSONValuePtr entry;

    if (virQEMUQAPISchemaPathGet(query, schema, &entry))
        return false;

    return !!entry;
}

static int
virQEMUQAPISchemaEntryProcess(size_t pos ATTRIBUTE_UNUSED,
                              virJSONValuePtr item,
                              void *opaque)
{
    const char *name;
    virHashTablePtr schema = opaque;

    if (!(name = virJSONValueObjectGetString(item, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed QMP schema"));
        return -1;
    }

    if (virHashAddEntry(schema, name, item) < 0)
        return -1;

    return 0;
}


/**
 * virQEMUQAPISchemaConvert:
 * @schemareply: Schema data as returned by the qemu monitor
 *
 * Converts the schema into the hash-table used by the functions working with
 * the schema. @schemareply is consumed and freed.
 */
virHashTablePtr
virQEMUQAPISchemaConvert(virJSONValuePtr schemareply)
{
    virHashTablePtr schema;
    virHashTablePtr ret = NULL;

    if (!(schema = virHashCreate(512, virJSONValueHashFree)))
        goto cleanup;

    if (virJSONValueArrayForeachSteal(schemareply,
                                      virQEMUQAPISchemaEntryProcess,
                                      schema) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, schema);

 cleanup:
    virJSONValueFree(schemareply);
    virHashFree(schema);
    return ret;
}
