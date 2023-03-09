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

#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_qapi");


/**
 * virQEMUQAPISchemaObjectGet:
 * @field: name of the object containing the requested type
 * @name: name of the requested type
 * @namefield: name of the object property holding @name
 * @elem: QAPI schema entry JSON object
 *
 * Helper that selects the type of a QMP schema object member or it's variant
 * member. Returns the QMP entry on success or NULL on error.
 */
static virJSONValue *
virQEMUQAPISchemaObjectGet(const char *field,
                           const char *name,
                           const char *namefield,
                           virJSONValue *elem)
{
    virJSONValue *arr;
    virJSONValue *cur;
    const char *curname;
    size_t i;

    if (!(arr = virJSONValueObjectGetArray(elem, field)))
        return NULL;

    for (i = 0; i < virJSONValueArraySize(arr); i++) {
        if (!(cur = virJSONValueArrayGet(arr, i)) ||
            !(curname = virJSONValueObjectGetString(cur, namefield)))
            continue;

        if (STREQ(name, curname))
            return cur;
    }

    return NULL;
}


struct virQEMUQAPISchemaTraverseContext {
    const char *prevquery;
    GHashTable *schema;
    char **queries;
    virJSONValue *returnType;
    size_t depth;
};


static int
virQEMUQAPISchemaTraverseContextValidateDepth(struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    if (ctxt->depth++ > 1000) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("possible loop in QMP schema"));
        return -1;
    }

    return 0;
}


static void
virQEMUQAPISchemaTraverseContextInit(struct virQEMUQAPISchemaTraverseContext *ctxt,
                                     char **queries,
                                     GHashTable *schema)
{
    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->schema = schema;
    ctxt->queries = queries;
}


static const char *
virQEMUQAPISchemaTraverseContextNextQuery(struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    ctxt->prevquery = ctxt->queries[0];
    ctxt->queries++;
    return ctxt->prevquery;
}


static bool
virQEMUQAPISchemaTraverseContextHasNextQuery(struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    return !!ctxt->queries[0];
}


static int
virQEMUQAPISchemaTraverse(const char *baseName,
                          struct virQEMUQAPISchemaTraverseContext *ctxt);


/**
 * @featurename: name of 'feature' field to select
 * @elem: QAPI JSON entry for a type
 *
 * Looks for @featurename in the array of 'features' for given type passed in
 * via @elem. Returns 1 if @featurename is present, 0 if it's not present
 * (or @elem has no 'features') or -2 if the schema is malformed.
 * (see virQEMUQAPISchemaTraverseFunc)
 */
static int
virQEMUQAPISchemaTraverseHasObjectFeature(const char *featurename,
                                          virJSONValue *elem)
{
    virJSONValue *featuresarray;
    virJSONValue *cur;
    const char *curstr;
    size_t i;

    if (!(featuresarray = virJSONValueObjectGetArray(elem, "features")))
        return 0;

    for (i = 0; i < virJSONValueArraySize(featuresarray); i++) {
        if (!(cur = virJSONValueArrayGet(featuresarray, i)) ||
            !(curstr = virJSONValueGetString(cur)))
            return -2;

        if (STREQ(featurename, curstr))
            return 1;
    }

    return 0;
}


static int
virQEMUQAPISchemaTraverseObject(virJSONValue *cur,
                                struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    virJSONValue *obj;
    const char *query = virQEMUQAPISchemaTraverseContextNextQuery(ctxt);
    char modifier = *query;

    if (!g_ascii_isalpha(modifier))
        query++;

    /* exit on modifiers for other types */
    if (modifier == '^' || modifier == '!')
        return 0;

    if (modifier == '$') {
        if (virQEMUQAPISchemaTraverseContextHasNextQuery(ctxt))
            return -3;

        return virQEMUQAPISchemaTraverseHasObjectFeature(query, cur);
    }

    if (modifier == '+') {
        obj = virQEMUQAPISchemaObjectGet("variants", query, "case", cur);
    } else {
        obj = virQEMUQAPISchemaObjectGet("members", query, "name", cur);

        if (modifier == '*' &&
            !virJSONValueObjectHasKey(obj, "default"))
            return 0;
    }

    if (!obj)
        return 0;

    return virQEMUQAPISchemaTraverse(virJSONValueObjectGetString(obj, "type"), ctxt);
}


static int
virQEMUQAPISchemaTraverseArray(virJSONValue *cur,
                               struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    const char *querytype;

    /* arrays are just flattened by default */
    if (!(querytype = virJSONValueObjectGetString(cur, "element-type")))
        return -2;

    return virQEMUQAPISchemaTraverse(querytype, ctxt);
}


static int
virQEMUQAPISchemaTraverseCommand(virJSONValue *cur,
                                 struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    const char *query = virQEMUQAPISchemaTraverseContextNextQuery(ctxt);
    const char *querytype;
    char modifier = *query;

    if (!g_ascii_isalpha(modifier))
        query++;

    /* exit on modifiers for other types */
    if (modifier == '^' || modifier == '!' || modifier == '+' || modifier == '*')
        return 0;

    if (modifier == '$') {
        if (virQEMUQAPISchemaTraverseContextHasNextQuery(ctxt))
            return -3;

        return virQEMUQAPISchemaTraverseHasObjectFeature(query, cur);
    }

    if (!(querytype = virJSONValueObjectGetString(cur, query)))
        return 0;

    return virQEMUQAPISchemaTraverse(querytype, ctxt);
}


static int
virQEMUQAPISchemaTraverseEnum(virJSONValue *cur,
                              struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    const char *query = virQEMUQAPISchemaTraverseContextNextQuery(ctxt);
    const char *featurequery = NULL;
    virJSONValue *values;
    virJSONValue *members;
    size_t i;

    if (query[0] != '^')
        return 0;

    if (virQEMUQAPISchemaTraverseContextHasNextQuery(ctxt)) {
        /* we might have a query for a feature flag of an enum value */
        featurequery = virQEMUQAPISchemaTraverseContextNextQuery(ctxt);

        if (*featurequery != '$' ||
            virQEMUQAPISchemaTraverseContextHasNextQuery(ctxt))
            return -3;

        featurequery++;
    }

    query++;

    /* qemu-6.2 added a "members" array superseding "values" */
    if ((members = virJSONValueObjectGetArray(cur, "members"))) {
        for (i = 0; i < virJSONValueArraySize(members); i++) {
            virJSONValue *member = virJSONValueArrayGet(members, i);
            const char *name;

            if (!member || !(name = virJSONValueObjectGetString(member, "name")))
                return -2;

            if (STREQ(name, query)) {
                if (featurequery)
                    return virQEMUQAPISchemaTraverseHasObjectFeature(featurequery, member);

                return 1;
            }
        }

        return 0;
    }

    /* old-style "values" array doesn't have feature flags so any query is necessarily false */
    if (featurequery)
        return 0;

    if (!(values = virJSONValueObjectGetArray(cur, "values")))
        return -2;

    for (i = 0; i < virJSONValueArraySize(values); i++) {
        virJSONValue *enumval;
        const char *value;

        if (!(enumval = virJSONValueArrayGet(values, i)) ||
            !(value = virJSONValueGetString(enumval)))
            continue;

        if (STREQ(value, query))
            return 1;
    }

    return 0;
}


static int
virQEMUQAPISchemaTraverseBuiltin(virJSONValue *cur,
                                 struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    const char *query = virQEMUQAPISchemaTraverseContextNextQuery(ctxt);
    const char *jsontype;

    if (query[0] != '!')
        return 0;

    if (virQEMUQAPISchemaTraverseContextHasNextQuery(ctxt))
        return -3;

    query++;

    if (!(jsontype = virJSONValueObjectGetString(cur, "json-type")))
        return -1;

    if (STREQ(jsontype, query))
        return 1;

    return 0;
}


static int
virQEMUQAPISchemaTraverseAlternate(virJSONValue *cur,
                                   struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    struct virQEMUQAPISchemaTraverseContext savectxt = *ctxt;
    virJSONValue *members;
    virJSONValue *member;
    const char *membertype;
    int rc;
    size_t i;

    if (!(members = virJSONValueObjectGetArray(cur, "members")))
        return -2;

    for (i = 0; i < virJSONValueArraySize(members); i++) {
        if (!(member = virJSONValueArrayGet(members, i)) ||
            !(membertype = virJSONValueObjectGetString(member, "type")))
            continue;

        *ctxt = savectxt;

        if ((rc = virQEMUQAPISchemaTraverse(membertype, ctxt)) != 0)
            return rc;
    }

    return 0;
}


/* The function must return 1 on successful query, 0 if the query was not found
 * -1 when a libvirt error is reported, -2 if the schema is invalid and -3 if
 *  the query component is malformed. */
typedef int (*virQEMUQAPISchemaTraverseFunc)(virJSONValue *cur,
                                             struct virQEMUQAPISchemaTraverseContext *ctxt);

struct virQEMUQAPISchemaTraverseMetaType {
    const char *metatype;
    virQEMUQAPISchemaTraverseFunc func;
};


static const struct virQEMUQAPISchemaTraverseMetaType traverseMetaType[] = {
    { "object", virQEMUQAPISchemaTraverseObject },
    { "array", virQEMUQAPISchemaTraverseArray },
    { "command", virQEMUQAPISchemaTraverseCommand },
    { "event", virQEMUQAPISchemaTraverseCommand },
    { "enum", virQEMUQAPISchemaTraverseEnum },
    { "builtin", virQEMUQAPISchemaTraverseBuiltin },
    { "alternate", virQEMUQAPISchemaTraverseAlternate },
};


static int
virQEMUQAPISchemaTraverse(const char *baseName,
                          struct virQEMUQAPISchemaTraverseContext *ctxt)
{
    virJSONValue *cur;
    const char *metatype;
    size_t i;

    if (virQEMUQAPISchemaTraverseContextValidateDepth(ctxt) < 0)
        return -2;

    if (!(cur = virHashLookup(ctxt->schema, baseName)))
        return -2;

    if (!virQEMUQAPISchemaTraverseContextHasNextQuery(ctxt)) {
        ctxt->returnType = cur;
        return 1;
    }

    if (!(metatype = virJSONValueObjectGetString(cur, "meta-type")))
        return -2;

    for (i = 0; i < G_N_ELEMENTS(traverseMetaType); i++) {
        if (STREQ(metatype, traverseMetaType[i].metatype))
            return traverseMetaType[i].func(cur, ctxt);
    }

    return 0;
}


/**
 * virQEMUQAPISchemaPathGet:
 * @query: string specifying the required data type (see below)
 * @schema: hash table containing the schema data
 * @entry: filled with the located schema object requested by @query (optional)
 *
 * Retrieves the requested schema entry specified by @query to @entry. The
 * @query parameter has the following syntax which is very closely tied to the
 * qemu schema syntax entries separated by slashes with a few special characters:
 *
 * "command_or_event/attribute/subattribute/subattribute/..."
 *
 * command_or_event: name of the event or attribute to introspect
 * attribute: selects whether arguments or return type should be introspected
 *            ("arg-type" or "ret-type" for commands, "arg-type" for events)
 *
 * 'subattribute' may be one or more of the following depending on the first
 * character.
 *
 * - Type queries - @entry is filled on success with the corresponding schema entry:
 *   'subattribute': selects a plain object member named 'subattribute'
 *   '*subattribute': same as above but the selected member must be optional
 *                    (has a property named 'default' in the schema)
 *   '+variant': In the case of unionized objects, select a specific variant of
 *               the previously selected member
 *
 * - Boolean queries - @entry remains NULL, return value indicates success:
 *   '^enumval': returns true if the previously selected enum contains 'enumval'
 *   '!basictype': returns true if previously selected type is of 'basictype'
 *                 JSON type. Supported are 'null', 'string', 'number', 'value',
 *                 'int' and 'boolean.
 *   '$feature': returns true if the previously selected type supports 'feature'
 *               ('feature' is in the 'features' array of given type)
 *
 * If the name of any (sub)attribute starts with non-alphabetical symbols it
 * needs to be prefixed by a single space.
 *
 * Array types are automatically flattened to the singular type. Alternates are
 * iterated until first success.
 *
 * The above types can be chained arbitrarily using slashes to construct any
 * path into the schema tree, booleans must be always the last component as they
 * don't refer to a type. An exception is querying feature of an enum value
 * (.../^enumval/$featurename) which is allowed.
 *
 * Returns 1 if @query was found in @schema filling @entry if non-NULL, 0 if
 * @query was not found in @schema and -1 on other errors along with an appropriate
 * error message.
 */
int
virQEMUQAPISchemaPathGet(const char *query,
                         GHashTable *schema,
                         virJSONValue **entry)
{
    g_auto(GStrv) elems = NULL;
    struct virQEMUQAPISchemaTraverseContext ctxt;
    const char *cmdname;
    int rc;

    if (entry)
        *entry = NULL;

    if (!(elems = g_strsplit(query, "/", 0)))
        return -1;

    if (!*elems) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("malformed query string"));
        return -1;
    }

    virQEMUQAPISchemaTraverseContextInit(&ctxt, elems, schema);
    cmdname = virQEMUQAPISchemaTraverseContextNextQuery(&ctxt);

    if (!virHashLookup(schema, cmdname))
        return 0;

    rc = virQEMUQAPISchemaTraverse(cmdname, &ctxt);

    if (entry)
        *entry = ctxt.returnType;

    if (rc >= 0)
        return rc;

    if (rc == -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed QAPI schema when querying '%1$s' of '%2$s'"),
                       NULLSTR(ctxt.prevquery), query);
    } else if (rc == -3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("terminal QAPI query component '%1$s' of '%2$s' must not have followers"),
                       NULLSTR(ctxt.prevquery), query);
    }

    return -1;
}


bool
virQEMUQAPISchemaPathExists(const char *query,
                            GHashTable *schema)
{
    return virQEMUQAPISchemaPathGet(query, schema, NULL) == 1;
}

static int
virQEMUQAPISchemaEntryProcess(size_t pos G_GNUC_UNUSED,
                              virJSONValue *item,
                              void *opaque)
{
    const char *name;
    GHashTable *schema = opaque;

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
GHashTable *
virQEMUQAPISchemaConvert(virJSONValue *schemareply)
{
    g_autoptr(GHashTable) schema = NULL;
    g_autoptr(virJSONValue) schemajson = schemareply;

    if (!(schema = virHashNew(virJSONValueHashFree)))
        return NULL;

    if (virJSONValueArrayForeachSteal(schemajson,
                                      virQEMUQAPISchemaEntryProcess,
                                      schema) < 0)
        return NULL;

    return g_steal_pointer(&schema);
}
