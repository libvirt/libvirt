/*
 * testutilsqemuschema.c: helper functions for QEMU QAPI schema testing
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
#include "testutils.h"
#include "testutilsqemu.h"
#include "testutilsqemuschema.h"
#include "qemu/qemu_qapi.h"

struct testQEMUSchemaValidateCtxt {
    GHashTable *schema;
    virBuffer *debug;
    bool allowDeprecated;
    bool allowIncomplete; /* allow members not (yet) covered by the schema */
};


static int
testQEMUSchemaValidateDeprecated(virJSONValue *root,
                                 const char *name,
                                 struct testQEMUSchemaValidateCtxt *ctxt)
{
    virJSONValue *features = virJSONValueObjectGetArray(root, "features");
    size_t nfeatures;
    size_t i;

    if (!features)
        return 0;

    nfeatures = virJSONValueArraySize(features);

    for (i = 0; i < nfeatures; i++) {
        virJSONValue *cur = virJSONValueArrayGet(features, i);
        const char *curstr;

        if (!cur ||
            !(curstr = virJSONValueGetString(cur))) {
            virBufferAsprintf(ctxt->debug, "ERROR: features of '%s' are malformed", name);
            return -2;
        }

        if (STREQ(curstr, "deprecated")) {
            if (ctxt->allowDeprecated) {
                virBufferAsprintf(ctxt->debug, "WARNING: '%s' is deprecated", name);
                if (virTestGetVerbose())
                    g_fprintf(stderr, "\nWARNING: '%s' is deprecated\n", name);
                return 0;
            } else {
                virBufferAsprintf(ctxt->debug, "ERROR: '%s' is deprecated", name);
                return -1;
            }
        }
    }

    return 0;
}


static int
testQEMUSchemaValidateRecurse(virJSONValue *obj,
                              virJSONValue *root,
                              struct testQEMUSchemaValidateCtxt *ctxt);

static int
testQEMUSchemaValidateBuiltin(virJSONValue *obj,
                              virJSONValue *root,
                              struct testQEMUSchemaValidateCtxt *ctxt)
{
    const char *t = virJSONValueObjectGetString(root, "json-type");
    const char *s = NULL;
    bool b = false;
    int ret = -1;

    if (STREQ_NULLABLE(t, "value")) {
        s = "{any}";
        ret = 0;
        goto cleanup;
    }

    switch (virJSONValueGetType(obj)) {
    case VIR_JSON_TYPE_STRING:
        if (STRNEQ_NULLABLE(t, "string"))
            goto cleanup;
        s = virJSONValueGetString(obj);
        break;

    case VIR_JSON_TYPE_NUMBER:
        if (STRNEQ_NULLABLE(t, "int") &&
            STRNEQ_NULLABLE(t, "number"))
            goto cleanup;
        s = "{number}";
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        if (STRNEQ_NULLABLE(t, "boolean"))
            goto cleanup;
        virJSONValueGetBoolean(obj, &b);
        if (b)
            s = "true";
        else
            s = "false";
        break;

    case VIR_JSON_TYPE_NULL:
        if (STRNEQ_NULLABLE(t, "null"))
            goto cleanup;
        break;

    case VIR_JSON_TYPE_OBJECT:
    case VIR_JSON_TYPE_ARRAY:
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret == 0)
        virBufferAsprintf(ctxt->debug, "'%s': OK", s);
    else
        virBufferAsprintf(ctxt->debug, "ERROR: expected type '%s', actual type %d",
                          t, virJSONValueGetType(obj));
    return ret;
}

struct testQEMUSchemaValidateObjectMemberData {
    virJSONValue *rootmembers;
    struct testQEMUSchemaValidateCtxt *ctxt;
    bool missingMandatory;
};


static virJSONValue *
testQEMUSchemaStealObjectMemberByName(const char *name,
                                      virJSONValue *members)
{
    virJSONValue *member;
    virJSONValue *ret = NULL;
    size_t i;

    for (i = 0; i < virJSONValueArraySize(members); i++) {
        member = virJSONValueArrayGet(members, i);

        if (STREQ_NULLABLE(name, virJSONValueObjectGetString(member, "name"))) {
            ret = virJSONValueArraySteal(members, i);
            break;
        }
    }

    return ret;
}


static int
testQEMUSchemaValidateObjectMember(const char *key,
                                   virJSONValue *value,
                                   void *opaque)
{
    struct testQEMUSchemaValidateObjectMemberData *data = opaque;
    g_autoptr(virJSONValue) keymember = NULL;
    const char *keytype;
    virJSONValue *keyschema = NULL;
    int rc;

    virBufferStrcat(data->ctxt->debug, key, ": ", NULL);

    /* lookup 'member' entry for key */
    if (!(keymember = testQEMUSchemaStealObjectMemberByName(key, data->rootmembers))) {
        if (data->ctxt->allowIncomplete) {
            virBufferAddLit(data->ctxt->debug, " schema missing - OK(waived)\n");
            return 0;
        }
        virBufferAddLit(data->ctxt->debug, "ERROR: attribute not in schema\n");
        return -1;
    }

    /* validate that the member is not deprecated */
    if ((rc = testQEMUSchemaValidateDeprecated(keymember, key, data->ctxt)) < 0)
        return rc;

    /* lookup schema entry for keytype */
    if (!(keytype = virJSONValueObjectGetString(keymember, "type")) ||
        !(keyschema = virHashLookup(data->ctxt->schema, keytype))) {
        virBufferAsprintf(data->ctxt->debug, "ERROR: can't find schema for type '%s'\n",
                          NULLSTR(keytype));
        return -2;
    }

    /* recurse */
    rc = testQEMUSchemaValidateRecurse(value, keyschema, data->ctxt);

    virBufferAddLit(data->ctxt->debug, "\n");
    return rc;
}


static int
testQEMUSchemaValidateObjectMergeVariantMember(size_t pos G_GNUC_UNUSED,
                                               virJSONValue *item,
                                               void *opaque)
{
    virJSONValue *array = opaque;
    g_autoptr(virJSONValue) copy = NULL;

    if (!(copy = virJSONValueCopy(item)))
        return -1;

    if (virJSONValueArrayAppend(array, &copy) < 0)
        return -1;

    return 1;
}


/**
 * testQEMUSchemaValidateObjectMergeVariant:
 *
 * Merges schema of variant @variantname in @root into @root and removes the
 * 'variants' array from @root.
 */
static int
testQEMUSchemaValidateObjectMergeVariant(virJSONValue *root,
                                         const char *variantfield,
                                         const char *variantname,
                                         struct testQEMUSchemaValidateCtxt *ctxt)
{
    size_t i;
    g_autoptr(virJSONValue) variants = NULL;
    virJSONValue *variant;
    virJSONValue *variantschema;
    virJSONValue *variantschemamembers;
    virJSONValue *rootmembers;
    const char *varianttype = NULL;

    if (!(variants = virJSONValueObjectStealArray(root, "variants"))) {
        virBufferAddLit(ctxt->debug, "ERROR: missing 'variants' in schema\n");
        return -2;
    }

    for (i = 0; i < virJSONValueArraySize(variants); i++) {
        variant = virJSONValueArrayGet(variants, i);

        if (STREQ_NULLABLE(variantname,
                           virJSONValueObjectGetString(variant, "case"))) {
            varianttype = virJSONValueObjectGetString(variant, "type");
            break;
        }
    }

    if (!varianttype) {
        virBufferAsprintf(ctxt->debug, "ERROR: variant '%s' for discriminator '%s' not found\n",
                          variantname, variantfield);
        return -1;
    }

    if (!(variantschema = virHashLookup(ctxt->schema, varianttype)) ||
        !(variantschemamembers = virJSONValueObjectGetArray(variantschema, "members"))) {
        virBufferAsprintf(ctxt->debug,
                          "ERROR: missing schema or schema members for variant '%s'(%s)\n",
                          variantname, varianttype);
        return -2;
    }

    rootmembers = virJSONValueObjectGetArray(root, "members");

    if (virJSONValueArrayForeachSteal(variantschemamembers,
                                      testQEMUSchemaValidateObjectMergeVariantMember,
                                      rootmembers) < 0) {
        return -2;
    }

    return 0;
}


static int
testQEMUSchemaValidateObjectMandatoryMember(size_t pos G_GNUC_UNUSED,
                                            virJSONValue *item,
                                            void *opaque G_GNUC_UNUSED)
{
    struct testQEMUSchemaValidateObjectMemberData *data = opaque;

    if (!virJSONValueObjectHasKey(item, "default")) {
        virBufferAsprintf(data->ctxt->debug, "ERROR: missing mandatory attribute '%s'\n",
                          NULLSTR(virJSONValueObjectGetString(item, "name")));
        data->missingMandatory = true;
    }

    return 1;
}


static int
testQEMUSchemaValidateObject(virJSONValue *obj,
                             virJSONValue *root,
                             struct testQEMUSchemaValidateCtxt *ctxt)
{
    struct testQEMUSchemaValidateObjectMemberData data = { NULL, ctxt, false };
    g_autoptr(virJSONValue) localroot = NULL;
    const char *variantfield;
    const char *variantname;

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virBufferAddLit(ctxt->debug, "ERROR: not an object");
        return -1;
    }

    virBufferAddLit(ctxt->debug, "{\n");
    virBufferAdjustIndent(ctxt->debug, 3);

    /* copy schema */
    if (!(localroot = virJSONValueCopy(root)))
        return -2;

    /* remove variant */
    if ((variantfield = virJSONValueObjectGetString(localroot, "tag"))) {
        if (!(variantname = virJSONValueObjectGetString(obj, variantfield))) {
            virBufferAsprintf(ctxt->debug, "ERROR: missing variant discriminator attribute '%s'\n",
                              variantfield);
            return -1;
        }

        if (testQEMUSchemaValidateObjectMergeVariant(localroot, variantfield,
                                                     variantname, ctxt) < 0)
            return -1;
    }


    /* validate members */
    data.rootmembers = virJSONValueObjectGetArray(localroot, "members");
    if (virJSONValueObjectForeachKeyValue(obj,
                                          testQEMUSchemaValidateObjectMember,
                                          &data) < 0)
        return -1;

    /* check missing mandatory values */
    if (virJSONValueArrayForeachSteal(data.rootmembers,
                                      testQEMUSchemaValidateObjectMandatoryMember,
                                      &data) < 0) {
        return -2;
    }

    if (data.missingMandatory)
        return -1;

    virBufferAdjustIndent(ctxt->debug, -3);
    virBufferAddLit(ctxt->debug, "} OK");
    return 0;
}


static int
testQEMUSchemaValidateEnum(virJSONValue *obj,
                           virJSONValue *root,
                           struct testQEMUSchemaValidateCtxt *ctxt)
{
    const char *objstr;
    virJSONValue *values = NULL;
    virJSONValue *members = NULL;
    size_t i;

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_STRING) {
        virBufferAddLit(ctxt->debug, "ERROR: not a string");
        return -1;
    }

    objstr = virJSONValueGetString(obj);

    /* qemu-6.2 added a "members" array superseding "values" */
    if ((members = virJSONValueObjectGetArray(root, "members"))) {
        for (i = 0; i < virJSONValueArraySize(members); i++) {
            virJSONValue *member = virJSONValueArrayGet(members, i);

            if (STREQ_NULLABLE(objstr, virJSONValueObjectGetString(member, "name"))) {
                int rc;

                /* the new 'members' array allows us to check deprecations */
                if ((rc = testQEMUSchemaValidateDeprecated(member, objstr, ctxt)) < 0)
                    return rc;

                virBufferAsprintf(ctxt->debug, "'%s' OK", NULLSTR(objstr));
                return 0;
            }
        }

        virBufferAsprintf(ctxt->debug, "ERROR: enum value '%s' is not in schema",
                          NULLSTR(objstr));
        return -1;
    }

    if ((values = virJSONValueObjectGetArray(root, "values"))) {
        for (i = 0; i < virJSONValueArraySize(values); i++) {
            virJSONValue *value = virJSONValueArrayGet(values, i);

            if (STREQ_NULLABLE(objstr, virJSONValueGetString(value))) {
                virBufferAsprintf(ctxt->debug, "'%s' OK", NULLSTR(objstr));
                return 0;
            }
        }

        virBufferAsprintf(ctxt->debug, "ERROR: enum value '%s' is not in schema",
                          NULLSTR(objstr));
        return -1;
    }

    virBufferAsprintf(ctxt->debug, "ERROR: missing enum values in schema '%s'",
                      NULLSTR(virJSONValueObjectGetString(root, "name")));
    return -2;
}


static int
testQEMUSchemaValidateArray(virJSONValue *objs,
                            virJSONValue *root,
                            struct testQEMUSchemaValidateCtxt *ctxt)
{
    const char *elemtypename = virJSONValueObjectGetString(root, "element-type");
    virJSONValue *elementschema;
    virJSONValue *obj;
    size_t i;

    if (virJSONValueGetType(objs) != VIR_JSON_TYPE_ARRAY) {
        virBufferAddLit(ctxt->debug, "ERROR: not an array\n");
        return -1;
    }

    if (!elemtypename ||
        !(elementschema = virHashLookup(ctxt->schema, elemtypename))) {
        virBufferAsprintf(ctxt->debug, "ERROR: missing schema for array element type '%s'",
                         NULLSTR(elemtypename));
        return -2;
    }

    virBufferAddLit(ctxt->debug, "[\n");
    virBufferAdjustIndent(ctxt->debug, 3);

    for (i = 0; i < virJSONValueArraySize(objs); i++) {
        obj = virJSONValueArrayGet(objs, i);

        if (testQEMUSchemaValidateRecurse(obj, elementschema, ctxt) < 0)
            return -1;
        virBufferAddLit(ctxt->debug, ",\n");
    }
    virBufferAddLit(ctxt->debug, "] OK");
    virBufferAdjustIndent(ctxt->debug, -3);

    return 0;
}

static int
testQEMUSchemaValidateAlternate(virJSONValue *obj,
                                virJSONValue *root,
                                struct testQEMUSchemaValidateCtxt *ctxt)
{
    virJSONValue *members;
    virJSONValue *member;
    size_t i;
    size_t n;
    const char *membertype;
    virJSONValue *memberschema;
    int indent;
    int rc;

    if (!(members = virJSONValueObjectGetArray(root, "members"))) {
        virBufferAddLit(ctxt->debug, "ERROR: missing 'members' for alternate schema");
        return -2;
    }

    virBufferAddLit(ctxt->debug, "(\n");
    virBufferAdjustIndent(ctxt->debug, 3);
    indent = virBufferGetIndent(ctxt->debug);

    n = virJSONValueArraySize(members);
    for (i = 0; i < n; i++) {
        membertype = NULL;

        /* P != NP */
        virBufferAsprintf(ctxt->debug, "(alternate %zu/%zu)\n", i + 1, n);
        virBufferAdjustIndent(ctxt->debug, 3);

        if (!(member = virJSONValueArrayGet(members, i)) ||
            !(membertype = virJSONValueObjectGetString(member, "type")) ||
            !(memberschema = virHashLookup(ctxt->schema, membertype))) {
            virBufferAsprintf(ctxt->debug, "ERROR: missing schema for alternate type '%s'",
                              NULLSTR(membertype));
            return -2;
        }

        rc = testQEMUSchemaValidateRecurse(obj, memberschema, ctxt);

        virBufferAddLit(ctxt->debug, "\n");
        virBufferSetIndent(ctxt->debug, indent);
        virBufferAsprintf(ctxt->debug, "(/alternate %zu/%zu)\n", i + 1, n);

        if (rc == 0) {
            virBufferAdjustIndent(ctxt->debug, -3);
            virBufferAddLit(ctxt->debug, ") OK");
            return 0;
        }
    }

    virBufferAddLit(ctxt->debug, "ERROR: no alternate type was matched");
    return -1;
}


static int
testQEMUSchemaValidateRecurse(virJSONValue *obj,
                              virJSONValue *root,
                              struct testQEMUSchemaValidateCtxt *ctxt)
{
    const char *n = virJSONValueObjectGetString(root, "name");
    const char *t = virJSONValueObjectGetString(root, "meta-type");
    int rc;

    if ((rc = testQEMUSchemaValidateDeprecated(root, n, ctxt)) < 0)
        return rc;

    if (STREQ_NULLABLE(t, "builtin")) {
        return testQEMUSchemaValidateBuiltin(obj, root, ctxt);
    } else if (STREQ_NULLABLE(t, "object")) {
        return testQEMUSchemaValidateObject(obj, root, ctxt);
    } else if (STREQ_NULLABLE(t, "enum")) {
        return testQEMUSchemaValidateEnum(obj, root, ctxt);
    } else if (STREQ_NULLABLE(t, "array")) {
        return testQEMUSchemaValidateArray(obj, root, ctxt);
    } else if (STREQ_NULLABLE(t, "alternate")) {
        return testQEMUSchemaValidateAlternate(obj, root, ctxt);
    }

    virBufferAsprintf(ctxt->debug,
                      "qapi schema meta-type '%s' of type '%s' not handled\n",
                      NULLSTR(t), NULLSTR(n));
    return -2;
}


/**
 * testQEMUSchemaValidate:
 * @obj: object to validate
 * @root: schema entry to start from
 * @schema: hash table containing schema entries
 * @debug: a virBuffer which will be filled with debug information if provided
 *
 * Validates whether @obj conforms to the QAPI schema passed in via @schema,
 * starting from the node @root. Returns 0, if @obj matches @schema, -1 if it
 * does not and -2 if there is a problem with the schema or with internals.
 *
 * @debug is filled with information regarding the validation process
 */
int
testQEMUSchemaValidate(virJSONValue *obj,
                       virJSONValue *root,
                       GHashTable *schema,
                       bool allowDeprecated,
                       virBuffer *debug)
{
    struct testQEMUSchemaValidateCtxt ctxt = { .schema = schema,
                                               .debug = debug,
                                               .allowDeprecated = allowDeprecated };

    return testQEMUSchemaValidateRecurse(obj, root, &ctxt);
}


/**
 * testQEMUSchemaValidateCommand:
 * @command: command to validate
 * @arguments: arguments of @command to validate
 * @schema: hash table containing schema entries
 * @allowDeprecated: don't fails schema validation if @command or one of @arguments
 *                   is deprecated
 * @allowRemoved: skip validation fully if @command was not found
 * @allowIncomplete: don't fail validation if members not covered by schema are present
 *                   (for waiving commands with incomplete schema)
 * @debug: a virBuffer which will be filled with debug information if provided
 *
 * Validates whether @command and its @arguments conform to the QAPI schema
 * passed in via @schema. Returns 0, if the command and args match @schema,
 * -1 if it does not and -2 if there is a problem with the schema or with
 *  internals.
 *
 * @allowRemoved should generally be used only if it's certain that there's a
 * replacement of @command in place.
 *
 * @debug is filled with information regarding the validation process
 */
int
testQEMUSchemaValidateCommand(const char *command,
                              virJSONValue *arguments,
                              GHashTable *schema,
                              bool allowDeprecated,
                              bool allowRemoved,
                              bool allowIncomplete,
                              virBuffer *debug)
{
    struct testQEMUSchemaValidateCtxt ctxt = { .schema = schema,
                                               .debug = debug,
                                               .allowDeprecated = allowDeprecated,
                                               .allowIncomplete = allowIncomplete };
    g_autofree char *schemapatharguments = g_strdup_printf("%s/arg-type", command);
    g_autoptr(virJSONValue) emptyargs = NULL;
    virJSONValue *schemarootcommand;
    virJSONValue *schemarootarguments;
    int rc;

    if (virQEMUQAPISchemaPathGet(command, schema, &schemarootcommand) < 0 ||
        !schemarootcommand) {
        if (allowRemoved)
            return 0;

        virBufferAsprintf(debug, "ERROR: command '%s' not found in the schema", command);
        return -1;
    }

    if ((rc = testQEMUSchemaValidateDeprecated(schemarootcommand, command, &ctxt)) < 0)
        return rc;

    if (!arguments)
        arguments = emptyargs = virJSONValueNewObject();

    if (virQEMUQAPISchemaPathGet(schemapatharguments, schema, &schemarootarguments) < 0 ||
        !schemarootarguments) {
        virBufferAsprintf(debug, "ERROR: failed to look up 'arg-type' of  '%s'", command);
        return -1;
    }

    return testQEMUSchemaValidateRecurse(arguments, schemarootarguments, &ctxt);
}


/**
 * testQEMUSchemaEntryMatchTemplate:
 *
 * @schemaentry: a JSON object representing a 'object' node in the QAPI schema
 * ...: a NULL terminated list of strings representing the template of properties
 *      which the QMP object needs to have.
 *
 *      The strings have following format:
 *
 *      "type:name"
 *      "?type:name"
 *
 *      "type" corresponds to the 'type' property of the member to check (str, bool, any ...)
 *      "name" corresponds to the name of the member to check
 *
 *      If the query string starts with an '?' and member 'name' may be missing.
 *
 * This function matches that @schemaentry has all expected members and the
 * members have expected types. @schemaentry also must not have any unknown
 * members.
 */
int
testQEMUSchemaEntryMatchTemplate(virJSONValue *schemaentry,
                                 ...)
{
    g_autoptr(virJSONValue) members = NULL;
    va_list ap;
    const char *next;
    int ret = -1;

    if (STRNEQ_NULLABLE(virJSONValueObjectGetString(schemaentry, "meta-type"), "object")) {
        VIR_TEST_VERBOSE("schemaentry is not an object");
        return -1;
    }

    if (!(members = virJSONValueCopy(virJSONValueObjectGetArray(schemaentry, "members")))) {
        VIR_TEST_VERBOSE("failed to copy 'members'");
        return -1;
    }

    va_start(ap, schemaentry);

    /* pass 1 */

    while ((next = va_arg(ap, const char *))) {
        char modifier = *next;
        g_autofree char *type = NULL;
        char *name;
        size_t i;
        bool found = false;
        bool optional = false;

        if (!g_ascii_isalpha(modifier))
            next++;

        if (modifier == '?')
            optional = true;

        type = g_strdup(next);

        if ((name = strchr(type, ':'))) {
            *(name++) = '\0';
        } else {
            VIR_TEST_VERBOSE("malformed template string '%s'", next);
            goto cleanup;
        }

        for (i = 0; i < virJSONValueArraySize(members); i++) {
            virJSONValue *member = virJSONValueArrayGet(members, i);
            const char *membername = virJSONValueObjectGetString(member, "name");
            const char *membertype = virJSONValueObjectGetString(member, "type");

            if (STRNEQ_NULLABLE(name, membername))
                continue;

            if (STRNEQ_NULLABLE(membertype, type)) {
                VIR_TEST_VERBOSE("member '%s' is of unexpected type '%s' (expected '%s')",
                                 NULLSTR(membername), NULLSTR(membertype), type);
                goto cleanup;
            }

            found = true;
            break;
        }

        if (found) {
            virJSONValueFree(virJSONValueArraySteal(members, i));
        } else {
            if (!optional) {
                VIR_TEST_VERBOSE("mandatory member '%s' not found", name);
                goto cleanup;
            }
        }
    }

    /* pass 2 - check any unexpected members */
    if (virJSONValueArraySize(members) > 0) {
        size_t i;

        for (i = 0; i < virJSONValueArraySize(members); i++) {
            VIR_TEST_VERBOSE("unexpected member '%s'",
                             NULLSTR(virJSONValueObjectGetString(virJSONValueArrayGet(members, i), "name")));
        }

        goto cleanup;
    }

    ret = 0;

 cleanup:
    va_end(ap);
    return ret;
}


static virJSONValue *
testQEMUSchemaLoadReplies(const char *filename)
{
    g_autofree char *caps = NULL;
    char *schemaReply;
    char *end;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *schema = NULL;

    if (virTestLoadFile(filename, &caps) < 0)
        return NULL;

    if (!(schemaReply = strstr(caps, "\"execute\": \"query-qmp-schema\"")) ||
        !(schemaReply = strstr(schemaReply, "\n\n")) ||
        !(end = strstr(schemaReply + 2, "\n\n"))) {
        VIR_TEST_VERBOSE("failed to find reply to 'query-qmp-schema' in '%s'",
                         filename);
        return NULL;
    }

    schemaReply += 2;
    *end = '\0';

    if (!(reply = virJSONValueFromString(schemaReply))) {
        VIR_TEST_VERBOSE("failed to parse 'query-qmp-schema' reply from '%s'",
                         filename);
        return NULL;
    }

    if (!(schema = virJSONValueObjectStealArray(reply, "return"))) {
        VIR_TEST_VERBOSE("missing qapi schema data in reply in '%s'",
                         filename);
        return NULL;
    }

    return schema;
}


/**
 * testQEMUSchemaGetLatest:
 *
 * Returns the schema data as the qemu monitor would reply from the latest
 * replies file used for qemucapabilitiestest for the x86_64 architecture.
 */
virJSONValue *
testQEMUSchemaGetLatest(const char *arch)
{
    g_autofree char *capsLatestFile = NULL;

    if (!(capsLatestFile = testQemuGetLatestCapsForArch(arch, "replies"))) {
        VIR_TEST_VERBOSE("failed to find latest caps replies");
        return NULL;
    }

    VIR_TEST_DEBUG("replies file: '%s'", capsLatestFile);

    return testQEMUSchemaLoadReplies(capsLatestFile);
}


GHashTable *
testQEMUSchemaLoadLatest(const char *arch)
{
    virJSONValue *schema;

    if (!(schema = testQEMUSchemaGetLatest(arch)))
        return NULL;

    return virQEMUQAPISchemaConvert(schema);
}


GHashTable *
testQEMUSchemaLoad(const char *filename)
{
    virJSONValue *schema;

    if (!(schema = testQEMUSchemaLoadReplies(filename)))
        return NULL;

    return virQEMUQAPISchemaConvert(schema);
}
