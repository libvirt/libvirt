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

static int
testQEMUSchemaValidateRecurse(virJSONValuePtr obj,
                              virJSONValuePtr root,
                              virHashTablePtr schema,
                              virBufferPtr debug);

static int
testQEMUSchemaValidateBuiltin(virJSONValuePtr obj,
                              virJSONValuePtr root,
                              virBufferPtr debug)
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
        virBufferAsprintf(debug, "'%s': OK", s);
    else
        virBufferAsprintf(debug, "ERROR: expected type '%s', actual type %d",
                          t, virJSONValueGetType(obj));
    return ret;
}

struct testQEMUSchemaValidateObjectMemberData {
    virJSONValuePtr rootmembers;
    virHashTablePtr schema;
    virBufferPtr debug;
    bool missingMandatory;
};


static virJSONValuePtr
testQEMUSchemaStealObjectMemberByName(const char *name,
                                      virJSONValuePtr members)
{
    virJSONValuePtr member;
    virJSONValuePtr ret = NULL;
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
                                   virJSONValuePtr value,
                                   void *opaque)
{
    struct testQEMUSchemaValidateObjectMemberData *data = opaque;
    virJSONValuePtr keymember = NULL;
    const char *keytype;
    virJSONValuePtr keyschema = NULL;
    int ret = -1;

    virBufferStrcat(data->debug, key, ": ", NULL);

    /* lookup 'member' entry for key */
    if (!(keymember = testQEMUSchemaStealObjectMemberByName(key, data->rootmembers))) {
        virBufferAddLit(data->debug, "ERROR: attribute not in schema");
        goto cleanup;
    }

    /* lookup schema entry for keytype */
    if (!(keytype = virJSONValueObjectGetString(keymember, "type")) ||
        !(keyschema = virHashLookup(data->schema, keytype))) {
        virBufferAsprintf(data->debug, "ERROR: can't find schema for type '%s'",
                          NULLSTR(keytype));
        ret = -2;
        goto cleanup;
    }

    /* recurse */
    ret = testQEMUSchemaValidateRecurse(value, keyschema, data->schema,
                                        data->debug);

 cleanup:
    virBufferAddLit(data->debug, "\n");
    virJSONValueFree(keymember);
    return ret;
}


static int
testQEMUSchemaValidateObjectMergeVariantMember(size_t pos G_GNUC_UNUSED,
                                               virJSONValuePtr item,
                                               void *opaque)
{
    virJSONValuePtr array = opaque;
    virJSONValuePtr copy;

    if (!(copy = virJSONValueCopy(item)))
        return -1;

    if (virJSONValueArrayAppend(array, copy) < 0)
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
testQEMUSchemaValidateObjectMergeVariant(virJSONValuePtr root,
                                         const char *variantfield,
                                         const char *variantname,
                                         virHashTablePtr schema,
                                         virBufferPtr debug)
{
    size_t i;
    virJSONValuePtr variants = NULL;
    virJSONValuePtr variant;
    virJSONValuePtr variantschema;
    virJSONValuePtr variantschemamembers;
    virJSONValuePtr rootmembers;
    const char *varianttype = NULL;
    int ret = -1;

    if (!(variants = virJSONValueObjectStealArray(root, "variants"))) {
        virBufferAddLit(debug, "ERROR: missing 'variants' in schema\n");
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
        virBufferAsprintf(debug, "ERROR: variant '%s' for discriminator '%s' not found\n",
                          variantname, variantfield);
        goto cleanup;

    }

    if (!(variantschema = virHashLookup(schema, varianttype)) ||
        !(variantschemamembers = virJSONValueObjectGetArray(variantschema, "members"))) {
        virBufferAsprintf(debug,
                          "ERROR: missing schema or schema members for variant '%s'(%s)\n",
                          variantname, varianttype);
        ret = -2;
        goto cleanup;
    }

    rootmembers = virJSONValueObjectGetArray(root, "members");

    if (virJSONValueArrayForeachSteal(variantschemamembers,
                                      testQEMUSchemaValidateObjectMergeVariantMember,
                                      rootmembers) < 0) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(variants);
    return ret;
}


static int
testQEMUSchemaValidateObjectMandatoryMember(size_t pos G_GNUC_UNUSED,
                                            virJSONValuePtr item,
                                            void *opaque G_GNUC_UNUSED)
{
    struct testQEMUSchemaValidateObjectMemberData *data = opaque;

    if (virJSONValueObjectHasKey(item, "default") != 1) {
        virBufferAsprintf(data->debug, "ERROR: missing mandatory attribute '%s'\n",
                          NULLSTR(virJSONValueObjectGetString(item, "name")));
        data->missingMandatory = true;
    }

    return 1;
}


static int
testQEMUSchemaValidateObject(virJSONValuePtr obj,
                             virJSONValuePtr root,
                             virHashTablePtr schema,
                             virBufferPtr debug)
{
    struct testQEMUSchemaValidateObjectMemberData data = { NULL, schema,
                                                           debug, false };
    virJSONValuePtr localroot = NULL;
    const char *variantfield;
    const char *variantname;
    int ret = -1;

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virBufferAddLit(debug, "ERROR: not an object");
        return -1;
    }

    virBufferAddLit(debug, "{\n");
    virBufferAdjustIndent(debug, 3);

    /* copy schema */
    if (!(localroot = virJSONValueCopy(root))) {
        ret = -2;
        goto cleanup;
    }

    /* remove variant */
    if ((variantfield = virJSONValueObjectGetString(localroot, "tag"))) {
        if (!(variantname = virJSONValueObjectGetString(obj, variantfield))) {
            virBufferAsprintf(debug, "ERROR: missing variant discriminator attribute '%s'\n",
                              variantfield);
            goto cleanup;
        }

        if (testQEMUSchemaValidateObjectMergeVariant(localroot, variantfield,
                                                     variantname,
                                                     schema, debug) < 0)
            goto cleanup;
    }


    /* validate members */
    data.rootmembers = virJSONValueObjectGetArray(localroot, "members");
    if (virJSONValueObjectForeachKeyValue(obj,
                                          testQEMUSchemaValidateObjectMember,
                                          &data) < 0)
        goto cleanup;

    /* check missing mandatory values */
    if (virJSONValueArrayForeachSteal(data.rootmembers,
                                      testQEMUSchemaValidateObjectMandatoryMember,
                                      &data) < 0) {
        ret = -2;
        goto cleanup;
    }

    if (data.missingMandatory)
        goto cleanup;

    virBufferAdjustIndent(debug, -3);
    virBufferAddLit(debug, "} OK");
    ret = 0;

 cleanup:
    virJSONValueFree(localroot);
    return ret;
}


static int
testQEMUSchemaValidateEnum(virJSONValuePtr obj,
                           virJSONValuePtr root,
                           virBufferPtr debug)
{
    const char *objstr;
    virJSONValuePtr values = NULL;
    virJSONValuePtr value;
    size_t i;

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_STRING) {
        virBufferAddLit(debug, "ERROR: not a string");
        return -1;
    }

    objstr = virJSONValueGetString(obj);

    if (!(values = virJSONValueObjectGetArray(root, "values"))) {
        virBufferAsprintf(debug, "ERROR: missing enum values in schema '%s'",
                          NULLSTR(virJSONValueObjectGetString(root, "name")));
        return -2;
    }

    for (i = 0; i < virJSONValueArraySize(values); i++) {
        value = virJSONValueArrayGet(values, i);

        if (STREQ_NULLABLE(objstr, virJSONValueGetString(value))) {
            virBufferAsprintf(debug, "'%s' OK", NULLSTR(objstr));
            return 0;
        }
    }

    virBufferAsprintf(debug, "ERROR: enum value '%s' is not in schema",
                      NULLSTR(objstr));
    return -1;
}


static int
testQEMUSchemaValidateArray(virJSONValuePtr objs,
                            virJSONValuePtr root,
                            virHashTablePtr schema,
                            virBufferPtr debug)
{
    const char *elemtypename = virJSONValueObjectGetString(root, "element-type");
    virJSONValuePtr elementschema;
    virJSONValuePtr obj;
    size_t i;

    if (virJSONValueGetType(objs) != VIR_JSON_TYPE_ARRAY) {
        virBufferAddLit(debug, "ERROR: not an array\n");
        return -1;
    }

    if (!elemtypename ||
        !(elementschema = virHashLookup(schema, elemtypename))) {
        virBufferAsprintf(debug, "ERROR: missing schema for array element type '%s'",
                         NULLSTR(elemtypename));
        return -2;
    }

    virBufferAddLit(debug, "[\n");
    virBufferAdjustIndent(debug, 3);

    for (i = 0; i < virJSONValueArraySize(objs); i++) {
        obj = virJSONValueArrayGet(objs, i);

        if (testQEMUSchemaValidateRecurse(obj, elementschema, schema, debug) < 0)
            return -1;
        virBufferAddLit(debug, ",\n");
    }
    virBufferAddLit(debug, "] OK");
    virBufferAdjustIndent(debug, -3);

    return 0;
}

static int
testQEMUSchemaValidateAlternate(virJSONValuePtr obj,
                                virJSONValuePtr root,
                                virHashTablePtr schema,
                                virBufferPtr debug)
{
    virJSONValuePtr members;
    virJSONValuePtr member;
    size_t i;
    size_t n;
    const char *membertype;
    virJSONValuePtr memberschema;
    int indent;
    int rc;

    if (!(members = virJSONValueObjectGetArray(root, "members"))) {
        virBufferAddLit(debug, "ERROR: missing 'members' for alternate schema");
        return -2;
    }

    virBufferAddLit(debug, "(\n");
    virBufferAdjustIndent(debug, 3);
    indent = virBufferGetIndent(debug, false);

    n = virJSONValueArraySize(members);
    for (i = 0; i < n; i++) {
        membertype = NULL;

        /* P != NP */
        virBufferAsprintf(debug, "(alternate %zu/%zu)\n", i + 1, n);
        virBufferAdjustIndent(debug, 3);

        if (!(member = virJSONValueArrayGet(members, i)) ||
            !(membertype = virJSONValueObjectGetString(member, "type")) ||
            !(memberschema = virHashLookup(schema, membertype))) {
            virBufferAsprintf(debug, "ERROR: missing schema for alternate type '%s'",
                              NULLSTR(membertype));
            return -2;
        }

        rc = testQEMUSchemaValidateRecurse(obj, memberschema, schema, debug);

        virBufferAddLit(debug, "\n");
        virBufferSetIndent(debug, indent);
        virBufferAsprintf(debug, "(/alternate %zu/%zu)\n", i + 1, n);

        if (rc == 0) {
            virBufferAdjustIndent(debug, -3);
            virBufferAddLit(debug, ") OK");
            return 0;
        }
    }

    virBufferAddLit(debug, "ERROR: no alternate type was matched");
    return -1;
}


static int
testQEMUSchemaValidateRecurse(virJSONValuePtr obj,
                              virJSONValuePtr root,
                              virHashTablePtr schema,
                              virBufferPtr debug)
{
    const char *n = virJSONValueObjectGetString(root, "name");
    const char *t = virJSONValueObjectGetString(root, "meta-type");

    if (STREQ_NULLABLE(t, "builtin")) {
        return testQEMUSchemaValidateBuiltin(obj, root, debug);
    } else if (STREQ_NULLABLE(t, "object")) {
        return testQEMUSchemaValidateObject(obj, root, schema, debug);
    } else if (STREQ_NULLABLE(t, "enum")) {
        return testQEMUSchemaValidateEnum(obj, root, debug);
    } else if (STREQ_NULLABLE(t, "array")) {
        return testQEMUSchemaValidateArray(obj, root, schema, debug);
    } else if (STREQ_NULLABLE(t, "alternate")) {
        return testQEMUSchemaValidateAlternate(obj, root, schema, debug);
    }

    virBufferAsprintf(debug,
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
testQEMUSchemaValidate(virJSONValuePtr obj,
                       virJSONValuePtr root,
                       virHashTablePtr schema,
                       virBufferPtr debug)
{
    return testQEMUSchemaValidateRecurse(obj, root, schema, debug);
}


/**
 * testQEMUSchemaGetLatest:
 *
 * Returns the schema data as the qemu monitor would reply from the latest
 * replies file used for qemucapabilitiestest for the x86_64 architecture.
 */
virJSONValuePtr
testQEMUSchemaGetLatest(void)
{
    char *capsLatestFile = NULL;
    char *capsLatest = NULL;
    char *schemaReply;
    char *end;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr schema = NULL;

    if (!(capsLatestFile = testQemuGetLatestCapsForArch("x86_64", "replies"))) {
        VIR_TEST_VERBOSE("failed to find latest caps replies");
        return NULL;
    }

    VIR_TEST_DEBUG("replies file: '%s'", capsLatestFile);

    if (virTestLoadFile(capsLatestFile, &capsLatest) < 0)
        goto cleanup;

    if (!(schemaReply = strstr(capsLatest, "\"execute\": \"query-qmp-schema\"")) ||
        !(schemaReply = strstr(schemaReply, "\n\n")) ||
        !(end = strstr(schemaReply + 2, "\n\n"))) {
        VIR_TEST_VERBOSE("failed to find reply to 'query-qmp-schema' in '%s'",
                         capsLatestFile);
        goto cleanup;
    }

    schemaReply += 2;
    *end = '\0';

    if (!(reply = virJSONValueFromString(schemaReply))) {
        VIR_TEST_VERBOSE("failed to parse 'query-qmp-schema' reply from '%s'",
                         capsLatestFile);
        goto cleanup;
    }

    if (!(schema = virJSONValueObjectStealArray(reply, "return"))) {
        VIR_TEST_VERBOSE("missing qapi schema data in reply in '%s'",
                         capsLatestFile);
        goto cleanup;
    }

 cleanup:
    VIR_FREE(capsLatestFile);
    VIR_FREE(capsLatest);
    virJSONValueFree(reply);
    return schema;
}


virHashTablePtr
testQEMUSchemaLoad(void)
{
    virJSONValuePtr schema;

    if (!(schema = testQEMUSchemaGetLatest()))
        return NULL;

    return virQEMUQAPISchemaConvert(schema);
}
