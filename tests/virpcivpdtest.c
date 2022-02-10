/*
 * Copyright (C) 2021 Canonical Ltd.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "virpcivpd.h"

#define LIBVIRT_VIRPCIVPDPRIV_H_ALLOW

#include "virpcivpdpriv.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef __linux__

VIR_LOG_INIT("tests.vpdtest");


typedef struct _TestPCIVPDKeywordValue {
    const char *keyword;
    const char *value;
    char **actual;
} TestPCIVPDKeywordValue;

static int
testPCIVPDResourceBasic(const void *data G_GNUC_UNUSED)
{
    size_t i = 0;
    g_autoptr(virPCIVPDResourceRO) ro = virPCIVPDResourceRONew();
    g_autoptr(virPCIVPDResourceRW) rw = virPCIVPDResourceRWNew();
    /* Note: when the same keyword is updated multiple times the
     * virPCIVPDResourceUpdateKeyword function is expected to free the
     * previous value whether it is a fixed keyword or a custom one.
     * */
    const TestPCIVPDKeywordValue readOnlyCases[] = {
        {.keyword = "EC", .value = "level1", .actual = &ro->change_level},
        {.keyword = "EC", .value = "level2", .actual = &ro->change_level},
        {.keyword = "change_level", .value = "level3", .actual = &ro->change_level},
        {.keyword = "PN", .value = "number1", .actual = &ro->part_number},
        {.keyword = "PN", .value = "number2", .actual = &ro->part_number},
        {.keyword = "part_number", .value = "number3", .actual = &ro->part_number},
        {.keyword = "MN", .value = "id1", .actual = &ro->manufacture_id},
        {.keyword = "MN", .value = "id2", .actual = &ro->manufacture_id},
        {.keyword = "manufacture_id", .value = "id3", &ro->manufacture_id},
        {.keyword = "SN", .value = "serial1", .actual = &ro->serial_number},
        {.keyword = "SN", .value = "serial2", .actual = &ro->serial_number},
        {.keyword = "serial_number", .value = "serial3", .actual = &ro->serial_number},
    };
    const TestPCIVPDKeywordValue readWriteCases[] = {
        {.keyword = "YA", .value = "tag1", .actual = &ro->change_level},
        {.keyword = "YA", .value = "tag2", .actual = &ro->change_level},
        {.keyword = "asset_tag", .value = "tag3", .actual = &ro->change_level},
    };
    const TestPCIVPDKeywordValue unsupportedFieldCases[] = {
        {.keyword = "FG", .value = "42", .actual = NULL},
        {.keyword = "LC", .value = "42", .actual = NULL},
        {.keyword = "PG", .value = "42", .actual = NULL},
        {.keyword = "CP", .value = "42", .actual = NULL},
        {.keyword = "EX", .value = "42", .actual = NULL},
    };
    size_t numROCases = G_N_ELEMENTS(readOnlyCases);
    size_t numRWCases = G_N_ELEMENTS(readWriteCases);
    size_t numUnsupportedCases = G_N_ELEMENTS(unsupportedFieldCases);
    g_autoptr(virPCIVPDResource) res = g_new0(virPCIVPDResource, 1);
    virPCIVPDResourceCustom *custom = NULL;

    g_autofree char *val = g_strdup("testval");
    res->name = g_steal_pointer(&val);

    /* RO has not been initialized - make sure updates fail. */
    for (i = 0; i < numROCases; ++i) {
        if (virPCIVPDResourceUpdateKeyword(res, true,
                                           readOnlyCases[i].keyword,
                                           readOnlyCases[i].value))
            return -1;
    }
    /* RW has not been initialized - make sure updates fail. */
    for (i = 0; i < numRWCases; ++i) {
        if (virPCIVPDResourceUpdateKeyword(res, false,
                                           readWriteCases[i].keyword,
                                           readWriteCases[i].value))
            return -1;
    }
    /* Initialize RO */
    res->ro = g_steal_pointer(&ro);

    /* Update keywords one by one and compare actual values with the expected ones. */
    for (i = 0; i < numROCases; ++i) {
        if (!virPCIVPDResourceUpdateKeyword(res, true,
                                            readOnlyCases[i].keyword,
                                            readOnlyCases[i].value))
            return -1;
        if (STRNEQ(readOnlyCases[i].value, *readOnlyCases[i].actual))
            return -1;
    }

    /* Do a basic vendor field check. */
    if (!virPCIVPDResourceUpdateKeyword(res, true, "V0", "vendor0"))
        return -1;

    if (res->ro->vendor_specific->len != 1)
        return -1;

    custom = g_ptr_array_index(res->ro->vendor_specific, 0);
    if (custom->idx != '0' || STRNEQ(custom->value, "vendor0"))
        return -1;

    /* Make sure unsupported RO keyword updates are not fatal. */
    for (i = 0; i < numUnsupportedCases; ++i) {
        if (!virPCIVPDResourceUpdateKeyword(res, true,
                                            unsupportedFieldCases[i].keyword,
                                            unsupportedFieldCases[i].value))
            return -1;
    }

    /* Check that RW updates fail if RW has not been initialized. */
    if (virPCIVPDResourceUpdateKeyword(res, false, "YA", "tag1"))
        return -1;

    if (virPCIVPDResourceUpdateKeyword(res, false, "asset_tag", "tag1"))
        return -1;

    /* Initialize RW */
    res->rw = g_steal_pointer(&rw);
    if (!virPCIVPDResourceUpdateKeyword(res, false, "YA", "tag1")
        || STRNEQ(res->rw->asset_tag, "tag1"))
        return -1;

    if (!virPCIVPDResourceUpdateKeyword(res, false, "asset_tag", "tag2")
        || STRNEQ(res->rw->asset_tag, "tag2"))
        return -1;

    /* Do a basic system field check. */
    if (!virPCIVPDResourceUpdateKeyword(res, false, "Y0", "system0"))
        return -1;

    if (res->rw->system_specific->len != 1)
        return -1;

    custom = g_ptr_array_index(res->rw->system_specific, 0);
    if (custom->idx != '0' || STRNEQ(custom->value, "system0"))
        return -1;

    /* Make sure unsupported RW keyword updates are not fatal. */
    for (i = 0; i < numUnsupportedCases; ++i) {
        if (!virPCIVPDResourceUpdateKeyword(res, false,
                                            unsupportedFieldCases[i].keyword,
                                            unsupportedFieldCases[i].value))
            return -1;
    }


    /* Just make sure the name has not been changed during keyword updates. */
    if (!STREQ_NULLABLE(res->name, "testval"))
        return -1;

    return 0;
}

static int
testPCIVPDResourceCustomCompareIndex(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virPCIVPDResourceCustom) a = NULL;
    g_autoptr(virPCIVPDResourceCustom) b = NULL;

    /* Both are NULL */
    if (!virPCIVPDResourceCustomCompareIndex(a, b))
        return -1;

    /* a is not NULL */
    a = g_new0(virPCIVPDResourceCustom, 1);
    if (virPCIVPDResourceCustomCompareIndex(a, b))
        return -1;

    /* Reverse */
    if (virPCIVPDResourceCustomCompareIndex(b, a))
        return -1;

    /* Same index, different strings */
    b = g_new0(virPCIVPDResourceCustom, 1);
    a->idx = 'z';
    a->value = g_strdup("42");
    b->idx = 'z';
    b->value = g_strdup("24");
    if (!virPCIVPDResourceCustomCompareIndex(b, a))
        return -1;

    /* Different index, different strings */
    a->idx = 'a';
    if (virPCIVPDResourceCustomCompareIndex(b, a))
        return -1;

    virPCIVPDResourceCustomFree(a);
    virPCIVPDResourceCustomFree(b);
    a = g_new0(virPCIVPDResourceCustom, 1);
    b = g_new0(virPCIVPDResourceCustom, 1);

    /* Same index, same strings */
    a->idx = 'z';
    a->value = g_strdup("42");
    b->idx = 'z';
    b->value = g_strdup("42");
    if (!virPCIVPDResourceCustomCompareIndex(b, a))
        return -1;

    /* Different index, same strings */
    a->idx = 'a';
    if (virPCIVPDResourceCustomCompareIndex(b, a))
        return -1;

    /* Different index, same value pointers */
    g_clear_pointer(&b->value, g_free);
    b->value = a->value;
    if (virPCIVPDResourceCustomCompareIndex(b, a)) {
        b->value = NULL;
        return -1;
    }

    b->value = NULL;

    return 0;
}

static int
testPCIVPDResourceCustomUpsertValue(const void *data G_GNUC_UNUSED)
{
    g_autoptr(GPtrArray) arr = g_ptr_array_new_full(0, (GDestroyNotify)virPCIVPDResourceCustomFree);
    virPCIVPDResourceCustom *custom = NULL;
    if (!virPCIVPDResourceCustomUpsertValue(arr, 'A', "testval"))
        return -1;

    if (arr->len != 1)
        return -1;

    custom = g_ptr_array_index(arr, 0);
    if (custom == NULL || custom->idx != 'A' || STRNEQ_NULLABLE(custom->value, "testval"))
        return -1;

    /* Idempotency */
    if (!virPCIVPDResourceCustomUpsertValue(arr, 'A', "testval"))
        return -1;

    if (arr->len != 1)
        return -1;

    custom = g_ptr_array_index(arr, 0);
    if (custom == NULL || custom->idx != 'A' || STRNEQ_NULLABLE(custom->value, "testval"))
        return -1;

    /* Existing value updates. */
    if (!virPCIVPDResourceCustomUpsertValue(arr, 'A', "testvalnew"))
        return -1;

    if (arr->len != 1)
        return -1;

    custom = g_ptr_array_index(arr, 0);
    if (custom == NULL || custom->idx != 'A' || STRNEQ_NULLABLE(custom->value, "testvalnew"))
        return -1;

    /* Inserting multiple values */
    if (!virPCIVPDResourceCustomUpsertValue(arr, '1', "42"))
        return -1;

    if (arr->len != 2)
        return -1;

    custom = g_ptr_array_index(arr, 1);
    if (custom == NULL || custom->idx != '1' || STRNEQ_NULLABLE(custom->value, "42"))
        return -1;

    return 0;
}


typedef struct _TestPCIVPDExpectedString {
    const char *keyword;
    bool expected;
} TestPCIVPDExpectedString;

/*
 * testPCIVPDIsValidTextValue:
 *
 * Test expected text value validation. Static metadata about possible values is taken
 * from the PCI(e) standards and based on some real-world hardware examples.
 * */
static int
testPCIVPDIsValidTextValue(const void *data G_GNUC_UNUSED)
{
    size_t i = 0;

    const TestPCIVPDExpectedString textValueCases[] = {
        /* Numbers */
        {"42", true},
        /* Alphanumeric */
        {"DCM1001008FC52101008FC53201008FC54301008FC5", true},
        /* Dots */
        {"DSV1028VPDR.VER1.0", true},
        /* Whitespace presence */
        {"NMVIntel Corp", true},
        /* Comma and spaces */
        {"BlueField-2 DPU 25GbE Dual-Port SFP56, Tall Bracket", true},
        /* Equal signs and colons. */
        {"MLX:MN=MLNX:CSKU=V2:UUID=V3:PCI=V0:MODL=BF2H332A", true},
        /* Dashes */
        {"MBF2H332A-AEEOT", true},
        {"under_score_example", true},
        {"", true},
        {";", true},
        {"\\42", true},
        {"N/A", true},
        /* The first and last code points are outside ASCII (multi-byte in UTF-8). */
        {"гbl🐧", false},
    };
    for (i = 0; i < G_N_ELEMENTS(textValueCases); ++i) {
        if (virPCIVPDResourceIsValidTextValue(textValueCases[i].keyword) !=
            textValueCases[i].expected)
            return -1;
    }
    return 0;
}

/*
 * testPCIVPDGetFieldValueFormat:
 *
 * A simple test to assess the functionality of the
 * virPCIVPDResourceGetFieldValueFormat function.
 * */
static int
testPCIVPDGetFieldValueFormat(const void *data G_GNUC_UNUSED)
{
    typedef struct _TestPCIVPDExpectedFieldValueFormat {
        const char *keyword;
        virPCIVPDResourceFieldValueFormat expected;
    } TestPCIVPDExpectedFieldValueFormat;

    size_t i = 0;

    const TestPCIVPDExpectedFieldValueFormat valueFormatCases[] = {
        {"SN", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"EC", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"MN", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"PN", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"RV", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RESVD},
        {"RW", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RDWR},
        {"VA", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"YA", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"YZ", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT},
        {"CP", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_BINARY},
        /* Invalid keywords. */
        {"", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"sn", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"ec", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"mn", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"pn", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"4", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"42", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"Y", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"V", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"v", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"vA", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"va", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"ya", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        {"Ya", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        /* 2 bytes but not present in the spec. */
        {"EX", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        /* Many numeric bytes. */
        {"4242", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
        /* Many letters. */
        {"EXAMPLE", VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST},
    };
    for (i = 0; i < G_N_ELEMENTS(valueFormatCases); ++i) {
        if (virPCIVPDResourceGetFieldValueFormat(valueFormatCases[i].keyword) !=
            valueFormatCases[i].expected)
            return -1;
    }
    return 0;
}

# define VPD_STRING_RESOURCE_EXAMPLE_HEADER \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_STRING_RESOURCE_FLAG, 0x08, 0x00

# define VPD_STRING_RESOURCE_EXAMPLE_DATA \
    't', 'e', 's', 't', 'n', 'a', 'm', 'e'

# define VPD_R_FIELDS_EXAMPLE_HEADER \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x16, 0x00

# define VPD_R_EXAMPLE_VALID_RV_FIELD \
    'R', 'V', 0x02, 0x31, 0x00

# define VPD_R_EXAMPLE_INVALID_RV_FIELD \
    'R', 'V', 0x02, 0xFF, 0x00

# define VPD_R_EXAMPLE_FIELDS \
    'P', 'N', 0x02, '4', '2', \
    'E', 'C', 0x04, '4', '2', '4', '2', \
    'V', 'A', 0x02, 'E', 'X'

# define VPD_R_FIELDS_EXAMPLE_DATA \
    VPD_R_EXAMPLE_FIELDS, \
    VPD_R_EXAMPLE_VALID_RV_FIELD

# define VPD_W_FIELDS_EXAMPLE_HEADER \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_WRITE_LARGE_RESOURCE_FLAG, 0x19, 0x00

# define VPD_W_EXAMPLE_FIELDS \
    'V', 'Z', 0x02, '4', '2', \
    'Y', 'A', 0x04, 'I', 'D', '4', '2', \
    'Y', 'F', 0x02, 'E', 'X', \
    'Y', 'E', 0x00, \
    'R', 'W', 0x02, 0x00, 0x00

static int
testVirPCIVPDReadVPDBytes(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    g_autofree uint8_t *buf = NULL;
    uint8_t csum = 0;
    size_t readBytes = 0;
    size_t dataLen = 0;

    /* An example of a valid VPD record with one VPD-R resource and 2 fields. */
    uint8_t fullVPDExample[] = {
        VPD_STRING_RESOURCE_EXAMPLE_HEADER, VPD_STRING_RESOURCE_EXAMPLE_DATA,
        VPD_R_FIELDS_EXAMPLE_HEADER, VPD_R_FIELDS_EXAMPLE_DATA,
        PCI_VPD_RESOURCE_END_VAL
    };
    dataLen = G_N_ELEMENTS(fullVPDExample) - 2;
    buf = g_malloc0(dataLen);

    if ((fd = virCreateAnonymousFile(fullVPDExample, dataLen)) < 0)
        return -1;

    readBytes = virPCIVPDReadVPDBytes(fd, buf, dataLen, 0, &csum);

    if (readBytes != dataLen) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "The number of bytes read %zu is lower than expected %zu ",
                       readBytes, dataLen);
        return -1;
    }

    if (csum) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "The sum of all VPD bytes up to and including the checksum byte"
                       "is equal to zero: 0x%02x", csum);
        return -1;
    }
    return 0;
}

static int
testVirPCIVPDParseVPDStringResource(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    uint8_t csum = 0;
    size_t dataLen = 0;
    bool result = false;

    g_autoptr(virPCIVPDResource) res = g_new0(virPCIVPDResource, 1);
    const char *expectedValue = "testname";

    const uint8_t stringResExample[] = {
        VPD_STRING_RESOURCE_EXAMPLE_DATA
    };

    dataLen = G_N_ELEMENTS(stringResExample);
    if ((fd = virCreateAnonymousFile(stringResExample, dataLen)) < 0)
        return -1;

    result = virPCIVPDParseVPDLargeResourceString(fd, 0, dataLen, &csum, res);

    if (!result) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Could not parse the example resource.");
        return -1;
    }

    if (STRNEQ(expectedValue, res->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected string resource value: %s, expected: %s",
                       res->name, expectedValue);
        return -1;
    }
    return 0;
}

static int
testVirPCIVPDValidateExampleReadOnlyFields(virPCIVPDResource *res)
{
    const char *expectedName = "testname";
    virPCIVPDResourceCustom *custom = NULL;
    if (STRNEQ(res->name, expectedName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                "Unexpected string resource value: %s, expected: %s",
                res->name, expectedName);
        return -1;
    }

    if (!res->ro) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-only keywords are missing from the VPD resource.");
        return -1;
    }

    if (STRNEQ_NULLABLE(res->ro->part_number, "42")) {
        return -1;
    } else if (STRNEQ_NULLABLE(res->ro->change_level, "4242")) {
        return -1;
    }
    if (!res->ro->vendor_specific)
        return -1;

    custom = g_ptr_array_index(res->ro->vendor_specific, 0);
    if (custom->idx != 'A' || STRNEQ_NULLABLE(custom->value, "EX"))
        return -1;

    return 0;
}

static int
testVirPCIVPDParseFullVPD(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    size_t dataLen = 0;

    g_autoptr(virPCIVPDResource) res = NULL;
    /* Note: Custom fields are supposed to be freed by the resource cleanup code. */
    virPCIVPDResourceCustom *custom = NULL;

    const uint8_t fullVPDExample[] = {
        VPD_STRING_RESOURCE_EXAMPLE_HEADER, VPD_STRING_RESOURCE_EXAMPLE_DATA,
        VPD_R_FIELDS_EXAMPLE_HEADER, VPD_R_FIELDS_EXAMPLE_DATA,
        VPD_W_FIELDS_EXAMPLE_HEADER, VPD_W_EXAMPLE_FIELDS,
        PCI_VPD_RESOURCE_END_VAL
    };

    dataLen = G_N_ELEMENTS(fullVPDExample);
    if ((fd = virCreateAnonymousFile(fullVPDExample, dataLen)) < 0)
        return -1;

    res = virPCIVPDParse(fd);

    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The resource pointer is NULL after parsing which is unexpected");
        return -1;
    }

    if (!res->ro) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-only keywords are missing from the VPD resource.");
        return -1;
    } else if (!res->rw) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-write keywords are missing from the VPD resource.");
        return -1;
    }

    if (testVirPCIVPDValidateExampleReadOnlyFields(res))
        return -1;

    if (STRNEQ_NULLABLE(res->rw->asset_tag, "ID42"))
        return -1;

    if (!res->rw->vendor_specific)
        return -1;

    custom = g_ptr_array_index(res->rw->vendor_specific, 0);
    if (custom->idx != 'Z' || STRNEQ_NULLABLE(custom->value, "42"))
        return -1;

    if (!res->rw->system_specific)
        return -1;

    custom = g_ptr_array_index(res->rw->system_specific, 0);
    if (custom->idx != 'F' || STRNEQ_NULLABLE(custom->value, "EX"))
        return -1;

    custom = g_ptr_array_index(res->rw->system_specific, 1);
    if (custom->idx != 'E' || STRNEQ_NULLABLE(custom->value, ""))
        return -1;

    custom = NULL;
    return 0;
}

static int
testVirPCIVPDParseZeroLengthRW(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    size_t dataLen = 0;

    g_autoptr(virPCIVPDResource) res = NULL;
    virPCIVPDResourceCustom *custom = NULL;

    /* The RW field has a zero length  which means there is no more RW space left. */
    const uint8_t fullVPDExample[] = {
        VPD_STRING_RESOURCE_EXAMPLE_HEADER, VPD_STRING_RESOURCE_EXAMPLE_DATA,
        VPD_R_FIELDS_EXAMPLE_HEADER, VPD_R_FIELDS_EXAMPLE_DATA,
        PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_WRITE_LARGE_RESOURCE_FLAG, 0x08, 0x00,
        'V', 'Z', 0x02, '4', '2',
        'R', 'W', 0x00,
        PCI_VPD_RESOURCE_END_VAL
    };

    dataLen = G_N_ELEMENTS(fullVPDExample);
    if ((fd = virCreateAnonymousFile(fullVPDExample, dataLen)) < 0)
        return -1;

    res = virPCIVPDParse(fd);

    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The resource pointer is NULL after parsing which is unexpected");
        return -1;
    }

    if (!res->ro) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-only keywords are missing from the VPD resource.");
        return -1;
    } else if (!res->rw) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-write keywords are missing from the VPD resource.");
        return -1;
    }

    if (testVirPCIVPDValidateExampleReadOnlyFields(res))
        return -1;

    custom = g_ptr_array_index(res->rw->vendor_specific, 0);
    if (custom->idx != 'Z' || STRNEQ_NULLABLE(custom->value, "42"))
        return -1;

    custom = NULL;
    return 0;
}

static int
testVirPCIVPDParseNoRW(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    size_t dataLen = 0;

    g_autoptr(virPCIVPDResource) res = NULL;
    virPCIVPDResourceCustom *custom = NULL;

    /* The RW field has a zero length  which means there is no more RW space left. */
    const uint8_t fullVPDExample[] = {
        VPD_STRING_RESOURCE_EXAMPLE_HEADER, VPD_STRING_RESOURCE_EXAMPLE_DATA,
        VPD_R_FIELDS_EXAMPLE_HEADER, VPD_R_FIELDS_EXAMPLE_DATA,
        PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_WRITE_LARGE_RESOURCE_FLAG, 0x05, 0x00,
        'V', 'Z', 0x02, '4', '2',
        PCI_VPD_RESOURCE_END_VAL
    };

    dataLen = G_N_ELEMENTS(fullVPDExample);
    if ((fd = virCreateAnonymousFile(fullVPDExample, dataLen)) < 0)
        return -1;

    res = virPCIVPDParse(fd);

    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The resource pointer is NULL after parsing which is unexpected");
        return -1;
    }

    if (!res->ro) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-only keywords are missing from the VPD resource.");
        return -1;
    } else if (!res->rw) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                "Read-write keywords are missing from the VPD resource.");
        return -1;
    }

    if (testVirPCIVPDValidateExampleReadOnlyFields(res))
        return -1;

    custom = g_ptr_array_index(res->rw->vendor_specific, 0);
    if (custom->idx != 'Z' || STRNEQ_NULLABLE(custom->value, "42"))
        return -1;

    custom = NULL;
    return 0;
}

static int
testVirPCIVPDParseFullVPDSkipInvalidKeywords(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    size_t dataLen = 0;

    g_autoptr(virPCIVPDResource) res = NULL;

    const uint8_t fullVPDExample[] = {
        VPD_STRING_RESOURCE_EXAMPLE_HEADER,
        VPD_STRING_RESOURCE_EXAMPLE_DATA,
        PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x25, 0x00,
        VPD_R_EXAMPLE_FIELDS,
        /* The keywords below (except for "RV") are invalid but will be skipped by the parser */
        0x07, 'A', 0x02, 0x00, 0x00,
        'V', 0x07, 0x02, 0x00, 0x00,
        'e', 'x', 0x02, 0x00, 0x00,
        'R', 'V', 0x02, 0x9A, 0x00,
        PCI_VPD_RESOURCE_END_VAL
    };

    dataLen = G_N_ELEMENTS(fullVPDExample);
    if ((fd = virCreateAnonymousFile(fullVPDExample, dataLen)) < 0)
        return -1;

    res = virPCIVPDParse(fd);

    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The resource pointer is NULL after parsing which is unexpected.");
        return -1;
    }
    if (!res->ro) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The RO portion of the VPD resource is NULL.");
        return -1;
    }

    if (testVirPCIVPDValidateExampleReadOnlyFields(res))
        return -1;

    return 0;
}

static int
testVirPCIVPDParseFullVPDSkipInvalidValues(const void *opaque G_GNUC_UNUSED)
{
    VIR_AUTOCLOSE fd = -1;
    size_t dataLen = 0;
    size_t i = 0;
    virPCIVPDResourceCustom *custom = NULL;

    g_autoptr(virPCIVPDResource) res = NULL;

    /* This example is based on real-world hardware which was programmed by the vendor with
     * invalid field values in both the RO section and RW section. The RO section contains
     * fields that are not valid per the spec but accepted by Libvirt as printable ASCII
     * characters. The RW field has a 0 length which means there is no more space in the
     * RW section. */
    const uint8_t fullVPDExample[] = {
        0x82, 0x23, 0x00, 0x48, 0x50, 0x20, 0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74,
        0x20, 0x31, 0x47, 0x62, 0x20, 0x32, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x33, 0x36,
        0x31, 0x69, 0x20, 0x41, 0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x90, 0x42, 0x00, 0x50,
        0x4e, 0x03, 0x4e, 0x2f, 0x41, 0x45, 0x43, 0x03, 0x4e, 0x2f, 0x41, 0x53, 0x4e, 0x03,
        0x4e, 0x2f, 0x41, 0x56, 0x30, 0x29, 0x34, 0x57, 0x2f, 0x31, 0x57, 0x20, 0x50, 0x43,
        0x49, 0x65, 0x47, 0x32, 0x78, 0x34, 0x20, 0x32, 0x70, 0x20, 0x31, 0x47, 0x62, 0x45,
        0x20, 0x52, 0x4a, 0x34, 0x35, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x69, 0x33,
        0x35, 0x30, 0x20, 0x20, 0x20, 0x52, 0x56, 0x01, 0x63, 0x91, 0x47, 0x00, 0x56, 0x31,
        0x06, 0x35, 0x2e, 0x37, 0x2e, 0x30, 0x36, 0x56, 0x33, 0x06, 0x32, 0x2e, 0x38, 0x2e,
        0x32, 0x30, 0x56, 0x36, 0x06, 0x31, 0x2e, 0x35, 0x2e, 0x33, 0x35, 0x59, 0x41, 0x03,
        0x4e, 0x2f, 0x41, 0x59, 0x42, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x59, 0x43, 0x0D, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 'R', 'W', 0x00, 0x78,
    };

    dataLen = G_N_ELEMENTS(fullVPDExample);
    if ((fd = virCreateAnonymousFile(fullVPDExample, dataLen)) < 0)
        return -1;

    res = virPCIVPDParse(fd);

    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The resource pointer is NULL after parsing which is unexpected.");
        return -1;
    }
    /* Some values in the read-write section are invalid but parsing should succeed
     * considering the parser is implemented to be graceful about invalid keywords and
     * values. */
    if (!res->ro) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The RO section consisting of only invalid fields got parsed successfully");
        return -1;
    }
    if (!res->rw) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Could not successfully parse an RW section with some invalid fields");
        return -1;
    }

    if (!STREQ_NULLABLE(res->ro->change_level, "N/A")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Could not parse a change level field with acceptable contents");
        return -1;
    }
    if (!STREQ_NULLABLE(res->ro->part_number, "N/A")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Could not parse a part number field with acceptable contents");
        return -1;
    }
    if (!STREQ_NULLABLE(res->ro->serial_number, "N/A")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Could not parse a serial number with acceptable contents");
        return -1;
    }
    if (!STREQ_NULLABLE(res->rw->asset_tag, "N/A")) {
        /* The asset tag has an invalid value in this case so it should be NULL. */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Could not parse an asset tag with acceptable contents");
        return -1;
    }
    if (res->rw->vendor_specific->len != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "The number of parsed vendor fields is not equal to the expected number.");
        return -1;
    }
    if (res->rw->system_specific->len > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Successfully parsed some systems-specific fields while none are valid");
        return -1;
    }
    for (i = 0; i < res->rw->vendor_specific->len; ++i) {
        custom = ((virPCIVPDResourceCustom*)g_ptr_array_index(res->rw->vendor_specific, i));
        if (custom->idx == '1') {
            if (STRNEQ(custom->value, "5.7.06")) {
                return -1;
            }
        } else if (custom->idx == '3') {
            if (STRNEQ(custom->value, "2.8.20")) {
                return -1;
            }
        } else if (custom->idx == '6') {
            if (STRNEQ(custom->value, "1.5.35")) {
                return -1;
            }
        }
    }

    return 0;
}


static int
testVirPCIVPDParseFullVPDInvalid(const void *opaque G_GNUC_UNUSED)
{
    size_t dataLen = 0;

# define VPD_INVALID_ZERO_BYTE \
    0x00

# define VPD_INVALID_STRING_HEADER_DATA_LONG \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_STRING_RESOURCE_FLAG, 0x04, 0x00, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x05, 0x00, \
    'R', 'V', 0x02, 0xDA, 0x00, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_INVALID_STRING_HEADER_DATA_SHORT \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_STRING_RESOURCE_FLAG, 0x0A, 0x00, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x05, 0x00, \
    'R', 'V', 0x02, 0xD4, 0x00, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_NO_VPD_R \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_R_NO_RV \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    VPD_R_FIELDS_EXAMPLE_HEADER, \
    VPD_R_EXAMPLE_FIELDS, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_R_INVALID_RV \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    VPD_R_FIELDS_EXAMPLE_HEADER, \
    VPD_R_EXAMPLE_FIELDS, \
    VPD_R_EXAMPLE_INVALID_RV_FIELD, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_R_INVALID_RV_ZERO_LENGTH \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x14, 0x00, \
    VPD_R_EXAMPLE_FIELDS, \
    'R', 'V', 0x00, \
    PCI_VPD_RESOURCE_END_VAL

/* The RW key is not expected in a VPD-R record. */
# define VPD_R_UNEXPECTED_RW_IN_VPD_R_KEY \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x1B, 0x00, \
    VPD_R_EXAMPLE_FIELDS, \
    'R', 'W', 0x02, 0x00, 0x00, \
    'R', 'V', 0x02, 0x81, 0x00, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_INVALID_STRING_RESOURCE_VALUE \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    't', 0x03, 's', 't', 'n', 'a', 'm', 'e', \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x0A, 0x00, \
    'S', 'N', 0x02, 0x04, 0x02, \
    'R', 'V', 0x02, 0x8A, 0x00, \
    PCI_VPD_RESOURCE_END_VAL

/* The SN field has a length field that goes past the resource boundaries. */
# define VPD_INVALID_SN_FIELD_LENGTH \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    't', 'e', 's', 't', 'n', 'a', 'm', 'e', \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x0A, 0x00, \
    'S', 'N', 0x42, 0x04, 0x02, \
    'R', 'V', 0x02, 0xE8, 0x00, \
    PCI_VPD_RESOURCE_END_VAL

/* The RV field is not the last one in VPD-R while the checksum is valid. */
# define VPD_INVALID_RV_NOT_LAST \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, \
    't', 'e', 's', 't', 'n', 'a', 'm', 'e', \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x0A, 0x00, \
    'R', 'V', 0x02, 0xD1, 0x00, \
    'S', 'N', 0x02, 0x04, 0x02, \
    PCI_VPD_RESOURCE_END_VAL

# define VPD_INVALID_RW_NOT_LAST \
    VPD_STRING_RESOURCE_EXAMPLE_HEADER, VPD_STRING_RESOURCE_EXAMPLE_DATA, \
    VPD_R_FIELDS_EXAMPLE_HEADER, VPD_R_FIELDS_EXAMPLE_DATA, \
    PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_WRITE_LARGE_RESOURCE_FLAG, 0x08, 0x00, \
    'R', 'W', 0x00, \
    'V', 'Z', 0x02, '4', '2', \
    PCI_VPD_RESOURCE_END_VAL


# define TEST_INVALID_VPD(invalidVPD) \
    do { \
        VIR_AUTOCLOSE fd = -1; \
        g_autoptr(virPCIVPDResource) res = NULL; \
        const uint8_t testCase[] = { invalidVPD }; \
        dataLen = G_N_ELEMENTS(testCase); \
        if ((fd = virCreateAnonymousFile(testCase, dataLen)) < 0) \
            return -1; \
        if ((res = virPCIVPDParse(fd))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", \
                    "Successfully parsed an invalid VPD - this is not expected"); \
            return -1; \
        } \
    } while (0);

    TEST_INVALID_VPD(VPD_INVALID_ZERO_BYTE);
    TEST_INVALID_VPD(VPD_INVALID_STRING_HEADER_DATA_SHORT);
    TEST_INVALID_VPD(VPD_INVALID_STRING_HEADER_DATA_LONG);
    TEST_INVALID_VPD(VPD_NO_VPD_R);
    TEST_INVALID_VPD(VPD_R_NO_RV);
    TEST_INVALID_VPD(VPD_R_INVALID_RV);
    TEST_INVALID_VPD(VPD_R_INVALID_RV_ZERO_LENGTH);
    TEST_INVALID_VPD(VPD_R_UNEXPECTED_RW_IN_VPD_R_KEY);
    TEST_INVALID_VPD(VPD_INVALID_STRING_RESOURCE_VALUE);
    TEST_INVALID_VPD(VPD_INVALID_SN_FIELD_LENGTH);
    TEST_INVALID_VPD(VPD_INVALID_RV_NOT_LAST);
    TEST_INVALID_VPD(VPD_INVALID_RW_NOT_LAST);

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("Basic functionality of virPCIVPDResource ", testPCIVPDResourceBasic, NULL) < 0)
        ret = -1;
    if (virTestRun("Custom field index comparison",
                   testPCIVPDResourceCustomCompareIndex, NULL) < 0)
        ret = -1;
    if (virTestRun("Custom field value insertion and updates ",
                   testPCIVPDResourceCustomUpsertValue, NULL) < 0)
        ret = -1;
    if (virTestRun("Valid text values ", testPCIVPDIsValidTextValue, NULL) < 0)
        ret = -1;
    if (virTestRun("Determining a field value format by a key ",
                   testPCIVPDGetFieldValueFormat, NULL) < 0)
        ret = -1;
    if (virTestRun("Reading VPD bytes ", testVirPCIVPDReadVPDBytes, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing VPD string resources ", testVirPCIVPDParseVPDStringResource, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing a VPD resource with a zero-length RW ",
                   testVirPCIVPDParseZeroLengthRW, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing a VPD resource without an RW ",
                   testVirPCIVPDParseNoRW, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing a VPD resource with an invalid values ",
                   testVirPCIVPDParseFullVPDSkipInvalidValues, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing a VPD resource with an invalid keyword ",
                   testVirPCIVPDParseFullVPDSkipInvalidKeywords, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing VPD resources from a full VPD ", testVirPCIVPDParseFullVPD, NULL) < 0)
        ret = -1;
    if (virTestRun("Parsing invalid VPD records ", testVirPCIVPDParseFullVPDInvalid, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else /* ! __linux__ */
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif /* ! __linux__ */
