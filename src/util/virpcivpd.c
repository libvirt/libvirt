/*
 * virpcivpd.c: helper APIs for working with the PCI/PCIe VPD capability
 *
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifdef __linux__
# include <unistd.h>
#endif

#define LIBVIRT_VIRPCIVPDPRIV_H_ALLOW

#include "virthread.h"
#include "virpcivpdpriv.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.pcivpd");

static bool
virPCIVPDResourceIsUpperOrNumber(const char c)
{
    return g_ascii_isupper(c) || g_ascii_isdigit(c);
}

static bool
virPCIVPDResourceIsVendorKeyword(const char *keyword)
{
    return g_str_has_prefix(keyword, "V") && virPCIVPDResourceIsUpperOrNumber(keyword[1]);
}

static bool
virPCIVPDResourceIsSystemKeyword(const char *keyword)
{
    /* Special-case the system-specific keywords since they share the "Y" prefix with "YA". */
    return (g_str_has_prefix(keyword, "Y") && virPCIVPDResourceIsUpperOrNumber(keyword[1]) &&
            STRNEQ(keyword, "YA"));
}

static char *
virPCIVPDResourceGetKeywordPrefix(const char *keyword)
{
    g_autofree char *key = NULL;

    /* Keywords must have a length of 2 bytes. */
    if (strlen(keyword) != 2) {
        VIR_INFO("The keyword length is not 2 bytes: %s", keyword);
        return NULL;
    } else if (!(virPCIVPDResourceIsUpperOrNumber(keyword[0]) &&
                 virPCIVPDResourceIsUpperOrNumber(keyword[1]))) {
        VIR_INFO("The keyword is not comprised only of uppercase ASCII letters or digits");
        return NULL;
    }
    /* Special-case the system-specific keywords since they share the "Y" prefix with "YA". */
    if (virPCIVPDResourceIsSystemKeyword(keyword) || virPCIVPDResourceIsVendorKeyword(keyword))
        key = g_strndup(keyword, 1);
    else
        key = g_strndup(keyword, 2);

    return g_steal_pointer(&key);
}

static GHashTable *fieldValueFormats;

static int
virPCIVPDResourceOnceInit(void)
{
    /* Initialize a hash table once with static format metadata coming from the PCI(e) specs.
     * The VPD format does not embed format metadata into the resource records so it is not
     * possible to do format discovery without static information. Legacy PICMIG keywords
     * are not included. NOTE: string literals are copied as g_hash_table_insert
     * requires pointers to non-const data. */
    fieldValueFormats = g_hash_table_new(g_str_hash, g_str_equal);
    /* Extended capability. Contains binary data per PCI(e) specs. */
    g_hash_table_insert(fieldValueFormats, g_strdup("CP"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_BINARY));
    /* Engineering Change Level of an Add-in Card. */
    g_hash_table_insert(fieldValueFormats, g_strdup("EC"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));
    /* Manufacture ID */
    g_hash_table_insert(fieldValueFormats, g_strdup("MN"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));
    /* Add-in Card Part Number */
    g_hash_table_insert(fieldValueFormats, g_strdup("PN"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));
    /* Checksum and Reserved */
    g_hash_table_insert(fieldValueFormats, g_strdup("RV"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RESVD));
    /* Remaining Read/Write Area */
    g_hash_table_insert(fieldValueFormats, g_strdup("RW"),
                            GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RDWR));
    /* Serial Number */
    g_hash_table_insert(fieldValueFormats, g_strdup("SN"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));
    /* Asset Tag Identifier */
    g_hash_table_insert(fieldValueFormats, g_strdup("YA"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));
    /* This is a vendor specific item and the characters are alphanumeric. The second
     * character (x) of the keyword can be 0 through Z so only the first one is stored. */
    g_hash_table_insert(fieldValueFormats, g_strdup("V"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));
    /* This is a system specific item and the characters are alphanumeric.
     * The second character (x) of the keyword can be 0 through 9 and B through Z. */
    g_hash_table_insert(fieldValueFormats, g_strdup("Y"),
                        GINT_TO_POINTER(VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT));

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virPCIVPDResource);

/**
 * virPCIVPDResourceGetFieldValueFormat:
 * @keyword: A keyword for which to get a value type
 *
 * Returns: a virPCIVPDResourceFieldValueFormat value which specifies the field value type for
 * a provided keyword based on the static information from PCI(e) specs.
 */
virPCIVPDResourceFieldValueFormat
virPCIVPDResourceGetFieldValueFormat(const char *keyword)
{
    g_autofree char *key = NULL;
    gpointer keyVal = NULL;
    virPCIVPDResourceFieldValueFormat format = VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST;

    /* Keywords are expected to be 2 bytes in length which is defined in the specs. */
    if (strlen(keyword) != 2)
        return VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST;

    if (virPCIVPDResourceInitialize() < 0)
        return VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST;

    /* The system and vendor-specific keywords have a variable part - lookup
     * the prefix significant for determining the value format. */
    key = virPCIVPDResourceGetKeywordPrefix(keyword);
    if (key) {
        keyVal = g_hash_table_lookup(fieldValueFormats, key);
        if (keyVal)
            format = GPOINTER_TO_INT(keyVal);
    }
    return format;
}

/**
 * virPCIVPDResourceIsValidTextValue:
 * @value: A NULL-terminated string to assess.
 *
 * Returns: a boolean indicating whether this value is a valid string resource
 * value or text field value. The expectations are based on the keywords specified
 * in relevant sections of PCI(e) specifications
 * ("I.3. VPD Definitions" in PCI specs, "6.28.1 VPD Format" PCIe 4.0).
 */
bool
virPCIVPDResourceIsValidTextValue(const char *value)
{
    size_t i = 0;
    /*
     * The PCI(e) specs mention alphanumeric characters when talking about text fields
     * and the string resource but also include spaces and dashes in the provided example.
     * Dots, commas, equal signs have also been observed in values used by major device vendors.
     * The specs do not specify a full set of allowed code points and for Libvirt it is important
     * to keep values in the ranges allowed within XML elements (mainly excluding less-than,
     * greater-than and ampersand).
     */

    if (value == NULL)
        return false;

    /* An empty string is a valid value. */
    if (STREQ(value, ""))
        return true;

    while (i < strlen(value)) {
        if (!g_ascii_isprint(value[i])) {
            VIR_DEBUG("The provided value contains non-ASCII printable characters: %s", value);
            return false;
        }
        ++i;
    }
    return true;
}

void
virPCIVPDResourceFree(virPCIVPDResource *res)
{
    if (!res)
        return;

    g_free(res->name);
    virPCIVPDResourceROFree(res->ro);
    virPCIVPDResourceRWFree(res->rw);
    g_free(res);
}

virPCIVPDResourceRO *
virPCIVPDResourceRONew(void)
{
    g_autoptr(virPCIVPDResourceRO) ro = g_new0(virPCIVPDResourceRO, 1);
    ro->vendor_specific = g_ptr_array_new_full(0, (GDestroyNotify)virPCIVPDResourceCustomFree);
    return g_steal_pointer(&ro);
}

void
virPCIVPDResourceROFree(virPCIVPDResourceRO *ro)
{
    if (!ro)
        return;

    g_free(ro->change_level);
    g_free(ro->manufacture_id);
    g_free(ro->part_number);
    g_free(ro->serial_number);
    g_ptr_array_unref(ro->vendor_specific);
    g_free(ro);
}

virPCIVPDResourceRW *
virPCIVPDResourceRWNew(void)
{
    g_autoptr(virPCIVPDResourceRW) rw = g_new0(virPCIVPDResourceRW, 1);
    rw->vendor_specific = g_ptr_array_new_full(0, (GDestroyNotify)virPCIVPDResourceCustomFree);
    rw->system_specific = g_ptr_array_new_full(0, (GDestroyNotify)virPCIVPDResourceCustomFree);
    return g_steal_pointer(&rw);
}

void
virPCIVPDResourceRWFree(virPCIVPDResourceRW *rw)
{
    if (!rw)
        return;

    g_free(rw->asset_tag);
    g_ptr_array_unref(rw->vendor_specific);
    g_ptr_array_unref(rw->system_specific);
    g_free(rw);
}

void
virPCIVPDResourceCustomFree(virPCIVPDResourceCustom *custom)
{
    g_free(custom->value);
    g_free(custom);
}

gboolean
virPCIVPDResourceCustomCompareIndex(virPCIVPDResourceCustom *a, virPCIVPDResourceCustom *b)
{
    if (a == b)
        return TRUE;
    else if (a == NULL || b == NULL)
        return FALSE;
    else
        return a->idx == b->idx ? TRUE : FALSE;
}

/**
 * virPCIVPDResourceCustomUpsertValue:
 * @arr: A GPtrArray with virPCIVPDResourceCustom entries to update.
 * @index: An index character for the keyword.
 * @value: A pointer to the value to be inserted at a given index.
 *
 * Returns: true if a value has been updated successfully, false otherwise.
 */
bool
virPCIVPDResourceCustomUpsertValue(GPtrArray *arr, char index, const char *const value)
{
    g_autoptr(virPCIVPDResourceCustom) custom = NULL;
    virPCIVPDResourceCustom *existing = NULL;
    guint pos = 0;
    bool found = false;

    if (arr == NULL || value == NULL)
        return false;

    custom = g_new0(virPCIVPDResourceCustom, 1);
    custom->idx = index;
    custom->value = g_strdup(value);
    found = g_ptr_array_find_with_equal_func(arr, custom,
                                             (GEqualFunc)virPCIVPDResourceCustomCompareIndex,
                                             &pos);
    if (found) {
        existing = g_ptr_array_index(arr, pos);
        g_free(existing->value);
        existing->value = g_steal_pointer(&custom->value);
    } else {
        g_ptr_array_add(arr, g_steal_pointer(&custom));
    }
    return true;
}

/**
 * virPCIVPDResourceUpdateKeyword:
 * @res: A non-NULL pointer to a virPCIVPDResource where a keyword will be updated.
 * @readOnly: A bool specifying which section to update (in-memory): read-only or read-write.
 * @keyword: A non-NULL pointer to a name of the keyword that will be updated.
 * @value: A pointer to the keyword value or NULL. The value is copied on successful update.
 *
 * The caller is responsible for initializing the relevant RO or RW sections of the resource,
 * otherwise, false will be returned.
 *
 * Keyword names are either 2-byte keywords from the spec or their human-readable alternatives
 * used in XML elements. For vendor-specific and system-specific keywords only V%s and Y%s
 * (except "YA" which is an asset tag) formatted values are accepted.
 *
 * Returns: true if a keyword has been updated successfully, false otherwise.
 */
bool
virPCIVPDResourceUpdateKeyword(virPCIVPDResource *res, const bool readOnly,
                               const char *const keyword, const char *const value)
{
    if (!res) {
        VIR_INFO("Cannot update the resource: a NULL resource pointer has been provided.");
        return false;
    } else if (!keyword) {
        VIR_INFO("Cannot update the resource: a NULL keyword pointer has been provided.");
        return false;
    }

    if (readOnly) {
        if (!res->ro) {
            VIR_INFO("Cannot update the read-only keyword: RO section not initialized.");
            return false;
        }

        if (STREQ("EC", keyword) || STREQ("change_level", keyword)) {
            g_free(res->ro->change_level);
            res->ro->change_level = g_strdup(value);
            return true;
        } else if (STREQ("MN", keyword) || STREQ("manufacture_id", keyword)) {
            g_free(res->ro->manufacture_id);
            res->ro->manufacture_id = g_strdup(value);
            return true;
        } else if (STREQ("PN", keyword) || STREQ("part_number", keyword)) {
            g_free(res->ro->part_number);
            res->ro->part_number = g_strdup(value);
            return true;
        } else if (STREQ("SN", keyword) || STREQ("serial_number", keyword)) {
            g_free(res->ro->serial_number);
            res->ro->serial_number = g_strdup(value);
            return true;
        } else if (virPCIVPDResourceIsVendorKeyword(keyword)) {
            if (!virPCIVPDResourceCustomUpsertValue(res->ro->vendor_specific, keyword[1], value)) {
                return false;
            }
            return true;
        } else if (STREQ("FG", keyword) || STREQ("LC", keyword) || STREQ("PG", keyword)) {
            /* Legacy PICMIG keywords are skipped on purpose. */
            return true;
        } else if (STREQ("CP", keyword)) {
            /* The CP keyword is currently not supported and is skipped. */
            return true;
        }

    } else {
        if (!res->rw) {
            VIR_INFO("Cannot update the read-write keyword: read-write section not initialized.");
            return false;
        }

        if (STREQ("YA", keyword) || STREQ("asset_tag", keyword)) {
            g_free(res->rw->asset_tag);
            res->rw->asset_tag = g_strdup(value);
            return true;
        } else if (virPCIVPDResourceIsVendorKeyword(keyword)) {
            if (!virPCIVPDResourceCustomUpsertValue(res->rw->vendor_specific, keyword[1], value)) {
                return false;
            }
            return true;
        } else if (virPCIVPDResourceIsSystemKeyword(keyword)) {
            if (!virPCIVPDResourceCustomUpsertValue(res->rw->system_specific, keyword[1], value)) {
                return false;
            }
            return true;
        }
    }
    VIR_WARN("Tried to update an unsupported keyword %s: skipping.", keyword);
    return true;
}

#ifdef __linux__

/**
 * virPCIVPDReadVPDBytes:
 * @vpdFileFd: A file descriptor associated with a file containing PCI device VPD.
 * @buf: An allocated buffer to use for storing VPD bytes read.
 * @count: The number of bytes to read from the VPD file descriptor.
 * @offset: The offset at which bytes need to be read.
 * @csum: A pointer to a byte containing the current checksum value. Mutated by this function.
 *
 * Returns: the number of VPD bytes read from the specified file descriptor. The csum value is
 * also modified as bytes are read. If an error occurs while reading data from the VPD file
 * descriptor, it is reported and -1 is returned to the caller. If EOF is occurred, 0 is returned
 * to the caller.
 */
size_t
virPCIVPDReadVPDBytes(int vpdFileFd, uint8_t *buf, size_t count, off_t offset, uint8_t *csum)
{
    ssize_t numRead = pread(vpdFileFd, buf, count, offset);

    if (numRead == -1) {
        VIR_DEBUG("Unable to read %zu bytes at offset %zd from fd: %d",
                  count, (ssize_t)offset, vpdFileFd);
    } else if (numRead) {
        /*
         * Update the checksum for every byte read. Per the PCI(e) specs
         * the checksum is correct if the sum of all bytes in VPD from
         * VPD address 0 up to and including the VPD-R RV field's first
         * data byte is zero.
         */
        while (count--) {
            *csum += *buf;
            buf++;
        }
    }
    return numRead;
}

/**
 * virPCIVPDParseVPDLargeResourceFields:
 * @vpdFileFd: A file descriptor associated with a file containing PCI device VPD.
 * @resPos: A position where the resource data bytes begin in a file descriptor.
 * @resDataLen: A length of the data portion of a resource.
 * @readOnly: A boolean showing whether the resource type is VPD-R or VPD-W.
 * @csum: A pointer to a 1-byte checksum.
 * @res: A pointer to virPCIVPDResource.
 *
 * Returns: a pointer to a VPDResource which needs to be freed by the caller or
 * NULL if getting it failed for some reason.
 */
bool
virPCIVPDParseVPDLargeResourceFields(int vpdFileFd, uint16_t resPos, uint16_t resDataLen,
                                     bool readOnly, uint8_t *csum, virPCIVPDResource *res)
{
    /* A buffer of up to one resource record field size (plus a zero byte) is needed. */
    g_autofree uint8_t *buf = g_malloc0(PCI_VPD_MAX_FIELD_SIZE + 1);
    uint16_t fieldDataLen = 0, bytesToRead = 0;
    uint16_t fieldPos = resPos;

    bool hasChecksum = false;
    bool hasRW = false;
    bool endReached = false;

    /* Note the equal sign - fields may have a zero length in which case they will
     * just occupy 3 header bytes. In the in case of the RW field this may mean that
     * no more space is left in the section. */
    while (fieldPos + 3 <= resPos + resDataLen) {
        virPCIVPDResourceFieldValueFormat fieldFormat = VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST;
        g_autofree char *fieldKeyword = NULL;
        g_autofree char *fieldValue = NULL;

        /* Keyword resources consist of keywords (2 ASCII bytes per the spec) and 1-byte length. */
        if (virPCIVPDReadVPDBytes(vpdFileFd, buf, 3, fieldPos, csum) != 3) {
            /* Invalid field encountered which means the resource itself is invalid too. Report
             * That VPD has invalid format and bail. */
            VIR_INFO("Could not read a resource field header - VPD has invalid format");
            return false;
        }
        fieldDataLen = buf[2];
        /* Change the position to the field's data portion skipping the keyword and length bytes. */
        fieldPos += 3;
        fieldKeyword = g_strndup((char *)buf, 2);
        fieldFormat = virPCIVPDResourceGetFieldValueFormat(fieldKeyword);

        /* Handle special cases first */
        if (!readOnly && fieldFormat == VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RESVD) {
            VIR_INFO("Unexpected RV keyword in the read-write section.");
            return false;
        } else if (readOnly && fieldFormat == VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RDWR) {
            VIR_INFO("Unexpected RW keyword in the read-only section.");
            return false;
        }

        /* Determine how many bytes to read per field value type. */
        switch (fieldFormat) {
            case VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT:
            case VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RDWR:
            case VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_BINARY:
                bytesToRead = fieldDataLen;
                break;
            case VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RESVD:
                /* Only need one byte to be read and accounted towards
                 * the checksum calculation. */
                bytesToRead = 1;
                break;
            case VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST:
                /* The VPD format could be extended in future versions with new
                 * keywords - attempt to skip them by reading past them since
                 * their data length would still be specified. */
                VIR_DEBUG("Could not determine a field value format for keyword: %s", fieldKeyword);
                bytesToRead = fieldDataLen;
                break;
            default:
                VIR_INFO("Unexpected field value format encountered.");
                return false;
        }

        if (resPos + resDataLen < fieldPos + fieldDataLen) {
            /* In this case the field cannot simply be skipped since the position of the
             * next field is determined based on the length of a previous field. */
            VIR_INFO("A field data length violates the resource length boundary.");
            return false;
        }
        if (virPCIVPDReadVPDBytes(vpdFileFd, buf, bytesToRead, fieldPos, csum) != bytesToRead) {
            VIR_INFO("Could not parse a resource field data - VPD has invalid format");
            return false;
        }
        /* Advance the position to the first byte of the next field. */
        fieldPos += fieldDataLen;

        if (fieldFormat == VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT) {
            /* Trim whitespace around a retrieved value and set it to be a field's value. Cases
             * where unnecessary whitespace was present around a field value have been encountered
             * in the wild.
             */
            fieldValue = g_strstrip(g_strndup((char *)buf, fieldDataLen));
            if (!virPCIVPDResourceIsValidTextValue(fieldValue)) {
                /* Skip fields with invalid values - this is safe assuming field length is
                 * correctly specified. */
                VIR_DEBUG("A value for field %s contains invalid characters", fieldKeyword);
                continue;
            }
        } else if (fieldFormat == VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RESVD) {
            if (*csum) {
                /* All bytes up to and including the checksum byte should add up to 0. */
                VIR_INFO("Checksum validation has failed");
                return false;
            }
            hasChecksum = true;
            break;
        } else if (fieldFormat == VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RDWR) {
            /* Skip the read-write space since it is used for indication only. */
            hasRW = true;
            break;
        } else if (fieldFormat == VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST) {
            /* Skip unknown fields */
            continue;
        } else {
            fieldValue = g_malloc(fieldDataLen);
            memcpy(fieldValue, buf, fieldDataLen);
        }

        if (readOnly) {
            if (!res->ro)
                res->ro = virPCIVPDResourceRONew();
        } else {
            if (!res->rw)
                res->rw = virPCIVPDResourceRWNew();
        }
        /* The field format, keyword and value are determined. Attempt to update the resource. */
        if (!virPCIVPDResourceUpdateKeyword(res, readOnly, fieldKeyword, fieldValue)) {
            VIR_INFO("Could not update the VPD resource keyword: %s", fieldKeyword);
            return false;
        }
    }

    /* May have exited the loop prematurely in case RV or RW were encountered and
     * they were not the last fields in the section. */
    endReached = (fieldPos >= resPos + resDataLen);
    if (readOnly && !(hasChecksum && endReached)) {
        VIR_DEBUG("VPD-R does not contain the mandatory RV field as the last field");
        return false;
    } else if (!readOnly && !endReached) {
        /* The lack of RW is allowed on purpose in the read-write section since some vendors
         * violate the PCI/PCIe specs and do not include it, however, this does not prevent parsing
         * of valid data. If the RW is present, however, we make sure it is the last field in
         * the read-write section. */
        if (hasRW) {
            VIR_DEBUG("VPD-W section parsing ended prematurely (RW is not the last field).");
            return false;
        } else {
            VIR_DEBUG("VPD-W section parsing ended prematurely.");
            return false;
        }
    }

    return true;
}

/**
 * virPCIVPDParseVPDLargeResourceString:
 * @vpdFileFd: A file descriptor associated with a file containing PCI device VPD.
 * @resPos: A position where the resource data bytes begin in a file descriptor.
 * @resDataLen: A length of the data portion of a resource.
 * @csum: A pointer to a 1-byte checksum.
 *
 * Returns: a pointer to a VPDResource which needs to be freed by the caller or
 * NULL if getting it failed for some reason.
 */
bool
virPCIVPDParseVPDLargeResourceString(int vpdFileFd, uint16_t resPos,
                                     uint16_t resDataLen, uint8_t *csum, virPCIVPDResource *res)
{
    g_autofree char *resValue = NULL;

    /* The resource value is not NULL-terminated so add one more byte. */
    g_autofree char *buf = g_malloc0(resDataLen + 1);

    if (virPCIVPDReadVPDBytes(vpdFileFd, (uint8_t *)buf, resDataLen, resPos, csum) != resDataLen) {
        VIR_INFO("Could not read a part of a resource - VPD has invalid format");
        return false;
    }
    resValue = g_strdup(g_strstrip(buf));
    if (!virPCIVPDResourceIsValidTextValue(resValue)) {
        VIR_INFO("The string resource has invalid characters in its value");
        return false;
    }
    res->name = g_steal_pointer(&resValue);
    return true;
}

/**
 * virPCIVPDParse:
 * @vpdFileFd: a file descriptor associated with a file containing PCI device VPD.
 *
 * Parse a PCI device's Vital Product Data (VPD) contained in a file descriptor.
 *
 * Returns: a pointer to a GList of VPDResource types which needs to be freed by the caller or
 * NULL if getting it failed for some reason.
 */
virPCIVPDResource *
virPCIVPDParse(int vpdFileFd)
{
    /* A checksum which is calculated as a sum of all bytes from VPD byte 0 up to
     * the checksum byte in the RV field's value. The RV field is only present in the
     * VPD-R resource and the checksum byte there is the first byte of the field's value.
     * The checksum byte in RV field is actually a two's complement of the sum of all bytes
     * of VPD that come before it so adding the two together must produce 0 if data
     * was not corrupted and VPD storage is intact.
     */
    uint8_t csum = 0;
    uint8_t headerBuf[2];

    bool isWellFormed = false;
    uint16_t resPos = 0, resDataLen;
    uint8_t tag = 0;
    bool endResReached = false, hasReadOnly = false;

    g_autoptr(virPCIVPDResource) res = g_new0(virPCIVPDResource, 1);

    while (resPos <= PCI_VPD_ADDR_MASK) {
        /* Read the resource data type tag. */
        if (virPCIVPDReadVPDBytes(vpdFileFd, &tag, 1, resPos, &csum) != 1)
            break;

        /* 0x80 == 0b10000000 - the large resource data type flag. */
        if (tag & PCI_VPD_LARGE_RESOURCE_FLAG) {
            if (resPos > PCI_VPD_ADDR_MASK + 1 - 3) {
                /* Bail if the large resource starts at the position
                 * where the end tag should be. */
                break;
            }
            /* Read the two length bytes of the large resource record. */
            if (virPCIVPDReadVPDBytes(vpdFileFd, headerBuf, 2, resPos + 1, &csum) != 2)
                break;

            resDataLen = headerBuf[0] + (headerBuf[1] << 8);
            /* Change the position to the byte following the tag and length bytes. */
            resPos += 3;
        } else {
            /* Handle a small resource record.
             * 0xxxxyyy & 00000111, where xxxx - resource data type bits, yyy - length bits. */
            resDataLen = tag & 7;
            /* 0xxxxyyy >> 3 == 0000xxxx */
            tag >>= 3;
            /* Change the position to the byte past the byte containing tag and length bits. */
            resPos += 1;
        }
        if (tag == PCI_VPD_RESOURCE_END_TAG) {
            /* Stop VPD traversal since the end tag was encountered. */
            endResReached = true;
            break;
        }
        if (resDataLen > PCI_VPD_ADDR_MASK + 1 - resPos) {
            /* Bail if the resource is too long to fit into the VPD address space. */
            break;
        }

        switch (tag) {
                /* Large resource type which is also a string: 0x80 | 0x02 = 0x82 */
            case PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_STRING_RESOURCE_FLAG:
                isWellFormed = virPCIVPDParseVPDLargeResourceString(vpdFileFd, resPos, resDataLen,
                                                                    &csum, res);
                break;
                /* Large resource type which is also a VPD-R: 0x80 | 0x10 == 0x90 */
            case PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG:
                isWellFormed = virPCIVPDParseVPDLargeResourceFields(vpdFileFd, resPos,
                                                                    resDataLen, true, &csum, res);
                /* Encountered the VPD-R tag. The resource record parsing also validates
                 * the presence of the required checksum in the RV field. */
                hasReadOnly = true;
                break;
                /* Large resource type which is also a VPD-W: 0x80 | 0x11 == 0x91 */
            case PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_WRITE_LARGE_RESOURCE_FLAG:
                isWellFormed = virPCIVPDParseVPDLargeResourceFields(vpdFileFd, resPos, resDataLen,
                                                                    false, &csum, res);
                break;
            default:
                /* While we cannot parse unknown resource types, they can still be skipped
                 * based on the header and data length. */
                VIR_DEBUG("Encountered an unexpected VPD resource tag: %#x", tag);
                resPos += resDataLen;
                continue;
        }

        if (!isWellFormed) {
            VIR_DEBUG("Encountered an invalid VPD");
            return NULL;
        }

        /* Continue processing other resource records. */
        resPos += resDataLen;
    }
    if (!hasReadOnly) {
        VIR_DEBUG("Encountered an invalid VPD: does not have a VPD-R record");
        return NULL;
    } else if (!endResReached) {
        /* Does not have an end tag. */
        VIR_DEBUG("Encountered an invalid VPD");
        return NULL;
    }
    return g_steal_pointer(&res);
}

#else /* ! __linux__ */

size_t
virPCIVPDReadVPDBytes(int vpdFileFd G_GNUC_UNUSED,
                      uint8_t *buf G_GNUC_UNUSED,
                      size_t count G_GNUC_UNUSED,
                      off_t offset G_GNUC_UNUSED,
                      uint8_t *csum G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("PCI VPD reporting not available on this platform"));
    return 0;
}

bool
virPCIVPDParseVPDLargeResourceString(int vpdFileFd G_GNUC_UNUSED,
                                     uint16_t resPos G_GNUC_UNUSED,
                                     uint16_t resDataLen G_GNUC_UNUSED,
                                     uint8_t *csum G_GNUC_UNUSED,
                                     virPCIVPDResource *res G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("PCI VPD reporting not available on this platform"));
    return false;
}

bool
virPCIVPDParseVPDLargeResourceFields(int vpdFileFd G_GNUC_UNUSED,
                                     uint16_t resPos G_GNUC_UNUSED,
                                     uint16_t resDataLen G_GNUC_UNUSED,
                                     bool readOnly G_GNUC_UNUSED,
                                     uint8_t *csum G_GNUC_UNUSED,
                                     virPCIVPDResource *res G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("PCI VPD reporting not available on this platform"));
    return false;
}

virPCIVPDResource *
virPCIVPDParse(int vpdFileFd G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("PCI VPD reporting not available on this platform"));
    return NULL;
}

#endif /* ! __linux__ */
