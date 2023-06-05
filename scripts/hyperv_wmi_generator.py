#!/usr/bin/env python3

#
# hyperv_wmi_generator.py: generates most of the WMI type mapping code
#
# Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.
#

import os
import os.path
import sys

separator = "/*" + ("*" * 50) + "*\n"
wmi_classes_by_name = {}


class WmiClass:
    """Represents WMI class and provides methods to generate C code."""

    def __init__(self, name, properties, uri_info):
        self.name = name
        self.properties = properties
        self.uri_info = uri_info

    def generate_classes_header(self):
        """Generate C header code and return it as string

        Declares:
          <class_name>_Data - used as hypervObject->data
          <class_name>_TypeInfo - used as wsman XmlSerializerInfo
          <class_name> - "inherits" hypervObject struct
        """

        name_upper = self.name.upper()

        header = separator
        header += " * %s\n" % self.name
        header += " */\n"
        header += "\n"
        header += "#define %s_WQL_SELECT \\\n" % name_upper
        header += "    \"SELECT * FROM %s \"\n" % self.name
        header += "\n"
        header += "extern hypervWmiClassInfo *%s_WmiInfo;\n\n" % self.name

        header += self._declare_data_structs()
        header += self._declare_hypervObject_struct()

        return header

    def generate_classes_source(self):
        """Returns a C code string defining wsman data structs

        Defines:
          <class_name>_Data struct
          <class_name>_WmiInfo - list holding metadata (e.g. request URIs) for the WMI class
        """

        source = separator
        source += " * %s\n" % self.name
        source += " */\n"

        source += "SER_START_ITEMS(%s_Data)\n" % self.name

        for property in self.properties:
            source += property.generate_classes_source(self.name)

        source += "SER_END_ITEMS(%s_Data);\n\n" % self.name

        # also generate typemap data while we're here
        source += "hypervCimType %s_Typemap[] = {\n" % self.name

        for property in self.properties:
            source += property.generate_typemap()
        source += '    { "", "", 0 },\n'  # null terminated
        source += '};\n\n'

        source += self._define_WmiInfo_struct()
        source += "\n\n"

        return source

    def generate_classes_typedef(self):
        """Returns C string for typedefs"""

        typedef = "typedef struct _%s %s;\n" % (self.name, self.name)
        typedef += "typedef struct _%s_Data %s_Data;\n" % (self.name, self.name)
        typedef += "G_DEFINE_AUTOPTR_CLEANUP_FUNC(%s, hypervFreeObject);\n" % self.name
        typedef += "\n"

        return typedef

    def _declare_data_structs(self):
        """Returns string C code declaring data structs.

        The *_Data structs are used as hypervObject->data. Each one has
        corresponding *_TypeInfo that is used for wsman unserialization of
        response XML into the *_Data structs.
        """

        header = "#define %s_RESOURCE_URI \\\n" % self.name.upper()
        header += "    \"%s\"\n" % self.uri_info.resourceUri
        header += "\n"
        header += "struct _%s_Data {\n" % self.name
        for property in self.properties:
            header += property.generate_classes_header()
        header += "};\n\n"
        header += "SER_DECLARE_TYPE(%s_Data);\n" % self.name

        return header

    def _declare_hypervObject_struct(self):
        """Return string for C code declaring hypervObject instance"""

        header = "\n/* must match hypervObject */\n"
        header += "struct _%s {\n" % self.name
        header += "    %s_Data *data;\n" % self.name
        header += "    hypervWmiClassInfo *info;\n"
        header += "    %s *next;\n" % self.name
        header += "};\n"

        header += "\n\n\n"

        return header

    def _define_WmiInfo_struct(self):
        """Return string for C code defining *_WmiInfo struct

        This struct holds info with meta-data needed to make wsman requests for the WMI class.
        """

        source = "hypervWmiClassInfo *%s_WmiInfo = &(hypervWmiClassInfo) {\n" % self.name
        source += "    .name = \"%s\",\n" % self.name
        source += "    .rootUri = %s,\n" % self.uri_info.rootUri
        source += "    .resourceUri = %s_RESOURCE_URI,\n" % self.name.upper()
        source += "    .serializerInfo = %s_Data_TypeInfo,\n" % self.name
        source += "    .propertyInfo = %s_Typemap\n" % self.name
        source += "};\n"

        return source


class ClassUriInfo:
    """Prepares URI information needed for wsman requests."""

    def __init__(self, wmi_name):
        if wmi_name.startswith("Msvm_"):
            self.rootUri = "ROOT_VIRTUALIZATION_V2"
            baseUri = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/virtualization/v2"
        else:
            self.rootUri = "ROOT_CIMV2"
            baseUri = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2"

        self.resourceUri = "%s/%s" % (baseUri, wmi_name)


class Property:
    typemap = {
        "boolean": "BOOL",
        "string": "STR",
        "datetime": "STR",
        "int8": "INT8",
        "sint8": "INT8",
        "int16": "INT16",
        "sint16": "INT16",
        "int32": "INT32",
        "sint32": "INT32",
        "int64": "INT64",
        "sint64": "INT64",
        "uint8": "UINT8",
        "uint16": "UINT16",
        "uint32": "UINT32",
        "uint64": "UINT64"
    }

    def __init__(self, type, name, is_array):
        if type not in Property.typemap:
            report_error("unhandled property type %s" % type)

        self.type = type
        self.name = name
        self.is_array = is_array

    def generate_classes_header(self):
        if self.is_array:
            return "    XML_TYPE_DYN_ARRAY %s;\n" % self.name
        else:
            return "    XML_TYPE_%s %s;\n" \
                   % (Property.typemap[self.type], self.name)

    def generate_classes_source(self, class_name):
        if self.is_array:
            return "    SER_NS_DYN_ARRAY(%s_RESOURCE_URI, \"%s\", 0, 0, %s),\n" \
                   % (class_name.upper(), self.name, self.type)
        else:
            return "    SER_NS_%s(%s_RESOURCE_URI, \"%s\", 1),\n" \
                   % (Property.typemap[self.type], class_name.upper(), self.name)

    def generate_typemap(self):
        return '    { "%s", "%s", %s },\n' % (self.name, self.type.lower(), str(self.is_array).lower())


def open_file(filename):
    return open(filename, "wt")


def report_error(message):
    print("error: " + message)
    sys.exit(1)


def parse_class(block, number):
    # expected format: class <name> : <optional parent>
    header_items = block[0][1].split()

    if len(header_items) not in [2, 4]:
        report_error("line %d: invalid block header" % (number))

    assert header_items[0] == "class"

    name = header_items[1]

    if name in wmi_classes_by_name:
        report_error("class '%s' has already been defined" % name)

    if len(header_items) == 4:
        parent_class = header_items[3]
        if parent_class not in wmi_classes_by_name:
            report_error("nonexistent parent class specified: %s" % parent_class)
        properties = wmi_classes_by_name[parent_class].properties.copy()
    else:
        properties = []

    for line in block[1:]:
        # expected format: <type> <name>
        items = line[1].split()

        if len(items) != 2:
            report_error("line %d: invalid property" % line[0])

        if items[1].endswith("[]"):
            items[1] = items[1][:-2]
            is_array = True
        else:
            is_array = False

        properties.append(Property(type=items[0], name=items[1], is_array=is_array))

    wmi_classes_by_name[name] = WmiClass(name, properties, ClassUriInfo(name))


def main():
    if len(sys.argv) != 3:
        report_error("usage: %s srcdir builddir" % sys.argv[0])

    input_filename = os.path.join(sys.argv[1], "hyperv", "hyperv_wmi_generator.input")
    output_dirname = os.path.join(sys.argv[2], "hyperv")

    classes_typedef = open_file(os.path.join(output_dirname, "hyperv_wmi_classes.generated.typedef"))
    classes_header = open_file(os.path.join(output_dirname, "hyperv_wmi_classes.generated.h"))
    classes_source = open_file(os.path.join(output_dirname, "hyperv_wmi_classes.generated.c"))

    # parse input file
    number = 0
    block = None

    for line in open(input_filename, "rt").readlines():
        number += 1

        if "#" in line:
            line = line[:line.index("#")]

        line = line.lstrip().rstrip()

        if len(line) < 1:
            continue

        if line.startswith("class"):
            if block is not None:
                report_error("line %d: nested block found" % (number))
            else:
                block = []

        if block is not None:
            if line == "end":
                if block[0][1].startswith("class"):
                    parse_class(block, number)

                block = None
            else:
                block.append((number, line))

    # write output files
    notice = "/* Generated by hyperv_wmi_generator.py */\n\n\n\n"

    classes_typedef.write(notice)
    classes_header.write(notice)
    classes_source.write(notice)

    classes_typedef.write("void hypervFreeObject(void *object);\n\n\n")

    names = sorted(wmi_classes_by_name.keys())

    for name in names:
        cls = wmi_classes_by_name[name]

        classes_typedef.write(cls.generate_classes_typedef())
        classes_header.write(cls.generate_classes_header())
        classes_source.write(cls.generate_classes_source())


if __name__ == "__main__":
    main()
