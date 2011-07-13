#!/usr/bin/env python

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
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
#

import sys
import os
import os.path



separator = "/* " + ("* " * 37) + "*\n"



class Class:
    def __init__(self, name, properties):
        self.name = name
        self.properties = properties


    def generate_header(self):
        name_upper = self.name.upper()

        header = separator
        header += " * %s\n" % self.name
        header += " */\n"
        header += "\n"
        header += "int hypervGet%sList(hypervPrivate *priv, virBufferPtr query, %s **list);\n" \
                  % (self.name.replace("_", ""), self.name)
        header += "\n"
        header += "\n"
        header += "\n"

        return header


    def generate_classes_typedef(self):
        typedef = "typedef struct _%s_Data %s_Data;\n" % (self.name, self.name)
        typedef += "typedef struct _%s %s;\n" % (self.name, self.name)

        return typedef


    def generate_classes_header(self):
        name_upper = self.name.upper()

        header = separator
        header += " * %s\n" % self.name
        header += " */\n"
        header += "\n"
        header += "#define %s_RESOURCE_URI \\\n" % name_upper

        if self.name.startswith("Win32_"):
            header += "    \"http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/%s\"\n" % self.name
        else:
            header += "    \"http://schemas.microsoft.com/wbem/wsman/1/wmi/root/virtualization/%s\"\n" % self.name

        header += "\n"
        header += "#define %s_CLASSNAME \\\n" % name_upper
        header += "    \"%s\"\n" % self.name
        header += "\n"
        header += "#define %s_WQL_SELECT \\\n" % name_upper
        header += "    \"select * from %s \"\n" % self.name
        header += "\n"
        header += "struct _%s_Data {\n" % self.name

        for property in self.properties:
            header += property.generate_classes_header()

        header += "};\n"
        header += "\n"
        header += "SER_DECLARE_TYPE(%s_Data);\n" % self.name
        header += "\n"
        header += "struct _%s {\n" % self.name
        header += "    XmlSerializerInfo *serializerInfo;\n"
        header += "    %s_Data *data;\n" % self.name
        header += "    %s *next;\n" % self.name
        header += "};\n"
        header += "\n"
        header += "\n"
        header += "\n"

        return header


    def generate_source(self):
        name_upper = self.name.upper()

        source = separator
        source += " * %s\n" % self.name
        source += " */\n"
        source += "\n"
        source += "int\n"
        source += "hypervGet%sList(hypervPrivate *priv, virBufferPtr query, %s **list)\n" \
                  % (self.name.replace("_", ""), self.name)
        source += "{\n"

        if self.name.startswith("Win32_"):
            source += "    return hypervEnumAndPull(priv, query, ROOT_CIMV2,\n"
        else:
            source += "    return hypervEnumAndPull(priv, query, ROOT_VIRTUALIZATION,\n"

        source += "                             %s_Data_TypeInfo,\n" % self.name
        source += "                             %s_RESOURCE_URI,\n" % name_upper
        source += "                             %s_CLASSNAME,\n" % name_upper
        source += "                             (hypervObject **)list);\n"
        source += "}\n"
        source += "\n"
        source += "\n"
        source += "\n"

        return source


    def generate_classes_source(self):
        name_upper = self.name.upper()

        source = separator
        source += " * %s\n" % self.name
        source += " */\n"
        source += "\n"
        source += "SER_START_ITEMS(%s_Data)\n" % self.name

        for property in self.properties:
            source += property.generate_classes_source(self.name)

        source += "SER_END_ITEMS(%s_Data);\n" % self.name
        source += "\n"
        source += "\n"
        source += "\n"

        return source


class Property:
    typemap = {"boolean"  : "BOOL",
               "string"   : "STR",
               "datetime" : "STR",
               "int8"     : "INT8",
               "int16"    : "INT16",
               "int32"    : "INT32",
               "int64"    : "INT64",
               "uint8"    : "UINT8",
               "uint16"   : "UINT16",
               "uint32"   : "UINT32",
               "uint64"   : "UINT64"}


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



def open_and_print(filename):
    if filename.startswith("./"):
        print "  GEN    " + filename[2:]
    else:
        print "  GEN    " + filename

    return open(filename, "wb")



def report_error(message):
    print "error: " + message
    sys.exit(1)



def parse_class(block):
    # expected format: class <name>
    header_items = block[0][1].split()

    if len(header_items) != 2:
        report_error("line %d: invalid block header" % (number))

    assert header_items[0] == "class"

    name = header_items[1]

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

        properties.append(Property(type=items[0], name=items[1],
                                   is_array=is_array))

    return Class(name=name, properties=properties)



def main():
    if "srcdir" in os.environ:
        input_filename = os.path.join(os.environ["srcdir"], "hyperv/hyperv_wmi_generator.input")
        output_dirname = os.path.join(os.environ["srcdir"], "hyperv")
    else:
        input_filename = os.path.join(os.getcwd(), "hyperv_wmi_generator.input")
        output_dirname = os.getcwd()

    header = open_and_print(os.path.join(output_dirname, "hyperv_wmi.generated.h"))
    source = open_and_print(os.path.join(output_dirname, "hyperv_wmi.generated.c"))
    classes_typedef = open_and_print(os.path.join(output_dirname, "hyperv_wmi_classes.generated.typedef"))
    classes_header = open_and_print(os.path.join(output_dirname, "hyperv_wmi_classes.generated.h"))
    classes_source = open_and_print(os.path.join(output_dirname, "hyperv_wmi_classes.generated.c"))

    # parse input file
    number = 0
    classes_by_name = {}
    block = None

    for line in file(input_filename, "rb").readlines():
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
                    cls = parse_class(block)
                    classes_by_name[cls.name] = cls

                block = None
            else:
                block.append((number, line))

    # write output files
    notice = "/* Generated by hyperv_wmi_generator.py */\n\n\n\n"

    header.write(notice)
    source.write(notice)
    classes_typedef.write(notice)
    classes_header.write(notice)
    classes_source.write(notice)

    names = classes_by_name.keys()
    names.sort()

    for name in names:
        header.write(classes_by_name[name].generate_header())
        source.write(classes_by_name[name].generate_source())
        classes_typedef.write(classes_by_name[name].generate_classes_typedef())
        classes_header.write(classes_by_name[name].generate_classes_header())
        classes_source.write(classes_by_name[name].generate_classes_source())



if __name__ == "__main__":
    main()
