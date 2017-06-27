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
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.
#

import sys
import os
import os.path

separator = "/*" + ("*" * 50) + "*\n"
wmi_version_separator = "/"
wmi_classes_by_name = {}

class WmiClass:
    """Represents WMI class and provides methods to generate C code.

    This class holds one or more instances of WmiClassVersion because with the
    Windows 2012 release, Microsoft introduced "v2" version of Msvm_* family of
    classes that need different URI for making wsman requests and also have
    some additional/changed properties (though many of the properies are the
    same as in "v1". Therefore, this class makes sure that C code is generated
    for each of them while avoiding name conflics, identifies common members,
    and defined *_WmiInfo structs holding info about each version so the driver
    code can make the right choices based on which Hyper-V host it's connected
    to.
    """

    def __init__(self, name, versions = []):
        self.name = name
        self.versions = versions
        self.common = None


    def prepare(self):
        """Prepares the class for code generation

        Makes sure that "versioned" classes are sorted by version, identifies
        common properies and ensures that they are aligned by name and
        type in each version
        """
        # sort vesioned classes by version in case input file did not have them
        # in order
        self.versions = sorted(self.versions, key=lambda cls: cls.version)

        # if there's more than one verion make sure first one has name suffixed
        # because we'll generate "common" memeber and will be the "base" name
        if len(self.versions) > 1:
            first = self.versions[0]
            if first.version == None:
                first.version = "v1"
            first.name = "%s_%s" % (first.name, first.version)

        # finally, identify common members in all versions and make sure they
        # are in the same order - to ensure C struct member alignment
        self._align_property_members()


    def generate_classes_header(self):
        """Generate C header code and return it as string

        Declares:
          <class_name>_Data - used as one of hypervObject->data members
          <class_name>_TypeInfo - used as wsman XmlSerializerInfo
          <class_name> - "inherits" hypervObject struct
        """

        name_upper = self.name.upper()

        header = separator
        header += " * %s\n" % self.name
        header += " */\n"
        header += "\n"
        header += "#define %s_CLASSNAME \\\n" % name_upper
        header += "    \"%s\"\n" % self.name
        header += "\n"
        header += "#define %s_WQL_SELECT \\\n" % name_upper
        header += "    \"SELECT * FROM %s \"\n" % self.name
        header += "\n"
        header += "extern hypervWmiClassInfoListPtr %s_WmiInfo;\n\n" % self.name

        header += self._declare_data_structs()
        header += self._declare_hypervObject_struct()

        return header


    def generate_classes_source(self):
        """Returns a C code string defining wsman data structs

        Defines:
          <class_name>_Data structs
          <class_name>_WmiInfo - list holding metadata (e.g. request URIs) for
                                 each known version of WMI class.
        """

        source = separator
        source += " * %s\n" % self.name
        source += " */\n"

        for cls in self.versions:
            source += "SER_START_ITEMS(%s_Data)\n" % cls.name

            for property in cls.properties:
                source += property.generate_classes_source(cls.name)

            source += "SER_END_ITEMS(%s_Data);\n\n" % cls.name

            # also generate typemap data while we're here
            source += "hypervCimType %s_Typemap[] = {\n" % cls.name

            for property in cls.properties:
                source += property.generate_typemap()
            source += '    { "", "", 0 },\n' # null terminated
            source += '};\n\n'


        source += self._define_WmiInfo_struct()
        source += "\n\n"

        return source


    def generate_classes_typedef(self):
        """Returns C string for typdefs"""

        typedef = "typedef struct _%s %s;\n" % (self.name, self.name)

        if self.common is not None:
            typedef += "typedef struct _%s_Data %s_Data;\n" % (self.name, self.name)

        for cls in self.versions:
            typedef += "typedef struct _%s_Data %s_Data;\n" % (cls.name, cls.name)

        return typedef



    def _declare_data_structs(self):
        """Returns string C code declaring data structs.

        The *_Data structs are members of hypervObject data union. Each one has
        corresponding *_TypeInfo that is used for wsman unserialization of
        response XML into the *_Data structs. If there's a "common" member, it
        won't have corresponding *_TypeInfo becuase this is a special case only
        used to provide a common "view" of v1, v2 etc members
        """

        header = ""
        if self.common is not None:
            header += "struct _%s_Data {\n" % self.name
            for property in self.common:
                header += property.generate_classes_header()
            header += "};\n\n"

        # Declare actual data struct for each versions
        for cls in self.versions:
            header += "#define %s_RESOURCE_URI \\\n" % cls.name.upper()
            header += "    \"%s\"\n" % cls.uri_info.resourceUri
            header += "\n"
            header += "struct _%s_Data {\n" % cls.name
            for property in cls.properties:
                header += property.generate_classes_header()
            header += "};\n\n"
            header += "SER_DECLARE_TYPE(%s_Data);\n" % cls.name

        return header


    def _declare_hypervObject_struct(self):
        """Return string for C code declaring hypervObject instance"""

        header = "\n/* must match hypervObject */\n"
        header += "struct _%s {\n" % self.name
        header += "    union {\n"

        # if there's common use it as "common" else first and only version is
        # the "common" member
        if self.common is not None:
            header += "        %s_Data *common;\n" % self.name
        else:
            header += "        %s_Data *common;\n" % self.versions[0].name

        for cls in self.versions:
            header += "        %s_Data *%s;\n" % (cls.name, cls.version)

        header += "    } data;\n"
        header += "    hypervWmiClassInfoPtr info;\n"
        header += "    %s *next;\n" % self.name
        header += "};\n"

        header += "\n\n\n"

        return header


    def _define_WmiInfo_struct(self):
        """Return string for C code defining *_WmiInfo struct

        Those structs hold info with meta-data needed to make wsman requests for
        each version of WMI class
        """

        source = "hypervWmiClassInfoListPtr %s_WmiInfo = &(hypervWmiClassInfoList) {\n" % self.name
        source += "    .count = %d,\n" % len(self.versions)
        source += "    .objs = (hypervWmiClassInfoPtr []) {\n"

        for cls in self.versions:
            source += "        &(hypervWmiClassInfo) {\n"
            source += "            .name = %s_CLASSNAME,\n" % self.name.upper()
            if cls.version is not None:
                source += "            .version = \"%s\",\n" % cls.version
            else:
                source += "            .version = NULL,\n"
            source += "            .rootUri = %s,\n" % cls.uri_info.rootUri
            source += "            .resourceUri = %s_RESOURCE_URI,\n" % cls.name.upper()
            source += "            .serializerInfo = %s_Data_TypeInfo,\n" % cls.name
            source += "            .propertyInfo = %s_Typemap\n" % cls.name
            source += "        },\n"

        source += "    }\n"
        source += "};\n"

        return source


    def _align_property_members(self):
        """Identifies common properties in all class versions.

        Makes sure that properties in all versions are ordered with common
        members first and that they are in the same order. This makes the
        generated C structs memory aligned and safe to access via the "common"
        struct that "shares" members with v1, v2 etc.
        """

        num_classes = len(self.versions)
        common = {}
        property_info = {}

        if num_classes < 2:
            return

        # count property occurences in all class versions
        for cls in self.versions:
            for prop in cls.properties:
                # consdered same if matches by name AND type
                key = "%s_%s_%s" % (prop.name, prop.type, prop.is_array)

                if key in property_info:
                    property_info[key][1] += 1
                else:
                    property_info[key] = [prop, 1]

        # isolate those that are common for all and keep track of their postions
        pos = 0
        for key in property_info:
            info = property_info[key]
            # exists in all class versions
            if info[1] == num_classes:
                common[info[0].name] = [info[0], pos]
                pos += 1

        # alter each versions's property list so that common members are first
        # and in the same order as in the common dictionary
        total = len(common)
        for cls in self.versions:
            index = 0
            count = len(cls.properties)

            while index < count:
                prop = cls.properties[index]

                # it's a "common" property
                if prop.name in common:
                    pos = common[prop.name][1]

                    # move to the same position as in "common" dictionary
                    if index != pos:
                        tmp = cls.properties[pos]
                        cls.properties[pos] = prop
                        cls.properties[index] = tmp
                    else:
                        index += 1
                else:
                    index += 1

        # finally, get common properties as list sorted by position in dictionary
        tmp = sorted(common.values(), key=lambda x: x[1])
        self.common = []
        for x in tmp:
            self.common.append(x[0])



class ClassUriInfo:
    """Prepares URI information needed for wsman requests."""

    def __init__(self, wmi_name, version):
        self.rootUri = "ROOT_CIMV2"
        self.resourceUri = None
        baseUri = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2"

        if wmi_name.startswith("Msvm_"):
            baseUri = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/virtualization"
            self.rootUri = "ROOT_VIRTUALIZATION"

            if version == "v2":
                baseUri += "/v2"
                self.rootUri = "ROOT_VIRTUALIZATION_V2"

        self.resourceUri = "%s/%s" % (baseUri, wmi_name)



class WmiClassVersion:
    """Represents specific version of WMI class."""

    def __init__(self, name, version, properties, uri_info):
        self.name = name
        self.version = version
        self.properties = properties
        self.uri_info = uri_info



class Property:
    typemap = {"boolean"  : "BOOL",
               "string"   : "STR",
               "datetime" : "STR",
               "int8"     : "INT8",
               "sint8"    : "INT8",
               "int16"    : "INT16",
               "sint16"   : "INT16",
               "int32"    : "INT32",
               "sint32"   : "INT32",
               "int64"    : "INT64",
               "sint64"   : "INT64",
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


    def generate_typemap(self):
        return '    { "%s", "%s", %s },\n' % (self.name, self.type.lower(), str(self.is_array).lower())



def open_and_print(filename):
    if filename.startswith("./"):
        print "  GEN      " + filename[2:]
    else:
        print "  GEN      " + filename

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
    version = None
    wmi_name = name
    ns_separator = name.find(wmi_version_separator)

    if ns_separator != -1:
        version = name[:ns_separator]
        wmi_name = name[ns_separator + 1:]
        name = "%s_%s" % (wmi_name, version)

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

    cls = WmiClassVersion(name=name, version=version, properties=properties,
                          uri_info=ClassUriInfo(wmi_name, version))

    if wmi_name in wmi_classes_by_name:
        wmi_classes_by_name[wmi_name].versions.append(cls)
    else:
        wmi_classes_by_name[wmi_name] = WmiClass(wmi_name, [cls])



def main():
    if "srcdir" in os.environ:
        input_filename = os.path.join(os.environ["srcdir"], "hyperv/hyperv_wmi_generator.input")
        output_dirname = os.path.join(os.environ["srcdir"], "hyperv")
    else:
        input_filename = os.path.join(os.getcwd(), "hyperv_wmi_generator.input")
        output_dirname = os.getcwd()

    classes_typedef = open_and_print(os.path.join(output_dirname, "hyperv_wmi_classes.generated.typedef"))
    classes_header = open_and_print(os.path.join(output_dirname, "hyperv_wmi_classes.generated.h"))
    classes_source = open_and_print(os.path.join(output_dirname, "hyperv_wmi_classes.generated.c"))

    # parse input file
    number = 0
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
                    parse_class(block)

                block = None
            else:
                block.append((number, line))

    # write output files
    notice = "/* Generated by hyperv_wmi_generator.py */\n\n\n\n"

    classes_typedef.write(notice)
    classes_header.write(notice)
    classes_source.write(notice)

    names = wmi_classes_by_name.keys()
    names.sort()

    for name in names:
        cls = wmi_classes_by_name[name]
        cls.prepare()

        classes_typedef.write(cls.generate_classes_typedef())
        classes_header.write(cls.generate_classes_header())
        classes_source.write(cls.generate_classes_source())



if __name__ == "__main__":
    main()
