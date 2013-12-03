#!/usr/bin/env python

#
# esx_vi_generator.py: generates most of the SOAP type mapping code
#
# Copyright (C) 2010-2012 Matthias Bolte <matthias.bolte@googlemail.com>
# Copyright (C) 2013 Ata E Husain Bohra <ata.husain@hotmail.com>
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



OCCURRENCE__REQUIRED_ITEM = "r"
OCCURRENCE__REQUIRED_LIST = "rl"
OCCURRENCE__OPTIONAL_ITEM = "o"
OCCURRENCE__OPTIONAL_LIST = "ol"
OCCURRENCE__IGNORED = "i"

valid_occurrences = [OCCURRENCE__REQUIRED_ITEM,
                     OCCURRENCE__REQUIRED_LIST,
                     OCCURRENCE__OPTIONAL_ITEM,
                     OCCURRENCE__OPTIONAL_LIST,
                     OCCURRENCE__IGNORED]

autobind_names = set()

separator = "/* " + ("* " * 37) + "*\n"



def aligned(left, right, length=59):
    while len(left) < length:
        left += " "

    return left + right



class Member:
    def __init__(self, type, occurrence):
        self.type = type
        self.occurrence = occurrence


    def is_enum(self):
        return self.type in predefined_enums or self.type in enums_by_name


    def is_object(self):
        return self.type in predefined_objects or self.type in objects_by_name


    def is_type_generated(self):
        return self.type in enums_by_name or self.type in objects_by_name


    def get_occurrence_comment(self):
        if self.occurrence == OCCURRENCE__REQUIRED_ITEM:
            return "/* required */"
        elif self.occurrence == OCCURRENCE__REQUIRED_LIST:
            return "/* required, list */"
        elif self.occurrence == OCCURRENCE__OPTIONAL_ITEM:
            return "/* optional */"
        elif self.occurrence == OCCURRENCE__OPTIONAL_LIST:
            return "/* optional, list */"

        raise ValueError("unknown occurrence value '%s'" % self.occurrence)



class Parameter(Member):
    def __init__(self, type, name, occurrence):
        Member.__init__(self, type, occurrence)

        if ':' in name and name.startswith("_this"):
            self.name, self.autobind_name = name.split(":")
        else:
            self.name = name
            self.autobind_name = None


    def generate_parameter(self, is_last=False, is_header=True, offset=0):
        if self.occurrence == OCCURRENCE__IGNORED:
            raise ValueError("invalid function parameter occurrence value '%s'"
                             % self.occurrence)
        elif self.autobind_name is not None:
            return ""
        else:
            string = "       "
            string += " " * offset
            string += "%s%s" % (self.get_type_string(), self.name)

            if is_last:
                if is_header:
                    string += "); "
                else:
                    string += "), "
            else:
                string += ", "

            return aligned(string, self.get_occurrence_comment() + "\n")


    def generate_return(self, offset = 0, end_of_line = ";"):
        if self.occurrence == OCCURRENCE__IGNORED:
            raise ValueError("invalid function parameter occurrence value '%s'"
                             % self.occurrence)
        else:
            string = "       "
            string += " " * offset
            string += "%s%s)%s" \
                      % (self.get_type_string(True), self.name, end_of_line)

            return aligned(string, self.get_occurrence_comment() + "\n")


    def generate_require_code(self):
        if self.occurrence in [OCCURRENCE__REQUIRED_ITEM,
                               OCCURRENCE__REQUIRED_LIST]:
            return "    ESX_VI__METHOD__PARAMETER__REQUIRE(%s)\n" % self.name
        else:
            return ""


    def generate_serialize_code(self):
        if self.occurrence in [OCCURRENCE__REQUIRED_LIST,
                               OCCURRENCE__OPTIONAL_LIST]:
            return "    ESX_VI__METHOD__PARAMETER__SERIALIZE_LIST(%s, %s)\n" \
                   % (self.type, self.name)
        elif self.type == "String":
            return "    ESX_VI__METHOD__PARAMETER__SERIALIZE_VALUE(String, %s)\n" \
                   % self.name
        else:
            return "    ESX_VI__METHOD__PARAMETER__SERIALIZE(%s, %s)\n" \
                   % (self.type, self.name)


    def get_type_string(self, as_return_value=False):
        string = ""

        if self.type == "String" and \
           self.occurrence not in [OCCURRENCE__REQUIRED_LIST,
                                   OCCURRENCE__OPTIONAL_LIST]:
            if as_return_value:
                string += "char *"
            else:
                string += "const char *"
        elif self.is_enum():
            string += "esxVI_%s " % self.type
        else:
            string += "esxVI_%s *" % self.type

        if as_return_value:
            string += "*"

        return string


    def get_occurrence_short_enum(self):
        if self.occurrence == OCCURRENCE__REQUIRED_ITEM:
            return "RequiredItem"
        elif self.occurrence == OCCURRENCE__REQUIRED_LIST:
            return "RequiredList"
        elif self.occurrence == OCCURRENCE__OPTIONAL_ITEM:
            return "OptionalItem"
        elif self.occurrence == OCCURRENCE__OPTIONAL_LIST:
            return "OptionalList"

        raise ValueError("unknown occurrence value '%s'" % self.occurrence)



class Method:
    def __init__(self, name, parameters, returns):
        self.name = name
        self.parameters = []
        self.autobind_parameter = None
        self.returns = returns

        for parameter in parameters:
            if parameter.autobind_name is None:
                self.parameters.append(parameter)
            else:
                self.autobind_parameter = parameter


    def generate_header(self):
        header = "int esxVI_%s\n" % self.name
        header += "      (esxVI_Context *ctx"

        if len(self.parameters) > 0 or self.returns is not None:
            header += ",\n"

            for parameter in self.parameters[:-1]:
                header += parameter.generate_parameter()

            if self.returns is None:
                header += self.parameters[-1].generate_parameter(is_last=True)
            else:
                header += self.parameters[-1].generate_parameter()
                header += self.returns.generate_return()
        else:
            header += ");\n"

        header += "\n"

        return header


    def generate_source(self):
        source = "/* esxVI_%s */\n" % self.name
        source += "ESX_VI__METHOD(%s," % self.name

        if self.autobind_parameter is not None:
            autobind_names.add(self.autobind_parameter.autobind_name)
            source += " %s,\n" % self.autobind_parameter.autobind_name
        else:
            source += " /* explicit _this */,\n"

        source += "               (esxVI_Context *ctx"

        if len(self.parameters) > 0 or self.returns is not None:
            source += ",\n"

            for parameter in self.parameters[:-1]:
                source += parameter.generate_parameter(is_header=False,
                                                       offset=9)

            if self.returns is None:
                source += self.parameters[-1].generate_parameter(is_last=True,
                                                                 is_header=False,
                                                                 offset=9)
            else:
                source += self.parameters[-1].generate_parameter(is_header=False,
                                                                 offset=9)
                source += self.returns.generate_return(offset=9,
                                                       end_of_line=",")
        else:
            source += "),\n"

        if self.returns is None:
            source += "               void, /* nothing */, None,\n"
        elif self.returns.type == "String":
            source += "               String, Value, %s,\n" \
                      % self.returns.get_occurrence_short_enum()
        else:
            source += "               %s, /* nothing */, %s,\n" \
                      % (self.returns.type,
                         self.returns.get_occurrence_short_enum())

        source += "{\n"

        if self.autobind_parameter is not None:
            source += self.autobind_parameter.generate_require_code()

        for parameter in self.parameters:
            source += parameter.generate_require_code()

        source += "},\n"
        source += "{\n"

        if self.autobind_parameter is not None:
            source += self.autobind_parameter.generate_serialize_code()

        for parameter in self.parameters:
            source += parameter.generate_serialize_code()

        source += "})\n\n\n\n"

        return source



class Property(Member):
    def __init__(self, type, name, occurrence):
        Member.__init__(self, type, occurrence)

        self.name = name


    def generate_struct_member(self):
        if self.occurrence == OCCURRENCE__IGNORED:
            return "    /* FIXME: %s is currently ignored */\n" % self.name
        else:
            string = "    %s%s; " % (self.get_type_string(), self.name)

            return aligned(string, self.get_occurrence_comment() + "\n")


    def generate_free_code(self):
        if self.type == "String" and \
           self.occurrence not in [OCCURRENCE__REQUIRED_LIST,
                                   OCCURRENCE__OPTIONAL_LIST,
                                   OCCURRENCE__IGNORED]:
            return "    VIR_FREE(item->%s);\n" % self.name
        elif self.is_enum():
            return ""
        else:
            if self.occurrence == OCCURRENCE__IGNORED:
                return "    /* FIXME: %s is currently ignored */\n" % self.name
            else:
                return "    esxVI_%s_Free(&item->%s);\n" % (self.type, self.name)


    def generate_validate_code(self, managed=False):
        if managed:
            macro = "ESX_VI__TEMPLATE__PROPERTY__MANAGED_REQUIRE"
        else:
            macro = "ESX_VI__TEMPLATE__PROPERTY__REQUIRE"

        if self.occurrence in [OCCURRENCE__REQUIRED_ITEM,
                               OCCURRENCE__REQUIRED_LIST]:
            return "    %s(%s)\n" % (macro, self.name)
        elif self.occurrence == OCCURRENCE__IGNORED:
            return "    /* FIXME: %s is currently ignored */\n" % self.name
        else:
            return ""


    def generate_deep_copy_code(self):
        if self.occurrence == OCCURRENCE__IGNORED:
            return "    /* FIXME: %s is currently ignored */\n" % self.name
        elif self.occurrence in [OCCURRENCE__REQUIRED_LIST,
                                 OCCURRENCE__OPTIONAL_LIST]:
            return "    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_LIST(%s, %s)\n" \
                   % (self.type, self.name)
        elif self.type == "String":
            return "    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_VALUE(String, %s)\n" \
                   % self.name
        elif self.is_enum():
            return "    (*dest)->%s = src->%s;\n" % (self.name, self.name)
        else:
            return "    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY(%s, %s)\n" \
                   % (self.type, self.name)


    def generate_serialize_code(self):
        if self.occurrence == OCCURRENCE__IGNORED:
            return "    /* FIXME: %s is currently ignored */\n" % self.name
        elif self.occurrence in [OCCURRENCE__REQUIRED_LIST,
                                 OCCURRENCE__OPTIONAL_LIST]:
            return "    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(%s, %s)\n" \
                   % (self.type, self.name)
        elif self.type == "String":
            return "    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, %s)\n" \
                   % self.name
        else:
            return "    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(%s, %s)\n" \
                   % (self.type, self.name)


    def generate_deserialize_code(self):
        if self.occurrence == OCCURRENCE__IGNORED:
            return "    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_IGNORE(%s) /* FIXME */\n" \
                   % self.name
        elif self.occurrence in [OCCURRENCE__REQUIRED_LIST,
                                 OCCURRENCE__OPTIONAL_LIST]:
            return "    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(%s, %s)\n" \
                   % (self.type, self.name)
        elif self.type == "String":
            return "    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, %s)\n" \
                   % self.name
        else:
            return "    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(%s, %s)\n" \
                   % (self.type, self.name)


    def generate_lookup_code(self):
        if self.occurrence == OCCURRENCE__IGNORED:
            return "    ESX_VI__TEMPLATE__PROPERTY__CAST_FROM_ANY_TYPE_IGNORE(%s) /* FIXME */\n" \
                   % self.name
        elif self.occurrence in [OCCURRENCE__REQUIRED_LIST,
                                 OCCURRENCE__OPTIONAL_LIST]:
            return "    ESX_VI__TEMPLATE__PROPERTY__CAST_LIST_FROM_ANY_TYPE(%s, %s)\n" \
                   % (self.type, self.name)
        elif self.type == "String":
            return "    ESX_VI__TEMPLATE__PROPERTY__CAST_VALUE_FROM_ANY_TYPE(String, %s)\n" \
                   % self.name
        else:
            return "    ESX_VI__TEMPLATE__PROPERTY__CAST_FROM_ANY_TYPE(%s, %s)\n" \
                   % (self.type, self.name)


    def get_type_string(self):
        if self.type == "String" and \
           self.occurrence not in [OCCURRENCE__REQUIRED_LIST,
                                   OCCURRENCE__OPTIONAL_LIST]:
            return "char *"
        elif self.is_enum():
            return "esxVI_%s " % self.type
        else:
            return "esxVI_%s *" % self.type



class Type:
    def __init__(self, kind, name):
        self.kind = kind
        self.name = name


    def generate_typedef(self):
        return "typedef %s _esxVI_%s esxVI_%s;\n" \
               % (self.kind, self.name, self.name)


    def generate_typeenum(self):
        return "    esxVI_Type_%s,\n" % self.name


    def generate_typetostring(self):
        string = "          case esxVI_Type_%s:\n" % self.name
        string += "            return \"%s\";\n\n" % self.name

        return string


    def generate_typefromstring(self):
        string =  "           else if (STREQ(type, \"%s\")) {\n" % self.name
        string += "               return esxVI_Type_%s;\n" % self.name
        string += "           }\n"

        return string


class GenericObject(Type):
    FEATURE__DYNAMIC_CAST = (1 << 1)
    FEATURE__LIST         = (1 << 2)
    FEATURE__DEEP_COPY    = (1 << 3)
    FEATURE__ANY_TYPE     = (1 << 4)
    FEATURE__SERIALIZE    = (1 << 5)
    FEATURE__DESERIALIZE  = (1 << 6)


    def __init__(self, name, category, managed, generic_objects_by_name):
        Type.__init__(self, "struct", name)
        self.category = category
        self.managed = managed
        self.generic_objects_by_name = generic_objects_by_name


    def generate_comment(self):
        comment = separator
        comment += " * %s: %s\n" % (self.category, self.name)

        if self.extends is not None:
            comment += " * %s  extends %s\n" \
                       % (' ' * len(self.category), self.extends)

        first = True

        if self.extended_by is not None:
            for extended_by in self.extended_by:
                if first:
                    comment += " * %s  extended by %s\n" \
                               % (' ' * len(self.category), extended_by)
                    first = False
                else:
                    comment += " * %s              %s\n" \
                               % (' ' * len(self.category), extended_by)

        comment += " */\n\n"

        return comment


    def generate_struct_members(self, add_banner=False, struct_gap=False):
        members = ""

        if struct_gap:
            members += "\n"

        if self.extends is not None:
            members += self.generic_objects_by_name[self.extends] \
                       .generate_struct_members(add_banner=True,
                                                struct_gap=False) + "\n"

        if self.extends is not None or add_banner:
            members += "    /* %s */\n" % self.name

        for property in self.properties:
            members += property.generate_struct_member()

        if len(self.properties) < 1:
            members += "    /* no properties */\n"

        return members


    def generate_dispatch(self, suffix, is_first=True):
        source = ""

        if self.extended_by is not None:
            if not is_first:
                source += "\n"

            source += "    /* %s */\n" % self.name

            for extended_by in self.extended_by:
                source += "    ESX_VI__TEMPLATE__DISPATCH__%s(%s)\n" \
                          % (suffix, extended_by)

            for extended_by in self.extended_by:
                source += self.generic_objects_by_name[extended_by] \
                          .generate_dispatch(suffix, False)

        return source


    def generate_free_code(self, add_banner=False):
        source = ""

        if self.extends is not None:
            source += self.generic_objects_by_name[self.extends] \
                      .generate_free_code(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            string = ""

            for property in self.properties:
                string += property.generate_free_code()

            if len(string) < 1:
                source += "    /* no properties to be freed */\n"
            else:
                source += string

        return source


    def generate_validate_code(self, add_banner=False):
        source = ""

        if self.extends is not None:
            source += self.generic_objects_by_name[self.extends] \
                      .generate_validate_code(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            string = ""

            for property in self.properties:
                string += property.generate_validate_code(self.managed)

            if len(string) < 1:
                source += "    /* no required properties */\n"
            else:
                source += string

        return source



class Object(GenericObject):
    def __init__(self, name, extends, properties, features=0, extended_by=None):
        GenericObject.__init__(self, name, 'VI Object', False, objects_by_name)
        self.extends = extends
        self.features = features
        self.properties = properties
        self.extended_by = extended_by
        self.candidate_for_dynamic_cast = False

        if self.extended_by is not None:
            self.extended_by.sort()


    def generate_dynamic_cast_code(self, is_first=True):
        source = ""

        if self.extended_by is not None:
            if not is_first:
                source += "\n"

            source += "    /* %s */\n" % self.name

            for extended_by in self.extended_by:
                source += "    ESX_VI__TEMPLATE__DYNAMIC_CAST__ACCEPT(%s)\n" \
                          % extended_by

            for extended_by in self.extended_by:
                source += objects_by_name[extended_by] \
                          .generate_dynamic_cast_code(False)

        return source


    def generate_deep_copy_code(self, add_banner = False):
        source = ""

        if self.extends is not None:
            source += objects_by_name[self.extends] \
                      .generate_deep_copy_code(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            string = ""

            for property in self.properties:
                string += property.generate_deep_copy_code()

            if len(string) < 1:
                source += "    /* no properties to be deep copied */\n"
            else:
                source += string

        return source


    def generate_serialize_code(self, add_banner=False):
        source = ""

        if self.extends is not None:
            source += objects_by_name[self.extends] \
                      .generate_serialize_code(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            for property in self.properties:
                source += property.generate_serialize_code()

        return source


    def generate_deserialize_code(self, add_banner=False):
        source = ""

        if self.extends is not None:
            source += objects_by_name[self.extends] \
                      .generate_deserialize_code(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            for property in self.properties:
                source += property.generate_deserialize_code()

        return source


    def generate_header(self):
        header = self.generate_comment()

        # struct
        header += "struct _esxVI_%s {\n" % self.name

        if self.features & Object.FEATURE__LIST:
            header += aligned("    esxVI_%s *_next; " % self.name,
                              "/* optional */\n")
        else:
            header += aligned("    esxVI_%s *_unused; " % self.name,
                              "/* optional */\n")

        header += aligned("    esxVI_Type _type; ", "/* required */\n")
        header += self.generate_struct_members(struct_gap=True)
        header += "};\n\n"

        # functions
        header += "int esxVI_%s_Alloc(esxVI_%s **item);\n" \
                  % (self.name, self.name)
        header += "void esxVI_%s_Free(esxVI_%s **item);\n" \
                  % (self.name, self.name)
        header += "int esxVI_%s_Validate(esxVI_%s *item);\n" \
                  % (self.name, self.name)

        if self.features & Object.FEATURE__DYNAMIC_CAST:
            if self.extended_by is not None or self.extends is not None:
                header += "esxVI_%s *esxVI_%s_DynamicCast(void *item);\n" \
                          % (self.name, self.name)
            else:
                report_error("cannot add dynamic cast support for an untyped object")

        if self.features & Object.FEATURE__LIST:
            header += "int esxVI_%s_AppendToList(esxVI_%s **list, esxVI_%s *item);\n" \
                      % (self.name, self.name, self.name)

        if self.features & Object.FEATURE__DEEP_COPY:
            header += "int esxVI_%s_DeepCopy(esxVI_%s **dst, esxVI_%s *src);\n" \
                      % (self.name, self.name, self.name)

            if self.features & Object.FEATURE__LIST:
                header += ("int esxVI_%s_DeepCopyList(esxVI_%s **dstList, "
                                                     "esxVI_%s *srcList);\n") \
                          % (self.name, self.name, self.name)

        if self.features & Object.FEATURE__ANY_TYPE:
            header += ("int esxVI_%s_CastFromAnyType(esxVI_AnyType *anyType, "
                                                    "esxVI_%s **item);\n") \
                      % (self.name, self.name)

            if self.features & Object.FEATURE__LIST:
                header += ("int esxVI_%s_CastListFromAnyType(esxVI_AnyType *anyType, "
                                                            "esxVI_%s **list);\n") \
                          % (self.name, self.name)

        if self.features & Object.FEATURE__SERIALIZE:
            header += ("int esxVI_%s_Serialize(esxVI_%s *item, "
                                              "const char *element, "
                                              "virBufferPtr output);\n") \
                      % (self.name, self.name)

            if self.features & Object.FEATURE__LIST:
                header += ("int esxVI_%s_SerializeList(esxVI_%s *list, "
                                                      "const char *element, "
                                                      "virBufferPtr output);\n") \
                          % (self.name, self.name)

        if self.features & Object.FEATURE__DESERIALIZE:
            header += "int esxVI_%s_Deserialize(xmlNodePtr node, esxVI_%s **item);\n" \
                      % (self.name, self.name)

            if self.features & Object.FEATURE__LIST:
                header += ("int esxVI_%s_DeserializeList(xmlNodePtr node, "
                                                        "esxVI_%s **list);\n") \
                          % (self.name, self.name)

        header += "\n\n\n"

        return header


    def generate_source(self):
        source = separator
        source += " * VI Object: %s\n" % self.name

        if self.extends is not None:
            source += " *            extends %s\n" % self.extends

        first = True

        if self.extended_by is not None:
            for extended_by in self.extended_by:
                if first:
                    source += " *            extended by %s\n" % extended_by
                    first = False
                else:
                    source += " *                        %s\n" % extended_by

        source += " */\n\n"

        # functions
        source += "/* esxVI_%s_Alloc */\n" % self.name
        source += "ESX_VI__TEMPLATE__ALLOC(%s)\n\n" % self.name

        # free
        source += "/* esxVI_%s_Free */\n" % self.name

        if self.extended_by is None:
            source += "ESX_VI__TEMPLATE__FREE(%s,\n" % self.name
        else:
            source += "ESX_VI__TEMPLATE__DYNAMIC_FREE(%s,\n" % self.name
            source += "{\n"
            source += self.generate_dispatch('FREE')
            source += "},\n"

        source += "{\n"

        if self.features & Object.FEATURE__LIST:
            if self.extends is not None:
                # avoid "dereferencing type-punned pointer will break
                # strict-aliasing rules" warnings
                source += "    esxVI_%s *next = (esxVI_%s *)item->_next;\n\n" \
                          % (self.extends, self.extends)
                source += "    esxVI_%s_Free(&next);\n" % self.extends
                source += "    item->_next = (esxVI_%s *)next;\n\n" % self.name
            else:
                source += "    esxVI_%s_Free(&item->_next);\n\n" % self.name

        source += self.generate_free_code()
        source += "})\n\n"

        # validate
        source += "/* esxVI_%s_Validate */\n" % self.name
        source += "ESX_VI__TEMPLATE__VALIDATE(%s,\n" % self.name
        source += "{\n"
        source += self.generate_validate_code()
        source += "})\n\n"

        # dynamic cast
        if self.features & Object.FEATURE__DYNAMIC_CAST:
            if self.extended_by is not None or self.extends is not None:
                source += "/* esxVI_%s_DynamicCast */\n" % self.name
                source += "ESX_VI__TEMPLATE__DYNAMIC_CAST(%s,\n" % self.name
                source += "{\n"
                source += self.generate_dynamic_cast_code()
                source += "})\n\n"
            else:
                report_error("cannot add dynamic cast support for an untyped object")

        # append to list
        if self.features & Object.FEATURE__LIST:
            source += "/* esxVI_%s_AppendToList */\n" % self.name
            source += "ESX_VI__TEMPLATE__LIST__APPEND(%s)\n\n" % self.name

        # deep copy
        if self.features & Object.FEATURE__DEEP_COPY:
            source += "/* esxVI_%s_DeepCopy */\n" % self.name

            if self.extended_by is None:
                source += "ESX_VI__TEMPLATE__DEEP_COPY(%s,\n" % self.name
            else:
                source += "ESX_VI__TEMPLATE__DYNAMIC_DEEP_COPY(%s,\n" % self.name
                source += "{\n"
                source += self.generate_dispatch('DEEP_COPY')
                source += "},\n"

            source += "{\n"
            source += self.generate_deep_copy_code()
            source += "})\n\n"

            if self.features & Object.FEATURE__LIST:
                source += "/* esxVI_%s_DeepCopyList */\n" % self.name
                source += "ESX_VI__TEMPLATE__LIST__DEEP_COPY(%s)\n\n" \
                          % self.name

        # cast from any type
        if self.features & Object.FEATURE__ANY_TYPE:
            source += "/* esxVI_%s_CastFromAnyType */\n" % self.name

            if self.extended_by is None:
                source += "ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(%s)\n\n" \
                          % self.name
            else:
                source += "ESX_VI__TEMPLATE__DYNAMIC_CAST_FROM_ANY_TYPE(%s,\n" \
                          % self.name
                source += "{\n"
                source += self.generate_dispatch('CAST_FROM_ANY_TYPE')
                source += "})\n\n"

            if self.features & Object.FEATURE__LIST:
                source += "/* esxVI_%s_CastListFromAnyType */\n" % self.name
                source += "ESX_VI__TEMPLATE__LIST__CAST_FROM_ANY_TYPE(%s)\n\n" \
                          % self.name

        # serialize
        if self.features & Object.FEATURE__SERIALIZE:
            source += "/* esxVI_%s_Serialize */\n" % self.name

            if self.extended_by is None:
                source += "ESX_VI__TEMPLATE__SERIALIZE(%s,\n" % self.name
            else:
                source += "ESX_VI__TEMPLATE__DYNAMIC_SERIALIZE(%s,\n" % self.name
                source += "{\n"
                source += self.generate_dispatch('SERIALIZE')
                source += "},\n"

            source += "{\n"
            source += self.generate_serialize_code()
            source += "})\n\n"

            if self.features & Object.FEATURE__LIST:
                source += "/* esxVI_%s_SerializeList */\n" % self.name
                source += "ESX_VI__TEMPLATE__LIST__SERIALIZE(%s)\n\n" \
                          % self.name

        # deserialize
        if self.features & Object.FEATURE__DESERIALIZE:
            source += "/* esxVI_%s_Deserialize */\n" % self.name

            if self.extended_by is None:
                source += "ESX_VI__TEMPLATE__DESERIALIZE(%s,\n" % self.name
            else:
                source += "ESX_VI__TEMPLATE__DYNAMIC_DESERIALIZE(%s,\n" \
                          % self.name
                source += "{\n"
                source += self.generate_dispatch('DESERIALIZE')
                source += "},\n"

            source += "{\n"
            source += self.generate_deserialize_code()
            source += "})\n\n"

            if self.features & Object.FEATURE__LIST:
                source += "/* esxVI_%s_DeserializeList */\n" % self.name
                source += "ESX_VI__TEMPLATE__LIST__DESERIALIZE(%s)\n\n" \
                          % self.name

        source += "\n\n"

        return source



class ManagedObject(GenericObject):
    def __init__(self, name, extends, properties, features=0, extended_by=None):
        GenericObject.__init__(self, name, 'VI Managed Object', True,
                               managed_objects_by_name)
        self.extends = extends
        self.features = features
        self.properties = properties
        self.extended_by = extended_by

        if self.extended_by is not None:
            self.extended_by.sort()


    def generate_lookup_code1(self, add_banner=False):
        source = ""

        if self.extends is not None:
            source += managed_objects_by_name[self.extends] \
                      .generate_lookup_code1(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            string = ""

            for property in self.properties:
                string += "    \"%s\\0\"\n" % property.name

            if len(string) < 1:
                source += "    /* no properties */\n"
            else:
                source += string

        return source


    def generate_lookup_code2(self, add_banner=False):
        source = ""

        if self.extends is not None:
            source += managed_objects_by_name[self.extends] \
                      .generate_lookup_code2(add_banner=True) + "\n"

        if self.extends is not None or add_banner:
            source += "    /* %s */\n" % self.name

        if len(self.properties) < 1:
            source += "    /* no properties */\n"
        else:
            string = ""

            for property in self.properties:
                string += property.generate_lookup_code()

            if len(string) < 1:
                source += "    /* no properties */\n"
            else:
                source += string

        return source


    def generate_header(self):
        header = self.generate_comment()

        # struct
        header += "struct _esxVI_%s {\n" % self.name

        if self.features & Object.FEATURE__LIST:
            header += aligned("    esxVI_%s *_next; " % self.name,
                              "/* optional */\n")
        else:
            header += aligned("    esxVI_%s *_unused; " % self.name,
                              "/* optional */\n")

        header += aligned("    esxVI_Type _type; ", "/* required */\n")
        header += aligned("    esxVI_ManagedObjectReference *_reference; ",
                          "/* required */\n")
        header += "\n"
        header += self.generate_struct_members()
        header += "};\n\n"

        # functions
        header += "int esxVI_%s_Alloc(esxVI_%s **item);\n" % (self.name, self.name)
        header += "void esxVI_%s_Free(esxVI_%s **item);\n" % (self.name, self.name)
        header += ("int esxVI_%s_Validate(esxVI_%s *item, "
                                         "esxVI_String *selectedPropertyNameList);\n") \
                  % (self.name, self.name)

        if self.features & Object.FEATURE__LIST:
            header += "int esxVI_%s_AppendToList(esxVI_%s **list, esxVI_%s *item);\n" \
                      % (self.name, self.name, self.name)

        header += "\n\n\n"

        return header


    def generate_helper_header(self):
        header = ""

        # functions
        header += ("int esxVI_Lookup%s(esxVI_Context *ctx, "
                                      "const char *name, "
                                      "esxVI_ManagedObjectReference *root, "
                                      "esxVI_String *selectedPropertyNameList, "
                                      "esxVI_%s **item, "
                                      "esxVI_Occurrence occurrence);\n") \
                  % (self.name, self.name)

        header += "\n"

        return header


    def generate_source(self):
        source = self.generate_comment()

        # functions
        source += "/* esxVI_%s_Alloc */\n" % self.name
        source += "ESX_VI__TEMPLATE__ALLOC(%s)\n\n" % self.name

        # free
        source += "/* esxVI_%s_Free */\n" % self.name

        if self.extended_by is None:
            source += "ESX_VI__TEMPLATE__FREE(%s,\n" % self.name
        else:
            source += "ESX_VI__TEMPLATE__DYNAMIC_FREE(%s,\n" % self.name
            source += "{\n"
            source += self.generate_dispatch('FREE')
            source += "},\n"

        source += "{\n"

        if self.features & ManagedObject.FEATURE__LIST:
            if self.extends is not None:
                # avoid "dereferencing type-punned pointer will break
                # strict-aliasing rules" warnings
                source += "    esxVI_%s *next = (esxVI_%s *)item->_next;\n\n" \
                          % (self.extends, self.extends)
                source += "    esxVI_%s_Free(&next);\n" % self.extends
                source += "    item->_next = (esxVI_%s *)next;\n\n" % self.name
            else:
                source += "    esxVI_%s_Free(&item->_next);\n" % self.name

        source += "    esxVI_ManagedObjectReference_Free(&item->_reference);\n\n"
        source += self.generate_free_code()
        source += "})\n\n"

        # validate
        source += "/* esxVI_%s_Validate */\n" % self.name
        source += "ESX_VI__TEMPLATE__MANAGED_VALIDATE(%s,\n" % self.name
        source += "{\n"

        source += self.generate_validate_code()

        source += "})\n\n"

        # append to list
        if self.features & ManagedObject.FEATURE__LIST:
            source += "/* esxVI_%s_AppendToList */\n" % self.name
            source += "ESX_VI__TEMPLATE__LIST__APPEND(%s)\n\n" % self.name

        source += "\n\n"

        return source


    def generate_helper_source(self):
        source = ""

        # lookup
        source += "/* esxVI_Lookup%s */\n" % self.name
        source += "ESX_VI__TEMPLATE__LOOKUP(%s,\n" % self.name
        source += "{\n"

        source += self.generate_lookup_code1()

        source += "},\n"
        source += "{\n"

        source += self.generate_lookup_code2()

        source += "})\n\n"

        source += "\n\n"

        return source



class Enum(Type):
    FEATURE__ANY_TYPE = (1 << 1)
    FEATURE__SERIALIZE = (1 << 2)
    FEATURE__DESERIALIZE = (1 << 3)


    def __init__(self, name, values, features=0):
        Type.__init__(self, "enum", name)
        self.values = values
        self.features = features


    def generate_header(self):
        header = separator
        header += " * VI Enum: %s\n" % self.name
        header += " */\n\n"
        header += "enum _esxVI_%s {\n" % self.name
        header += "    esxVI_%s_Undefined = 0,\n" % self.name

        for value in self.values:
            header += "    esxVI_%s_%s,\n" % (self.name, capitalize_first(value))

        header += "};\n\n"

        # functions
        if self.features & Enum.FEATURE__ANY_TYPE:
            header += ("int esxVI_%s_CastFromAnyType(esxVI_AnyType *anyType, "
                                                    "esxVI_%s *item);\n") \
                      % (self.name, self.name)

        if self.features & Enum.FEATURE__SERIALIZE:
            header += ("int esxVI_%s_Serialize(esxVI_%s item, const char *element, "
                                              "virBufferPtr output);\n") \
                      % (self.name, self.name)

        if self.features & Enum.FEATURE__DESERIALIZE:
            header += ("int esxVI_%s_Deserialize(xmlNodePtr node, "
                                                "esxVI_%s *item);\n") \
                      % (self.name, self.name)

        header += "\n\n\n"

        return header


    def generate_source(self):
        source = separator
        source += " * VI Enum: %s\n" % self.name
        source += " */\n\n"
        source += "static const esxVI_Enumeration _esxVI_%s_Enumeration = {\n" \
                  % self.name
        source += "    esxVI_Type_%s, {\n" % self.name

        for value in self.values:
            source += "        { \"%s\", esxVI_%s_%s },\n" \
                      % (value, self.name, capitalize_first(value))

        source += "        { NULL, -1 },\n"
        source += "    },\n"
        source += "};\n\n"

        # functions
        if self.features & Enum.FEATURE__ANY_TYPE:
            source += "/* esxVI_%s_CastFromAnyType */\n" % self.name
            source += "ESX_VI__TEMPLATE__ENUMERATION__CAST_FROM_ANY_TYPE(%s)\n\n" \
                      % self.name

        if self.features & Enum.FEATURE__SERIALIZE:
            source += "/* esxVI_%s_Serialize */\n" % self.name
            source += "ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(%s)\n\n" \
                      % self.name

        if self.features & Enum.FEATURE__DESERIALIZE:
            source += "/* esxVI_%s_Deserialize */\n" % self.name
            source += "ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(%s)\n\n" \
                      % self.name

        source += "\n\n"

        return source



def report_error(message):
    print "error: " + message
    sys.exit(1)



def capitalize_first(string):
    return string[:1].upper() + string[1:]



def parse_object(block):
    # expected format: [managed] object <name> [extends <name>]
    header_items = block[0][1].split()
    managed = False

    if header_items[0] == "managed":
        managed = True
        del header_items[0]

    if len(header_items) < 2:
        report_error("line %d: invalid block header" % (number))

    assert header_items[0] == "object"

    name = header_items[1]
    extends = None

    if len(header_items) > 2:
        if header_items[2] != "extends":
            report_error("line %d: invalid block header" % (number))
        else:
            extends = header_items[3]

    properties = []

    for line in block[1:]:
        # expected format: <type> <name> <occurrence>
        items = line[1].split()

        if len(items) != 3:
            report_error("line %d: invalid property" % line[0])

        if items[2] not in valid_occurrences:
            report_error("line %d: invalid occurrence" % line[0])

        properties.append(Property(type=items[0], name=items[1],
                                   occurrence=items[2]))

    if managed:
        return ManagedObject(name=name, extends=extends, properties=properties)
    else:
        return Object(name=name, extends=extends, properties=properties)



def parse_enum(block):
    # expected format: enum <name>
    header_items = block[0][1].split()

    if len(header_items) < 2:
        report_error("line %d: invalid block header" % (number))

    assert header_items[0] == "enum"

    name = header_items[1]

    values = []

    for line in block[1:]:
        # expected format: <value>
        values.append(line[1])

    return Enum(name=name, values=values)



def parse_method(block):
    # expected format: method <name> [returns <type> <occurrence>]
    header_items = block[0][1].split()

    if len(header_items) < 2:
        report_error("line %d: invalid block header" % (number))

    assert header_items[0] == "method"

    name = header_items[1]
    returns = None

    if len(header_items) > 2:
        if header_items[2] != "returns":
            report_error("line %d: invalid block header" % (number))
        else:
            returns = Parameter(type=header_items[3], name="output",
                                occurrence=header_items[4])

    parameters = []

    for line in block[1:]:
        # expected format: <type> <name> <occurrence>
        items = line[1].split()

        if len(items) != 3:
            report_error("line %d: invalid property" % line[0])

        if items[2] not in valid_occurrences:
            report_error("line %d: invalid occurrence" % line[0])

        parameters.append(Parameter(type=items[0], name=items[1],
                                    occurrence=items[2]))

    return Method(name=name, parameters=parameters, returns=returns)



def is_known_type(type):
    return type in predefined_objects or \
           type in predefined_enums or \
           type in objects_by_name or \
           type in managed_objects_by_name or \
           type in enums_by_name



def open_and_print(filename):
    if filename.startswith("./"):
        print "  GEN      " + filename[2:]
    else:
        print "  GEN      " + filename

    return open(filename, "wb")



predefined_enums = ["Boolean"]

predefined_objects = ["AnyType",
                      "Byte",
                      "Int",
                      "Long",
                      "String",
                      "DateTime",
                      "MethodFault",
                      "ManagedObjectReference"]

additional_enum_features = { "ManagedEntityStatus"      : Enum.FEATURE__ANY_TYPE,
                             "TaskInfoState"            : Enum.FEATURE__ANY_TYPE,
                             "VirtualMachinePowerState" : Enum.FEATURE__ANY_TYPE }

additional_object_features = { "AutoStartDefaults"          : Object.FEATURE__ANY_TYPE,
                               "AutoStartPowerInfo"         : Object.FEATURE__ANY_TYPE,
                               "DatastoreHostMount"         : Object.FEATURE__DEEP_COPY |
                                                              Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "DatastoreInfo"              : Object.FEATURE__ANY_TYPE |
                                                              Object.FEATURE__DYNAMIC_CAST,
                               "HostConfigManager"          : Object.FEATURE__ANY_TYPE,
                               "HostCpuIdInfo"              : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "HostDatastoreBrowserSearchResults" : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "HostHostBusAdapter"         : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "HostInternetScsiHba"        : Object.FEATURE__DYNAMIC_CAST |
                                                              Object.FEATURE__DEEP_COPY,
                               "HostInternetScsiTargetTransport"  : Object.FEATURE__DYNAMIC_CAST,
                               "HostScsiDisk"               : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE |
                                                              Object.FEATURE__DYNAMIC_CAST,
                               "HostScsiTopologyInterface"  : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "HostScsiTopologyLun"        : Object.FEATURE__ANY_TYPE |
                                                              Object.FEATURE__LIST |
                                                              Object.FEATURE__DEEP_COPY,
                               "HostScsiTopologyTarget"     : Object.FEATURE__ANY_TYPE |
                                                              Object.FEATURE__LIST,
                               "HostPortGroup"              : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "HostVirtualSwitch"          : Object.FEATURE__DEEP_COPY |
                                                              Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "ManagedObjectReference"     : Object.FEATURE__ANY_TYPE,
                               "ObjectContent"              : Object.FEATURE__DEEP_COPY,
                               "PhysicalNic"                : Object.FEATURE__DEEP_COPY |
                                                              Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "ResourcePoolResourceUsage"  : Object.FEATURE__ANY_TYPE,
                               "ScsiLun"                    : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE |
                                                              Object.FEATURE__DEEP_COPY,
                               "ScsiLunDurableName"         : Object.FEATURE__LIST,
                               "ServiceContent"             : Object.FEATURE__DESERIALIZE,
                               "SharesInfo"                 : Object.FEATURE__ANY_TYPE,
                               "TaskInfo"                   : Object.FEATURE__LIST |
                                                              Object.FEATURE__ANY_TYPE,
                               "UserSession"                : Object.FEATURE__ANY_TYPE,
                               "VirtualMachineQuestionInfo" : Object.FEATURE__ANY_TYPE,
                               "VirtualMachineSnapshotTree" : Object.FEATURE__DEEP_COPY |
                                                              Object.FEATURE__ANY_TYPE,
                               "VmEventArgument"            : Object.FEATURE__DESERIALIZE }

removed_object_features = {}



if "srcdir" in os.environ:
    input_filename = os.path.join(os.environ["srcdir"], "esx/esx_vi_generator.input")
    output_dirname = os.path.join(os.environ["srcdir"], "esx")
else:
    input_filename = os.path.join(os.getcwd(), "esx_vi_generator.input")
    output_dirname = os.getcwd()



types_typedef = open_and_print(os.path.join(output_dirname, "esx_vi_types.generated.typedef"))
types_typeenum = open_and_print(os.path.join(output_dirname, "esx_vi_types.generated.typeenum"))
types_typetostring = open_and_print(os.path.join(output_dirname, "esx_vi_types.generated.typetostring"))
types_typefromstring = open_and_print(os.path.join(output_dirname, "esx_vi_types.generated.typefromstring"))
types_header = open_and_print(os.path.join(output_dirname, "esx_vi_types.generated.h"))
types_source = open_and_print(os.path.join(output_dirname, "esx_vi_types.generated.c"))
methods_header = open_and_print(os.path.join(output_dirname, "esx_vi_methods.generated.h"))
methods_source = open_and_print(os.path.join(output_dirname, "esx_vi_methods.generated.c"))
methods_macro = open_and_print(os.path.join(output_dirname, "esx_vi_methods.generated.macro"))
helpers_header = open_and_print(os.path.join(output_dirname, "esx_vi.generated.h"))
helpers_source = open_and_print(os.path.join(output_dirname, "esx_vi.generated.c"))



number = 0
objects_by_name = {}
managed_objects_by_name = {}
enums_by_name = {}
methods_by_name = {}
block = None



# parse input file
for line in file(input_filename, "rb").readlines():
    number += 1

    if "#" in line:
        line = line[:line.index("#")]

    line = line.lstrip().rstrip()

    if len(line) < 1:
        continue

    if line.startswith("object") or line.startswith("managed object") or \
       line.startswith("enum") or line.startswith("method"):
        if block is not None:
            report_error("line %d: nested block found" % (number))
        else:
            block = []

    if block is not None:
        if line == "end":
            if block[0][1].startswith("object"):
                obj = parse_object(block)
                objects_by_name[obj.name] = obj
            elif block[0][1].startswith("managed object"):
                obj = parse_object(block)
                managed_objects_by_name[obj.name] = obj
            elif block[0][1].startswith("enum"):
                enum = parse_enum(block)
                enums_by_name[enum.name] = enum
            else:
                method = parse_method(block)
                methods_by_name[method.name] = method

            block = None
        else:
            block.append((number, line))



for method in methods_by_name.values():
    # method parameter types must be serializable
    for parameter in method.parameters:
        if not parameter.is_type_generated():
            continue

        if parameter.is_enum():
            enums_by_name[parameter.type].features |= Enum.FEATURE__SERIALIZE
        else:
            objects_by_name[parameter.type].features |= Object.FEATURE__SERIALIZE
            objects_by_name[parameter.type].candidate_for_dynamic_cast = True

        # detect list usage
        if parameter.occurrence == OCCURRENCE__REQUIRED_LIST or \
           parameter.occurrence == OCCURRENCE__OPTIONAL_LIST:
            if parameter.is_enum():
                report_error("unsupported usage of enum '%s' as list in '%s'"
                             % (parameter.type, method.name))
            else:
                objects_by_name[parameter.type].features |= Object.FEATURE__LIST

    # method return types must be deserializable
    if method.returns and method.returns.is_type_generated():
        if method.returns.is_enum():
            enums_by_name[method.returns.type].features |= Enum.FEATURE__DESERIALIZE
        else:
            objects_by_name[method.returns.type].features |= Object.FEATURE__DESERIALIZE
            objects_by_name[method.returns.type].candidate_for_dynamic_cast = True

        # detect list usage
        if method.returns.occurrence == OCCURRENCE__REQUIRED_LIST or \
           method.returns.occurrence == OCCURRENCE__OPTIONAL_LIST:
            if method.returns.is_enum():
                report_error("unsupported usage of enum '%s' as list in '%s'"
                             % (method.returns.type, method.name))
            else:
                objects_by_name[method.returns.type].features |= Object.FEATURE__LIST



for enum in enums_by_name.values():
    # apply additional features
    if enum.name in additional_enum_features:
        enum.features |= additional_enum_features[enum.name]

        if additional_enum_features[enum.name] & Enum.FEATURE__ANY_TYPE:
            enum.features |= Enum.FEATURE__DESERIALIZE



for obj in objects_by_name.values():
    for property in obj.properties:
        if property.occurrence != OCCURRENCE__IGNORED and \
           not is_known_type(property.type):
            report_error("object '%s' contains unknown property type '%s'"
                         % (obj.name, property.type))

    if obj.extends is not None:
        if not is_known_type(obj.extends):
            report_error("object '%s' extends unknown object '%s'"
                         % (obj.name, obj.extends))

    for property in obj.properties:
        if not property.is_type_generated():
            continue

        if property.is_enum():
            enums_by_name[property.type].candidate_for_dynamic_cast = True
        else:
            objects_by_name[property.type].candidate_for_dynamic_cast = True

        # detect list usage
        if property.occurrence == OCCURRENCE__REQUIRED_LIST or \
           property.occurrence == OCCURRENCE__OPTIONAL_LIST:
            if property.is_enum():
                report_error("unsupported usage of enum '%s' as list in '%s'"
                             % (property.type, obj.type))
            else:
                objects_by_name[property.type].features |= Object.FEATURE__LIST

    # apply/remove additional features
    if obj.name in additional_object_features:
        obj.features |= additional_object_features[obj.name]

        if additional_object_features[obj.name] & Object.FEATURE__ANY_TYPE:
            obj.features |= Object.FEATURE__DESERIALIZE

    if obj.name in removed_object_features:
        obj.features &= ~removed_object_features[obj.name]

    # detect extended_by relation
    if obj.extends is not None:
        extended_obj = objects_by_name[obj.extends]

        if extended_obj.extended_by is None:
            extended_obj.extended_by = [obj.name]
        else:
            extended_obj.extended_by.append(obj.name)
            extended_obj.extended_by.sort()



for obj in objects_by_name.values():
    # if an object is a candidate (it is used directly as parameter or return
    # type or is a member of another object) and it is extended by another
    # object then this type needs the dynamic cast feature
    if obj.candidate_for_dynamic_cast and obj.extended_by:
        obj.features |= Object.FEATURE__DYNAMIC_CAST



def propagate_feature(obj, feature):
    global features_have_changed

    if not (obj.features & feature):
        return

    for property in obj.properties:
        if property.occurrence == OCCURRENCE__IGNORED or \
           not property.is_type_generated():
            continue

        if property.is_enum():
            if feature == Object.FEATURE__SERIALIZE and \
               not (enums_by_name[property.type].features & Enum.FEATURE__SERIALIZE):
                enums_by_name[property.type].features |= Enum.FEATURE__SERIALIZE
                features_have_changed = True
            elif feature == Object.FEATURE__DESERIALIZE and \
               not (enums_by_name[property.type].features & Enum.FEATURE__DESERIALIZE):
                enums_by_name[property.type].features |= Enum.FEATURE__DESERIALIZE
                features_have_changed = True
        elif property.is_object():
            if not (objects_by_name[property.type].features & feature):
                objects_by_name[property.type].features |= feature
                features_have_changed = True

            if obj.name != property.type:
                propagate_feature(objects_by_name[property.type], feature)



def inherit_features(obj):
    global features_have_changed

    if obj.extended_by is not None:
        for extended_by in obj.extended_by:
            previous = objects_by_name[extended_by].features
            objects_by_name[extended_by].features |= obj.features

            if objects_by_name[extended_by].features != previous:
                features_have_changed = True

    if obj.extends is not None:
        previous = objects_by_name[obj.extends].features
        objects_by_name[obj.extends].features |= obj.features

        if objects_by_name[obj.extends].features != previous:
            features_have_changed = True

    if obj.extended_by is not None:
        for extended_by in obj.extended_by:
            inherit_features(objects_by_name[extended_by])



# there are two directions to spread features:
# 1) up and down the inheritance chain
# 2) from object types to their member property types
# spreading needs to be done alternating on both directions because they can
# affect each other
features_have_changed = True

while features_have_changed:
    features_have_changed = False

    for obj in objects_by_name.values():
        propagate_feature(obj, Object.FEATURE__DEEP_COPY)
        propagate_feature(obj, Object.FEATURE__SERIALIZE)
        propagate_feature(obj, Object.FEATURE__DESERIALIZE)

    for obj in objects_by_name.values():
        inherit_features(obj)



for obj in managed_objects_by_name.values():
    for property in obj.properties:
        if property.occurrence != OCCURRENCE__IGNORED and \
           not is_known_type(property.type):
            report_error("object '%s' contains unknown property type '%s'"
                         % (obj.name, property.type))

    if obj.extends is not None:
        if not is_known_type(obj.extends):
            report_error("object '%s' extends unknown object '%s'"
                         % (obj.name, obj.extends))

    # detect extended_by relation
    if obj.extends is not None:
        extended_obj = managed_objects_by_name[obj.extends]

        if extended_obj.extended_by is None:
            extended_obj.extended_by = [obj.name]
        else:
            extended_obj.extended_by.append(obj.name)
            extended_obj.extended_by.sort()



notice = "/* Generated by esx_vi_generator.py */\n\n\n\n"

types_typedef.write(notice)
types_typeenum.write(notice)
types_typetostring.write(notice)
types_typefromstring.write(notice)
types_header.write(notice)
types_source.write(notice)
methods_header.write(notice)
methods_source.write(notice)
methods_macro.write(notice)
helpers_header.write(notice)
helpers_source.write(notice)



# output enums
types_typedef.write(separator +
                    " * VI Enums\n" +
                    " */\n\n")

names = enums_by_name.keys()
names.sort()

for name in names:
    types_typedef.write(enums_by_name[name].generate_typedef())
    types_typeenum.write(enums_by_name[name].generate_typeenum())
    types_typetostring.write(enums_by_name[name].generate_typetostring())
    types_typefromstring.write(enums_by_name[name].generate_typefromstring())
    types_header.write(enums_by_name[name].generate_header())
    types_source.write(enums_by_name[name].generate_source())



# output objects
types_typedef.write("\n\n\n" +
                    separator +
                    " * VI Objects\n" +
                    " */\n\n")
types_typeenum.write("\n")
types_typetostring.write("\n")
types_typefromstring.write("\n")

names = objects_by_name.keys()
names.sort()

for name in names:
    types_typedef.write(objects_by_name[name].generate_typedef())
    types_typeenum.write(objects_by_name[name].generate_typeenum())
    types_typetostring.write(objects_by_name[name].generate_typetostring())
    types_typefromstring.write(objects_by_name[name].generate_typefromstring())
    types_header.write(objects_by_name[name].generate_header())
    types_source.write(objects_by_name[name].generate_source())



# output managed objects
types_typedef.write("\n\n\n" +
                    separator +
                    " * VI Managed Objects\n" +
                    " */\n\n")
types_typeenum.write("\n")
types_typetostring.write("\n")
types_typefromstring.write("\n")

names = managed_objects_by_name.keys()
names.sort()

for name in names:
    types_typedef.write(managed_objects_by_name[name].generate_typedef())
    types_typeenum.write(managed_objects_by_name[name].generate_typeenum())
    types_typetostring.write(managed_objects_by_name[name].generate_typetostring())
    types_typefromstring.write(managed_objects_by_name[name].generate_typefromstring())
    types_header.write(managed_objects_by_name[name].generate_header())
    types_source.write(managed_objects_by_name[name].generate_source())



# output methods
names = methods_by_name.keys()
names.sort()

for name in names:
    methods_header.write(methods_by_name[name].generate_header())
    methods_source.write(methods_by_name[name].generate_source())

names = list(autobind_names)
names.sort()

for name in names:
    string = aligned("#define ESX_VI__METHOD__PARAMETER__THIS__%s " % name, "\\\n", 78)
    string += "    ESX_VI__METHOD__PARAMETER__THIS_FROM_SERVICE(ManagedObjectReference,      \\\n"
    string += aligned("", "%s)\n\n\n\n" % name, 49)

    methods_macro.write(string)



# output helpers
names = managed_objects_by_name.keys()
names.sort()

for name in names:
    helpers_header.write(managed_objects_by_name[name].generate_helper_header())
    helpers_source.write(managed_objects_by_name[name].generate_helper_source())
