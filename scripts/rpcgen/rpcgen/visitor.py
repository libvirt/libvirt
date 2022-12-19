# SPDX-License-Identifier: LGPL-2.1-or-later

import abc

from .ast import (
    XDRSpecification,
    XDRDefinition,
    XDRDeclaration,
    XDRType,
    XDREnumValue,
    XDREnumBody,
    XDRStructBody,
    XDRUnionCase,
    XDRUnionBody,
)


class XDRVisitor(abc.ABC):
    def __init__(self, spec):
        self.spec = spec

    def visit(self, indent="", context=""):
        return self.visit_object(self.spec, indent="", context=context)

    def visit_object(self, obj, indent="", context=""):
        if isinstance(obj, XDRSpecification):
            funcname = "visit_specification"
        elif isinstance(obj, XDRDefinition):
            funcname = "visit_definition_" + type(obj).__name__[13:].lower()
        elif isinstance(obj, XDRDeclaration):
            funcname = "visit_declaration_" + type(obj).__name__[14:].lower()
        elif isinstance(obj, XDRType):
            funcname = "visit_type_" + type(obj).__name__[7:].lower()
        elif isinstance(obj, XDREnumValue):
            funcname = "visit_enum_value"
        elif isinstance(obj, XDREnumBody):
            funcname = "visit_enum_body"
        elif isinstance(obj, XDRStructBody):
            funcname = "visit_struct_body"
        elif isinstance(obj, XDRUnionCase):
            funcname = "visit_union_case"
        elif isinstance(obj, XDRUnionBody):
            funcname = "visit_union_body"
        else:
            raise Exception("Unhandled %s" % obj.__class__.__name__)

        func = getattr(self, funcname)
        assert func is not None
        return func(obj, indent, context)

    def visit_specification(self, obj, indent, context):
        code = []
        for definition in self.spec.definitions:
            defcode = self.visit_object(definition, indent, context)
            if defcode is not None:
                code.append(defcode)
        return "\n".join(code)

    def visit_definition_cescape(self, obj, indent, context):
        pass

    def visit_definition_constant(self, obj, indent, context):
        pass

    def visit_definition_enum(self, obj, indent, context):
        pass

    def visit_definition_struct(self, obj, indent, context):
        pass

    def visit_definition_union(self, obj, indent, context):
        pass

    def visit_definition_typedef(self, obj, indent, context):
        pass

    def visit_declaration_scalar(self, obj, indent, context):
        pass

    def visit_declaration_pointer(self, obj, indent, context):
        pass

    def visit_declaration_fixedarray(self, obj, indent, context):
        pass

    def visit_declaration_variablearray(self, obj, indent, context):
        pass

    def visit_type_custom(self, obj, indent, context):
        pass

    def visit_type_opaque(self, obj, indent, context):
        pass

    def visit_type_string(self, obj, indent, context):
        pass

    def visit_type_void(self, obj, indent, context):
        pass

    def visit_type_char(self, obj, indent, context):
        pass

    def visit_type_unsignedchar(self, obj, indent, context):
        pass

    def visit_type_short(self, obj, indent, context):
        pass

    def visit_type_unsignedshort(self, obj, indent, context):
        pass

    def visit_type_int(self, obj, indent, context):
        pass

    def visit_type_unsignedint(self, obj, indent, context):
        pass

    def visit_type_hyper(self, obj, indent, context):
        pass

    def visit_type_unsignedhyper(self, obj, indent, context):
        pass

    def visit_type_bool(self, obj, indent, context):
        pass

    def visit_type_float(self, obj, indent, context):
        pass

    def visit_type_double(self, obj, indent, context):
        pass

    def visit_type_enum(self, obj, indent, context):
        pass

    def visit_type_struct(self, obj, indent, context):
        pass

    def visit_type_union(self, obj, indent, context):
        pass

    def visit_enum_value(self, obj, indent, context):
        pass

    def visit_enum_body(self, obj, indent, context):
        pass

    def visit_struct_body(self, obj, indent, context):
        pass

    def visit_union_case(self, obj, indent, context):
        pass

    def visit_union_body(self, obj, indent, context):
        pass
