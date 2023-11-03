# SPDX-License-Identifier: LGPL-2.1-or-later

import platform

from .visitor import XDRVisitor
from .parser import (
    XDRTypeString,
    XDRTypeVoid,
    XDRTypeOpaque,
    XDRTypeCustom,
    XDRDefinitionTypedef,
    XDRDeclarationFixedArray,
    XDRDeclarationVariableArray,
    XDRDeclarationPointer,
)


class XDRTypeDeclarationGenerator(XDRVisitor):
    def visit_definition_cescape(self, obj, indent, context):
        return obj.code + "\n"

    def visit_definition_constant(self, obj, indent, context):
        return "#%sdefine %s %s\n" % (indent, obj.name, obj.value)

    def visit_definition_enum(self, obj, indent, context):
        code = "%senum %s %s;\n" % (
            indent,
            obj.name,
            self.visit_object(obj.body, indent),
        ) + "%stypedef enum %s %s;\n" % (indent, obj.name, obj.name)
        return code

    def generate_cleanup(self, name, indent):
        code = "%svoid xdr_%s_clear(%s *objp);\n" % (
            indent,
            name,
            name,
        ) + "%sG_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(%s, xdr_%s_clear);\n" % (
            indent,
            name,
            name,
        )
        return code

    def visit_definition_struct(self, obj, indent, context):
        code = (
            "%sstruct %s %s;\n"
            % (indent, obj.name, self.visit_object(obj.body, indent))
            + "%stypedef struct %s %s;\n" % (indent, obj.name, obj.name)
            + self.generate_cleanup(obj.name, indent)
        )
        return code

    def visit_definition_union(self, obj, indent, context):
        code = (
            "%sstruct %s %s;\n"
            % (indent, obj.name, self.visit_object(obj.body, indent, obj.name))
            + "%stypedef struct %s %s;\n" % (indent, obj.name, obj.name)
            + self.generate_cleanup(obj.name, indent)
        )
        return code

    def visit_definition_typedef(self, obj, indent, context):
        code = "%stypedef %s;\n" % (
            indent,
            self.visit_object(obj.decl, indent),
        ) + self.generate_cleanup(obj.decl.identifier, indent)
        return code

    def visit_declaration_scalar(self, obj, indent, context):
        return "%s %s" % (self.visit_object(obj.typ, indent), obj.identifier)

    def visit_declaration_pointer(self, obj, indent, context):
        return "%s *%s" % (self.visit_object(obj.typ, indent), obj.identifier)

    def visit_declaration_fixedarray(self, obj, indent, context):
        return "%s %s[%s]" % (
            self.visit_object(obj.typ, indent),
            obj.identifier,
            obj.length,
        )

    def visit_declaration_variablearray(self, obj, indent, context):
        if type(obj.typ) is XDRTypeString:
            return "%schar *%s" % (indent, obj.identifier)
        else:
            code = (
                "%sstruct {\n" % indent
                + "%s    u_int %s_len;\n" % (indent, obj.identifier)
                + "%s    %s *%s_val;\n"
                % (indent, self.visit_object(obj.typ, ""), obj.identifier)
                + "%s} %s" % (indent, obj.identifier)
            )
            return code

    def visit_type_custom(self, obj, indent, context):
        return "%s%s" % (indent, obj.identifier)

    def visit_type_opaque(self, obj, indent, context):
        return "%schar" % indent

    def visit_type_string(self, obj, indent, context):
        return "%sstring" % indent

    def visit_type_void(self, obj, indent, context):
        return "%svoid" % indent

    def visit_type_char(self, obj, indent, context):
        return "%schar" % indent

    def visit_type_unsignedchar(self, obj, indent, context):
        return "%su_char" % indent

    def visit_type_short(self, obj, indent, context):
        return "%sshort" % indent

    def visit_type_unsignedshort(self, obj, indent, context):
        return "%su_short" % indent

    def visit_type_int(self, obj, indent, context):
        return "%sint" % indent

    def visit_type_unsignedint(self, obj, indent, context):
        return "%su_int" % indent

    def visit_type_hyper(self, obj, indent, context):
        return "%sint64_t" % indent

    def visit_type_unsignedhyper(self, obj, indent, context):
        return "%suint64_t" % indent

    def visit_type_bool(self, obj, indent, context):
        return "%sbool_t" % indent

    def visit_type_float(self, obj, indent, context):
        return "%sfloat" % indent

    def visit_type_double(self, obj, indent, context):
        return "%sdouble" % indent

    def visit_type_enum(self, obj, indent, context):
        return "%senum %s" % (indent, self.visit_object(obj.body.body, indent))

    def visit_type_struct(self, obj, indent, context):
        return "%sstruct %s" % (indent, self.visit_object(obj.body, indent))

    def visit_type_union(self, obj, indent, context):
        return "%sstruct %s" % (indent, self.visit_object(obj.body, indent))

    def visit_enum_value(self, obj, indent, context):
        return "%s%s = %s" % (indent, obj.name, obj.value)

    def visit_enum_body(self, obj, indent, context):
        code = "{\n"
        for value in obj.values:
            code = code + self.visit_object(value, indent + "    ") + ",\n"
        code = code + "%s}" % indent
        return code

    def visit_struct_body(self, obj, indent, context):
        code = "{\n"
        for value in obj.fields:
            code = code + self.visit_object(value, indent + "    ") + ";\n"
        code = code + "%s}" % indent
        return code

    def visit_union_case(self, obj, indent, context):
        return self.visit_object(obj.decl, indent)

    def visit_union_body(self, obj, indent, context):
        prefix = context
        if prefix != "":
            prefix = prefix + "_"

        code = (
            "%s{\n" % indent
            + "%s    %s;\n" % (indent, self.visit_object(obj.discriminator))
            + "%s    union {\n" % indent
        )
        for value in obj.cases:
            if type(value.decl.typ) is XDRTypeVoid:
                continue
            code = code + self.visit_object(value, indent + "        ") + ";\n"
        if obj.default is not None and type(obj.default.typ) is not XDRTypeVoid:
            code = code + self.visit_object(obj.default, indent + "        ") + ";\n"
        code = code + "%s    } %su;\n" % (indent, prefix) + "%s}" % indent
        return code


class XDRTypeImplementationGenerator(XDRVisitor):
    def visit_definition_enum(self, obj, indent, context):
        pass

    def generate_cleanup(self, name, indent):
        code = (
            "\n"
            + "%svoid xdr_%s_clear(%s *objp)\n" % (indent, name, name)
            + "%s{\n" % indent
            + "%s    xdr_free((xdrproc_t)xdr_%s, (char *)objp);\n" % (indent, name)
            + "%s}\n" % indent
        )
        return code

    def visit_definition_union(self, obj, indent, context):
        return self.generate_cleanup(obj.name, indent)

    def visit_definition_struct(self, obj, indent, context):
        return self.generate_cleanup(obj.name, indent)

    def visit_definition_typedef(self, obj, indent, context):
        return self.generate_cleanup(obj.decl.identifier, indent)


class XDRMarshallDeclarationGenerator(XDRVisitor):
    def visit_definition_enum(self, obj, indent, context):
        return "%sextern  bool_t xdr_%s(XDR *, %s*);\n" % (indent, obj.name, obj.name)

    def visit_definition_union(self, obj, indent, context):
        return "%sextern  bool_t xdr_%s(XDR *, %s*);\n" % (indent, obj.name, obj.name)

    def visit_definition_struct(self, obj, indent, context):
        return "%sextern  bool_t xdr_%s(XDR *, %s*);\n" % (indent, obj.name, obj.name)

    def visit_definition_typedef(self, obj, indent, context):
        if isinstance(obj.decl, XDRDeclarationFixedArray):
            return "%sextern  bool_t xdr_%s(XDR *, %s);\n" % (
                indent,
                obj.decl.identifier,
                obj.decl.identifier,
            )
        else:
            return "%sextern  bool_t xdr_%s(XDR *, %s*);\n" % (
                indent,
                obj.decl.identifier,
                obj.decl.identifier,
            )


class XDRMarshallImplementationGenerator(XDRVisitor):
    def visit_definition_enum(self, obj, indent, context):
        code = (
            "%sbool_t\n" % indent
            + "%sxdr_%s(XDR *xdrs, %s *objp)\n" % (indent, obj.name, obj.name)
            + "%s{\n" % indent
            + "%s    if (!xdr_enum(xdrs, (enum_t *)objp))\n" % indent
            + "%s        return FALSE;\n" % indent
            + "%s    return TRUE;\n" % indent
            + "%s}\n" % indent
        )
        return code

    def generate_type_call(self, decl, field, typename, embedded=False, indent=""):
        if type(decl.typ) is XDRTypeVoid:
            return ""
        if type(decl) is XDRDeclarationFixedArray:
            if type(decl.typ) is XDRTypeOpaque:
                code = "%s    if (!xdr_%s(xdrs, %s, %s))\n" % (
                    indent,
                    self.visit_object(decl.typ, context="func"),
                    field,
                    decl.length,
                )
            else:
                code = "%s    if (!xdr_vector(xdrs, (char *)%s, %s,\n" % (
                    indent,
                    field,
                    decl.length,
                ) + "%s        sizeof(%s), (xdrproc_t)xdr_%s))\n" % (
                    indent,
                    self.visit_object(decl.typ),
                    self.visit_object(decl.typ, context="func"),
                )
        elif type(decl) is XDRDeclarationVariableArray:
            fieldRef = "."
            pointerStr = ""
            if embedded:
                pointerStr = "&"
            else:
                fieldRef = "->"

            if type(decl.typ) is XDRTypeString:
                code = "%s    if (!xdr_%s(xdrs, %s%s, %s))\n" % (
                    indent,
                    self.visit_object(decl.typ, context="func"),
                    pointerStr,
                    field,
                    decl.maxlength,
                )
            elif type(decl.typ) is XDRTypeOpaque:
                code = "%s    if (!xdr_bytes(xdrs, (char **)&%s%s%s_val, " % (
                    indent,
                    field,
                    fieldRef,
                    typename,
                ) + "(u_int *) &%s%s%s_len, %s))\n" % (
                    field,
                    fieldRef,
                    typename,
                    decl.maxlength,
                )
            else:
                code = (
                    "%s    if (!xdr_array(xdrs, (char **)&%s%s%s_val, "
                    % (indent, field, fieldRef, typename)
                    + "(u_int *) &%s%s%s_len, %s,\n"
                    % (field, fieldRef, typename, decl.maxlength)
                    + "%s        sizeof(%s), (xdrproc_t)xdr_%s))\n"
                    % (
                        indent,
                        self.visit_object(decl.typ),
                        self.visit_object(decl.typ, context="func"),
                    )
                )
        elif type(decl) is XDRDeclarationPointer:
            pointerStr = ""
            if embedded:
                pointerStr = "&"

            code = "%s    if (!xdr_pointer(xdrs, (char **)%s%s, " % (
                indent,
                pointerStr,
                field,
            ) + "sizeof(%s), (xdrproc_t)xdr_%s))\n" % (
                self.visit_object(decl.typ, context="func"),
                self.visit_object(decl.typ, context="func"),
            )
        else:
            pointerStr = ""
            isFixedArray = (
                type(decl.typ) is XDRTypeCustom
                and type(decl.typ.definition) is XDRDefinitionTypedef
                and type(decl.typ.definition.decl) is XDRDeclarationFixedArray
            )

            if embedded and not isFixedArray:
                pointerStr = "&"

            code = "%s    if (!xdr_%s(xdrs, %s%s))\n" % (
                indent,
                self.visit_object(decl.typ, context="func"),
                pointerStr,
                field,
            )

        code = code + "%s        return FALSE;\n" % indent
        return code

    def visit_definition_union(self, obj, indent, context):
        code = (
            "%sbool_t\n" % indent
            + "%sxdr_%s(XDR *xdrs, %s *objp)\n" % (indent, obj.name, obj.name)
            + "%s{\n" % indent
            + self.generate_type_call(
                obj.body.discriminator,
                "objp->%s" % obj.body.discriminator.identifier,
                obj.body.discriminator.identifier,
                embedded=True,
                indent=indent,
            )
            + "%s    switch (objp->%s) {\n"
            % (indent, obj.body.discriminator.identifier)
        )

        for case in obj.body.cases:
            code = (
                code
                + "%s    case %s:\n" % (indent, case.value)
                + self.generate_type_call(
                    case.decl,
                    "objp->%s_u.%s" % (obj.name, case.decl.identifier),
                    obj.name,
                    embedded=True,
                    indent=indent + "    ",
                )
                + "%s        break;\n" % indent
            )

        code = code + "%s    default:\n" % indent

        if obj.body.default is not None:
            code = (
                code
                + self.generate_type_call(
                    obj.body.default,
                    "objp->%s_u.%s" % (obj.name, obj.body.default.identifier),
                    obj.name,
                    embedded=True,
                    indent=indent + "    ",
                )
                + "%s        break;\n" % indent
            )
        else:
            code = code + "%s        return FALSE;\n" % indent

        code = (
            code
            + "%s    }\n" % indent
            + "%s    return TRUE;\n" % indent
            + "%s}\n" % indent
        )
        return code

    def visit_definition_struct(self, obj, indent, context):
        code = (
            "%sbool_t\n" % indent
            + "%sxdr_%s(XDR *xdrs, %s *objp)\n" % (indent, obj.name, obj.name)
            + "%s{\n" % indent
        )
        for field in obj.body.fields:
            code = code + self.generate_type_call(
                field,
                "objp->%s" % field.identifier,
                field.identifier,
                embedded=True,
                indent=indent,
            )
        code = code + "%s    return TRUE;\n" % indent + "%s}\n" % indent
        return code

    def visit_definition_typedef(self, obj, indent, context):
        code = "%sbool_t\n" % indent
        if isinstance(obj.decl, XDRDeclarationFixedArray):
            code = code + "%sxdr_%s(XDR *xdrs, %s objp)\n" % (
                indent,
                obj.decl.identifier,
                obj.decl.identifier,
            )
        else:
            code = code + "%sxdr_%s(XDR *xdrs, %s *objp)\n" % (
                indent,
                obj.decl.identifier,
                obj.decl.identifier,
            )
        code = (
            code
            + "%s{\n" % indent
            + self.generate_type_call(
                obj.decl, "objp", obj.decl.identifier, embedded=False, indent=indent
            )
            + "%s    return TRUE;\n" % indent
            + "%s}\n" % indent
        )
        return code

    def visit_declaration_pointer(self, obj, indent, context):
        return "%s%s *%s" % (indent, self.visit_object(obj.typ), obj.identifier)

    def visit_declaration_fixedarray(self, obj, indent, context):
        return "%s%s %s[%s]" % (
            indent,
            self.visit_object(obj.typ),
            obj.identifier,
            obj.length,
        )

    def visit_declaration_variablearray(self, obj, indent, context):
        return "%s%s *%s" % (indent, self.visit_object(obj.typ), obj.identifier)

    def visit_type_custom(self, obj, indent, context):
        return "%s%s" % (indent, obj.identifier)

    def visit_type_opaque(self, obj, indent, context):
        return "%sopaque" % indent

    def visit_type_string(self, obj, indent, context):
        return "%sstring" % indent

    def visit_type_char(self, obj, indent, context):
        return "%schar" % indent

    def visit_type_unsignedchar(self, obj, indent, context):
        return "%su_char" % indent

    def visit_type_short(self, obj, indent, context):
        return "%sshort" % indent

    def visit_type_unsignedshort(self, obj, indent, context):
        return "%su_short" % indent

    def visit_type_int(self, obj, indent, context):
        return "%sint" % indent

    def visit_type_unsignedint(self, obj, indent, context):
        return "%su_int" % indent

    def visit_type_hyper(self, obj, indent, context):
        return "%sint64_t" % indent

    def visit_type_unsignedhyper(self, obj, indent, context):
        if context == "func" and platform.system() == "Darwin":
            return "%su_int64_t" % indent
        else:
            return "%suint64_t" % indent

    def visit_type_bool(self, obj, indent, context):
        if context == "func":
            return "%sbool" % indent
        else:
            return "%sbool_t" % indent

    def visit_type_float(self, obj, indent, context):
        return "%sfloat" % indent

    def visit_type_double(self, obj, indent, context):
        return "%sdouble" % indent

    def visit_enum_value(self, obj, indent, context):
        return "%s%s = %s" % (indent, obj.name, obj.value)

    def visit_union_case(self, obj, indent, context):
        return self.visit_object(obj.value, indent)
