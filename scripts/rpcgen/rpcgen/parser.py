# SPDX-License-Identifier: LGPL-2.1-or-later

from .lexer import (
    XDRLexer,
    XDRTokenPunctuation,
    XDRTokenIdentifier,
    XDRTokenCEscape,
    XDRTokenConstant,
)
from .ast import (
    XDRSpecification,
    XDRDefinitionConstant,
    XDRDefinitionTypedef,
    XDRDefinitionEnum,
    XDRDefinitionStruct,
    XDRDefinitionUnion,
    XDRDefinitionCEscape,
    XDRDeclarationScalar,
    XDRDeclarationPointer,
    XDRDeclarationFixedArray,
    XDRDeclarationVariableArray,
    XDRTypeVoid,
    XDRTypeChar,
    XDRTypeUnsignedChar,
    XDRTypeShort,
    XDRTypeUnsignedShort,
    XDRTypeInt,
    XDRTypeUnsignedInt,
    XDRTypeHyper,
    XDRTypeUnsignedHyper,
    XDRTypeFloat,
    XDRTypeDouble,
    XDRTypeBool,
    XDRTypeOpaque,
    XDRTypeString,
    XDRTypeCustom,
    XDREnumValue,
    XDREnumBody,
    XDRTypeEnum,
    XDRStructBody,
    XDRTypeStruct,
    XDRUnionCase,
    XDRUnionBody,
    XDRTypeUnion,
)


# We are parsing (approximately the following grammar
# from RFC 4506 #6.3:
#
#    declaration:
#         type-specifier identifier
#       | type-specifier identifier "[" value "]"
#       | type-specifier identifier "<" [ value ] ">"
#       | "opaque" identifier "[" value "]"
#       | "opaque" identifier "<" [ value ] ">"
#       | "string" identifier "<" [ value ] ">"
#       | type-specifier "*" identifier
#       | "void"
#
#    value:
#         constant
#       | identifier
#
#    constant:
#       decimal-constant | hexadecimal-constant | octal-constant
#
#    type-specifier:
#         [ "unsigned" ] "int"
#       | [ "unsigned" ] "hyper"
#       | "float"
#       | "double"
#       | "quadruple"     /* We're skipping this one */
#       | "bool"
#       | enum-type-spec
#       | struct-type-spec
#       | union-type-spec
#       | identifier
#
#    enum-type-spec:
#       "enum" enum-body
#
#    enum-body:
#       "{"
#          ( identifier "=" value )
#          ( "," identifier "=" value )*
#       "}"
#
#    struct-type-spec:
#       "struct" struct-body
#
#    struct-body:
#       "{"
#          ( declaration ";" )
#          ( declaration ";" )*
#       "}"
#
#    union-type-spec:
#       "union" union-body
#
#    union-body:
#       "switch" "(" declaration ")" "{"
#          case-spec
#          case-spec *
#          [ "default" ":" declaration ";" ]
#       "}"
#
#    case-spec:
#      ( "case" value ":")
#      ( "case" value ":") *
#      declaration ";"
#
#    constant-def:
#       "const" identifier "=" constant ";"
#
#    type-def:
#         "typedef" declaration ";"
#       | "enum" identifier enum-body ";"
#       | "struct" identifier struct-body ";"
#       | "union" identifier union-body ";"
#
#    definition:
#         type-def
#       | constant-def
#
#    specification:
#         definition *
#
# Notable divergance:
#
#   - In 'type-decl' we allow 'char' and 'short'
#     in signed and unsigned variants
#
#   - In 'definition' we allow '%...' as escape C code
#     to passthrough to the header output
#
#   - In 'enum-type-spec' we allow a bare enum name
#     instead of enum body
#
#   - In 'struct-type-spec' we allow a bare struct name
#     instead of struct body
#
#   - In 'union-type-spec' we allow a bare union name
#     instead of union body
#
class XDRParser:
    def __init__(self, fp):
        self.lexer = XDRLexer(fp)
        self.typedefs = {}

    def parse(self):
        spec = XDRSpecification()
        while True:
            definition = self.parse_definition()
            if definition is None:
                break
            spec.definitions.append(definition)
        return spec

    def parse_definition(self):
        token = self.lexer.next()
        if token is None:
            return None

        if type(token) is XDRTokenCEscape:
            return XDRDefinitionCEscape(token.value[1:])

        if type(token) is not XDRTokenIdentifier:
            raise Exception("Expected identifier, but got %s" % token)

        defs = {
            "const": XDRDefinitionConstant,
            "typedef": XDRDefinitionTypedef,
            "enum": XDRDefinitionEnum,
            "struct": XDRDefinitionStruct,
            "union": XDRDefinitionUnion,
        }

        if token.value not in defs:
            raise Exception("Unexpected identifier %s" % token)

        funcname = "parse_definition_" + token.value
        func = getattr(self, funcname)
        assert func is not None

        definition = func()

        semi = self.lexer.next()
        if type(semi) is not XDRTokenPunctuation or semi.value != ";":
            raise Exception("Expected ';', but got %s" % semi)

        return definition

    def parse_definition_const(self):
        ident = self.lexer.next()
        if type(ident) is not XDRTokenIdentifier:
            raise Exception("Expected identifier, but got %s" % ident)

        assign = self.lexer.next()
        if type(assign) is not XDRTokenPunctuation or assign.value != "=":
            raise Exception("Expected '=', but got %s" % assign)

        const = self.lexer.next()
        if type(const) not in [XDRTokenConstant, XDRTokenIdentifier]:
            raise Exception("Expected constant, but got %s" % const)

        return XDRDefinitionConstant(ident.value, const.value)

    def parse_definition_typedef(self):
        decl = self.parse_declaration()
        if decl.identifier in self.typedefs:
            raise Exception("Type '%s' already defined" % decl.identifier)

        definition = XDRDefinitionTypedef(decl)
        self.typedefs[decl.identifier] = definition
        return definition

    def parse_definition_enum(self):
        name = self.lexer.next()
        if type(name) is not XDRTokenIdentifier:
            raise Exception("Expected identifier, but got %s" % name)

        body = self.parse_enum_body()

        if name.value in self.typedefs:
            raise Exception("Type '%s' already defined" % name.value)

        definition = XDRDefinitionEnum(name.value, body)
        self.typedefs[name.value] = definition
        return definition

    def parse_definition_struct(self):
        name = self.lexer.next()
        if type(name) is not XDRTokenIdentifier:
            raise Exception("Expected identifier, but got %s" % name)

        body = self.parse_struct_body()

        if name.value in self.typedefs:
            raise Exception("Type '%s' already defined" % name.value)

        definition = XDRDefinitionStruct(name.value, body)
        self.typedefs[name.value] = definition
        return definition

    def parse_definition_union(self):
        name = self.lexer.next()
        if type(name) is not XDRTokenIdentifier:
            raise Exception("Expected identifier, but got %s" % name)

        body = self.parse_union_body()

        if name.value in self.typedefs:
            raise Exception("Type '%s' already defined" % name.value)

        definition = XDRDefinitionUnion(name.value, body)
        self.typedefs[name.value] = definition
        return definition

    def parse_declaration(self):
        typ = self.parse_type()

        if type(typ) is XDRTypeVoid:
            return XDRDeclarationScalar(typ, None)

        ident = self.lexer.next()

        pointer = False
        if type(ident) is XDRTokenPunctuation:
            if ident.value != "*":
                raise Exception("Expected '*' or identifer, but got %s" % ident)
            if type(typ) is XDRTypeString or type(typ) is XDRTypeOpaque:
                raise Exception("Pointer invalid for 'string' and 'opaque' types")

            pointer = True
            ident = self.lexer.next()

        bracket = self.lexer.peek()
        if type(bracket) is XDRTokenPunctuation:
            if bracket.value == "[":
                _ = self.lexer.next()
                value = self.lexer.next()
                if type(value) not in [XDRTokenConstant, XDRTokenIdentifier]:
                    raise Exception("Expected constant, but got %s" % value)

                close = self.lexer.next()
                if type(close) is not XDRTokenPunctuation or close.value != "]":
                    raise Exception("Expected ']', but got %s" % value)

                if type(typ) is XDRTypeString:
                    raise Exception("Fixed array invalid for 'string' type")
                return XDRDeclarationFixedArray(typ, ident.value, value.value)
            elif bracket.value == "<":
                _ = self.lexer.next()
                maybeValue = self.lexer.peek()
                value = None
                if type(maybeValue) in [XDRTokenConstant, XDRTokenIdentifier]:
                    value = self.lexer.next().value

                close = self.lexer.next()
                if type(close) is not XDRTokenPunctuation or close.value != ">":
                    raise Exception("Expected '>', but got %s" % close)

                return XDRDeclarationVariableArray(typ, ident.value, value)

        if pointer:
            return XDRDeclarationPointer(typ, ident.value)
        else:
            return XDRDeclarationScalar(typ, ident.value)

    def parse_type(self):
        typ = self.lexer.next()
        if type(typ) is not XDRTokenIdentifier:
            raise Exception("Expected identifier, but got %s" % typ)

        if typ.value == "unsigned":
            typ = self.lexer.peek()
            if type(typ) is not XDRTokenIdentifier:
                raise Exception("Expected identifier, but got %s" % typ)

            if typ.value == "char":
                _ = self.lexer.next()
                return XDRTypeUnsignedChar()
            elif typ.value == "short":
                _ = self.lexer.next()
                return XDRTypeUnsignedShort()
            elif typ.value == "int":
                _ = self.lexer.next()
                return XDRTypeUnsignedInt()
            elif typ.value == "hyper":
                _ = self.lexer.next()
                return XDRTypeUnsignedHyper()
            else:
                # Bare 'unsigned' isn't allowed by 'type-specifier'
                # grammer in RFC 1014, but rpcgen allows it
                return XDRTypeUnsignedInt()

        if typ.value == "void":
            return XDRTypeVoid()
        elif typ.value == "char":
            return XDRTypeChar()
        elif typ.value == "short":
            return XDRTypeShort()
        elif typ.value == "int":
            return XDRTypeInt()
        elif typ.value == "hyper":
            return XDRTypeHyper()
        elif typ.value == "float":
            return XDRTypeFloat()
        elif typ.value == "double":
            return XDRTypeDouble()
        elif typ.value == "bool":
            return XDRTypeBool()
        elif typ.value == "enum":
            return self.parse_type_enum()
        elif typ.value == "struct":
            return self.parse_type_struct()
        elif typ.value == "union":
            return self.parse_type_union()
        elif typ.value == "opaque":
            return XDRTypeOpaque()
        elif typ.value == "string":
            return XDRTypeString()
        else:
            return XDRTypeCustom(typ.value, self.typedefs.get(typ.value, None))

    def parse_enum_body(self):
        body = self.lexer.next()
        if type(body) is not XDRTokenPunctuation or body.value != "{":
            raise Exception("Expected '{', but got %s" % body)

        values = []
        while True:
            ident = self.lexer.next()
            if type(ident) is not XDRTokenIdentifier:
                raise Exception("Expected identifier, but got %s" % ident)

            equal = self.lexer.next()
            if type(equal) is not XDRTokenPunctuation or equal.value != "=":
                raise Exception("Expected '=', but got %s" % ident)

            value = self.lexer.next()
            if type(value) is not XDRTokenConstant:
                raise Exception("Expected constant, but got %s" % ident)

            separator = self.lexer.next()
            if type(separator) is not XDRTokenPunctuation and separator.value not in [
                "}",
                ",",
            ]:
                raise Exception("Expected '}' or ',', but got %s" % separator)

            values.append(XDREnumValue(ident.value, value.value))

            if separator.value == "}":
                break

        return XDREnumBody(values)

    def parse_type_enum(self):
        body = self.parse_enum_body()
        return XDRTypeEnum(body)

    def parse_struct_body(self):
        body = self.lexer.next()
        if type(body) is not XDRTokenPunctuation or body.value != "{":
            raise Exception("Expected '{', but got %s" % body)

        fields = []
        while True:
            field = self.parse_declaration()
            fields.append(field)

            separator = self.lexer.next()
            if type(separator) is not XDRTokenPunctuation and separator.value != ";":
                raise Exception("Expected ';', but got %s" % separator)

            end = self.lexer.peek()
            if type(end) is XDRTokenPunctuation and end.value == "}":
                break

        # discard the '}' we peeked at to end the loop
        _ = self.lexer.next()
        return XDRStructBody(fields)

    def parse_type_struct(self):
        body = self.parse_struct_body()
        return XDRTypeStruct(body)

    def parse_union_body(self):
        ident = self.lexer.next()
        if type(ident) is not XDRTokenIdentifier or ident.value != "switch":
            raise Exception("Expected 'switch', but got %s" % ident)

        bracket = self.lexer.next()
        if type(bracket) is not XDRTokenPunctuation or bracket.value != "(":
            raise Exception("Expected '(', but got %s" % bracket)

        discriminator = self.parse_declaration()

        bracket = self.lexer.next()
        if type(bracket) is not XDRTokenPunctuation or bracket.value != ")":
            raise Exception("Expected ')', but got %s" % bracket)

        bracket = self.lexer.next()
        if type(bracket) is not XDRTokenPunctuation or bracket.value != "{":
            raise Exception("Expected '{', but got %s" % bracket)

        default = None
        cases = []
        while True:
            ident = self.lexer.next()
            if type(ident) is not XDRTokenIdentifier or ident.value not in [
                "default",
                "case",
            ]:
                raise Exception("Expected 'default' or 'case', but got %s" % ident)

            value = None
            if ident.value == "case":
                value = self.lexer.next()
                if type(value) not in [XDRTokenConstant, XDRTokenIdentifier]:
                    raise Exception("Expected constant, but got %s" % value)

                sep = self.lexer.next()
                if type(sep) is not XDRTokenPunctuation or sep.value != ":":
                    raise Exception("Expected ':', but got %s" % value)

                decl = self.parse_declaration()

                case = XDRUnionCase(value.value, decl)
                cases.append(case)
            else:
                if default is not None:
                    raise Exception("Duplicate 'default' clause")

                sep = self.lexer.next()
                if type(sep) is not XDRTokenPunctuation or sep.value != ":":
                    raise Exception("Expected ':', but got %s" % value)

                default = self.parse_declaration()

            separator = self.lexer.next()
            if type(separator) is not XDRTokenPunctuation and separator.value != ";":
                raise Exception("Expected ';', but got %s" % bracket)

            end = self.lexer.peek()
            if type(end) is XDRTokenPunctuation and end.value == "}":
                break

        # discard the '}' we peeked at to end the loop
        _ = self.lexer.next()
        return XDRUnionBody(discriminator, cases, default)

    def parse_type_union(self):
        body = self.parse_union_body()
        return XDRTypeUnion(body)
