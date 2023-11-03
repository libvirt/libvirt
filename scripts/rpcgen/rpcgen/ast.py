# SPDX-License-Identifier: LGPL-2.1-or-later

import abc


class XDRSpecification:
    def __init__(self):
        self.definitions = []

    def __repr__(self):
        return "\n".join([repr(a) for a in self.definitions])


class XDRDefinition(abc.ABC):
    pass


class XDRDefinitionConstant(XDRDefinition):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return "const:{name=%s,value=%s}" % (self.name, self.value)


class XDRDefinitionTypedef(XDRDefinition):
    def __init__(self, decl):
        self.decl = decl

    def __repr__(self):
        return "typedef:{decl=%s}" % (self.decl)


class XDRDefinitionEnum(XDRDefinition):
    def __init__(self, name, body):
        self.name = name
        self.body = body

    def __repr__(self):
        return "enum:{name=%s,body=%s}" % (self.name, self.body)


class XDRDefinitionStruct(XDRDefinition):
    def __init__(self, name, body):
        self.name = name
        self.body = body

    def __repr__(self):
        return "struct:{name=%s,body=%s}" % (self.name, self.body)


class XDRDefinitionUnion(XDRDefinition):
    def __init__(self, name, body):
        self.name = name
        self.body = body

    def __repr__(self):
        return "union:{name=%s,body=%s}" % (self.name, self.body)


class XDRDefinitionCEscape(XDRDefinition):
    def __init__(self, code):
        self.code = code

    def __repr__(self):
        return "c-escape:{code=%s}" % (self.code)


class XDRDeclaration(abc.ABC):
    def __init__(self, typ, identifier):
        self.typ = typ
        self.identifier = identifier


class XDRDeclarationScalar(XDRDeclaration):
    def __repr__(self):
        return "scalar:{type=%s,identifier=%s}" % (self.typ, self.identifier)


class XDRDeclarationPointer(XDRDeclaration):
    def __repr__(self):
        return "pointer:{type=%s,identifier=%s}" % (self.typ, self.identifier)


class XDRDeclarationFixedArray(XDRDeclaration):
    def __init__(self, typ, identifier, length):
        super().__init__(typ, identifier)
        self.length = length

    def __repr__(self):
        return "fixed-array:{type=%s,identifier=%s,length=%s}" % (
            self.typ,
            self.identifier,
            self.length,
        )


class XDRDeclarationVariableArray(XDRDeclaration):
    def __init__(self, typ, identifier, maxlength):
        super().__init__(typ, identifier)
        self.maxlength = maxlength

    def __repr__(self):
        return "variable-array:{type=%s,identifier=%s,maxlength=%s}" % (
            self.typ,
            self.identifier,
            self.maxlength,
        )


class XDRType(abc.ABC):
    def __repr__(self):
        name = self.__class__.__name__
        return name[7:].lower()

    def is_scalar(self):
        return False


class XDRTypeScalar(XDRType):
    def is_scalar(self):
        return True


class XDRTypeVoid(XDRTypeScalar):
    pass


class XDRTypeChar(XDRTypeScalar):
    pass


class XDRTypeUnsignedChar(XDRTypeScalar):
    pass


class XDRTypeShort(XDRTypeScalar):
    pass


class XDRTypeUnsignedShort(XDRTypeScalar):
    pass


class XDRTypeInt(XDRTypeScalar):
    pass


class XDRTypeUnsignedInt(XDRTypeScalar):
    pass


class XDRTypeHyper(XDRTypeScalar):
    pass


class XDRTypeUnsignedHyper(XDRTypeScalar):
    pass


class XDRTypeFloat(XDRTypeScalar):
    pass


class XDRTypeDouble(XDRTypeScalar):
    pass


class XDRTypeBool(XDRTypeScalar):
    pass


class XDRTypeOpaque(XDRType):
    pass


class XDRTypeString(XDRType):
    pass


class XDRTypeCustom(XDRType):
    def __init__(self, identifier, definition):
        self.identifier = identifier
        self.definition = definition

    def is_scalar(self):
        if type(self.definition) is XDRDefinitionEnum:
            return True
        if type(self.definition) is XDRDefinitionTypedef:
            return self.definition.decl.typ.is_scalar()
        return False

    def __repr__(self):
        return "custom{identifier=%s,definition=%s}" % (
            self.identifier,
            self.definition,
        )


class XDREnumValue:
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return "%s=%s" % (self.name, self.value)


class XDREnumBody:
    def __init__(self, values):
        self.values = values

    def __repr__(self):
        return "enum-body{values=[" + ",".join([str(a) for a in self.values]) + "]}"


class XDRTypeEnum(XDRTypeScalar):
    def __init__(self, body):
        self.body = body

    def __repr__(self):
        return "enum{%s}" % self.body


class XDRStructBody:
    def __init__(self, fields):
        self.fields = fields

    def __repr__(self):
        return "struct-body{fields=[" + ",".join([str(a) for a in self.fields]) + "]}"


class XDRTypeStruct(XDRType):
    def __init__(self, body):
        self.body = body

    def __repr__(self):
        return "struct{%s}" % self.body


class XDRUnionCase:
    def __init__(self, value, decl):
        self.value = value
        self.decl = decl

    def __repr__(self):
        return "%s=%s" % (self.value, self.decl)


class XDRUnionBody:
    def __init__(self, discriminator, cases, default):
        self.discriminator = discriminator
        self.cases = cases
        self.default = default

    def __repr__(self):
        return (
            "union-body{discriminator=%s,cases=["
            + ",".join([str(a) for a in self.cases])
            + "],default=%s}"
        ) % (self.discriminator, self.default)


class XDRTypeUnion(XDRType):
    def __init__(self, body):
        self.body = body

    def __repr__(self):
        return "union{%s}" % self.body
