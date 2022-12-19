# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

from rpcgen.ast import (
    XDRSpecification,
    XDRDefinitionConstant,
    XDRDefinitionEnum,
    XDRDefinitionUnion,
    XDRDefinitionStruct,
    XDRDeclarationScalar,
    XDRDeclarationVariableArray,
    XDREnumValue,
    XDREnumBody,
    XDRStructBody,
    XDRUnionCase,
    XDRUnionBody,
    XDRTypeCustom,
    XDRTypeVoid,
    XDRTypeString,
    XDRTypeOpaque,
)
from rpcgen.parser import XDRParser


def test_parser():
    p = Path(Path(__file__).parent, "simple.x")
    with p.open("r") as fp:
        parser = XDRParser(fp)

        got = parser.parse()

    enum = XDRDefinitionEnum(
        "filekind",
        XDREnumBody(
            [
                XDREnumValue("TEXT", "0"),
                XDREnumValue("DATA", "1"),
                XDREnumValue("EXEC", "2"),
            ],
        ),
    )

    union = XDRDefinitionUnion(
        "filetype",
        XDRUnionBody(
            XDRDeclarationScalar(XDRTypeCustom("filekind", enum), "kind"),
            [
                XDRUnionCase("TEXT", XDRDeclarationScalar(XDRTypeVoid(), None)),
                XDRUnionCase(
                    "DATA",
                    XDRDeclarationVariableArray(
                        XDRTypeString(), "creator", "MAXNAMELEN"
                    ),
                ),
                XDRUnionCase(
                    "EXEC",
                    XDRDeclarationVariableArray(
                        XDRTypeString(), "interpretor", "MAXNAMELEN"
                    ),
                ),
            ],
            None,
        ),
    )

    struct = XDRDefinitionStruct(
        "file",
        XDRStructBody(
            [
                XDRDeclarationVariableArray(XDRTypeString(), "filename", "MAXNAMELEN"),
                XDRDeclarationScalar(XDRTypeCustom("filetype", union), "type"),
                XDRDeclarationVariableArray(XDRTypeString(), "owner", "MAXUSERNAME"),
                XDRDeclarationVariableArray(XDRTypeOpaque(), "data", "MAXFILELEN"),
            ]
        ),
    )

    want = XDRSpecification()
    want.definitions.extend(
        [
            XDRDefinitionConstant("MAXUSERNAME", "32"),
            XDRDefinitionConstant("MAXFILELEN", "65535"),
            XDRDefinitionConstant("MAXNAMELEN", "255"),
            enum,
            union,
            struct,
        ]
    )

    assert str(got) == str(want)
