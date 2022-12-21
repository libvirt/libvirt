# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path

from rpcgen.parser import XDRParser
from rpcgen.generator import (
    XDRTypeDeclarationGenerator,
    XDRTypeImplementationGenerator,
    XDRMarshallDeclarationGenerator,
    XDRMarshallImplementationGenerator,
)


def test_generate_header():
    x = Path(Path(__file__).parent, "demo.x")
    h = Path(Path(__file__).parent, "demo.h")
    with x.open("r") as fp:
        parser = XDRParser(fp)
        spec = parser.parse()

    got = (
        XDRTypeDeclarationGenerator(spec).visit()
        + "\n"
        + XDRMarshallDeclarationGenerator(spec).visit()
    )

    with h.open("r") as fp:
        want = fp.read()

    if "VIR_TEST_REGENERATE_OUTPUT" in os.environ:
        want = got
        with h.open("w") as fp:
            fp.write(want)

    assert got == want


def test_generate_source():
    x = Path(Path(__file__).parent, "demo.x")
    h = Path(Path(__file__).parent, "demo.c")
    with x.open("r") as fp:
        parser = XDRParser(fp)
        spec = parser.parse()

    got = (
        XDRTypeImplementationGenerator(spec).visit()
        + "\n"
        + XDRMarshallImplementationGenerator(spec).visit()
    )

    with h.open("r") as fp:
        want = fp.read()

    if "VIR_TEST_REGENERATE_OUTPUT" in os.environ:
        want = got
        with h.open("w") as fp:
            fp.write(want)

    assert got == want
