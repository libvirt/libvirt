#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import os
import sys

from rpcgen.parser import XDRParser
from rpcgen.generator import (
    XDRTypeDeclarationGenerator,
    XDRTypeImplementationGenerator,
    XDRMarshallDeclarationGenerator,
    XDRMarshallImplementationGenerator,
)


def parse_cli():
    parser = argparse.ArgumentParser("RPC code generator")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["header", "source", "repr"],
        help="Output generation mode",
    )
    parser.add_argument(
        "-r", "--header", default=[], action="append", help="Extra headers to include"
    )
    parser.add_argument("input", default="-", nargs="?", help="XDR input protocol file")
    parser.add_argument("output", default="-", nargs="?", help="Generated output file")

    return parser.parse_args()


def main():
    args = parse_cli()

    infp = sys.stdin
    outfp = sys.stdout
    if args.input != "-":
        infp = open(args.input, "r")
    if args.output != "-":
        # the old genprotocol.pl wrapper would make the
        # output files mode 0444, which will prevent us
        # from writing directly do them. Explicitly
        # unlinking first gets rid of any old possibly
        # read-only copy
        #
        # We can delete this in a few years, once we
        # know users won't have a previously generated
        # readonly copy lieing around.
        try:
            os.unlink(args.output)
        except Exception:
            pass
        outfp = open(args.output, "w")

    parser = XDRParser(infp)
    spec = parser.parse()

    if args.mode == "header":
        print("/* This file is auto-generated from %s */\n" % args.input, file=outfp)
        print("#include <rpc/rpc.h>", file=outfp)
        print('#include "internal.h"', file=outfp)
        for h in args.header:
            print('#include "%s"' % h, file=outfp)
        print("", file=outfp)
        print("#pragma once\n", file=outfp)
        generator = XDRTypeDeclarationGenerator(spec)
        print(generator.visit(), file=outfp)
        generator = XDRMarshallDeclarationGenerator(spec)
        print(generator.visit(), file=outfp)
    elif args.mode == "source":
        print("/* This file is auto-generated from %s */\n" % args.input, file=outfp)
        print("#include <config.h>", file=outfp)
        for h in args.header:
            print('#include "%s"' % h, file=outfp)
        print("", file=outfp)
        generator = XDRTypeImplementationGenerator(spec)
        print(generator.visit(), file=outfp)
        generator = XDRMarshallImplementationGenerator(spec)
        print(generator.visit(), file=outfp)
    elif args.mode == "repr":
        print(spec, file=outfp)
    else:
        pass  # Just validates XDR input syntax


main()
