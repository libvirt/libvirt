#!/usr/bin/env python3

import argparse
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("xsltproc", type=str, help="path to xsltproc bin")
parser.add_argument("xmllint", type=str, help="path to xmllint bin")
parser.add_argument("builddir", type=str, help="build root dir path")
parser.add_argument("timestamp", type=str, help="docs timestamp")
parser.add_argument("style", type=str, help="XSL stile file")
parser.add_argument("infile", type=str, help="path to source HTML file")
parser.add_argument("htmlfile", type=str, help="path to generated HTML file")
parser.add_argument("pagesrc", type=str, default="", nargs='?', help="(optional) path to source file used for edit this page")
args = parser.parse_args()

html_tmp = subprocess.run(
    [
        args.xsltproc,
        '--stringparam', 'pagesrc', args.pagesrc,
        '--stringparam', 'builddir', args.builddir,
        '--stringparam', 'timestamp', args.timestamp,
        '--nonet', args.style, args.infile,
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

html = subprocess.run(
    [args.xmllint, '--nonet', '--format', '-'],
    input=html_tmp.stdout,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

with open(args.htmlfile, 'wb') as outfile:
    outfile.write(html.stdout)
