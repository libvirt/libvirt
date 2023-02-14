#!/usr/bin/env python3
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
# Check that external references between documentation HTML files are not broken.

import sys
import os
import argparse
import re
import xml.etree.ElementTree as ET

ns = {'html': 'http://www.w3.org/1999/xhtml'}
externallinks = []


def get_file_list(prefix):
    filelist = []

    for root, dir, files in os.walk(prefix):
        for file in files:
            if not re.search('\\.html$', file):
                continue

            # the 404 page doesn't play well
            if '404.html' in file:
                continue

            filelist.append(os.path.join(root, file))

    return filelist


# loads an XHTML and extracts all anchors, local and remote links for the one file
def process_file(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    docname = root.get('data-sourcedoc')

    if not docname:
        docname = filename

    anchors = [filename]
    targets = []

    for elem in root.findall('.//html:a', ns):
        target = elem.get('href')
        an = elem.get('id')

        if an:
            anchors.append(filename + '#' + an)

        if target:
            if re.search('://', target):
                externallinks.append(target)
            elif target[0] != '#' and 'mailto:' not in target:
                dirname = os.path.dirname(filename)
                targetfull = os.path.normpath(os.path.join(dirname, target))

                targets.append((filename, docname, targetfull, target))

    # older docutils generate "<div class='section'"
    for elem in root.findall('.//html:div/[@class=\'section\']', ns):
        an = elem.get('id')

        if an:
            anchors.append(filename + '#' + an)

    # modern docutils generate a <section element
    for elem in root.findall('.//html:section', ns):
        an = elem.get('id')

        if an:
            anchors.append(filename + '#' + an)

    return (anchors, targets)


def process_all(filelist):
    anchors = []
    targets = []

    for file in filelist:
        anchor, target = process_file(file)

        targets = targets + target
        anchors = anchors + anchor

    return (targets, anchors)


def check_targets(targets, anchors):
    errors = []
    for _, docname, target, targetorig in targets:
        if target not in anchors:
            errors.append((docname, targetorig))

    if errors:
        errors.sort()

        for file, target in errors:
            print(f'ERROR: \'{file}\': broken link to: \'{target}\'')

        return True

    return False


parser = argparse.ArgumentParser(description='HTML reference checker')
parser.add_argument('--webroot', required=True,
                    help='path to the web root')
parser.add_argument('--external', action="store_true",
                    help='print external references instead')

args = parser.parse_args()

files = get_file_list(os.path.abspath(args.webroot))

targets, anchors = process_all(files)

if args.external:
    prev = None
    externallinks.sort()
    for ext in externallinks:
        if ext != prev:
            print(ext)

        prev = ext
else:
    if check_targets(targets, anchors):
        sys.exit(1)

    sys.exit(0)
