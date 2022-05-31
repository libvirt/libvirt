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
        prefixbase = os.path.dirname(prefix)

        if root.startswith(prefixbase):
            relroot = root[len(prefixbase):]
        else:
            relroot = root

        for file in files:
            if not re.search('\\.html$', file):
                continue

            # the 404 page doesn't play well
            if '404.html' in file:
                continue

            fullfilename = os.path.join(root, file)
            relfilename = os.path.join(relroot, file)
            filelist.append((fullfilename, relfilename))

    return filelist


# loads an XHTML and extracts all anchors, local and remote links for the one file
def process_file(filetuple):
    filename, relfilename = filetuple
    tree = ET.parse(filename)
    root = tree.getroot()

    anchors = [relfilename]
    targets = []

    for elem in root.findall('.//html:a', ns):
        target = elem.get('href')
        an = elem.get('id')

        if an:
            anchors.append(relfilename + '#' + an)

        if target:
            if re.search('://', target):
                externallinks.append(target)
            elif target[0] != '#' and 'mailto:' not in target:
                dirname = os.path.dirname(relfilename)
                targetname = os.path.normpath(os.path.join(dirname, target))

                targets.append((targetname, filename, target))

    # older docutils generate "<div class='section'"
    for elem in root.findall('.//html:div/[@class=\'section\']', ns):
        an = elem.get('id')

        if an:
            anchors.append(relfilename + '#' + an)

    # modern docutils generate a <section element
    for elem in root.findall('.//html:section', ns):
        an = elem.get('id')

        if an:
            anchors.append(relfilename + '#' + an)

    return (anchors, targets)


def process_all(filelist):
    anchors = []
    targets = []

    for filetuple in filelist:
        anchor, target = process_file(filetuple)

        targets = targets + target
        anchors = anchors + anchor

    return (targets, anchors)


def check_targets(targets, anchors):
    errors = []
    for target, targetfrom, targetorig in targets:
        if target not in anchors:
            errors.append((targetfrom, targetorig))

    if errors:
        errors.sort()

        print('broken link targets:')

        for file, target in errors:
            print(file + " broken link: " + target)

        return True

    return False


parser = argparse.ArgumentParser(description='HTML reference checker')
parser.add_argument('--prefix', default='.',
                    help='build tree prefix')
parser.add_argument('--external', action="store_true",
                    help='print external references instead')

args = parser.parse_args()

files = get_file_list(args.prefix)

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
