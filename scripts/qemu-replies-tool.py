#!/usr/bin/env python3
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# A "swiss army knife" tool for qemu capability probing '.replies' files. See
# below in 'description' for more information.

from pathlib import Path
import argparse
import json
import os
import sys


class qrtException(Exception):
    pass


# Load the 'replies' file into a list of (command, reply) tuples of parsed JSON
def qemu_replies_load(filename):
    conv = []

    with open(filename, "r") as fh:
        command = None
        jsonstr = ''

        try:
            for line in fh:
                jsonstr += line

                if line == '\n':
                    if command is None:
                        command = json.loads(jsonstr)
                    else:
                        conv.append((command, json.loads(jsonstr)))
                        command = None

                    jsonstr = ''

            if command is not None and jsonstr != '':
                conv.append((command, json.loads(jsonstr)))
                command = None
                jsonstr = ''

        except json.decoder.JSONDecodeError as je:
            raise qrtException("JSON error:\n'%s'\nwhile processing snippet:\n'%s'" % (je, jsonstr))

        if command is not None or jsonstr != '':
            if command is not None:
                errorstr = json.dumps(command, indent=2)
            else:
                errorstr = jsonstr

            raise qrtException("replies file error: Missing reply for command:\n'%s'" % errorstr)

    return conv


# Format the list of (command, reply) tuples into a string and compare it with
# the 'replies' file. Optionally regenerate the replies file if the output doesn't match
def qemu_replies_compare_or_replace(filename, conv, regenerate_on_error):
    actual = ''
    seq = 9999  # poison the initial counter state

    # possibly fix mis-ordererd 'id' fields
    for (cmd, rep) in conv:
        # 'qmp_capabilities' command restarts the numbering sequence
        if cmd['execute'] == 'qmp_capabilities':
            seq = 1

        newid = 'libvirt-%d' % seq
        cmd['id'] = newid
        rep['id'] = newid

        seq += 1

        # format the output string
        if len(actual) != 0:
            actual += '\n\n'

        actual += json.dumps(cmd, indent=2) + '\n\n' + json.dumps(rep, indent=2)

    expect = ''
    actual += '\n'

    with open(filename, "r") as fh:
        expect = fh.read()

    if actual != expect:
        if regenerate_on_error:
            with open(filename, "w") as fh:
                fh.write(actual)

        raise qrtException("replies file error: Expected content of '%s' doesn't match actual content" % filename)


# Process the replies file programmatically here.
# The 'conv' argument contains the whole conversation as a list of
# (command, reply) tuples, where both command and reply are already parsed JSON
# and thus represented by native python types (dict, list, etc ...)
#
# The code below contains a few examples and hints how to use the programatic
# processing. Do not forget to use '--regenerate' flag to update the output files.
#
# Beware that this updates the output file which is used as input for any
# subsequent re-run of the tool which can re-apply the modification.
def modify_replies(conv):
    return  # remove this to enable modifications

    version = None  # filled with a dictionary  with 'major', 'minor', 'micro' keys

    # find version of current qemu for later use
    for (cmd, rep) in conv:
        if cmd['execute'] == 'query-version':
            version = rep['return']['qemu']
            break

    if version is None:
        raise Exception("'query-version' not found in the .replies file")

    idx = -1
    # Find index of a command, in this case we're looking for the last
    # invocation of given command
    for i in range(len(conv)):
        (cmd, rep) = conv[i]

        if cmd['execute'] == 'device-list-properties':
            idx = i

    if idx == -1:
        raise Exception("entry not found")

    # Prepare data for inserting a new command

    # Command definition and error are instantiated via native python types
    cmd = {'execute': 'device-list-properties',
           'arguments': {'typename': 'example-device'}}

    reply_unsupp = {'error': {'class': 'DeviceNotFound',
                              'desc': "Device 'example-device' not found"}}

    # Real reply data can be also parsed from JSON
    reply = json.loads('''
    {
      "return": [
        {
          "name": "dummy_prop",
          "type": "str"
        },
        {
          "name": "test",
          "type": "str"
        }
        ]
    }
    ''')

    # insert command into the QMP conversation based on version of qemu
    if version['major'] >= 8 and version['minor'] > 0:
        conv.insert(idx, (cmd, reply))
    else:
        conv.insert(idx, (cmd, reply_unsupp))


def process_one(filename, args):
    try:
        conv = qemu_replies_load(filename)

        modify_replies(conv)

        qemu_replies_compare_or_replace(filename, conv, args.regenerate)

    except qrtException as e:
        print("'%s' ... FAIL\n%s" % (filename, e))
        return False

    print("'%s' ... OK" % filename)
    return True


description = '''A Swiss army knife tool for '.replies' files used by 'qemucapabilitiestest'

This tool is used to validate, programmatically update or inspect the
'.*replies' normally stored files under 'tests/qemucapabilitiesdata'.

By default the file(s) passed as positional argument are used. All '.replies'
files in a directory can be processed by specifying '--repliesdir /path/to/dir'
argument.

The default mode is validation which checks the following:
    - each command has a reply and both are valid JSON
    - numbering of the 'id' field is as expected
    - the input file has the expected JSON formatting

The tool can be also used to programmaticaly modify the '.replies' file by
editing the 'modify_replies' method directly in the source, or for
re-formatting and re-numbering the '.replies' file to conform with the required
format. To update the output file the '--regenerate' flag can be used or the
'VIR_TEST_REGENERATE_OUTPUT' environment variable must be set to '1'.
'''

if os.environ.get('VIR_TEST_REGENERATE_OUTPUT', '0') == '1':
    default_regenerate = True
else:
    default_regenerate = False

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=description)

parser.add_argument('--regenerate', action="store_true", default=default_regenerate,
                    help="regenerate output file if actual output doesn't match")

parser.add_argument('--repliesdir', default='',
                    help='use all .replies files from the directory')

parser.add_argument('replyfiles', nargs='*',
                    help='.replies file(s) to process')

args = parser.parse_args()

files = []

if args.replyfiles:
    files += args.replyfiles

if args.repliesdir:
    files += Path(args.repliesdir).glob('*.replies')

if len(files) == 0:
    parser.print_help()
    sys.exit(1)

fail = False

for file in files:
    if not process_one(str(file), args):
        fail = True

if fail:
    sys.exit(1)
