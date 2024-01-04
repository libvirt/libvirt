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


class qmpSchemaException(Exception):
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


# Validates that 'entry' (an member of the QMP schema):
# - checks that it's a Dict (imported from a JSON object)
# - checks that all 'mandatory' fields are present and their types match
# - checks the types of all 'optional' fields
# - checks that no unknown fields are present
def validate_qmp_schema_check_keys(entry, mandatory, optional):
    keys = set(entry.keys())

    for k, t in mandatory:
        try:
            keys.remove(k)
        except KeyError:
            raise qmpSchemaException("missing mandatory key '%s' in schema '%s'" % (k, entry))

        if not isinstance(entry[k], t):
            raise qmpSchemaException("key '%s' is not of the expected type '%s' in schema '%s'" % (k, t, entry))

    for k, t in optional:
        if k in keys:
            keys.discard(k)

            if not isinstance(entry[k], t):
                raise qmpSchemaException("key '%s' is not of the expected type '%s' in schema '%s'" % (k, t, entry))

    if len(keys) > 0:
        raise qmpSchemaException("unhandled keys '%s' in schema '%s'" % (','.join(list(keys)), entry))


# Validates the optional 'features' and that they consist only of strings
def validate_qmp_schema_check_features_list(entry):
    for f in entry.get('features', []):
        if not isinstance(f, str):
            raise qmpSchemaException("broken 'features' list in schema entry '%s'" % entry)


# Validate that the passed schema has only members supported by this script and
# by the libvirt internals. This is useful to stay up to date with any changes
# to the schema.
def validate_qmp_schema(schemalist):
    for entry in schemalist:
        if not isinstance(entry, dict):
            raise qmpSchemaException("schema entry '%s' is not a JSON Object (dict)" % (entry))

        if entry.get('meta-type', None) == 'command':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str),
                                                      ('arg-type', str),
                                                      ('ret-type', str)],
                                           optional=[('features', list),
                                                     ('allow-oob', bool)])

            validate_qmp_schema_check_features_list(entry)

        elif entry.get('meta-type', None) == 'event':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str),
                                                      ('arg-type', str)],
                                           optional=[('features', list)])

            validate_qmp_schema_check_features_list(entry)

        elif entry.get('meta-type', None) == 'object':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str),
                                                      ('members', list)],
                                           optional=[('tag', str),
                                                     ('variants', list),
                                                     ('features', list)])

            validate_qmp_schema_check_features_list(entry)

            for m in entry.get('members', []):
                validate_qmp_schema_check_keys(m,
                                               mandatory=[('name', str),
                                                          ('type', str)],
                                               optional=[('default', type(None)),
                                                         ('features', list)])
                validate_qmp_schema_check_features_list(m)

            for m in entry.get('variants', []):
                validate_qmp_schema_check_keys(m,
                                               mandatory=[('case', str),
                                                          ('type', str)],
                                               optional=[])

        elif entry.get('meta-type', None) == 'array':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str),
                                                      ('element-type', str)],
                                           optional=[])

        elif entry.get('meta-type', None) == 'enum':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str)],
                                           optional=[('members', list),
                                                     ('values', list)])

            for m in entry.get('members', []):
                validate_qmp_schema_check_keys(m,
                                               mandatory=[('name', str)],
                                               optional=[('features', list)])
                validate_qmp_schema_check_features_list(m)

        elif entry.get('meta-type', None) == 'alternate':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str),
                                                      ('members', list)],
                                           optional=[])

            for m in entry.get('members', []):
                validate_qmp_schema_check_keys(m,
                                               mandatory=[('type', str)],
                                               optional=[])

        elif entry.get('meta-type', None) == 'builtin':
            validate_qmp_schema_check_keys(entry,
                                           mandatory=[('name', str),
                                                      ('meta-type', str),
                                                      ('json-type', str)],
                                           optional=[])

        else:
            raise qmpSchemaException("unknown or missing 'meta-type' in schema entry '%s'" % entry)


# Recursively traverse the schema and print out the schema query strings for
# the corresponding entries. In certain cases the schema references itself,
# which is handled by passing a 'trace' list which contains the current path
def dump_qmp_probe_strings_iter(name, cur, trace, schema):
    obj = schema[name]

    if name in trace:
        # The following is not a query string but sometimes useful for debugging
        # print('%s (recursion)' % cur)
        return

    trace = trace + [name]

    if obj['meta-type'] == 'command' or obj['meta-type'] == 'event':
        arguments = obj.get('arg-type', None)
        returns = obj.get('ret-type', None)

        print(cur)

        for f in obj.get('features', []):
            print('%s/$%s' % (cur, f))

        if arguments:
            dump_qmp_probe_strings_iter(arguments, cur + '/arg-type', trace, schema)

        if returns:
            dump_qmp_probe_strings_iter(returns, cur + '/ret-type', trace, schema)

    elif obj['meta-type'] == 'object':
        members = sorted(obj.get('members', []), key=lambda d: d['name'])
        variants = sorted(obj.get('variants', []), key=lambda d: d['case'])

        for f in obj.get('features', []):
            print('%s/$%s' % (cur, f))

        for memb in members:
            membpath = "%s/%s" % (cur, memb['name'])
            print(membpath)

            for f in memb.get('features', []):
                print('%s/$%s' % (membpath, f))

            dump_qmp_probe_strings_iter(memb['type'], membpath, trace, schema)

        for var in variants:
            varpath = "%s/+%s" % (cur, var['case'])
            print(varpath)
            dump_qmp_probe_strings_iter(var['type'], varpath, trace, schema)

    elif obj['meta-type'] == 'enum':
        members = sorted(obj.get('members', []), key=lambda d: d['name'])

        for m in members:
            print('%s/^%s' % (cur, m['name']))

            for f in m.get('features', []):
                print('%s/^%s/$%s' % (cur, m['name'], f))

    elif obj['meta-type'] == 'array':
        dump_qmp_probe_strings_iter(obj['element-type'], cur, trace, schema)

    elif obj['meta-type'] == 'builtin':
        print('%s/!%s' % (cur, name))

    elif obj['meta-type'] == 'alternate':
        for var in obj['members']:
            dump_qmp_probe_strings_iter(var['type'], cur, trace, schema)


def dump_qmp_probe_strings(schemalist):
    schemadict = {}
    toplevel = []

    for memb in schemalist:
        schemadict[memb['name']] = memb

        if memb['meta-type'] == 'command' or memb['meta-type'] == 'event':
            toplevel.append(memb['name'])

    toplevel.sort()

    for c in toplevel:
        dump_qmp_probe_strings_iter(c, '(qmp) ' + c, [], schemadict)


def dump_qom_list_types(conv):
    types = []

    for (cmd, rep) in conv:
        if cmd['execute'] == 'qom-list-types':
            for qomtype in rep['return']:
                # validate known fields:
                # 'parent' is ignored below as it causes output churn
                for k in qomtype:
                    if k not in ['name', 'parent']:
                        raise Exception("Unhandled 'qom-list-types' field '%s'" % k)

                types.append(qomtype['name'])

            break

    types.sort()

    for t in types:
        print('(qom) ' + t)


def dump_device_list_properties(conv):
    devices = []

    for (cmd, rep) in conv:
        if cmd['execute'] == 'device-list-properties':
            if 'return' in rep:
                for arg in rep['return']:
                    for k in arg:
                        if k not in ['name', 'type', 'description', 'default-value']:
                            raise Exception("Unhandled 'device-list-properties' typename '%s' field '%s'" % (cmd['arguments']['typename'], k))

                    if 'default-value' in arg:
                        defval = ' (%s)' % str(arg['default-value'])
                    else:
                        defval = ''

                    devices.append('%s %s %s%s' % (cmd['arguments']['typename'],
                                                   arg['name'],
                                                   arg['type'],
                                                   defval))
    devices.sort()

    for d in devices:
        print('(dev) ' + d)


def process_one(filename, args):
    try:
        conv = qemu_replies_load(filename)
        dumped = False

        modify_replies(conv)

        for (cmd, rep) in conv:
            if cmd['execute'] == 'query-qmp-schema':
                validate_qmp_schema(rep['return'])

                if args.dump_all or args.dump_qmp_query_strings:
                    dump_qmp_probe_strings(rep['return'])
                    dumped = True

        if args.dump_all or args.dump_qom_list_types:
            dump_qom_list_types(conv)
            dumped = True

        if args.dump_all or args.dump_device_list_properties:
            dump_device_list_properties(conv)
            dumped = True

        if dumped:
            return True

        qemu_replies_compare_or_replace(filename, conv, args.regenerate)

    except qrtException as e:
        print("'%s' ... FAIL\n%s" % (filename, e))
        return False
    except qmpSchemaException as qe:
        print("'%s' ... FAIL\nqmp schema error: %s" % (filename, qe))
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
    - the QMP schema from qemu is fully covered by libvirt's code

In 'dump' mode if '-dump-all' or one of the specific '-dump-*' flags (below)
is selected the script outputs information gathered from the given '.replies'
file. The data is also usable for comparing two '.replies' files in a "diffable"
fashion as many of the query commands may change ordering or naming without
functional impact on libvirt.

  --dump-qmp-query-strings

    Dumps all possible valid QMP capability query strings based on the current
    qemu version in format used by virQEMUQAPISchemaPathGet or
    virQEMUCapsQMPSchemaQueries. It's useful to find specific query string
    without having to piece the information together from 'query-qmp-schema'

  --dump-qom-list-types

    Dumps all types returned by 'qom-list-types' in a stable order with the
    'parent' property dropped as it's not relevant for libvirt.

  --dump-device-list-properties

    Dumps all properties of all devices queried by libvirt in stable order
    along with types and default values.

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

parser.add_argument('--dump-all', action='store_true',
                    help='invoke all --dump-* sub-commands')

parser.add_argument('--dump-qmp-query-strings', action='store_true',
                    help='dump QMP schema in form of query strings used to probe capabilities')

parser.add_argument('--dump-qom-list-types', action='store_true',
                    help='dump data from qom-list-types in a stable order')

parser.add_argument('--dump-device-list-properties', action='store_true',
                    help='dump all devices and their properties')

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
