#!/usr/bin/python -u
#
# generate python wrappers from the XML API description
#

functions = {}
qemu_functions = {}
enums = {} # { enumType: { enumConstant: enumValue } }
qemu_enums = {} # { enumType: { enumConstant: enumValue } }

import os
import sys
import string
import re

quiet=True

if __name__ == "__main__":
    # launched as a script
    srcPref = os.path.dirname(sys.argv[0])
    if len(sys.argv) > 1:
        python = sys.argv[1]
    else:
        print "Python binary not specified"
        sys.exit(1)
else:
    # imported
    srcPref = os.path.dirname(__file__)

#######################################################################
#
#  That part if purely the API acquisition phase from the
#  libvirt API description
#
#######################################################################
import os
import xml.sax

debug = 0

def getparser():
    # Attach parser to an unmarshalling object. return both objects.
    target = docParser()
    parser = xml.sax.make_parser()
    parser.setContentHandler(target)
    return parser, target

class docParser(xml.sax.handler.ContentHandler):
    def __init__(self):
        self._methodname = None
        self._data = []
        self.in_function = 0

        self.startElement = self.start
        self.endElement = self.end
        self.characters = self.data

    def close(self):
        if debug:
            print "close"

    def getmethodname(self):
        return self._methodname

    def data(self, text):
        if debug:
            print "data %s" % text
        self._data.append(text)

    def cdata(self, text):
        if debug:
            print "data %s" % text
        self._data.append(text)

    def start(self, tag, attrs):
        if debug:
            print "start %s, %s" % (tag, attrs)
        if tag == 'function':
            self._data = []
            self.in_function = 1
            self.function = None
            self.function_cond = None
            self.function_args = []
            self.function_descr = None
            self.function_return = None
            self.function_file = None
            self.function_module= None
            if attrs.has_key('name'):
                self.function = attrs['name']
            if attrs.has_key('file'):
                self.function_file = attrs['file']
            if attrs.has_key('module'):
                self.function_module= attrs['module']
        elif tag == 'cond':
            self._data = []
        elif tag == 'info':
            self._data = []
        elif tag == 'arg':
            if self.in_function == 1:
                self.function_arg_name = None
                self.function_arg_type = None
                self.function_arg_info = None
                if attrs.has_key('name'):
                    self.function_arg_name = attrs['name']
                    if self.function_arg_name == 'from':
                        self.function_arg_name = 'frm'
                if attrs.has_key('type'):
                    self.function_arg_type = attrs['type']
                if attrs.has_key('info'):
                    self.function_arg_info = attrs['info']
        elif tag == 'return':
            if self.in_function == 1:
                self.function_return_type = None
                self.function_return_info = None
                self.function_return_field = None
                if attrs.has_key('type'):
                    self.function_return_type = attrs['type']
                if attrs.has_key('info'):
                    self.function_return_info = attrs['info']
                if attrs.has_key('field'):
                    self.function_return_field = attrs['field']
        elif tag == 'enum':
            if (attrs['file'] == "libvirt" or
                attrs['file'] == "virterror"):
                enum(attrs['type'],attrs['name'],attrs['value'])
            elif attrs['file'] == "libvirt-qemu":
                qemu_enum(attrs['type'],attrs['name'],attrs['value'])

    def end(self, tag):
        if debug:
            print "end %s" % tag
        if tag == 'function':
            if self.function != None:
                if (self.function_module == "libvirt" or
                    self.function_module == "event" or
                    self.function_module == "virterror"):
                    function(self.function, self.function_descr,
                             self.function_return, self.function_args,
                             self.function_file, self.function_module,
                             self.function_cond)
                elif self.function_module == "libvirt-qemu":
                    qemu_function(self.function, self.function_descr,
                             self.function_return, self.function_args,
                             self.function_file, self.function_module,
                             self.function_cond)
                elif self.function_file == "python":
                    function(self.function, self.function_descr,
                             self.function_return, self.function_args,
                             self.function_file, self.function_module,
                             self.function_cond)
                elif self.function_file == "python-qemu":
                    qemu_function(self.function, self.function_descr,
                                  self.function_return, self.function_args,
                                  self.function_file, self.function_module,
                                  self.function_cond)
                self.in_function = 0
        elif tag == 'arg':
            if self.in_function == 1:
                self.function_args.append([self.function_arg_name,
                                           self.function_arg_type,
                                           self.function_arg_info])
        elif tag == 'return':
            if self.in_function == 1:
                self.function_return = [self.function_return_type,
                                        self.function_return_info,
                                        self.function_return_field]
        elif tag == 'info':
            str = ''
            for c in self._data:
                str = str + c
            if self.in_function == 1:
                self.function_descr = str
        elif tag == 'cond':
            str = ''
            for c in self._data:
                str = str + c
            if self.in_function == 1:
                self.function_cond = str


def function(name, desc, ret, args, file, module, cond):
    functions[name] = (desc, ret, args, file, module, cond)

def qemu_function(name, desc, ret, args, file, module, cond):
    qemu_functions[name] = (desc, ret, args, file, module, cond)

def enum(type, name, value):
    if not enums.has_key(type):
        enums[type] = {}
    if value == 'VIR_TYPED_PARAM_INT':
        value = 1
    elif value == 'VIR_TYPED_PARAM_UINT':
        value = 2
    elif value == 'VIR_TYPED_PARAM_LLONG':
        value = 3
    elif value == 'VIR_TYPED_PARAM_ULLONG':
        value = 4
    elif value == 'VIR_TYPED_PARAM_DOUBLE':
        value = 5
    elif value == 'VIR_TYPED_PARAM_BOOLEAN':
        value = 6
    elif value == 'VIR_DOMAIN_AFFECT_CURRENT':
        value = 0
    elif value == 'VIR_DOMAIN_AFFECT_LIVE':
        value = 1
    elif value == 'VIR_DOMAIN_AFFECT_CONFIG':
        value = 2
    if name[-5:] != '_LAST':
        enums[type][name] = value

def qemu_enum(type, name, value):
    if not qemu_enums.has_key(type):
        qemu_enums[type] = {}
    qemu_enums[type][name] = value


#######################################################################
#
#  Some filtering rukes to drop functions/types which should not
#  be exposed as-is on the Python interface
#
#######################################################################

functions_failed = []
qemu_functions_failed = []
functions_skipped = [
    "virConnectListDomains",
]
qemu_functions_skipped = []

skipped_modules = {
}

skipped_types = {
#    'int *': "usually a return type",
     'virConnectDomainEventCallback': "No function types in python",
     'virConnectDomainEventGenericCallback': "No function types in python",
     'virConnectDomainEventRTCChangeCallback': "No function types in python",
     'virConnectDomainEventWatchdogCallback': "No function types in python",
     'virConnectDomainEventIOErrorCallback': "No function types in python",
     'virConnectDomainEventGraphicsCallback': "No function types in python",
     'virStreamEventCallback': "No function types in python",
     'virEventHandleCallback': "No function types in python",
     'virEventTimeoutCallback': "No function types in python",
     'virDomainBlockJobInfoPtr': "Not implemented yet",
}

#######################################################################
#
#  Table of remapping to/from the python type or class to the C
#  counterpart.
#
#######################################################################

py_types = {
    'void': (None, None, None, None),
    'int':  ('i', None, "int", "int"),
    'long':  ('l', None, "long", "long"),
    'double':  ('d', None, "double", "double"),
    'unsigned int':  ('i', None, "int", "int"),
    'unsigned long':  ('l', None, "long", "long"),
    'long long':  ('l', None, "longlong", "long long"),
    'unsigned long long':  ('l', None, "longlong", "long long"),
    'unsigned char *':  ('z', None, "charPtr", "char *"),
    'char *':  ('z', None, "charPtr", "char *"),
    'const char *':  ('z', None, "constcharPtr", "const char *"),
    'size_t': ('n', None, "size_t", "size_t"),

    'virDomainPtr':  ('O', "virDomain", "virDomainPtr", "virDomainPtr"),
    'const virDomainPtr':  ('O', "virDomain", "virDomainPtr", "virDomainPtr"),
    'virDomain *':  ('O', "virDomain", "virDomainPtr", "virDomainPtr"),
    'const virDomain *':  ('O', "virDomain", "virDomainPtr", "virDomainPtr"),

    'virNetworkPtr':  ('O', "virNetwork", "virNetworkPtr", "virNetworkPtr"),
    'const virNetworkPtr':  ('O', "virNetwork", "virNetworkPtr", "virNetworkPtr"),
    'virNetwork *':  ('O', "virNetwork", "virNetworkPtr", "virNetworkPtr"),
    'const virNetwork *':  ('O', "virNetwork", "virNetworkPtr", "virNetworkPtr"),

    'virInterfacePtr':  ('O', "virInterface", "virInterfacePtr", "virInterfacePtr"),
    'const virInterfacePtr':  ('O', "virInterface", "virInterfacePtr", "virInterfacePtr"),
    'virInterface *':  ('O', "virInterface", "virInterfacePtr", "virInterfacePtr"),
    'const virInterface *':  ('O', "virInterface", "virInterfacePtr", "virInterfacePtr"),

    'virStoragePoolPtr':  ('O', "virStoragePool", "virStoragePoolPtr", "virStoragePoolPtr"),
    'const virStoragePoolPtr':  ('O', "virStoragePool", "virStoragePoolPtr", "virStoragePoolPtr"),
    'virStoragePool *':  ('O', "virStoragePool", "virStoragePoolPtr", "virStoragePoolPtr"),
    'const virStoragePool *':  ('O', "virStoragePool", "virStoragePoolPtr", "virStoragePoolPtr"),

    'virStorageVolPtr':  ('O', "virStorageVol", "virStorageVolPtr", "virStorageVolPtr"),
    'const virStorageVolPtr':  ('O', "virStorageVol", "virStorageVolPtr", "virStorageVolPtr"),
    'virStorageVol *':  ('O', "virStorageVol", "virStorageVolPtr", "virStorageVolPtr"),
    'const virStorageVol *':  ('O', "virStorageVol", "virStorageVolPtr", "virStorageVolPtr"),

    'virConnectPtr':  ('O', "virConnect", "virConnectPtr", "virConnectPtr"),
    'const virConnectPtr':  ('O', "virConnect", "virConnectPtr", "virConnectPtr"),
    'virConnect *':  ('O', "virConnect", "virConnectPtr", "virConnectPtr"),
    'const virConnect *':  ('O', "virConnect", "virConnectPtr", "virConnectPtr"),

    'virNodeDevicePtr':  ('O', "virNodeDevice", "virNodeDevicePtr", "virNodeDevicePtr"),
    'const virNodeDevicePtr':  ('O', "virNodeDevice", "virNodeDevicePtr", "virNodeDevicePtr"),
    'virNodeDevice *':  ('O', "virNodeDevice", "virNodeDevicePtr", "virNodeDevicePtr"),
    'const virNodeDevice *':  ('O', "virNodeDevice", "virNodeDevicePtr", "virNodeDevicePtr"),

    'virSecretPtr':  ('O', "virSecret", "virSecretPtr", "virSecretPtr"),
    'const virSecretPtr':  ('O', "virSecret", "virSecretPtr", "virSecretPtr"),
    'virSecret *':  ('O', "virSecret", "virSecretPtr", "virSecretPtr"),
    'const virSecret *':  ('O', "virSecret", "virSecretPtr", "virSecretPtr"),

    'virNWFilterPtr':  ('O', "virNWFilter", "virNWFilterPtr", "virNWFilterPtr"),
    'const virNWFilterPtr':  ('O', "virNWFilter", "virNWFilterPtr", "virNWFilterPtr"),
    'virNWFilter *':  ('O', "virNWFilter", "virNWFilterPtr", "virNWFilterPtr"),
    'const virNWFilter *':  ('O', "virNWFilter", "virNWFilterPtr", "virNWFilterPtr"),

    'virStreamPtr':  ('O', "virStream", "virStreamPtr", "virStreamPtr"),
    'const virStreamPtr':  ('O', "virStream", "virStreamPtr", "virStreamPtr"),
    'virStream *':  ('O', "virStream", "virStreamPtr", "virStreamPtr"),
    'const virStream *':  ('O', "virStream", "virStreamPtr", "virStreamPtr"),

    'virDomainSnapshotPtr':  ('O', "virDomainSnapshot", "virDomainSnapshotPtr", "virDomainSnapshotPtr"),
    'const virDomainSnapshotPtr':  ('O', "virDomainSnapshot", "virDomainSnapshotPtr", "virDomainSnapshotPtr"),
    'virDomainSnapshot *':  ('O', "virDomainSnapshot", "virDomainSnapshotPtr", "virDomainSnapshotPtr"),
    'const virDomainSnapshot *':  ('O', "virDomainSnapshot", "virDomainSnapshotPtr", "virDomainSnapshotPtr"),
}

py_return_types = {
}

unknown_types = {}

foreign_encoding_args = (
)

#######################################################################
#
#  This part writes the C <-> Python stubs libvirt.[ch] and
#  the table libvirt-export.c to add when registrering the Python module
#
#######################################################################

# Class methods which are written by hand in libvir.c but the Python-level
# code is still automatically generated (so they are not in skip_function()).
skip_impl = (
    'virConnectGetVersion',
    'virConnectGetLibVersion',
    'virConnectListDomainsID',
    'virConnectListDefinedDomains',
    'virConnectListNetworks',
    'virConnectListDefinedNetworks',
    'virConnectListSecrets',
    'virConnectListInterfaces',
    'virConnectListStoragePools',
    'virConnectListDefinedStoragePools',
    'virConnectListStorageVols',
    'virConnectListDefinedStorageVols',
    'virConnectListDefinedInterfaces',
    'virConnectListNWFilters',
    'virDomainSnapshotListNames',
    'virDomainSnapshotListChildrenNames',
    'virConnGetLastError',
    'virGetLastError',
    'virDomainGetInfo',
    'virDomainGetState',
    'virDomainGetControlInfo',
    'virDomainGetBlockInfo',
    'virDomainGetJobInfo',
    'virNodeGetInfo',
    'virDomainGetUUID',
    'virDomainGetUUIDString',
    'virDomainLookupByUUID',
    'virNetworkGetUUID',
    'virNetworkGetUUIDString',
    'virNetworkLookupByUUID',
    'virDomainGetAutostart',
    'virNetworkGetAutostart',
    'virDomainBlockStats',
    'virDomainInterfaceStats',
    'virDomainMemoryStats',
    'virNodeGetCellsFreeMemory',
    'virDomainGetSchedulerType',
    'virDomainGetSchedulerParameters',
    'virDomainGetSchedulerParametersFlags',
    'virDomainSetSchedulerParameters',
    'virDomainSetSchedulerParametersFlags',
    'virDomainSetBlkioParameters',
    'virDomainGetBlkioParameters',
    'virDomainSetMemoryParameters',
    'virDomainGetMemoryParameters',
    'virDomainSetNumaParameters',
    'virDomainGetNumaParameters',
    'virDomainGetVcpus',
    'virDomainPinVcpu',
    'virDomainPinVcpuFlags',
    'virDomainGetVcpuPinInfo',
    'virSecretGetValue',
    'virSecretSetValue',
    'virSecretGetUUID',
    'virSecretGetUUIDString',
    'virSecretLookupByUUID',
    'virNWFilterGetUUID',
    'virNWFilterGetUUIDString',
    'virNWFilterLookupByUUID',
    'virStoragePoolGetUUID',
    'virStoragePoolGetUUIDString',
    'virStoragePoolLookupByUUID',
    'virStoragePoolGetInfo',
    'virStorageVolGetInfo',
    'virStoragePoolGetAutostart',
    'virStoragePoolListVolumes',
    'virDomainBlockPeek',
    'virDomainMemoryPeek',
    'virEventRegisterImpl',
    'virNodeListDevices',
    'virNodeDeviceListCaps',
    'virConnectBaselineCPU',
    'virDomainRevertToSnapshot',
    'virDomainSendKey',
    'virNodeGetCPUStats',
    'virNodeGetMemoryStats',
    'virDomainGetBlockJobInfo',
    'virDomainMigrateGetMaxSpeed',
    'virDomainBlockStatsFlags',
    'virDomainSetBlockIoTune',
    'virDomainGetBlockIoTune',
    'virDomainSetInterfaceParameters',
    'virDomainGetInterfaceParameters',
    'virDomainGetCPUStats',
    'virDomainGetDiskErrors',
)

qemu_skip_impl = (
    'virDomainQemuMonitorCommand',
)


# These are functions which the generator skips completly - no python
# or C code is generated. Generally should not be used for any more
# functions than those already listed
skip_function = (
    'virConnectListDomains', # Python API is called virConectListDomainsID for unknown reasons
    'virConnSetErrorFunc', # Not used in Python API  XXX is this a bug ?
    'virResetError', # Not used in Python API  XXX is this a bug ?
    'virGetVersion', # Python C code is manually written
    'virSetErrorFunc', # Python API is called virRegisterErrorHandler for unknown reasons
    'virConnCopyLastError', # Python API is called virConnGetLastError instead
    'virCopyLastError', # Python API is called virGetLastError instead
    'virConnectOpenAuth', # Python C code is manually written
    'virDefaultErrorFunc', # Python virErrorFuncHandler impl calls this from C
    'virDomainGetSecurityLabel', # Needs investigation...
    'virNodeGetSecurityModel', # Needs investigation...
    'virConnectDomainEventRegister',   # overridden in virConnect.py
    'virConnectDomainEventDeregister', # overridden in virConnect.py
    'virConnectDomainEventRegisterAny',   # overridden in virConnect.py
    'virConnectDomainEventDeregisterAny', # overridden in virConnect.py
    'virSaveLastError', # We have our own python error wrapper
    'virFreeError', # Only needed if we use virSaveLastError

    'virStreamRecvAll', # Pure python libvirt-override-virStream.py
    'virStreamSendAll', # Pure python libvirt-override-virStream.py
    'virStreamRecv', # overridden in libvirt-override-virStream.py
    'virStreamSend', # overridden in libvirt-override-virStream.py

    # 'Ref' functions have no use for bindings users.
    "virConnectRef",
    "virDomainRef",
    "virInterfaceRef",
    "virNetworkRef",
    "virNodeDeviceRef",
    "virSecretRef",
    "virNWFilterRef",
    "virStoragePoolRef",
    "virStorageVolRef",
    'virStreamRef',

    # This functions shouldn't be called via the bindings (and even the docs
    # contain an explicit warning to that effect). The equivalent should be
    # implemented in pure python for each class
    "virDomainGetConnect",
    "virInterfaceGetConnect",
    "virNetworkGetConnect",
    "virSecretGetConnect",
    "virNWFilterGetConnect",
    "virStoragePoolGetConnect",
    "virStorageVolGetConnect",
)

qemu_skip_function = (
    #"virDomainQemuAttach",
)

# Generate C code, but skip python impl
function_skip_python_impl = (
    "virStreamFree", # Needed in custom virStream __del__, but free shouldn't
                     # be exposed in bindings
)

qemu_function_skip_python_impl = ()

function_skip_index_one = (
    "virDomainRevertToSnapshot",
)

def print_function_wrapper(module, name, output, export, include):
    global py_types
    global unknown_types
    global functions
    global qemu_functions
    global skipped_modules
    global function_skip_python_impl

    try:
        if module == "libvirt":
            (desc, ret, args, file, mod, cond) = functions[name]
        if module == "libvirt-qemu":
            (desc, ret, args, file, mod, cond) = qemu_functions[name]
    except:
        print "failed to get function %s infos" % name
        return

    if skipped_modules.has_key(module):
        return 0

    if module == "libvirt":
        if name in skip_function:
            return 0
        if name in skip_impl:
            # Don't delete the function entry in the caller.
            return 1
    elif module == "libvirt-qemu":
        if name in qemu_skip_function:
            return 0
        if name in qemu_skip_impl:
            # Don't delete the function entry in the caller.
            return 1

    c_call = "";
    format=""
    format_args=""
    c_args=""
    c_return=""
    c_convert=""
    num_bufs=0
    for arg in args:
        # This should be correct
        if arg[1][0:6] == "const ":
            arg[1] = arg[1][6:]
        c_args = c_args + "    %s %s;\n" % (arg[1], arg[0])
        if py_types.has_key(arg[1]):
            (f, t, n, c) = py_types[arg[1]]
            if (f == 'z') and (name in foreign_encoding_args) and (num_bufs == 0):
                f = 't#'
            if f != None:
                format = format + f
            if t != None:
                format_args = format_args + ", &pyobj_%s" % (arg[0])
                c_args = c_args + "    PyObject *pyobj_%s;\n" % (arg[0])
                c_convert = c_convert + \
                   "    %s = (%s) Py%s_Get(pyobj_%s);\n" % (arg[0],
                   arg[1], t, arg[0]);
            else:
                format_args = format_args + ", &%s" % (arg[0])
            if f == 't#':
                format_args = format_args + ", &py_buffsize%d" % num_bufs
                c_args = c_args + "    int py_buffsize%d;\n" % num_bufs
                num_bufs = num_bufs + 1
            if c_call != "":
                c_call = c_call + ", ";
            c_call = c_call + "%s" % (arg[0])
        else:
            if skipped_types.has_key(arg[1]):
                return 0
            if unknown_types.has_key(arg[1]):
                lst = unknown_types[arg[1]]
                lst.append(name)
            else:
                unknown_types[arg[1]] = [name]
            return -1
    if format != "":
        format = format + ":%s" % (name)

    if ret[0] == 'void':
        if file == "python_accessor":
            if args[1][1] == "char *":
                c_call = "\n    VIR_FREE(%s->%s);\n" % (
                                 args[0][0], args[1][0], args[0][0], args[1][0])
                c_call = c_call + "    %s->%s = (%s)strdup((const xmlChar *)%s);\n" % (args[0][0],
                                 args[1][0], args[1][1], args[1][0])
            else:
                c_call = "\n    %s->%s = %s;\n" % (args[0][0], args[1][0],
                                                   args[1][0])
        else:
            c_call = "\n    %s(%s);\n" % (name, c_call);
        ret_convert = "    Py_INCREF(Py_None);\n    return Py_None;\n"
    elif py_types.has_key(ret[0]):
        (f, t, n, c) = py_types[ret[0]]
        c_return = "    %s c_retval;\n" % (ret[0])
        if file == "python_accessor" and ret[2] != None:
            c_call = "\n    c_retval = %s->%s;\n" % (args[0][0], ret[2])
        else:
            c_call = "\n    c_retval = %s(%s);\n" % (name, c_call);
        ret_convert = "    py_retval = libvirt_%sWrap((%s) c_retval);\n" % (n,c)
        ret_convert = ret_convert + "    return py_retval;\n"
    elif py_return_types.has_key(ret[0]):
        (f, t, n, c) = py_return_types[ret[0]]
        c_return = "    %s c_retval;\n" % (ret[0])
        c_call = "\n    c_retval = %s(%s);\n" % (name, c_call);
        ret_convert = "    py_retval = libvirt_%sWrap((%s) c_retval);\n" % (n,c)
        ret_convert = ret_convert + "    return py_retval;\n"
    else:
        if skipped_types.has_key(ret[0]):
            return 0
        if unknown_types.has_key(ret[0]):
            lst = unknown_types[ret[0]]
            lst.append(name)
        else:
            unknown_types[ret[0]] = [name]
        return -1

    if cond != None and cond != "":
        include.write("#if %s\n" % cond)
        export.write("#if %s\n" % cond)
        output.write("#if %s\n" % cond)

    include.write("PyObject * ")
    if module == "libvirt":
        include.write("libvirt_%s(PyObject *self, PyObject *args);\n" % (name));
        export.write("    { (char *)\"%s\", libvirt_%s, METH_VARARGS, NULL },\n" %
                     (name, name))
    elif module == "libvirt-qemu":
        include.write("libvirt_qemu_%s(PyObject *self, PyObject *args);\n" % (name));
        export.write("    { (char *)\"%s\", libvirt_qemu_%s, METH_VARARGS, NULL },\n" %
                     (name, name))

    if file == "python":
        # Those have been manually generated
        if cond != None and cond != "":
            include.write("#endif\n");
            export.write("#endif\n");
            output.write("#endif\n");
        return 1
    if file == "python_accessor" and ret[0] != "void" and ret[2] is None:
        # Those have been manually generated
        if cond != None and cond != "":
            include.write("#endif\n");
            export.write("#endif\n");
            output.write("#endif\n");
        return 1

    output.write("PyObject *\n")
    if module == "libvirt":
        output.write("libvirt_%s(PyObject *self ATTRIBUTE_UNUSED," % (name))
    elif module == "libvirt-qemu":
        output.write("libvirt_qemu_%s(PyObject *self ATTRIBUTE_UNUSED," % (name))
    output.write(" PyObject *args")
    if format == "":
        output.write(" ATTRIBUTE_UNUSED")
    output.write(") {\n")
    if ret[0] != 'void':
        output.write("    PyObject *py_retval;\n")
    if c_return != "":
        output.write(c_return)
    if c_args != "":
        output.write(c_args)
    if format != "":
        output.write("\n    if (!PyArg_ParseTuple(args, (char *)\"%s\"%s))\n" %
                     (format, format_args))
        output.write("        return NULL;\n")
    if c_convert != "":
        output.write(c_convert + "\n")

    output.write("    LIBVIRT_BEGIN_ALLOW_THREADS;");
    output.write(c_call);
    output.write("    LIBVIRT_END_ALLOW_THREADS;\n");
    output.write(ret_convert)
    output.write("}\n\n")
    if cond != None and cond != "":
        include.write("#endif /* %s */\n" % cond)
        export.write("#endif /* %s */\n" % cond)
        output.write("#endif /* %s */\n" % cond)

    if module == "libvirt":
        if name in function_skip_python_impl:
            return 0
    elif module == "libvirt-qemu":
        if name in qemu_function_skip_python_impl:
            return 0
    return 1

def buildStubs(module):
    global py_types
    global py_return_types
    global unknown_types

    if module not in ["libvirt", "libvirt-qemu"]:
        print "ERROR: Unknown module type: %s" % module
        return None

    if module == "libvirt":
        funcs = functions
        funcs_failed = functions_failed
        funcs_skipped = functions_skipped
    elif module == "libvirt-qemu":
        funcs = qemu_functions
        funcs_failed = qemu_functions_failed
        funcs_skipped = functions_skipped

    api_xml = "%s-api.xml" % module

    try:
        f = open(os.path.join(srcPref,api_xml))
        data = f.read()
        (parser, target)  = getparser()
        parser.feed(data)
        parser.close()
    except IOError, msg:
        try:
            f = open(os.path.join(srcPref,"..","docs",api_xml))
            data = f.read()
            (parser, target)  = getparser()
            parser.feed(data)
            parser.close()
        except IOError, msg:
            print file, ":", msg
            sys.exit(1)

    n = len(funcs.keys())
    if not quiet:
        print "Found %d functions in %s" % ((n), api_xml)

    override_api_xml = "%s-override-api.xml" % module
    py_types['pythonObject'] = ('O', "pythonObject", "pythonObject", "pythonObject")

    try:
        f = open(os.path.join(srcPref, override_api_xml))
        data = f.read()
        (parser, target)  = getparser()
        parser.feed(data)
        parser.close()
    except IOError, msg:
        print file, ":", msg

    if not quiet:
        # XXX: This is not right, same function already in @functions
        # will be overwritten.
        print "Found %d functions in %s" % ((len(funcs.keys()) - n), override_api_xml)
    nb_wrap = 0
    failed = 0
    skipped = 0

    header_file = "%s.h" % module
    export_file = "%s-export.c" % module
    wrapper_file = "%s.c" % module

    include = open(header_file, "w")
    include.write("/* Generated */\n\n")

    export = open(export_file, "w")
    export.write("/* Generated */\n\n")

    wrapper = open(wrapper_file, "w")
    wrapper.write("/* Generated by generator.py */\n\n")
    wrapper.write("#include <config.h>\n")
    wrapper.write("#include <Python.h>\n")
    wrapper.write("#include <libvirt/" + module + ".h>\n")
    wrapper.write("#include \"typewrappers.h\"\n")
    wrapper.write("#include \"" + module + ".h\"\n\n")

    for function in funcs.keys():
        # Skip the functions which are not for the module
        ret = print_function_wrapper(module, function, wrapper, export, include)
        if ret < 0:
            failed = failed + 1
            funcs_failed.append(function)
            del funcs[function]
        if ret == 0:
            skipped = skipped + 1
            funcs_skipped.append(function)
            del funcs[function]
        if ret == 1:
            nb_wrap = nb_wrap + 1
    include.close()
    export.close()
    wrapper.close()

    if not quiet:
        print "Generated %d wrapper functions" % nb_wrap

    if unknown_types:
        print "Missing type converters: "
        for type in unknown_types.keys():
            print "%s:%d " % (type, len(unknown_types[type])),

    for f in funcs_failed:
        print "ERROR: failed %s" % f

    if failed > 0:
        return -1
    if len(unknown_types) > 0:
        return -1
    return 0

#######################################################################
#
#  This part writes part of the Python front-end classes based on
#  mapping rules between types and classes and also based on function
#  renaming to get consistent function names at the Python level
#
#######################################################################

#
# The type automatically remapped to generated classes
#
classes_type = {
    "virDomainPtr": ("._o", "virDomain(self,_obj=%s)", "virDomain"),
    "virDomain *": ("._o", "virDomain(self, _obj=%s)", "virDomain"),
    "virNetworkPtr": ("._o", "virNetwork(self, _obj=%s)", "virNetwork"),
    "virNetwork *": ("._o", "virNetwork(self, _obj=%s)", "virNetwork"),
    "virInterfacePtr": ("._o", "virInterface(self, _obj=%s)", "virInterface"),
    "virInterface *": ("._o", "virInterface(self, _obj=%s)", "virInterface"),
    "virStoragePoolPtr": ("._o", "virStoragePool(self, _obj=%s)", "virStoragePool"),
    "virStoragePool *": ("._o", "virStoragePool(self, _obj=%s)", "virStoragePool"),
    "virStorageVolPtr": ("._o", "virStorageVol(self, _obj=%s)", "virStorageVol"),
    "virStorageVol *": ("._o", "virStorageVol(self, _obj=%s)", "virStorageVol"),
    "virNodeDevicePtr": ("._o", "virNodeDevice(self, _obj=%s)", "virNodeDevice"),
    "virNodeDevice *": ("._o", "virNodeDevice(self, _obj=%s)", "virNodeDevice"),
    "virSecretPtr": ("._o", "virSecret(self, _obj=%s)", "virSecret"),
    "virSecret *": ("._o", "virSecret(self, _obj=%s)", "virSecret"),
    "virNWFilterPtr": ("._o", "virNWFilter(self, _obj=%s)", "virNWFilter"),
    "virNWFilter *": ("._o", "virNWFilter(self, _obj=%s)", "virNWFilter"),
    "virStreamPtr": ("._o", "virStream(self, _obj=%s)", "virStream"),
    "virStream *": ("._o", "virStream(self, _obj=%s)", "virStream"),
    "virConnectPtr": ("._o", "virConnect(_obj=%s)", "virConnect"),
    "virConnect *": ("._o", "virConnect(_obj=%s)", "virConnect"),
    "virDomainSnapshotPtr": ("._o", "virDomainSnapshot(self,_obj=%s)", "virDomainSnapshot"),
    "virDomainSnapshot *": ("._o", "virDomainSnapshot(self, _obj=%s)", "virDomainSnapshot"),
}

converter_type = {
}

primary_classes = ["virDomain", "virNetwork", "virInterface",
                   "virStoragePool", "virStorageVol",
                   "virConnect", "virNodeDevice", "virSecret",
                   "virNWFilter", "virStream", "virDomainSnapshot"]

classes_ancestor = {
}

classes_destructors = {
    "virDomain": "virDomainFree",
    "virNetwork": "virNetworkFree",
    "virInterface": "virInterfaceFree",
    "virStoragePool": "virStoragePoolFree",
    "virStorageVol": "virStorageVolFree",
    "virNodeDevice" : "virNodeDeviceFree",
    "virSecret": "virSecretFree",
    "virNWFilter": "virNWFilterFree",
    "virDomainSnapshot": "virDomainSnapshotFree",
    # We hand-craft __del__ for this one
    #"virStream": "virStreamFree",
}

class_skip_connect_impl = {
    "virConnect" : True,
    "virDomainSnapshot": True,
}

class_domain_impl = {
    "virDomainSnapshot": True,
}

functions_noexcept = {
    'virDomainGetID': True,
    'virDomainGetName': True,
    'virNetworkGetName': True,
    'virInterfaceGetName': True,
    'virStoragePoolGetName': True,
    'virStorageVolGetName': True,
    'virStorageVolGetkey': True,
    'virNodeDeviceGetName': True,
    'virNodeDeviceGetParent': True,
    'virSecretGetUsageType': True,
    'virSecretGetUsageID': True,
    'virNWFilterGetName': True,
}

reference_keepers = {
}

function_classes = {}

function_classes["None"] = []

function_post = {}

# Functions returning an integral type which need special rules to
# check for errors and raise exceptions.
functions_int_exception_test = {
    'virDomainGetMaxMemory': "%s == 0",
}
functions_int_default_test = "%s == -1"

def is_integral_type (name):
    return not re.search ("^(unsigned)? ?(int|long)$", name) is None

# Functions returning lists which need special rules to check for errors
# and raise exceptions.
functions_list_exception_test = {
}
functions_list_default_test = "%s is None"

def is_list_type (name):
    whitelist = [ "virDomainBlockStats",
                  "virDomainInterfaceStats" ]

    return name[-1:] == "*" or name in whitelist

def nameFixup(name, classe, type, file):
    # avoid a desastrous clash
    listname = classe + "List"
    ll = len(listname)
    l = len(classe)
    if name[0:l] == listname:
        func = name[l:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:16] == "virNetworkDefine":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:19] == "virNetworkCreateXML":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:16] == "virNetworkLookup":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:18] == "virInterfaceDefine":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:21] == "virInterfaceCreateXML":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:18] == "virInterfaceLookup":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:15] == "virSecretDefine":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:15] == "virSecretLookup":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:17] == "virNWFilterDefine":
        func = name[3:]
        func = string.lower(func[0:3]) + func[3:]
    elif name[0:17] == "virNWFilterLookup":
        func = name[3:]
        func = string.lower(func[0:3]) + func[3:]
    elif name[0:20] == "virStoragePoolDefine":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:23] == "virStoragePoolCreateXML":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:20] == "virStoragePoolLookup":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:19] == "virStorageVolDefine":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:19] == "virStorageVolLookup":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:20] == "virDomainGetCPUStats":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:12] == "virDomainGet":
        func = name[12:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:29] == "virDomainSnapshotLookupByName":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:26] == "virDomainSnapshotListNames":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:28] == "virDomainSnapshotNumChildren":
        func = name[17:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:20] == "virDomainSnapshotNum":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:26] == "virDomainSnapshotCreateXML":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:24] == "virDomainSnapshotCurrent":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:17] == "virDomainSnapshot":
        func = name[17:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:9] == "virDomain":
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:13] == "virNetworkGet":
        func = name[13:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:10] == "virNetwork":
        func = name[10:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:15] == "virInterfaceGet":
        func = name[15:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:12] == "virInterface":
        func = name[12:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:12] == 'virSecretGet':
        func = name[12:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:9] == 'virSecret':
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:14] == 'virNWFilterGet':
        func = name[14:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:11] == 'virNWFilter':
        func = name[11:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:12] == 'virStreamNew':
        func = "newStream"
    elif name[0:9] == 'virStream':
        func = name[9:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:17] == "virStoragePoolGet":
        func = name[17:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:14] == "virStoragePool":
        func = name[14:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:16] == "virStorageVolGet":
        func = name[16:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:13] == "virStorageVol":
        func = name[13:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:13] == "virNodeDevice":
        if name[13:16] == "Get":
            func = string.lower(name[16]) + name[17:]
        elif name[13:19] == "Lookup" or name[13:19] == "Create":
            func = string.lower(name[3]) + name[4:]
        else:
            func = string.lower(name[13]) + name[14:]
    elif name[0:7] == "virNode":
        func = name[7:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:10] == "virConnect":
        func = name[10:]
        func = string.lower(func[0:1]) + func[1:]
    elif name[0:3] == "xml":
        func = name[3:]
        func = string.lower(func[0:1]) + func[1:]
    else:
        func = name
    if func == "iD":
        func = "ID"
    if func == "uUID":
        func = "UUID"
    if func == "uUIDString":
        func = "UUIDString"
    if func == "oSType":
        func = "OSType"
    if func == "xMLDesc":
        func = "XMLDesc"
    if func == "mACString":
        func = "MACString"

    return func


def functionCompare(info1, info2):
    (index1, func1, name1, ret1, args1, file1, mod1) = info1
    (index2, func2, name2, ret2, args2, file2, mod2) = info2
    if file1 == file2:
        if func1 < func2:
            return -1
        if func1 > func2:
            return 1
    if file1 == "python_accessor":
        return -1
    if file2 == "python_accessor":
        return 1
    if file1 < file2:
        return -1
    if file1 > file2:
        return 1
    return 0

def writeDoc(module, name, args, indent, output):
     if module == "libvirt":
         funcs = functions
     elif module == "libvirt-qemu":
         funcs = qemu_functions
     if funcs[name][0] is None or funcs[name][0] == "":
         return
     val = funcs[name][0]
     val = string.replace(val, "NULL", "None");
     output.write(indent)
     output.write('"""')
     i = string.find(val, "\n")
     while i >= 0:
         str = val[0:i+1]
         val = val[i+1:]
         output.write(str)
         i = string.find(val, "\n")
         output.write(indent)
     output.write(val)
     output.write(' """\n')

def buildWrappers(module):
    global ctypes
    global py_types
    global py_return_types
    global unknown_types
    global functions
    global function_classes
    global classes_type
    global classes_list
    global converter_type
    global primary_classes
    global converter_type
    global classes_ancestor
    global converter_type
    global primary_classes
    global classes_destructors
    global functions_noexcept

    if not module == "libvirt":
        print "ERROR: Unknown module type: %s" % module
        return None

    for type in classes_type.keys():
        function_classes[classes_type[type][2]] = []

    #
    # Build the list of C types to look for ordered to start
    # with primary classes
    #
    ctypes = []
    classes_list = []
    ctypes_processed = {}
    classes_processed = {}
    for classe in primary_classes:
        classes_list.append(classe)
        classes_processed[classe] = ()
        for type in classes_type.keys():
            tinfo = classes_type[type]
            if tinfo[2] == classe:
                ctypes.append(type)
                ctypes_processed[type] = ()
    for type in classes_type.keys():
        if ctypes_processed.has_key(type):
            continue
        tinfo = classes_type[type]
        if not classes_processed.has_key(tinfo[2]):
            classes_list.append(tinfo[2])
            classes_processed[tinfo[2]] = ()

        ctypes.append(type)
        ctypes_processed[type] = ()

    for name in functions.keys():
        found = 0;
        (desc, ret, args, file, mod, cond) = functions[name]
        for type in ctypes:
            classe = classes_type[type][2]

            if name[0:3] == "vir" and len(args) >= 1 and args[0][1] == type:
                found = 1
                func = nameFixup(name, classe, type, file)
                info = (0, func, name, ret, args, file, mod)
                function_classes[classe].append(info)
            elif name[0:3] == "vir" and len(args) >= 2 and args[1][1] == type \
                and file != "python_accessor" and not name in function_skip_index_one:
                found = 1
                func = nameFixup(name, classe, type, file)
                info = (1, func, name, ret, args, file, mod)
                function_classes[classe].append(info)
        if found == 1:
            continue
        func = nameFixup(name, "None", file, file)
        info = (0, func, name, ret, args, file, mod)
        function_classes['None'].append(info)

    classes_file = "%s.py" % module
    extra_file = os.path.join(srcPref, "%s-override.py" % module)
    extra = None

    classes = open(classes_file, "w")

    if os.path.exists(extra_file):
        extra = open(extra_file, "r")
    classes.write("#! " + python + " -i\n")
    classes.write("#\n")
    classes.write("# WARNING WARNING WARNING WARNING\n")
    classes.write("#\n")
    classes.write("# This file is automatically written by generator.py. Any changes\n")
    classes.write("# made here will be lost.\n")
    classes.write("#\n")
    classes.write("# To change the manually written methods edit " + module + "-override.py\n")
    classes.write("# To change the automatically written methods edit generator.py\n")
    classes.write("#\n")
    classes.write("# WARNING WARNING WARNING WARNING\n")
    classes.write("#\n")
    if extra != None:
        classes.writelines(extra.readlines())
    classes.write("#\n")
    classes.write("# WARNING WARNING WARNING WARNING\n")
    classes.write("#\n")
    classes.write("# Automatically written part of python bindings for libvirt\n")
    classes.write("#\n")
    classes.write("# WARNING WARNING WARNING WARNING\n")
    if extra != None:
        extra.close()

    if function_classes.has_key("None"):
        flist = function_classes["None"]
        flist.sort(functionCompare)
        oldfile = ""
        for info in flist:
            (index, func, name, ret, args, file, mod) = info
            if file != oldfile:
                classes.write("#\n# Functions from module %s\n#\n\n" % file)
                oldfile = file
            classes.write("def %s(" % func)
            n = 0
            for arg in args:
                if n != 0:
                    classes.write(", ")
                classes.write("%s" % arg[0])
                n = n + 1
            classes.write("):\n")
            writeDoc(module, name, args, '    ', classes);

            for arg in args:
                if classes_type.has_key(arg[1]):
                    classes.write("    if %s is None: %s__o = None\n" %
                                  (arg[0], arg[0]))
                    classes.write("    else: %s__o = %s%s\n" %
                                  (arg[0], arg[0], classes_type[arg[1]][0]))
            if ret[0] != "void":
                classes.write("    ret = ");
            else:
                classes.write("    ");
            classes.write("libvirtmod.%s(" % name)
            n = 0
            for arg in args:
                if n != 0:
                    classes.write(", ");
                classes.write("%s" % arg[0])
                if classes_type.has_key(arg[1]):
                    classes.write("__o");
                n = n + 1
            classes.write(")\n");

            if ret[0] != "void":
                if classes_type.has_key(ret[0]):
                    #
                    # Raise an exception
                    #
                    if functions_noexcept.has_key(name):
                        classes.write("    if ret is None:return None\n");
                    else:
                        classes.write(
                     "    if ret is None:raise libvirtError('%s() failed')\n" %
                                      (name))

                    classes.write("    return ");
                    classes.write(classes_type[ret[0]][1] % ("ret"));
                    classes.write("\n");

                # For functions returning an integral type there are
                # several things that we can do, depending on the
                # contents of functions_int_*:
                elif is_integral_type (ret[0]):
                    if not functions_noexcept.has_key (name):
                        if functions_int_exception_test.has_key (name):
                            test = functions_int_exception_test[name]
                        else:
                            test = functions_int_default_test
                        classes.write (("    if " + test +
                                        ": raise libvirtError ('%s() failed')\n") %
                                       ("ret", name))
                    classes.write("    return ret\n")

                elif is_list_type (ret[0]):
                    if not functions_noexcept.has_key (name):
                        if functions_list_exception_test.has_key (name):
                            test = functions_list_exception_test[name]
                        else:
                            test = functions_list_default_test
                        classes.write (("    if " + test +
                                        ": raise libvirtError ('%s() failed')\n") %
                                       ("ret", name))
                    classes.write("    return ret\n")

                else:
                    classes.write("    return ret\n")

            classes.write("\n");

    for classname in classes_list:
        if classname == "None":
            pass
        else:
            if classes_ancestor.has_key(classname):
                classes.write("class %s(%s):\n" % (classname,
                              classes_ancestor[classname]))
                classes.write("    def __init__(self, _obj=None):\n")
                if reference_keepers.has_key(classname):
                    rlist = reference_keepers[classname]
                    for ref in rlist:
                        classes.write("        self.%s = None\n" % ref[1])
                classes.write("        self._o = _obj\n")
                classes.write("        %s.__init__(self, _obj=_obj)\n\n" % (
                              classes_ancestor[classname]))
            else:
                classes.write("class %s:\n" % (classname))
                if classname in [ "virDomain", "virNetwork", "virInterface", "virStoragePool",
                                  "virStorageVol", "virNodeDevice", "virSecret","virStream",
                                  "virNWFilter" ]:
                    classes.write("    def __init__(self, conn, _obj=None):\n")
                elif classname in [ 'virDomainSnapshot' ]:
                    classes.write("    def __init__(self, dom, _obj=None):\n")
                else:
                    classes.write("    def __init__(self, _obj=None):\n")
                if reference_keepers.has_key(classname):
                    list = reference_keepers[classname]
                    for ref in list:
                        classes.write("        self.%s = None\n" % ref[1])
                if classname in [ "virDomain", "virNetwork", "virInterface",
                                  "virNodeDevice", "virSecret", "virStream",
                                  "virNWFilter" ]:
                    classes.write("        self._conn = conn\n")
                elif classname in [ "virStorageVol", "virStoragePool" ]:
                    classes.write("        self._conn = conn\n" + \
                                  "        if not isinstance(conn, virConnect):\n" + \
                                  "            self._conn = conn._conn\n")
                elif classname in [ "virDomainSnapshot" ]:
                    classes.write("        self._dom = dom\n")
                classes.write("        if _obj != None:self._o = _obj;return\n")
                classes.write("        self._o = None\n\n");
            destruct=None
            if classes_destructors.has_key(classname):
                classes.write("    def __del__(self):\n")
                classes.write("        if self._o != None:\n")
                classes.write("            libvirtmod.%s(self._o)\n" %
                              classes_destructors[classname]);
                classes.write("        self._o = None\n\n");
                destruct=classes_destructors[classname]

            if not class_skip_connect_impl.has_key(classname):
                # Build python safe 'connect' method
                classes.write("    def connect(self):\n")
                classes.write("        return self._conn\n\n")

            if class_domain_impl.has_key(classname):
                classes.write("    def domain(self):\n")
                classes.write("        return self._dom\n\n")

            flist = function_classes[classname]
            flist.sort(functionCompare)
            oldfile = ""
            for info in flist:
                (index, func, name, ret, args, file, mod) = info
                #
                # Do not provide as method the destructors for the class
                # to avoid double free
                #
                if name == destruct:
                    continue;
                if file != oldfile:
                    if file == "python_accessor":
                        classes.write("    # accessors for %s\n" % (classname))
                    else:
                        classes.write("    #\n")
                        classes.write("    # %s functions from module %s\n" % (
                                      classname, file))
                        classes.write("    #\n\n")
                oldfile = file
                classes.write("    def %s(self" % func)
                n = 0
                for arg in args:
                    if n != index:
                        classes.write(", %s" % arg[0])
                    n = n + 1
                classes.write("):\n")
                writeDoc(module, name, args, '        ', classes);
                n = 0
                for arg in args:
                    if classes_type.has_key(arg[1]):
                        if n != index:
                            classes.write("        if %s is None: %s__o = None\n" %
                                          (arg[0], arg[0]))
                            classes.write("        else: %s__o = %s%s\n" %
                                          (arg[0], arg[0], classes_type[arg[1]][0]))
                    n = n + 1
                if ret[0] != "void":
                    classes.write("        ret = ");
                else:
                    classes.write("        ");
                n = 0
                classes.write("libvirtmod.%s(" % name)
                for arg in args:
                    if n != 0:
                        classes.write(", ");
                    if n != index:
                        classes.write("%s" % arg[0])
                        if classes_type.has_key(arg[1]):
                            classes.write("__o");
                    else:
                        classes.write("self");
                        if classes_type.has_key(arg[1]):
                            classes.write(classes_type[arg[1]][0])
                    n = n + 1
                classes.write(")\n");

                if name == "virConnectClose":
                    classes.write("        self._o = None\n")

                # For functions returning object types:
                if ret[0] != "void":
                    if classes_type.has_key(ret[0]):
                        #
                        # Raise an exception
                        #
                        if functions_noexcept.has_key(name):
                            classes.write(
                                "        if ret is None:return None\n");
                        else:
                            if classname == "virConnect":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', conn=self)\n" %
                                              (name))
                            elif classname == "virDomain":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', dom=self)\n" %
                                              (name))
                            elif classname == "virNetwork":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', net=self)\n" %
                                              (name))
                            elif classname == "virInterface":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', net=self)\n" %
                                              (name))
                            elif classname == "virStoragePool":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', pool=self)\n" %
                                              (name))
                            elif classname == "virStorageVol":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', vol=self)\n" %
                                              (name))
                            elif classname == "virDomainSnapshot":
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed', dom=self._dom)\n" %
                                              (name))
                            else:
                                classes.write(
                     "        if ret is None:raise libvirtError('%s() failed')\n" %
                                              (name))

                        #
                        # generate the returned class wrapper for the object
                        #
                        classes.write("        __tmp = ");
                        classes.write(classes_type[ret[0]][1] % ("ret"));
                        classes.write("\n");

                        #
                        # Sometime one need to keep references of the source
                        # class in the returned class object.
                        # See reference_keepers for the list
                        #
                        tclass = classes_type[ret[0]][2]
                        if reference_keepers.has_key(tclass):
                            list = reference_keepers[tclass]
                            for pref in list:
                                if pref[0] == classname:
                                    classes.write("        __tmp.%s = self\n" %
                                                  pref[1])

                        # Post-processing - just before we return.
                        if function_post.has_key(name):
                            classes.write("        %s\n" %
                                          (function_post[name]));

                        #
                        # return the class
                        #
                        classes.write("        return __tmp\n");
                    elif converter_type.has_key(ret[0]):
                        #
                        # Raise an exception
                        #
                        if functions_noexcept.has_key(name):
                            classes.write(
                                "        if ret is None:return None");

                        # Post-processing - just before we return.
                        if function_post.has_key(name):
                            classes.write("        %s\n" %
                                          (function_post[name]));

                        classes.write("        return ");
                        classes.write(converter_type[ret[0]] % ("ret"));
                        classes.write("\n");

                    # For functions returning an integral type there
                    # are several things that we can do, depending on
                    # the contents of functions_int_*:
                    elif is_integral_type (ret[0]):
                        if not functions_noexcept.has_key (name):
                            if functions_int_exception_test.has_key (name):
                                test = functions_int_exception_test[name]
                            else:
                                test = functions_int_default_test
                            if classname == "virConnect":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', conn=self)\n") %
                                               ("ret", name))
                            elif classname == "virDomain":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', dom=self)\n") %
                                               ("ret", name))
                            elif classname == "virNetwork":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', net=self)\n") %
                                               ("ret", name))
                            elif classname == "virInterface":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', net=self)\n") %
                                               ("ret", name))
                            elif classname == "virStoragePool":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', pool=self)\n") %
                                               ("ret", name))
                            elif classname == "virStorageVol":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', vol=self)\n") %
                                               ("ret", name))
                            else:
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed')\n") %
                                               ("ret", name))

                        # Post-processing - just before we return.
                        if function_post.has_key(name):
                            classes.write("        %s\n" %
                                          (function_post[name]));

                        classes.write ("        return ret\n")

                    elif is_list_type (ret[0]):
                        if not functions_noexcept.has_key (name):
                            if functions_list_exception_test.has_key (name):
                                test = functions_list_exception_test[name]
                            else:
                                test = functions_list_default_test
                            if classname == "virConnect":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', conn=self)\n") %
                                               ("ret", name))
                            elif classname == "virDomain":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', dom=self)\n") %
                                               ("ret", name))
                            elif classname == "virNetwork":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', net=self)\n") %
                                               ("ret", name))
                            elif classname == "virInterface":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', net=self)\n") %
                                               ("ret", name))
                            elif classname == "virStoragePool":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', pool=self)\n") %
                                               ("ret", name))
                            elif classname == "virStorageVol":
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed', vol=self)\n") %
                                               ("ret", name))
                            else:
                                classes.write (("        if " + test +
                                                ": raise libvirtError ('%s() failed')\n") %
                                               ("ret", name))

                        # Post-processing - just before we return.
                        if function_post.has_key(name):
                            classes.write("        %s\n" %
                                          (function_post[name]));

                        classes.write ("        return ret\n")

                    else:
                        # Post-processing - just before we return.
                        if function_post.has_key(name):
                            classes.write("        %s\n" %
                                          (function_post[name]));

                        classes.write("        return ret\n");

                classes.write("\n");
            # Append "<classname>.py" to class def, iff it exists
            try:
                extra = open(os.path.join(srcPref,"libvirt-override-" + classname + ".py"), "r")
                classes.write ("    #\n")
                classes.write ("    # %s methods from %s.py (hand coded)\n" % (classname,classname))
                classes.write ("    #\n")
                classes.writelines(extra.readlines())
                classes.write("\n")
                extra.close()
            except:
                pass

    #
    # Generate enum constants
    #
    for type,enum in enums.items():
        classes.write("# %s\n" % type)
        items = enum.items()
        items.sort(lambda i1,i2: cmp(long(i1[1]),long(i2[1])))
        for name,value in items:
            classes.write("%s = %s\n" % (name,value))
        classes.write("\n");

    classes.close()

def qemuBuildWrappers(module):
    global qemu_functions

    if not module == "libvirt-qemu":
        print "ERROR: only libvirt-qemu is supported"
        return None

    extra_file = os.path.join(srcPref, "%s-override.py" % module)
    extra = None

    fd = open("libvirt_qemu.py", "w")

    if os.path.exists(extra_file):
        extra = open(extra_file, "r")
    fd.write("#! " + python + " -i\n")
    fd.write("#\n")
    fd.write("# WARNING WARNING WARNING WARNING\n")
    fd.write("#\n")
    fd.write("# This file is automatically written by generator.py. Any changes\n")
    fd.write("# made here will be lost.\n")
    fd.write("#\n")
    fd.write("# To change the manually written methods edit " + module + "-override.py\n")
    fd.write("# To change the automatically written methods edit generator.py\n")
    fd.write("#\n")
    fd.write("# WARNING WARNING WARNING WARNING\n")
    fd.write("#\n")
    if extra != None:
        fd.writelines(extra.readlines())
    fd.write("#\n")
    fd.write("# WARNING WARNING WARNING WARNING\n")
    fd.write("#\n")
    fd.write("# Automatically written part of python bindings for libvirt\n")
    fd.write("#\n")
    fd.write("# WARNING WARNING WARNING WARNING\n")
    if extra != None:
        extra.close()

    fd.write("try:\n")
    fd.write("    import libvirtmod_qemu\n")
    fd.write("except ImportError, lib_e:\n")
    fd.write("    try:\n")
    fd.write("        import cygvirtmod_qemu as libvirtmod_qemu\n")
    fd.write("    except ImportError, cyg_e:\n")
    fd.write("        if str(cyg_e).count(\"No module named\"):\n")
    fd.write("            raise lib_e\n\n")

    fd.write("import libvirt\n\n");
    fd.write("#\n# Functions from module %s\n#\n\n" % module)
    #
    # Generate functions directly, no classes
    #
    for name in qemu_functions.keys():
        func = nameFixup(name, 'None', None, None)
        (desc, ret, args, file, mod, cond) = qemu_functions[name]
        fd.write("def %s(" % func)
        n = 0
        for arg in args:
            if n != 0:
                fd.write(", ")
            fd.write("%s" % arg[0])
            n = n + 1
        fd.write("):\n")
        writeDoc(module, name, args, '    ', fd);

        if ret[0] != "void":
            fd.write("    ret = ");
        else:
            fd.write("    ");
        fd.write("libvirtmod_qemu.%s(" % name)
        n = 0

        conn = None

        for arg in args:
            if arg[1] == "virConnectPtr":
                conn = arg[0]

            if n != 0:
                fd.write(", ");
            if arg[1] in ["virDomainPtr", "virConnectPtr"]:
                # FIXME: This might have problem if the function
                # has multiple args which are objects.
                fd.write("%s.%s" % (arg[0], "_o"))
            else:
                fd.write("%s" % arg[0])
            n = n + 1
        fd.write(")\n");

        if ret[0] != "void":
            fd.write("    if ret is None: raise libvirt.libvirtError('" + name + "() failed')\n")
            if ret[0] == "virDomainPtr":
                fd.write("    __tmp = virDomain(" + conn + ",_obj=ret)\n")
                fd.write("    return __tmp\n")
            else:
                fd.write("    return ret\n")

        fd.write("\n")

    #
    # Generate enum constants
    #
    for type,enum in qemu_enums.items():
        fd.write("# %s\n" % type)
        items = enum.items()
        items.sort(lambda i1,i2: cmp(long(i1[1]),long(i2[1])))
        for name,value in items:
            fd.write("%s = %s\n" % (name,value))
        fd.write("\n");

    fd.close()


quiet = 0
if buildStubs("libvirt") < 0:
    sys.exit(1)
if buildStubs("libvirt-qemu") < 0:
    sys.exit(1)
buildWrappers("libvirt")
qemuBuildWrappers("libvirt-qemu")
sys.exit(0)
