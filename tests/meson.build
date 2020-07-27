tests_dep = declare_dependency(
  compile_args: [
    '-Dabs_builddir="@0@"'.format(meson.current_build_dir()),
    '-Dabs_top_builddir="@0@"'.format(meson.build_root()),
    '-Dabs_srcdir="@0@"'.format(meson.current_source_dir()),
    '-Dabs_top_srcdir="@0@"'.format(meson.source_root()),
  ] + coverage_flags + cc_flags_relaxed_frame_limit,
  dependencies: [
    apparmor_dep,
    dlopen_dep,
    glib_dep,
    gnutls_dep,
    libnl_dep,
    libxml_dep,
    rpc_dep,
    sasl_dep,
    selinux_dep,
    xdr_dep,
    yajl_dep,
  ],
  include_directories: [
    conf_inc_dir,
    hypervisor_inc_dir,
    libvirt_inc,
    src_inc_dir,
    top_inc_dir,
    util_inc_dir,
  ],
  link_args: libvirt_export_dynamic,
)

tests_env = [
  'abs_builddir=@0@'.format(meson.current_build_dir()),
  'abs_srcdir=@0@'.format(meson.current_source_dir()),
  'abs_top_builddir=@0@'.format(meson.build_root()),
  'abs_top_srcdir=@0@'.format(meson.source_root()),
  'LC_ALL=C',
  'LIBVIRT_AUTOSTART=0',
]

if use_expensive_tests
  tests_env += 'VIR_TEST_EXPENSIVE=1'
else
  tests_env += 'VIR_TEST_EXPENSIVE=0'
endif


# mock_libs:
#   each entry is a dictionary with following items:
#   * name - mock library name which is also used as default source file name (required)
#   * sources - override default sources based on name (optional, default [])
#   * deps - additional dependencies (optional, default [])

mock_libs = [
  { 'name': 'domaincapsmock' },
  { 'name': 'shunload', 'sources': [ 'shunloadhelper.c' ] },
  { 'name': 'vircgroupmock' },
  { 'name': 'virdeterministichashmock' },
  { 'name': 'virfilecachemock' },
  { 'name': 'virhostcpumock' },
  { 'name': 'virhostdevmock' },
  { 'name': 'virnetdaemonmock' },
  { 'name': 'virnetdevmock' },
  { 'name': 'virnetserverclientmock' },
  { 'name': 'virpcimock' },
  { 'name': 'virportallocatormock' },
  { 'name': 'virprocessmock' },
  { 'name': 'virrandommock' },
]

if host_machine.system() == 'linux'
  mock_libs += [
    { 'name': 'virfilemock' },
    { 'name': 'virnetdevbandwidthmock' },
    { 'name': 'virnumamock' },
    { 'name': 'virtestmock' },
    { 'name': 'virusbmock' },
  ]
endif

if conf.has('WITH_BHYVE')
  mock_libs += [
    { 'name': 'bhyveargv2xmlmock' },
    { 'name': 'bhyvexml2argvmock' },
  ]
endif

if conf.has('WITH_DBUS')
  mock_libs += [
    { 'name': 'virdbusmock', 'deps': [ dbus_dep ] },
  ]
endif

if conf.has('WITH_LIBXL')
  mock_libs += [
    { 'name': 'xlmock', 'sources': [ 'libxlmock.c' ], 'deps': [ libxl_dep ] },
  ]
endif

if conf.has('WITH_NSS')
  mock_libs += [
    { 'name': 'nssmock' },
  ]
endif

if conf.has('WITH_QEMU')
  mock_libs += [
    { 'name': 'qemucaps2xmlmock' },
    { 'name': 'qemucapsprobemock' },
    { 'name': 'qemucpumock' },
    { 'name': 'qemuhotplugmock' },
    { 'name': 'qemuxml2argvmock' },
  ]
endif

if conf.has('WITH_SECDRIVER_SELINUX')
  mock_libs += [
    { 'name': 'securityselinuxhelper' },
  ]
endif

foreach mock : mock_libs
  shared_module(
    mock['name'],
    mock.get('sources', [ '@0@.c'.format(mock['name']) ]),
    dependencies: [
      tests_dep,
      mock.get('deps', []),
    ],
    link_with: [
      libvirt_lib,
    ],
  )
endforeach


# build libraries used by tests

test_utils_lib = static_library(
  'test_utils',
  [ 'testutils.c' ],
  dependencies: [ tests_dep ],
)

if conf.has('WITH_LIBXL')
  test_utils_xen_lib = static_library(
    'test_utils_xen',
    [ 'testutilsxen.c' ],
    dependencies: [ tests_dep ],
  )

  test_xen_driver_lib = shared_library(
    'test_xen_driver',
    link_whole: [ libxl_driver_imp ],
    link_with: [ libvirt_lib ],
  )
else
  test_utils_xen_lib = []
  test_xen_driver_lib = []
endif

if conf.has('WITH_LXC')
  test_utils_lxc_lib = static_library(
    'test_utils_lxc',
    [ 'testutilslxc.c' ],
    dependencies: [ tests_dep ],
  )
else
  test_utils_lxc_lib = []
endif

if conf.has('WITH_QEMU')
  test_utils_qemu_lib = static_library(
    'test_utils_qemu',
    [ 'testutilsqemu.c' ],
    dependencies: [ tests_dep ],
  )

  test_utils_qemu_monitor_lib = static_library(
    'test_utils_qemu_monitor',
    [ 'qemumonitortestutils.c', 'testutilsqemuschema.c' ],
    dependencies: [ tests_dep ],
  )

  test_qemu_driver_lib = shared_library(
    'test_qemu_driver',
    [ qemu_dtrace_gen_objects ],
    link_whole: [ qemu_driver_impl ],
    link_with: [ libvirt_lib ],
  )
else
  test_qemu_driver_lib = []
  test_utils_qemu_lib = []
  test_utils_qemu_monitor_lib = []
endif

test_file_wrapper_lib = static_library(
  'test_file_wrapper',
  [ 'virfilewrapper.c' ],
  dependencies: [ tests_dep ],
)


# build helpers used by tests

# Must not link to any libvirt modules - libc only otherwise external
# libraries might unexpectedly leak file descriptors into commandhelper
# invalidating the test logic assumptions.
executable(
  'commandhelper',
  [ 'commandhelper.c' ],
  dependencies: [
    tests_dep,
  ],
  link_args: [
    libvirt_no_indirect,
  ],
)

# This is a fake SSH we use from virnetsockettest
executable(
  'ssh',
  [ 'ssh.c' ],
  dependencies: [
    tests_dep,
  ],
  link_args: [
    coverage_flags,
  ],
)


# build and define libvirt tests

# tests:
#   each entry is a dictionary with following items:
#   * name - name of the test which is also used as default source file name (required)
#   * sources - override default sources based on name (optional, default [ '$name.c' ])
#   * c_args - args used by test (optional, default [])
#   * deps - additional dependencies (optional, default [])
#   * include - include_directories (optional, default [])
#   * link_with - compiled libraries to link with (optional, default [])
#   * link_whole - compiled libraries to link whole (optional, default [])

tests = []

cputest_link_with = []
cputest_link_whole = []
if conf.has('WITH_QEMU')
  cputest_link_with += [ test_utils_qemu_monitor_lib, test_qemu_driver_lib ]
  cputest_link_whole += [ test_utils_qemu_lib ]
endif

domaincapstest_link_with = []
domaincapstest_link_whole = [ test_file_wrapper_lib ]
if conf.has('WITH_BHYVE')
  domaincapstest_link_with += [ bhyve_driver_impl ]
endif
if conf.has('WITH_LIBXL')
  domaincapstest_link_with += [ test_xen_driver_lib ]
  domaincapstest_link_whole += [ test_utils_xen_lib ]
endif
if conf.has('WITH_QEMU')
  domaincapstest_link_with += [ test_qemu_driver_lib ]
  domaincapstest_link_whole += [ test_utils_qemu_lib ]
endif

vircapstest_link_with = []
vircapstest_link_whole = []
vircapstest_sources = [ 'vircapstest.c' ]
if conf.has('WITH_LXC')
  vircapstest_link_with += [ lxc_driver_impl_lib ]
  vircapstest_link_whole += [ test_utils_lxc_lib ]
endif
if conf.has('WITH_QEMU')
  vircapstest_link_with += [ qemu_driver_impl ]
  vircapstest_link_whole += [ test_utils_qemu_lib ]
  vircapstest_sources += [ qemu_dtrace_gen_objects ]
endif

tests += [
  { 'name': 'commandtest' },
  { 'name': 'cputest', 'link_with': cputest_link_with, 'link_whole': cputest_link_whole },
  { 'name': 'domaincapstest', 'link_with': domaincapstest_link_with, 'link_whole': domaincapstest_link_whole },
  { 'name': 'domainconftest' },
  { 'name': 'genericxml2xmltest' },
  { 'name': 'interfacexml2xmltest' },
  { 'name': 'metadatatest' },
  { 'name': 'networkxml2xmlupdatetest' },
  { 'name': 'nodedevxml2xmltest' },
  { 'name': 'nwfilterxml2xmltest' },
  { 'name': 'objecteventtest' },
  { 'name': 'seclabeltest' },
  { 'name': 'secretxml2xmltest' },
  { 'name': 'shunloadtest', 'deps': [ thread_dep ] },
  { 'name': 'sockettest' },
  { 'name': 'storagevolxml2xmltest' },
  { 'name': 'sysinfotest' },
  { 'name': 'utiltest' },
  { 'name': 'viralloctest' },
  { 'name': 'virauthconfigtest' },
  { 'name': 'virbitmaptest' },
  { 'name': 'virbuftest' },
  { 'name': 'vircapstest', 'sources': vircapstest_sources, 'link_with': vircapstest_link_with, 'link_whole': vircapstest_link_whole },
  { 'name': 'vircgrouptest' },
  { 'name': 'virconftest' },
  { 'name': 'vircryptotest' },
  { 'name': 'virendiantest' },
  { 'name': 'virerrortest' },
  { 'name': 'virfilecachetest' },
  { 'name': 'virfiletest' },
  { 'name': 'virfirewalltest', 'deps': [ dbus_dep ] },
  { 'name': 'virhashtest' },
  { 'name': 'virhostcputest', 'link_whole': [ test_file_wrapper_lib ] },
  { 'name': 'virhostdevtest' },
  { 'name': 'viriscsitest' },
  { 'name': 'virkeycodetest' },
  { 'name': 'virkmodtest' },
  { 'name': 'virlockspacetest' },
  { 'name': 'virlogtest' },
  { 'name': 'virnetdevtest' },
  { 'name': 'virnetworkportxml2xmltest' },
  { 'name': 'virnwfilterbindingxml2xmltest' },
  { 'name': 'virpcitest' },
  { 'name': 'virportallocatortest' },
  { 'name': 'virrotatingfiletest' },
  { 'name': 'virschematest' },
  { 'name': 'virshtest' },
  { 'name': 'virstringtest' },
  { 'name': 'virtimetest' },
  { 'name': 'virtypedparamtest' },
  { 'name': 'viruritest' },
  { 'name': 'vshtabletest', 'link_with': [ libvirt_shell_lib ] },
]

if host_machine.system() == 'linux'
  tests += [
    { 'name': 'fchosttest' },
    { 'name': 'scsihosttest' },
    { 'name': 'vircaps2xmltest', 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'virnetdevbandwidthtest' },
    { 'name': 'virresctrltest', 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'virscsitest' },
    { 'name': 'virusbtest' },
  ]
endif

if conf.has('WITH_BHYVE')
  tests += [
    { 'name': 'bhyveargv2xmltest', 'link_with': [ bhyve_driver_impl ] },
    { 'name': 'bhyvexml2argvtest', 'link_with': [ bhyve_driver_impl ] },
    { 'name': 'bhyvexml2xmltest', 'link_with': [ bhyve_driver_impl ] },
  ]
endif

if conf.has('WITH_DBUS')
  tests += [
    { 'name': 'virdbustest', 'deps': [ dbus_dep ] },
    { 'name': 'virsystemdtest', 'deps': [ dbus_dep ] },
  ]

  if conf.has('WITH_POLKIT')
    tests += [
      { 'name': 'virpolkittest', 'deps': [ dbus_dep ] },
    ]
  endif
endif

if conf.has('WITH_ESX')
  tests += [
    { 'name': 'esxutilstest', 'include': [ esx_inc_dir ] },
  ]
endif

if conf.has('WITH_LIBVIRTD')
  tests += [
    { 'name': 'eventtest', 'deps': [ thread_dep ] },
    { 'name': 'fdstreamtest' },
    { 'name': 'virdriverconnvalidatetest' },
    { 'name': 'virdrivermoduletest' },
  ]
endif

if conf.has('WITH_LIBXL')
  tests += [
    { 'name': 'libxlxml2domconfigtest', 'link_with': [ test_xen_driver_lib ], 'link_whole': [ test_utils_xen_lib ], 'deps': [ libxl_dep ] },
    { 'name': 'xlconfigtest', 'link_with': [ test_xen_driver_lib ], 'link_whole': [ test_utils_xen_lib ] },
    { 'name': 'xmconfigtest', 'link_with': [ test_xen_driver_lib ], 'link_whole': [ test_utils_xen_lib ] },
  ]
endif

if conf.has('WITH_LXC')
  tests += [
    { 'name': 'lxcconf2xmltest', 'link_with': [ lxc_driver_impl_lib ], 'link_whole': [ test_utils_lxc_lib ] },
    { 'name': 'lxcxml2xmltest', 'link_with': [ lxc_driver_impl_lib ], 'link_whole': [ test_utils_lxc_lib ] },
  ]
endif

if conf.has('WITH_NETWORK')
  tests += [
    { 'name': 'networkxml2conftest', 'link_with': [ network_driver_impl ] },
    { 'name': 'networkxml2firewalltest', 'link_with': [ network_driver_impl ] },
    { 'name': 'networkxml2xmltest', 'link_with': [ network_driver_impl ] },
  ]
endif

if conf.has('WITH_NODE_DEVICES')
  tests += [
    { 'name': 'nodedevmdevctltest', 'link_with': [ node_device_driver_impl ] },
  ]
endif

if conf.has('WITH_NSS')
  tests += [
    {
      'name': 'nsstest',
      'include': [ nss_inc_dir ],
      'link_with': [ nss_libvirt_impl ],
    },
    {
      'name': 'nssguesttest',
      'sources': [ 'nsstest.c' ],
      'c_args': [ '-DLIBVIRT_NSS_GUEST' ],
      'include': [ nss_inc_dir ],
      'link_with': [ nss_libvirt_guest_impl ],
    },
  ]
endif

if conf.has('WITH_NWFILTER')
  tests += [
    { 'name': 'nwfilterebiptablestest', 'link_with': [ nwfilter_driver_impl ] },
    { 'name': 'nwfilterxml2firewalltest', 'link_with': [ nwfilter_driver_impl ] },
  ]
endif

if conf.has('WITH_OPENVZ')
  tests += [
    { 'name': 'openvzutilstest', 'link_with': [ openvz_lib ] },
  ]
endif

if conf.has('WITH_QEMU')
  tests += [
    { 'name': 'qemuagenttest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemublocktest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucapabilitiestest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucaps2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucommandutiltest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemudomaincheckpointxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemudomainsnapshotxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemufirmwaretest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'qemuhotplugtest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemumemlocktest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemumigparamstest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemumonitorjsontest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemusecuritytest', 'sources': [ 'qemusecuritytest.c', 'qemusecuritymock.c' ], 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemuvhostusertest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'qemuxml2argvtest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
    { 'name': 'qemuxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
  ]
endif

if conf.has('WITH_REMOTE')
  tests += [
    { 'name': 'virnetdaemontest' },
    { 'name': 'virnetmessagetest' },
    { 'name': 'virnetserverclienttest' },
    { 'name': 'virnetsockettest' },
  ]

  nettls_sources = [ 'virnettlshelpers.c' ]
  if conf.has('HAVE_LIBTASN1_H')
    nettls_sources += 'pkix_asn1_tab.c'
  endif

  libtasn1_dep = cc.find_library('tasn1', required: false)

  tests += [
    { 'name': 'virnettlscontexttest', 'sources': [ 'virnettlscontexttest.c', nettls_sources ], 'deps': [ libtasn1_dep, ] },
    { 'name': 'virnettlssessiontest', 'sources': [ 'virnettlssessiontest.c', nettls_sources ], 'deps': [ libtasn1_dep, ] },
  ]
endif

foreach data : tests
  test_sources = '@0@.c'.format(data['name'])
  test_bin = executable(
    data['name'],
    [
      data.get('sources', test_sources),
      dtrace_gen_objects,
    ],
    c_args: [
      data.get('c_args', []),
    ],
    dependencies: [
      tests_dep,
      data.get('deps', []),
    ],
    include_directories: [
      data.get('include', []),
    ],
    link_args: [
      libvirt_no_indirect,
    ],
    link_with: [
      libvirt_lib,
      data.get('link_with', []),
    ],
    link_whole: [
      test_utils_lib,
      data.get('link_whole', []),
    ],
    export_dynamic: true,
  )
  test(data['name'], test_bin, env: tests_env)
endforeach
