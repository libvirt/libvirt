tests_dep = declare_dependency(
  compile_args: [
    '-Dabs_builddir="@0@"'.format(meson.current_build_dir()),
    '-Dabs_top_builddir="@0@"'.format(meson.project_build_root()),
    '-Dabs_srcdir="@0@"'.format(meson.current_source_dir()),
    '-Dabs_top_srcdir="@0@"'.format(meson.project_source_root()),
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
  link_args: (
    libvirt_export_dynamic
    + libvirt_flat_namespace
    + coverage_flags
  ),
)

tests_env = [
  'abs_builddir=@0@'.format(meson.current_build_dir()),
  'abs_srcdir=@0@'.format(meson.current_source_dir()),
  'abs_top_builddir=@0@'.format(meson.project_build_root()),
  'abs_top_srcdir=@0@'.format(meson.project_source_root()),
  'LC_ALL=C',
  'LIBVIRT_AUTOSTART=0',
]


# On macOS when BROKEN_POLL is set for GLib, our tests will
# periodically trigger a warning:
#
#  (process:50880): GLib-WARNING **: 02:54:15.272: poll(2) failed due to: Bad file descriptor.
#
# Our code is inherently racy, calling g_source_destroy which
# removes the FD from the event thread poll asynchronously
# but we close the FD immediately after g_source_destroy returns.
#
# With poll() this results in POLLNVAL, but with select() it
# generates the BADF error on macOS
if host_machine.system() != 'darwin'
  tests_env += ['G_DEBUG=fatal-warnings']
endif

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
  { 'name': 'virdnsmasqmock' },
  { 'name': 'virfilecachemock' },
  { 'name': 'virfirewallmock' },
  { 'name': 'virhostcpumock' },
  { 'name': 'virhostdevmock' },
  { 'name': 'virnetdaemonmock' },
  { 'name': 'virnetdevmock' },
  { 'name': 'virnetserverclientmock' },
  { 'name': 'virnumamock' },
  { 'name': 'virpcimock' },
  { 'name': 'virportallocatormock' },
  { 'name': 'virprocessmock' },
  { 'name': 'virrandommock' },
]

if host_machine.system() == 'linux'
  mock_libs += [
    { 'name': 'virfilemock' },
    { 'name': 'virnetdevbandwidthmock' },
    { 'name': 'virtestmock' },
    { 'name': 'virusbmock' },
  ]
endif

if host_machine.system() != 'windows'
  mock_libs += [
    { 'name': 'virgdbusmock' },
  ]
endif


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

  mock_libs += [
    { 'name': 'xlmock', 'sources': [ 'libxlmock.c' ], 'deps': [ libxl_dep ] },
  ]
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
    [ 'testutilsqemu.c', 'testutilsqemuschema.c' ],
    dependencies: [ tests_dep ],
  )

  test_utils_qemu_monitor_lib = static_library(
    'test_utils_qemu_monitor',
    [ 'qemumonitortestutils.c', ],
    dependencies: [ tests_dep ],
  )

  test_qemu_driver_lib = shared_library(
    'test_qemu_driver',
    [ qemu_dtrace_gen_objects ],
    link_args: [ libvirt_flat_namespace ],
    link_whole: [ qemu_driver_impl ],
    link_with: [ libvirt_lib ],
  )

  mock_libs += [
    { 'name': 'qemucaps2xmlmock' },
    { 'name': 'qemucapsprobemock', 'link_with': [ test_qemu_driver_lib ] },
    { 'name': 'qemucpumock' },
    { 'name': 'qemuhotplugmock', 'link_with': [ test_utils_qemu_lib, test_utils_lib ] },
    { 'name': 'qemuxml2argvmock' },
    { 'name': 'virhostidmock' },
  ]
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

tests_deps = []

# build helpers used by tests

# Must not link to any libvirt modules - libc only otherwise external
# libraries might unexpectedly leak file descriptors into commandhelper
# invalidating the test logic assumptions.
tests_deps += executable(
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
tests_deps += executable(
  'ssh',
  [ 'ssh.c' ],
  dependencies: [
    tests_dep,
  ],
)

subdir('schemas')

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

tests += [
  { 'name': 'commandtest' },
  { 'name': 'cputest', 'link_with': cputest_link_with, 'link_whole': cputest_link_whole },
  { 'name': 'domaincapstest', 'link_with': domaincapstest_link_with, 'link_whole': domaincapstest_link_whole },
  { 'name': 'domainconftest' },
  { 'name': 'genericxml2xmltest' },
  { 'name': 'interfacexml2xmltest' },
  { 'name': 'metadatatest' },
  { 'name': 'networkmetadatatest' },
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
  { 'name': 'vircgrouptest' },
  { 'name': 'virconftest' },
  { 'name': 'vircryptotest' },
  { 'name': 'virendiantest' },
  { 'name': 'virerrortest' },
  { 'name': 'virfilecachetest' },
  { 'name': 'virfiletest' },
  { 'name': 'virfirewalltest' },
  { 'name': 'virhostcputest', 'link_whole': [ test_file_wrapper_lib ] },
  { 'name': 'virhostdevtest' },
  { 'name': 'viridentitytest' },
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
  { 'name': 'virsystemdtest' },
  { 'name': 'virtimetest' },
  { 'name': 'virtypedparamtest' },
  { 'name': 'viruritest' },
  { 'name': 'virpcivpdtest' },
  { 'name': 'vshtabletest', 'link_with': [ libvirt_shell_lib ] },
  { 'name': 'virmigtest' },
]

if host_machine.endian() == 'little'
  tests += [
    { 'name': 'viracpitest' },
  ]
endif

if host_machine.system() == 'linux'
  tests += [
    { 'name': 'fchosttest' },
    { 'name': 'scsihosttest' },
    { 'name': 'vircaps2xmltest', 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'virnetdevbandwidthtest' },
    { 'name': 'virprocessstattest', 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'virresctrltest', 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'virscsitest' },
    { 'name': 'virusbtest' },
  ]
  if conf.has('WITH_YAJL')
    tests += [
      { 'name': 'virnetdevopenvswitchtest' },
    ]
  endif
endif

if conf.has('WITH_BHYVE')
  tests += [
    { 'name': 'bhyveargv2xmltest', 'link_with': [ bhyve_driver_impl ] },
    { 'name': 'bhyvexml2argvtest', 'link_with': [ bhyve_driver_impl ] },
    { 'name': 'bhyvexml2xmltest', 'link_with': [ bhyve_driver_impl ] },
  ]

  mock_libs += [
    { 'name': 'bhyveargv2xmlmock' },
    { 'name': 'bhyvexml2argvmock' },
  ]
endif

if conf.has('WITH_CH')
  tests += [
    { 'name': 'chxml2xmltest', 'link_with': [ ch_driver_impl ] },
  ]
endif

if conf.has('WITH_ESX')
  tests += [
    { 'name': 'esxutilstest', 'deps': [ esx_dep ] },
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

  mock_libs += [
    { 'name': 'nssmock' },
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
    { 'name': 'openvzutilstest' },
  ]
endif

if conf.has('WITH_POLKIT')
  tests += [
    { 'name': 'virpolkittest' },
  ]
endif

if conf.has('WITH_QEMU')
  tests += [
    { 'name': 'qemuagenttest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemublocktest', 'include': [ storage_file_inc_dir ], 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucapabilitiestest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucapabilitiesnumbering', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucaps2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemucommandutiltest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemudomaincheckpointxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemudomainsnapshotxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemufirmwaretest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'qemuhotplugtest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemumemlocktest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemumigparamstest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemumigrationcookiexmltest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
    { 'name': 'qemumonitorjsontest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemusecuritytest', 'sources': [ 'qemusecuritytest.c', 'qemusecuritymock.c' ], 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
    { 'name': 'qemustatusxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
    { 'name': 'qemuvhostusertest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_file_wrapper_lib ] },
    { 'name': 'qemuxml2argvtest', 'link_with': [ test_qemu_driver_lib, test_utils_qemu_monitor_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
    { 'name': 'qemuxml2xmltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
  ]
  if conf.has('WITH_NBDKIT')
    tests += [
      { 'name': 'qemunbdkittest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib, test_file_wrapper_lib ] },
    ]
  endif
endif

if conf.has('WITH_REMOTE')
  tests += [
    { 'name': 'virnetdaemontest' },
    { 'name': 'virnetmessagetest' },
    { 'name': 'virnetserverclienttest' },
    { 'name': 'virnetsockettest' },
  ]

  nettls_sources = [ 'virnettlshelpers.c' ]
  if conf.has('WITH_LIBTASN1_H')
    nettls_sources += 'pkix_asn1_tab.c'
  endif

  libtasn1_dep = cc.find_library('tasn1', required: false)

  tests += [
    { 'name': 'virnettlscontexttest', 'sources': [ 'virnettlscontexttest.c', nettls_sources ], 'deps': [ libtasn1_dep, ] },
    { 'name': 'virnettlssessiontest', 'sources': [ 'virnettlssessiontest.c', nettls_sources ], 'deps': [ libtasn1_dep, ] },
  ]
endif

if conf.has('WITH_SECDRIVER_SELINUX')
  if conf.has('WITH_LIBATTR')
    tests += [
      { 'name': 'securityselinuxtest' },
    ]

    if conf.has('WITH_QEMU')
      tests += [
        { 'name': 'securityselinuxlabeltest', 'link_with': [ test_qemu_driver_lib ], 'link_whole': [ test_utils_qemu_lib ] },
      ]
    endif
  endif

  mock_libs += [
    { 'name': 'securityselinuxhelper' },
  ]
endif

if conf.has('WITH_STORAGE')
  tests += [
    { 'name': 'storagepoolcapstest' },
    { 'name': 'storagepoolxml2argvtest', 'link_with': [ storage_driver_impl_lib ] },
    { 'name': 'storagepoolxml2xmltest', 'link_with': [ storage_driver_impl_lib ] },
    { 'name': 'storagevolxml2argvtest', 'link_with': [ storage_driver_impl_lib ] },
    { 'name': 'virstorageutiltest', 'link_with': [ storage_driver_impl_lib ] },
  ]
endif

if conf.has('WITH_STORAGE_FS')
  tests += [
    { 'name': 'virstoragetest', 'include': [ storage_file_inc_dir ],'link_with': [ storage_driver_impl_lib ] },
  ]
endif

if conf.has('WITH_VBOX')
  tests += [
    { 'name': 'vboxsnapshotxmltest', 'link_with': [ vbox_driver_impl ] },
  ]
endif

if conf.has('WITH_VMWARE')
  tests += [
    { 'name': 'vmwarevertest' },
  ]
endif

if conf.has('WITH_VMX')
  tests += [
    { 'name': 'vmx2xmltest' },
    { 'name': 'xml2vmxtest' },
  ]
endif

if conf.has('WITH_YAJL')
  tests += [
    { 'name': 'virjsontest' },
    { 'name': 'virmacmaptest' },
  ]
endif

foreach mock : mock_libs
  tests_deps += shared_library(
    mock['name'],
    mock.get('sources', [ '@0@.c'.format(mock['name']) ]),
    override_options: [
     'b_asneeded=false',
     'b_lundef=false',
    ],
    dependencies: [
      tests_dep,
      mock.get('deps', []),
    ],
    link_with: [
      libvirt_lib,
      mock.get('link_with', []),
    ],
  )
endforeach

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
  if data['name'] == 'qemuxml2argvtest'
    timeout = 90
  else
    # default meson timeout
    timeout = 30
  endif
  test(
    data['name'],
    test_bin,
    env: tests_env,
    timeout: timeout,
    depends: tests_deps,
    suite: 'bin'
  )
endforeach


# helpers:
#   each entry is a dictionary with following items:
#   * name - name of the test which is also used as default source file name (required)
#   * sources - override default sources based on name (optional, default [ '$name.c' ])
#   * c_args - args used by test (optional, default [])
#   * include - include_directories (optional, default [])
#   * link_with - compiled libraries to link with (optional, default [])

helpers = []

if conf.has('WITH_NSS')
  helpers += [
    # Intentionally not linking with anything else.
    # See the test source for more detailed explanation.
    {
      'name': 'nsslinktest',
      'include': [ nss_inc_dir ],
      'link_with': [ nss_libvirt_impl ],
    },
    {
      'name': 'nssguestlinktest',
      'sources': [ 'nsslinktest.c' ],
      'c_args': [ '-DLIBVIRT_NSS_GUEST' ],
      'include': [ nss_inc_dir ],
      'link_with': [ nss_libvirt_guest_impl ],
    },
  ]
endif

if conf.has('WITH_QEMU')
  helpers += [
    {
      'name': 'qemucapsprobe',
      'link_with': [ test_qemu_driver_lib, libvirt_lib ],
    },
  ]
endif

foreach data : helpers
  helper_sources = '@0@.c'.format(data['name'])
  helper_bin = executable(
    data['name'],
    [
      data.get('sources', helper_sources),
    ],
    c_args: [
      data.get('c_args', []),
    ],
    dependencies: [
      tests_dep,
    ],
    include_directories: [
      data.get('include', []),
    ],
    link_with: [
      data['link_with'],
    ],
    export_dynamic: true,
  )
endforeach


# test_scripts:
#   list of test scripts to run
test_scripts = []

if conf.has('WITH_LIBVIRTD')
  test_scripts += [
    'libvirtd-fail',
    'libvirtd-pool',
    'virsh-auth',
    'virsh-checkpoint',
    'virsh-cpuset',
    'virsh-define-dev-segfault',
    'virsh-int-overflow',
    'virsh-optparse',
    'virsh-output',
    'virsh-read-bufsiz',
    'virsh-read-non-seekable',
    'virsh-schedinfo',
    'virsh-self-test',
    'virsh-snapshot',
    'virsh-start',
    'virsh-undefine',
    'virsh-uriprecedence',
    'virsh-vcpupin',
    'virt-admin-self-test',
  ]

  if conf.has('WITH_SECDRIVER_APPARMOR')
    test_scripts += 'virt-aa-helper-test'
  endif
endif

foreach name : test_scripts
  script = find_program(name)
  test(name, script, env: tests_env, suite: 'script')
endforeach

testenv = runutf8
testenv += 'VIR_TEST_FILE_ACCESS=1'

add_test_setup(
  'access',
  env: testenv,
  exe_wrapper: [ python3_prog, check_file_access_prog.full_path() ],
)

add_test_setup(
  'valgrind',
  exe_wrapper: [
    'valgrind', '--quiet', '--leak-check=full', '--trace-children=yes',
    '--trace-children-skip="*/tools/virsh,*/tests/commandhelper,/usr/bin/*"',
    '--suppressions=@0@'.format(meson.current_source_dir() / '.valgrind.supp'),
    '--error-exitcode=1',
  ],
  # default timeout in meson is 30s
  timeout_multiplier: 4,
)
