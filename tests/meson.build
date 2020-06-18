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

else
  test_utils_xen_lib = []
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
else
  test_utils_qemu_lib = []
  test_utils_qemu_monitor_lib = []
endif

test_file_wrapper_lib = static_library(
  'test_file_wrapper',
  [ 'virfilewrapper.c' ],
  dependencies: [ tests_dep ],
)
