src_inc_dir = include_directories('.')

src_dep = declare_dependency(
  compile_args: [
    '-DIN_LIBVIRT',
    '-Dabs_top_builddir="@0@"'.format(meson.build_root()),
    '-Dabs_top_srcdir="@0@"'.format(meson.source_root()),
  ] + coverage_flags + win32_flags,
  dependencies: [
    glib_dep,
    libxml_dep,
  ],
  include_directories: [
    libvirt_inc,
    src_inc_dir,
    top_inc_dir,
  ],
  link_args: (
    libvirt_relro
    + libvirt_no_indirect
    + coverage_flags
    + driver_modules_flags
    + win32_link_flags
  ),
)


# define secdriver_dep

secdriver_dep = []
if conf.has('WITH_SECDRIVER_SELINUX')
  secdriver_dep += selinux_dep
endif
if conf.has('WITH_SECDRIVER_APPARMOR')
  secdriver_dep += apparmor_dep
endif


# Internal generic driver infrastructure

datatypes_sources = [
  'datatypes.c',
]


# generate systemtap files

systemtap_dir = datadir / 'systemtap' / 'tapset'

dtrace_gen_headers = []
dtrace_gen_objects = []

if conf.has('WITH_DTRACE_PROBES')
  infile = 'libvirt_probes.d'
  out_h = 'libvirt_probes.h'
  out_o = 'libvirt_probes.o'
  out_stp = 'libvirt_probes.stp'

  dtrace_gen_headers += custom_target(
    out_h,
    input: infile,
    output: out_h,
    command: [ dtrace_prog, '-o', '@OUTPUT@', '-h', '-s', '@INPUT@' ],
  )

  dtrace_gen_objects += custom_target(
    out_o,
    input: infile,
    output: out_o,
    command: [ dtrace_prog, '-o', '@OUTPUT@', '-G', '-s', '@INPUT@' ],
  )

  custom_target(
    out_stp,
    input: infile,
    output: out_stp,
    command: [
      meson_python_prog, python3_prog.path(), dtrace2systemtap_prog.path(),
      bindir, sbindir, libdir, '@INPUT@'
    ],
    capture: true,
    install: true,
    install_dir: systemtap_dir,
  )
endif


# symbol files

public_sym_file = 'libvirt_public.syms'

used_sym_files = [
  'libvirt_private.syms',
  'libvirt_driver_modules.syms',
]

generated_sym_files = []

sym_files = []

if host_machine.system() == 'linux'
  used_sym_files += 'libvirt_linux.syms'
else
  sym_files += 'libvirt_linux.syms'
endif

if conf.has('WITH_SASL')
  used_sym_files += 'libvirt_sasl.syms'
else
  sym_files += 'libvirt_sasl.syms'
endif

if conf.has('WITH_LIBSSH')
  used_sym_files += 'libvirt_libssh.syms'
else
  sym_files += 'libvirt_libssh.syms'
endif

if conf.has('WITH_SSH2')
  used_sym_files += 'libvirt_libssh2.syms'
else
  sym_files += 'libvirt_libssh2.syms'
endif


# variables filled by subdirectories

libvirt_libs = []

# virt_modules:
#   each entry is a dictionary with following items:
#   * name - module name (required)
#   * sources - module sources (optional, default [])
#   * name_prefix - resulting library prefix (optional, default 'lib')
#   * include - include_directories (optional, default [])
#   * deps - dependencies (optional, default [])
#   * link_with - static libraries to link with (optional, default [])
#   * link_whole - static libraries to include (optional, default [])
#   * link_args - arguments for linker (optional, default [])
#   * install_dir - installation directory (optional, default libdir / 'libvirt' / 'connection-driver'
virt_modules = []

# virt_daemons:
#   each entry is a dictionary with following items:
#   * name - binary name (required)
#   * sources - binary sources (optional, default remote_daemon_sources)
#   * c_args - compile arguments (optional, default [])
#   * include = include_directories (optional, default [])
virt_daemons = []

# virt_helpers:
#   each entry is a dictionary with following items:
#   * name - binary name (required)
#   * sources - binary sources (required)
#   * c_args - compile arguments (optional, default [])
#   * include - include_directories (optional, default [])
#   * deps - dependencies (optional, default [])
#   * install_dir - installation directory (optional, libexecdir)
virt_helpers = []

# virt_conf_files:
#   libvirt conf files
virt_conf_files = []

# virt_aug_files:
#   libvirt aug files
virt_aug_files = []

# virt_test_aug_files:
#   generate libvirt augeas test files
#   * name - augeas test file name (required)
#   * aug - augeas test file source (required)
#   * conf - conf file (required)
virt_test_aug_files = []

# virt_daemon_confs:
#   generation libvirt daemon conf files
#   each entry is a dictionary with following items:
#   * name - daemon name (required)
#   * with_ip - only for libvirtd and virtproxyd (optional, default false)
virt_daemon_confs = []

virt_aug_dir = datadir / 'augeas' / 'lenses'
virt_test_aug_dir = datadir / 'augeas' / 'lenses' / 'tests'

# guest_unit_files:
#   guest unit files to install
guest_unit_files = []

# virt_daemon_units:
#   generate libvirt daemon systemd unit files
#   * service - name of the service (required)
#   * service_in - service source file (required)
#   * name - socket description (required)
#   * sockprefix - socket prefix name (required)
#   * sockets - array of additional sockets (optional, default [ 'main', 'ro', 'admin' ])
#   * socket_$name_in - additional socket source files (optional, default remote/libvirtd.socket.in )
#   * deps - socket dependencies (optional, default '')
#   * conflicts - if the service conflicts with libvirtd (optional, true)
virt_daemon_units = []

# openrc_init_files
#   generate libvirt daemon openrc init files
#   * name - daemon name (required)
#   * in_file - source init file (required)
openrc_init_files = []


# list subdirectories

subdir('cpu_map')

subdir('util')

src_dep = declare_dependency(
  dependencies: [ src_dep ],
  include_directories: [ util_inc_dir ],
)

subdir('conf')
subdir('rpc')
subdir('access')
subdir('cpu')

subdir('hypervisor')
subdir('vmx')

subdir('remote')

subdir('admin')
subdir('interface')
subdir('locking')
subdir('logging')
subdir('network')
subdir('node_device')
subdir('nwfilter')
subdir('secret')
subdir('security')
subdir('storage')

subdir('bhyve')
subdir('esx')
subdir('hyperv')
subdir('libxl')
subdir('lxc')
subdir('openvz')
subdir('qemu')
subdir('test')
subdir('vbox')
subdir('vmware')
subdir('vz')


driver_sources = [
  'driver.c',
  'libvirt.c',
  'libvirt-domain.c',
  'libvirt-domain-checkpoint.c',
  'libvirt-domain-snapshot.c',
  'libvirt-host.c',
  'libvirt-interface.c',
  'libvirt-network.c',
  'libvirt-nodedev.c',
  'libvirt-nwfilter.c',
  'libvirt-secret.c',
  'libvirt-storage.c',
  'libvirt-stream.c',
]

driver_lib = static_library(
  'virt_driver',
  [
    driver_sources,
    datatypes_sources,
  ],
  dependencies: [
    curl_dep,
    dlopen_dep,
    gnutls_dep,
    rpc_dep,
    src_dep,
    xdr_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)

libvirt_libs += driver_lib


# symbol files for libvirt.so

# Build our version script.  This is composed of three parts:
#
# 1. libvirt_public.syms - public API.  These functions are always
# present in the library and should never change incompatibly.
#
# 2. libvirt_private.syms - private API.  These symbols are private and
# semantics may change on every release, hence the version number is
# spliced in at build time. This ensures that if libvirtd, virsh, or a
# driver module was built against one libvirt release, it will refuse to
# load with another where symbols may have same names but different
# semantics. Such symbols should never be visible in an (installed)
# public header file.
#
# 3. libvirt_*.syms - dynamic private API.  Like libvirt_private.syms,
# except that build options (such as --enable-debug) can mean these
# symbols aren't present at all.

libvirt_syms = custom_target(
  'libvirt.syms',
  input: [ public_sym_file ] + used_sym_files + generated_sym_files,
  output: 'libvirt.syms',
  command: [
    meson_python_prog, python3_prog.path(), meson_gen_sym_prog.path(),
    '@OUTPUT@', 'LIBVIRT_PRIVATE_' + meson.project_version(), '@INPUT@',
  ],
)
libvirt_syms_file = libvirt_syms
if host_machine.system() == 'windows'
  libvirt_def = custom_target(
    'libvirt.def',
    input: libvirt_syms,
    output: 'libvirt.def',
    command: [
      meson_python_prog, python3_prog.path(), meson_gen_def_prog.path(),
      '@INPUT@', '@OUTPUT@',
    ],
  )
  libvirt_syms_file = libvirt_def
endif


# libvirt.so library

libvirt_syms_flags = '@0@@1@'.format(
  version_script_flags,
  libvirt_syms_file.full_path(),
)

libvirt_lib = shared_library(
  'virt',
  dtrace_gen_objects,
  dependencies: [
    src_dep,
  ],
  link_args: [
    libvirt_flat_namespace,
    libvirt_no_undefined,
    libvirt_nodelete,
    libvirt_syms_flags,
  ],
  link_whole: [
    libvirt_libs,
  ],
  link_depends: [
    libvirt_syms_file,
  ],
  install: true,
  version: libvirt_lib_version,
  soversion: libvirt_so_version,
)


# libvirt-qemu.syms symbol files

libvirt_qemu_syms = meson.current_source_dir() / 'libvirt_qemu.syms'
libvirt_qemu_syms_file = libvirt_qemu_syms
libvirt_qemu_syms_path = libvirt_qemu_syms
if host_machine.system() == 'windows'
  libvirt_qemu_def = custom_target(
    'libvirt_qemu.def',
    input: libvirt_qemu_syms,
    output: 'libvirt_qemu.def',
    command: [
      meson_python_prog, python3_prog.path(), meson_gen_def_prog.path(),
      '@INPUT@', '@OUTPUT@',
    ],
  )
  libvirt_qemu_syms_file = libvirt_qemu_def
  libvirt_qemu_syms_path = libvirt_qemu_def.full_path()
endif


# libvirt-qemu.so

libvirt_qemu_syms_flags = '@0@@1@'.format(
  version_script_flags,
  libvirt_qemu_syms_path,
)

libvirt_qemu_lib = shared_library(
  'virt-qemu',
  'libvirt-qemu.c',
  dependencies: [
    src_dep,
  ],
  link_args: [
    libvirt_nodelete,
    libvirt_qemu_syms_flags,
  ],
  link_with: [
    libvirt_lib,
  ],
  link_depends: [
    libvirt_qemu_syms_file,
  ],
  install: true,
  install_rpath: libdir,
  version: libvirt_lib_version,
  soversion: libvirt_so_version,
)


# libvirt-lxc.so symbol files

libvirt_lxc_syms = meson.current_source_dir() / 'libvirt_lxc.syms'
libvirt_lxc_syms_file = libvirt_lxc_syms
libvirt_lxc_syms_path = libvirt_lxc_syms
if host_machine.system() == 'windows'
  libvirt_lxc_def = custom_target(
    'libvirt_lxc.def',
    input: libvirt_lxc_syms,
    output: 'libvirt_lxc.def',
    command: [
      meson_python_prog, python3_prog.path(), meson_gen_def_prog.path(),
      '@INPUT@', '@OUTPUT@',
    ],
  )
  libvirt_lxc_syms_file = libvirt_lxc_def
  libvirt_lxc_syms_path = libvirt_lxc_def.full_path()
endif


# libvirt-lxc.so

libvirt_lxc_syms_flags = '@0@@1@'.format(
  version_script_flags,
  libvirt_lxc_syms_path,
)

libvirt_lxc_lib = shared_library(
  'virt-lxc',
  'libvirt-lxc.c',
  dependencies: [
    apparmor_dep,
    selinux_dep,
    src_dep,
  ],
  link_args: [
    libvirt_nodelete,
    libvirt_lxc_syms_flags,
  ],
  link_with: [
    libvirt_lib,
  ],
  link_depends: [
    libvirt_lxc_syms_file,
  ],
  install: true,
  install_rpath: libdir,
  version: libvirt_lib_version,
  soversion: libvirt_so_version,
)


# libvirt-admin.so

libvirt_admin_lib = shared_library(
  'virt-admin',
  [
    admin_sources,
    admin_client_generated,
    admin_driver_generated,
    datatypes_sources,
    dtrace_gen_objects,
  ],
  dependencies: [
    capng_dep,
    devmapper_dep,
    gnutls_dep,
    libssh2_dep,
    libssh_dep,
    sasl_dep,
    src_dep,
    rpc_dep,
    xdr_dep,
    yajl_dep,
  ],
  include_directories: [
    admin_inc_dir,
    remote_inc_dir,
  ],
  link_args: [
    libvirt_admin_syms_flags,
    libvirt_nodelete,
  ],
  link_with: [
    libvirt_lib,
  ],
  link_depends: [
    libvirt_admin_syms_file,
  ],
  install: true,
  install_rpath: libdir,
  version: libvirt_lib_version,
  soversion: libvirt_so_version,
)


# build libvirt shared modules

foreach module : virt_modules
  mod = shared_module(
    module['name'],
    module.get('sources', []),
    name_prefix: module.get('name_prefix', 'lib'),
    include_directories: [
      conf_inc_dir,
      module.get('include', []),
    ],
    dependencies: [
      src_dep,
      module.get('deps', []),
    ],
    link_with: [
      libvirt_lib,
      module.get('link_with', []),
    ],
    link_whole: [
      module.get('link_whole', []),
    ],
    link_args: [
      libvirt_nodelete,
      module.get('link_args', []),
    ],
    install: true,
    install_dir: module.get('install_dir', libdir / 'libvirt' / 'connection-driver'),
    install_rpath: libdir,
  )
  set_variable('@0@_module'.format(module['name'].underscorify()), mod)
endforeach


# build libvirt daemons

foreach daemon : virt_daemons
  bin = executable(
    daemon['name'],
    [
      daemon.get('sources', [ remote_daemon_sources, remote_daemon_generated ]),
      dtrace_gen_objects,
    ],
    c_args: [
      daemon.get('c_args', []),
    ],
    include_directories: [
      conf_inc_dir,
      remote_inc_dir,
      daemon.get('include', []),
    ],
    dependencies: [
      admin_dep,
      access_dep,
      dbus_dep,
      gnutls_dep,
      libnl_dep,
      rpc_dep,
      src_dep,
      sasl_dep,
      xdr_dep,
    ],
    link_with: [
      admin_driver_lib,
      libvirt_lib,
      libvirt_lxc_lib,
      libvirt_qemu_lib,
    ],
    link_args: [
      libvirt_no_undefined,
    ],
    install: true,
    install_dir: sbindir,
    install_rpath: libdir,
  )
endforeach


# build libvirt helpers

foreach helper : virt_helpers
  bin = executable(
    helper['name'],
    [
      helper['sources'],
    ],
    c_args: [
      helper.get('c_args', []),
    ],
    include_directories: [
      helper.get('include', []),
    ],
    dependencies: [
      src_dep,
      helper.get('deps', []),
    ],
    link_with: [
      libvirt_lib,
    ],
    install: true,
    install_dir: helper.get('install_dir', libexecdir),
    install_rpath: libdir,
  )
endforeach


# Generate daemon config, augeas and augeas test files

virt_conf_files += 'libvirt.conf'

install_data(virt_conf_files, install_dir: confdir)
install_data(virt_aug_files, install_dir: virt_aug_dir)

foreach data : virt_test_aug_files
  custom_target(
    data['name'],
    input: [ data['conf'], data['aug'] ],
    output: data['name'],
    command: [
      meson_python_prog, python3_prog.path(), augeas_gentest_prog.path(),
      '@INPUT@',
    ],
    capture: true,
    install: true,
    install_dir: virt_test_aug_dir,
  )
endforeach

foreach data : virt_daemon_confs
  capitalize_args = [ '-c', 'print("@0@".capitalize())'.format(data['name']) ]
  name_uc = run_command(python3_prog, capitalize_args, check: true).stdout().strip()
  daemon_conf = configuration_data()
  daemon_conf.set('runstatedir', runstatedir)
  daemon_conf.set('sbindir', sbindir)
  daemon_conf.set('sysconfdir', sysconfdir)
  daemon_conf.set('DAEMON_NAME', data['name'])
  daemon_conf.set('DAEMON_NAME_UC', name_uc)
  # to silence meson warning about missing 'CONFIG' in the configuration_data
  daemon_conf.set('CONFIG', '@CONFIG@')

  if data.get('with_ip', false)
    conf_in = libvirtd_conf_tmp
  else
    conf_in = virtd_conf_tmp
  endif
  conf_out = configure_file(
    input: conf_in,
    output: '@0@.conf'.format(data['name']),
    configuration: daemon_conf,
    install: true,
    install_dir: confdir,
  )

  if data.get('with_ip', false)
    aug_in = libvirtd_aug_tmp
  else
    aug_in = virtd_aug_tmp
  endif
  configure_file(
    input: aug_in,
    output: '@0@.aug'.format(data['name']),
    configuration: daemon_conf,
    install: true,
    install_dir: virt_aug_dir,
  )

  if data.get('with_ip', false)
    test_aug_in = test_libvirtd_aug_tmp
  else
    test_aug_in = test_virtd_aug_tmp
  endif
  test_aug_tmp = configure_file(
    input: test_aug_in,
    output: 'test_@0@.aug.tmp'.format(data['name']),
    configuration: daemon_conf,
  )

  test_aug_out = 'test_@0@.aug'.format(data['name'])
  custom_target(
    test_aug_out,
    input: [ conf_out, test_aug_tmp ],
    output: test_aug_out,
    command: [
      meson_python_prog, python3_prog.path(), augeas_gentest_prog.path(),
      '@INPUT@',
    ],
    capture: true,
    install: true,
    install_dir: virt_test_aug_dir,
  )
endforeach


if conf.has('WITH_LIBVIRTD')
  # Generate systemd service and socket unit files
  if init_script == 'systemd'
    systemd_unit_dir = prefix / 'lib' / 'systemd' / 'system'

    install_data(
      guest_unit_files,
      install_dir: systemd_unit_dir,
    )

    foreach unit : virt_daemon_units
      unit_conf = configuration_data()
      unit_conf.set('runstatedir', runstatedir)
      unit_conf.set('sbindir', sbindir)
      unit_conf.set('sysconfdir', sysconfdir)
      unit_conf.set('name', unit['name'])
      unit_conf.set('service', unit['service'])
      unit_conf.set('sockprefix', unit['sockprefix'])
      unit_conf.set('deps', unit.get('deps', ''))

      configure_file(
        input: unit['service_in'],
        output: '@0@.service'.format(unit['service']),
        configuration: unit_conf,
        install: true,
        install_dir: systemd_unit_dir,
      )

      foreach socket : unit.get('sockets', [ 'main', 'ro', 'admin' ])
        if socket == 'main'
          socket_in_def = 'remote' / 'libvirtd.socket.in'
          socket_in = unit.get('socket_in', socket_in_def)
          socket_out = '@0@.socket'.format(unit['service'])
        else
          socket_in_def = 'remote' / 'libvirtd-@0@.socket.in'.format(socket)
          socket_in = unit.get('socket_@0@_in'.format(socket), socket_in_def)
          socket_out = '@0@-@1@.socket'.format(unit['service'], socket)
        endif
        configure_file(
          input: socket_in,
          output: socket_out,
          configuration: unit_conf,
          install: true,
          install_dir: systemd_unit_dir,
        )
      endforeach
    endforeach
  endif

  # Generate openrc init files
  if init_script == 'openrc'
    foreach init : openrc_init_files
      init_conf = configuration_data()
      init_conf.set('sbindir', sbindir)
      init_conf.set('runstatedir', runstatedir)
      if conf.has('WITH_FIREWALLD')
        need_firewalld = 'need firewalld'
      else
        need_firewalld = ''
      endif
      init_conf.set('NEED_FIREWALLD', need_firewalld)

      init_file = configure_file(
        input: init['in_file'],
        output: '@0@.init'.format(init['name']),
        configuration: init_conf,
      )

      install_data(
        init_file,
        install_dir: sysconfdir / 'init.d',
        rename: [ init['name'] ],
      )

      if init.has_key('confd')
        install_data(
          init['confd'],
          install_dir: sysconfdir / 'conf.d',
          rename: [ init['name'] ],
        )
      endif
    endforeach
  endif
endif
