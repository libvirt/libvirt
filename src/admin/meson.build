admin_driver_sources = [
  'admin_server.c',
  'admin_server_dispatch.c',
]

admin_driver_protocol = files('admin_protocol.x')

rpc_probe_files += admin_driver_protocol

admin_driver_generated = []

admin_protocol_h = custom_target(
  'admin_protocol.h',
  input: admin_driver_protocol,
  output: 'admin_protocol.h',
  command: [
    genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
  ],
)
admin_driver_generated += admin_protocol_h

admin_driver_generated += custom_target(
  'admin_protocol.c',
  input: admin_driver_protocol,
  output: 'admin_protocol.c',
  command: [
    genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
  ],
)

admin_driver_generated += custom_target(
  'admin_server_dispatch_stubs.h',
  input: admin_driver_protocol,
  output: 'admin_server_dispatch_stubs.h',
  command: [
    gendispatch_prog, '--mode=server', 'admin', 'ADMIN', '@INPUT@',
  ],
  capture: true,
)

admin_sources = files(
  'libvirt-admin.c',
)

admin_client_generated = custom_target(
  'admin_client.h',
  input: admin_driver_protocol,
  output: 'admin_client.h',
  command: [
    gendispatch_prog, '--mode=client', 'admin', 'ADMIN', '@INPUT@',
  ],
  capture: true,
)

libvirt_admin_public_syms = files(
  'libvirt_admin_public.syms',
)

libvirt_admin_private_syms = files(
  'libvirt_admin_private.syms',
)

libvirt_admin_syms = custom_target(
  'libvirt_admin.syms',
  input: [
    libvirt_admin_public_syms,
    libvirt_admin_private_syms,
  ],
  output: 'libvirt_admin.syms',
  command: [
    meson_gen_sym_prog,
    '@OUTPUT@', 'LIBVIRT_ADMIN_PRIVATE_' + meson.project_version(), '@INPUT@',
  ],
)

if host_machine.system() == 'windows'
  libvirt_admin_def = custom_target(
    'libvirt_admin.def',
    input: libvirt_admin_syms,
    output: 'libvirt_admin.def',
    command: [
      meson_gen_def_prog,
      '@INPUT@', '@OUTPUT@',
    ],
  )
  libvirt_admin_syms_file = libvirt_admin_def
  libvirt_admin_syms_path = libvirt_admin_syms_file.full_path()
else
  libvirt_admin_syms_file = libvirt_admin_syms
  libvirt_admin_syms_path = libvirt_admin_syms_file.full_path()
endif

libvirt_admin_link_args = [
  libvirt_nodelete,
]
libvirt_admin_link_depends = []

if version_script_flags != ''
  libvirt_admin_link_args += '@0@@1@'.format(
    version_script_flags,
    libvirt_admin_syms_path,
  )
  libvirt_admin_link_depends += libvirt_admin_syms_file
endif

if conf.has('WITH_REMOTE')
  admin_driver_lib = static_library(
    'virt_admin_driver',
    [
      admin_driver_sources,
      admin_driver_generated,
    ],
    dependencies: [
      rpc_dep,
      sasl_dep,
      src_dep,
      xdr_dep,
    ],
  )

  check_protocols += {
    'name': 'admin_protocol',
    'lib': admin_driver_lib,
  }
endif

virt_conf_files += files('libvirt-admin.conf')

admin_inc_dir = include_directories('.')

admin_dep = declare_dependency(
  include_directories: admin_inc_dir,
  sources: [ admin_protocol_h ],
)
