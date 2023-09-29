log_driver_sources = [
  'log_manager.c',
]

log_protocol = 'log_protocol.x'

log_protocol_generated = []

log_protocol_header_generated = custom_target(
  'log_protocol.h',
  input: log_protocol,
  output: 'log_protocol.h',
  command: [
    genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@'
  ],
)
log_protocol_generated += log_protocol_header_generated

log_protocol_generated += custom_target(
  'log_protocol.c',
  input: log_protocol,
  output: 'log_protocol.c',
  command: [
    genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@'
  ],
)

log_daemon_sources = files(
  'log_daemon.c',
  'log_daemon_config.c',
  'log_daemon_dispatch.c',
  'log_handler.c',
  'log_cleaner.c',
)

if conf.has('WITH_REMOTE')
  log_driver_lib = static_library(
    'virt_log_driver',
    [
      log_driver_sources,
      log_protocol_generated,
    ],
    dependencies: [
      rpc_dep,
      src_dep,
      xdr_dep,
    ],
  )

  libvirt_libs += log_driver_lib
  used_sym_files += 'libvirt_logging.syms'
else
  sym_files += 'libvirt_logging.syms'
endif

if conf.has('WITH_LIBVIRTD')
  log_daemon_generated = custom_target(
    'log_daemon_dispatch_stubs.h',
    input: log_protocol,
    output: 'log_daemon_dispatch_stubs.h',
    command: [
      gendispatch_prog, '--mode=server',
      'virLogManagerProtocol', 'VIR_LOG_MANAGER_PROTOCOL', '@INPUT@',
    ],
    capture: true,
  )

  virt_daemons += {
    'name': 'virtlogd',
    'sources': [
      log_daemon_sources,
      log_daemon_generated,
      log_protocol_generated,
    ],
    'include': [
      include_directories('.'),
    ],
  }

  virt_conf_files += files('virtlogd.conf')
  virt_aug_files += files('virtlogd.aug')
  virt_test_aug_files += {
    'name': 'test_virtlogd.aug',
    'aug': files('test_virtlogd.aug.in'),
    'conf': files('virtlogd.conf'),
    'test_name': 'virtlogd',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
  }

  virt_daemon_units += {
    'service': 'virtlogd',
    'name': 'logging',
    'service_in': files('virtlogd.service.in'),
    'service_extra_in': [
      files('virtlogd.service.extra.in'),
      systemd_service_oomscoreadjust_extra_in,
      systemd_service_limitnofile_extra_in,
    ],
    'sockets': [ 'main', 'admin' ],
    'socket_in': files('virtlogd.socket.in'),
    'socket_admin_in': files('virtlogd-admin.socket.in'),
    'socket_extra_in': [
      files('virtlogd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtlogd',
    'in_file': files('virtlogd.init.in'),
  }
endif

log_inc_dir = include_directories('.')

log_dep = declare_dependency(
  include_directories: log_inc_dir,
  sources: log_protocol_header_generated,
)
