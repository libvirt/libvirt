remote_driver_sources = [
  'remote_driver.c',
]

remote_driver_generated = []

foreach name : [ 'remote', 'qemu', 'lxc' ]
  client_bodies_h = '@0@_client_bodies.h'.format(name)
  protocol_c = '@0@_protocol.c'.format(name)
  protocol_h = '@0@_protocol.h'.format(name)
  protocol_x = '@0@_protocol.x'.format(name)

  remote_driver_generated += custom_target(
    client_bodies_h,
    input: protocol_x,
    output: client_bodies_h,
    command: [
      gendispatch_prog, '--mode=client', name, name.to_upper(), '@INPUT@',
    ],
    capture: true,
  )

  remote_driver_generated += custom_target(
    protocol_h,
    input: protocol_x,
    output: protocol_h,
    command: [
      genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
    ],
  )

  remote_driver_generated += custom_target(
    protocol_c,
    input: protocol_x,
    output: protocol_c,
    command: [
      genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
    ],
  )
endforeach

remote_daemon_sources = files(
  'remote_daemon.c',
  'remote_daemon_config.c',
  'remote_daemon_dispatch.c',
  'remote_daemon_stream.c',
)

remote_daemon_generated = []

foreach name : [ 'remote', 'qemu', 'lxc' ]
  protocol_x = '@0@_protocol.x'.format(name)
  dispatch_h = '@0@_daemon_dispatch_stubs.h'.format(name)

  remote_daemon_generated += custom_target(
    dispatch_h,
    input: protocol_x,
    output: dispatch_h,
    command: [
      gendispatch_prog, '--mode=server', name, name.to_upper(), '@INPUT@',
    ],
    capture: true,
  )
endforeach

if conf.has('WITH_REMOTE')
  remote_driver_lib = static_library(
    'virt_remote_driver',
    [
      remote_driver_sources,
      remote_driver_generated,
    ],
    dependencies: [
      rpc_dep,
      sasl_dep,
      src_dep,
      xdr_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  libvirt_libs += remote_driver_lib

  if conf.has('WITH_LIBVIRTD')
    virt_daemons += {
      'name': 'libvirtd',
      'c_args': [
        '-DSOCK_PREFIX="libvirt"',
        '-DDAEMON_NAME="libvirtd"',
        '-DWITH_IP',
        '-DLIBVIRTD',
      ],
    }
  endif
endif

if conf.has('WITH_REMOTE')
  used_sym_files += 'libvirt_remote.syms'
else
  sym_files += 'libvirt_remote.syms'
endif

remote_inc_dir = include_directories('.')
