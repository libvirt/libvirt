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

# libvirt_conf_files:
#   Generate libvirtd and virtd template files that are used to generate
#   daemon configuration files.
#   Each entry is a dictionary with following items:
#   * input: source config file (required)
#   * libvirtd: libvirtd config output template file (required)
#   * virtd: virtd config output template file (required)
libvirt_conf_files = [
  {
    'input':'libvirtd.conf.in',
    'libvirtd':'libvirtd.conf.tmp',
    'virtd':'virtd.conf.tmp',
  },
  {
    'input':'libvirtd.aug.in',
    'libvirtd':'libvirtd.aug.tmp',
    'virtd':'virtd.aug.tmp',
  },
  {
    'input':'test_libvirtd.aug.in',
    'libvirtd':'test_libvirtd.aug.tmp',
    'virtd':'test_virtd.aug.tmp',
  },
]

foreach name : libvirt_conf_files
  tmp = configure_file(
    input: name['input'],
    output: name['libvirtd'],
    command: [ 'sed', '-e', '/[@]CUT_ENABLE_IP[@]/d', '-e', '/[@]END[@]/d', '@INPUT@' ],
    capture: true,
  )
  set_variable(name['libvirtd'].underscorify(), tmp)
endforeach

foreach name : libvirt_conf_files
  tmp = configure_file(
    input: name['input'],
    output: name['virtd'],
    command: [ 'sed', '-e', '/[@]CUT_ENABLE_IP[@]/,/[@]END[@]/d', '@INPUT@' ],
    capture: true,
  )
  set_variable(name['virtd'].underscorify(), tmp)
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

    virt_daemon_confs += {
      'name': 'libvirtd',
      'with_ip': true,
    }

    virt_daemons += {
      'name': 'virtproxyd',
      'c_args': [
        '-DSOCK_PREFIX="libvirt"',
        '-DDAEMON_NAME="virtproxyd"',
        '-DWITH_IP',
        '-DVIRTPROXYD',
      ],
    }

    virt_daemon_confs += {
      'name': 'virtproxyd',
      'with_ip': true,
    }
  endif
endif

if conf.has('WITH_REMOTE')
  used_sym_files += 'libvirt_remote.syms'
else
  sym_files += 'libvirt_remote.syms'
endif

remote_inc_dir = include_directories('.')
