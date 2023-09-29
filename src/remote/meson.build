remote_driver_sources = [
  'remote_driver.c',
  'remote_sockets.c',
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

  rpc_probe_files += files(protocol_x)
endforeach

remote_daemon_sources = files(
  'remote_daemon.c',
  'remote_daemon_config.c',
  'remote_daemon_dispatch.c',
  'remote_daemon_stream.c',
)

remote_daemon_generated = []

virt_ssh_helper_sources = files(
  'remote_sockets.c',
  'remote_ssh_helper.c',
)

virt_ssh_helper_dep = [
  src_dep,
]

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

libvirtd_socket_unit_files = [
  'libvirtd.socket',
  'libvirtd-ro.socket',
  'libvirtd-admin.socket',
  'libvirtd-tcp.socket',
  'libvirtd-tls.socket',
]

logrotate_files = [
  'libvirtd.qemu',
  'libvirtd.lxc',
  'libvirtd.libxl',
  'libvirtd',
]

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

  check_protocols += {
    'name': 'remote_protocol',
    'lib': remote_driver_lib,
  }

  check_protocols += {
    'name': 'qemu_protocol',
    'lib': remote_driver_lib,
  }

  check_protocols += {
    'name': 'lxc_protocol',
    'lib': remote_driver_lib,
  }

  libvirt_libs += remote_driver_lib

  if conf.has('WITH_LIBVIRTD')
    guest_unit_files += files('virt-guest-shutdown.target')

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

    virt_daemon_units += {
      'service': 'libvirtd',
      'name': 'legacy monolithic',
      'service_in': files('libvirtd.service.in'),
      'service_extra_in': [
        files('libvirtd.service.extra.in'),
        systemd_service_limitnofile_extra_in,
        systemd_service_tasksmax_extra_in,
        systemd_service_limitmemlock_extra_in,
      ],
      'sockets': [ 'main', 'ro', 'admin', 'tcp', 'tls' ],
      'socket_in': files('libvirtd.socket.in'),
      'socket_ro_in': files('libvirtd-ro.socket.in'),
      'socket_admin_in': files('libvirtd-admin.socket.in'),
      'socket_tcp_in': files('libvirtd-tcp.socket.in'),
      'socket_tls_in': files('libvirtd-tls.socket.in'),
      'socket_extra_in': [
        files('libvirtd.socket.extra.in'),
      ],
    }

    openrc_init_files += {
      'name': 'libvirtd',
      'in_file': files('libvirtd.init.in'),
      'confd': files('libvirtd.confd'),
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

    virt_daemon_units += {
      'service': 'virtproxyd',
      'name': 'proxy',
      'service_extra_in': [
        files('virtproxyd.service.extra.in'),
      ],
      'sockprefix': 'libvirt',
      'sockets': [ 'main', 'ro', 'admin', 'tcp', 'tls' ],
      'socket_extra_in': [
        files('virtproxyd.socket.extra.in'),
      ],
    }

    openrc_init_files += {
      'name': 'virtproxyd',
      'in_file': files('virtproxyd.init.in'),
      'confd': files('virtproxyd.confd'),
    }

    virt_install_dirs += [
      localstatedir / 'log' / 'libvirt',
      runstatedir / 'libvirt',
      runstatedir / 'libvirt' / 'common',
    ]

    logrotate_conf = configuration_data({
      'localstatedir': localstatedir,
    })

    foreach name : logrotate_files
      log_file = configure_file(
        input: '@0@.logrotate.in'.format(name),
        output: '@0@.logrotate'.format(name),
        configuration: logrotate_conf,
      )
      install_data(
        log_file,
        install_dir: sysconfdir / 'logrotate.d',
        rename: [ name ],
      )
    endforeach

    if conf.has('WITH_SYSCTL')
      # Use $(prefix)/lib rather than $(libdir), since man sysctl.d insists on
      # /usr/lib/sysctl.d/ even when libdir is /usr/lib64
      install_data(
        'libvirtd.sysctl',
        install_dir: prefix / 'lib' / 'sysctl.d',
        rename: [ '60-libvirtd.conf' ],
      )
    endif

    if conf.has('WITH_POLKIT')
      polkitdir = datadir / 'polkit-1'
      install_data(
        'libvirtd.policy',
        install_dir: polkitdir / 'actions',
        rename: [ 'org.libvirt.unix.policy' ],
      )
      install_data(
        'libvirtd.rules',
        install_dir: polkitdir / 'rules.d',
        rename: [ '50-libvirt.rules' ],
      )
    endif

    virt_helpers += {
      'name': 'virt-ssh-helper',
      'sources': [
        virt_ssh_helper_sources
      ],
      'install_dir': bindir,
    }
  endif
endif

if conf.has('WITH_REMOTE')
  used_sym_files += 'libvirt_remote.syms'
else
  sym_files += 'libvirt_remote.syms'
endif

# This is needed for clients too, so can't wrap in
# the WITH_LIBVIRTD conditional
if conf.has('WITH_SASL')
  install_data(
    'libvirtd.sasl',
    install_dir: sysconfdir / 'sasl2',
    rename: [ 'libvirt.conf' ],
  )
endif

remote_inc_dir = include_directories('.')
