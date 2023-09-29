lock_protocol = 'lock_protocol.x'

rpc_probe_files += files(lock_protocol)

lock_driver_sources = [
  'lock_manager.c',
  'lock_driver_nop.c',
  'domain_lock.c',
]

lock_driver_lockd_sources = [
  'lock_driver_lockd.c',
]

lock_protocol_generated = []

lock_protocol_generated += custom_target(
  'lock_protocol.h',
  input: lock_protocol,
  output: 'lock_protocol.h',
  command: [
    genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@',
  ],
)

lock_protocol_generated += custom_target(
  'lock_protocol.c',
  input: lock_protocol,
  output: 'lock_protocol.c',
  command: [
    genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@',
  ],
)

lock_daemon_sources = files(
  'lock_daemon.c',
  'lock_daemon_config.c',
  'lock_daemon_dispatch.c',
)

lock_daemon_generated = custom_target(
  'lock_daemon_dispatch_stubs.h',
  input: lock_protocol,
  output: 'lock_daemon_dispatch_stubs.h',
  command: [
    gendispatch_prog, '--mode=server',
    'virLockSpaceProtocol', 'VIR_LOCK_SPACE_PROTOCOL', '@INPUT@',
  ],
  capture: true,
)

sanlock_sources = [
  'lock_driver_sanlock.c',
]

sanlock_helper_sources = files(
  'sanlock_helper.c',
)

lock_driver_lib = static_library(
  'virt_lock_driver',
  [
    lock_driver_sources,
  ],
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)

libvirt_libs += lock_driver_lib

if conf.has('WITH_LIBVIRTD')
  lockd_lib_impl = static_library(
    'lockd_impl',
    [
      files(lock_driver_lockd_sources),
      lock_protocol_generated,
    ],
    include_directories: [
      conf_inc_dir,
    ],
    dependencies: [
      rpc_dep,
      sasl_dep,
      src_dep,
      xdr_dep,
    ],
  )

  check_protocols += {
    'name': 'lock_protocol',
    'lib': lockd_lib_impl,
  }

  lockdriver_dir = libdir / 'libvirt' / 'lock-driver'

  virt_modules += {
    'name': 'lockd',
    'name_prefix': '',
    'sources': [
      dtrace_gen_objects,
    ],
    'link_whole': [
      lockd_lib_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
    'install_dir': lockdriver_dir,
  }

  if conf.has('WITH_SANLOCK')
    virt_modules += {
      'name': 'sanlock',
      'name_prefix': '',
      'sources': [
        files(sanlock_sources),
      ],
      'deps': [
        sanlock_dep,
      ],
      'link_args': [
        libvirt_no_undefined,
      ],
      'install_dir': lockdriver_dir,
    }
  endif

  virt_daemons += {
    'name': 'virtlockd',
    'sources': [
      lock_daemon_sources,
      lock_daemon_generated,
      lock_protocol_generated,
    ],
    'include': [
      include_directories('.'),
    ],
  }

  virt_daemon_units += {
    'service': 'virtlockd',
    'name': 'locking',
    'service_in': files('virtlockd.service.in'),
    'service_extra_in': [
      files('virtlockd.service.extra.in'),
      systemd_service_oomscoreadjust_extra_in,
      systemd_service_limitnofile_extra_in,
    ],
    'sockets': [ 'main', 'admin' ],
    'socket_in': files('virtlockd.socket.in'),
    'socket_admin_in': files('virtlockd-admin.socket.in'),
    'socket_extra_in': [
      files('virtlockd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtlockd',
    'in_file': files('virtlockd.init.in'),
  }

  if conf.has('WITH_SANLOCK')
    virt_helpers += {
      'name': 'libvirt_sanlock_helper',
      'sources': [
        sanlock_helper_sources,
      ],
      'include': [
        conf_inc_dir,
      ],
    }
  endif

  virt_aug_files += files('libvirt_lockd.aug')

  if conf.has('WITH_QEMU')
    qemu_lockd_conf = configure_file(
      input: 'lockd.conf',
      output: 'qemu-lockd.conf',
      configuration: configmake_conf,
    )
    virt_conf_files += qemu_lockd_conf
    virt_test_aug_files += {
      'name': 'test_libvirt_lockd.aug',
      'aug': files('test_libvirt_lockd.aug.in'),
      'conf': qemu_lockd_conf,
      'test_name': 'libvirt_lockd',
      'test_srcdir': meson.current_source_dir(),
      'test_builddir': meson.current_build_dir(),
    }
  endif

  if conf.has('WITH_LIBXL')
    libxl_lockd_conf = configure_file(
      input: 'lockd.conf',
      output: 'libxl-lockd.conf',
      configuration: configmake_conf,
    )
    virt_conf_files += libxl_lockd_conf
  endif

  if conf.has('WITH_SANLOCK')
    virt_aug_files += files('libvirt_sanlock.aug')

    if conf.has('WITH_QEMU')
      qemu_sanlock_conf = configure_file(
        input: 'sanlock.conf',
        output: 'qemu-sanlock.conf',
        configuration: configmake_conf,
      )
      virt_conf_files += qemu_sanlock_conf
      virt_test_aug_files += {
        'name': 'test_libvirt_sanlock.aug',
        'aug': files('test_libvirt_sanlock.aug.in'),
        'conf': qemu_sanlock_conf,
        'test_name': 'libvirt_sanlock',
        'test_srcdir': meson.current_source_dir(),
        'test_builddir': meson.current_build_dir(),
      }
    endif

    if conf.has('WITH_LIBXL')
      libxl_sanlock_conf = configure_file(
        input: 'sanlock.conf',
        output: 'libxl-sanlock.conf',
        configuration: configmake_conf,
      )
      virt_conf_files += libxl_sanlock_conf
    endif
  endif

  virt_conf_files += files('virtlockd.conf')
  virt_aug_files += files('virtlockd.aug')
  virt_test_aug_files += {
    'name': 'test_virtlockd.aug',
    'aug': files('test_virtlockd.aug.in'),
    'conf': files('virtlockd.conf'),
    'test_name': 'virtlockd',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
  }

  virt_install_dirs += [
    localstatedir / 'lib' / 'libvirt' / 'lockd',
    localstatedir / 'lib' / 'libvirt' / 'lockd' / 'files',
    runstatedir / 'libvirt' / 'lockd',
  ]

  if conf.has('WITH_SANLOCK')
    virt_install_dirs += [
      localstatedir / 'lib' / 'libvirt' / 'sanlock',
    ]
  endif
endif
