lxc_driver_sources = [
  'lxc_cgroup.c',
  'lxc_conf.c',
  'lxc_container.c',
  'lxc_domain.c',
  'lxc_driver.c',
  'lxc_fuse.c',
  'lxc_hostdev.c',
  'lxc_monitor.c',
  'lxc_native.c',
  'lxc_process.c',
]

lxc_monitor_protocol = files('lxc_monitor_protocol.x')

rpc_probe_files += lxc_monitor_protocol

lxc_monitor_protocol_generated = []

lxc_monitor_protocol_generated += custom_target(
  'lxc_monitor_protocol_h',
  input: lxc_monitor_protocol,
  output: 'lxc_monitor_protocol.h',
  command: [ genprotocol_prog, rpcgen_prog, '-h', '@INPUT@', '@OUTPUT@' ]
)

lxc_monitor_protocol_generated += custom_target(
  'lxc_monitor_protocol_c',
  input: lxc_monitor_protocol,
  output: 'lxc_monitor_protocol.c',
  command: [ genprotocol_prog, rpcgen_prog, '-c', '@INPUT@', '@OUTPUT@' ]
)

lxc_monitor_generated = custom_target(
  'lxc_monitor_dispatch_h',
  input: lxc_monitor_protocol,
  output: 'lxc_monitor_dispatch.h',
  command: [
    gendispatch_prog, '--mode=client',
    'virLXCMonitor', 'VIR_LXC_MONITOR', '@INPUT@'
  ],
  capture: true,
)

driver_source_files += [
  files(lxc_driver_sources),
  lxc_monitor_protocol_generated,
  lxc_monitor_generated,
]

stateful_driver_source_files += [
  files(lxc_driver_sources),
  lxc_monitor_protocol_generated,
  lxc_monitor_generated,
]

lxc_controller_sources = files(
  'lxc_conf.c',
  'lxc_container.c',
  'lxc_cgroup.c',
  'lxc_domain.c',
  'lxc_fuse.c',
  'lxc_controller.c',
)

lxc_controller_generated = custom_target(
  'lxc_controller_dispatch_h',
  input: lxc_monitor_protocol,
  output: 'lxc_controller_dispatch.h',
  command: [
    gendispatch_prog, '--mode=server',
    'virLXCMonitor', 'VIR_LXC_MONITOR', '@INPUT@'
  ],
  capture: true,
)

if conf.has('WITH_LXC')
  lxc_driver_impl_lib = static_library(
    'virt_driver_lxc_impl',
    [
      lxc_driver_sources,
      lxc_monitor_protocol_generated,
      lxc_monitor_generated,
    ],
    dependencies: [
      access_dep,
      blkid_dep,
      capng_dep,
      fuse_dep,
      libnl_dep,
      secdriver_dep,
      src_dep,
      rpc_dep,
      xdr_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  check_protocols += {
    'name': 'lxc_monitor_protocol',
    'lib': lxc_driver_impl_lib,
  }

  virt_modules += {
    'name': 'virt_driver_lxc',
    'link_whole': [
      lxc_driver_impl_lib,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtlxcd',
    'c_args': [
      '-DDAEMON_NAME="virtlxcd"',
      '-DMODULE_NAME="lxc"',
    ],
  }

  virt_helpers += {
    'name': 'libvirt_lxc',
    'sources': [
      lxc_controller_sources,
      lxc_monitor_protocol_generated,
      lxc_controller_generated,
      datatypes_sources,
      dtrace_gen_objects,
    ],
    'include': [
      conf_inc_dir,
      hypervisor_inc_dir,
      include_directories('.'),
    ],
    'deps': [
      blkid_dep,
      capng_dep,
      fuse_dep,
      libnl_dep,
      rpc_dep,
      secdriver_dep,
      xdr_dep,
    ],
  }

  virt_conf_files += files('lxc.conf')
  virt_aug_files += files('libvirtd_lxc.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_lxc.aug',
    'aug': files('test_libvirtd_lxc.aug.in'),
    'conf': files('lxc.conf'),
    'test_name': 'libvirtd_lxc',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
  }

  virt_daemon_confs += {
    'name': 'virtlxcd',
  }

  virt_daemon_units += {
    'service': 'virtlxcd',
    'name': 'LXC',
    'service_extra_in': [
      files('virtlxcd.service.extra.in'),
      systemd_service_limitnofile_extra_in,
      systemd_service_tasksmax_extra_in,
      systemd_service_limitmemlock_extra_in,
    ],
    'socket_extra_in': [
      files('virtlxcd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtlxcd',
    'in_file': files('virtlxcd.init.in'),
  }

  virt_install_dirs += [
    confdir / 'lxc',
    confdir / 'lxc' / 'autostart',
    localstatedir / 'lib' / 'libvirt' / 'lxc',
    localstatedir / 'log' / 'libvirt' / 'lxc',
    runstatedir / 'libvirt' / 'lxc',
  ]
endif
