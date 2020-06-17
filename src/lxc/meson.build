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
endif
