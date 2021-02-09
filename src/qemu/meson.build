qemu_driver_sources = [
  'qemu_agent.c',
  'qemu_alias.c',
  'qemu_backup.c',
  'qemu_block.c',
  'qemu_blockjob.c',
  'qemu_capabilities.c',
  'qemu_cgroup.c',
  'qemu_checkpoint.c',
  'qemu_command.c',
  'qemu_conf.c',
  'qemu_dbus.c',
  'qemu_domain.c',
  'qemu_domain_address.c',
  'qemu_domainjob.c',
  'qemu_driver.c',
  'qemu_extdevice.c',
  'qemu_firmware.c',
  'qemu_hostdev.c',
  'qemu_hotplug.c',
  'qemu_interface.c',
  'qemu_interop_config.c',
  'qemu_migration.c',
  'qemu_migration_cookie.c',
  'qemu_migration_params.c',
  'qemu_monitor.c',
  'qemu_monitor_json.c',
  'qemu_monitor_text.c',
  'qemu_namespace.c',
  'qemu_process.c',
  'qemu_qapi.c',
  'qemu_saveimage.c',
  'qemu_security.c',
  'qemu_snapshot.c',
  'qemu_slirp.c',
  'qemu_tpm.c',
  'qemu_validate.c',
  'qemu_vhost_user.c',
  'qemu_vhost_user_gpu.c',
  'qemu_virtiofs.c',
]

driver_source_files += files(qemu_driver_sources)
stateful_driver_source_files += files(qemu_driver_sources)

qemu_dtrace_gen_headers = []
qemu_dtrace_gen_objects = []

if conf.has('WITH_DTRACE_PROBES')
  infile = 'libvirt_qemu_probes.d'
  out_h = 'libvirt_qemu_probes.h'
  out_o = 'libvirt_qemu_probes.o'
  out_stp = 'libvirt_qemu_probes.stp'

  qemu_dtrace_gen_headers += custom_target(
    out_h,
    input: infile,
    output: out_h,
    command: dtrace_command + [ '-o', '@OUTPUT@', '-h', '-s', '@INPUT@' ],
  )

  qemu_dtrace_gen_objects += custom_target(
    out_o,
    input: infile,
    output: out_o,
    command: dtrace_command + [ '-o', '@OUTPUT@', '-G', '-s', '@INPUT@' ],
  )

  qemu_dtrace_gen_stp = custom_target(
    out_stp,
    input: infile,
    output: out_stp,
    command: [
      meson_python_prog, python3_prog, dtrace2systemtap_prog,
      bindir, sbindir, libdir, '@INPUT@',
    ],
    capture: true,
    install: conf.has('WITH_QEMU'),
    install_dir: systemtap_dir,
  )
endif

qemu_shim_sources = files(
  'qemu_shim.c',
)

if conf.has('WITH_QEMU')
  qemu_driver_impl = static_library(
    'virt_driver_qemu_impl',
    [
      qemu_driver_sources,
      qemu_dtrace_gen_headers,
    ],
    dependencies: [
      access_dep,
      capng_dep,
      gnutls_dep,
      libnl_dep,
      log_dep,
      selinux_dep,
      src_dep,
      xdr_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
      storage_file_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_qemu',
    'sources': [
      qemu_dtrace_gen_objects,
    ],
    'link_whole': [
      qemu_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtqemud',
    'c_args': [
      '-DDAEMON_NAME="virtqemud"',
      '-DMODULE_NAME="qemu"',
    ],
  }

  virt_conf_files += files('qemu.conf')
  virt_aug_files += files('libvirtd_qemu.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_qemu.aug',
    'aug': files('test_libvirtd_qemu.aug.in'),
    'conf': files('qemu.conf'),
    'test_name': 'libvirtd_qemu',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
  }

  virt_helpers += {
    'name': 'virt-qemu-run',
    'sources': [
      qemu_shim_sources
    ],
    'install_dir': bindir,
  }

  virt_daemon_confs += {
    'name': 'virtqemud',
  }

  virt_daemon_units += {
    'service': 'virtqemud',
    'service_in': files('virtqemud.service.in'),
    'name': 'Libvirt qemu',
    'sockprefix': 'virtqemud',
    'sockets': [ 'main', 'ro', 'admin' ],
  }

  openrc_init_files += {
    'name': 'virtqemud',
    'in_file': files('virtqemud.init.in'),
  }

  sysconf_files += {
    'name': 'virtqemud',
    'file': files('virtqemud.sysconf'),
  }

  virt_install_dirs += [
    localstatedir / 'lib' / 'libvirt' / 'qemu',
    runstatedir / 'libvirt' / 'qemu',
    localstatedir / 'cache' / 'libvirt' / 'qemu',
    localstatedir / 'log' / 'libvirt' / 'qemu',
    localstatedir / 'lib' / 'libvirt' / 'swtpm',
    runstatedir / 'libvirt' / 'qemu' / 'swtpm',
    localstatedir / 'log' / 'swtpm' / 'libvirt' / 'qemu',
  ]
endif
