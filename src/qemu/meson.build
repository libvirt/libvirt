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
  'qemu_fd.c',
  'qemu_firmware.c',
  'qemu_hostdev.c',
  'qemu_hotplug.c',
  'qemu_interface.c',
  'qemu_interop_config.c',
  'qemu_logcontext.c',
  'qemu_migration.c',
  'qemu_migration_cookie.c',
  'qemu_migration_params.c',
  'qemu_monitor.c',
  'qemu_monitor_json.c',
  'qemu_monitor_text.c',
  'qemu_namespace.c',
  'qemu_nbdkit.c',
  'qemu_passt.c',
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
      libnbd_dep,
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

  qemu_user_group_conf = configuration_data({
    'QEMU_USER': qemu_user,
    'QEMU_GROUP': qemu_group,
  })
  qemu_conf = configure_file(
    input: 'qemu.conf.in',
    output: 'qemu.conf',
    configuration: qemu_user_group_conf,
  )

  qemu_user_group_hack_conf = configuration_data({
    'QEMU_USER': qemu_user,
    'QEMU_GROUP': qemu_group,
    # This hack is necessary because the output file is going to be
    # used as input for another configure_file() call later, which
    # will take care of substituting @CONFIG@ with useful data
    'CONFIG': '@CONFIG@',
  })
  test_libvirtd_qemu_aug_tmp = configure_file(
    input: 'test_libvirtd_qemu.aug.in',
    output: 'test_libvirtd_qemu.aug.tmp',
    configuration: qemu_user_group_hack_conf,
  )

  virt_conf_files += qemu_conf
  virt_aug_files += files('libvirtd_qemu.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_qemu.aug',
    'aug': test_libvirtd_qemu_aug_tmp,
    'conf': qemu_conf,
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
    'name': 'QEMU',
    'service_extra_in': [
      files('virtqemud.service.extra.in'),
      systemd_service_limitnofile_extra_in,
      systemd_service_tasksmax_extra_in,
      systemd_service_limitmemlock_extra_in,
    ],
    'socket_extra_in': [
      files('virtqemud.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtqemud',
    'in_file': files('virtqemud.init.in'),
  }

  if conf.has('WITH_SYSCTL')
    install_data(
      'postcopy-migration.sysctl',
      install_dir: prefix / 'lib' / 'sysctl.d',
      rename: [ '60-qemu-postcopy-migration.conf' ],
    )
  endif

  virt_install_dirs += [
    confdir / 'qemu',
    confdir / 'qemu' / 'autostart',
    localstatedir / 'cache' / 'libvirt' / 'qemu',
    localstatedir / 'lib' / 'libvirt' / 'qemu',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'channel',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'channel' / 'target',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'checkpoint',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'dump',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'nvram',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'ram',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'save',
    localstatedir / 'lib' / 'libvirt' / 'qemu' / 'snapshot',
    localstatedir / 'lib' / 'libvirt' / 'swtpm',
    localstatedir / 'log' / 'libvirt' / 'qemu',
    localstatedir / 'log' / 'swtpm' / 'libvirt' / 'qemu',
    runstatedir / 'libvirt' / 'qemu',
    runstatedir / 'libvirt' / 'qemu' / 'dbus',
    runstatedir / 'libvirt' / 'qemu' / 'passt',
    runstatedir / 'libvirt' / 'qemu' / 'slirp',
    runstatedir / 'libvirt' / 'qemu' / 'swtpm',
  ]
endif
