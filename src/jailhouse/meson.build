jailhouse_sources = files(
  'jailhouse_driver.c',
)

driver_source_files += jailhouse_sources
stateful_driver_source_files += jailhouse_sources

if conf.has('WITH_JAILHOUSE')
  jailhouse_driver_impl = static_library(
    'virt_driver_jailhouse_impl',
    [
      jailhouse_sources,
    ],
    dependencies: [
      access_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_jailhouse',
    'link_whole': [
      jailhouse_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtjailhoused',
    'c_args': [
      '-DDAEMON_NAME="virtjailhoused"',
      '-DMODULE_NAME="jailhouse"'
    ],
  }

  virt_conf_files += files('jailhouse.conf')
  virt_aug_files += files('libvirtd_jailhouse.aug')

  virt_daemon_confs += {
    'name': 'virtjailhoused',
  }
endif
