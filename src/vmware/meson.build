vmware_sources = [
  'vmware_conf.c',
  'vmware_driver.c',
]

if conf.has('WITH_VMWARE')
  vmware_lib = static_library(
    'virt_vmware',
    vmware_sources,
    dependencies: [
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      vmx_inc_dir,
    ],
  )
endif
